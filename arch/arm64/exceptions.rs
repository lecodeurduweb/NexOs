//! ARM64 Exception Vector Initialization & Register Dump Handler.

use core::arch::{asm, global_asm};

use crate::log::LogLevel;
use crate::{klog, kprintln};

global_asm!(include_str!("vectors.S"));

extern "C" {
    static __exception_vectors: u8;
}

#[repr(C)]
pub struct TrapFrame {
    pub x: [u64; 31],
    pub sp_el0: u64,
    pub elr_el1: u64,
    pub spsr_el1: u64,
    pub esr_el1: u64,
    pub far_el1: u64,
    pub q: [[u64; 2]; 32],
    pub fpcr: u64,
    pub fpsr: u64,
}

/// Install `__exception_vectors` into `VBAR_EL1`.
pub fn init() {
    let vbar = unsafe { &__exception_vectors as *const u8 as u64 };
    unsafe {
        asm!(
            "msr VBAR_EL1, {}",
            "isb",
            in(reg) vbar,
            options(nostack)
        );
    }
    klog!(LogLevel::Info, "exc", "VBAR_EL1 installed at {:#010x}", vbar);
}

/// Enable IRQ delivery at CPU level (clear DAIF.I).
#[inline(always)]
pub fn enable_irq() {
    unsafe {
        asm!("msr DAIFClr, #2", options(nomem, nostack));
    }
}

/// Disable IRQ delivery at CPU level (set DAIF.I).
#[inline(always)]
pub fn disable_irq() {
    unsafe {
        asm!("msr DAIFSet, #2", options(nomem, nostack));
    }
}

fn vector_name(vec_id: u64) -> &'static str {
    match vec_id {
        0 => "CurrentEL_SP0_Sync",
        1 => "CurrentEL_SP0_IRQ",
        2 => "CurrentEL_SP0_FIQ",
        3 => "CurrentEL_SP0_SError",
        4 => "CurrentEL_SPx_Sync",
        5 => "CurrentEL_SPx_IRQ",
        6 => "CurrentEL_SPx_FIQ",
        7 => "CurrentEL_SPx_SError",
        8 => "LowerEL_A64_Sync",
        9 => "LowerEL_A64_IRQ",
        10 => "LowerEL_A64_FIQ",
        11 => "LowerEL_A64_SError",
        12 => "LowerEL_A32_Sync",
        13 => "LowerEL_A32_IRQ",
        14 => "LowerEL_A32_FIQ",
        15 => "LowerEL_A32_SError",
        _ => "UnknownVector",
    }
}

fn esr_ec_name(ec: u64) -> &'static str {
    match ec {
        0x00 => "Unknown",
        0x01 => "WFI/WFE trapped",
        0x07 => "FP/SIMD access trapped",
        0x0E => "Illegal Execution State",
        0x15 => "SVC (AArch64)",
        0x18 => "MSR/MRS trapped",
        0x20 => "Instruction Abort (lower EL)",
        0x21 => "Instruction Abort (current EL)",
        0x22 => "PC Alignment Fault",
        0x24 => "Data Abort (lower EL)",
        0x25 => "Data Abort (current EL)",
        0x26 => "SP Alignment Fault",
        0x2C => "FP Exception (AArch64)",
        0x2F => "SError Interrupt",
        0x3C => "BRK Instruction (AArch64)",
        _ => "Other Exception Class",
    }
}

pub fn dump_trap_frame(frame: &TrapFrame, vec_id: u64) {
    let ec = (frame.esr_el1 >> 26) & 0x3F;
    let iss = frame.esr_el1 & 0x01FF_FFFF;

    kprintln!("--- EXCEPTION DUMP ({}) ---", vector_name(vec_id));
    kprintln!(
        "  ESR_EL1  = {:#018x} (EC={:#04x} [{}], ISS={:#09x})",
        frame.esr_el1,
        ec,
        esr_ec_name(ec),
        iss
    );
    kprintln!(
        "  ELR_EL1  = {:#018x}   SPSR_EL1 = {:#018x}",
        frame.elr_el1,
        frame.spsr_el1
    );
    kprintln!(
        "  FAR_EL1  = {:#018x}   SP_EL0   = {:#018x}",
        frame.far_el1,
        frame.sp_el0
    );

    let mut i = 0;
    while i < 30 {
        kprintln!(
            "  x{:02} = {:#018x}   x{:02} = {:#018x}",
            i,
            frame.x[i],
            i + 1,
            frame.x[i + 1]
        );
        i += 2;
    }
    kprintln!("  x30 = {:#018x} (LR)", frame.x[30]);
    kprintln!("-------------------------------------------");
}

/// Trigger a deliberate synchronous BRK exception for Stage 3 verification.
pub fn run_self_test() {
    klog!(LogLevel::Info, "exc", "Triggering deliberate synchronous exception (brk #0x42)...");
    unsafe {
        asm!("brk #0x42", options(nostack));
    }
    klog!(LogLevel::Info, "exc", "Stage 3 exception test passed (resumed cleanly after ERET).");
}

#[no_mangle]
extern "C" fn rust_exception_handler(frame: &mut TrapFrame, vec_id: u64) -> usize {
    let tf_ptr = frame as *mut TrapFrame as usize;

    // IRQ vector (CurrentEL_SPx_IRQ or LowerEL_A64_IRQ)
    if vec_id == 5 || vec_id == 9 {
        let iar = crate::drivers::gicv2::acknowledge_irq();
        let intid = iar & 0x3FF;
        let mut force_resched = false;
        if intid < 1020 {
            if intid == crate::arch::timer::timer_irq_id() {
                crate::arch::timer::handle_irq();
            } else if intid == crate::drivers::gicv2::SGI_RESCHED_IRQ {
                force_resched = true;
            } else {
                klog!(LogLevel::Warn, "irq", "Unhandled GIC INTID {}", intid);
            }
            crate::drivers::gicv2::end_of_irq(iar);
        }
        return crate::scheduler::schedule_from_trap(tf_ptr, force_resched);
    }

    let ec = (frame.esr_el1 >> 26) & 0x3F;
    let iss = frame.esr_el1 & 0x01FF_FFFF;

    // EL0 (LowerEL_A64_Sync, vec_id == 8)
    if vec_id == 8 {
        if ec == 0x15 && (iss & 0xFFFF) == 0 {
            return crate::syscall::handle_syscall(frame);
        }
        // Any other fault from EL0 (illegal kernel read/write, privileged instruction, etc.)
        // is contained: log the fault, terminate ONLY the offending EL0 task, and reschedule.
        let pid = crate::scheduler::current_task_id();
        klog!(
            LogLevel::Warn,
            "isol",
            "EL0 fault contained (pid={}): EC={:#04x} [{}], ELR={:#x}, FAR={:#x}",
            pid,
            ec,
            esr_ec_name(ec),
            frame.elr_el1,
            frame.far_el1
        );
        crate::scheduler::mark_current_exited();
        return crate::scheduler::schedule_from_trap(tf_ptr, true);
    }

    // Kernel voluntary yield / sleep / exit (EL1 SVC #1)
    if vec_id == 4 && ec == 0x15 && (iss & 0xFFFF) == 1 {
        return crate::scheduler::schedule_from_trap(tf_ptr, true);
    }

    // Deliberate Stage 3 self-test BRK #0x42: dump registers and advance past BRK
    if vec_id == 4 && ec == 0x3C && (iss & 0xFFFF) == 0x42 {
        dump_trap_frame(frame, vec_id);
        frame.elr_el1 = frame.elr_el1.wrapping_add(4);
        return tf_ptr;
    }

    // Any unexpected synchronous fault or SError in EL1 is fatal
    dump_trap_frame(frame, vec_id);
    panic!("Unhandled CPU exception on vector {} ({})", vec_id, vector_name(vec_id));
}
