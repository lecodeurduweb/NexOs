//! ARM64 (AArch64) architectural primitives and system register helpers.

pub mod boards;
pub mod exceptions;
pub mod mmu;
pub mod smp;
pub mod timer;

use core::arch::{asm, global_asm};

global_asm!(include_str!("neon_gemv.S"), options(raw));

extern "C" {
    pub fn nexos_neon_dot_f32(a: *const f32, b: *const f32, n: usize) -> f32;
    pub fn nexos_neon_gemv_q8_0(
        out: *mut f32,
        mat_q8: *const u8,
        x: *const f32,
        rows: usize,
        cols: usize,
    );
}

/// Read current Exception Level (0, 1, 2, or 3).
#[inline(always)]
pub fn current_el() -> u64 {
    let el: u64;
    unsafe {
        asm!("mrs {}, CurrentEL", out(reg) el, options(nomem, nostack, preserves_flags));
    }
    (el >> 2) & 0x3
}

/// Read Main ID Register (MIDR_EL1) to identify CPU implementer and part number.
#[inline(always)]
pub fn midr_el1() -> u64 {
    let val: u64;
    unsafe {
        asm!("mrs {}, MIDR_EL1", out(reg) val, options(nomem, nostack, preserves_flags));
    }
    val
}

/// Read ID_AA64MMFR0_EL1 to inspect architectural memory features (e.g., PARange).
#[inline(always)]
pub fn id_aa64mmfr0_el1() -> u64 {
    let val: u64;
    unsafe {
        asm!("mrs {}, ID_AA64MMFR0_EL1", out(reg) val, options(nomem, nostack, preserves_flags));
    }
    val
}

/// Decode physical address width (in bits) from ID_AA64MMFR0_EL1.PARange[3:0].
/// Cortex-A72 reports 0b0100 (44 bits / 16 TiB).
pub fn physical_address_bits() -> u8 {
    match id_aa64mmfr0_el1() & 0xF {
        0b0000 => 32,
        0b0001 => 36,
        0b0010 => 40,
        0b0011 => 42,
        0b0100 => 44,
        0b0101 => 48,
        0b0110 => 52,
        _ => 40, // Conservative architectural fallback
    }
}

/// Data Synchronization Barrier (Full System).
#[inline(always)]
pub fn dsb_sy() {
    unsafe {
        asm!("dsb sy", options(nostack, preserves_flags));
    }
}

/// Instruction Synchronization Barrier.
#[inline(always)]
pub fn isb() {
    unsafe {
        asm!("isb", options(nostack, preserves_flags));
    }
}

/// Wait For Event.
#[inline(always)]
pub fn wfe() {
    unsafe {
        asm!("wfe", options(nomem, nostack, preserves_flags));
    }
}

/// Send Event (wake cores waiting in WFE).
#[inline(always)]
pub fn sev() {
    unsafe {
        asm!("sev", options(nomem, nostack, preserves_flags));
    }
}

/// Wait For Interrupt.
#[inline(always)]
pub fn wfi() {
    unsafe {
        asm!("wfi", options(nomem, nostack, preserves_flags));
    }
}

/// CPU spin-loop hint.
#[inline(always)]
pub fn nop() {
    unsafe {
        asm!("nop", options(nomem, nostack, preserves_flags));
    }
}

/// Halt the core forever in low-power WFE state.
pub fn halt_forever() -> ! {
    loop {
        wfe();
    }
}
