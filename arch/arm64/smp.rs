//! ARM64 SMP (Symmetric Multiprocessing) & PSCI Boot Support.
//!
//! Brings up secondary Cortex-A72 cores via:
//!   - PSCI `CPU_ON` (HVC or SMC conduit discovered from DTB `/psci`), e.g. QEMU `virt -smp 4`
//!   - Spin-table `cpu-release-addr` fallback (with cache clean + `SEV`) for BCM2711 firmware
//!   - Internal `.Lpark_core` release table fallback if firmware jumped all cores at `_start`.

use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

use crate::arch::{self, mmu};
use crate::drivers::dtb::{DeviceTreeInfo, MAX_CPUS};
use crate::klog;
use crate::log::LogLevel;

const PSCI_SYSTEM_OFF: u64 = 0x8400_0008;
const PSCI_SYSTEM_RESET: u64 = 0x8400_0009;
const SECONDARY_STACK_BYTES: usize = 32 * 1024;

#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct CpuBootStack([u8; SECONDARY_STACK_BYTES]);

static mut SECONDARY_BOOT_STACKS: [CpuBootStack; MAX_CPUS] =
    [CpuBootStack([0; SECONDARY_STACK_BYTES]); MAX_CPUS];

/// Shared with `boot/entry.S` (secondary cores start with MMU OFF).
#[no_mangle]
pub static mut SECONDARY_RELEASE_ADDRS: [u64; MAX_CPUS] = [0; MAX_CPUS];

/// Per-CPU EL1 stack tops read by `_secondary_start` in `boot/entry.S`.
#[no_mangle]
pub static mut SECONDARY_STACK_TOPS: [u64; MAX_CPUS] = [0; MAX_CPUS];

/// Kernel `[MAIR_EL1, TCR_EL1, TTBR0_EL1]` read by `_secondary_start` in `boot/entry.S`.
#[no_mangle]
pub static mut SECONDARY_MMU_CFG: [u64; 3] = [0; 3];

extern "C" {
    fn _secondary_start();
}

static ONLINE_MASK: AtomicU8 = AtomicU8::new(1); // CPU 0 online from boot
static ONLINE_COUNT: AtomicUsize = AtomicUsize::new(1);
static TOTAL_CPUS: AtomicUsize = AtomicUsize::new(1);
static PSCI_USE_HVC: AtomicBool = AtomicBool::new(false);

/// Return current core index (`MPIDR_EL1.Aff0` clamped `< MAX_CPUS`).
#[inline(always)]
pub fn cpu_id() -> usize {
    let mpidr: u64;
    unsafe {
        asm!("mrs {}, MPIDR_EL1", out(reg) mpidr, options(nomem, nostack, preserves_flags));
    }
    let id = (mpidr & 0xFF) as usize;
    if id < MAX_CPUS {
        id
    } else {
        0
    }
}

pub fn online_mask() -> u8 {
    ONLINE_MASK.load(Ordering::Acquire)
}

pub fn online_cpus() -> usize {
    ONLINE_COUNT.load(Ordering::Acquire)
}

pub fn total_cpus() -> usize {
    TOTAL_CPUS.load(Ordering::Acquire)
}

/// Execute a PSCI SMC or HVC call.
#[inline(never)]
pub fn psci_call(use_hvc: bool, func_id: u64, arg0: u64, arg1: u64, arg2: u64) -> i64 {
    let ret: i64;
    unsafe {
        if use_hvc {
            asm!(
                "hvc #0",
                inout("x0") func_id => ret,
                in("x1") arg0,
                in("x2") arg1,
                in("x3") arg2,
                options(nostack)
            );
        } else {
            asm!(
                "smc #0",
                inout("x0") func_id => ret,
                in("x1") arg0,
                in("x2") arg1,
                in("x3") arg2,
                options(nostack)
            );
        }
    }
    ret
}

/// Power off system via PSCI `SYSTEM_OFF` (falls back to WFE halt).
pub fn psci_system_off() -> ! {
    let hvc = PSCI_USE_HVC.load(Ordering::Acquire);
    let _ = psci_call(hvc, PSCI_SYSTEM_OFF, 0, 0, 0);
    arch::halt_forever()
}

/// Reboot system via PSCI `SYSTEM_RESET` (or BCM2711 PM_WDOG on RPi4 if compiled).
pub fn psci_system_reset() -> ! {
    #[cfg(feature = "board-rpi4")]
    {
        if crate::arch::mmu::is_pm_wdog_mapped() {
            crate::services::bcm2711_hw_watchdog::trigger_immediate_reset();
        }
    }
    let hvc = PSCI_USE_HVC.load(Ordering::Acquire);
    let _ = psci_call(hvc, PSCI_SYSTEM_RESET, 0, 0, 0);
    arch::halt_forever()
}

/// Boot all secondary cores described in the Device Tree Blob.
/// Returns the total number of online CPU cores (including CPU 0).
pub fn boot_secondary_cpus(dtb: &DeviceTreeInfo) -> usize {
    let detected = dtb.cpu_count.clamp(1, MAX_CPUS);
    TOTAL_CPUS.store(detected, Ordering::Release);
    PSCI_USE_HVC.store(dtb.psci_hvc, Ordering::Release);

    if detected <= 1 {
        klog!(LogLevel::Info, "smp", "Single-core topology detected (1 CPU online).");
        return 1;
    }

    let (mair, tcr, l0) = mmu::current_mmu_regs();
    unsafe {
        SECONDARY_MMU_CFG[0] = mair;
        SECONDARY_MMU_CFG[1] = tcr;
        SECONDARY_MMU_CFG[2] = l0;

        for idx in 1..detected {
            let base = SECONDARY_BOOT_STACKS[idx].0.as_ptr() as usize;
            let top = (base + SECONDARY_STACK_BYTES) & !0xF;
            SECONDARY_STACK_TOPS[idx] = top as u64;
            SECONDARY_RELEASE_ADDRS[idx] = 0;
        }

        // Secondary cores execute _secondary_start with MMU+D-cache OFF, so clean shared
        // boot metadata and L0 page table to Point of Coherency first.
        mmu::dcache_clean_range(core::ptr::addr_of!(SECONDARY_MMU_CFG) as usize, 24);
        mmu::dcache_clean_range(core::ptr::addr_of!(SECONDARY_STACK_TOPS) as usize, MAX_CPUS * 8);
        mmu::dcache_clean_range(core::ptr::addr_of!(SECONDARY_RELEASE_ADDRS) as usize, MAX_CPUS * 8);
        mmu::dcache_clean_range(l0 as usize, 4096);
    }
    arch::dsb_sy();

    let entry_paddr = _secondary_start as *const () as usize as u64;

    for idx in 1..detected {
        let cpu = dtb.cpus[idx];
        // Prepare idle task slot for this CPU before releasing the core
        crate::scheduler::prepare_cpu_idle(idx);

        let mut woke_method = "none";
        if cpu.use_psci {
            let rc = psci_call(
                dtb.psci_hvc,
                dtb.psci_cpu_on_id as u64,
                cpu.mpidr,
                entry_paddr,
                idx as u64,
            );
            if rc == 0 {
                woke_method = if dtb.psci_hvc { "psci-hvc" } else { "psci-smc" };
            } else {
                klog!(
                    LogLevel::Warn,
                    "smp",
                    "PSCI CPU_ON failed for CPU {} (mpidr={:#x}): rc={}",
                    idx,
                    cpu.mpidr,
                    rc
                );
            }
        } else if cpu.release_addr != 0 {
            // Spin-table release (BCM2711 armstub8 mailboxes live at 0xD8..0xF0)
            let mapped_temp = cpu.release_addr < 0x1000;
            if mapped_temp {
                let _ = mmu::map_page_4k(l0, 0, 0, mmu::MemAttr::NormalRw);
                mmu::invalidate_tlb_all();
            }
            unsafe {
                core::ptr::write_volatile(cpu.release_addr as *mut u64, entry_paddr);
            }
            mmu::dcache_clean_range(cpu.release_addr as usize, 8);
            arch::dsb_sy();
            arch::sev();
            if mapped_temp {
                let _ = mmu::unmap_page_4k(l0, 0);
                mmu::invalidate_tlb_all();
            }
            woke_method = "spin-table";
        } else {
            // Fallback for internal .Lpark_core
            unsafe {
                SECONDARY_RELEASE_ADDRS[idx] = entry_paddr;
                mmu::dcache_clean_range(
                    core::ptr::addr_of!(SECONDARY_RELEASE_ADDRS) as usize,
                    MAX_CPUS * 8,
                );
            }
            arch::dsb_sy();
            arch::sev();
            woke_method = "park-table";
        }

        // Wait up to 200 ms for CPU `idx` to come online
        let freq = crate::arch::timer::read_cntfrq().max(1);
        let timeout = crate::arch::timer::read_cntpct() + (freq / 5);
        while (ONLINE_MASK.load(Ordering::Acquire) & (1u8 << idx)) == 0 {
            if crate::arch::timer::read_cntpct() >= timeout {
                break;
            }
            core::hint::spin_loop();
        }

        let is_up = (ONLINE_MASK.load(Ordering::Acquire) & (1u8 << idx)) != 0;
        klog!(
            if is_up { LogLevel::Info } else { LogLevel::Warn },
            "smp",
            "CPU {} (MPIDR={:#x}, method={}): {}",
            idx,
            cpu.mpidr,
            woke_method,
            if is_up { "ONLINE" } else { "TIMEOUT" }
        );
    }

    online_cpus()
}

/// Entry point for secondary CPUs once `_secondary_start` has configured stack, VBAR_EL1, and MMU.
#[no_mangle]
pub extern "C" fn secondary_cpu_entry(cpu_idx: usize) -> ! {
    crate::drivers::gicv2::init_secondary_cpu_interface();
    crate::arch::timer::init_secondary();
    crate::scheduler::secondary_init(cpu_idx);

    if cpu_idx < 8 {
        let bit = 1u8 << cpu_idx;
        if (ONLINE_MASK.fetch_or(bit, Ordering::AcqRel) & bit) == 0 {
            ONLINE_COUNT.fetch_add(1, Ordering::AcqRel);
        }
    }

    crate::arch::exceptions::enable_irq();

    loop {
        crate::arch::wfi();
    }
}
