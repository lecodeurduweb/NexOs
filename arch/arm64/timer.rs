//! ARM Generic Timer (CNTP_*_EL0) periodic tick driver.
//!
//! Uses the Non-Secure Physical Timer (INTID discovered from DTB, typically 30).

use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::drivers::dtb::TimerInfo;
use crate::drivers::gicv2;
use crate::klog;
use crate::log::LogLevel;

static TIMER_FREQ_HZ: AtomicU64 = AtomicU64::new(0);
static TICK_INTERVAL_CYCLES: AtomicU64 = AtomicU64::new(0);
static TIMER_IRQ_ID: AtomicU32 = AtomicU32::new(30);
static TICK_COUNT: AtomicU64 = AtomicU64::new(0);
static LOG_PERIODIC_TICKS: AtomicBool = AtomicBool::new(true);

pub const TICK_HZ: u64 = 100; // 10 ms per tick

#[inline(always)]
pub fn read_cntfrq() -> u64 {
    let v: u64;
    unsafe {
        asm!("mrs {}, CNTFRQ_EL0", out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

#[inline(always)]
pub fn read_cntpct() -> u64 {
    let v: u64;
    unsafe {
        asm!("mrs {}, CNTPCT_EL0", out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

#[inline(always)]
fn write_cntp_tval(cycles: u32) {
    unsafe {
        asm!("msr CNTP_TVAL_EL0, {}", in(reg) cycles as u64, options(nomem, nostack));
    }
}

#[inline(always)]
fn write_cntp_ctl(val: u64) {
    unsafe {
        asm!("msr CNTP_CTL_EL0, {}", in(reg) val, options(nomem, nostack));
    }
}

/// Initialize periodic system timer using DTB-discovered IRQ and CNTFRQ_EL0.
pub fn init(dtb_timer: &TimerInfo) -> Result<u32, &'static str> {
    if !dtb_timer.found {
        return Err("ARM generic timer node not found in DTB");
    }
    let irq = dtb_timer
        .ns_phys_irq
        .ok_or("DTB timer missing non-secure physical IRQ")?;

    let freq = read_cntfrq();
    if freq == 0 {
        return Err("CNTFRQ_EL0 reported 0 Hz");
    }

    let interval = (freq / TICK_HZ).max(1);
    TIMER_FREQ_HZ.store(freq, Ordering::Release);
    TICK_INTERVAL_CYCLES.store(interval, Ordering::Release);
    TIMER_IRQ_ID.store(irq, Ordering::Release);

    // Mask and stop timer before enabling in GIC
    write_cntp_ctl(0);
    gicv2::enable_irq(irq);

    // Arm first tick and enable timer (ENABLE=1, IMASK=0)
    write_cntp_tval(interval as u32);
    write_cntp_ctl(1);
    crate::arch::isb();

    klog!(
        LogLevel::Info,
        "timer",
        "ARM Generic Timer started: CNTFRQ={} Hz, tick={} Hz ({} cycles), GIC INTID={}",
        freq,
        TICK_HZ,
        interval,
        irq
    );

    Ok(irq)
}

/// Arm the local Non-Secure Physical Timer PPI on a secondary CPU core.
pub fn init_secondary() {
    let irq = TIMER_IRQ_ID.load(Ordering::Acquire);
    let interval = TICK_INTERVAL_CYCLES.load(Ordering::Acquire) as u32;
    if interval == 0 {
        return;
    }
    write_cntp_ctl(0);
    gicv2::enable_irq(irq);
    write_cntp_tval(interval);
    write_cntp_ctl(1);
    crate::arch::isb();
}

pub fn timer_irq_id() -> u32 {
    TIMER_IRQ_ID.load(Ordering::Relaxed)
}

pub fn ticks() -> u64 {
    TICK_COUNT.load(Ordering::Relaxed)
}

pub fn uptime_ms() -> u64 {
    (ticks() * 1000) / TICK_HZ
}

pub fn set_periodic_log(enabled: bool) {
    LOG_PERIODIC_TICKS.store(enabled, Ordering::Relaxed);
}

/// Called from IRQ vector when GIC acknowledges `TIMER_IRQ_ID` on any CPU.
pub fn handle_irq() {
    let interval = TICK_INTERVAL_CYCLES.load(Ordering::Relaxed) as u32;
    write_cntp_tval(interval);

    let cpu = crate::arch::smp::cpu_id();
    if cpu == 0 {
        let count = TICK_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
        if LOG_PERIODIC_TICKS.load(Ordering::Relaxed) && (count <= 3 || count % 25 == 0) {
            klog!(
                LogLevel::Info,
                "timer",
                "Tick #{} (uptime={} ms)",
                count,
                (count * 1000) / TICK_HZ
            );
        }
    }
    crate::scheduler::on_timer_tick_cpu(cpu);
}
