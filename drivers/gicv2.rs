//! ARM GICv2 (Generic Interrupt Controller v2 / GIC-400) Driver.
//!
//! Shared between QEMU `virt` (`gic-version=2`, `arm,cortex-a15-gic`) and
//! Raspberry Pi 4 BCM2711 (`arm,gic-400`). Addresses and compatibility are
//! verified dynamically from the Device Tree Blob (DTB).

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::drivers::dtb::{GicInfo, GicVersion};
use crate::klog;
use crate::log::LogLevel;
use crate::sync::SpinLock;

pub const SGI_RESCHED_IRQ: u32 = 0;

// GIC Distributor (GICD) register offsets
const GICD_CTLR: usize = 0x000;
const GICD_TYPER: usize = 0x004;
const GICD_IIDR: usize = 0x008;
const GICD_IGROUPR: usize = 0x080;
const GICD_ISENABLER: usize = 0x100;
const GICD_ICENABLER: usize = 0x180;
const GICD_ICPENDR: usize = 0x280;
const GICD_IPRIORITYR: usize = 0x400;
const GICD_ITARGETSR: usize = 0x800;
const GICD_ICFGR: usize = 0xC00;
const GICD_SGIR: usize = 0xF00;

// GIC CPU Interface (GICC) register offsets
const GICC_CTLR: usize = 0x000;
const GICC_PMR: usize = 0x004;
const GICC_BPR: usize = 0x008;
const GICC_IAR: usize = 0x00C;
const GICC_EOIR: usize = 0x010;
const GICC_IIDR: usize = 0x0FC;

static GICD_BASE: AtomicUsize = AtomicUsize::new(0);
static GICC_BASE: AtomicUsize = AtomicUsize::new(0);
static MAX_IRQS: AtomicUsize = AtomicUsize::new(0);
static GICD_LOCK: SpinLock<()> = SpinLock::new(());

#[inline(always)]
fn gicd_read(off: usize) -> u32 {
    let base = GICD_BASE.load(Ordering::Relaxed);
    unsafe { read_volatile((base + off) as *const u32) }
}

#[inline(always)]
fn gicd_write(off: usize, val: u32) {
    let base = GICD_BASE.load(Ordering::Relaxed);
    unsafe { write_volatile((base + off) as *mut u32, val) }
}

#[inline(always)]
fn gicc_read(off: usize) -> u32 {
    let base = GICC_BASE.load(Ordering::Relaxed);
    unsafe { read_volatile((base + off) as *const u32) }
}

#[inline(always)]
fn gicc_write(off: usize, val: u32) {
    let base = GICC_BASE.load(Ordering::Relaxed);
    unsafe { write_volatile((base + off) as *mut u32, val) }
}

/// Initialize GICv2 after verifying DTB compatibility and MMIO ranges.
pub fn init(gic: &GicInfo) -> Result<(), &'static str> {
    if gic.version != GicVersion::V2 {
        return Err("DTB GIC is not GICv2 (expected arm,gic-400 or arm,cortex-a15-gic)");
    }
    if gic.gicd_base == 0 || gic.gicc_base == 0 {
        return Err("DTB GIC missing GICD or GICC base address");
    }

    GICD_BASE.store(gic.gicd_base as usize, Ordering::Release);
    GICC_BASE.store(gic.gicc_base as usize, Ordering::Release);

    let typer = gicd_read(GICD_TYPER);
    let it_lines = (typer & 0x1F) as usize;
    let max_irqs = ((it_lines + 1) * 32).min(1020);
    MAX_IRQS.store(max_irqs, Ordering::Release);

    let gicd_iidr = gicd_read(GICD_IIDR);
    let gicc_iidr = gicc_read(GICC_IIDR);

    // Disable distributor during configuration
    gicd_write(GICD_CTLR, 0);

    // Disable & clear pending on all SPIs (32..max_irqs), set Group 0
    let num_words = (max_irqs + 31) / 32;
    for w in 0..num_words {
        gicd_write(GICD_IGROUPR + w * 4, 0);
        gicd_write(GICD_ICENABLER + w * 4, 0xFFFF_FFFF);
        gicd_write(GICD_ICPENDR + w * 4, 0xFFFF_FFFF);
    }

    // Set default priority (0xA0) for all IRQs
    for w in 0..(max_irqs / 4) {
        gicd_write(GICD_IPRIORITYR + w * 4, 0xA0A0_A0A0);
    }

    // Route all SPIs (32..max_irqs) to CPU 0 (target mask 0x01)
    for w in 8..(max_irqs / 4) {
        gicd_write(GICD_ITARGETSR + w * 4, 0x0101_0101);
    }

    // Level-sensitive default for SPIs
    for w in 2..(max_irqs / 16) {
        gicd_write(GICD_ICFGR + w * 4, 0);
    }

    // Enable Distributor (EnableGrp0)
    gicd_write(GICD_CTLR, 1);

    // Configure CPU 0 Interface: allow all priorities, binary point 0, enable Group 0
    gicc_write(GICC_PMR, 0xFF);
    gicc_write(GICC_BPR, 0);
    gicc_write(GICC_CTLR, 1);

    // Enable SGI 0 (SMP reschedule IPI) on CPU 0
    enable_irq(SGI_RESCHED_IRQ);

    klog!(
        LogLevel::Info,
        "gicv2",
        "Initialized GICv2 (\"{}\"): GICD={:#x} (IIDR={:#x}), GICC={:#x} (IIDR={:#x}), max_irqs={}",
        gic.compatible_str(),
        gic.gicd_base,
        gicd_iidr,
        gic.gicc_base,
        gicc_iidr,
        max_irqs
    );

    Ok(())
}

/// Initialize banked GICD SGI/PPI registers and GICC CPU interface on secondary cores.
pub fn init_secondary_cpu_interface() {
    if GICD_BASE.load(Ordering::Acquire) == 0 || GICC_BASE.load(Ordering::Acquire) == 0 {
        return;
    }
    // GICD registers [0] for SGIs/PPIs are banked per-CPU interface (no lock needed for word 0)
    gicd_write(GICD_IGROUPR, 0);
    gicd_write(GICD_ICENABLER, 0xFFFF_FFFF);
    gicd_write(GICD_ICPENDR, 0xFFFF_FFFF);
    for w in 0..8 {
        gicd_write(GICD_IPRIORITYR + w * 4, 0x8080_8080);
    }
    // Enable SGI 0 (reschedule IPI) for this CPU
    gicd_write(GICD_ISENABLER, 1u32 << SGI_RESCHED_IRQ);

    gicc_write(GICC_PMR, 0xFF);
    gicc_write(GICC_BPR, 0);
    gicc_write(GICC_CTLR, 1);
}

/// Enable a specific GIC interrupt ID (SGI 0..15, PPI 16..31, SPI 32..max_irqs).
pub fn enable_irq(intid: u32) {
    let max_irqs = MAX_IRQS.load(Ordering::Acquire) as u32;
    if intid >= max_irqs {
        klog!(LogLevel::Warn, "gicv2", "Ignoring out-of-range IRQ {}", intid);
        return;
    }

    let _guard = GICD_LOCK.lock();

    // Set priority byte to 0x80 (higher priority than default 0xA0)
    let prio_reg = GICD_IPRIORITYR + ((intid as usize) & !3);
    let shift = (intid & 3) * 8;
    let mut prio = gicd_read(prio_reg);
    prio = (prio & !(0xFF << shift)) | (0x80 << shift);
    gicd_write(prio_reg, prio);

    // If SPI (>= 32), ensure routed to CPU 0
    if intid >= 32 {
        let tgt_reg = GICD_ITARGETSR + ((intid as usize) & !3);
        let mut tgt = gicd_read(tgt_reg);
        tgt = (tgt & !(0xFF << shift)) | (0x01 << shift);
        gicd_write(tgt_reg, tgt);
    }

    // Enable interrupt bit in ISENABLER
    let word_idx = (intid / 32) as usize;
    let bit_mask = 1u32 << (intid % 32);
    gicd_write(GICD_ISENABLER + word_idx * 4, bit_mask);
}

/// Send a Software Generated Interrupt (`sgi_id` 0..15) to CPUs in `target_cpu_mask`.
#[inline]
pub fn send_sgi(sgi_id: u32, target_cpu_mask: u8) {
    if target_cpu_mask == 0 || GICD_BASE.load(Ordering::Relaxed) == 0 {
        return;
    }
    crate::arch::dsb_sy();
    let val = ((target_cpu_mask as u32) << 16) | (sgi_id & 0xF);
    gicd_write(GICD_SGIR, val);
}

/// Acknowledge highest-priority pending interrupt; returns raw GICC_IAR value.
#[inline]
pub fn acknowledge_irq() -> u32 {
    if GICC_BASE.load(Ordering::Relaxed) == 0 {
        return 1023;
    }
    gicc_read(GICC_IAR)
}

/// Signal End Of Interrupt for the raw GICC_IAR token.
#[inline]
pub fn end_of_irq(iar: u32) {
    if GICC_BASE.load(Ordering::Relaxed) != 0 {
        gicc_write(GICC_EOIR, iar);
    }
}
