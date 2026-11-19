//! VirtIO-MMIO transport discovery and shared virtqueue primitives.
//!
//! Discovers VirtIO devices dynamically from DTB `virtio,mmio` slots.
//! Supports both VirtIO-MMIO v2 (modern, QEMU 7.2 default) and v1 (legacy).

use core::ptr::{read_volatile, write_volatile};

use crate::arch::mmu;
use crate::memory::phys;

pub const VIRTIO_MAGIC: u32 = 0x7472_6976; // "virt"

pub const VIRTIO_DEV_NET: u32 = 1;
pub const VIRTIO_DEV_BLK: u32 = 2;
pub const VIRTIO_DEV_RNG: u32 = 4;

// VirtIO-MMIO register offsets (v1 & v2 shared layout)
pub const MMIO_MAGIC_VALUE: usize = 0x000;
pub const MMIO_VERSION: usize = 0x004;
pub const MMIO_DEVICE_ID: usize = 0x008;
pub const MMIO_VENDOR_ID: usize = 0x00C;
pub const MMIO_DEVICE_FEATURES: usize = 0x010;
pub const MMIO_DEVICE_FEATURES_SEL: usize = 0x014;
pub const MMIO_DRIVER_FEATURES: usize = 0x020;
pub const MMIO_DRIVER_FEATURES_SEL: usize = 0x024;
pub const MMIO_GUEST_PAGE_SIZE: usize = 0x028; // v1 only
pub const MMIO_QUEUE_SEL: usize = 0x030;
pub const MMIO_QUEUE_NUM_MAX: usize = 0x034;
pub const MMIO_QUEUE_NUM: usize = 0x038;
pub const MMIO_QUEUE_ALIGN: usize = 0x03C; // v1 only
pub const MMIO_QUEUE_PFN: usize = 0x040; // v1 only
pub const MMIO_QUEUE_READY: usize = 0x044; // v2 only
pub const MMIO_QUEUE_NOTIFY: usize = 0x050;
pub const MMIO_INTERRUPT_STATUS: usize = 0x060;
pub const MMIO_INTERRUPT_ACK: usize = 0x064;
pub const MMIO_STATUS: usize = 0x070;
pub const MMIO_QUEUE_DESC_LOW: usize = 0x080;
pub const MMIO_QUEUE_DESC_HIGH: usize = 0x084;
pub const MMIO_QUEUE_AVAIL_LOW: usize = 0x090;
pub const MMIO_QUEUE_AVAIL_HIGH: usize = 0x094;
pub const MMIO_QUEUE_USED_LOW: usize = 0x0A0;
pub const MMIO_QUEUE_USED_HIGH: usize = 0x0A4;
pub const MMIO_CONFIG: usize = 0x100;

pub const STATUS_ACK: u32 = 1;
pub const STATUS_DRIVER: u32 = 2;
pub const STATUS_DRIVER_OK: u32 = 4;
pub const STATUS_FEATURES_OK: u32 = 8;

pub const VIRTQ_DESC_F_NEXT: u16 = 1;
pub const VIRTQ_DESC_F_WRITE: u16 = 2;

pub const QUEUE_SIZE: usize = 16;

#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct VirtqDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

#[repr(C, align(2))]
pub struct VirtqAvail {
    pub flags: u16,
    pub idx: u16,
    pub ring: [u16; QUEUE_SIZE],
    pub used_event: u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct VirtqUsedElem {
    pub id: u32,
    pub len: u32,
}

#[repr(C, align(4))]
pub struct VirtqUsed {
    pub flags: u16,
    pub idx: u16,
    pub ring: [VirtqUsedElem; QUEUE_SIZE],
    pub avail_event: u16,
}

pub struct VirtQueue {
    pub desc: *mut VirtqDesc,
    pub avail: *mut VirtqAvail,
    pub used: *mut VirtqUsed,
    pub last_used_idx: u16,
    pub avail_idx: u16,
    pub free_head: u16,
}

unsafe impl Send for VirtQueue {}

impl VirtQueue {
    pub fn allocate(mmio_base: usize, version: u32, queue_index: u32) -> Result<Self, &'static str> {
        mmio_write(mmio_base, MMIO_QUEUE_SEL, queue_index);
        let max = mmio_read(mmio_base, MMIO_QUEUE_NUM_MAX);
        if max < QUEUE_SIZE as u32 {
            return Err("VirtIO queue too small");
        }
        mmio_write(mmio_base, MMIO_QUEUE_NUM, QUEUE_SIZE as u32);

        if version == 1 {
            // Legacy v1 requires a physically contiguous 2-page block aligned to 4096
            let page0 = phys::alloc_contiguous_frames(2).ok_or("VirtQueue v1 contiguous alloc")?;
            let desc_va = page0;
            let avail_va = page0 + 16 * QUEUE_SIZE as u64;
            let used_va = page0 + 4096;
            mmio_write(mmio_base, MMIO_GUEST_PAGE_SIZE, 4096);
            mmio_write(mmio_base, MMIO_QUEUE_ALIGN, 4096);
            mmio_write(mmio_base, MMIO_QUEUE_PFN, (page0 >> 12) as u32);

            Ok(Self {
                desc: desc_va as *mut VirtqDesc,
                avail: avail_va as *mut VirtqAvail,
                used: used_va as *mut VirtqUsed,
                last_used_idx: 0,
                avail_idx: 0,
                free_head: 0,
            })
        } else {
            // Modern v2 allows separate physical addresses for desc, avail, used
            let desc_pa = phys::alloc_frame().ok_or("VirtQueue desc alloc")?;
            let avail_pa = phys::alloc_frame().ok_or("VirtQueue avail alloc")?;
            let used_pa = phys::alloc_frame().ok_or("VirtQueue used alloc")?;

            mmio_write(mmio_base, MMIO_QUEUE_DESC_LOW, desc_pa as u32);
            mmio_write(mmio_base, MMIO_QUEUE_DESC_HIGH, (desc_pa >> 32) as u32);
            mmio_write(mmio_base, MMIO_QUEUE_AVAIL_LOW, avail_pa as u32);
            mmio_write(mmio_base, MMIO_QUEUE_AVAIL_HIGH, (avail_pa >> 32) as u32);
            mmio_write(mmio_base, MMIO_QUEUE_USED_LOW, used_pa as u32);
            mmio_write(mmio_base, MMIO_QUEUE_USED_HIGH, (used_pa >> 32) as u32);
            mmio_write(mmio_base, MMIO_QUEUE_READY, 1);

            Ok(Self {
                desc: desc_pa as *mut VirtqDesc,
                avail: avail_va_from_pa(avail_pa),
                used: used_pa as *mut VirtqUsed,
                last_used_idx: 0,
                avail_idx: 0,
                free_head: 0,
            })
        }
    }
}

#[inline(always)]
fn avail_va_from_pa(pa: u64) -> *mut VirtqAvail {
    pa as *mut VirtqAvail
}

#[inline(always)]
pub fn mmio_read(base: usize, off: usize) -> u32 {
    unsafe { read_volatile((base + off) as *const u32) }
}

#[inline(always)]
pub fn mmio_write(base: usize, off: usize, val: u32) {
    unsafe { write_volatile((base + off) as *mut u32, val) }
}

/// Convert a kernel virtual address to physical address for VirtIO DMA descriptors.
pub fn virt_to_phys(va: usize) -> u64 {
    mmu::translate_el1(va as u64).unwrap_or(va as u64)
}

pub mod blk;
pub mod net;
pub mod rng;
