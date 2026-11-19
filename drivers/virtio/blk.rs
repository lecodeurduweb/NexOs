//! VirtIO Block (`virtio-blk`) MMIO Driver.

use core::ptr::{read_volatile, write_volatile};

use crate::arch;
use crate::drivers::block::{BlockDevice, BlockError};
use crate::drivers::dtb::DeviceTreeInfo;
use crate::klog;
use crate::log::LogLevel;
use crate::memory::phys;

use super::{
    mmio_read, mmio_write, virt_to_phys, VirtQueue, QUEUE_SIZE, MMIO_CONFIG, MMIO_DEVICE_FEATURES,
    MMIO_DEVICE_FEATURES_SEL, MMIO_DEVICE_ID, MMIO_DRIVER_FEATURES, MMIO_DRIVER_FEATURES_SEL,
    MMIO_INTERRUPT_ACK, MMIO_INTERRUPT_STATUS, MMIO_MAGIC_VALUE, MMIO_QUEUE_NOTIFY, MMIO_STATUS,
    MMIO_VERSION, STATUS_ACK, STATUS_DRIVER, STATUS_DRIVER_OK, STATUS_FEATURES_OK,
    VIRTIO_DEV_BLK, VIRTIO_MAGIC, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE,
};

const VIRTIO_BLK_T_IN: u32 = 0;
const VIRTIO_BLK_T_OUT: u32 = 1;
const VIRTIO_F_VERSION_1: u32 = 1 << 0; // in features word 1 (bit 32)

#[repr(C)]
struct VirtioBlkReqHeader {
    req_type: u32,
    reserved: u32,
    sector: u64,
}

pub struct VirtioBlk {
    mmio_base: usize,
    version: u32,
    capacity_sectors: u64,
    queue: VirtQueue,
    req_page: u64, // 4 KiB DMA-aligned scratch page for header + status + 512B sector bounce
}

impl VirtioBlk {
    /// Probe DTB VirtIO-MMIO slots and initialize the first `virtio-blk` device found.
    pub fn probe(dtb: &DeviceTreeInfo) -> Option<Self> {
        for i in 0..dtb.virtio_count {
            let slot = dtb.virtio_mmio[i];
            let base = slot.base as usize;
            let magic = mmio_read(base, MMIO_MAGIC_VALUE);
            if magic != VIRTIO_MAGIC {
                continue;
            }
            let dev_id = mmio_read(base, MMIO_DEVICE_ID);
            if dev_id != VIRTIO_DEV_BLK {
                continue;
            }
            let version = mmio_read(base, MMIO_VERSION);

            // Reset device
            mmio_write(base, MMIO_STATUS, 0);
            mmio_write(base, MMIO_STATUS, STATUS_ACK | STATUS_DRIVER);

            // Negotiate features (we only require VIRTIO_F_VERSION_1 for v2, none for v1)
            mmio_write(base, MMIO_DEVICE_FEATURES_SEL, 0);
            let _feat_lo = mmio_read(base, MMIO_DEVICE_FEATURES);
            mmio_write(base, MMIO_DRIVER_FEATURES_SEL, 0);
            mmio_write(base, MMIO_DRIVER_FEATURES, 0);

            if version >= 2 {
                mmio_write(base, MMIO_DEVICE_FEATURES_SEL, 1);
                let feat_hi = mmio_read(base, MMIO_DEVICE_FEATURES);
                mmio_write(base, MMIO_DRIVER_FEATURES_SEL, 1);
                mmio_write(base, MMIO_DRIVER_FEATURES, feat_hi & VIRTIO_F_VERSION_1);
                mmio_write(
                    base,
                    MMIO_STATUS,
                    STATUS_ACK | STATUS_DRIVER | STATUS_FEATURES_OK,
                );
                if (mmio_read(base, MMIO_STATUS) & STATUS_FEATURES_OK) == 0 {
                    klog!(LogLevel::Warn, "virtio-blk", "Features negotiation failed at {:#x}", base);
                    continue;
                }
            }

            let queue = match VirtQueue::allocate(base, version, 0) {
                Ok(q) => q,
                Err(e) => {
                    klog!(LogLevel::Error, "virtio-blk", "Queue alloc failed: {}", e);
                    continue;
                }
            };

            let req_page = match phys::alloc_frame() {
                Some(p) => p,
                None => continue,
            };

            // Read 64-bit capacity (in 512-byte sectors) from config space offset 0
            let cap_lo = mmio_read(base, MMIO_CONFIG) as u64;
            let cap_hi = mmio_read(base, MMIO_CONFIG + 4) as u64;
            let capacity_sectors = cap_lo | (cap_hi << 32);

            mmio_write(
                base,
                MMIO_STATUS,
                if version >= 2 {
                    STATUS_ACK | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK
                } else {
                    STATUS_ACK | STATUS_DRIVER | STATUS_DRIVER_OK
                },
            );

            klog!(
                LogLevel::Info,
                "virtio-blk",
                "Attached virtio-blk v{} at {:#x} (irq={:?}, capacity={} sectors / {} MiB)",
                version,
                base,
                slot.irq,
                capacity_sectors,
                (capacity_sectors * 512) / (1024 * 1024)
            );

            return Some(Self {
                mmio_base: base,
                version,
                capacity_sectors,
                queue,
                req_page,
            });
        }
        None
    }

    fn do_rw_sector(&mut self, lba: u64, buf: &mut [u8], is_write: bool) -> Result<(), BlockError> {
        if buf.len() != 512 {
            return Err(BlockError::InvalidSize);
        }
        if lba >= self.capacity_sectors {
            return Err(BlockError::OutOfBounds);
        }

        // Layout inside `req_page` (4 KiB):
        //   0x000..0x010 : VirtioBlkReqHeader (16 bytes)
        //   0x100..0x300 : 512-byte DMA sector bounce buffer
        //   0x300        : 1-byte status
        let hdr_va = self.req_page as usize;
        let data_va = hdr_va + 0x100;
        let status_va = hdr_va + 0x300;

        unsafe {
            let hdr = &mut *(hdr_va as *mut VirtioBlkReqHeader);
            hdr.req_type = if is_write {
                VIRTIO_BLK_T_OUT
            } else {
                VIRTIO_BLK_T_IN
            };
            hdr.reserved = 0;
            hdr.sector = lba;

            if is_write {
                core::ptr::copy_nonoverlapping(buf.as_ptr(), data_va as *mut u8, 512);
            }
            write_volatile(status_va as *mut u8, 0xFF);

            let d0 = &mut *self.queue.desc.add(0);
            let d1 = &mut *self.queue.desc.add(1);
            let d2 = &mut *self.queue.desc.add(2);

            d0.addr = virt_to_phys(hdr_va);
            d0.len = 16;
            d0.flags = VIRTQ_DESC_F_NEXT;
            d0.next = 1;

            d1.addr = virt_to_phys(data_va);
            d1.len = 512;
            d1.flags = VIRTQ_DESC_F_NEXT | if is_write { 0 } else { VIRTQ_DESC_F_WRITE };
            d1.next = 2;

            d2.addr = virt_to_phys(status_va);
            d2.len = 1;
            d2.flags = VIRTQ_DESC_F_WRITE;
            d2.next = 0;

            let avail = &mut *self.queue.avail;
            let ring_slot = (self.queue.avail_idx as usize) % QUEUE_SIZE;
            avail.ring[ring_slot] = 0;
            arch::dsb_sy();
            self.queue.avail_idx = self.queue.avail_idx.wrapping_add(1);
            write_volatile(&mut avail.idx, self.queue.avail_idx);
            arch::dsb_sy();

            mmio_write(self.mmio_base, MMIO_QUEUE_NOTIFY, 0);

            let used = &*self.queue.used;
            let mut timeout = 5_000_000u32;
            while read_volatile(&used.idx) == self.queue.last_used_idx {
                if timeout == 0 {
                    return Err(BlockError::IoError);
                }
                timeout -= 1;
                core::hint::spin_loop();
            }
            self.queue.last_used_idx = self.queue.last_used_idx.wrapping_add(1);

            let isr = mmio_read(self.mmio_base, MMIO_INTERRUPT_STATUS);
            if isr != 0 {
                mmio_write(self.mmio_base, MMIO_INTERRUPT_ACK, isr);
            }

            let status = read_volatile(status_va as *const u8);
            if status != 0 {
                return Err(BlockError::IoError);
            }

            if !is_write {
                core::ptr::copy_nonoverlapping(data_va as *const u8, buf.as_mut_ptr(), 512);
            }
        }

        let _ = self.version;
        Ok(())
    }
}

impl BlockDevice for VirtioBlk {
    fn name(&self) -> &str {
        "virtio-blk0"
    }

    fn block_size(&self) -> usize {
        512
    }

    fn block_count(&self) -> u64 {
        self.capacity_sectors
    }

    fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        if buf.len() % 512 != 0 {
            return Err(BlockError::InvalidSize);
        }
        let sectors = buf.len() / 512;
        if lba.checked_add(sectors as u64).ok_or(BlockError::OutOfBounds)? > self.capacity_sectors {
            return Err(BlockError::OutOfBounds);
        }
        for i in 0..sectors {
            let off = i * 512;
            self.do_rw_sector(lba + i as u64, &mut buf[off..off + 512], false)?;
        }
        Ok(())
    }

    fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        if buf.len() % 512 != 0 {
            return Err(BlockError::InvalidSize);
        }
        let sectors = buf.len() / 512;
        if lba.checked_add(sectors as u64).ok_or(BlockError::OutOfBounds)? > self.capacity_sectors {
            return Err(BlockError::OutOfBounds);
        }
        let mut scratch = [0u8; 512];
        for i in 0..sectors {
            let off = i * 512;
            scratch.copy_from_slice(&buf[off..off + 512]);
            self.do_rw_sector(lba + i as u64, &mut scratch, true)?;
        }
        Ok(())
    }
}
