//! VirtIO Entropy (`virtio-rng`) MMIO Driver (v1 & v2).
//!
//! Discovers VirtIO RNG devices (`device_id = 4`) dynamically from DTB `virtio,mmio` slots
//! and fills kernel entropy buffers synchronously over virtqueue 0.

use core::ptr::{read_volatile, write_volatile};

use crate::arch;
use crate::drivers::dtb::DeviceTreeInfo;
use crate::klog;
use crate::log::LogLevel;
use crate::memory::phys;

use super::{
    mmio_read, mmio_write, virt_to_phys, VirtQueue, MMIO_DEVICE_FEATURES,
    MMIO_DEVICE_FEATURES_SEL, MMIO_DEVICE_ID, MMIO_DRIVER_FEATURES, MMIO_DRIVER_FEATURES_SEL,
    MMIO_INTERRUPT_ACK, MMIO_INTERRUPT_STATUS, MMIO_MAGIC_VALUE, MMIO_QUEUE_NOTIFY, MMIO_STATUS,
    MMIO_VERSION, QUEUE_SIZE, STATUS_ACK, STATUS_DRIVER, STATUS_DRIVER_OK, STATUS_FEATURES_OK,
    VIRTIO_DEV_RNG, VIRTIO_MAGIC, VIRTQ_DESC_F_WRITE,
};

const VIRTIO_F_VERSION_1: u32 = 1 << 0; // feature word 1 (bit 32)

pub struct VirtioRng {
    mmio_base: usize,
    version: u32,
    queue: VirtQueue,
    buf_page: u64,
}

impl VirtioRng {
    /// Probe DTB `virtio,mmio` slots for the first `virtio-rng` device.
    pub fn probe(dtb: &DeviceTreeInfo) -> Option<Self> {
        for i in 0..dtb.virtio_count {
            let slot = dtb.virtio_mmio[i];
            let base = slot.base as usize;
            if mmio_read(base, MMIO_MAGIC_VALUE) != VIRTIO_MAGIC {
                continue;
            }
            if mmio_read(base, MMIO_DEVICE_ID) != VIRTIO_DEV_RNG {
                continue;
            }
            let version = mmio_read(base, MMIO_VERSION);

            // Reset device
            mmio_write(base, MMIO_STATUS, 0);
            mmio_write(base, MMIO_STATUS, STATUS_ACK | STATUS_DRIVER);

            mmio_write(base, MMIO_DEVICE_FEATURES_SEL, 0);
            let _ = mmio_read(base, MMIO_DEVICE_FEATURES);
            mmio_write(base, MMIO_DRIVER_FEATURES_SEL, 0);
            mmio_write(base, MMIO_DRIVER_FEATURES, 0);

            if version >= 2 {
                mmio_write(base, MMIO_DEVICE_FEATURES_SEL, 1);
                let feat_hi = mmio_read(base, MMIO_DEVICE_FEATURES);
                let drv_hi = feat_hi & VIRTIO_F_VERSION_1;
                mmio_write(base, MMIO_DRIVER_FEATURES_SEL, 1);
                mmio_write(base, MMIO_DRIVER_FEATURES, drv_hi);

                mmio_write(
                    base,
                    MMIO_STATUS,
                    STATUS_ACK | STATUS_DRIVER | STATUS_FEATURES_OK,
                );
                if (mmio_read(base, MMIO_STATUS) & STATUS_FEATURES_OK) == 0 {
                    klog!(
                        LogLevel::Warn,
                        "virtio-rng",
                        "Features negotiation failed at {:#x}",
                        base
                    );
                    continue;
                }
            }

            let queue = match VirtQueue::allocate(base, version, 0) {
                Ok(q) => q,
                Err(e) => {
                    klog!(LogLevel::Error, "virtio-rng", "Queue alloc failed: {}", e);
                    continue;
                }
            };

            let Some(buf_page) = phys::alloc_frame() else {
                return None;
            };

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
                "virtio-rng",
                "Attached virtio-rng v{} at {:#x} (irq={:?})",
                version,
                base,
                slot.irq
            );

            return Some(Self {
                mmio_base: base,
                version,
                queue,
                buf_page,
            });
        }
        None
    }

    fn ack_irq(&self) {
        let isr = mmio_read(self.mmio_base, MMIO_INTERRUPT_STATUS);
        if isr != 0 {
            mmio_write(self.mmio_base, MMIO_INTERRUPT_ACK, isr);
        }
    }

    /// Synchronously request entropy bytes from the VirtIO-RNG device.
    pub fn read_entropy(&mut self, out: &mut [u8]) -> Result<usize, &'static str> {
        let _ = self.version;
        if out.is_empty() {
            return Ok(0);
        }

        let mut filled = 0usize;
        while filled < out.len() {
            let chunk = (out.len() - filled).min(256);
            unsafe {
                let d = &mut *self.queue.desc.add(0);
                d.addr = virt_to_phys(self.buf_page as usize);
                d.len = chunk as u32;
                d.flags = VIRTQ_DESC_F_WRITE;
                d.next = 0;

                let avail = &mut *self.queue.avail;
                let slot = (self.queue.avail_idx as usize) % QUEUE_SIZE;
                avail.ring[slot] = 0;
                arch::dsb_sy();
                self.queue.avail_idx = self.queue.avail_idx.wrapping_add(1);
                write_volatile(&mut avail.idx, self.queue.avail_idx);
                arch::dsb_sy();

                mmio_write(self.mmio_base, MMIO_QUEUE_NOTIFY, 0);

                let used = &*self.queue.used;
                let mut timeout = 5_000_000u32;
                while read_volatile(&used.idx) == self.queue.last_used_idx {
                    if timeout == 0 {
                        return Err("VirtIO-RNG timeout");
                    }
                    timeout -= 1;
                    core::hint::spin_loop();
                }

                let ring_pos = (self.queue.last_used_idx as usize) % QUEUE_SIZE;
                let elem = read_volatile(&used.ring[ring_pos]);
                self.queue.last_used_idx = self.queue.last_used_idx.wrapping_add(1);
                self.ack_irq();

                let got = (elem.len as usize).min(chunk);
                if got == 0 {
                    break;
                }
                core::ptr::copy_nonoverlapping(
                    self.buf_page as *const u8,
                    out[filled..].as_mut_ptr(),
                    got,
                );
                filled += got;
            }
        }
        Ok(filled)
    }
}
