//! VirtIO Network (`virtio-net`) MMIO Driver (v1 & v2).

use core::ptr::{read_volatile, write_bytes, write_volatile};

use crate::arch;
use crate::drivers::dtb::DeviceTreeInfo;
use crate::drivers::net::{NetDevice, NetError};
use crate::klog;
use crate::log::LogLevel;
use crate::memory::phys;

use super::{
    mmio_read, mmio_write, virt_to_phys, VirtQueue, MMIO_CONFIG, MMIO_DEVICE_FEATURES,
    MMIO_DEVICE_FEATURES_SEL, MMIO_DEVICE_ID, MMIO_DRIVER_FEATURES, MMIO_DRIVER_FEATURES_SEL,
    MMIO_INTERRUPT_ACK, MMIO_INTERRUPT_STATUS, MMIO_MAGIC_VALUE, MMIO_QUEUE_NOTIFY, MMIO_STATUS,
    MMIO_VERSION, QUEUE_SIZE, STATUS_ACK, STATUS_DRIVER, STATUS_DRIVER_OK, STATUS_FEATURES_OK,
    VIRTIO_DEV_NET, VIRTIO_MAGIC, VIRTQ_DESC_F_WRITE,
};

const VIRTIO_NET_F_MAC: u32 = 1 << 5;
const VIRTIO_NET_F_STATUS: u32 = 1 << 16;
const VIRTIO_F_VERSION_1: u32 = 1 << 0; // feature word 1 (bit 32)
const RX_SLOT_BYTES: usize = 2048;

pub struct VirtioNet {
    mmio_base: usize,
    version: u32,
    irq: Option<u32>,
    has_status: bool,
    mac: [u8; 6],
    hdr_len: usize,
    rx_queue: VirtQueue,
    tx_queue: VirtQueue,
    rx_buf_pages: [u64; QUEUE_SIZE / 2], // 2 slots of 2048 bytes per 4K page
    tx_page: u64,
}

impl VirtioNet {
    /// Probe DTB `virtio,mmio` slots and initialize the first `virtio-net` device found.
    pub fn probe(dtb: &DeviceTreeInfo) -> Option<Self> {
        for i in 0..dtb.virtio_count {
            let slot = dtb.virtio_mmio[i];
            let base = slot.base as usize;
            if mmio_read(base, MMIO_MAGIC_VALUE) != VIRTIO_MAGIC {
                continue;
            }
            if mmio_read(base, MMIO_DEVICE_ID) != VIRTIO_DEV_NET {
                continue;
            }
            let version = mmio_read(base, MMIO_VERSION);

            // Reset device
            mmio_write(base, MMIO_STATUS, 0);
            mmio_write(base, MMIO_STATUS, STATUS_ACK | STATUS_DRIVER);

            // Negotiate MAC + Status (word 0)
            mmio_write(base, MMIO_DEVICE_FEATURES_SEL, 0);
            let feat_lo = mmio_read(base, MMIO_DEVICE_FEATURES);
            let drv_lo = feat_lo & (VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS);
            mmio_write(base, MMIO_DRIVER_FEATURES_SEL, 0);
            mmio_write(base, MMIO_DRIVER_FEATURES, drv_lo);

            let mut hdr_len = 10usize;
            if version >= 2 {
                mmio_write(base, MMIO_DEVICE_FEATURES_SEL, 1);
                let feat_hi = mmio_read(base, MMIO_DEVICE_FEATURES);
                let drv_hi = feat_hi & VIRTIO_F_VERSION_1;
                mmio_write(base, MMIO_DRIVER_FEATURES_SEL, 1);
                mmio_write(base, MMIO_DRIVER_FEATURES, drv_hi);
                if (drv_hi & VIRTIO_F_VERSION_1) != 0 {
                    hdr_len = 12;
                }
                mmio_write(
                    base,
                    MMIO_STATUS,
                    STATUS_ACK | STATUS_DRIVER | STATUS_FEATURES_OK,
                );
                if (mmio_read(base, MMIO_STATUS) & STATUS_FEATURES_OK) == 0 {
                    klog!(LogLevel::Warn, "virtio-net", "Features negotiation failed at {:#x}", base);
                    continue;
                }
            }

            let mut rx_queue = match VirtQueue::allocate(base, version, 0) {
                Ok(q) => q,
                Err(e) => {
                    klog!(LogLevel::Error, "virtio-net", "RX queue alloc failed: {}", e);
                    continue;
                }
            };
            let tx_queue = match VirtQueue::allocate(base, version, 1) {
                Ok(q) => q,
                Err(e) => {
                    klog!(LogLevel::Error, "virtio-net", "TX queue alloc failed: {}", e);
                    continue;
                }
            };

            let mut rx_buf_pages = [0u64; QUEUE_SIZE / 2];
            for p in rx_buf_pages.iter_mut() {
                *p = match phys::alloc_frame() {
                    Some(pa) => pa,
                    None => return None,
                };
            }
            let tx_page = phys::alloc_frame()?;

            // Read 6-byte MAC address from config space (MMIO_CONFIG + 0..6)
            let mut mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
            if (drv_lo & VIRTIO_NET_F_MAC) != 0 {
                let w0 = mmio_read(base, MMIO_CONFIG);
                let w1 = mmio_read(base, MMIO_CONFIG + 4);
                mac[0] = (w0 & 0xFF) as u8;
                mac[1] = ((w0 >> 8) & 0xFF) as u8;
                mac[2] = ((w0 >> 16) & 0xFF) as u8;
                mac[3] = ((w0 >> 24) & 0xFF) as u8;
                mac[4] = (w1 & 0xFF) as u8;
                mac[5] = ((w1 >> 8) & 0xFF) as u8;
            }

            // Pre-populate all RX descriptors and notify queue 0
            unsafe {
                let avail = &mut *rx_queue.avail;
                for idx in 0..QUEUE_SIZE {
                    let page = rx_buf_pages[idx / 2];
                    let off = (idx % 2) * RX_SLOT_BYTES;
                    let buf_va = (page as usize) + off;
                    let d = &mut *rx_queue.desc.add(idx);
                    d.addr = virt_to_phys(buf_va);
                    d.len = RX_SLOT_BYTES as u32;
                    d.flags = VIRTQ_DESC_F_WRITE;
                    d.next = 0;
                    avail.ring[idx] = idx as u16;
                }
                rx_queue.avail_idx = QUEUE_SIZE as u16;
                arch::dsb_sy();
                write_volatile(&mut avail.idx, rx_queue.avail_idx);
                arch::dsb_sy();
            }

            mmio_write(
                base,
                MMIO_STATUS,
                if version >= 2 {
                    STATUS_ACK | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK
                } else {
                    STATUS_ACK | STATUS_DRIVER | STATUS_DRIVER_OK
                },
            );
            mmio_write(base, MMIO_QUEUE_NOTIFY, 0);

            klog!(
                LogLevel::Info,
                "virtio-net",
                "Attached virtio-net v{} at {:#x} (irq={:?}, hdr={}B, MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})",
                version,
                base,
                slot.irq,
                hdr_len,
                mac[0],
                mac[1],
                mac[2],
                mac[3],
                mac[4],
                mac[5]
            );

            return Some(Self {
                mmio_base: base,
                version,
                irq: slot.irq,
                has_status: (drv_lo & VIRTIO_NET_F_STATUS) != 0,
                mac,
                hdr_len,
                rx_queue,
                tx_queue,
                rx_buf_pages,
                tx_page,
            });
        }
        None
    }

    pub fn irq(&self) -> Option<u32> {
        self.irq
    }

    pub fn ack_irq(&self) {
        let isr = mmio_read(self.mmio_base, MMIO_INTERRUPT_STATUS);
        if isr != 0 {
            mmio_write(self.mmio_base, MMIO_INTERRUPT_ACK, isr);
        }
    }

    fn rx_slot_va(&self, idx: usize) -> usize {
        let page = self.rx_buf_pages[idx / 2];
        (page as usize) + (idx % 2) * RX_SLOT_BYTES
    }
}

impl NetDevice for VirtioNet {
    fn name(&self) -> &str {
        "virtio-net0"
    }

    fn mac_addr(&self) -> [u8; 6] {
        self.mac
    }

    fn link_up(&self) -> bool {
        let _ = self.version;
        if self.has_status {
            let status_word = mmio_read(self.mmio_base, MMIO_CONFIG + 4);
            let link_status = (status_word >> 16) & 0xFFFF;
            (link_status & 1) != 0
        } else {
            true
        }
    }

    fn send_frame(&mut self, frame: &[u8]) -> Result<(), NetError> {
        if frame.len() + self.hdr_len > 2048 {
            return Err(NetError::FrameTooLarge);
        }

        let tx_va = self.tx_page as usize;
        let total_len = self.hdr_len + frame.len();

        unsafe {
            write_bytes(tx_va as *mut u8, 0, self.hdr_len);
            core::ptr::copy_nonoverlapping(
                frame.as_ptr(),
                (tx_va + self.hdr_len) as *mut u8,
                frame.len(),
            );

            let d = &mut *self.tx_queue.desc.add(0);
            d.addr = virt_to_phys(tx_va);
            d.len = total_len as u32;
            d.flags = 0;
            d.next = 0;

            let avail = &mut *self.tx_queue.avail;
            let slot = (self.tx_queue.avail_idx as usize) % QUEUE_SIZE;
            avail.ring[slot] = 0;
            arch::dsb_sy();
            self.tx_queue.avail_idx = self.tx_queue.avail_idx.wrapping_add(1);
            write_volatile(&mut avail.idx, self.tx_queue.avail_idx);
            arch::dsb_sy();

            mmio_write(self.mmio_base, MMIO_QUEUE_NOTIFY, 1);

            let used = &*self.tx_queue.used;
            let mut timeout = 5_000_000u32;
            while read_volatile(&used.idx) == self.tx_queue.last_used_idx {
                if timeout == 0 {
                    return Err(NetError::TxTimeout);
                }
                timeout -= 1;
                core::hint::spin_loop();
            }
            self.tx_queue.last_used_idx = self.tx_queue.last_used_idx.wrapping_add(1);
        }

        self.ack_irq();
        Ok(())
    }

    fn recv_frame(&mut self, out: &mut [u8]) -> Option<usize> {
        unsafe {
            arch::dsb_sy();
            let used = &*self.rx_queue.used;
            let used_idx = read_volatile(&used.idx);
            if used_idx == self.rx_queue.last_used_idx {
                return None;
            }

            let ring_pos = (self.rx_queue.last_used_idx as usize) % QUEUE_SIZE;
            let elem = read_volatile(&used.ring[ring_pos]);
            let desc_id = (elem.id as usize) % QUEUE_SIZE;
            let total_len = elem.len as usize;

            let payload_len = total_len.saturating_sub(self.hdr_len);
            let copy_len = payload_len.min(out.len());
            if copy_len > 0 {
                let src = (self.rx_slot_va(desc_id) + self.hdr_len) as *const u8;
                core::ptr::copy_nonoverlapping(src, out.as_mut_ptr(), copy_len);
            }

            // Re-post descriptor back to RX available ring
            let d = &mut *self.rx_queue.desc.add(desc_id);
            d.addr = virt_to_phys(self.rx_slot_va(desc_id));
            d.len = RX_SLOT_BYTES as u32;
            d.flags = VIRTQ_DESC_F_WRITE;
            d.next = 0;

            let avail = &mut *self.rx_queue.avail;
            let avail_slot = (self.rx_queue.avail_idx as usize) % QUEUE_SIZE;
            avail.ring[avail_slot] = desc_id as u16;
            arch::dsb_sy();
            self.rx_queue.avail_idx = self.rx_queue.avail_idx.wrapping_add(1);
            write_volatile(&mut avail.idx, self.rx_queue.avail_idx);
            arch::dsb_sy();

            self.rx_queue.last_used_idx = self.rx_queue.last_used_idx.wrapping_add(1);
            mmio_write(self.mmio_base, MMIO_QUEUE_NOTIFY, 0);
            self.ack_irq();

            if copy_len > 0 {
                Some(copy_len)
            } else {
                None
            }
        }
    }
}
