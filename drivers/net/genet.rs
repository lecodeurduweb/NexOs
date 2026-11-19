//! Raspberry Pi 4 (BCM2711) GENET v5 Gigabit Ethernet Driver.
//!
//! STATUS: COMPILÉ + TESTÉ PAR MOCK MMIO / NON TESTÉ SUR MATÉRIEL (QEMU 7.2 lacks `raspi4b`).
//! Discovered dynamically from DTB `compatible = "brcm,bcm2711-genet-v5"`.
//! Enforces 32-bit DMA descriptor addresses (`alloc_frame_below(0x1_0000_0000)`)
//! for BCM2711 peripheral DMA compatibility on 8 GiB boards.

#![allow(dead_code)]

use alloc::vec;
use core::ptr::{read_volatile, write_volatile};

use crate::drivers::net::{NetDevice, NetError};
use crate::klog;
use crate::log::LogLevel;
use crate::memory::phys;

// GENET v5 register block offsets (from DTB base, typically 0xFD58_0000)
const SYS_REV_CTRL: usize = 0x000;
const SYS_PORT_CTRL: usize = 0x004;
const SYS_RBUF_FLUSH_CTRL: usize = 0x008;
const SYS_TBUF_FLUSH_CTRL: usize = 0x00C;

const EXT_RGMII_OOB_CTRL: usize = 0x08C;

const INTRL2_0_STAT: usize = 0x200;
const INTRL2_0_SET: usize = 0x204;
const INTRL2_0_CLEAR: usize = 0x208;
const INTRL2_0_MASK_STATUS: usize = 0x20C;
const INTRL2_0_MASK_SET: usize = 0x210;
const INTRL2_0_MASK_CLEAR: usize = 0x214;

const UMAC_CMD: usize = 0x808;
const UMAC_MAC0: usize = 0x80C;
const UMAC_MAC1: usize = 0x810;
const UMAC_MAX_FRAME_LEN: usize = 0x814;
const UMAC_MIB_CTRL: usize = 0xD80;
const MDIO_CMD: usize = 0xE14;

// RDMA / TDMA descriptor & ring register bases
const RDMA_OFF: usize = 0x2000;
const TDMA_OFF: usize = 0x4000;
const DMA_RING_REG_BASE_OFF: usize = 0x0C00;
const DMA_RING_CFG_OFF: usize = 0x1040;
const DMA_CTRL_OFF: usize = 0x1044;
const DMA_STATUS_OFF: usize = 0x1048;

const DEFAULT_RING_IDX: usize = 16;
const RING_REG_STRIDE: usize = 0x40;
const RING_DESC_COUNT: usize = 16;
const RX_BUF_SIZE: u32 = 2048;

// RDMA per-ring register offsets
const RDMA_WRITE_PTR: usize = 0x00;
const RDMA_PROD_INDEX: usize = 0x08;
const RDMA_CONS_INDEX: usize = 0x0C;
const RDMA_RING_BUF_SIZE: usize = 0x10;
const RDMA_START_ADDR: usize = 0x14;
const RDMA_END_ADDR: usize = 0x1C;
const RDMA_MBUF_DONE_THRESH: usize = 0x24;
const RDMA_XON_XOFF_THRESH: usize = 0x28;
const RDMA_READ_PTR: usize = 0x2C;

// TDMA per-ring register offsets
const TDMA_READ_PTR: usize = 0x00;
const TDMA_CONS_INDEX: usize = 0x08;
const TDMA_PROD_INDEX: usize = 0x0C;
const TDMA_RING_BUF_SIZE: usize = 0x10;
const TDMA_START_ADDR: usize = 0x14;
const TDMA_END_ADDR: usize = 0x1C;
const TDMA_MBUF_DONE_THRESH: usize = 0x24;
const TDMA_FLOW_PERIOD: usize = 0x28;
const TDMA_WRITE_PTR: usize = 0x2C;

// UMAC_CMD bits
const CMD_TX_EN: u32 = 1 << 0;
const CMD_RX_EN: u32 = 1 << 1;
const CMD_SPEED_10: u32 = 0 << 2;
const CMD_SPEED_100: u32 = 1 << 2;
const CMD_SPEED_1000: u32 = 2 << 2;
const CMD_SW_RESET: u32 = 1 << 13;

// MDIO_CMD bits & MII registers
const MDIO_START_BUSY: u32 = 1 << 29;
const MDIO_READ: u32 = 1 << 27;
const MDIO_PMD_SHIFT: u32 = 21;
const MDIO_REG_SHIFT: u32 = 16;
const MII_BMSR: u32 = 1;
const MII_LPA: u32 = 5;
const MII_STAT1000: u32 = 10;

// Descriptor flags (length occupies bits [27:16])
const DMA_SOP: u32 = 1 << 13;
const DMA_EOP: u32 = 1 << 14;
const DMA_TX_APPEND_CRC: u32 = 1 << 6;
const DMA_TX_QTAG_MASK: u32 = 0x3F << 7;
const DMA_LEN_SHIFT: u32 = 16;

#[repr(C)]
#[derive(Clone, Copy)]
struct GenetDmaDesc {
    length_status: u32,
    address_lo: u32,
    address_hi: u32,
}

pub struct Bcm2711Genet {
    base: usize,
    mac: [u8; 6],
    dtb_mac_set: bool,
    initialized: bool,
    tx_prod_idx: u32,
    rx_cons_idx: u32,
    tx_bufs: [u64; RING_DESC_COUNT],
    rx_bufs: [u64; RING_DESC_COUNT],
}

impl Bcm2711Genet {
    pub fn new(base: usize) -> Self {
        Self {
            base,
            mac: [0; 6],
            dtb_mac_set: false,
            initialized: false,
            tx_prod_idx: 0,
            rx_cons_idx: 0,
            tx_bufs: [0; RING_DESC_COUNT],
            rx_bufs: [0; RING_DESC_COUNT],
        }
    }

    pub fn set_mac_addr(&mut self, mac: [u8; 6]) {
        if mac != [0; 6] {
            self.mac = mac;
            self.dtb_mac_set = true;
        }
    }

    #[inline(always)]
    fn read32(&self, off: usize) -> u32 {
        unsafe { read_volatile((self.base + off) as *const u32) }
    }

    #[inline(always)]
    fn write32(&self, off: usize, val: u32) {
        unsafe { write_volatile((self.base + off) as *mut u32, val) }
    }

    #[inline(always)]
    fn rdma_ring_off() -> usize {
        RDMA_OFF + DMA_RING_REG_BASE_OFF + DEFAULT_RING_IDX * RING_REG_STRIDE
    }

    #[inline(always)]
    fn tdma_ring_off() -> usize {
        TDMA_OFF + DMA_RING_REG_BASE_OFF + DEFAULT_RING_IDX * RING_REG_STRIDE
    }

    fn mdio_read(&self, phy_id: u32, reg: u32) -> Option<u16> {
        let cmd = MDIO_START_BUSY
            | MDIO_READ
            | ((phy_id & 0x1F) << MDIO_PMD_SHIFT)
            | ((reg & 0x1F) << MDIO_REG_SHIFT);
        self.write32(MDIO_CMD, cmd);
        for _ in 0..10_000 {
            let v = self.read32(MDIO_CMD);
            if (v & MDIO_START_BUSY) == 0 {
                return Some((v & 0xFFFF) as u16);
            }
            core::hint::spin_loop();
        }
        None
    }

    pub fn link_speed_mbps(&self) -> u32 {
        let bmsr = self.mdio_read(1, MII_BMSR).unwrap_or(0);
        if (bmsr & (1 << 2)) == 0 {
            return 0;
        }
        let stat1000 = self.mdio_read(1, MII_STAT1000).unwrap_or(0);
        if (stat1000 & ((1 << 11) | (1 << 10))) != 0 {
            return 1000;
        }
        let lpa = self.mdio_read(1, MII_LPA).unwrap_or(0);
        if (lpa & ((1 << 8) | (1 << 7))) != 0 {
            100
        } else {
            10
        }
    }

    pub fn free_rings(&mut self) {
        for i in 0..RING_DESC_COUNT {
            if self.tx_bufs[i] != 0 {
                let _ = phys::free_frame(self.tx_bufs[i]);
                self.tx_bufs[i] = 0;
            }
            if self.rx_bufs[i] != 0 {
                let _ = phys::free_frame(self.rx_bufs[i]);
                self.rx_bufs[i] = 0;
            }
        }
        self.initialized = false;
    }

    pub fn init(&mut self) -> Result<(), NetError> {
        let rev = self.read32(SYS_REV_CTRL);
        let major = (rev >> 24) & 0x0F;
        if major == 0 {
            return Err(NetError::HardwareError);
        }

        self.write32(INTRL2_0_MASK_SET, 0xFFFF_FFFF);
        self.write32(INTRL2_0_CLEAR, 0xFFFF_FFFF);

        self.write32(SYS_PORT_CTRL, 3);
        self.write32(SYS_RBUF_FLUSH_CTRL, 1 << 1);
        for _ in 0..1000 {
            core::hint::spin_loop();
        }
        self.write32(SYS_RBUF_FLUSH_CTRL, 0);
        self.write32(SYS_TBUF_FLUSH_CTRL, 0);

        self.write32(UMAC_CMD, CMD_SW_RESET);
        for _ in 0..1000 {
            core::hint::spin_loop();
        }
        self.write32(UMAC_CMD, 0);

        if !self.dtb_mac_set {
            let mac0 = self.read32(UMAC_MAC0);
            let mac1 = self.read32(UMAC_MAC1);
            self.mac = [
                ((mac0 >> 24) & 0xFF) as u8,
                ((mac0 >> 16) & 0xFF) as u8,
                ((mac0 >> 8) & 0xFF) as u8,
                (mac0 & 0xFF) as u8,
                ((mac1 >> 8) & 0xFF) as u8,
                (mac1 & 0xFF) as u8,
            ];
            if self.mac == [0; 6] {
                self.mac = [0xDC, 0xA6, 0x32, 0x4E, 0x45, 0x58];
            }
        }
        // Always program UMAC_MAC0/MAC1 with the active MAC (from DTB or firmware)
        self.write32(
            UMAC_MAC0,
            ((self.mac[0] as u32) << 24)
                | ((self.mac[1] as u32) << 16)
                | ((self.mac[2] as u32) << 8)
                | (self.mac[3] as u32),
        );
        self.write32(
            UMAC_MAC1,
            ((self.mac[4] as u32) << 8) | (self.mac[5] as u32),
        );

        self.write32(UMAC_MAX_FRAME_LEN, 1536);
        self.write32(UMAC_MIB_CTRL, 0x7);
        self.write32(UMAC_MIB_CTRL, 0);

        for i in 0..RING_DESC_COUNT {
            let Some(tx) = phys::alloc_frame_below(0x1_0000_0000) else {
                self.free_rings();
                return Err(NetError::HardwareError);
            };
            self.tx_bufs[i] = tx;
            let Some(rx) = phys::alloc_frame_below(0x1_0000_0000) else {
                self.free_rings();
                return Err(NetError::HardwareError);
            };
            self.rx_bufs[i] = rx;
            crate::arch::mmu::dcache_invalidate_range(
                self.rx_bufs[i] as usize,
                RX_BUF_SIZE as usize,
            );
        }

        self.write32(RDMA_OFF + DMA_CTRL_OFF, 0);
        self.write32(TDMA_OFF + DMA_CTRL_OFF, 0);

        for i in 0..RING_DESC_COUNT {
            let desc = GenetDmaDesc {
                length_status: RX_BUF_SIZE << DMA_LEN_SHIFT,
                address_lo: self.rx_bufs[i] as u32,
                address_hi: (self.rx_bufs[i] >> 32) as u32,
            };
            unsafe {
                write_volatile((self.base + RDMA_OFF + i * 12) as *mut GenetDmaDesc, desc);
            }
        }

        let r_off = Self::rdma_ring_off();
        let ring_words_end = (RING_DESC_COUNT as u32) * 3 - 1;
        self.write32(r_off + RDMA_WRITE_PTR, 0);
        self.write32(r_off + RDMA_READ_PTR, 0);
        self.write32(r_off + RDMA_PROD_INDEX, 0);
        self.write32(r_off + RDMA_CONS_INDEX, 0);
        self.write32(
            r_off + RDMA_RING_BUF_SIZE,
            ((RING_DESC_COUNT as u32) << 16) | RX_BUF_SIZE,
        );
        self.write32(r_off + RDMA_START_ADDR, 0);
        self.write32(r_off + RDMA_END_ADDR, ring_words_end);
        self.write32(r_off + RDMA_MBUF_DONE_THRESH, 1);
        self.write32(r_off + RDMA_XON_XOFF_THRESH, (5 << 16) | 16);

        let t_off = Self::tdma_ring_off();
        self.write32(t_off + TDMA_READ_PTR, 0);
        self.write32(t_off + TDMA_WRITE_PTR, 0);
        self.write32(t_off + TDMA_CONS_INDEX, 0);
        self.write32(t_off + TDMA_PROD_INDEX, 0);
        self.write32(
            t_off + TDMA_RING_BUF_SIZE,
            ((RING_DESC_COUNT as u32) << 16) | RX_BUF_SIZE,
        );
        self.write32(t_off + TDMA_START_ADDR, 0);
        self.write32(t_off + TDMA_END_ADDR, ring_words_end);
        self.write32(t_off + TDMA_MBUF_DONE_THRESH, 1);
        self.write32(t_off + TDMA_FLOW_PERIOD, 0);

        self.tx_prod_idx = 0;
        self.rx_cons_idx = 0;

        self.write32(RDMA_OFF + DMA_RING_CFG_OFF, 1 << DEFAULT_RING_IDX);
        self.write32(TDMA_OFF + DMA_RING_CFG_OFF, 1 << DEFAULT_RING_IDX);
        self.write32(RDMA_OFF + DMA_CTRL_OFF, (1 << (DEFAULT_RING_IDX + 1)) | 1);
        self.write32(TDMA_OFF + DMA_CTRL_OFF, (1 << (DEFAULT_RING_IDX + 1)) | 1);

        let oob = self.read32(EXT_RGMII_OOB_CTRL);
        self.write32(EXT_RGMII_OOB_CTRL, oob | (1 << 4) | (1 << 6));

        let speed = self.link_speed_mbps();
        let speed_bits = match speed {
            10 => CMD_SPEED_10,
            100 => CMD_SPEED_100,
            _ => CMD_SPEED_1000,
        };
        self.write32(UMAC_CMD, speed_bits | CMD_TX_EN | CMD_RX_EN);

        let phy_bmsr = self.mdio_read(1, MII_BMSR).unwrap_or(0);
        self.initialized = true;

        klog!(
            LogLevel::Info,
            "genet",
            "BCM2711 GENET v5 initialized at {:#x} rev={:#x} MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} BMSR={:#06x} speed={}Mbps [NON TESTÉ SUR MATÉRIEL]",
            self.base,
            rev,
            self.mac[0],
            self.mac[1],
            self.mac[2],
            self.mac[3],
            self.mac[4],
            self.mac[5],
            phy_bmsr,
            speed
        );
        Ok(())
    }
}

impl NetDevice for Bcm2711Genet {
    fn name(&self) -> &str {
        "bcm2711-genet0"
    }

    fn mac_addr(&self) -> [u8; 6] {
        self.mac
    }

    fn link_up(&self) -> bool {
        if !self.initialized {
            return false;
        }
        (self.mdio_read(1, MII_BMSR).unwrap_or(0) & (1 << 2)) != 0
    }

    fn send_frame(&mut self, frame: &[u8]) -> Result<(), NetError> {
        if !self.initialized {
            return Err(NetError::NotInitialized);
        }
        if frame.len() > 1518 {
            return Err(NetError::FrameTooLarge);
        }

        let t_off = Self::tdma_ring_off();
        let mut timeout = 500_000u32;
        loop {
            let cons = self.read32(t_off + TDMA_CONS_INDEX) & 0xFFFF;
            let in_flight = (self.tx_prod_idx & 0xFFFF).wrapping_sub(cons);
            if (in_flight as usize) < RING_DESC_COUNT {
                break;
            }
            if timeout == 0 {
                return Err(NetError::TxTimeout);
            }
            timeout -= 1;
            core::hint::spin_loop();
        }

        let idx = (self.tx_prod_idx as usize) % RING_DESC_COUNT;
        let buf_pa = self.tx_bufs[idx];
        unsafe {
            core::ptr::copy_nonoverlapping(frame.as_ptr(), buf_pa as *mut u8, frame.len());
        }
        crate::arch::mmu::dcache_clean_range(buf_pa as usize, frame.len());

        let desc_addr = self.base + TDMA_OFF + idx * 12;
        let desc = GenetDmaDesc {
            length_status: ((frame.len() as u32) << DMA_LEN_SHIFT)
                | DMA_TX_QTAG_MASK
                | DMA_SOP
                | DMA_EOP
                | DMA_TX_APPEND_CRC,
            address_lo: buf_pa as u32,
            address_hi: (buf_pa >> 32) as u32,
        };
        unsafe {
            write_volatile(desc_addr as *mut GenetDmaDesc, desc);
        }
        crate::arch::dsb_sy();

        self.tx_prod_idx = (self.tx_prod_idx + 1) & 0xFFFF;
        self.write32(t_off + TDMA_PROD_INDEX, self.tx_prod_idx);
        Ok(())
    }

    fn recv_frame(&mut self, out: &mut [u8]) -> Option<usize> {
        if !self.initialized {
            return None;
        }
        let r_off = Self::rdma_ring_off();
        let prod = self.read32(r_off + RDMA_PROD_INDEX) & 0xFFFF;
        if prod == (self.rx_cons_idx & 0xFFFF) {
            return None;
        }

        let idx = (self.rx_cons_idx as usize) % RING_DESC_COUNT;
        let desc_addr = self.base + RDMA_OFF + idx * 12;
        let desc = unsafe { read_volatile(desc_addr as *const GenetDmaDesc) };
        let len = ((desc.length_status >> DMA_LEN_SHIFT) & 0x0FFF) as usize;
        let rx_err = (desc.length_status & 0x3F) != 0;
        let single_pkt = (desc.length_status & (DMA_SOP | DMA_EOP)) == (DMA_SOP | DMA_EOP);

        let copy_len = if !rx_err && single_pkt && len > 0 && len <= 1536 {
            crate::arch::mmu::dcache_invalidate_range(
                self.rx_bufs[idx] as usize,
                len.min(RX_BUF_SIZE as usize),
            );
            let n = len.min(out.len());
            if n > 0 {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        self.rx_bufs[idx] as *const u8,
                        out.as_mut_ptr(),
                        n,
                    );
                }
            }
            n
        } else {
            0
        };

        let reset = GenetDmaDesc {
            length_status: RX_BUF_SIZE << DMA_LEN_SHIFT,
            address_lo: self.rx_bufs[idx] as u32,
            address_hi: (self.rx_bufs[idx] >> 32) as u32,
        };
        unsafe {
            write_volatile(desc_addr as *mut GenetDmaDesc, reset);
        }
        crate::arch::dsb_sy();

        self.rx_cons_idx = (self.rx_cons_idx + 1) & 0xFFFF;
        self.write32(r_off + RDMA_CONS_INDEX, self.rx_cons_idx);
        if copy_len > 0 {
            Some(copy_len)
        } else {
            None
        }
    }
}

/// Deterministic MMIO ring & MAC self-test for `Bcm2711Genet` (runs in QEMU without Pi 4 HW).
pub fn self_test_mock() -> Result<(), NetError> {
    let mut mock_mmio = vec![0u8; 0x5400];
    let base = mock_mmio.as_mut_ptr() as usize;

    let mut genet = Bcm2711Genet::new(base);
    // Should reject uninitialized send & invalid rev=0
    if genet.send_frame(&[0u8; 64]) != Err(NetError::NotInitialized) {
        return Err(NetError::HardwareError);
    }
    if genet.init() != Err(NetError::HardwareError) {
        return Err(NetError::HardwareError);
    }

    // Populate GENET v5 revision & simulate DTB MAC address + simulated TX/RX ring
    unsafe {
        write_volatile((base + SYS_REV_CTRL) as *mut u32, 0x0600_0000);
    }
    let test_mac = [0xDC, 0xA6, 0x32, 0x11, 0x22, 0x33];
    genet.set_mac_addr(test_mac);
    genet.init()?;

    if genet.mac_addr() != test_mac {
        genet.free_rings();
        return Err(NetError::HardwareError);
    }
    // Check UMAC_MAC0/MAC1 registers were programmed
    let mac0 = unsafe { read_volatile((base + UMAC_MAC0) as *const u32) };
    let mac1 = unsafe { read_volatile((base + UMAC_MAC1) as *const u32) };
    if mac0 != 0xDCA6_3211 || mac1 != 0x2233 {
        genet.free_rings();
        return Err(NetError::HardwareError);
    }

    // Simulate TX frame
    let tx_pkt = [0xABu8; 64];
    genet.send_frame(&tx_pkt)?;
    let prod = unsafe { read_volatile((base + Bcm2711Genet::tdma_ring_off() + TDMA_PROD_INDEX) as *const u32) };
    if prod != 1 {
        genet.free_rings();
        return Err(NetError::HardwareError);
    }

    // Simulate RX frame in ring slot 0
    let rx_pa = genet.rx_bufs[0];
    unsafe {
        core::ptr::copy_nonoverlapping(tx_pkt.as_ptr(), rx_pa as *mut u8, 64);
        write_volatile(
            (base + RDMA_OFF) as *mut GenetDmaDesc,
            GenetDmaDesc {
                length_status: (64u32 << DMA_LEN_SHIFT) | DMA_SOP | DMA_EOP,
                address_lo: rx_pa as u32,
                address_hi: (rx_pa >> 32) as u32,
            },
        );
        write_volatile(
            (base + Bcm2711Genet::rdma_ring_off() + RDMA_PROD_INDEX) as *mut u32,
            1,
        );
    }

    let mut rx_out = [0u8; 128];
    let n = genet.recv_frame(&mut rx_out).ok_or(NetError::HardwareError)?;
    if n != 64 || rx_out[..64] != tx_pkt {
        genet.free_rings();
        return Err(NetError::HardwareError);
    }

    // Simulate corrupt RX descriptor (CRC error bit 1 set) in slot 1 -> must drop cleanly
    let rx_pa1 = genet.rx_bufs[1];
    unsafe {
        write_volatile(
            (base + RDMA_OFF + 12) as *mut GenetDmaDesc,
            GenetDmaDesc {
                length_status: (64u32 << DMA_LEN_SHIFT) | DMA_SOP | DMA_EOP | 0x02,
                address_lo: rx_pa1 as u32,
                address_hi: (rx_pa1 >> 32) as u32,
            },
        );
        write_volatile(
            (base + Bcm2711Genet::rdma_ring_off() + RDMA_PROD_INDEX) as *mut u32,
            2,
        );
    }
    if genet.recv_frame(&mut rx_out).is_some() {
        genet.free_rings();
        return Err(NetError::HardwareError);
    }

    genet.free_rings();
    Ok(())
}
