//! Raspberry Pi 4 (BCM2711) EMMC2 / SDHCI Host Controller Driver.
//!
//! STATUS: COMPILÉ + TESTÉ PAR MOCK MMIO / NON TESTÉ SUR MATÉRIEL (QEMU 7.2.22 lacks `raspi4b`).
//! Address discovered dynamically via DTB (`compatible = "brcm,bcm2711-emmc2"`).

use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::ptr::{read_volatile, write_volatile};

use crate::drivers::block::{BlockDevice, BlockError};
use crate::klog;
use crate::log::LogLevel;

const EMMC_BLKSIZECNT: usize = 0x04;
const EMMC_ARG1: usize = 0x08;
const EMMC_CMDTM: usize = 0x0C;
const EMMC_RESP0: usize = 0x10;
const EMMC_RESP1: usize = 0x14;
const EMMC_RESP2: usize = 0x18;
const EMMC_RESP3: usize = 0x1C;
const EMMC_DATA: usize = 0x20;
const EMMC_STATUS: usize = 0x24;
const EMMC_CONTROL0: usize = 0x28;
const EMMC_CONTROL1: usize = 0x2C;
const EMMC_INTERRUPT: usize = 0x30;
const EMMC_IRPT_MASK: usize = 0x34;
const EMMC_IRPT_EN: usize = 0x38;
const EMMC_SLOTISR_VER: usize = 0xFC;

const CMD_GO_IDLE: u32 = 0 << 24;
const CMD_ALL_SEND_CID: u32 = (2 << 24) | (1 << 16); // R2 136-bit
const CMD_SEND_REL_ADDR: u32 = (3 << 24) | (2 << 16); // R6 48-bit
const CMD_SELECT_CARD: u32 = (7 << 24) | (3 << 16); // R1b
const CMD_SEND_IF_COND: u32 = (8 << 24) | (2 << 16); // R7
const CMD_SEND_CSD: u32 = (9 << 24) | (1 << 16); // R2 136-bit
const CMD_SET_BLOCKLEN: u32 = (16 << 24) | (2 << 16); // R1
const CMD_READ_SINGLE: u32 = (17 << 24) | (1 << 21) | (2 << 16) | (1 << 4);
const CMD_WRITE_SINGLE: u32 = (24 << 24) | (1 << 21) | (2 << 16);
const CMD_APP_CMD: u32 = (55 << 24) | (2 << 16);

const INT_CMD_DONE: u32 = 1 << 0;
const INT_DATA_DONE: u32 = 1 << 1;
const INT_WRITE_RDY: u32 = 1 << 4;
const INT_READ_RDY: u32 = 1 << 5;
const INT_ERR: u32 = 1 << 15;

pub trait EmmcBus: Send {
    fn read_reg(&self, off: usize) -> u32;
    fn write_reg(&mut self, off: usize, val: u32);
}

pub struct VolatileEmmcBus {
    base: usize,
}

impl EmmcBus for VolatileEmmcBus {
    #[inline(always)]
    fn read_reg(&self, off: usize) -> u32 {
        unsafe { read_volatile((self.base + off) as *const u32) }
    }
    #[inline(always)]
    fn write_reg(&mut self, off: usize, val: u32) {
        unsafe { write_volatile((self.base + off) as *mut u32, val) }
    }
}

pub struct Bcm2711Emmc2Generic<B: EmmcBus> {
    bus: B,
    label: &'static str,
    rca: u32,
    sectors: u64,
    sdhc: bool,
    initialized: bool,
}

pub type Bcm2711Emmc2 = Bcm2711Emmc2Generic<VolatileEmmcBus>;

impl Bcm2711Emmc2 {
    pub const fn new(base: usize) -> Self {
        Self {
            bus: VolatileEmmcBus { base },
            label: "emmc2-sd0",
            rca: 0,
            sectors: 0,
            sdhc: true,
            initialized: false,
        }
    }
}

impl<B: EmmcBus> Bcm2711Emmc2Generic<B> {
    pub const fn with_bus(bus: B, label: &'static str) -> Self {
        Self {
            bus,
            label,
            rca: 0,
            sectors: 0,
            sdhc: true,
            initialized: false,
        }
    }

    fn read_reg(&self, off: usize) -> u32 {
        self.bus.read_reg(off)
    }

    fn write_reg(&mut self, off: usize, val: u32) {
        self.bus.write_reg(off, val)
    }

    fn send_cmd(&mut self, cmd: u32, arg: u32) -> Result<u32, BlockError> {
        let mut timeout = 1_000_000u32;
        let inhibit_mask = if (cmd & (1 << 21)) != 0 { 0x3 } else { 0x1 };
        while (self.read_reg(EMMC_STATUS) & inhibit_mask) != 0 {
            if timeout == 0 {
                return Err(BlockError::NotReady);
            }
            timeout -= 1;
            core::hint::spin_loop();
        }
        self.write_reg(EMMC_INTERRUPT, 0xFFFF_FFFF);
        self.write_reg(EMMC_ARG1, arg);
        self.write_reg(EMMC_CMDTM, cmd);

        timeout = 1_000_000;
        loop {
            let irpt = self.read_reg(EMMC_INTERRUPT);
            if (irpt & INT_ERR) != 0 {
                self.write_reg(EMMC_INTERRUPT, 0xFFFF_FFFF);
                return Err(BlockError::IoError);
            }
            if (irpt & INT_CMD_DONE) != 0 {
                self.write_reg(EMMC_INTERRUPT, INT_CMD_DONE);
                return Ok(self.read_reg(EMMC_RESP0));
            }
            if timeout == 0 {
                return Err(BlockError::IoError);
            }
            timeout -= 1;
            core::hint::spin_loop();
        }
    }

    fn wait_int(&mut self, bit: u32) -> Result<(), BlockError> {
        let mut timeout = 2_000_000u32;
        loop {
            let irpt = self.read_reg(EMMC_INTERRUPT);
            if (irpt & INT_ERR) != 0 {
                self.write_reg(EMMC_INTERRUPT, 0xFFFF_FFFF);
                return Err(BlockError::IoError);
            }
            if (irpt & bit) != 0 {
                self.write_reg(EMMC_INTERRUPT, bit);
                return Ok(());
            }
            if timeout == 0 {
                return Err(BlockError::IoError);
            }
            timeout -= 1;
            core::hint::spin_loop();
        }
    }

    fn parse_csd_sectors(&self) -> u64 {
        let r3 = self.read_reg(EMMC_RESP3);
        let r2 = self.read_reg(EMMC_RESP2);
        let r1 = self.read_reg(EMMC_RESP1);
        let csd_struct = (r3 >> 22) & 0x3;
        if csd_struct == 1 {
            // CSD v2.0 (SDHC/SDXC)
            let c_size = (((r2 & 0x3F) as u64) << 16) | (((r1 >> 16) & 0xFFFF) as u64);
            (c_size + 1) * 1024
        } else {
            // CSD v1.0 (SDSC)
            let read_bl_len = (r2 >> 8) & 0xF;
            let c_size = (((r2 & 0x3) as u64) << 10) | (((r1 >> 22) & 0x3FF) as u64);
            let c_size_mult = (r1 >> 7) & 0x7;
            let block_len = 1u64 << read_bl_len.min(11);
            let mult = 1u64 << (c_size_mult + 2);
            ((c_size + 1) * mult * block_len) / 512
        }
    }

    /// Initialize EMMC2 controller and probe SD card.
    pub fn init(&mut self) -> Result<(), BlockError> {
        let ver = self.read_reg(EMMC_SLOTISR_VER);
        klog!(
            LogLevel::Info,
            "emmc2",
            "BCM2711 EMMC2 probe '{}' (SLOTISR_VER={:#x})",
            self.label,
            ver
        );

        let ctl1 = self.read_reg(EMMC_CONTROL1);
        self.write_reg(EMMC_CONTROL1, ctl1 | (1 << 24));
        let mut reset_ok = false;
        for _ in 0..100_000 {
            if (self.read_reg(EMMC_CONTROL1) & (1 << 24)) == 0 {
                reset_ok = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !reset_ok {
            return Err(BlockError::NotReady);
        }

        self.write_reg(EMMC_CONTROL0, 0);
        self.write_reg(EMMC_CONTROL1, (1 << 0) | (0x7 << 16) | (0xFA << 8));
        let mut clk_ok = false;
        for _ in 0..100_000 {
            if (self.read_reg(EMMC_CONTROL1) & (1 << 1)) != 0 {
                clk_ok = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !clk_ok {
            return Err(BlockError::NotReady);
        }
        let ctl1 = self.read_reg(EMMC_CONTROL1);
        self.write_reg(EMMC_CONTROL1, ctl1 | (1 << 2));

        self.write_reg(EMMC_IRPT_MASK, 0xFFFF_FFFF);
        self.write_reg(EMMC_IRPT_EN, 0);

        self.send_cmd(CMD_GO_IDLE, 0)?;
        let r7 = self.send_cmd(CMD_SEND_IF_COND, 0x1AA)?;
        if (r7 & 0xFFF) != 0x1AA {
            return Err(BlockError::NotReady);
        }

        let mut acmd_ocr = 0u32;
        let mut ready = false;
        for _ in 0..1000 {
            self.send_cmd(CMD_APP_CMD, 0)?;
            let ocr = self.send_cmd((41 << 24) | (2 << 16), 0x41FF_8000)?;
            if (ocr & (1 << 31)) != 0 {
                acmd_ocr = ocr;
                ready = true;
                break;
            }
            for _ in 0..1000 {
                core::hint::spin_loop();
            }
        }
        if !ready {
            return Err(BlockError::NotReady);
        }
        self.sdhc = (acmd_ocr & (1 << 30)) != 0;

        let _cid = self.send_cmd(CMD_ALL_SEND_CID, 0)?;
        let r6 = self.send_cmd(CMD_SEND_REL_ADDR, 0)?;
        self.rca = r6 & 0xFFFF_0000;

        self.send_cmd(CMD_SEND_CSD, self.rca)?;
        self.sectors = self.parse_csd_sectors();

        self.send_cmd(CMD_SELECT_CARD, self.rca)?;
        if !self.sdhc {
            let _ = self.send_cmd(CMD_SET_BLOCKLEN, 512);
        }

        self.initialized = true;
        Ok(())
    }
}

impl<B: EmmcBus> BlockDevice for Bcm2711Emmc2Generic<B> {
    fn name(&self) -> &str {
        self.label
    }
    fn block_size(&self) -> usize {
        512
    }
    fn block_count(&self) -> u64 {
        self.sectors
    }
    fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        if !self.initialized {
            return Err(BlockError::NotReady);
        }
        if buf.is_empty() || buf.len() % 512 != 0 {
            return Err(BlockError::InvalidSize);
        }
        let secs = (buf.len() / 512) as u64;
        if self.sectors > 0 && lba.checked_add(secs).ok_or(BlockError::OutOfBounds)? > self.sectors {
            return Err(BlockError::OutOfBounds);
        }

        for s in 0..secs {
            let cur_lba = lba + s;
            let addr = if self.sdhc {
                cur_lba as u32
            } else {
                (cur_lba as u32).saturating_mul(512)
            };
            self.write_reg(EMMC_BLKSIZECNT, (1 << 16) | 512);
            self.send_cmd(CMD_READ_SINGLE, addr)?;
            self.wait_int(INT_READ_RDY)?;
            let sec_off = (s as usize) * 512;
            for w in 0..128 {
                let word = self.read_reg(EMMC_DATA);
                buf[sec_off + w * 4..sec_off + w * 4 + 4].copy_from_slice(&word.to_le_bytes());
            }
            self.wait_int(INT_DATA_DONE)?;
        }
        Ok(())
    }
    fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        if !self.initialized {
            return Err(BlockError::NotReady);
        }
        if buf.is_empty() || buf.len() % 512 != 0 {
            return Err(BlockError::InvalidSize);
        }
        let secs = (buf.len() / 512) as u64;
        if self.sectors > 0 && lba.checked_add(secs).ok_or(BlockError::OutOfBounds)? > self.sectors {
            return Err(BlockError::OutOfBounds);
        }

        for s in 0..secs {
            let cur_lba = lba + s;
            let addr = if self.sdhc {
                cur_lba as u32
            } else {
                (cur_lba as u32).saturating_mul(512)
            };
            self.write_reg(EMMC_BLKSIZECNT, (1 << 16) | 512);
            self.send_cmd(CMD_WRITE_SINGLE, addr)?;
            self.wait_int(INT_WRITE_RDY)?;
            let sec_off = (s as usize) * 512;
            for w in 0..128 {
                let word = u32::from_le_bytes([
                    buf[sec_off + w * 4],
                    buf[sec_off + w * 4 + 1],
                    buf[sec_off + w * 4 + 2],
                    buf[sec_off + w * 4 + 3],
                ]);
                self.write_reg(EMMC_DATA, word);
            }
            self.wait_int(INT_DATA_DONE)?;
        }
        Ok(())
    }
}

/// Deterministic MMIO state-machine mock test for `Bcm2711Emmc2` (runs in QEMU without Pi 4 HW).
pub fn self_test_mock() -> Result<u64, BlockError> {
    struct MockEmmc {
        state: RefCell<MockState>,
    }
    struct MockState {
        arg1: u32,
        ctl1: u32,
        irpt: u32,
        resp: [u32; 4],
        active_lba: usize,
        rx_fifo: VecDeque<u32>,
        tx_words: Vec<u32>,
        disk: Vec<u8>,
        inject_err_next: bool,
    }
    unsafe impl Send for MockEmmc {}

    impl EmmcBus for MockEmmc {
        fn read_reg(&self, off: usize) -> u32 {
            let mut st = self.state.borrow_mut();
            match off {
                EMMC_SLOTISR_VER => 0x0003_0000,
                EMMC_STATUS => 0,
                EMMC_CONTROL1 => st.ctl1 & !(1 << 24),
                EMMC_INTERRUPT => st.irpt,
                EMMC_RESP0 => st.resp[0],
                EMMC_RESP1 => st.resp[1],
                EMMC_RESP2 => st.resp[2],
                EMMC_RESP3 => st.resp[3],
                EMMC_DATA => st.rx_fifo.pop_front().unwrap_or(0),
                _ => 0,
            }
        }
        fn write_reg(&mut self, off: usize, val: u32) {
            let mut st = self.state.borrow_mut();
            match off {
                EMMC_ARG1 => st.arg1 = val,
                EMMC_CONTROL1 => {
                    st.ctl1 = (val & !(1 << 24)) | (1 << 1); // CLK_STABLE=1, reset self-cleared
                }
                EMMC_INTERRUPT => st.irpt &= !val,
                EMMC_CMDTM => {
                    let cmd = (val >> 24) & 0x3F;
                    if st.inject_err_next && (cmd == 17 || cmd == 24) {
                        st.inject_err_next = false;
                        st.irpt |= INT_ERR;
                        return;
                    }
                    st.irpt |= INT_CMD_DONE;
                    match cmd {
                        8 => st.resp[0] = st.arg1,
                        41 => st.resp[0] = (1 << 31) | (1 << 30), // Ready + SDHC
                        3 => st.resp[0] = 0x1234_0000,
                        9 => {
                            // CSD v2.0 with C_SIZE=3 => 4096 sectors (2 MiB mock SD card)
                            st.resp[3] = 1 << 22;
                            st.resp[2] = 0;
                            st.resp[1] = 3 << 16;
                        }
                        17 => {
                            let lba = st.arg1 as usize;
                            st.active_lba = lba;
                            st.rx_fifo.clear();
                            let base = lba * 512;
                            for w in 0..128 {
                                let off = base + w * 4;
                                let word = u32::from_le_bytes([
                                    st.disk[off],
                                    st.disk[off + 1],
                                    st.disk[off + 2],
                                    st.disk[off + 3],
                                ]);
                                st.rx_fifo.push_back(word);
                            }
                            st.irpt |= INT_READ_RDY | INT_DATA_DONE;
                        }
                        24 => {
                            st.active_lba = st.arg1 as usize;
                            st.tx_words.clear();
                            st.irpt |= INT_WRITE_RDY | INT_DATA_DONE;
                        }
                        _ => st.resp[0] = 0,
                    }
                }
                EMMC_DATA => {
                    st.tx_words.push(val);
                    if st.tx_words.len() == 128 {
                        let base = st.active_lba * 512;
                        for w in 0..128 {
                            let word = st.tx_words[w];
                            st.disk[base + w * 4..base + w * 4 + 4]
                                .copy_from_slice(&word.to_le_bytes());
                        }
                        st.tx_words.clear();
                    }
                }
                _ => {}
            }
        }
    }

    let mock = MockEmmc {
        state: RefCell::new(MockState {
            arg1: 0,
            ctl1: 0,
            irpt: 0,
            resp: [0; 4],
            active_lba: 0,
            rx_fifo: VecDeque::new(),
            tx_words: Vec::new(),
            disk: vec![0u8; 4096 * 512],
            inject_err_next: false,
        }),
    };

    let mut dev = Bcm2711Emmc2Generic::with_bus(mock, "emmc2-mock");
    // Must fail before init
    let mut sec = [0u8; 512];
    if dev.read_blocks(0, &mut sec) != Err(BlockError::NotReady) {
        return Err(BlockError::IoError);
    }

    dev.init()?;
    if dev.block_count() != 4096 {
        return Err(BlockError::IoError);
    }

    // Write + readback across LBA 5
    sec[0..11].copy_from_slice(b"EMMC2-MOCK!");
    dev.write_blocks(5, &sec)?;
    let mut rb = [0u8; 512];
    dev.read_blocks(5, &mut rb)?;
    if rb != sec {
        return Err(BlockError::IoError);
    }

    // Multi-block (2 sectors = 1024 B) write + readback across LBA 10..11
    let mut two = [0u8; 1024];
    for (i, b) in two.iter_mut().enumerate() {
        *b = ((i * 17) & 0xFF) as u8;
    }
    dev.write_blocks(10, &two)?;
    let mut two_rb = [0u8; 1024];
    dev.read_blocks(10, &mut two_rb)?;
    if two_rb != two {
        return Err(BlockError::IoError);
    }

    // Inject INT_ERR and verify IoError propagation + subsequent recovery read
    dev.bus.state.borrow_mut().inject_err_next = true;
    if dev.read_blocks(5, &mut rb) != Err(BlockError::IoError) {
        return Err(BlockError::IoError);
    }
    rb.fill(0);
    dev.read_blocks(5, &mut rb)?;
    if rb != sec {
        return Err(BlockError::IoError);
    }

    if dev.write_blocks(4096, &sec) != Err(BlockError::OutOfBounds) {
        return Err(BlockError::IoError);
    }

    Ok(dev.block_count())
}
