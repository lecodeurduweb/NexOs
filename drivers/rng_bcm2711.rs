//! Raspberry Pi 4 (BCM2711) Hardware RNG200 (`iproc-rng200`) Driver.
//!
//! STATUS: BUILD-VERIFIED + MOCK-VERIFIED / NON TESTÉ SUR MATÉRIEL (QEMU lacks `raspi4b`).
//! Register map follows Broadcom BCM2711 / `brcm,bcm2711-rng200` (base 0xFE10_4000 in 35-bit low-periph mode).

use alloc::collections::VecDeque;
use core::cell::RefCell;
use core::ptr::{read_volatile, write_volatile};

pub const BCM2711_RNG200_DEFAULT_BASE: usize = 0xFE10_4000;

const RNG_CTRL_OFFSET: usize = 0x00;
const RNG_SOFT_RESET_OFFSET: usize = 0x04;
const RBG_SOFT_RESET_OFFSET: usize = 0x08;
const RNG_INT_STATUS_OFFSET: usize = 0x18;
const RNG_FIFO_DATA_OFFSET: usize = 0x20;
const RNG_FIFO_COUNT_OFFSET: usize = 0x24;

const RNG_CTRL_RBGEN_MASK: u32 = 0x0000_1FFF;
const RNG_CTRL_RBGEN_ENABLE: u32 = 0x0000_0001;
const RNG_SOFT_RESET_BIT: u32 = 0x0000_0001;
const RBG_SOFT_RESET_BIT: u32 = 0x0000_0001;
const RNG_FIFO_COUNT_MASK: u32 = 0x0000_00FF;
const RNG_INT_STATUS_MASTER_FAIL_LOCKOUT: u32 = 0x8000_0000;
const RNG_INT_STATUS_NIST_FAIL: u32 = 0x0000_0020;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RngHwError {
    NotInitialized,
    HealthFault,
    Timeout,
}

pub trait RngBus {
    fn read_reg(&self, off: usize) -> u32;
    fn write_reg(&mut self, off: usize, val: u32);
}

pub struct VolatileRngBus {
    base: usize,
}

impl RngBus for VolatileRngBus {
    #[inline(always)]
    fn read_reg(&self, off: usize) -> u32 {
        unsafe { read_volatile((self.base + off) as *const u32) }
    }

    #[inline(always)]
    fn write_reg(&mut self, off: usize, val: u32) {
        unsafe { write_volatile((self.base + off) as *mut u32, val) }
    }
}

pub struct Bcm2711RngGeneric<B: RngBus> {
    bus: B,
    initialized: bool,
}

pub type Bcm2711Rng200 = Bcm2711RngGeneric<VolatileRngBus>;

impl Bcm2711Rng200 {
    pub const fn new(base: usize) -> Self {
        Self {
            bus: VolatileRngBus { base },
            initialized: false,
        }
    }
}

impl<B: RngBus> Bcm2711RngGeneric<B> {
    pub const fn with_bus(bus: B) -> Self {
        Self {
            bus,
            initialized: false,
        }
    }

    /// Initialize RNG200, clear error flags, enable ring oscillator generator, and discard warm-up words.
    pub fn init(&mut self) -> Result<(), RngHwError> {
        let ctrl = self.bus.read_reg(RNG_CTRL_OFFSET);
        if (ctrl & RNG_CTRL_RBGEN_MASK) == 0 {
            self.bus
                .write_reg(RNG_CTRL_OFFSET, ctrl | RNG_CTRL_RBGEN_ENABLE);
        }

        // Clear any pre-existing lockout / NIST failure indicators via soft reset if latched
        let status = self.bus.read_reg(RNG_INT_STATUS_OFFSET);
        if (status & (RNG_INT_STATUS_MASTER_FAIL_LOCKOUT | RNG_INT_STATUS_NIST_FAIL)) != 0 {
            self.bus.write_reg(RNG_SOFT_RESET_OFFSET, RNG_SOFT_RESET_BIT);
            self.bus.write_reg(RBG_SOFT_RESET_OFFSET, RBG_SOFT_RESET_BIT);
            self.bus.write_reg(RNG_SOFT_RESET_OFFSET, 0);
            self.bus.write_reg(RBG_SOFT_RESET_OFFSET, 0);
            self.bus
                .write_reg(RNG_INT_STATUS_OFFSET, RNG_INT_STATUS_MASTER_FAIL_LOCKOUT | RNG_INT_STATUS_NIST_FAIL);
        }

        // Probe at least one available word to verify generator responds
        let mut probe_word = 0u32;
        self.initialized = true;
        if self.read_word_internal(&mut probe_word).is_err() {
            self.initialized = false;
            return Err(RngHwError::Timeout);
        }
        Ok(())
    }

    fn read_word_internal(&mut self, out: &mut u32) -> Result<(), RngHwError> {
        if !self.initialized {
            return Err(RngHwError::NotInitialized);
        }
        let mut timeout = 500_000u32;
        while timeout > 0 {
            let status = self.bus.read_reg(RNG_INT_STATUS_OFFSET);
            if (status & (RNG_INT_STATUS_MASTER_FAIL_LOCKOUT | RNG_INT_STATUS_NIST_FAIL)) != 0 {
                return Err(RngHwError::HealthFault);
            }
            let fifo_cnt = self.bus.read_reg(RNG_FIFO_COUNT_OFFSET) & RNG_FIFO_COUNT_MASK;
            if fifo_cnt > 0 {
                *out = self.bus.read_reg(RNG_FIFO_DATA_OFFSET);
                return Ok(());
            }
            timeout -= 1;
            core::hint::spin_loop();
        }
        Err(RngHwError::Timeout)
    }

    pub fn read_bytes(&mut self, out: &mut [u8]) -> Result<usize, RngHwError> {
        if !self.initialized {
            return Err(RngHwError::NotInitialized);
        }
        let mut pos = 0usize;
        while pos < out.len() {
            let mut w = 0u32;
            self.read_word_internal(&mut w)?;
            let bytes = w.to_le_bytes();
            let take = (out.len() - pos).min(4);
            out[pos..pos + take].copy_from_slice(&bytes[..take]);
            pos += take;
        }
        Ok(pos)
    }
}

/// Deterministic MMIO state-machine mock test for BCM2711 RNG200.
pub fn self_test_mock() -> Result<(), RngHwError> {
    struct MockRng {
        ctrl: RefCell<u32>,
        int_status: RefCell<u32>,
        fifo: RefCell<VecDeque<u32>>,
    }

    impl RngBus for MockRng {
        fn read_reg(&self, off: usize) -> u32 {
            match off {
                RNG_CTRL_OFFSET => *self.ctrl.borrow(),
                RNG_INT_STATUS_OFFSET => *self.int_status.borrow(),
                RNG_FIFO_COUNT_OFFSET => self.fifo.borrow().len().min(16) as u32,
                RNG_FIFO_DATA_OFFSET => self.fifo.borrow_mut().pop_front().unwrap_or(0),
                _ => 0,
            }
        }
        fn write_reg(&mut self, off: usize, val: u32) {
            match off {
                RNG_CTRL_OFFSET => *self.ctrl.borrow_mut() = val,
                RNG_INT_STATUS_OFFSET => *self.int_status.borrow_mut() &= !val,
                _ => {}
            }
        }
    }

    let mut q = VecDeque::new();
    for i in 1u32..=12 {
        q.push_back(0x9E37_79B9u32.wrapping_mul(i) ^ 0xA55A_5AA5);
    }
    let mock = MockRng {
        ctrl: RefCell::new(0),
        int_status: RefCell::new(RNG_INT_STATUS_NIST_FAIL), // verify reset clears fault
        fifo: RefCell::new(q),
    };

    let mut rng = Bcm2711RngGeneric::with_bus(mock);
    let mut buf = [0u8; 16];
    if rng.read_bytes(&mut buf) != Err(RngHwError::NotInitialized) {
        return Err(RngHwError::HealthFault);
    }
    rng.init()?;
    let n = rng.read_bytes(&mut buf)?;
    if n != 16 || buf == [0u8; 16] {
        return Err(RngHwError::HealthFault);
    }
    Ok(())
}
