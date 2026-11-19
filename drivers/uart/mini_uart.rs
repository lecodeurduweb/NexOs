//! BCM2711 AUX Mini-UART (UART1) driver for Raspberry Pi 4.
//!
//! Separated cleanly from PL011 as required by the hardware isolation rules.
//! Registers are relative to the BCM2711 AUX block base (typically 0xFE21_5000).

use core::ptr::{read_volatile, write_volatile};

const AUX_ENABLES: usize = 0x04;
const AUX_MU_IO_REG: usize = 0x40;
const AUX_MU_IER_REG: usize = 0x44;
const AUX_MU_IIR_REG: usize = 0x48;
const AUX_MU_LCR_REG: usize = 0x4C;
const AUX_MU_MCR_REG: usize = 0x50;
const AUX_MU_LSR_REG: usize = 0x54;
const AUX_MU_CNTL_REG: usize = 0x60;
const AUX_MU_BAUD_REG: usize = 0x68;

const LSR_DATA_READY: u32 = 1 << 0;
const LSR_TX_EMPTY: u32 = 1 << 5;

#[derive(Clone, Copy)]
pub struct MiniUart {
    aux_base: usize,
}

impl MiniUart {
    pub const fn new(aux_base: usize) -> Self {
        Self { aux_base }
    }

    #[inline(always)]
    fn read_reg(&self, offset: usize) -> u32 {
        unsafe { read_volatile((self.aux_base + offset) as *const u32) }
    }

    #[inline(always)]
    fn write_reg(&self, offset: usize, val: u32) {
        unsafe { write_volatile((self.aux_base + offset) as *mut u32, val) }
    }

    pub fn init(&self, system_clock_hz: u32, baud: u32) {
        // Enable Mini-UART peripheral inside AUX
        let enables = self.read_reg(AUX_ENABLES);
        self.write_reg(AUX_ENABLES, enables | 1);

        // Disable TX/RX and interrupts while configuring
        self.write_reg(AUX_MU_CNTL_REG, 0);
        self.write_reg(AUX_MU_IER_REG, 0);
        // 8-bit mode (bits [1:0] = 0b11 per BCM2711 errata/spec)
        self.write_reg(AUX_MU_LCR_REG, 3);
        self.write_reg(AUX_MU_MCR_REG, 0);
        // Clear TX and RX FIFOs
        self.write_reg(AUX_MU_IIR_REG, 0xC6);

        if system_clock_hz > 0 && baud > 0 {
            let baud_reg = (system_clock_hz / (8 * baud)).saturating_sub(1);
            self.write_reg(AUX_MU_BAUD_REG, baud_reg);
        }

        // Enable TX and RX
        self.write_reg(AUX_MU_CNTL_REG, 3);
    }

    pub fn write_byte(&self, byte: u8) {
        while (self.read_reg(AUX_MU_LSR_REG) & LSR_TX_EMPTY) == 0 {
            core::hint::spin_loop();
        }
        self.write_reg(AUX_MU_IO_REG, byte as u32);
    }

    pub fn read_byte(&self) -> Option<u8> {
        if (self.read_reg(AUX_MU_LSR_REG) & LSR_DATA_READY) == 0 {
            None
        } else {
            Some((self.read_reg(AUX_MU_IO_REG) & 0xFF) as u8)
        }
    }
}
