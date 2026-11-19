//! ARM PrimeCell PL011 UART driver.
//!
//! Parameterized strictly by MMIO base address so it can be driven from
//! DTB-discovered addresses on both QEMU `virt` and Raspberry Pi 4 (UART0).

use core::ptr::{read_volatile, write_volatile};

const UARTDR: usize = 0x00;
const UARTFR: usize = 0x18;
const UARTIBRD: usize = 0x24;
const UARTFBRD: usize = 0x28;
const UARTLCR_H: usize = 0x2C;
const UARTCR: usize = 0x30;
const UARTIMSC: usize = 0x38;
const UARTICR: usize = 0x44;

const FR_BUSY: u32 = 1 << 3;
const FR_RXFE: u32 = 1 << 4;
const FR_TXFF: u32 = 1 << 5;

const LCRH_FEN: u32 = 1 << 4;
const LCRH_WLEN_8: u32 = 0b11 << 5;

const CR_UARTEN: u32 = 1 << 0;
const CR_TXE: u32 = 1 << 8;
const CR_RXE: u32 = 1 << 9;

#[derive(Clone, Copy)]
pub struct Pl011 {
    base: usize,
}

impl Pl011 {
    pub const fn new(base: usize) -> Self {
        Self { base }
    }

    pub const fn base(&self) -> usize {
        self.base
    }

    #[inline(always)]
    fn read_reg(&self, offset: usize) -> u32 {
        unsafe { read_volatile((self.base + offset) as *const u32) }
    }

    #[inline(always)]
    fn write_reg(&self, offset: usize, val: u32) {
        unsafe { write_volatile((self.base + offset) as *mut u32, val) }
    }

    pub fn init(&self, clock_hz: u32, baud: u32) {
        // Wait briefly for any prior bootloader/firmware TX character to finish shifting out
        let mut spins = 100_000u32;
        while (self.read_reg(UARTFR) & FR_BUSY) != 0 && spins > 0 {
            spins -= 1;
            core::hint::spin_loop();
        }
        // Disable UART before reconfiguring
        self.write_reg(UARTCR, 0);
        // Clear pending interrupts
        self.write_reg(UARTICR, 0x7FF);
        // Mask all interrupts during early polled boot
        self.write_reg(UARTIMSC, 0);

        if clock_hz > 0 && baud > 0 {
            // Baud divisor = clock_hz / (16 * baud)
            // Integer = div >> 6, Fractional (6 bits) = div & 0x3F
            let div_x64 = (clock_hz as u64 * 4) / (baud as u64);
            let ibrd = (div_x64 >> 6) as u32;
            let fbrd = (div_x64 & 0x3F) as u32;
            if ibrd > 0 {
                self.write_reg(UARTIBRD, ibrd);
                self.write_reg(UARTFBRD, fbrd);
            }
        }

        // 8 data bits, no parity, 1 stop bit, FIFOs enabled
        self.write_reg(UARTLCR_H, LCRH_WLEN_8 | LCRH_FEN);
        // Enable UART, TX and RX
        self.write_reg(UARTCR, CR_UARTEN | CR_TXE | CR_RXE);
    }

    pub fn write_byte(&self, byte: u8) {
        while (self.read_reg(UARTFR) & FR_TXFF) != 0 {
            core::hint::spin_loop();
        }
        self.write_reg(UARTDR, byte as u32);
    }

    pub fn read_byte(&self) -> Option<u8> {
        if (self.read_reg(UARTFR) & FR_RXFE) != 0 {
            None
        } else {
            Some((self.read_reg(UARTDR) & 0xFF) as u8)
        }
    }
}
