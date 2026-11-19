//! UART console abstraction and hardware drivers.
//!
//! - `pl011`: ARM PrimeCell PL011 UART (QEMU `virt` and Pi 4 UART0).
//! - `mini_uart`: BCM2711 AUX UART1 (Raspberry Pi 4 specific module).

pub mod mini_uart;
pub mod pl011;

use core::fmt::{self, Write};
use crate::sync::SpinLock;

#[derive(Clone, Copy)]
enum UartKind {
    None,
    Pl011(pl011::Pl011),
    MiniUart(mini_uart::MiniUart),
}

struct ConsoleState {
    backend: UartKind,
}

impl ConsoleState {
    const fn new() -> Self {
        Self {
            backend: UartKind::None,
        }
    }

    fn write_byte(&self, byte: u8) {
        match self.backend {
            UartKind::None => {}
            UartKind::Pl011(ref dev) => dev.write_byte(byte),
            UartKind::MiniUart(ref dev) => dev.write_byte(byte),
        }
    }

    fn read_byte(&self) -> Option<u8> {
        match self.backend {
            UartKind::None => None,
            UartKind::Pl011(ref dev) => dev.read_byte(),
            UartKind::MiniUart(ref dev) => dev.read_byte(),
        }
    }
}

impl Write for ConsoleState {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &b in s.as_bytes() {
            if b == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(b);
        }
        Ok(())
    }
}

static CONSOLE: SpinLock<ConsoleState> = SpinLock::new(ConsoleState::new());

/// Initialize active console using an ARM PL011 UART at `base`.
pub fn init_pl011(base: usize, clock_hz: u32, baud: u32) {
    let dev = pl011::Pl011::new(base);
    dev.init(clock_hz, baud);
    let mut guard = CONSOLE.lock();
    guard.backend = UartKind::Pl011(dev);
}

/// Bind console to the DTB-discovered PL011 base address (without interrupting active TX).
pub fn bind_pl011_base(base: usize) {
    let mut guard = CONSOLE.lock();
    guard.backend = UartKind::Pl011(pl011::Pl011::new(base));
}

/// Initialize active console using BCM2711 Mini-UART (Raspberry Pi 4).
pub fn init_mini_uart(aux_base: usize, system_clock_hz: u32, baud: u32) {
    let dev = mini_uart::MiniUart::new(aux_base);
    dev.init(system_clock_hz, baud);
    let mut guard = CONSOLE.lock();
    guard.backend = UartKind::MiniUart(dev);
}

/// Write formatted arguments to the active serial console.
pub fn write_fmt(args: fmt::Arguments<'_>) {
    let mut guard = CONSOLE.lock();
    let _ = guard.write_fmt(args);
}

/// Non-blocking read of one byte from the active serial console.
pub fn read_byte() -> Option<u8> {
    let guard = CONSOLE.lock();
    guard.read_byte()
}

/// Write a single raw byte to the active serial console.
pub fn write_byte(byte: u8) {
    let guard = CONSOLE.lock();
    guard.write_byte(byte);
}
