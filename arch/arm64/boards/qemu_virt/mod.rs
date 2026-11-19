//! QEMU `virt` board definitions (`-machine virt,gic-version=2`).
//!
//! Bootstrap Exception Notice:
//!   `EARLY_PL011_BASE` (0x0900_0000) is the only hardcoded peripheral address
//!   used before the Device Tree Blob (DTB) is parsed (Stage 4), purely to
//!   provide early serial diagnostics during boot.

pub const BOARD_NAME: &str = "qemu-virt (gic-version=2)";

/// Early bootstrap PL011 UART base on QEMU `virt` before DTB parsing.
/// Documented exception: replaced/verified by DTB discovery in Stage 4.
pub const EARLY_PL011_BASE: usize = 0x0900_0000;

/// QEMU `virt` PL011 reference clock (24 MHz standard in QEMU).
pub const EARLY_UART_CLOCK_HZ: u32 = 24_000_000;

/// Initialize early bootstrap console UART on QEMU `virt`.
pub fn init_early_console() {
    crate::drivers::uart::init_pl011(EARLY_PL011_BASE, EARLY_UART_CLOCK_HZ, 115_200);
}
