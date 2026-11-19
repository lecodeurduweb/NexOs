//! Raspberry Pi 4 Model B (BCM2711, 8 GiB RAM) board definitions.
//!
//! STATUS: NON TESTÉ SUR MATÉRIEL (validated only at compilation time).
//!
//! Bootstrap Exception Notice:
//!   In 35-bit low-peripheral mode (default without `arm_peri_high`), BCM2711
//!   peripherals live at 0xFE00_0000. Early bootstrap UART addresses below are
//!   used strictly prior to DTB parsing (Stage 4).
//!
//! BCM2711 Specifics (isolated here):
//!   - PL011 UART0 base: 0xFE20_1000 (routed to GPIO 14/15 when `dtoverlay=disable-bt`)
//!   - AUX Mini-UART (UART1) base: 0xFE21_5000 (enabled by default `enable_uart=1`)
//!   - GPIO base: 0xFE20_0000
//!   - ARM Local interrupt/timer controller: 0xFF80_0000
//!   - GIC-400 (GICv2) base: 0xFF84_0000 (verified dynamically via DTB in Stage 5)

pub const BOARD_NAME: &str = "rpi4 (BCM2711) [NON TESTE SUR MATERIEL]";

/// BCM2711 low-peripheral MMIO base (35-bit mode, 0xFE00_0000).
pub const BCM2711_PERIPH_BASE: usize = 0xFE00_0000;

/// BCM2711 GPIO base address.
pub const BCM2711_GPIO_BASE: usize = BCM2711_PERIPH_BASE + 0x0020_0000;

/// BCM2711 PL011 UART0 base (GPIO 14/15 ALT0 when `dtoverlay=disable-bt`).
pub const EARLY_PL011_BASE: usize = BCM2711_PERIPH_BASE + 0x0020_1000;

/// BCM2711 AUX / Mini-UART base (GPIO 14/15 ALT5).
pub const EARLY_AUX_BASE: usize = BCM2711_PERIPH_BASE + 0x0021_5000;

/// Default VideoCore PL011 UART clock (48 MHz on Pi 4 when configured by firmware).
pub const EARLY_PL011_CLOCK_HZ: u32 = 48_000_000;

/// Initialize early bootstrap console UART on Raspberry Pi 4.
/// Configures GPIO 14 (TXD0) & GPIO 15 (RXD0) to ALT0 and disables pulls,
/// then initializes PL011 UART0 (matched with `dtoverlay=disable-bt` in `config.txt`),
/// while keeping the Mini-UART driver available in `drivers::uart::mini_uart`.
pub fn init_early_console() {
    const GPFSEL1: usize = BCM2711_GPIO_BASE + 0x04;
    const GPIO_PUP_PDN_CNTRL_REG0: usize = BCM2711_GPIO_BASE + 0xE4;
    unsafe {
        // Set GPIO 14 [14:12] = 0b100 (ALT0) and GPIO 15 [17:15] = 0b100 (ALT0)
        let mut gpfsel1 = core::ptr::read_volatile(GPFSEL1 as *const u32);
        gpfsel1 &= !((0b111 << 12) | (0b111 << 15));
        gpfsel1 |= (0b100 << 12) | (0b100 << 15);
        core::ptr::write_volatile(GPFSEL1 as *mut u32, gpfsel1);

        // GPIO 14 TXD0 [29:28] = 0b00 (no pull), GPIO 15 RXD0 [31:30] = 0b01 (pull-up)
        let mut pup = core::ptr::read_volatile(GPIO_PUP_PDN_CNTRL_REG0 as *const u32);
        pup &= !((0b11 << 28) | (0b11 << 30));
        pup |= 0b01 << 30;
        core::ptr::write_volatile(GPIO_PUP_PDN_CNTRL_REG0 as *mut u32, pup);
    }
    crate::drivers::uart::init_pl011(EARLY_PL011_BASE, EARLY_PL011_CLOCK_HZ, 115_200);
}
