//! Board-specific hardware isolation layer.
//!
//! Hardware-dependent addresses, bootstrap UART locations, and board-specific
//! quirks are strictly isolated inside `qemu_virt/` and `rpi4/`.

#[cfg(all(feature = "board-qemu-virt", feature = "board-rpi4"))]
compile_error!("Select only one board feature: either `board-qemu-virt` or `board-rpi4`.");

#[cfg(not(any(feature = "board-qemu-virt", feature = "board-rpi4")))]
compile_error!("A board feature (`board-qemu-virt` or `board-rpi4`) must be enabled.");

#[cfg(feature = "board-qemu-virt")]
pub mod qemu_virt;
#[cfg(feature = "board-qemu-virt")]
pub use qemu_virt as active;

#[cfg(feature = "board-rpi4")]
pub mod rpi4;
#[cfg(feature = "board-rpi4")]
pub use rpi4 as active;
