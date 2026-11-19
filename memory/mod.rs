//! NexOS Memory Management Subsystem.
//!
//! - `phys`: Physical frame allocator (4 KiB pages), dynamic PA width via
//!   `ID_AA64MMFR0_EL1.PARange`, DTB memory & reserved regions, and DMA zones.

pub mod heap;
pub mod phys;
