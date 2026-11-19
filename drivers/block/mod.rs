//! Block device abstraction and storage drivers.

pub mod cache;
pub mod ramdisk;
pub mod sd_emmc2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockError {
    OutOfBounds,
    ReadOnly,
    IoError,
    Unaligned,
    InvalidSize,
    NotReady,
}

pub trait BlockDevice: Send {
    fn name(&self) -> &str;
    fn block_size(&self) -> usize;
    fn block_count(&self) -> u64;
    fn read_only(&self) -> bool {
        false
    }
    fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError>;
    fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError>;
    fn flush(&mut self) -> Result<(), BlockError> {
        Ok(())
    }
}
