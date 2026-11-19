//! In-memory RAM disk block device (512-byte sectors).

use alloc::vec::Vec;

use super::{BlockDevice, BlockError};

pub struct RamDisk {
    data: Vec<u8>,
    sector_size: usize,
    read_only: bool,
}

impl RamDisk {
    pub fn new(sectors: u64) -> Self {
        let sector_size = 512usize;
        let len = (sectors as usize) * sector_size;
        Self {
            data: alloc::vec![0u8; len],
            sector_size,
            read_only: false,
        }
    }

    pub fn set_read_only(&mut self, ro: bool) {
        self.read_only = ro;
    }
}

impl BlockDevice for RamDisk {
    fn name(&self) -> &str {
        "ramdisk0"
    }

    fn block_size(&self) -> usize {
        self.sector_size
    }

    fn block_count(&self) -> u64 {
        (self.data.len() / self.sector_size) as u64
    }

    fn read_only(&self) -> bool {
        self.read_only
    }

    fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        if buf.len() % self.sector_size != 0 {
            return Err(BlockError::InvalidSize);
        }
        let sectors = (buf.len() / self.sector_size) as u64;
        let end_lba = lba.checked_add(sectors).ok_or(BlockError::OutOfBounds)?;
        if end_lba > self.block_count() {
            return Err(BlockError::OutOfBounds);
        }
        let start = (lba as usize) * self.sector_size;
        let end = start + buf.len();
        buf.copy_from_slice(&self.data[start..end]);
        Ok(())
    }

    fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        if self.read_only {
            return Err(BlockError::ReadOnly);
        }
        if buf.len() % self.sector_size != 0 {
            return Err(BlockError::InvalidSize);
        }
        let sectors = (buf.len() / self.sector_size) as u64;
        let end_lba = lba.checked_add(sectors).ok_or(BlockError::OutOfBounds)?;
        if end_lba > self.block_count() {
            return Err(BlockError::OutOfBounds);
        }
        let start = (lba as usize) * self.sector_size;
        let end = start + buf.len();
        self.data[start..end].copy_from_slice(buf);
        Ok(())
    }
}
