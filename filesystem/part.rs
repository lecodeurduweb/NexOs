//! MBR & GPT Partition Table Parser + Bounds-Checked Partition BlockDevice.

use alloc::vec::Vec;

use crate::drivers::block::{BlockDevice, BlockError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PartitionScheme {
    Mbr,
    Gpt,
}

#[derive(Clone, Copy, Debug)]
pub struct PartitionInfo {
    pub index: usize,
    pub scheme: PartitionScheme,
    pub part_type: u8,
    pub start_lba: u64,
    pub sector_count: u64,
}

/// Parse MBR (and GPT if protective MBR `0xEE` + `"EFI PART"` at LBA 1 is found).
pub fn parse_partitions<D: BlockDevice>(dev: &mut D) -> Result<Vec<PartitionInfo>, BlockError> {
    let mut sector0 = [0u8; 512];
    dev.read_blocks(0, &mut sector0)?;

    if sector0[510] != 0x55 || sector0[511] != 0xAA {
        return Ok(Vec::new());
    }

    let mut parts = Vec::new();
    let mut has_gpt_protective = false;

    for i in 0..4 {
        let off = 446 + i * 16;
        let ptype = sector0[off + 4];
        if ptype == 0 {
            continue;
        }
        let start_lba = u32::from_le_bytes([
            sector0[off + 8],
            sector0[off + 9],
            sector0[off + 10],
            sector0[off + 11],
        ]) as u64;
        let sectors = u32::from_le_bytes([
            sector0[off + 12],
            sector0[off + 13],
            sector0[off + 14],
            sector0[off + 15],
        ]) as u64;

        if ptype == 0xEE {
            has_gpt_protective = true;
        }
        if sectors > 0 {
            parts.push(PartitionInfo {
                index: i + 1,
                scheme: PartitionScheme::Mbr,
                part_type: ptype,
                start_lba,
                sector_count: sectors,
            });
        }
    }

    if has_gpt_protective && dev.block_count() > 34 {
        let mut lba1 = [0u8; 512];
        dev.read_blocks(1, &mut lba1)?;
        if &lba1[0..8] == b"EFI PART" {
            let entry_lba = u64::from_le_bytes(lba1[72..80].try_into().unwrap());
            let num_entries = u32::from_le_bytes(lba1[80..84].try_into().unwrap()) as usize;
            let entry_size = u32::from_le_bytes(lba1[84..88].try_into().unwrap()) as usize;

            if entry_size >= 128 && entry_size <= 512 {
                let mut gpt_parts = Vec::new();
                let entries_per_sec = 512 / entry_size;
                let max_entries = num_entries.min(128);
                let sectors_to_read = (max_entries + entries_per_sec - 1) / entries_per_sec;
                let valid_entry_table = entry_lba >= 2
                    && entry_lba
                        .checked_add(sectors_to_read as u64)
                        .map_or(false, |end| end <= dev.block_count());
                if valid_entry_table {
                    let mut sec_buf = [0u8; 512];
                    for s in 0..sectors_to_read {
                        dev.read_blocks(entry_lba + s as u64, &mut sec_buf)?;
                        for e in 0..entries_per_sec {
                            let idx = s * entries_per_sec + e;
                            if idx >= max_entries {
                                break;
                            }
                            let off = e * entry_size;
                            let type_guid = &sec_buf[off..off + 16];
                            if type_guid.iter().all(|&b| b == 0) {
                                continue;
                            }
                            let first_lba =
                                u64::from_le_bytes(sec_buf[off + 32..off + 40].try_into().unwrap());
                            let last_lba =
                                u64::from_le_bytes(sec_buf[off + 40..off + 48].try_into().unwrap());
                            if last_lba >= first_lba && last_lba < dev.block_count() {
                                gpt_parts.push(PartitionInfo {
                                    index: idx + 1,
                                    scheme: PartitionScheme::Gpt,
                                    part_type: 0x0C, // Treat GPT data partition uniformly
                                    start_lba: first_lba,
                                    sector_count: last_lba - first_lba + 1,
                                });
                            }
                        }
                    }
                }
                if !gpt_parts.is_empty() {
                    return Ok(gpt_parts);
                }
            }
        }
    }

    Ok(parts)
}

/// Bounds-checked sub-range BlockDevice representing a single disk partition.
pub struct PartitionBlockDevice<'a, D: BlockDevice> {
    inner: &'a mut D,
    info: PartitionInfo,
}

impl<'a, D: BlockDevice> PartitionBlockDevice<'a, D> {
    pub fn new(inner: &'a mut D, info: PartitionInfo) -> Result<Self, BlockError> {
        let end = info
            .start_lba
            .checked_add(info.sector_count)
            .ok_or(BlockError::OutOfBounds)?;
        if end > inner.block_count() {
            return Err(BlockError::OutOfBounds);
        }
        Ok(Self { inner, info })
    }

    pub fn info(&self) -> PartitionInfo {
        self.info
    }
}

impl<'a, D: BlockDevice> BlockDevice for PartitionBlockDevice<'a, D> {
    fn name(&self) -> &str {
        "partition"
    }

    fn block_size(&self) -> usize {
        self.inner.block_size()
    }

    fn block_count(&self) -> u64 {
        self.info.sector_count
    }

    fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        let count = (buf.len() / self.block_size()) as u64;
        if buf.len() % self.block_size() != 0 {
            return Err(BlockError::InvalidSize);
        }
        let end = lba.checked_add(count).ok_or(BlockError::OutOfBounds)?;
        if end > self.info.sector_count {
            return Err(BlockError::OutOfBounds);
        }
        self.inner.read_blocks(self.info.start_lba + lba, buf)
    }

    fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        let count = (buf.len() / self.block_size()) as u64;
        if buf.len() % self.block_size() != 0 {
            return Err(BlockError::InvalidSize);
        }
        let end = lba.checked_add(count).ok_or(BlockError::OutOfBounds)?;
        if end > self.info.sector_count {
            return Err(BlockError::OutOfBounds);
        }
        self.inner.write_blocks(self.info.start_lba + lba, buf)
    }
}
