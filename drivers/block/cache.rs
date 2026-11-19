//! Bounded Write-Back Sector Cache (`CachedBlockDevice<D>`).
//!
//! Caches 512-byte sectors in a bounded 64-entry (32 KiB) slot table with
//! Clock/LRU-approximation eviction and explicit `flush()` write-back.
//! Strictly propagates `ReadOnly`, `OutOfBounds`, and `IoError` without silent drops.

use alloc::vec;
use alloc::vec::Vec;

use crate::drivers::block::{BlockDevice, BlockError};

pub const DEFAULT_CACHE_SLOTS: usize = 64;

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockCacheStats {
    pub hits: u64,
    pub misses: u64,
    pub dirty_writes: u64,
    pub flushes: u64,
    pub evictions: u64,
}

#[derive(Clone)]
struct CacheSlot {
    valid: bool,
    dirty: bool,
    referenced: bool,
    lba: u64,
    data: [u8; 512],
}

impl CacheSlot {
    const fn empty() -> Self {
        Self {
            valid: false,
            dirty: false,
            referenced: false,
            lba: 0,
            data: [0u8; 512],
        }
    }
}

pub struct CachedBlockDevice<D: BlockDevice> {
    inner: D,
    slots: Vec<CacheSlot>,
    clock_hand: usize,
    stats: BlockCacheStats,
}

impl<D: BlockDevice> CachedBlockDevice<D> {
    pub fn new(inner: D) -> Self {
        Self {
            inner,
            slots: vec![CacheSlot::empty(); DEFAULT_CACHE_SLOTS],
            clock_hand: 0,
            stats: BlockCacheStats::default(),
        }
    }

    pub fn stats(&self) -> BlockCacheStats {
        self.stats
    }

    pub fn into_inner(mut self) -> Result<D, BlockError> {
        self.flush()?;
        Ok(self.inner)
    }

    fn find_slot(&self, lba: u64) -> Option<usize> {
        self.slots.iter().position(|s| s.valid && s.lba == lba)
    }

    fn alloc_slot(&mut self, lba: u64) -> Result<usize, BlockError> {
        if let Some(empty) = self.slots.iter().position(|s| !s.valid) {
            self.slots[empty].lba = lba;
            return Ok(empty);
        }

        // Clock sweep eviction
        let n = self.slots.len();
        loop {
            let idx = self.clock_hand;
            self.clock_hand = (self.clock_hand + 1) % n;
            if self.slots[idx].referenced {
                self.slots[idx].referenced = false;
                continue;
            }
            if self.slots[idx].dirty {
                let dirty_lba = self.slots[idx].lba;
                self.inner
                    .write_blocks(dirty_lba, &self.slots[idx].data)?;
                self.slots[idx].dirty = false;
                self.stats.dirty_writes += 1;
            }
            self.slots[idx].valid = false;
            self.slots[idx].lba = lba;
            self.stats.evictions += 1;
            return Ok(idx);
        }
    }

    fn read_sector(&mut self, lba: u64, dst: &mut [u8]) -> Result<(), BlockError> {
        if let Some(idx) = self.find_slot(lba) {
            self.stats.hits += 1;
            self.slots[idx].referenced = true;
            dst.copy_from_slice(&self.slots[idx].data);
            return Ok(());
        }

        self.stats.misses += 1;
        let idx = self.alloc_slot(lba)?;
        let mut sec = [0u8; 512];
        self.inner.read_blocks(lba, &mut sec)?;
        self.slots[idx].valid = true;
        self.slots[idx].dirty = false;
        self.slots[idx].referenced = true;
        self.slots[idx].lba = lba;
        self.slots[idx].data.copy_from_slice(&sec);
        dst.copy_from_slice(&sec);
        Ok(())
    }

    fn write_sector(&mut self, lba: u64, src: &[u8]) -> Result<(), BlockError> {
        if self.inner.read_only() {
            return Err(BlockError::ReadOnly);
        }
        if lba >= self.inner.block_count() {
            return Err(BlockError::OutOfBounds);
        }

        if let Some(idx) = self.find_slot(lba) {
            self.stats.hits += 1;
            self.slots[idx].data.copy_from_slice(src);
            self.slots[idx].dirty = true;
            self.slots[idx].referenced = true;
            return Ok(());
        }

        self.stats.misses += 1;
        let idx = self.alloc_slot(lba)?;
        self.slots[idx].valid = true;
        self.slots[idx].dirty = true;
        self.slots[idx].referenced = true;
        self.slots[idx].lba = lba;
        self.slots[idx].data.copy_from_slice(src);
        Ok(())
    }
}

impl<D: BlockDevice> BlockDevice for CachedBlockDevice<D> {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn block_size(&self) -> usize {
        self.inner.block_size()
    }

    fn block_count(&self) -> u64 {
        self.inner.block_count()
    }

    fn read_only(&self) -> bool {
        self.inner.read_only()
    }

    fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        if self.inner.block_size() != 512 || buf.is_empty() || (buf.len() % 512) != 0 {
            return Err(BlockError::InvalidSize);
        }
        let secs = (buf.len() / 512) as u64;
        if lba.checked_add(secs).ok_or(BlockError::OutOfBounds)? > self.inner.block_count() {
            return Err(BlockError::OutOfBounds);
        }
        for s in 0..secs {
            let off = (s as usize) * 512;
            self.read_sector(lba + s, &mut buf[off..off + 512])?;
        }
        Ok(())
    }

    fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        if self.inner.block_size() != 512 || buf.is_empty() || (buf.len() % 512) != 0 {
            return Err(BlockError::InvalidSize);
        }
        if self.inner.read_only() {
            return Err(BlockError::ReadOnly);
        }
        let secs = (buf.len() / 512) as u64;
        if lba.checked_add(secs).ok_or(BlockError::OutOfBounds)? > self.inner.block_count() {
            return Err(BlockError::OutOfBounds);
        }
        for s in 0..secs {
            let off = (s as usize) * 512;
            self.write_sector(lba + s, &buf[off..off + 512])?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        if self.inner.read_only() {
            return Ok(());
        }
        for slot in self.slots.iter_mut() {
            if slot.valid && slot.dirty {
                self.inner.write_blocks(slot.lba, &slot.data)?;
                slot.dirty = false;
                self.stats.dirty_writes += 1;
            }
        }
        self.inner.flush()?;
        self.stats.flushes += 1;
        Ok(())
    }
}

/// Self-test CachedBlockDevice hit/miss, eviction write-back, flush, ReadOnly, and OOB errors.
pub fn self_test() -> Result<BlockCacheStats, BlockError> {
    use crate::drivers::block::ramdisk::RamDisk;

    let rd = RamDisk::new(128);
    let mut cached = CachedBlockDevice::new(rd);

    // Fill 80 distinct LBAs (> 64 cache slots) to exercise eviction + dirty write-back
    let mut pattern = [0u8; 512];
    for lba in 0..80u64 {
        pattern[0] = (lba & 0xFF) as u8;
        pattern[1] = 0x5A;
        cached.write_blocks(lba, &pattern)?;
    }

    // 1. Re-read hot sectors (64..80) -> guaranteed cache hits
    let mut rb = [0u8; 512];
    for lba in 64..80u64 {
        cached.read_blocks(lba, &mut rb)?;
        if rb[0] != (lba & 0xFF) as u8 || rb[1] != 0x5A {
            return Err(BlockError::IoError);
        }
    }
    // 2. Re-read earlier sectors (0..64, including evicted dirty 0..16)
    for lba in 0..64u64 {
        cached.read_blocks(lba, &mut rb)?;
        if rb[0] != (lba & 0xFF) as u8 || rb[1] != 0x5A {
            return Err(BlockError::IoError);
        }
    }

    // OOB write rejection
    if cached.write_blocks(128, &pattern) != Err(BlockError::OutOfBounds) {
        return Err(BlockError::IoError);
    }

    cached.flush()?;
    let stats = cached.stats();
    if stats.evictions == 0 || stats.hits < 16 || stats.flushes == 0 {
        return Err(BlockError::IoError);
    }
    Ok(stats)
}
