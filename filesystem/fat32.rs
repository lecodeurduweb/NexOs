//! FAT32 Filesystem Driver (Read + Write + Create + Subdirectories + Mkdir + Remove + Sync).
//!
//! Operates on any `BlockDevice` (e.g. `CachedBlockDevice<OwnedDiskPartition>` or `RamDisk`)
//! and propagates `BlockError` write/flush failures directly upward.

use alloc::string::String;
use alloc::vec::Vec;

use crate::drivers::block::{BlockDevice, BlockError};

const EOC_MIN: u32 = 0x0FFF_FFF8;
const EOC_MARK: u32 = 0x0FFF_FFFF;

#[derive(Clone, Debug)]
pub struct FatEntryInfo {
    pub name: String,
    pub size: u32,
    pub is_dir: bool,
    pub first_cluster: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FatError {
    InvalidBpb,
    NotFound,
    AlreadyExists,
    IsDirectory,
    NotDirectory,
    NotEmpty,
    DiskFull,
    CorruptFs,
    Block(BlockError),
}

impl From<BlockError> for FatError {
    fn from(e: BlockError) -> Self {
        FatError::Block(e)
    }
}

pub struct Fat32<D: BlockDevice> {
    dev: D,
    bytes_per_sector: u32,
    sectors_per_cluster: u32,
    reserved_sectors: u32,
    num_fats: u32,
    fat_size_sectors: u32,
    root_cluster: u32,
    total_clusters: u32,
}

impl<D: BlockDevice> Fat32<D> {
    pub fn mount(mut dev: D) -> Result<Self, FatError> {
        if dev.block_size() != 512 {
            return Err(FatError::InvalidBpb);
        }
        let mut bpb = [0u8; 512];
        dev.read_blocks(0, &mut bpb)?;

        if bpb[510] != 0x55 || bpb[511] != 0xAA {
            return Err(FatError::InvalidBpb);
        }

        let bytes_per_sector = u16::from_le_bytes([bpb[11], bpb[12]]) as u32;
        let sectors_per_cluster = bpb[13] as u32;
        let reserved_sectors = u16::from_le_bytes([bpb[14], bpb[15]]) as u32;
        let num_fats = bpb[16] as u32;
        let total_sectors_16 = u16::from_le_bytes([bpb[19], bpb[20]]) as u32;
        let total_sectors_32 = u32::from_le_bytes([bpb[32], bpb[33], bpb[34], bpb[35]]);
        let fat_size_32 = u32::from_le_bytes([bpb[36], bpb[37], bpb[38], bpb[39]]);
        let root_cluster = u32::from_le_bytes([bpb[44], bpb[45], bpb[46], bpb[47]]);

        if bytes_per_sector != 512
            || sectors_per_cluster == 0
            || !sectors_per_cluster.is_power_of_two()
            || num_fats == 0
            || num_fats > 4
            || fat_size_32 == 0
            || root_cluster < 2
        {
            return Err(FatError::InvalidBpb);
        }

        let total_sectors = if total_sectors_16 != 0 {
            total_sectors_16
        } else {
            total_sectors_32
        };
        if (total_sectors as u64) > dev.block_count() {
            return Err(FatError::InvalidBpb);
        }
        let data_start = reserved_sectors.saturating_add(num_fats.saturating_mul(fat_size_32));
        if total_sectors <= data_start {
            return Err(FatError::InvalidBpb);
        }
        let total_clusters = (total_sectors - data_start) / sectors_per_cluster;
        if total_clusters == 0
            || (total_clusters as u64)
                .saturating_add(2)
                .saturating_mul(4)
                > (fat_size_32 as u64).saturating_mul(512)
        {
            return Err(FatError::InvalidBpb);
        }

        Ok(Self {
            dev,
            bytes_per_sector,
            sectors_per_cluster,
            reserved_sectors,
            num_fats,
            fat_size_sectors: fat_size_32,
            root_cluster,
            total_clusters,
        })
    }

    pub fn block_device(&self) -> &D {
        &self.dev
    }

    pub fn block_device_mut(&mut self) -> &mut D {
        &mut self.dev
    }

    pub fn sync(&mut self) -> Result<(), FatError> {
        self.dev.flush()?;
        Ok(())
    }

    fn first_data_sector(&self) -> u64 {
        (self.reserved_sectors + self.num_fats * self.fat_size_sectors) as u64
    }

    fn is_valid_data_cluster(&self, cluster: u32) -> bool {
        cluster >= 2 && cluster < self.total_clusters.saturating_add(2)
    }

    fn cluster_to_lba(&self, cluster: u32) -> u64 {
        self.first_data_sector() + ((cluster - 2) as u64) * (self.sectors_per_cluster as u64)
    }

    fn read_fat_entry(&mut self, cluster: u32) -> Result<u32, FatError> {
        if !self.is_valid_data_cluster(cluster) {
            return Err(FatError::CorruptFs);
        }
        let fat_offset = (cluster as u64) * 4;
        let sec_rel = fat_offset / 512;
        if sec_rel >= self.fat_size_sectors as u64 {
            return Err(FatError::CorruptFs);
        }
        let fat_sector = (self.reserved_sectors as u64) + sec_rel;
        let ent_off = (fat_offset % 512) as usize;
        let mut sec = [0u8; 512];
        self.dev.read_blocks(fat_sector, &mut sec)?;
        let val = u32::from_le_bytes([sec[ent_off], sec[ent_off + 1], sec[ent_off + 2], sec[ent_off + 3]]);
        Ok(val & 0x0FFF_FFFF)
    }

    fn write_fat_entry(&mut self, cluster: u32, value: u32) -> Result<(), FatError> {
        if !self.is_valid_data_cluster(cluster) {
            return Err(FatError::CorruptFs);
        }
        let fat_offset = (cluster as u64) * 4;
        let sec_rel = fat_offset / 512;
        if sec_rel >= self.fat_size_sectors as u64 {
            return Err(FatError::CorruptFs);
        }
        let ent_off = (fat_offset % 512) as usize;

        for fat_idx in 0..self.num_fats {
            let fat_sector =
                (self.reserved_sectors as u64) + (fat_idx as u64) * (self.fat_size_sectors as u64) + sec_rel;
            let mut sec = [0u8; 512];
            self.dev.read_blocks(fat_sector, &mut sec)?;
            let existing =
                u32::from_le_bytes([sec[ent_off], sec[ent_off + 1], sec[ent_off + 2], sec[ent_off + 3]]);
            let new_val = (existing & 0xF000_0000) | (value & 0x0FFF_FFFF);
            sec[ent_off..ent_off + 4].copy_from_slice(&new_val.to_le_bytes());
            self.dev.write_blocks(fat_sector, &sec)?;
        }
        Ok(())
    }

    fn alloc_cluster(&mut self) -> Result<u32, FatError> {
        let max_c = self.total_clusters.saturating_add(2);
        for c in 2..max_c {
            if self.read_fat_entry(c)? == 0 {
                self.write_fat_entry(c, EOC_MARK)?;
                let zero = alloc::vec![0u8; (self.sectors_per_cluster * 512) as usize];
                let lba = self.cluster_to_lba(c);
                self.dev.write_blocks(lba, &zero)?;
                return Ok(c);
            }
        }
        Err(FatError::DiskFull)
    }

    fn free_chain(&mut self, mut cluster: u32) -> Result<(), FatError> {
        let mut steps = 0u32;
        while cluster >= 2 && cluster < EOC_MIN {
            if !self.is_valid_data_cluster(cluster) || steps > self.total_clusters {
                return Err(FatError::CorruptFs);
            }
            let next = self.read_fat_entry(cluster)?;
            self.write_fat_entry(cluster, 0)?;
            cluster = next;
            steps += 1;
        }
        Ok(())
    }

    fn format_83_name(raw: &[u8; 11]) -> String {
        let name_part = core::str::from_utf8(&raw[0..8]).unwrap_or("").trim_end_matches(' ');
        let ext_part = core::str::from_utf8(&raw[8..11]).unwrap_or("").trim_end_matches(' ');
        if ext_part.is_empty() {
            String::from(name_part)
        } else {
            let mut s = String::from(name_part);
            s.push('.');
            s.push_str(ext_part);
            s
        }
    }

    fn to_83_name(name: &str) -> [u8; 11] {
        let mut out = [b' '; 11];
        let mut parts = name.splitn(2, '.');
        let base = parts.next().unwrap_or("");
        let ext = parts.next().unwrap_or("");
        for (i, b) in base.bytes().take(8).enumerate() {
            out[i] = b.to_ascii_uppercase();
        }
        for (i, b) in ext.bytes().take(3).enumerate() {
            out[8 + i] = b.to_ascii_uppercase();
        }
        out
    }

    fn list_dir_cluster(&mut self, start_cluster: u32) -> Result<Vec<FatEntryInfo>, FatError> {
        let mut entries = Vec::new();
        let mut cluster = start_cluster;
        let cluster_bytes = (self.sectors_per_cluster * self.bytes_per_sector) as usize;
        let mut buf = alloc::vec![0u8; cluster_bytes];
        let mut steps = 0u32;

        while cluster >= 2 && cluster < EOC_MIN {
            if !self.is_valid_data_cluster(cluster) || steps > self.total_clusters {
                return Err(FatError::CorruptFs);
            }
            let lba = self.cluster_to_lba(cluster);
            self.dev.read_blocks(lba, &mut buf)?;
            for off in (0..cluster_bytes).step_by(32) {
                let first = buf[off];
                if first == 0x00 {
                    return Ok(entries);
                }
                if first == 0xE5 {
                    continue;
                }
                let attr = buf[off + 11];
                if attr == 0x0F || (attr & 0x08) != 0 {
                    continue;
                }
                let mut raw_name = [0u8; 11];
                raw_name.copy_from_slice(&buf[off..off + 11]);
                let name = Self::format_83_name(&raw_name);
                if name == "." || name == ".." {
                    continue;
                }
                let ch = u16::from_le_bytes([buf[off + 20], buf[off + 21]]) as u32;
                let cl = u16::from_le_bytes([buf[off + 26], buf[off + 27]]) as u32;
                let size = u32::from_le_bytes([buf[off + 28], buf[off + 29], buf[off + 30], buf[off + 31]]);
                entries.push(FatEntryInfo {
                    name,
                    size,
                    is_dir: (attr & 0x10) != 0,
                    first_cluster: (ch << 16) | cl,
                });
            }
            cluster = self.read_fat_entry(cluster)?;
            steps += 1;
        }
        Ok(entries)
    }

    fn resolve_dir_cluster(&mut self, dir_path: &str) -> Result<u32, FatError> {
        let mut cur = self.root_cluster;
        for seg in dir_path.split('/').filter(|s| !s.is_empty()) {
            let target = Self::format_83_name(&Self::to_83_name(seg));
            let entries = self.list_dir_cluster(cur)?;
            let found = entries
                .into_iter()
                .find(|e| e.name.eq_ignore_ascii_case(&target))
                .ok_or(FatError::NotFound)?;
            if !found.is_dir {
                return Err(FatError::NotDirectory);
            }
            cur = if found.first_cluster < 2 {
                self.root_cluster
            } else {
                found.first_cluster
            };
        }
        Ok(cur)
    }

    fn split_parent<'a>(rel_path: &'a str) -> Result<(&'a str, &'a str), FatError> {
        let trimmed = rel_path.trim_matches('/');
        if trimmed.is_empty() {
            return Err(FatError::NotFound);
        }
        match trimmed.rsplit_once('/') {
            Some((parent, leaf)) => {
                if leaf.is_empty() {
                    Err(FatError::NotFound)
                } else {
                    Ok((parent, leaf))
                }
            }
            None => Ok(("", trimmed)),
        }
    }

    /// List entries in root directory.
    pub fn list_root(&mut self) -> Result<Vec<FatEntryInfo>, FatError> {
        self.list_dir_cluster(self.root_cluster)
    }

    /// List entries in any directory (`""` = root, `"SUBDIR"`, `"A/B"`).
    pub fn list_dir(&mut self, rel_path: &str) -> Result<Vec<FatEntryInfo>, FatError> {
        let cluster = self.resolve_dir_cluster(rel_path)?;
        self.list_dir_cluster(cluster)
    }

    pub fn read_file(&mut self, rel_path: &str) -> Result<Vec<u8>, FatError> {
        let (parent_path, leaf) = Self::split_parent(rel_path)?;
        let dir_cluster = self.resolve_dir_cluster(parent_path)?;
        let target = Self::to_83_name(leaf);
        let target_str = Self::format_83_name(&target);
        let entries = self.list_dir_cluster(dir_cluster)?;
        let entry = entries
            .into_iter()
            .find(|e| e.name.eq_ignore_ascii_case(&target_str))
            .ok_or(FatError::NotFound)?;

        if entry.is_dir {
            return Err(FatError::IsDirectory);
        }

        let cluster_bytes = (self.sectors_per_cluster * self.bytes_per_sector) as usize;
        let max_fs_bytes = (self.total_clusters as u64).saturating_mul(cluster_bytes as u64);
        if (entry.size as u64) > max_fs_bytes {
            return Err(FatError::CorruptFs);
        }

        let mut data = Vec::with_capacity(entry.size as usize);
        let mut cluster = entry.first_cluster;
        let mut buf = alloc::vec![0u8; cluster_bytes];
        let mut steps = 0u32;

        while cluster >= 2 && cluster < EOC_MIN && data.len() < entry.size as usize {
            if !self.is_valid_data_cluster(cluster) || steps > self.total_clusters {
                return Err(FatError::CorruptFs);
            }
            let lba = self.cluster_to_lba(cluster);
            self.dev.read_blocks(lba, &mut buf)?;
            let rem = (entry.size as usize) - data.len();
            let take = rem.min(cluster_bytes);
            data.extend_from_slice(&buf[..take]);
            cluster = self.read_fat_entry(cluster)?;
            steps += 1;
        }

        Ok(data)
    }

    fn upsert_dir_entry(
        &mut self,
        start_dir_cluster: u32,
        name83: &[u8; 11],
        attr: u8,
        first_cluster: u32,
        size: u32,
    ) -> Result<(), FatError> {
        let cluster_bytes = (self.sectors_per_cluster * self.bytes_per_sector) as usize;
        let mut dir_cluster = start_dir_cluster;
        let mut last_dir_cluster = start_dir_cluster;
        let mut buf = alloc::vec![0u8; cluster_bytes];
        let mut steps = 0u32;

        while dir_cluster >= 2 && dir_cluster < EOC_MIN {
            if !self.is_valid_data_cluster(dir_cluster) || steps > self.total_clusters {
                return Err(FatError::CorruptFs);
            }
            let lba = self.cluster_to_lba(dir_cluster);
            self.dev.read_blocks(lba, &mut buf)?;
            for off in (0..cluster_bytes).step_by(32) {
                let tag = buf[off];
                let existing_match = tag != 0x00 && tag != 0xE5 && buf[off..off + 11] == *name83;
                let free_slot = tag == 0x00 || tag == 0xE5;
                if existing_match || free_slot {
                    if existing_match {
                        if (buf[off + 11] & 0x10) != 0 {
                            return Err(FatError::IsDirectory);
                        }
                        let ch = u16::from_le_bytes([buf[off + 20], buf[off + 21]]) as u32;
                        let cl = u16::from_le_bytes([buf[off + 26], buf[off + 27]]) as u32;
                        let old_first = (ch << 16) | cl;
                        if old_first >= 2 {
                            let _ = self.free_chain(old_first);
                        }
                    }
                    buf[off..off + 32].fill(0);
                    buf[off..off + 11].copy_from_slice(name83);
                    buf[off + 11] = attr;
                    let ch = ((first_cluster >> 16) as u16).to_le_bytes();
                    let cl = ((first_cluster & 0xFFFF) as u16).to_le_bytes();
                    let sz = size.to_le_bytes();
                    buf[off + 20..off + 22].copy_from_slice(&ch);
                    buf[off + 26..off + 28].copy_from_slice(&cl);
                    buf[off + 28..off + 32].copy_from_slice(&sz);
                    self.dev.write_blocks(lba, &buf)?;
                    return Ok(());
                }
            }
            last_dir_cluster = dir_cluster;
            dir_cluster = self.read_fat_entry(dir_cluster)?;
            steps += 1;
        }

        // Extend directory cluster chain if current clusters are full
        let new_dir_c = self.alloc_cluster()?;
        self.write_fat_entry(last_dir_cluster, new_dir_c)?;
        let mut new_buf = alloc::vec![0u8; cluster_bytes];
        new_buf[0..11].copy_from_slice(name83);
        new_buf[11] = attr;
        new_buf[20..22].copy_from_slice(&((first_cluster >> 16) as u16).to_le_bytes());
        new_buf[26..28].copy_from_slice(&((first_cluster & 0xFFFF) as u16).to_le_bytes());
        new_buf[28..32].copy_from_slice(&size.to_le_bytes());
        let lba = self.cluster_to_lba(new_dir_c);
        self.dev.write_blocks(lba, &new_buf)?;
        Ok(())
    }

    /// Create or overwrite a file at `rel_path` (supports subdirectories), rolling back on write errors.
    pub fn write_file(&mut self, rel_path: &str, data: &[u8]) -> Result<(), FatError> {
        let (parent_path, leaf) = Self::split_parent(rel_path)?;
        let dir_cluster = self.resolve_dir_cluster(parent_path)?;
        let name83 = Self::to_83_name(leaf);
        let cluster_bytes = (self.sectors_per_cluster * self.bytes_per_sector) as usize;

        let mut first_cluster = 0u32;
        if !data.is_empty() {
            let needed_clusters = (data.len() + cluster_bytes - 1) / cluster_bytes;
            let mut prev = 0u32;
            for idx in 0..needed_clusters {
                let c = match self.alloc_cluster() {
                    Ok(c) => c,
                    Err(e) => {
                        if first_cluster >= 2 {
                            let _ = self.free_chain(first_cluster);
                        }
                        return Err(e);
                    }
                };
                if idx == 0 {
                    first_cluster = c;
                } else if let Err(e) = self.write_fat_entry(prev, c) {
                    let _ = self.free_chain(first_cluster);
                    return Err(e);
                }
                let start = idx * cluster_bytes;
                let end = (start + cluster_bytes).min(data.len());
                let mut cbuf = alloc::vec![0u8; cluster_bytes];
                cbuf[..end - start].copy_from_slice(&data[start..end]);
                let lba = self.cluster_to_lba(c);
                if let Err(e) = self.dev.write_blocks(lba, &cbuf) {
                    let _ = self.free_chain(first_cluster);
                    return Err(e.into());
                }
                prev = c;
            }
        }

        if let Err(e) = self.upsert_dir_entry(dir_cluster, &name83, 0x20, first_cluster, data.len() as u32) {
            if first_cluster >= 2 {
                let _ = self.free_chain(first_cluster);
            }
            return Err(e);
        }
        Ok(())
    }

    /// Create a new FAT32 subdirectory at `rel_path` (parent must exist).
    pub fn mkdir(&mut self, rel_path: &str) -> Result<(), FatError> {
        let (parent_path, leaf) = Self::split_parent(rel_path)?;
        let parent_cluster = self.resolve_dir_cluster(parent_path)?;
        let name83 = Self::to_83_name(leaf);
        let target_str = Self::format_83_name(&name83);

        if self
            .list_dir_cluster(parent_cluster)?
            .iter()
            .any(|e| e.name.eq_ignore_ascii_case(&target_str))
        {
            return Err(FatError::AlreadyExists);
        }

        let new_c = self.alloc_cluster()?;
        let cluster_bytes = (self.sectors_per_cluster * self.bytes_per_sector) as usize;
        let mut dir_buf = alloc::vec![0u8; cluster_bytes];

        // "." entry
        dir_buf[0..11].copy_from_slice(b".          ");
        dir_buf[11] = 0x10;
        dir_buf[20..22].copy_from_slice(&((new_c >> 16) as u16).to_le_bytes());
        dir_buf[26..28].copy_from_slice(&((new_c & 0xFFFF) as u16).to_le_bytes());

        // ".." entry (FAT32 encodes root parent cluster as 0)
        let dotdot_c = if parent_cluster == self.root_cluster {
            0
        } else {
            parent_cluster
        };
        dir_buf[32..43].copy_from_slice(b"..         ");
        dir_buf[43] = 0x10;
        dir_buf[52..54].copy_from_slice(&((dotdot_c >> 16) as u16).to_le_bytes());
        dir_buf[58..60].copy_from_slice(&((dotdot_c & 0xFFFF) as u16).to_le_bytes());

        let lba = self.cluster_to_lba(new_c);
        if let Err(e) = self.dev.write_blocks(lba, &dir_buf) {
            let _ = self.free_chain(new_c);
            return Err(e.into());
        }

        if let Err(e) = self.upsert_dir_entry(parent_cluster, &name83, 0x10, new_c, 0) {
            let _ = self.free_chain(new_c);
            return Err(e);
        }
        Ok(())
    }

    /// Delete a file or empty directory at `rel_path`.
    pub fn remove(&mut self, rel_path: &str) -> Result<(), FatError> {
        let (parent_path, leaf) = Self::split_parent(rel_path)?;
        let parent_cluster = self.resolve_dir_cluster(parent_path)?;
        let name83 = Self::to_83_name(leaf);
        let cluster_bytes = (self.sectors_per_cluster * self.bytes_per_sector) as usize;

        let mut dir_cluster = parent_cluster;
        let mut buf = alloc::vec![0u8; cluster_bytes];
        let mut steps = 0u32;

        while dir_cluster >= 2 && dir_cluster < EOC_MIN {
            if !self.is_valid_data_cluster(dir_cluster) || steps > self.total_clusters {
                return Err(FatError::CorruptFs);
            }
            let lba = self.cluster_to_lba(dir_cluster);
            self.dev.read_blocks(lba, &mut buf)?;
            for off in (0..cluster_bytes).step_by(32) {
                let tag = buf[off];
                if tag == 0x00 {
                    return Err(FatError::NotFound);
                }
                if tag != 0xE5 && buf[off..off + 11] == name83 {
                    let is_dir = (buf[off + 11] & 0x10) != 0;
                    let ch = u16::from_le_bytes([buf[off + 20], buf[off + 21]]) as u32;
                    let cl = u16::from_le_bytes([buf[off + 26], buf[off + 27]]) as u32;
                    let first_c = (ch << 16) | cl;
                    if is_dir && first_c >= 2 {
                        let children = self.list_dir_cluster(first_c)?;
                        if !children.is_empty() {
                            return Err(FatError::NotEmpty);
                        }
                    }
                    buf[off] = 0xE5;
                    self.dev.write_blocks(lba, &buf)?;
                    if first_c >= 2 {
                        self.free_chain(first_c)?;
                    }
                    return Ok(());
                }
            }
            dir_cluster = self.read_fat_entry(dir_cluster)?;
            steps += 1;
        }
        Err(FatError::NotFound)
    }
}
