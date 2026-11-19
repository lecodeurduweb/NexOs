//! Virtual Filesystem (VFS) Layer for NexOS.
//!
//! Unifies `/ram` (in-memory writable store with directories & metadata) and `/disk`
//! (FAT32 backed by `CachedBlockDevice` over `VirtioBlk` or `Bcm2711Emmc2`)
//! behind a single path-routed API with explicit error propagation.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use crate::drivers::block::cache::{BlockCacheStats, CachedBlockDevice};
use crate::drivers::block::{BlockDevice, BlockError};
use crate::filesystem::fat32::{Fat32, FatError};
use crate::filesystem::part::PartitionBlockDevice;
use crate::sync::SpinLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VfsMeta {
    pub mode: u16,
    pub uid: u16,
    pub gid: u16,
}

impl VfsMeta {
    pub const fn default_file() -> Self {
        Self {
            mode: 0o644,
            uid: 0,
            gid: 0,
        }
    }
    pub const fn default_dir() -> Self {
        Self {
            mode: 0o755,
            uid: 0,
            gid: 0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct VfsEntry {
    pub name: String,
    pub size: usize,
    pub is_dir: bool,
    pub meta: VfsMeta,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VfsError {
    NotFound,
    AlreadyExists,
    InvalidPath,
    NotMounted,
    NotEmpty,
    IsDirectory,
    NotDirectory,
    ReadOnly,
    DiskFull,
    IoError,
}

impl From<FatError> for VfsError {
    fn from(e: FatError) -> Self {
        match e {
            FatError::NotFound => VfsError::NotFound,
            FatError::AlreadyExists => VfsError::AlreadyExists,
            FatError::IsDirectory => VfsError::IsDirectory,
            FatError::NotDirectory => VfsError::NotDirectory,
            FatError::NotEmpty => VfsError::NotEmpty,
            FatError::DiskFull => VfsError::DiskFull,
            FatError::Block(BlockError::ReadOnly) => VfsError::ReadOnly,
            _ => VfsError::IoError,
        }
    }
}

struct RamNode {
    data: Vec<u8>,
    meta: VfsMeta,
}

struct VfsState {
    ram_files: BTreeMap<String, RamNode>,
    ram_dirs: BTreeSet<String>,
    disk_fs: Option<Fat32<CachedBlockDevice<OwnedDiskPartition>>>,
}

impl VfsState {
    const fn empty() -> Self {
        Self {
            ram_files: BTreeMap::new(),
            ram_dirs: BTreeSet::new(),
            disk_fs: None,
        }
    }
}

/// Generic owned partition wrapper supporting VirtIO-BLK (QEMU) and BCM2711 EMMC2 (Pi 4).
pub struct OwnedDiskPartition {
    dev: Box<dyn BlockDevice + Send>,
    label: &'static str,
    start_lba: u64,
    sector_count: u64,
}

impl OwnedDiskPartition {
    pub fn new<D: BlockDevice + Send + 'static>(
        dev: D,
        start_lba: u64,
        sector_count: u64,
    ) -> Result<Self, BlockError> {
        let end = start_lba
            .checked_add(sector_count)
            .ok_or(BlockError::OutOfBounds)?;
        if end > dev.block_count() {
            return Err(BlockError::OutOfBounds);
        }
        Ok(Self {
            label: "disk0p1",
            dev: Box::new(dev),
            start_lba,
            sector_count,
        })
    }

    pub fn with_label(mut self, label: &'static str) -> Self {
        self.label = label;
        self
    }
}

impl BlockDevice for OwnedDiskPartition {
    fn name(&self) -> &str {
        self.label
    }
    fn block_size(&self) -> usize {
        self.dev.block_size()
    }
    fn block_count(&self) -> u64 {
        self.sector_count
    }
    fn read_only(&self) -> bool {
        self.dev.read_only()
    }
    fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        let secs = (buf.len() / 512) as u64;
        if buf.len() % 512 != 0 {
            return Err(BlockError::InvalidSize);
        }
        if lba.checked_add(secs).ok_or(BlockError::OutOfBounds)? > self.sector_count {
            return Err(BlockError::OutOfBounds);
        }
        self.dev.read_blocks(self.start_lba + lba, buf)
    }
    fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        let secs = (buf.len() / 512) as u64;
        if buf.len() % 512 != 0 {
            return Err(BlockError::InvalidSize);
        }
        if lba.checked_add(secs).ok_or(BlockError::OutOfBounds)? > self.sector_count {
            return Err(BlockError::OutOfBounds);
        }
        self.dev.write_blocks(self.start_lba + lba, buf)
    }
    fn flush(&mut self) -> Result<(), BlockError> {
        self.dev.flush()
    }
}

static VFS: SpinLock<VfsState> = SpinLock::new(VfsState::empty());

fn normalize_rel(raw: &str) -> Result<String, VfsError> {
    let trimmed = raw.trim_matches('/');
    if trimmed.is_empty() || trimmed.contains('\\') || trimmed.bytes().any(|b| b == 0) {
        return Err(VfsError::InvalidPath);
    }
    let mut parts = Vec::new();
    for seg in trimmed.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return Err(VfsError::InvalidPath);
        }
        parts.push(seg);
    }
    Ok(parts.join("/"))
}

pub fn init_ramfs() {
    let mut vfs = VFS.lock();
    vfs.ram_files.insert(
        String::from("motd.txt"),
        RamNode {
            data: Vec::from(b"NexOS RAMFS active (/ram).\n".as_slice()),
            meta: VfsMeta::default_file(),
        },
    );
}

pub fn mount_fat32_disk(part: OwnedDiskPartition) -> Result<(), VfsError> {
    let cached = CachedBlockDevice::new(part);
    let fs = Fat32::mount(cached)?;
    VFS.lock().disk_fs = Some(fs);
    Ok(())
}

pub fn umount_disk() -> Result<(), VfsError> {
    let mut vfs = VFS.lock();
    if let Some(mut fs) = vfs.disk_fs.take() {
        fs.sync()?;
    }
    Ok(())
}

pub fn sync() -> Result<(), VfsError> {
    let mut vfs = VFS.lock();
    if let Some(fs) = vfs.disk_fs.as_mut() {
        fs.sync()?;
    }
    Ok(())
}

pub fn is_disk_mounted() -> bool {
    VFS.lock().disk_fs.is_some()
}

pub fn cache_stats() -> Option<BlockCacheStats> {
    VFS.lock()
        .disk_fs
        .as_ref()
        .map(|fs| fs.block_device().stats())
}

pub fn list_dir(path: &str) -> Result<Vec<VfsEntry>, VfsError> {
    let mut vfs = VFS.lock();
    if path == "/" {
        let mut out = Vec::new();
        out.push(VfsEntry {
            name: String::from("ram"),
            size: 0,
            is_dir: true,
            meta: VfsMeta::default_dir(),
        });
        if vfs.disk_fs.is_some() {
            out.push(VfsEntry {
                name: String::from("disk"),
                size: 0,
                is_dir: true,
                meta: VfsMeta::default_dir(),
            });
        }
        return Ok(out);
    }
    if path == "/ram" || path == "/ram/" {
        return list_ram_dir(&vfs, "");
    }
    if let Some(rel_raw) = path.strip_prefix("/ram/") {
        let rel = normalize_rel(rel_raw)?;
        if !vfs.ram_dirs.contains(&rel) {
            return Err(VfsError::NotFound);
        }
        return list_ram_dir(&vfs, &rel);
    }
    if path == "/disk" || path == "/disk/" {
        let fs = vfs.disk_fs.as_mut().ok_or(VfsError::NotMounted)?;
        let entries = fs.list_root()?;
        return Ok(entries
            .into_iter()
            .map(|e| VfsEntry {
                name: e.name,
                size: e.size as usize,
                is_dir: e.is_dir,
                meta: if e.is_dir {
                    VfsMeta::default_dir()
                } else {
                    VfsMeta::default_file()
                },
            })
            .collect());
    }
    if let Some(rel_raw) = path.strip_prefix("/disk/") {
        let rel = normalize_rel(rel_raw)?;
        let fs = vfs.disk_fs.as_mut().ok_or(VfsError::NotMounted)?;
        let entries = fs.list_dir(&rel)?;
        return Ok(entries
            .into_iter()
            .map(|e| VfsEntry {
                name: e.name,
                size: e.size as usize,
                is_dir: e.is_dir,
                meta: if e.is_dir {
                    VfsMeta::default_dir()
                } else {
                    VfsMeta::default_file()
                },
            })
            .collect());
    }
    Err(VfsError::InvalidPath)
}

fn list_ram_dir(vfs: &VfsState, prefix: &str) -> Result<Vec<VfsEntry>, VfsError> {
    let mut out = Vec::new();
    let slash_prefix = if prefix.is_empty() {
        String::new()
    } else {
        alloc::format!("{}/", prefix)
    };
    for d in vfs.ram_dirs.iter() {
        if let Some(rest) = d.strip_prefix(&slash_prefix) {
            if !rest.is_empty() && !rest.contains('/') {
                out.push(VfsEntry {
                    name: String::from(rest),
                    size: 0,
                    is_dir: true,
                    meta: VfsMeta::default_dir(),
                });
            }
        }
    }
    for (k, v) in vfs.ram_files.iter() {
        if let Some(rest) = k.strip_prefix(&slash_prefix) {
            if !rest.is_empty() && !rest.contains('/') {
                out.push(VfsEntry {
                    name: String::from(rest),
                    size: v.data.len(),
                    is_dir: false,
                    meta: v.meta,
                });
            }
        }
    }
    Ok(out)
}

pub fn read_file(path: &str) -> Result<Vec<u8>, VfsError> {
    let mut vfs = VFS.lock();
    if let Some(rel_raw) = path.strip_prefix("/ram/") {
        let rel = normalize_rel(rel_raw)?;
        return vfs
            .ram_files
            .get(&rel)
            .map(|n| n.data.clone())
            .ok_or(VfsError::NotFound);
    }
    if let Some(rel_raw) = path.strip_prefix("/disk/") {
        let rel = normalize_rel(rel_raw)?;
        let fs = vfs.disk_fs.as_mut().ok_or(VfsError::NotMounted)?;
        return Ok(fs.read_file(&rel)?);
    }
    Err(VfsError::InvalidPath)
}

pub fn write_file(path: &str, data: &[u8]) -> Result<(), VfsError> {
    let mut vfs = VFS.lock();
    if let Some(rel_raw) = path.strip_prefix("/ram/") {
        let rel = normalize_rel(rel_raw)?;
        if let Some((parent, _)) = rel.rsplit_once('/') {
            if !vfs.ram_dirs.contains(parent) {
                return Err(VfsError::NotFound);
            }
        }
        let meta = vfs
            .ram_files
            .get(&rel)
            .map(|n| n.meta)
            .unwrap_or_else(VfsMeta::default_file);
        vfs.ram_files.insert(
            rel,
            RamNode {
                data: Vec::from(data),
                meta,
            },
        );
        return Ok(());
    }
    if let Some(rel_raw) = path.strip_prefix("/disk/") {
        let rel = normalize_rel(rel_raw)?;
        let fs = vfs.disk_fs.as_mut().ok_or(VfsError::NotMounted)?;
        fs.write_file(&rel, data)?;
        return Ok(());
    }
    Err(VfsError::InvalidPath)
}

pub fn mkdir(path: &str) -> Result<(), VfsError> {
    let mut vfs = VFS.lock();
    if let Some(rel_raw) = path.strip_prefix("/ram/") {
        let rel = normalize_rel(rel_raw)?;
        if vfs.ram_dirs.contains(&rel) || vfs.ram_files.contains_key(&rel) {
            return Err(VfsError::AlreadyExists);
        }
        if let Some((parent, _)) = rel.rsplit_once('/') {
            if !vfs.ram_dirs.contains(parent) {
                return Err(VfsError::NotFound);
            }
        }
        vfs.ram_dirs.insert(rel);
        return Ok(());
    }
    if let Some(rel_raw) = path.strip_prefix("/disk/") {
        let rel = normalize_rel(rel_raw)?;
        let fs = vfs.disk_fs.as_mut().ok_or(VfsError::NotMounted)?;
        fs.mkdir(&rel)?;
        return Ok(());
    }
    Err(VfsError::InvalidPath)
}

pub fn remove(path: &str) -> Result<(), VfsError> {
    let mut vfs = VFS.lock();
    if let Some(rel_raw) = path.strip_prefix("/ram/") {
        let rel = normalize_rel(rel_raw)?;
        if vfs.ram_files.remove(&rel).is_some() {
            return Ok(());
        }
        if vfs.ram_dirs.contains(&rel) {
            let prefix = alloc::format!("{}/", rel);
            let has_child = vfs.ram_dirs.iter().any(|d| d.starts_with(&prefix))
                || vfs.ram_files.keys().any(|f| f.starts_with(&prefix));
            if has_child {
                return Err(VfsError::NotEmpty);
            }
            vfs.ram_dirs.remove(&rel);
            return Ok(());
        }
        return Err(VfsError::NotFound);
    }
    if let Some(rel_raw) = path.strip_prefix("/disk/") {
        let rel = normalize_rel(rel_raw)?;
        let fs = vfs.disk_fs.as_mut().ok_or(VfsError::NotMounted)?;
        fs.remove(&rel)?;
        return Ok(());
    }
    Err(VfsError::InvalidPath)
}

pub fn chmod(path: &str, mode: u16) -> Result<(), VfsError> {
    let mut vfs = VFS.lock();
    if let Some(rel_raw) = path.strip_prefix("/ram/") {
        let rel = normalize_rel(rel_raw)?;
        let node = vfs.ram_files.get_mut(&rel).ok_or(VfsError::NotFound)?;
        node.meta.mode = mode & 0o777;
        return Ok(());
    }
    Err(VfsError::InvalidPath)
}

pub fn stat(path: &str) -> Result<VfsEntry, VfsError> {
    let mut vfs = VFS.lock();
    if let Some(rel_raw) = path.strip_prefix("/ram/") {
        let rel = normalize_rel(rel_raw)?;
        if let Some(n) = vfs.ram_files.get(&rel) {
            let leaf = rel.rsplit_once('/').map(|(_, l)| l).unwrap_or(&rel);
            return Ok(VfsEntry {
                name: String::from(leaf),
                size: n.data.len(),
                is_dir: false,
                meta: n.meta,
            });
        }
        if vfs.ram_dirs.contains(&rel) {
            let leaf = rel.rsplit_once('/').map(|(_, l)| l).unwrap_or(&rel);
            return Ok(VfsEntry {
                name: String::from(leaf),
                size: 0,
                is_dir: true,
                meta: VfsMeta::default_dir(),
            });
        }
        return Err(VfsError::NotFound);
    }
    if let Some(rel_raw) = path.strip_prefix("/disk/") {
        let rel = normalize_rel(rel_raw)?;
        let (parent, leaf) = match rel.rsplit_once('/') {
            Some((p, l)) => (p, l),
            None => ("", rel.as_str()),
        };
        let fs = vfs.disk_fs.as_mut().ok_or(VfsError::NotMounted)?;
        let entries = fs.list_dir(parent)?;
        return entries
            .into_iter()
            .find(|e| e.name.eq_ignore_ascii_case(leaf))
            .map(|e| VfsEntry {
                name: e.name,
                size: e.size as usize,
                is_dir: e.is_dir,
                meta: if e.is_dir {
                    VfsMeta::default_dir()
                } else {
                    VfsMeta::default_file()
                },
            })
            .ok_or(VfsError::NotFound);
    }
    Err(VfsError::InvalidPath)
}

/// Silence unused PartitionBlockDevice warning when borrowed temporarily
pub fn _verify_partition_bounds<D: BlockDevice>(
    dev: &mut PartitionBlockDevice<'_, D>,
) -> Result<(), BlockError> {
    let oob_lba = dev.block_count();
    let dummy = [0u8; 512];
    dev.write_blocks(oob_lba, &dummy)
}
