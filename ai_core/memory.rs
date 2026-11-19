//! Persistent and temporary NexOS AI memory.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::convert::TryInto;

use crate::filesystem::vfs;
use crate::security::sha256::crc32;
use crate::sync::SpinLock;

const MEMORY_PATH: &str = "/disk/NEXOS_AI_MEMORY.DB";
const MAGIC: &[u8; 4] = b"NAIM";
const VERSION: u32 = 1;
const MAX_ENTRIES: usize = 32;
const MAX_TEXT: usize = 1024;

#[derive(Clone)]
pub struct MemoryEntry {
    pub kind: String,
    pub agent: String,
    pub text: String,
}

struct MemoryState {
    entries: Vec<MemoryEntry>,
}

static MEMORY: SpinLock<MemoryState> = SpinLock::new(MemoryState {
    entries: Vec::new(),
});

fn encode(entry: &MemoryEntry) -> Option<Vec<u8>> {
    if entry.text.len() > MAX_TEXT || entry.kind.len() > 32 || entry.agent.len() > 32 {
        return None;
    }
    let mut out = Vec::new();
    out.extend_from_slice(&(entry.kind.len() as u16).to_le_bytes());
    out.extend_from_slice(entry.kind.as_bytes());
    out.extend_from_slice(&(entry.agent.len() as u16).to_le_bytes());
    out.extend_from_slice(entry.agent.as_bytes());
    out.extend_from_slice(&(entry.text.len() as u16).to_le_bytes());
    out.extend_from_slice(entry.text.as_bytes());
    Some(out)
}

fn decode(mut data: &[u8]) -> Option<MemoryEntry> {
    if data.len() < 2 { return None; }
    let kl = u16::from_le_bytes(data[0..2].try_into().ok()? ) as usize;
    data = &data[2..];
    if data.len() < kl { return None; }
    let kind = core::str::from_utf8(&data[..kl]).ok()?.to_string();
    data = &data[kl..];
    if data.len() < 2 { return None; }
    let al = u16::from_le_bytes(data[0..2].try_into().ok()? ) as usize;
    data = &data[2..];
    if data.len() < al { return None; }
    let agent = core::str::from_utf8(&data[..al]).ok()?.to_string();
    data = &data[al..];
    if data.len() < 2 { return None; }
    let tl = u16::from_le_bytes(data[0..2].try_into().ok()? ) as usize;
    data = &data[2..];
    if data.len() < tl || tl > MAX_TEXT { return None; }
    let text = core::str::from_utf8(&data[..tl]).ok()?.to_string();
    Some(MemoryEntry { kind, agent, text })
}

pub fn init() {
    if !vfs::is_disk_mounted() { return; }
    let Ok(blob) = vfs::read_file(MEMORY_PATH) else { return; };
    if blob.len() < 16 || &blob[0..4] != MAGIC { return; }
    if u32::from_le_bytes(blob[4..8].try_into().unwrap()) != VERSION { return; }
    let count = u32::from_le_bytes(blob[8..12].try_into().unwrap()) as usize;
    let stored_crc = u32::from_le_bytes(blob[12..16].try_into().unwrap());
    if crc32(&blob[16..]) != stored_crc { return; }
    let mut off = 16usize;
    let mut entries = Vec::new();
    for _ in 0..count.min(MAX_ENTRIES) {
        if off + 2 > blob.len() { return; }
        let len = u16::from_le_bytes(blob[off..off+2].try_into().unwrap()) as usize;
        off += 2;
        if off + len > blob.len() { return; }
        if let Some(entry) = decode(&blob[off..off+len]) {
            entries.push(entry);
        }
        off += len;
    }
    MEMORY.lock().entries = entries;
}

fn persist(entries: &[MemoryEntry]) -> bool {
    if !vfs::is_disk_mounted() { return false; }
    let mut blob = Vec::new();
    blob.extend_from_slice(MAGIC);
    blob.extend_from_slice(&VERSION.to_le_bytes());
    blob.extend_from_slice(&(entries.len().min(MAX_ENTRIES) as u32).to_le_bytes());
    blob.extend_from_slice(&[0u8; 4]); // CRC placeholder
    let count = entries.len().min(MAX_ENTRIES);
    for entry in &entries[entries.len().saturating_sub(count)..] {
        if let Some(encoded) = encode(entry) {
            blob.extend_from_slice(&(encoded.len() as u16).to_le_bytes());
            blob.extend_from_slice(&encoded);
        }
    }
    let crc = crc32(&blob[16..]);
    blob[12..16].copy_from_slice(&crc.to_le_bytes());
    vfs::write_file(MEMORY_PATH, &blob).is_ok() && vfs::sync().is_ok()
}

pub fn push(kind: &str, agent: &str, text: &str) {
    let mut state = MEMORY.lock();
    if state.entries.len() >= MAX_ENTRIES {
        state.entries.remove(0);
    }
    state.entries.push(MemoryEntry {
        kind: String::from(kind),
        agent: String::from(agent),
        text: String::from(text),
    });
    let _ = persist(&state.entries);
}

pub fn entries() -> Vec<MemoryEntry> {
    MEMORY.lock().entries.clone()
}
