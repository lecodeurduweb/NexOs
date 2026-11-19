//! NexOS Native Autonomous AI Agent (`ai_core/agent.rs`).
//!
//! Provides:
//! - Persistent conversation history & repair ledger (`/disk/AIMEM.DB`, CRC-32 verified)
//! - Strict allowlisted operational tool catalog (no raw arbitrary command execution)
//! - Multi-subsystem system diagnostics & log anomaly analysis
//! - RBAC-bounded automatic repairs (`PERM_MANAGE_SERVICES`, `PERM_WRITE_VFS`, `PERM_AI_ADMIN`)
//! - Mandatory post-repair state verification & deterministic rollback/undo
//! - Grounded conversational interface with prompt-injection defense & `.nxm` delegation

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::convert::TryInto;

use crate::arch::timer;
use crate::filesystem::vfs;
use crate::klog;
use crate::log::{self, LogLevel};
use crate::memory::{ai_arena, heap, phys};
use crate::network;
use crate::scheduler;
use crate::security::{
    self, sha256::crc32, PERM_AI_ADMIN, PERM_MANAGE_SERVICES, PERM_READ_METRICS, PERM_WRITE_VFS,
};
use crate::services::{self, ServiceState};
use crate::sync::Mutex;

const AIMEM_DB_PATH: &str = "/disk/AIMEM.DB";
const AIMEM_BACKUP_PATH: &str = "/disk/AIMEM.BAK";
const AIMEM_MAGIC: &[u8; 4] = b"NXAI";
const AIMEM_VERSION_V1: u32 = 1;
const AIMEM_VERSION: u32 = 2;
const MAX_HISTORY_TURNS: usize = 32;
const MAX_REPAIR_RECORDS: usize = 16;
const MAX_MEMORY_FACTS: usize = 16;

const PROTECTED_SERVICES: &[&str] = &["storage-vfs", "net-stack", "web-admin", "ai-core"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TurnRole {
    User = 0,
    Assistant = 1,
    System = 2,
}

impl TurnRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            TurnRole::User => "user",
            TurnRole::Assistant => "assistant",
            TurnRole::System => "system",
        }
    }

    const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(TurnRole::User),
            1 => Some(TurnRole::Assistant),
            2 => Some(TurnRole::System),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct ConversationTurn {
    pub uptime_ms: u64,
    pub role: TurnRole,
    pub tool: String,
    pub text: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepairKind {
    StartService = 0,
    RestartService = 1,
    UnlockUser = 2,
    VfsSync = 3,
    FsckRepair = 4,
}

impl RepairKind {
    const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(RepairKind::StartService),
            1 => Some(RepairKind::RestartService),
            2 => Some(RepairKind::UnlockUser),
            3 => Some(RepairKind::VfsSync),
            4 => Some(RepairKind::FsckRepair),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            RepairKind::StartService => "service_start",
            RepairKind::RestartService => "service_restart",
            RepairKind::UnlockUser => "user_unlock",
            RepairKind::VfsSync => "vfs_sync",
            RepairKind::FsckRepair => "fat32_fsck",
        }
    }

    pub const fn required_perm(self) -> u32 {
        match self {
            RepairKind::StartService | RepairKind::RestartService => PERM_MANAGE_SERVICES,
            RepairKind::UnlockUser => PERM_AI_ADMIN,
            RepairKind::VfsSync | RepairKind::FsckRepair => PERM_WRITE_VFS,
        }
    }
}

#[derive(Clone)]
pub struct MemoryFact {
    pub uptime_ms: u64,
    pub key: String,
    pub value: String,
}

#[derive(Clone)]
pub struct RepairRecord {
    pub id: u64,
    pub uptime_ms: u64,
    pub issue_id: String,
    pub kind: RepairKind,
    pub target: String,
    pub actor: String,
    pub verified: bool,
    pub rolled_back: bool,
}

#[derive(Clone)]
pub struct ToolSpec {
    pub name: &'static str,
    pub mutating: bool,
    pub required_perm: u32,
    pub description: &'static str,
}

#[derive(Clone)]
pub struct DiagnosticIssue {
    pub id: String,
    pub severity: &'static str,
    pub component: &'static str,
    pub summary: String,
    pub proposed_tool: &'static str,
    pub repair_kind: Option<RepairKind>,
    pub target: String,
    pub required_perm: u32,
    pub auto_fixable: bool,
}

#[derive(Clone)]
pub struct DiagnosticReport {
    pub uptime_ms: u64,
    pub health_score: u8,
    pub log_errors: usize,
    pub log_warns: usize,
    pub auth_fails: usize,
    pub issues: Vec<DiagnosticIssue>,
}

#[derive(Clone)]
pub struct RepairOutcome {
    pub repair_id: u64,
    pub issue_id: String,
    pub action: &'static str,
    pub target: String,
    pub verified: bool,
    pub rolled_back: bool,
    pub summary: String,
}

#[derive(Clone)]
pub struct ChatResponse {
    pub reply: String,
    pub tool_used: String,
    pub history_len: usize,
    pub persisted: bool,
    pub model_used: bool,
}

struct AgentState {
    initialized: bool,
    next_repair_id: u64,
    turns: Vec<ConversationTurn>,
    repairs: Vec<RepairRecord>,
    facts: Vec<MemoryFact>,
    repair_window_start_ms: u64,
    repair_window_count: u32,
}

impl AgentState {
    const fn new() -> Self {
        Self {
            initialized: false,
            next_repair_id: 1,
            turns: Vec::new(),
            repairs: Vec::new(),
            facts: Vec::new(),
            repair_window_start_ms: 0,
            repair_window_count: 0,
        }
    }

    fn push_turn(&mut self, turn: ConversationTurn) {
        if self.turns.len() >= MAX_HISTORY_TURNS {
            self.turns.remove(0);
        }
        self.turns.push(turn);
    }

    fn push_repair(&mut self, rec: RepairRecord) {
        if self.repairs.len() >= MAX_REPAIR_RECORDS {
            self.repairs.remove(0);
        }
        self.repairs.push(rec);
    }

    fn push_fact(&mut self, key: &str, value: &str, uptime_ms: u64) {
        if let Some(existing) = self
            .facts
            .iter_mut()
            .find(|f| f.key.eq_ignore_ascii_case(key))
        {
            existing.uptime_ms = uptime_ms;
            existing.value = String::from(value);
            return;
        }
        if self.facts.len() >= MAX_MEMORY_FACTS {
            self.facts.remove(0);
        }
        self.facts.push(MemoryFact {
            uptime_ms,
            key: String::from(key),
            value: String::from(value),
        });
    }
}

static AGENT: Mutex<AgentState> = Mutex::new(AgentState::new());

pub fn allowlisted_tools() -> &'static [ToolSpec] {
    &[
        ToolSpec {
            name: "sys_metrics",
            mutating: false,
            required_perm: PERM_READ_METRICS,
            description: "Read physical RAM, kernel heap, AI Arena, CPUs, and uptime",
        },
        ToolSpec {
            name: "service_list",
            mutating: false,
            required_perm: PERM_READ_METRICS,
            description: "Inspect supervised services, PIDs, states, and restart counts",
        },
        ToolSpec {
            name: "service_start",
            mutating: true,
            required_perm: PERM_MANAGE_SERVICES,
            description: "Start a stopped managed service (rollback-capable)",
        },
        ToolSpec {
            name: "service_restart",
            mutating: true,
            required_perm: PERM_MANAGE_SERVICES,
            description: "Restart a managed daemon and verify new heartbeat",
        },
        ToolSpec {
            name: "service_stop",
            mutating: true,
            required_perm: PERM_MANAGE_SERVICES,
            description: "Stop a non-critical managed service",
        },
        ToolSpec {
            name: "logs_analyze",
            mutating: false,
            required_perm: PERM_READ_METRICS,
            description: "Inspect kernel ring buffer and count error/warning anomalies",
        },
        ToolSpec {
            name: "vfs_stats",
            mutating: false,
            required_perm: PERM_READ_METRICS,
            description: "Inspect /ram and FAT32 /disk mount & block-cache counters",
        },
        ToolSpec {
            name: "vfs_sync",
            mutating: true,
            required_perm: PERM_WRITE_VFS,
            description: "Flush dirty FAT32 block-cache sectors to disk",
        },
        ToolSpec {
            name: "net_status",
            mutating: false,
            required_perm: PERM_READ_METRICS,
            description: "Inspect NIC IPv4/IPv6, MAC, gateway, DNS, and RX/TX counters",
        },
        ToolSpec {
            name: "sec_audit",
            mutating: false,
            required_perm: PERM_AI_ADMIN,
            description: "Inspect user lock status and recent security audit events",
        },
        ToolSpec {
            name: "user_unlock",
            mutating: true,
            required_perm: PERM_AI_ADMIN,
            description: "Unlock a rate-limited user account (rollback-capable)",
        },
        ToolSpec {
            name: "ai_status",
            mutating: false,
            required_perm: PERM_READ_METRICS,
            description: "Read loaded .nxm model and AiArena memory statistics",
        },
        ToolSpec {
            name: "ai_load",
            mutating: true,
            required_perm: PERM_AI_ADMIN,
            description: "Stream an allowed .nxm model from VFS into AiArena",
        },
        ToolSpec {
            name: "ai_unload",
            mutating: true,
            required_perm: PERM_AI_ADMIN,
            description: "Unload active model and reclaim physical frames to OS",
        },
        ToolSpec {
            name: "fat32_fsck",
            mutating: true,
            required_perm: PERM_WRITE_VFS,
            description: "Verify and repair FAT32 FAT mirrors, chains, and orphan clusters",
        },
        ToolSpec {
            name: "thermal_status",
            mutating: false,
            required_perm: PERM_READ_METRICS,
            description: "Read BCM2711 SoC temperature, ARM clock, and throttling flags",
        },
        ToolSpec {
            name: "ai_remember",
            mutating: true,
            required_perm: PERM_AI_ADMIN,
            description: "Store persistent key=value operational facts in /disk/AIMEM.DB",
        },
    ]
}

fn write_str(out: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    let n = b.len().min(512);
    out.extend_from_slice(&(n as u16).to_le_bytes());
    out.extend_from_slice(&b[..n]);
}

fn read_str(data: &[u8], off: &mut usize) -> Result<String, &'static str> {
    let lb: [u8; 2] = data
        .get(*off..*off + 2)
        .ok_or("AIMEM.DB truncated len")?
        .try_into()
        .map_err(|_| "AIMEM.DB bad len")?;
    let n = u16::from_le_bytes(lb) as usize;
    *off += 2;
    let slice = data.get(*off..*off + n).ok_or("AIMEM.DB truncated str")?;
    *off += n;
    let s = core::str::from_utf8(slice).map_err(|_| "AIMEM.DB invalid utf8")?;
    Ok(String::from(s))
}

fn serialize_db(state: &AgentState) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(AIMEM_MAGIC);
    out.extend_from_slice(&AIMEM_VERSION.to_le_bytes());
    out.extend_from_slice(&state.next_repair_id.to_le_bytes());
    out.extend_from_slice(&(state.turns.len() as u32).to_le_bytes());
    out.extend_from_slice(&(state.repairs.len() as u32).to_le_bytes());
    out.extend_from_slice(&(state.facts.len() as u32).to_le_bytes());
    for t in &state.turns {
        out.extend_from_slice(&t.uptime_ms.to_le_bytes());
        out.push(t.role as u8);
        write_str(&mut out, &t.tool);
        write_str(&mut out, &t.text);
    }
    for r in &state.repairs {
        out.extend_from_slice(&r.id.to_le_bytes());
        out.extend_from_slice(&r.uptime_ms.to_le_bytes());
        write_str(&mut out, &r.issue_id);
        out.push(r.kind as u8);
        write_str(&mut out, &r.target);
        write_str(&mut out, &r.actor);
        out.push(if r.verified { 1 } else { 0 });
        out.push(if r.rolled_back { 1 } else { 0 });
    }
    for f in &state.facts {
        out.extend_from_slice(&f.uptime_ms.to_le_bytes());
        write_str(&mut out, &f.key);
        write_str(&mut out, &f.value);
    }
    let crc = crc32(&out);
    out.extend_from_slice(&crc.to_le_bytes());
    out
}

fn deserialize_db(
    data: &[u8],
) -> Result<(u64, Vec<ConversationTurn>, Vec<RepairRecord>, Vec<MemoryFact>), &'static str> {
    if data.len() < 28 || &data[0..4] != AIMEM_MAGIC {
        return Err("Invalid AIMEM.DB magic");
    }
    let ver = u32::from_le_bytes(data[4..8].try_into().unwrap());
    if ver != AIMEM_VERSION_V1 && ver != AIMEM_VERSION {
        return Err("Unsupported AIMEM.DB version");
    }
    let stored_crc = u32::from_le_bytes(data[data.len() - 4..].try_into().unwrap());
    let calc_crc = crc32(&data[..data.len() - 4]);
    if stored_crc != calc_crc {
        return Err("AIMEM.DB CRC-32 mismatch");
    }
    let payload = &data[..data.len() - 4];
    let next_repair_id = u64::from_le_bytes(payload[8..16].try_into().unwrap()).max(1);
    let turn_count = u32::from_le_bytes(payload[16..20].try_into().unwrap()) as usize;
    let repair_count = u32::from_le_bytes(payload[20..24].try_into().unwrap()) as usize;
    let (fact_count, mut off) = if ver == AIMEM_VERSION {
        if payload.len() < 28 {
            return Err("AIMEM.DB v2 truncated header");
        }
        (
            u32::from_le_bytes(payload[24..28].try_into().unwrap()) as usize,
            28usize,
        )
    } else {
        (0usize, 24usize)
    };
    if turn_count > MAX_HISTORY_TURNS
        || repair_count > MAX_REPAIR_RECORDS
        || fact_count > MAX_MEMORY_FACTS
    {
        return Err("AIMEM.DB count exceeds limit");
    }
    let mut turns = Vec::with_capacity(turn_count);
    for _ in 0..turn_count {
        let ub: [u8; 8] = payload
            .get(off..off + 8)
            .ok_or("AIMEM.DB truncated turn")?
            .try_into()
            .unwrap();
        let uptime_ms = u64::from_le_bytes(ub);
        off += 8;
        let role_b = *payload.get(off).ok_or("AIMEM.DB truncated role")?;
        let role = TurnRole::from_u8(role_b).ok_or("AIMEM.DB bad role")?;
        off += 1;
        let tool = read_str(payload, &mut off)?;
        let text = read_str(payload, &mut off)?;
        turns.push(ConversationTurn {
            uptime_ms,
            role,
            tool,
            text,
        });
    }
    let mut repairs = Vec::with_capacity(repair_count);
    for _ in 0..repair_count {
        let hdr_b: [u8; 16] = payload
            .get(off..off + 16)
            .ok_or("AIMEM.DB truncated repair")?
            .try_into()
            .unwrap();
        let id = u64::from_le_bytes(hdr_b[0..8].try_into().unwrap());
        let uptime_ms = u64::from_le_bytes(hdr_b[8..16].try_into().unwrap());
        off += 16;
        let issue_id = read_str(payload, &mut off)?;
        let kb = *payload.get(off).ok_or("AIMEM.DB truncated repair kind")?;
        let kind = RepairKind::from_u8(kb).ok_or("AIMEM.DB bad repair kind")?;
        off += 1;
        let target = read_str(payload, &mut off)?;
        let actor = read_str(payload, &mut off)?;
        let verified = *payload.get(off).ok_or("AIMEM.DB truncated flags")? != 0;
        let rolled_back = *payload.get(off + 1).ok_or("AIMEM.DB truncated flags")? != 0;
        off += 2;
        repairs.push(RepairRecord {
            id,
            uptime_ms,
            issue_id,
            kind,
            target,
            actor,
            verified,
            rolled_back,
        });
    }
    let mut facts = Vec::with_capacity(fact_count);
    for _ in 0..fact_count {
        let ub: [u8; 8] = payload
            .get(off..off + 8)
            .ok_or("AIMEM.DB truncated fact")?
            .try_into()
            .unwrap();
        let uptime_ms = u64::from_le_bytes(ub);
        off += 8;
        let key = read_str(payload, &mut off)?;
        let value = read_str(payload, &mut off)?;
        facts.push(MemoryFact {
            uptime_ms,
            key,
            value,
        });
    }
    if off != payload.len() {
        return Err("AIMEM.DB trailing data");
    }
    Ok((next_repair_id, turns, repairs, facts))
}

fn persist_locked(state: &AgentState) -> bool {
    if !vfs::is_disk_mounted() {
        return false;
    }
    let blob = serialize_db(state);
    vfs::write_atomic_with_backup(AIMEM_DB_PATH, AIMEM_BACKUP_PATH, &blob).is_ok()
}

pub fn init() {
    let mut st = AGENT.lock();
    if st.initialized {
        return;
    }
    let mut loaded_turns = 0usize;
    let mut loaded_repairs = 0usize;
    let mut loaded_facts = 0usize;
    if vfs::is_disk_mounted() {
        match vfs::read_with_backup_fallback(AIMEM_DB_PATH, AIMEM_BACKUP_PATH, |raw| {
            deserialize_db(raw)
        }) {
            Some(((next_id, turns, repairs, facts), recovered)) => {
                loaded_turns = turns.len();
                loaded_repairs = repairs.len();
                loaded_facts = facts.len();
                st.next_repair_id = next_id;
                st.turns = turns;
                st.repairs = repairs;
                st.facts = facts;
                if recovered {
                    klog!(
                        LogLevel::Warn,
                        "ai-agent",
                        "Recovered {} from backup mirror {}",
                        AIMEM_DB_PATH,
                        AIMEM_BACKUP_PATH
                    );
                    security::record_custom_audit(String::from(
                        "AIMEM_RECOVERED source=backup_mirror",
                    ));
                }
            }
            None => {
                if vfs::stat(AIMEM_DB_PATH).is_ok() {
                    klog!(
                        LogLevel::Warn,
                        "ai-agent",
                        "Rejected corrupted {} and backup; starting fresh ledger",
                        AIMEM_DB_PATH
                    );
                }
            }
        }
    }
    st.initialized = true;
    klog!(
        LogLevel::Info,
        "ai-agent",
        "AI Assistant Agent ready (tools={}, persisted_turns={}, repair_records={}, facts={})",
        allowlisted_tools().len(),
        loaded_turns,
        loaded_repairs,
        loaded_facts
    );
}

pub fn history() -> (Vec<ConversationTurn>, Vec<RepairRecord>) {
    let st = AGENT.lock();
    (st.turns.clone(), st.repairs.clone())
}

pub fn facts() -> Vec<MemoryFact> {
    AGENT.lock().facts.clone()
}

pub fn remember(
    key: &str,
    value: &str,
    actor: &str,
    actor_perms: u32,
) -> Result<Vec<MemoryFact>, &'static str> {
    if (actor_perms & (PERM_AI_ADMIN | PERM_WRITE_VFS)) == 0 {
        return Err("Permission denied: PERM_AI_ADMIN or PERM_WRITE_VFS required");
    }
    let k = key.trim();
    let v = value.trim();
    if k.is_empty() || v.is_empty() || k.len() > 64 || v.len() > 256 {
        return Err("Invalid fact key or value length");
    }
    if contains_injection(k) || contains_injection(v) {
        return Err("Blocked by AI security policy");
    }
    let mut st = AGENT.lock();
    st.push_fact(k, v, timer::uptime_ms());
    let persisted = persist_locked(&st);
    security::record_custom_audit(format!(
        "AI_FACT_STORED actor={} key={} persisted={}",
        actor, k, persisted
    ));
    Ok(st.facts.clone())
}

pub fn diagnose() -> DiagnosticReport {
    let now = timer::uptime_ms();
    let mut issues = Vec::new();
    let mut score: i32 = 100;

    // 1. Inspect managed services
    for s in services::snapshot() {
        if s.state == ServiceState::Stopped || s.state == ServiceState::Failed {
            score -= 20;
            issues.push(DiagnosticIssue {
                id: format!("SVC_DOWN:{}", s.name),
                severity: if s.state == ServiceState::Failed {
                    "HIGH"
                } else {
                    "MEDIUM"
                },
                component: "services",
                summary: format!("Service '{}' is {:?} (restarts={})", s.name, s.state, s.restarts),
                proposed_tool: "service_start",
                repair_kind: Some(RepairKind::StartService),
                target: s.name.clone(),
                required_perm: PERM_MANAGE_SERVICES,
                auto_fixable: true,
            });
        } else if s.restarts >= 3 {
            score -= 10;
            issues.push(DiagnosticIssue {
                id: format!("SVC_RESTART_STORM:{}", s.name),
                severity: "MEDIUM",
                component: "services",
                summary: format!("Service '{}' experienced {} watchdog restarts", s.name, s.restarts),
                proposed_tool: "logs_analyze",
                repair_kind: None,
                target: s.name.clone(),
                required_perm: PERM_MANAGE_SERVICES,
                auto_fixable: false,
            });
        }
    }

    // 2. Inspect physical memory, kernel heap, and AI Arena pressure
    let ps = phys::stats();
    let free_pct = if ps.total_frames > 0 {
        (ps.free_frames * 100) / ps.total_frames
    } else {
        100
    };
    if free_pct < 10 {
        score -= 25;
        issues.push(DiagnosticIssue {
            id: String::from("MEM_LOW_FREE"),
            severity: "HIGH",
            component: "memory",
            summary: format!("Low physical free RAM ({}%)", free_pct),
            proposed_tool: "ai_unload",
            repair_kind: None,
            target: String::from("phys"),
            required_perm: PERM_AI_ADMIN,
            auto_fixable: false,
        });
    }
    let hs = heap::stats();
    if hs.mapped_bytes > 0 && (hs.used_bytes * 100) / hs.mapped_bytes > 90 && hs.used_bytes > 32 * 1024 * 1024 {
        score -= 10;
        issues.push(DiagnosticIssue {
            id: String::from("HEAP_PRESSURE"),
            severity: "MEDIUM",
            component: "heap",
            summary: format!("Kernel heap pressure: {} KiB used", hs.used_bytes / 1024),
            proposed_tool: "sys_metrics",
            repair_kind: None,
            target: String::from("heap"),
            required_perm: PERM_READ_METRICS,
            auto_fixable: false,
        });
    }
    let ast = ai_arena::stats();
    if ast.effective_budget_bytes > 0 && (ast.used_bytes * 100) / ast.effective_budget_bytes > 92 {
        score -= 10;
        issues.push(DiagnosticIssue {
            id: String::from("AI_ARENA_PRESSURE"),
            severity: "LOW",
            component: "ai_arena",
            summary: format!(
                "AI Arena at {} MiB / {} MiB",
                ast.used_bytes / (1024 * 1024),
                ast.effective_budget_bytes / (1024 * 1024)
            ),
            proposed_tool: "ai_unload",
            repair_kind: None,
            target: String::from("ai_arena"),
            required_perm: PERM_AI_ADMIN,
            auto_fixable: false,
        });
    }

    // 3. Inspect VFS, FAT32 filesystem consistency, and dirty block cache
    if !vfs::is_disk_mounted() {
        score -= 20;
        issues.push(DiagnosticIssue {
            id: String::from("DISK_UNMOUNTED"),
            severity: "HIGH",
            component: "vfs",
            summary: String::from("/disk FAT32 persistent volume is not mounted"),
            proposed_tool: "vfs_stats",
            repair_kind: None,
            target: String::from("/disk"),
            required_perm: PERM_READ_METRICS,
            auto_fixable: false,
        });
    } else {
        if let Ok(fs_rep) = vfs::fsck_disk(false) {
            if !fs_rep.healthy {
                score -= 15;
                issues.push(DiagnosticIssue {
                    id: String::from("FS_CHECK_ISSUE"),
                    severity: "HIGH",
                    component: "vfs",
                    summary: format!(
                        "FAT32 check found {} FAT mirror mismatch(es), {} orphan cluster(s), {} chain/size error(s)",
                        fs_rep.fat_mirror_mismatches,
                        fs_rep.orphan_clusters,
                        fs_rep.broken_chains + fs_rep.size_mismatches
                    ),
                    proposed_tool: "fat32_fsck",
                    repair_kind: Some(RepairKind::FsckRepair),
                    target: String::from("/disk"),
                    required_perm: PERM_WRITE_VFS,
                    auto_fixable: true,
                });
            }
        }
        if let Some(cs) = vfs::cache_stats() {
            if cs.dirty_writes > cs.flushes.saturating_add(16) {
                score -= 5;
                issues.push(DiagnosticIssue {
                    id: String::from("VFS_DIRTY_CACHE"),
                    severity: "LOW",
                    component: "vfs",
                    summary: format!(
                        "Unflushed block-cache writes (dirty={}, flushes={})",
                        cs.dirty_writes, cs.flushes
                    ),
                    proposed_tool: "vfs_sync",
                    repair_kind: Some(RepairKind::VfsSync),
                    target: String::from("/disk"),
                    required_perm: PERM_WRITE_VFS,
                    auto_fixable: true,
                });
            }
        }
    }

    // 4. Inspect Security accounts & audit events
    for u in security::list_users() {
        if u.locked {
            score -= 10;
            issues.push(DiagnosticIssue {
                id: format!("USER_LOCKED:{}", u.username),
                severity: "MEDIUM",
                component: "security",
                summary: format!("User '{}' is currently locked out (fails={})", u.username, u.failed_attempts),
                proposed_tool: "user_unlock",
                repair_kind: Some(RepairKind::UnlockUser),
                target: u.username,
                required_perm: PERM_AI_ADMIN,
                auto_fixable: true,
            });
        }
    }
    let audits = security::recent_audit_events();
    let auth_fails = audits
        .iter()
        .filter(|ev| ev.contains("AUTH_FAIL") || ev.contains("PERM_DENIED"))
        .count();
    if auth_fails >= 5 {
        score -= 5;
        issues.push(DiagnosticIssue {
            id: String::from("AUTH_FAIL_SPIKE"),
            severity: "LOW",
            component: "security",
            summary: format!("Observed {} auth/permission failures in recent audit buffer", auth_fails),
            proposed_tool: "sec_audit",
            repair_kind: None,
            target: String::from("audit"),
            required_perm: PERM_AI_ADMIN,
            auto_fixable: false,
        });
    }

    // 5. Analyze kernel ring buffer logs
    let recs = log::recent_records(64);
    let mut log_errors = 0usize;
    let mut log_warns = 0usize;
    for r in &recs {
        match r.level {
            LogLevel::Error => log_errors += 1,
            LogLevel::Warn => log_warns += 1,
            _ => {}
        }
    }
    if log_errors > 0 {
        score -= (log_errors as i32 * 5).min(20);
    }

    // 6. Check network stack initialization
    let ns = network::stats();
    if !ns.initialized {
        score -= 10;
        issues.push(DiagnosticIssue {
            id: String::from("NET_UNINIT"),
            severity: "MEDIUM",
            component: "network",
            summary: String::from("Network stack not initialized"),
            proposed_tool: "net_status",
            repair_kind: None,
            target: String::from("net"),
            required_perm: PERM_READ_METRICS,
            auto_fixable: false,
        });
    }

    // 7. Check BCM2711 SoC thermal & throttling telemetry (only when VC4 hardware probed)
    let therm = crate::drivers::mailbox_bcm2711::thermal_status();
    if therm.hardware_probed && (therm.soc_temp_mc >= 80_000 || (therm.throttled_flags & 0xF) != 0) {
        score -= 10;
        issues.push(DiagnosticIssue {
            id: String::from("BCM2711_THERMAL_WARN"),
            severity: "MEDIUM",
            component: "thermal",
            summary: format!(
                "SoC temperature {}.{} C, throttled={:#x}",
                therm.soc_temp_mc / 1000,
                (therm.soc_temp_mc % 1000) / 100,
                therm.throttled_flags
            ),
            proposed_tool: "thermal_status",
            repair_kind: None,
            target: String::from("bcm2711"),
            required_perm: PERM_READ_METRICS,
            auto_fixable: false,
        });
    }

    DiagnosticReport {
        uptime_ms: now,
        health_score: score.clamp(0, 100) as u8,
        log_errors,
        log_warns,
        auth_fails,
        issues,
    }
}

pub fn execute_repair(
    requested_issue: Option<&str>,
    actor: &str,
    actor_perms: u32,
) -> Result<RepairOutcome, &'static str> {
    let report = diagnose();
    let target_issue = match requested_issue {
        Some(id) if !id.trim().is_empty() && id.trim() != "auto" => report
            .issues
            .into_iter()
            .find(|i| i.id == id.trim() && i.auto_fixable)
            .ok_or("Requested auto-fixable issue not found")?,
        _ => report
            .issues
            .into_iter()
            .find(|i| i.auto_fixable)
            .ok_or("No auto-fixable issues detected")?,
    };

    let kind = target_issue.repair_kind.ok_or("Issue has no automated repair")?;
    if (actor_perms & kind.required_perm()) != kind.required_perm() {
        security::record_custom_audit(format!(
            "AI_REPAIR_DENIED actor={} issue={} tool={}",
            actor, target_issue.id, kind.as_str()
        ));
        return Err("Permission denied for requested repair");
    }

    // Rate-limit mutating auto-repairs to max 16 per 10-second window
    {
        let now = timer::uptime_ms();
        let mut st = AGENT.lock();
        if now.saturating_sub(st.repair_window_start_ms) >= 10_000 {
            st.repair_window_start_ms = now;
            st.repair_window_count = 0;
        }
        if st.repair_window_count >= 16 {
            security::record_custom_audit(format!("AI_REPAIR_RATE_LIMITED actor={}", actor));
            return Err("AI repair rate limit exceeded; retry shortly");
        }
        st.repair_window_count += 1;
    }

    let exec_res: Result<(), &'static str> = match kind {
        RepairKind::StartService => services::start_service(&target_issue.target).map(|_| ()),
        RepairKind::RestartService => services::restart_service(&target_issue.target).map(|_| ()),
        RepairKind::UnlockUser => security::unlock_user(&target_issue.target)
            .map(|_| ())
            .map_err(|_| "User unlock failed"),
        RepairKind::VfsSync => vfs::sync().map_err(|_| "VFS sync error"),
        RepairKind::FsckRepair => vfs::fsck_disk(true)
            .map(|_| ())
            .map_err(|_| "FAT32 fsck repair failed"),
    };
    if let Err(e) = exec_res {
        return Err(e);
    }

    // Brief yield to allow restarted daemon/task state to stabilize before verification
    scheduler::sleep_ms(20);

    // Post-repair verification check
    let verified = match kind {
        RepairKind::StartService | RepairKind::RestartService => services::snapshot()
            .into_iter()
            .any(|s| s.name == target_issue.target && s.state == ServiceState::Running),
        RepairKind::UnlockUser => security::list_users()
            .into_iter()
            .any(|u| u.username == target_issue.target && !u.locked),
        RepairKind::VfsSync => vfs::is_disk_mounted(),
        RepairKind::FsckRepair => vfs::fsck_disk(false).map(|r| r.healthy).unwrap_or(false),
    };

    let mut st = AGENT.lock();
    let rid = st.next_repair_id;
    st.next_repair_id += 1;
    let rec = RepairRecord {
        id: rid,
        uptime_ms: timer::uptime_ms(),
        issue_id: target_issue.id.clone(),
        kind,
        target: target_issue.target.clone(),
        actor: String::from(actor),
        verified,
        rolled_back: false,
    };
    st.push_repair(rec);
    st.push_turn(ConversationTurn {
        uptime_ms: timer::uptime_ms(),
        role: TurnRole::System,
        tool: String::from(kind.as_str()),
        text: format!(
            "Repair #{} {} target='{}' by {} -> verified={}",
            rid,
            kind.as_str(),
            target_issue.target,
            actor,
            verified
        ),
    });
    persist_locked(&st);

    security::record_custom_audit(format!(
        "AI_REPAIR_OK id={} actor={} action={} target={} verified={}",
        rid,
        actor,
        kind.as_str(),
        target_issue.target,
        verified
    ));
    klog!(
        LogLevel::Info,
        "ai-agent",
        "Repair #{} applied ({} on '{}', verified={})",
        rid,
        kind.as_str(),
        target_issue.target,
        verified
    );

    Ok(RepairOutcome {
        repair_id: rid,
        issue_id: target_issue.id,
        action: kind.as_str(),
        target: target_issue.target.clone(),
        verified,
        rolled_back: false,
        summary: format!(
            "Applied {} to '{}' (verified={})",
            kind.as_str(),
            target_issue.target,
            verified
        ),
    })
}

pub fn rollback_last(actor: &str, actor_perms: u32) -> Result<RepairOutcome, &'static str> {
    let target_rec = {
        let st = AGENT.lock();
        st.repairs
            .iter()
            .rev()
            .find(|r| !r.rolled_back)
            .cloned()
            .ok_or("No repair record available to roll back")?
    };

    if (actor_perms & target_rec.kind.required_perm()) != target_rec.kind.required_perm() {
        security::record_custom_audit(format!(
            "AI_ROLLBACK_DENIED actor={} id={} target={}",
            actor, target_rec.id, target_rec.target
        ));
        return Err("Permission denied for rollback");
    }

    match target_rec.kind {
        RepairKind::StartService => {
            if PROTECTED_SERVICES.contains(&target_rec.target.as_str()) {
                return Err("Refused rollback stop on critical system service");
            }
            services::stop_service(&target_rec.target)?;
        }
        RepairKind::RestartService => {
            return Err("Restart repair has no destructive inverse to roll back");
        }
        RepairKind::UnlockUser => {
            security::lock_user(&target_rec.target, 30_000).map_err(|_| "Lock rollback failed")?;
        }
        RepairKind::VfsSync | RepairKind::FsckRepair => {
            return Err("Filesystem sync/repair cannot be un-applied");
        }
    }

    scheduler::sleep_ms(15);

    // Post-rollback verification
    let verified = match target_rec.kind {
        RepairKind::StartService => services::snapshot()
            .into_iter()
            .any(|s| s.name == target_rec.target && s.state == ServiceState::Stopped),
        RepairKind::UnlockUser => security::list_users()
            .into_iter()
            .any(|u| u.username == target_rec.target && u.locked),
        _ => false,
    };

    {
        let mut st = AGENT.lock();
        if let Some(rec) = st.repairs.iter_mut().find(|r| r.id == target_rec.id) {
            rec.rolled_back = true;
        }
        st.push_turn(ConversationTurn {
            uptime_ms: timer::uptime_ms(),
            role: TurnRole::System,
            tool: String::from("rollback"),
            text: format!(
                "Rolled back repair #{} ({} '{}') by {} -> verified={}",
                target_rec.id,
                target_rec.kind.as_str(),
                target_rec.target,
                actor,
                verified
            ),
        });
        persist_locked(&st);
    }

    security::record_custom_audit(format!(
        "AI_ROLLBACK_OK id={} actor={} target={} verified={}",
        target_rec.id, actor, target_rec.target, verified
    ));
    klog!(
        LogLevel::Info,
        "ai-agent",
        "Rolled back repair #{} ('{}', verified={})",
        target_rec.id,
        target_rec.target,
        verified
    );

    Ok(RepairOutcome {
        repair_id: target_rec.id,
        issue_id: target_rec.issue_id,
        action: "rollback",
        target: target_rec.target.clone(),
        verified,
        rolled_back: true,
        summary: format!(
            "Rolled back repair #{} on '{}' (verified={})",
            target_rec.id, target_rec.target, verified
        ),
    })
}

fn contains_injection(prompt: &str) -> bool {
    let mut norm = String::with_capacity(prompt.len());
    let mut prev_space = false;
    for ch in prompt.chars() {
        if ch.is_control() && ch != '\n' && ch != '\r' && ch != '\t' {
            continue;
        }
        if ch.is_ascii_whitespace() {
            if !prev_space {
                norm.push(' ');
                prev_space = true;
            }
        } else {
            norm.push(ch.to_ascii_lowercase());
            prev_space = false;
        }
    }
    norm.contains("nexusers")
        || norm.contains("aimem.db")
        || norm.contains("aimem.bak")
        || norm.contains(".bak")
        || norm.contains("../")
        || norm.contains("..\\")
        || norm.contains("ignore previous")
        || norm.contains("ignore all previous")
        || norm.contains("system prompt")
        || norm.contains("reveal prompt")
        || norm.contains("bypass rbac")
        || norm.contains("dump secret")
        || norm.contains("rm -rf")
        || norm.contains("; rm ")
        || norm.contains("$(")
        || norm.contains("`")
        || norm.contains("&&")
        || norm.contains("||")
}

pub fn chat(prompt: &str, actor: &str, actor_perms: u32) -> ChatResponse {
    let trimmed = prompt.trim();
    let now = timer::uptime_ms();

    {
        let mut st = AGENT.lock();
        st.push_turn(ConversationTurn {
            uptime_ms: now,
            role: TurnRole::User,
            tool: String::from("chat"),
            text: String::from(trimmed),
        });
    }

    if trimmed.is_empty() {
        return finalize_chat("Please enter a question or system request.", "none", false);
    }

    if (actor_perms & PERM_READ_METRICS) == 0 {
        security::record_custom_audit(format!("AI_CHAT_DENIED actor={}", actor));
        return finalize_chat(
            "Permission denied: PERM_READ_METRICS required.",
            "rbac_guard",
            false,
        );
    }

    if contains_injection(trimmed) {
        security::record_custom_audit(format!("AI_PROMPT_BLOCKED actor={}", actor));
        return finalize_chat(
            "Blocked by NexOS AI security policy: protected credentials and RBAC bypasses cannot be accessed.",
            "security_filter",
            false,
        );
    }

    // Optional explicit delegation to the loaded .nxm Transformer
    if let Some(raw_prompt) = trimmed.strip_prefix("/raw ") {
        return match crate::ai_core::infer(raw_prompt.trim(), 32, 0, 1) {
            Ok(res) => finalize_chat(&res.output, "nxm_infer", true),
            Err(e) => finalize_chat(&format!("Model inference error: {}", e), "nxm_infer", false),
        };
    }

    let lower = trimmed.to_ascii_lowercase();

    // Persistent memory fact capture: "remember key=value" / "retiens key=value"
    if let Some(rest) = lower
        .strip_prefix("remember ")
        .or_else(|| lower.strip_prefix("retiens "))
    {
        let orig_offset = trimmed.len() - rest.len();
        let orig_rest = trimmed[orig_offset..].trim();
        if let Some((k, v)) = orig_rest.split_once('=') {
            return match remember(k, v, actor, actor_perms) {
                Ok(all_facts) => finalize_chat(
                    &format!(
                        "Stored persistent operational fact '{}'='{}' ({} total fact(s) in /disk/AIMEM.DB).",
                        k.trim(),
                        v.trim(),
                        all_facts.len()
                    ),
                    "ai_remember",
                    false,
                ),
                Err(e) => finalize_chat(&format!("Cannot store fact: {}", e), "ai_remember", false),
            };
        }
    }

    // Guided, allowlisted operational tool routing grounded in live kernel state (EN + FR)
    if lower.contains("diag")
        || lower.contains("health")
        || lower.contains("issue")
        || lower.contains("problem")
        || lower.contains("santé")
        || lower.contains("sante")
        || lower.contains("bilan")
    {
        let rep = diagnose();
        let mut out = format!(
            "System health={}/100 (log_errors={}, log_warns={}, auth_fails={}, issues={}).",
            rep.health_score,
            rep.log_errors,
            rep.log_warns,
            rep.auth_fails,
            rep.issues.len()
        );
        for iss in rep.issues.iter().take(4) {
            out.push_str(&format!(
                " [{}] {} -> proposed={} (fixable={}).",
                iss.severity, iss.id, iss.proposed_tool, iss.auto_fixable
            ));
        }
        return finalize_chat(&out, "diagnose", false);
    }

    if lower.contains("history")
        || lower.contains("previous")
        || lower.contains("historique")
        || lower.contains("facts")
        || (lower.contains("memory") && lower.contains("chat"))
    {
        let (turns, repairs) = history();
        let all_facts = facts();
        let mut out = format!(
            "Persistent AI memory (/disk/AIMEM.DB): {} conversation turn(s), {} repair record(s), {} fact(s).",
            turns.len(),
            repairs.len(),
            all_facts.len()
        );
        for t in turns.iter().rev().take(4).rev() {
            let snippet: String = t.text.chars().take(60).collect();
            out.push_str(&format!(" [{}: {}]", t.role.as_str(), snippet));
        }
        return finalize_chat(&out, "history", false);
    }

    if lower.contains("service") || lower.contains("daemon") || lower.contains("watchdog") {
        let svcs = services::snapshot();
        let running = svcs.iter().filter(|s| s.state == ServiceState::Running).count();
        let mut out = format!("Services: {}/{} running.", running, svcs.len());
        for s in svcs {
            out.push_str(&format!(" {}={:?}(restarts={})", s.name, s.state, s.restarts));
        }
        return finalize_chat(&out, "service_list", false);
    }

    if lower.contains("therm") || lower.contains("temp") || lower.contains("throttl") || lower.contains("clock") {
        let th = crate::drivers::mailbox_bcm2711::thermal_status();
        let msg = if th.hardware_probed {
            format!(
                "BCM2711 thermal: temp={}.{} C max={}.{} C arm_clock={} MHz throttled={:#x}.",
                th.soc_temp_mc / 1000,
                (th.soc_temp_mc % 1000) / 100,
                th.max_temp_mc / 1000,
                (th.max_temp_mc % 1000) / 100,
                th.arm_clock_hz / 1_000_000,
                th.throttled_flags
            )
        } else {
            format!(
                "Thermal telemetry: source={} (mock_verified={}, VC4 mailbox unavailable under QEMU virt).",
                th.source, th.mock_verified
            )
        };
        return finalize_chat(&msg, "thermal_status", false);
    }

    if lower.contains("fsck") || lower.contains("integrity") || lower.contains("intégrité") {
        let msg = match vfs::fsck_disk(false) {
            Ok(rep) => format!(
                "FAT32 fsck: healthy={} files={} dirs={} used_clusters={}/{} mirror_mismatches={} orphans={}.",
                rep.healthy,
                rep.files_checked,
                rep.dirs_checked,
                rep.used_clusters,
                rep.total_clusters,
                rep.fat_mirror_mismatches,
                rep.orphan_clusters
            ),
            Err(e) => format!("FAT32 fsck unavailable: {:?}", e),
        };
        return finalize_chat(&msg, "fat32_fsck", false);
    }

    if lower.contains("ram") || lower.contains("mem") || lower.contains("arena") || lower.contains("heap") {
        let ps = phys::stats();
        let hs = heap::stats();
        let ast = ai_arena::stats();
        let msg = format!(
            "RAM: {} MiB free / {} MiB total (reserve {} MiB). Heap: {} KiB used. AI Arena: {} KiB used ({} KiB KV) / {} MiB budget.",
            (ps.free_frames * phys::PAGE_SIZE) / (1024 * 1024),
            (ps.total_frames * phys::PAGE_SIZE) / (1024 * 1024),
            ast.reserve_bytes / (1024 * 1024),
            hs.used_bytes / 1024,
            ast.used_bytes / 1024,
            ast.kv_cache_bytes / 1024,
            ast.effective_budget_bytes / (1024 * 1024)
        );
        return finalize_chat(&msg, "sys_metrics", false);
    }

    if lower.contains("log") || lower.contains("dmesg") || lower.contains("error") || lower.contains("journaux") {
        let recs = log::recent_records(24);
        let errs = recs.iter().filter(|r| r.level == LogLevel::Error).count();
        let warns = recs.iter().filter(|r| r.level == LogLevel::Warn).count();
        let last_msg = recs.last().map(|r| r.msg_str()).unwrap_or("none");
        let msg = format!(
            "Kernel logs (last {}): errors={}, warns={}. Latest: \"{}\"",
            recs.len(),
            errs,
            warns,
            last_msg
        );
        return finalize_chat(&msg, "logs_analyze", false);
    }

    if lower.contains("disk")
        || lower.contains("vfs")
        || lower.contains("storage")
        || lower.contains("fat32")
        || lower.contains("stockage")
    {
        let mounted = vfs::is_disk_mounted();
        let cs = vfs::cache_stats();
        let msg = format!(
            "VFS storage: /disk mounted={}, cache hits={}, misses={}, dirty_writes={}, flushes={}.",
            mounted,
            cs.map(|c| c.hits).unwrap_or(0),
            cs.map(|c| c.misses).unwrap_or(0),
            cs.map(|c| c.dirty_writes).unwrap_or(0),
            cs.map(|c| c.flushes).unwrap_or(0)
        );
        return finalize_chat(&msg, "vfs_stats", false);
    }

    if lower.contains("net") || lower.contains("ip") || lower.contains("tcp") || lower.contains("dns") || lower.contains("réseau") {
        let ns = network::stats();
        let msg = format!(
            "Network: init={} mac={} ip4={} ip6={} rx={} tx={}.",
            ns.initialized, ns.mac, ns.ip, ns.link_local_ipv6, ns.rx_packets, ns.tx_packets
        );
        return finalize_chat(&msg, "net_status", false);
    }

    if lower.contains("audit") || lower.contains("security") || lower.contains("user") || lower.contains("sécurité") {
        if (actor_perms & PERM_AI_ADMIN) != 0 {
            let users = security::list_users();
            let evs = security::recent_audit_events();
            let msg = format!(
                "Security: {} configured user(s), {} recent audit event(s). Latest: {}",
                users.len(),
                evs.len(),
                evs.last().map(|s| s.as_str()).unwrap_or("none")
            );
            return finalize_chat(&msg, "sec_audit", false);
        } else {
            return finalize_chat(
                "Permission note: sec_audit requires PERM_AI_ADMIN.",
                "sec_audit",
                false,
            );
        }
    }

    if lower.contains("model") || lower.contains("slot") || lower.contains("quant") || lower.contains("modèle") {
        let st = super::status();
        let mut msg = format!(
            "AI Core: active={} quant={} ({}/{} slots), arena={} KiB.",
            st.model_path,
            st.quant_type,
            st.loaded_models.len(),
            st.max_slots,
            st.arena_used_bytes / 1024
        );
        for s in &st.loaded_models {
            msg.push_str(&format!(
                " [slot {}: {} {} {} KiB]",
                s.slot,
                s.path,
                s.quant_type,
                s.mem_bytes / 1024
            ));
        }
        return finalize_chat(&msg, "ai_status", false);
    }

    if lower.contains("tools") || lower.contains("outils") {
        let tools = allowlisted_tools();
        let mut msg = format!("Allowlisted AI tools ({}):", tools.len());
        for (i, t) in tools.iter().enumerate() {
            if i > 0 {
                msg.push(',');
            }
            msg.push_str(&format!(
                " {}({})",
                t.name,
                if t.mutating { "mut" } else { "ro" }
            ));
        }
        return finalize_chat(&msg, "tools_list", false);
    }

    // Otherwise run loaded .nxm Transformer if loaded + summarize system context
    let ast = super::status();
    if ast.model_loaded {
        if let Ok(res) = crate::ai_core::infer(trimmed, 32, 0, 1) {
            return finalize_chat(&res.output, "nxm_infer", true);
        }
    }

    let ps = phys::stats();
    let msg = format!(
        "NexOS AI Assistant ready (board={}, free_ram={} MiB, model={} [{}], {} tools available). Try asking about diagnostics, services, memory, logs, storage, thermal, network, or use '/raw <prompt>'.",
        crate::arch::boards::active::BOARD_NAME,
        (ps.free_frames * phys::PAGE_SIZE) / (1024 * 1024),
        ast.model_path,
        ast.quant_type,
        allowlisted_tools().len()
    );
    finalize_chat(&msg, "ai_status", false)
}

fn finalize_chat(reply: &str, tool_used: &str, model_used: bool) -> ChatResponse {
    let mut st = AGENT.lock();
    st.push_turn(ConversationTurn {
        uptime_ms: timer::uptime_ms(),
        role: TurnRole::Assistant,
        tool: String::from(tool_used),
        text: String::from(reply),
    });
    let persisted = persist_locked(&st);
    let history_len = st.turns.len();
    ChatResponse {
        reply: String::from(reply),
        tool_used: String::from(tool_used),
        history_len,
        persisted,
        model_used,
    }
}
