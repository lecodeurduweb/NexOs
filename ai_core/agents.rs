//! NexOS AI agent coordinator.
//!
//! This module provides deterministic system reasoning and agent routing. It is
//! intentionally separated from model inference: an external model can analyze
//! the returned facts, while the kernel never grants a model direct privileges.

use alloc::string::String;
use alloc::vec::Vec;

use crate::arch::timer;
use crate::filesystem::vfs;
use crate::memory::{heap, phys};
use crate::network;
use crate::scheduler;
use crate::services;
use crate::sync::Mutex;
use crate::security::csprng;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentKind {
    System,
    Network,
    Security,
    Memory,
    Storage,
    Process,
    Diagnostic,
    Repair,
}

impl AgentKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Network => "network",
            Self::Security => "security",
            Self::Memory => "memory",
            Self::Storage => "storage",
            Self::Process => "process",
            Self::Diagnostic => "diagnostic",
            Self::Repair => "repair",
        }
    }
}

#[derive(Clone)]
pub struct AgentObservation {
    pub agent: &'static str,
    pub summary: String,
}

struct AgentHistoryState {
    entries: Vec<AgentObservation>,
}

static AGENT_HISTORY: Mutex<AgentHistoryState> = Mutex::new(AgentHistoryState {
    entries: Vec::new(),
});

#[derive(Clone)]
pub struct PendingRepair {
    pub id: u64,
    pub action: String,
    pub target: String,
    pub approval_token: String,
    pub expires_ms: u64,
}

struct RepairState {
    next_id: u64,
    pending: Vec<PendingRepair>,
}

static REPAIR_STATE: Mutex<RepairState> = Mutex::new(RepairState {
    next_id: 1,
    pending: Vec::new(),
});

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::new();
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

pub fn request_service_restart(service: &str) -> Result<PendingRepair, &'static str> {
    if service.is_empty() || service.len() > 48 {
        return Err("Invalid service name");
    }
    if services::snapshot().iter().find(|s| s.name == service).is_none() {
        return Err("Service not found");
    }
    let mut rnd = [0u8; 24];
    csprng::fill_bytes(&mut rnd).map_err(|_| "Entropy unavailable")?;
    let token = encode_hex(&rnd);
    csprng::zeroize_bytes(&mut rnd);
    let mut state = REPAIR_STATE.lock();
    let id = state.next_id;
    state.next_id = state.next_id.saturating_add(1);
    let pending = PendingRepair {
        id,
        action: String::from("restart_service"),
        target: String::from(service),
        approval_token: token,
        expires_ms: timer::uptime_ms().saturating_add(300_000),
    };
    state.pending.push(pending.clone());
    if state.pending.len() > 8 {
        state.pending.remove(0);
    }
    super::memory::push("repair_request", "repair", &alloc::format!("restart_service target={}", service));
    Ok(pending)
}

pub fn approve_and_restart(id: u64, token: &str) -> Result<(u64, String), &'static str> {
    let now = timer::uptime_ms();
    let target = {
        let mut state = REPAIR_STATE.lock();
        let pos = state.pending.iter().position(|p| p.id == id)
            .ok_or("Approval not found")?;
        let pending = &state.pending[pos];
        if pending.expires_ms < now {
            state.pending.remove(pos);
            return Err("Approval expired");
        }
        if pending.action != "restart_service" {
            return Err("Action not allowlisted");
        }
        if !crate::security::sha256::constant_time_slice_eq(pending.approval_token.as_bytes(), token.trim().as_bytes()) {
            return Err("Invalid approval token");
        }
        let target = pending.target.clone();
        state.pending.remove(pos);
        target
    };
    let pid = services::restart_service(&target).map_err(|e| e)?;
    super::memory::push("repair_action", "repair", &alloc::format!("restart_service target={} pid={} verified_pending", target, pid));
    Ok((pid, target))
}

pub fn verify_repair(service: &str) -> bool {
    services::snapshot().iter().any(|s| s.name == service && s.state == crate::services::ServiceState::Running)
}

fn push_history(agent: &'static str, summary: String) {
    let mut state = AGENT_HISTORY.lock();
    if state.entries.len() >= 64 {
        state.entries.remove(0);
    }
    state.entries.push(AgentObservation { agent, summary: summary.clone() });
    drop(state);
    super::memory::push("observation", agent, &summary);
}

pub fn history() -> Vec<AgentObservation> {
    AGENT_HISTORY.lock().entries.clone()
}

fn route(prompt: &str) -> AgentKind {
    let p = prompt.to_lowercase();
    if p.contains("network") || p.contains("ip ") || p.contains("dns") || p.contains("ping") || p.contains("tcp") {
        AgentKind::Network
    } else if p.contains("security") || p.contains("auth") || p.contains("password") || p.contains("session") {
        AgentKind::Security
    } else if p.contains("memory") || p.contains("heap") || p.contains("ram") {
        AgentKind::Memory
    } else if p.contains("disk") || p.contains("storage") || p.contains("fat") || p.contains("vfs") {
        AgentKind::Storage
    } else if p.contains("process") || p.contains("task") || p.contains("service") || p.contains("restart") {
        AgentKind::Process
    } else if p.contains("repair") || p.contains("fix") || p.contains("recover") {
        AgentKind::Repair
    } else if p.contains("diagnose") || p.contains("problem") || p.contains("error") || p.contains("fail") {
        AgentKind::Diagnostic
    } else {
        AgentKind::System
    }
}

fn system_observation() -> AgentObservation {
    let ps = phys::stats();
    let hs = heap::stats();
    let tasks = scheduler::snapshot();
    let svcs = services::snapshot();
    let ram_free_mib = ps.free_frames.saturating_mul(phys::PAGE_SIZE) / (1024 * 1024);
    let ram_total_mib = ps.total_frames.saturating_mul(phys::PAGE_SIZE) / (1024 * 1024);
    AgentObservation {
        agent: AgentKind::System.name(),
        summary: alloc::format!(
            "uptime_ms={}; ram_free_mib={}; ram_total_mib={}; heap_used_bytes={}; tasks={}; services={}; cores_online={}",
            timer::uptime_ms(),
            ram_free_mib,
            ram_total_mib,
            hs.used_bytes,
            tasks.len(),
            svcs.len(),
            crate::arch::smp::online_cpus(),
        ),
    }
}

pub fn agents_status_json() -> String {
    alloc::format!(
        "{{\"agents\":[\
{{\"name\":\"system\",\"role\":\"System telemetry and uptime\"}},\
{{\"name\":\"network\",\"role\":\"IPv4/IPv6, DHCP, DNS, TCP and packet diagnostics\"}},\
{{\"name\":\"security\",\"role\":\"Authentication, sessions, RBAC and audit analysis\"}},\
{{\"name\":\"memory\",\"role\":\"Physical and heap memory analysis\"}},\
{{\"name\":\"storage\",\"role\":\"VFS, FAT32 and block-cache analysis\"}},\
{{\"name\":\"process\",\"role\":\"Tasks, scheduler and service analysis\"}},\
{{\"name\":\"diagnostic\",\"role\":\"Cross-domain fault correlation\"}},\
{{\"name\":\"repair\",\"role\":\"Risk-assessed, approval-bound remediation\"}}\
]}}"
    )
}

pub fn diagnose(prompt: &str) -> AgentObservation {
    let agent = route(prompt);
    let observation = match agent {
        AgentKind::Network => {
            let ns = network::stats();
            AgentObservation {
                agent: agent.name(),
                summary: alloc::format!(
                    "initialized={}; ip={}; ipv6={}; rx_packets={}; tx_packets={}; rx_bytes={}; tx_bytes={}; config={:?}",
                    ns.initialized,
                    ns.ip,
                    ns.link_local_ipv6,
                    ns.rx_packets,
                    ns.tx_packets,
                    ns.rx_bytes,
                    ns.tx_bytes,
                    ns.config_source,
                ),
            }
        }
        AgentKind::Security => AgentObservation {
            agent: agent.name(),
            summary: alloc::format!(
                "needs_setup={}; csprng_source={}; csprng_seeded={}; persisted_users={}",
                crate::security::needs_setup(),
                crate::security::csprng::source_name(),
                crate::security::csprng::is_seeded(),
                crate::security::list_users().len(),
            ),
        },
        AgentKind::Memory => {
            let ps = phys::stats();
            let hs = heap::stats();
            AgentObservation {
                agent: agent.name(),
                summary: alloc::format!(
                    "pa_bits={}; total_frames={}; free_frames={}; dma32_free_frames={}; heap_used_bytes={}; heap_mapped_bytes={}; heap_active_allocs={}",
                    ps.pa_bits,
                    ps.total_frames,
                    ps.free_frames,
                    ps.dma32_free_frames,
                    hs.used_bytes,
                    hs.mapped_bytes,
                    hs.active_allocs,
                ),
            }
        }
        AgentKind::Storage => {
            let cs = vfs::cache_stats();
            AgentObservation {
                agent: agent.name(),
                summary: alloc::format!(
                    "disk_mounted={}; cache_hits={}; cache_misses={}; cache_dirty_writes={}; cache_flushes={}",
                    vfs::is_disk_mounted(),
                    cs.map(|c| c.hits).unwrap_or(0),
                    cs.map(|c| c.misses).unwrap_or(0),
                    cs.map(|c| c.dirty_writes).unwrap_or(0),
                    cs.map(|c| c.flushes).unwrap_or(0),
                ),
            }
        }
        AgentKind::Process => {
            let tasks = scheduler::snapshot();
            let svcs = services::snapshot();
            AgentObservation {
                agent: agent.name(),
                summary: alloc::format!(
                    "tasks={}; services={}; context_switches={}; exited_tasks_pending_reap={}",
                    tasks.len(),
                    svcs.len(),
                    scheduler::total_switches(),
                    scheduler::reap_exited(),
                ),
            }
        }
        AgentKind::Repair => AgentObservation {
            agent: agent.name(),
            summary: String::from("No destructive operation is implicit. Use an allowlisted read-only diagnostic or request explicit approval for service control."),
        },
        AgentKind::Diagnostic => system_observation(),
        AgentKind::System => system_observation(),
    };
    push_history(agent.name(), observation.summary.clone());
    observation
}
