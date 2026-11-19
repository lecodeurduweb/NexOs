//! NexOS Native AI Inference Runtime (`ai_core`).
//!
//! Zero external OS dependencies (no Linux, no Python, no llama.cpp).
//! Uses AArch64 NEON SIMD assembly (`neon_gemv.S`), multi-GiB page-backed
//! `memory::ai_arena` memory management (no 64 MiB heap ceiling), sleeping
//! `Mutex` locking (preemption-safe), streaming `.nxm` loading, and abort controls.

pub mod agent;
pub mod format;
pub mod model;
pub mod tensor;
pub mod tokenizer;

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::filesystem::vfs;
use crate::klog;
use crate::log::LogLevel;
use crate::memory::ai_arena::{self, AiArenaStats};
use crate::scheduler;
use crate::services::{self, RestartPolicy};
use crate::sync::Mutex;

use format::{quant_name, FormatError};
use model::{InferResult, NxmModel, ABORT_FLAG};

pub const MAX_MODEL_SLOTS: usize = 4;

struct LoadedSlot {
    path: String,
    model: Box<NxmModel>,
    last_tokens_per_sec_x100: u64,
    inferences: u64,
}

#[derive(Clone)]
pub struct ModelSlotSummary {
    pub slot: usize,
    pub active: bool,
    pub path: String,
    pub quant_type: &'static str,
    pub dim: usize,
    pub n_layers: usize,
    pub n_heads: usize,
    pub vocab_size: usize,
    pub max_seq: usize,
    pub mem_bytes: usize,
    pub kv_bytes: usize,
    pub inferences: u64,
    pub last_tokens_per_sec_x100: u64,
}

struct AiCoreState {
    initialized: bool,
    neon_verified: bool,
    slots: Vec<LoadedSlot>,
    active_slot: Option<usize>,
    last_tokens_per_sec_x100: u64,
    total_inferences: u64,
}

impl AiCoreState {
    const fn new() -> Self {
        Self {
            initialized: false,
            neon_verified: false,
            slots: Vec::new(),
            active_slot: None,
            last_tokens_per_sec_x100: 0,
            total_inferences: 0,
        }
    }

    fn active(&self) -> Option<&LoadedSlot> {
        self.active_slot.and_then(|idx| self.slots.get(idx))
    }

    fn active_mut(&mut self) -> Option<&mut LoadedSlot> {
        self.active_slot.and_then(|idx| self.slots.get_mut(idx))
    }
}

#[derive(Clone)]
pub struct AiStatus {
    pub initialized: bool,
    pub neon_verified: bool,
    pub model_loaded: bool,
    pub model_path: String,
    pub quant_type: &'static str,
    pub vocab_size: usize,
    pub dim: usize,
    pub n_layers: usize,
    pub n_heads: usize,
    pub max_seq: usize,
    pub model_ram_bytes: usize,
    pub kv_cache_bytes: usize,
    pub arena_used_bytes: usize,
    pub active_budget_bytes: usize,
    pub last_tokens_per_sec_x100: u64,
    pub total_inferences: u64,
    pub active_slot: Option<usize>,
    pub loaded_models: Vec<ModelSlotSummary>,
    pub max_slots: usize,
}

static AI_STATE: Mutex<AiCoreState> = Mutex::new(AiCoreState::new());
static AI_READY: AtomicBool = AtomicBool::new(false);

pub fn arena_stats() -> AiArenaStats {
    ai_arena::stats()
}

pub fn set_ceiling_bytes(ceiling_bytes: usize) -> Result<(), &'static str> {
    ai_arena::set_ceiling_bytes(ceiling_bytes)
}

pub fn init() {
    match tensor::self_test() {
        Ok(()) => {
            klog!(
                LogLevel::Info,
                "ai",
                "AArch64 NEON SIMD kernels verified (dot_f32, saxpy_f32, gemv_q8_0, gemv_q4_0, gemv_f16 scalar equivalence OK)"
            );
        }
        Err(e) => {
            klog!(LogLevel::Error, "ai", "NEON SIMD self-test failed: {}", e);
            return;
        }
    }

    {
        let mut st = AI_STATE.lock();
        st.initialized = true;
        st.neon_verified = true;
    }
    AI_READY.store(true, Ordering::Release);

    // Auto-load /disk/MODEL.NXM if present on persistent storage
    if vfs::is_disk_mounted() && vfs::stat("/disk/MODEL.NXM").is_ok() {
        match load_from_vfs("/disk/MODEL.NXM") {
            Ok(msg) => klog!(LogLevel::Info, "ai", "Auto-loaded model: {}", msg),
            Err(e) => klog!(LogLevel::Warn, "ai", "Auto-load /disk/MODEL.NXM skipped: {}", e),
        }
    }

    agent::init();

    let _ = services::register_daemon(
        "ai-core",
        "Native ARM64 NEON .nxm Transformer Inference Daemon",
        Some("storage-vfs"),
        135,
        RestartPolicy::Always,
        0,
        ai_daemon_worker,
        0,
    );
}

fn ai_daemon_worker(_: usize) -> ! {
    loop {
        services::heartbeat("ai-core");
        scheduler::sleep_ms(200);
    }
}

pub fn status() -> AiStatus {
    let st = AI_STATE.lock();
    let ast = ai_arena::stats();
    let loaded_models: Vec<ModelSlotSummary> = st
        .slots
        .iter()
        .enumerate()
        .map(|(idx, s)| ModelSlotSummary {
            slot: idx,
            active: st.active_slot == Some(idx),
            path: s.path.clone(),
            quant_type: quant_name(s.model.hdr.quant_type),
            dim: s.model.hdr.dim,
            n_layers: s.model.hdr.n_layers,
            n_heads: s.model.hdr.n_heads,
            vocab_size: s.model.hdr.vocab_size,
            max_seq: s.model.active_max_seq,
            mem_bytes: s.model.mem_bytes,
            kv_bytes: s.model.kv_bytes,
            inferences: s.inferences,
            last_tokens_per_sec_x100: s.last_tokens_per_sec_x100,
        })
        .collect();

    match st.active() {
        Some(slot) => AiStatus {
            initialized: st.initialized,
            neon_verified: st.neon_verified,
            model_loaded: true,
            model_path: slot.path.clone(),
            quant_type: quant_name(slot.model.hdr.quant_type),
            vocab_size: slot.model.hdr.vocab_size,
            dim: slot.model.hdr.dim,
            n_layers: slot.model.hdr.n_layers,
            n_heads: slot.model.hdr.n_heads,
            max_seq: slot.model.active_max_seq,
            model_ram_bytes: slot.model.mem_bytes,
            kv_cache_bytes: slot.model.kv_bytes,
            arena_used_bytes: ast.used_bytes,
            active_budget_bytes: ast.effective_budget_bytes,
            last_tokens_per_sec_x100: st.last_tokens_per_sec_x100,
            total_inferences: st.total_inferences,
            active_slot: st.active_slot,
            loaded_models,
            max_slots: MAX_MODEL_SLOTS,
        },
        None => AiStatus {
            initialized: st.initialized,
            neon_verified: st.neon_verified,
            model_loaded: false,
            model_path: String::from("none"),
            quant_type: "NONE",
            vocab_size: 0,
            dim: 0,
            n_layers: 0,
            n_heads: 0,
            max_seq: 0,
            model_ram_bytes: 0,
            kv_cache_bytes: 0,
            arena_used_bytes: ast.used_bytes,
            active_budget_bytes: ast.effective_budget_bytes,
            last_tokens_per_sec_x100: st.last_tokens_per_sec_x100,
            total_inferences: st.total_inferences,
            active_slot: None,
            loaded_models,
            max_slots: MAX_MODEL_SLOTS,
        },
    }
}

pub fn current_model_path() -> Option<String> {
    AI_STATE.lock().active().map(|s| s.path.clone())
}

fn format_model_err(e: FormatError) -> String {
    match e {
        FormatError::UnsupportedGguf(g) => format!(
            "Unsupported external GGUF v{} ({} tensors): convert to NexOS .nxm v1",
            g.version, g.tensor_count
        ),
        FormatError::BudgetExceeded {
            required_bytes,
            budget_bytes,
        } => format!(
            "AI Arena budget exceeded: required {} KiB > free budget {} KiB",
            required_bytes / 1024,
            budget_bytes / 1024
        ),
        FormatError::IntegrityMismatch { expected, actual } => format!(
            ".nxm CRC-32 integrity check failed: expected {:#010x}, got {:#010x}",
            expected, actual
        ),
        other => format!("Invalid .nxm model: {:?}", other),
    }
}

#[inline(never)]
pub fn load_from_vfs(path: &str) -> Result<String, String> {
    let _ = vfs::stat(path).map_err(|e| format!("VFS stat '{}': {:?}", path, e))?;

    // If replacing an already-loaded slot at the same path, drop it first to reclaim its arena space
    {
        let mut st = AI_STATE.lock();
        if let Some(pos) = st.slots.iter().position(|s| s.path.eq_ignore_ascii_case(path)) {
            st.slots.remove(pos);
            if st.slots.is_empty() {
                st.active_slot = None;
            } else if let Some(act) = st.active_slot {
                if act == pos {
                    st.active_slot = Some(0);
                } else if act > pos {
                    st.active_slot = Some(act - 1);
                }
            }
        }
        // Keep room for a new slot within MAX_MODEL_SLOTS
        while st.slots.len() >= MAX_MODEL_SLOTS {
            let evict_idx = if st.active_slot == Some(0) && st.slots.len() > 1 {
                1
            } else {
                0
            };
            st.slots.remove(evict_idx);
            if let Some(act) = st.active_slot {
                if act == evict_idx {
                    st.active_slot = Some(0);
                } else if act > evict_idx {
                    st.active_slot = Some(act - 1);
                }
            }
        }
    }

    let budget = ai_arena::stats().free_budget_bytes;
    let mdl = match NxmModel::from_vfs_path(path, budget) {
        Ok(m) => m,
        Err(FormatError::BudgetExceeded { .. }) => {
            // Evict inactive slots first (then active if needed) to free AiArena memory
            {
                let mut st = AI_STATE.lock();
                if !st.slots.is_empty() {
                    st.slots.clear();
                    st.active_slot = None;
                }
            }
            let fresh_budget = ai_arena::stats().free_budget_bytes;
            NxmModel::from_vfs_path(path, fresh_budget).map_err(format_model_err)?
        }
        Err(e) => return Err(format_model_err(e)),
    };

    let qlabel = quant_name(mdl.hdr.quant_type);
    let info = format!(
        "{} (dim={}, hidden={}, layers={}, heads={}, vocab={}, seq={}, q={}, mem={} KiB, kv={} KiB)",
        path,
        mdl.hdr.dim,
        mdl.hdr.hidden_dim,
        mdl.hdr.n_layers,
        mdl.hdr.n_heads,
        mdl.hdr.vocab_size,
        mdl.active_max_seq,
        qlabel,
        mdl.mem_bytes / 1024,
        mdl.kv_bytes / 1024
    );

    let mut st = AI_STATE.lock();
    st.slots.push(LoadedSlot {
        path: String::from(path),
        model: mdl,
        last_tokens_per_sec_x100: 0,
        inferences: 0,
    });
    st.active_slot = Some(st.slots.len() - 1);
    klog!(LogLevel::Info, "ai", "Loaded .nxm model {} (slot={})", info, st.slots.len() - 1);
    Ok(info)
}

pub fn select_model(target: &str) -> Result<String, String> {
    let t = target.trim();
    let mut st = AI_STATE.lock();
    let idx = if let Ok(slot_num) = t.parse::<usize>() {
        if slot_num < st.slots.len() {
            Some(slot_num)
        } else {
            None
        }
    } else {
        st.slots
            .iter()
            .position(|s| s.path.eq_ignore_ascii_case(t))
            .or_else(|| {
                let lower = t.to_ascii_lowercase();
                st.slots
                    .iter()
                    .position(|s| s.path.to_ascii_lowercase().contains(&lower))
            })
    };
    let Some(slot_idx) = idx else {
        return Err(format!("Model slot '{}' not loaded", t));
    };
    st.active_slot = Some(slot_idx);
    let s = &st.slots[slot_idx];
    Ok(format!(
        "slot={} path={} quant={}",
        slot_idx,
        s.path,
        quant_name(s.model.hdr.quant_type)
    ))
}

pub fn unload_slot(target: &str) -> bool {
    let t = target.trim();
    let mut st = AI_STATE.lock();
    let idx = if let Ok(slot_num) = t.parse::<usize>() {
        if slot_num < st.slots.len() {
            Some(slot_num)
        } else {
            None
        }
    } else {
        st.slots.iter().position(|s| s.path.eq_ignore_ascii_case(t))
    };
    let Some(pos) = idx else {
        return false;
    };
    st.slots.remove(pos);
    if st.slots.is_empty() {
        st.active_slot = None;
    } else if let Some(act) = st.active_slot {
        if act == pos {
            st.active_slot = Some(0);
        } else if act > pos {
            st.active_slot = Some(act - 1);
        }
    }
    true
}

pub fn unload() -> bool {
    let mut st = AI_STATE.lock();
    let had = !st.slots.is_empty();
    st.slots.clear();
    st.active_slot = None;
    had
}

pub fn abort() {
    ABORT_FLAG.store(true, Ordering::Release);
}

pub fn infer(
    prompt: &str,
    max_tokens: usize,
    temp_x100: u32,
    top_k: usize,
) -> Result<InferResult, &'static str> {
    let mut st = AI_STATE.lock();
    let slot = st.active_mut().ok_or("No .nxm model loaded")?;
    let res = slot
        .model
        .generate(prompt, max_tokens.clamp(1, 128), temp_x100, top_k, |_| {});
    slot.last_tokens_per_sec_x100 = res.tokens_per_sec_x100;
    slot.inferences += 1;
    st.last_tokens_per_sec_x100 = res.tokens_per_sec_x100;
    st.total_inferences += 1;
    Ok(res)
}

pub fn benchmark(max_tokens: usize) -> Result<InferResult, &'static str> {
    infer("nexos status", max_tokens.clamp(4, 32), 0, 1)
}
