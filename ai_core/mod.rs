//! NexOS Native AI Inference Runtime (`ai_core`).
//!
//! Zero external OS dependencies (no Linux, no Python, no llama.cpp).
//! Uses AArch64 NEON SIMD assembly (`neon_gemv.S`), strict RAM budget control,
//! sleeping `Mutex` locking (preemption-safe), and streaming/abort controls.

pub mod format;
pub mod model;
pub mod tensor;
pub mod tokenizer;
pub mod agents;
pub mod memory;

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::filesystem::vfs;
use crate::klog;
use crate::log::LogLevel;
use crate::memory::{heap, phys};
use crate::scheduler;
use crate::services::{self, RestartPolicy};
use crate::sync::Mutex;

use format::FormatError;
use model::{InferResult, NxmModel, ABORT_FLAG};

/// Target configurable ceiling for AI runtime on 8 GiB Raspberry Pi 4 (~5 GiB),
/// dynamically capped to available physical RAM minus system reserve (`128 MiB`) and heap limit.
pub const DEFAULT_CONFIG_CEILING_BYTES: usize = 5 * 1024 * 1024 * 1024;
const MIN_SYSTEM_RESERVE_BYTES: usize = 128 * 1024 * 1024;
const HEAP_MAX_BYTES: usize = 64 * 1024 * 1024;

struct AiCoreState {
    initialized: bool,
    neon_verified: bool,
    configured_ceiling_bytes: usize,
    model_path: Option<String>,
    model: Option<Box<NxmModel>>,
    last_tokens_per_sec_x100: u64,
    total_inferences: u64,
}

impl AiCoreState {
    const fn new() -> Self {
        Self {
            initialized: false,
            neon_verified: false,
            configured_ceiling_bytes: DEFAULT_CONFIG_CEILING_BYTES,
            model_path: None,
            model: None,
            last_tokens_per_sec_x100: 0,
            total_inferences: 0,
        }
    }
}

#[derive(Clone)]
pub struct AiStatus {
    pub initialized: bool,
    pub neon_verified: bool,
    pub model_loaded: bool,
    pub model_path: String,
    pub vocab_size: usize,
    pub dim: usize,
    pub n_layers: usize,
    pub n_heads: usize,
    pub max_seq: usize,
    pub model_ram_bytes: usize,
    pub active_budget_bytes: usize,
    pub last_tokens_per_sec_x100: u64,
    pub total_inferences: u64,
}

static AI_STATE: Mutex<AiCoreState> = Mutex::new(AiCoreState::new());
static AI_READY: AtomicBool = AtomicBool::new(false);

pub fn effective_budget_bytes(configured_ceiling: usize) -> usize {
    let ps = phys::stats();
    let total_ram = ps.total_frames.saturating_mul(phys::PAGE_SIZE);
    let phys_cap = total_ram.saturating_sub(MIN_SYSTEM_RESERVE_BYTES);
    let hs = heap::stats();
    let heap_cap = HEAP_MAX_BYTES.saturating_sub(hs.used_bytes + 4 * 1024 * 1024);
    configured_ceiling.min(phys_cap).min(heap_cap)
}

pub fn init() {
    memory::init();
    match tensor::self_test() {
        Ok(()) => {
            klog!(
                LogLevel::Info,
                "ai",
                "AArch64 NEON SIMD kernels verified (dot_f32 & gemv_q8_0 scalar equivalence OK)"
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
    if vfs::is_disk_mounted() && vfs::read_file("/disk/MODEL.NXM").is_ok() {
        match load_from_vfs("/disk/MODEL.NXM") {
            Ok(msg) => klog!(LogLevel::Info, "ai", "Auto-loaded model: {}", msg),
            Err(e) => klog!(LogLevel::Warn, "ai", "Auto-load /disk/MODEL.NXM skipped: {}", e),
        }
    }

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
    let budget = effective_budget_bytes(st.configured_ceiling_bytes);
    match &st.model {
        Some(m) => AiStatus {
            initialized: st.initialized,
            neon_verified: st.neon_verified,
            model_loaded: true,
            model_path: st.model_path.clone().unwrap_or_default(),
            vocab_size: m.hdr.vocab_size,
            dim: m.hdr.dim,
            n_layers: m.hdr.n_layers,
            n_heads: m.hdr.n_heads,
            max_seq: m.hdr.max_seq,
            model_ram_bytes: m.mem_bytes,
            active_budget_bytes: budget,
            last_tokens_per_sec_x100: st.last_tokens_per_sec_x100,
            total_inferences: st.total_inferences,
        },
        None => AiStatus {
            initialized: st.initialized,
            neon_verified: st.neon_verified,
            model_loaded: false,
            model_path: String::from("none"),
            vocab_size: 0,
            dim: 0,
            n_layers: 0,
            n_heads: 0,
            max_seq: 0,
            model_ram_bytes: 0,
            active_budget_bytes: budget,
            last_tokens_per_sec_x100: st.last_tokens_per_sec_x100,
            total_inferences: st.total_inferences,
        },
    }
}

#[inline(never)]
pub fn load_from_vfs(path: &str) -> Result<String, String> {
    let bytes = vfs::read_file(path).map_err(|e| format!("VFS read '{}': {:?}", path, e))?;
    let budget = {
        let st = AI_STATE.lock();
        effective_budget_bytes(st.configured_ceiling_bytes)
    };
    let mdl = NxmModel::from_bytes(&bytes, budget).map_err(|e| match e {
        FormatError::UnsupportedGguf(g) => format!(
            "Unsupported external GGUF v{} ({} tensors): convert to NexOS .nxm v1",
            g.version, g.tensor_count
        ),
        FormatError::BudgetExceeded {
            required_bytes,
            budget_bytes,
        } => format!(
            "RAM budget exceeded: required {} KiB > budget {} KiB",
            required_bytes / 1024,
            budget_bytes / 1024
        ),
        FormatError::IntegrityMismatch { expected, actual } => format!(
            ".nxm CRC-32 integrity check failed: expected {:#010x}, got {:#010x}",
            expected, actual
        ),
        other => format!("Invalid .nxm model: {:?}", other),
    })?;
    let info = format!(
        "{} (dim={}, hidden={}, layers={}, heads={}, vocab={}, q=Q8_0, mem={} KiB)",
        path,
        mdl.hdr.dim,
        mdl.hdr.hidden_dim,
        mdl.hdr.n_layers,
        mdl.hdr.n_heads,
        mdl.hdr.vocab_size,
        mdl.mem_bytes / 1024
    );
    let mut st = AI_STATE.lock();
    st.model_path = Some(String::from(path));
    st.model = Some(mdl);
    klog!(LogLevel::Info, "ai", "Loaded .nxm model {}", info);
    Ok(info)
}

pub fn unload() -> bool {
    let mut st = AI_STATE.lock();
    let had = st.model.is_some();
    st.model = None;
    st.model_path = None;
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
    let mdl = st.model.as_mut().ok_or("No .nxm model loaded")?;
    let res = mdl.generate(prompt, max_tokens.clamp(1, 64), temp_x100, top_k, |_| {});
    st.last_tokens_per_sec_x100 = res.tokens_per_sec_x100;
    st.total_inferences += 1;
    Ok(res)
}

pub fn benchmark(max_tokens: usize) -> Result<InferResult, &'static str> {
    infer("nexos status", max_tokens.clamp(4, 32), 0, 1)
}
