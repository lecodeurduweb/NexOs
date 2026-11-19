//! Native NexOS Causal Transformer Inference Engine (Q8_0 + AArch64 NEON + KV Cache).
//!
//! Streams `.nxm` payloads directly from VFS (`VfsCursor`) into page-backed
//! `memory::ai_arena::AiBuffer`s (up to multi-GiB RAM on Raspberry Pi 4 8 GiB)
//! while computing incremental IEEE 802.3 CRC-32 verification.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::timer;
use crate::filesystem::vfs::{self, VfsCursor};
use crate::klog;
use crate::log::LogLevel;
use crate::memory::ai_arena::{self, AiBuffer};
use crate::security::sha256::Crc32;

use super::format::{
    FormatError, NxmHeader, FLAG_CRC32_INTEGRITY, FLAG_TIED_CLS, NXM_HEADER_SIZE,
};
use super::tensor::{dequant_row, dot_f32, gemv, powf, rmsnorm, saxpy_f32, siluf, sin_cos_f32, softmax};
use super::tokenizer::{NxmTokenizer, TOKEN_EOS};

pub static ABORT_FLAG: AtomicBool = AtomicBool::new(false);

struct LayerWeights {
    blob: AiBuffer,
    rms_att_off: usize,
    wq_off: usize,
    wq_len: usize,
    wk_off: usize,
    wk_len: usize,
    wv_off: usize,
    wv_len: usize,
    wo_off: usize,
    wo_len: usize,
    rms_ffn_off: usize,
    w1_off: usize,
    w1_len: usize,
    w2_off: usize,
    w2_len: usize,
    w3_off: usize,
    w3_len: usize,
    dim: usize,
}

impl LayerWeights {
    #[inline]
    fn bytes_slice(&self, off: usize, len: usize) -> &[u8] {
        &self.blob.as_slice()[off..off + len]
    }

    #[inline]
    fn f32_slice(&self, off: usize, count: usize) -> &[f32] {
        let base = self.blob.as_slice()[off..off + count * 4].as_ptr() as *const f32;
        unsafe { core::slice::from_raw_parts(base, count) }
    }

    fn rms_att(&self) -> &[f32] {
        self.f32_slice(self.rms_att_off, self.dim)
    }
    fn wq(&self) -> &[u8] {
        self.bytes_slice(self.wq_off, self.wq_len)
    }
    fn wk(&self) -> &[u8] {
        self.bytes_slice(self.wk_off, self.wk_len)
    }
    fn wv(&self) -> &[u8] {
        self.bytes_slice(self.wv_off, self.wv_len)
    }
    fn wo(&self) -> &[u8] {
        self.bytes_slice(self.wo_off, self.wo_len)
    }
    fn rms_ffn(&self) -> &[f32] {
        self.f32_slice(self.rms_ffn_off, self.dim)
    }
    fn w1(&self) -> &[u8] {
        self.bytes_slice(self.w1_off, self.w1_len)
    }
    fn w2(&self) -> &[u8] {
        self.bytes_slice(self.w2_off, self.w2_len)
    }
    fn w3(&self) -> &[u8] {
        self.bytes_slice(self.w3_off, self.w3_len)
    }
}

struct KvLayerCache {
    k: AiBuffer, // [active_max_seq * kv_dim] f32 (is_kv = true)
    v: AiBuffer, // [active_max_seq * kv_dim] f32 (is_kv = true)
}

pub struct InferResult {
    pub output: String,
    pub prompt_tokens: usize,
    pub generated_tokens: usize,
    pub elapsed_ms: u64,
    pub elapsed_us: u64,
    pub tokens_per_sec_x100: u64,
    pub aborted: bool,
}

enum StreamSource<'a> {
    Slice { data: &'a [u8], pos: usize },
    Vfs(VfsCursor),
}

impl<'a> StreamSource<'a> {
    fn remaining(&self) -> usize {
        match self {
            StreamSource::Slice { data, pos } => data.len().saturating_sub(*pos),
            StreamSource::Vfs(cur) => cur.remaining(),
        }
    }

    fn read_exact(&mut self, out: &mut [u8]) -> Result<(), FormatError> {
        match self {
            StreamSource::Slice { data, pos } => {
                let slice = data
                    .get(*pos..*pos + out.len())
                    .ok_or(FormatError::TruncatedData)?;
                out.copy_from_slice(slice);
                *pos += out.len();
                Ok(())
            }
            StreamSource::Vfs(cur) => {
                vfs::read_cursor_exact(cur, out).map_err(|_| FormatError::TruncatedData)
            }
        }
    }
}

fn stream_exact(
    src: &mut StreamSource<'_>,
    crc: &mut Crc32,
    dst: &mut [u8],
    bytes_read: &mut u64,
) -> Result<(), FormatError> {
    let mut off = 0usize;
    while off < dst.len() {
        let end = (off + 16384).min(dst.len());
        src.read_exact(&mut dst[off..end])?;
        crc.update(&dst[off..end]);
        *bytes_read += (end - off) as u64;
        off = end;
    }
    Ok(())
}

pub struct NxmModel {
    pub hdr: NxmHeader,
    pub active_max_seq: usize,
    pub tokenizer: NxmTokenizer,
    pub mem_bytes: usize,
    pub kv_bytes: usize,
    tok_emb: AiBuffer,
    layers: Vec<LayerWeights>,
    rms_final: AiBuffer,
    w_cls: Option<AiBuffer>,
    rope_cos: AiBuffer,
    rope_sin: AiBuffer,
    kv_cache: Vec<KvLayerCache>,
    // Preallocated scratch buffers in AiArena
    x: AiBuffer,
    xb: AiBuffer,  // padded_dim floats (tail kept zero)
    xb2: AiBuffer, // dim floats
    q: AiBuffer,   // dim floats
    k: AiBuffer,   // kv_dim floats
    v: AiBuffer,   // kv_dim floats
    att: AiBuffer, // n_heads * active_max_seq floats
    hb: AiBuffer,  // padded_hidden floats (tail kept zero)
    hb2: AiBuffer, // hidden floats
    logits: AiBuffer,
    rng_state: u64,
}

impl NxmModel {
    #[inline(never)]
    pub fn from_vfs_path(path: &str, budget_bytes: usize) -> Result<Box<Self>, FormatError> {
        let cur = vfs::open_cursor(path).map_err(|_| FormatError::Io("VFS open failed"))?;
        let mut src = StreamSource::Vfs(cur);
        Self::from_stream(&mut src, budget_bytes)
    }

    #[inline(never)]
    pub fn from_bytes(data: &[u8], budget_bytes: usize) -> Result<Box<Self>, FormatError> {
        let mut src = StreamSource::Slice { data, pos: 0 };
        Self::from_stream(&mut src, budget_bytes)
    }

    #[inline(never)]
    fn from_stream(
        src: &mut StreamSource<'_>,
        budget_bytes: usize,
    ) -> Result<Box<Self>, FormatError> {
        let rem0 = src.remaining();
        if rem0 < NXM_HEADER_SIZE {
            let mut probe = [0u8; 24];
            let take = rem0.min(24);
            if take > 0 && src.read_exact(&mut probe[..take]).is_ok() {
                if let Some(g) = super::format::inspect_gguf(&probe[..take]) {
                    return Err(FormatError::UnsupportedGguf(g));
                }
            }
            return Err(FormatError::TooSmall);
        }

        let mut hdr_buf = [0u8; NXM_HEADER_SIZE];
        src.read_exact(&mut hdr_buf)?;
        let hdr = NxmHeader::parse_header_only(&hdr_buf)?;

        if (hdr.flags & FLAG_CRC32_INTEGRITY) != 0 {
            let rem = src.remaining() as u64;
            if rem < hdr.payload_len {
                return Err(FormatError::TruncatedData);
            }
            if rem != hdr.payload_len {
                return Err(FormatError::InvalidHyperparams("payload length mismatch"));
            }
        }

        let weights_bytes = hdr.estimated_weights_bytes();
        let dim = hdr.dim;
        let padded_dim = NxmHeader::padded_cols(dim);
        let kv_dim = hdr.kv_dim();
        let hidden = hdr.hidden_dim;
        let padded_hidden = NxmHeader::padded_cols(hidden);
        let head_dim = hdr.head_dim();
        let tied_cls = (hdr.flags & FLAG_TIED_CLS) != 0;

        let scratch_base =
            (dim * 3 + padded_dim + kv_dim * 2 + padded_hidden + hidden + hdr.vocab_size) * 4;
        let min_req = weights_bytes + scratch_base;
        if min_req > budget_bytes {
            return Err(FormatError::BudgetExceeded {
                required_bytes: min_req,
                budget_bytes,
            });
        }

        let full_req = hdr.estimated_runtime_bytes();
        let active_max_seq = if full_req <= budget_bytes {
            hdr.max_seq
        } else {
            let per_tok = hdr.n_layers * 2 * kv_dim * 4 + (head_dim / 2) * 8 + hdr.n_heads * 4;
            let avail_for_seq = budget_bytes.saturating_sub(min_req);
            let scaled = if per_tok > 0 { avail_for_seq / per_tok } else { 0 };
            if scaled < 16 {
                return Err(FormatError::BudgetExceeded {
                    required_bytes: full_req,
                    budget_bytes,
                });
            }
            klog!(
                LogLevel::Warn,
                "ai",
                "KV-cache context dynamically scaled max_seq {} -> {} within {} MiB AI Arena budget",
                hdr.max_seq,
                scaled,
                budget_bytes / (1024 * 1024)
            );
            scaled
        };

        let mut crc = Crc32::new();
        let mut payload_read = 0u64;

        let tokenizer = match src {
            StreamSource::Slice { data, pos } => {
                let start = *pos;
                let tok = NxmTokenizer::parse(data, pos, hdr.vocab_size)?;
                crc.update(&data[start..*pos]);
                payload_read += (*pos - start) as u64;
                tok
            }
            StreamSource::Vfs(cur) => {
                let before = cur.pos();
                let tok = NxmTokenizer::parse_from_cursor(cur, &mut crc, hdr.vocab_size)?;
                payload_read += (cur.pos() - before) as u64;
                tok
            }
        };

        let map_arena_err = |_| FormatError::Io("AiArena allocation failed");

        let q = hdr.quant_type;
        let emb_bytes = NxmHeader::matrix_bytes(q, hdr.vocab_size, dim);
        let mut tok_emb = ai_arena::alloc_buffer(emb_bytes, false).map_err(map_arena_err)?;
        stream_exact(src, &mut crc, tok_emb.as_mut_slice(), &mut payload_read)?;

        let mut layers = Vec::with_capacity(hdr.n_layers);
        let mut kv_cache = Vec::with_capacity(hdr.n_layers);

        let wq_len = NxmHeader::matrix_bytes(q, dim, dim);
        let wk_len = NxmHeader::matrix_bytes(q, kv_dim, dim);
        let wv_len = wk_len;
        let wo_len = wq_len;
        let w1_len = NxmHeader::matrix_bytes(q, hidden, dim);
        let w2_len = NxmHeader::matrix_bytes(q, dim, hidden);
        let w3_len = w1_len;
        let rms_bytes = dim * 4;
        let layer_blob_len =
            rms_bytes + wq_len + wk_len + wv_len + wo_len + rms_bytes + w1_len + w2_len + w3_len;

        let rms_att_off = 0usize;
        let wq_off = rms_att_off + rms_bytes;
        let wk_off = wq_off + wq_len;
        let wv_off = wk_off + wk_len;
        let wo_off = wv_off + wv_len;
        let rms_ffn_off = wo_off + wo_len;
        let w1_off = rms_ffn_off + rms_bytes;
        let w2_off = w1_off + w1_len;
        let w3_off = w2_off + w2_len;

        for _ in 0..hdr.n_layers {
            let mut blob = ai_arena::alloc_buffer(layer_blob_len, false).map_err(map_arena_err)?;
            stream_exact(src, &mut crc, blob.as_mut_slice(), &mut payload_read)?;

            let k_buf = ai_arena::alloc_f32(active_max_seq * kv_dim, true).map_err(map_arena_err)?;
            let v_buf = ai_arena::alloc_f32(active_max_seq * kv_dim, true).map_err(map_arena_err)?;

            layers.push(LayerWeights {
                blob,
                rms_att_off,
                wq_off,
                wq_len,
                wk_off,
                wk_len,
                wv_off,
                wv_len,
                wo_off,
                wo_len,
                rms_ffn_off,
                w1_off,
                w1_len,
                w2_off,
                w2_len,
                w3_off,
                w3_len,
                dim,
            });
            kv_cache.push(KvLayerCache { k: k_buf, v: v_buf });
        }

        let mut rms_final = ai_arena::alloc_f32(dim, false).map_err(map_arena_err)?;
        stream_exact(src, &mut crc, rms_final.as_mut_slice(), &mut payload_read)?;

        let w_cls = if tied_cls {
            None
        } else {
            let mut cls_buf = ai_arena::alloc_buffer(emb_bytes, false).map_err(map_arena_err)?;
            stream_exact(src, &mut crc, cls_buf.as_mut_slice(), &mut payload_read)?;
            Some(cls_buf)
        };

        if (hdr.flags & FLAG_CRC32_INTEGRITY) != 0 {
            if payload_read != hdr.payload_len || src.remaining() != 0 {
                return Err(FormatError::InvalidHyperparams("payload length mismatch"));
            }
            let actual_crc = crc.finalize();
            if actual_crc != hdr.payload_crc32 {
                return Err(FormatError::IntegrityMismatch {
                    expected: hdr.payload_crc32,
                    actual: actual_crc,
                });
            }
        }

        // Precompute RoPE cos/sin table [active_max_seq, head_dim / 2] inside AiArena
        let half_hd = head_dim / 2;
        let mut rope_cos =
            ai_arena::alloc_f32(active_max_seq * half_hd, false).map_err(map_arena_err)?;
        let mut rope_sin =
            ai_arena::alloc_f32(active_max_seq * half_hd, false).map_err(map_arena_err)?;
        {
            let cos_s = rope_cos.as_mut_f32_slice();
            let sin_s = rope_sin.as_mut_f32_slice();
            for pos in 0..active_max_seq {
                for j in 0..half_hd {
                    let exp = -((2 * j) as f32) / (head_dim as f32);
                    let freq = powf(hdr.rope_theta, exp);
                    let (s, c) = sin_cos_f32((pos as f32) * freq);
                    cos_s[pos * half_hd + j] = c;
                    sin_s[pos * half_hd + j] = s;
                }
            }
        }

        let kv_bytes: usize = kv_cache
            .iter()
            .map(|c| c.k.mapped_bytes() + c.v.mapped_bytes())
            .sum();

        let x = ai_arena::alloc_f32(dim, false).map_err(map_arena_err)?;
        let xb = ai_arena::alloc_f32(padded_dim, false).map_err(map_arena_err)?;
        let xb2 = ai_arena::alloc_f32(dim, false).map_err(map_arena_err)?;
        let q = ai_arena::alloc_f32(dim, false).map_err(map_arena_err)?;
        let k = ai_arena::alloc_f32(kv_dim, false).map_err(map_arena_err)?;
        let v = ai_arena::alloc_f32(kv_dim, false).map_err(map_arena_err)?;
        let att =
            ai_arena::alloc_f32(hdr.n_heads * active_max_seq, false).map_err(map_arena_err)?;
        let hb = ai_arena::alloc_f32(padded_hidden, false).map_err(map_arena_err)?;
        let hb2 = ai_arena::alloc_f32(hidden, false).map_err(map_arena_err)?;
        let logits = ai_arena::alloc_f32(hdr.vocab_size, false).map_err(map_arena_err)?;

        let total_mapped = tok_emb.mapped_bytes()
            + layers.iter().map(|l| l.blob.mapped_bytes()).sum::<usize>()
            + rms_final.mapped_bytes()
            + w_cls.as_ref().map(|c| c.mapped_bytes()).unwrap_or(0)
            + rope_cos.mapped_bytes()
            + rope_sin.mapped_bytes()
            + kv_bytes
            + x.mapped_bytes()
            + xb.mapped_bytes()
            + xb2.mapped_bytes()
            + q.mapped_bytes()
            + k.mapped_bytes()
            + v.mapped_bytes()
            + att.mapped_bytes()
            + hb.mapped_bytes()
            + hb2.mapped_bytes()
            + logits.mapped_bytes();

        Ok(Box::new(Self {
            mem_bytes: total_mapped,
            kv_bytes,
            active_max_seq,
            hdr,
            tokenizer,
            tok_emb,
            layers,
            rms_final,
            w_cls,
            rope_cos,
            rope_sin,
            kv_cache,
            x,
            xb,
            xb2,
            q,
            k,
            v,
            att,
            hb,
            hb2,
            logits,
            rng_state: crate::security::csprng::next_u64()
                .map(|v| v | 1)
                .unwrap_or(0x9E37_79B9_7F4A_7C15),
        }))
    }

    pub fn clear_kv_cache(&mut self) {
        for layer in self.kv_cache.iter_mut() {
            layer.k.fill_f32(0.0);
            layer.v.fill_f32(0.0);
        }
    }

    pub fn forward_token(&mut self, token: usize, pos: usize) -> &[f32] {
        let qtype = self.hdr.quant_type;
        let dim = self.hdr.dim;
        let kv_dim = self.hdr.kv_dim();
        let head_dim = self.hdr.head_dim();
        let half_hd = head_dim / 2;
        let hidden = self.hdr.hidden_dim;
        let n_heads = self.hdr.n_heads;
        let kv_mul = n_heads / self.hdr.n_kv_heads;
        let pos_clamped = pos.min(self.active_max_seq - 1);

        let tok_id = token.min(self.hdr.vocab_size - 1);
        let row_bytes = NxmHeader::matrix_bytes(qtype, 1, dim);

        {
            let x_s = self.x.as_mut_f32_slice();
            let tok_s = &self.tok_emb.as_slice()[tok_id * row_bytes..(tok_id + 1) * row_bytes];
            dequant_row(qtype, x_s, tok_s, dim);
        }

        let rope_off = pos_clamped * half_hd;
        let rope_cos_s = self.rope_cos.as_f32_slice();
        let rope_sin_s = self.rope_sin.as_f32_slice();

        for l in 0..self.hdr.n_layers {
            let lw = &self.layers[l];
            {
                let x_s = self.x.as_f32_slice();
                let xb_s = self.xb.as_mut_f32_slice();
                rmsnorm(&mut xb_s[..dim], x_s, lw.rms_att());
                // Zero-pad tail for NEON GEMV when dim % 32 != 0
                for z in &mut xb_s[dim..] {
                    *z = 0.0;
                }
            }

            {
                let xb_s = self.xb.as_f32_slice();
                gemv(qtype, self.q.as_mut_f32_slice(), lw.wq(), xb_s, dim, dim);
                gemv(qtype, self.k.as_mut_f32_slice(), lw.wk(), xb_s, kv_dim, dim);
                gemv(qtype, self.v.as_mut_f32_slice(), lw.wv(), xb_s, kv_dim, dim);
            }

            // Apply Rotary Position Embedding (RoPE) to Q and K
            {
                let q_s = self.q.as_mut_f32_slice();
                for h in 0..n_heads {
                    let qh = &mut q_s[h * head_dim..(h + 1) * head_dim];
                    for j in 0..half_hd {
                        let c = rope_cos_s[rope_off + j];
                        let s = rope_sin_s[rope_off + j];
                        let q0 = qh[2 * j];
                        let q1 = qh[2 * j + 1];
                        qh[2 * j] = q0 * c - q1 * s;
                        qh[2 * j + 1] = q0 * s + q1 * c;
                    }
                }
            }
            {
                let k_s = self.k.as_mut_f32_slice();
                for h in 0..self.hdr.n_kv_heads {
                    let kh = &mut k_s[h * head_dim..(h + 1) * head_dim];
                    for j in 0..half_hd {
                        let c = rope_cos_s[rope_off + j];
                        let s = rope_sin_s[rope_off + j];
                        let k0 = kh[2 * j];
                        let k1 = kh[2 * j + 1];
                        kh[2 * j] = k0 * c - k1 * s;
                        kh[2 * j + 1] = k0 * s + k1 * c;
                    }
                }
            }

            // Store K and V in layer cache at `pos_clamped`
            let cache = &mut self.kv_cache[l];
            let cache_k = cache.k.as_mut_f32_slice();
            let cache_v = cache.v.as_mut_f32_slice();
            cache_k[pos_clamped * kv_dim..(pos_clamped + 1) * kv_dim]
                .copy_from_slice(self.k.as_f32_slice());
            cache_v[pos_clamped * kv_dim..(pos_clamped + 1) * kv_dim]
                .copy_from_slice(self.v.as_f32_slice());

            // Causal Multi-Head / GQA Attention
            let inv_sqrt_hd = 1.0 / super::tensor::sqrtf(head_dim as f32);
            self.xb.fill_f32(0.0);
            {
                let q_s = self.q.as_f32_slice();
                let att_s = self.att.as_mut_f32_slice();
                let xb_s = self.xb.as_mut_f32_slice();

                for h in 0..n_heads {
                    let qh = &q_s[h * head_dim..(h + 1) * head_dim];
                    let kvh = h / kv_mul;
                    let att_h = &mut att_s
                        [h * self.active_max_seq..h * self.active_max_seq + pos_clamped + 1];
                    for t in 0..=pos_clamped {
                        let kt =
                            &cache_k[t * kv_dim + kvh * head_dim..t * kv_dim + (kvh + 1) * head_dim];
                        att_h[t] = dot_f32(qh, kt) * inv_sqrt_hd;
                    }
                    softmax(att_h);
                    let out_h = &mut xb_s[h * head_dim..(h + 1) * head_dim];
                    for t in 0..=pos_clamped {
                        let w = att_h[t];
                        let vt =
                            &cache_v[t * kv_dim + kvh * head_dim..t * kv_dim + (kvh + 1) * head_dim];
                        saxpy_f32(out_h, vt, w);
                    }
                }
            }

            gemv(
                qtype,
                self.xb2.as_mut_f32_slice(),
                lw.wo(),
                self.xb.as_f32_slice(),
                dim,
                dim,
            );
            {
                let x_s = self.x.as_mut_f32_slice();
                let xb2_s = self.xb2.as_f32_slice();
                for i in 0..dim {
                    x_s[i] += xb2_s[i];
                }
            }

            // SwiGLU Feed-Forward Network: w2(silu(w1(norm(x))) * w3(norm(x)))
            {
                let x_s = self.x.as_f32_slice();
                let xb_s = self.xb.as_mut_f32_slice();
                rmsnorm(&mut xb_s[..dim], x_s, lw.rms_ffn());
                for z in &mut xb_s[dim..] {
                    *z = 0.0;
                }
            }
            {
                let xb_s = self.xb.as_f32_slice();
                gemv(qtype, self.hb.as_mut_f32_slice(), lw.w1(), xb_s, hidden, dim);
                gemv(qtype, self.hb2.as_mut_f32_slice(), lw.w3(), xb_s, hidden, dim);
            }
            {
                let hb_s = self.hb.as_mut_f32_slice();
                let hb2_s = self.hb2.as_f32_slice();
                for i in 0..hidden {
                    hb_s[i] = siluf(hb_s[i]) * hb2_s[i];
                }
                for z in &mut hb_s[hidden..] {
                    *z = 0.0;
                }
            }
            gemv(
                qtype,
                self.xb.as_mut_f32_slice(),
                lw.w2(),
                self.hb.as_f32_slice(),
                dim,
                hidden,
            );
            {
                let x_s = self.x.as_mut_f32_slice();
                let xb_s = self.xb.as_f32_slice();
                for i in 0..dim {
                    x_s[i] += xb_s[i];
                }
            }
        }

        // Final RMSNorm & Logits projection (using NEON GEMV)
        {
            let x_s = self.x.as_f32_slice();
            let xb_s = self.xb.as_mut_f32_slice();
            rmsnorm(&mut xb_s[..dim], x_s, self.rms_final.as_f32_slice());
            for z in &mut xb_s[dim..] {
                *z = 0.0;
            }
        }
        let cls_mat = self
            .w_cls
            .as_ref()
            .map(|c| c.as_slice())
            .unwrap_or_else(|| self.tok_emb.as_slice());
        gemv(
            qtype,
            self.logits.as_mut_f32_slice(),
            cls_mat,
            self.xb.as_f32_slice(),
            self.hdr.vocab_size,
            dim,
        );
        self.logits.as_f32_slice()
    }

    fn sample_next(&mut self, temp_x100: u32, top_k: usize) -> usize {
        let logits_s = self.logits.as_f32_slice();
        if temp_x100 == 0 || top_k <= 1 {
            let mut best_i = 0usize;
            let mut best_v = logits_s[0];
            for (i, &v) in logits_s.iter().enumerate().skip(1) {
                if v > best_v {
                    best_v = v;
                    best_i = i;
                }
            }
            return best_i;
        }

        // Temperature + Top-K sampling
        let temp = (temp_x100 as f32) / 100.0;
        let k = top_k.min(logits_s.len()).max(1);
        let mut pairs: Vec<(usize, f32)> = logits_s
            .iter()
            .enumerate()
            .map(|(i, &v)| (i, v / temp))
            .collect();
        pairs.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(core::cmp::Ordering::Equal));
        pairs.truncate(k);

        let mut probs: Vec<f32> = pairs.iter().map(|p| p.1).collect();
        softmax(&mut probs);

        self.rng_state ^= self.rng_state << 13;
        self.rng_state ^= self.rng_state >> 7;
        self.rng_state ^= self.rng_state << 17;
        let r = ((self.rng_state & 0xFFFF) as f32) / 65536.0;

        let mut cdf = 0.0f32;
        for (idx, p) in probs.iter().enumerate() {
            cdf += *p;
            if r <= cdf {
                return pairs[idx].0;
            }
        }
        pairs[0].0
    }

    pub fn generate<F: FnMut(&str)>(
        &mut self,
        prompt: &str,
        max_tokens: usize,
        temp_x100: u32,
        top_k: usize,
        mut on_piece: F,
    ) -> InferResult {
        ABORT_FLAG.store(false, Ordering::Release);
        self.clear_kv_cache();

        let prompt_ids = self.tokenizer.encode(prompt, true);
        let prompt_len = prompt_ids.len().max(1);
        let freq = timer::read_cntfrq().max(1);
        let t0 = timer::read_cntpct();

        let mut pos = 0usize;
        let mut next_tok = 1usize;
        for (idx, &tok) in prompt_ids.iter().enumerate() {
            if pos >= self.active_max_seq {
                break;
            }
            let _ = self.forward_token(tok, pos);
            pos += 1;
            if idx + 1 == prompt_ids.len() {
                next_tok = self.sample_next(temp_x100, top_k);
            }
        }

        let mut output = String::new();
        let mut generated = 0usize;
        let mut aborted = false;

        for _ in 0..max_tokens {
            if ABORT_FLAG.load(Ordering::Acquire) {
                aborted = true;
                break;
            }
            if next_tok == TOKEN_EOS || pos >= self.active_max_seq {
                break;
            }
            let piece = String::from(self.tokenizer.decode_token(next_tok));
            if !piece.is_empty() {
                on_piece(&piece);
                output.push_str(&piece);
            }
            generated += 1;

            let _ = self.forward_token(next_tok, pos);
            pos += 1;
            next_tok = self.sample_next(temp_x100, top_k);
        }

        let dt_cnt = timer::read_cntpct().saturating_sub(t0);
        let elapsed_us = (dt_cnt * 1_000_000) / freq;
        let elapsed_ms = elapsed_us / 1000;
        let total_toks = generated.max(1) as u64;
        let tokens_per_sec_x100 = if elapsed_us > 0 {
            (total_toks * 100_000_000) / elapsed_us
        } else {
            0
        };

        InferResult {
            output,
            prompt_tokens: prompt_len,
            generated_tokens: generated,
            elapsed_ms,
            elapsed_us,
            tokens_per_sec_x100,
            aborted,
        }
    }
}
