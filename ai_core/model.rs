//! Native NexOS Causal Transformer Inference Engine (Q8_0 + AArch64 NEON + KV Cache).

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::convert::TryInto;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::timer;

use super::format::{FormatError, NxmHeader, FLAG_TIED_CLS, Q8_BLOCK_BYTES, Q8_BLOCK_ELEMS};
use super::tensor::{dequant_row_q8_0, dot_f32, gemv_q8_0, powf, rmsnorm, siluf, sin_cos_f32, softmax};
use super::tokenizer::{NxmTokenizer, TOKEN_EOS};

pub static ABORT_FLAG: AtomicBool = AtomicBool::new(false);

struct LayerWeights {
    rms_att: Vec<f32>,
    wq: Vec<u8>,
    wk: Vec<u8>,
    wv: Vec<u8>,
    wo: Vec<u8>,
    rms_ffn: Vec<f32>,
    w1: Vec<u8>,
    w2: Vec<u8>,
    w3: Vec<u8>,
}

struct KvLayerCache {
    k: Vec<f32>, // [max_seq * kv_dim]
    v: Vec<f32>, // [max_seq * kv_dim]
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

pub struct NxmModel {
    pub hdr: NxmHeader,
    pub tokenizer: NxmTokenizer,
    pub mem_bytes: usize,
    tok_emb: Vec<u8>,
    layers: Vec<LayerWeights>,
    rms_final: Vec<f32>,
    w_cls: Option<Vec<u8>>,
    rope_cos: Vec<f32>,
    rope_sin: Vec<f32>,
    kv_cache: Vec<KvLayerCache>,
    // Preallocated scratch buffers
    x: Vec<f32>,
    xb: Vec<f32>,
    xb2: Vec<f32>,
    q: Vec<f32>,
    k: Vec<f32>,
    v: Vec<f32>,
    att: Vec<f32>,
    hb: Vec<f32>,
    hb2: Vec<f32>,
    logits: Vec<f32>,
    rng_state: u64,
}

fn read_bytes(data: &[u8], off: &mut usize, len: usize) -> Result<Vec<u8>, FormatError> {
    let slice = data
        .get(*off..*off + len)
        .ok_or(FormatError::TruncatedData)?;
    *off += len;
    Ok(Vec::from(slice))
}

fn read_f32_vec(data: &[u8], off: &mut usize, count: usize) -> Result<Vec<f32>, FormatError> {
    let bytes = count * 4;
    let slice = data
        .get(*off..*off + bytes)
        .ok_or(FormatError::TruncatedData)?;
    *off += bytes;
    let mut out = Vec::with_capacity(count);
    for ch in slice.chunks_exact(4) {
        out.push(f32::from_le_bytes(ch.try_into().unwrap()));
    }
    Ok(out)
}

impl NxmModel {
    #[inline(never)]
    pub fn from_bytes(data: &[u8], budget_bytes: usize) -> Result<Box<Self>, FormatError> {
        let hdr = NxmHeader::parse(data)?;
        let req = hdr.estimated_runtime_bytes();
        if req > budget_bytes {
            return Err(FormatError::BudgetExceeded {
                required_bytes: req,
                budget_bytes,
            });
        }

        let mut off = 64usize;
        let tokenizer = NxmTokenizer::parse(data, &mut off, hdr.vocab_size)?;

        let dim = hdr.dim;
        let kv_dim = hdr.kv_dim();
        let hidden = hdr.hidden_dim;
        let head_dim = hdr.head_dim();
        let tied_cls = (hdr.flags & FLAG_TIED_CLS) != 0;

        let tok_emb = read_bytes(data, &mut off, NxmHeader::q8_matrix_bytes(hdr.vocab_size, dim))?;

        let mut layers = Vec::with_capacity(hdr.n_layers);
        let mut kv_cache = Vec::with_capacity(hdr.n_layers);
        for _ in 0..hdr.n_layers {
            let rms_att = read_f32_vec(data, &mut off, dim)?;
            let wq = read_bytes(data, &mut off, NxmHeader::q8_matrix_bytes(dim, dim))?;
            let wk = read_bytes(data, &mut off, NxmHeader::q8_matrix_bytes(kv_dim, dim))?;
            let wv = read_bytes(data, &mut off, NxmHeader::q8_matrix_bytes(kv_dim, dim))?;
            let wo = read_bytes(data, &mut off, NxmHeader::q8_matrix_bytes(dim, dim))?;
            let rms_ffn = read_f32_vec(data, &mut off, dim)?;
            let w1 = read_bytes(data, &mut off, NxmHeader::q8_matrix_bytes(hidden, dim))?;
            let w2 = read_bytes(data, &mut off, NxmHeader::q8_matrix_bytes(dim, hidden))?;
            let w3 = read_bytes(data, &mut off, NxmHeader::q8_matrix_bytes(hidden, dim))?;
            layers.push(LayerWeights {
                rms_att,
                wq,
                wk,
                wv,
                wo,
                rms_ffn,
                w1,
                w2,
                w3,
            });
            kv_cache.push(KvLayerCache {
                k: vec![0.0f32; hdr.max_seq * kv_dim],
                v: vec![0.0f32; hdr.max_seq * kv_dim],
            });
        }

        let rms_final = read_f32_vec(data, &mut off, dim)?;
        let w_cls = if tied_cls {
            None
        } else {
            Some(read_bytes(
                data,
                &mut off,
                NxmHeader::q8_matrix_bytes(hdr.vocab_size, dim),
            )?)
        };

        // Precompute RoPE cos/sin table [max_seq, head_dim / 2]
        let half_hd = head_dim / 2;
        let mut rope_cos = Vec::with_capacity(hdr.max_seq * half_hd);
        let mut rope_sin = Vec::with_capacity(hdr.max_seq * half_hd);
        for pos in 0..hdr.max_seq {
            for j in 0..half_hd {
                let exp = -((2 * j) as f32) / (head_dim as f32);
                let freq = powf(hdr.rope_theta, exp);
                let (s, c) = sin_cos_f32((pos as f32) * freq);
                rope_cos.push(c);
                rope_sin.push(s);
            }
        }

        Ok(Box::new(Self {
            mem_bytes: req,
            x: vec![0.0f32; dim],
            xb: vec![0.0f32; dim],
            xb2: vec![0.0f32; dim],
            q: vec![0.0f32; dim],
            k: vec![0.0f32; kv_dim],
            v: vec![0.0f32; kv_dim],
            att: vec![0.0f32; hdr.n_heads * hdr.max_seq],
            hb: vec![0.0f32; hidden],
            hb2: vec![0.0f32; hidden],
            logits: vec![0.0f32; hdr.vocab_size],
            hdr,
            tokenizer,
            tok_emb,
            layers,
            rms_final,
            w_cls,
            rope_cos,
            rope_sin,
            kv_cache,
            rng_state: 0x9E37_79B9_7F4A_7C15,
        }))
    }

    pub fn clear_kv_cache(&mut self) {
        for layer in self.kv_cache.iter_mut() {
            layer.k.fill(0.0);
            layer.v.fill(0.0);
        }
    }

    pub fn forward_token(&mut self, token: usize, pos: usize) -> &[f32] {
        let dim = self.hdr.dim;
        let kv_dim = self.hdr.kv_dim();
        let head_dim = self.hdr.head_dim();
        let half_hd = head_dim / 2;
        let hidden = self.hdr.hidden_dim;
        let n_heads = self.hdr.n_heads;
        let kv_mul = n_heads / self.hdr.n_kv_heads;
        let pos_clamped = pos.min(self.hdr.max_seq - 1);

        let tok_id = token.min(self.hdr.vocab_size - 1);
        let row_bytes = (dim / Q8_BLOCK_ELEMS) * Q8_BLOCK_BYTES;
        dequant_row_q8_0(
            &mut self.x,
            &self.tok_emb[tok_id * row_bytes..(tok_id + 1) * row_bytes],
            dim,
        );

        let rope_off = pos_clamped * half_hd;

        for l in 0..self.hdr.n_layers {
            let lw = &self.layers[l];
            rmsnorm(&mut self.xb, &self.x, &lw.rms_att);

            gemv_q8_0(&mut self.q, &lw.wq, &self.xb, dim, dim);
            gemv_q8_0(&mut self.k, &lw.wk, &self.xb, kv_dim, dim);
            gemv_q8_0(&mut self.v, &lw.wv, &self.xb, kv_dim, dim);

            // Apply Rotary Position Embedding (RoPE) to Q and K
            for h in 0..n_heads {
                let qh = &mut self.q[h * head_dim..(h + 1) * head_dim];
                for j in 0..half_hd {
                    let c = self.rope_cos[rope_off + j];
                    let s = self.rope_sin[rope_off + j];
                    let q0 = qh[2 * j];
                    let q1 = qh[2 * j + 1];
                    qh[2 * j] = q0 * c - q1 * s;
                    qh[2 * j + 1] = q0 * s + q1 * c;
                }
            }
            for h in 0..self.hdr.n_kv_heads {
                let kh = &mut self.k[h * head_dim..(h + 1) * head_dim];
                for j in 0..half_hd {
                    let c = self.rope_cos[rope_off + j];
                    let s = self.rope_sin[rope_off + j];
                    let k0 = kh[2 * j];
                    let k1 = kh[2 * j + 1];
                    kh[2 * j] = k0 * c - k1 * s;
                    kh[2 * j + 1] = k0 * s + k1 * c;
                }
            }

            // Store K and V in layer cache at `pos_clamped`
            let cache = &mut self.kv_cache[l];
            cache.k[pos_clamped * kv_dim..(pos_clamped + 1) * kv_dim].copy_from_slice(&self.k);
            cache.v[pos_clamped * kv_dim..(pos_clamped + 1) * kv_dim].copy_from_slice(&self.v);

            // Causal Multi-Head / GQA Attention
            let inv_sqrt_hd = 1.0 / super::tensor::sqrtf(head_dim as f32);
            self.xb.fill(0.0);
            for h in 0..n_heads {
                let qh = &self.q[h * head_dim..(h + 1) * head_dim];
                let kvh = h / kv_mul;
                let att_h = &mut self.att[h * self.hdr.max_seq..h * self.hdr.max_seq + pos_clamped + 1];
                for t in 0..=pos_clamped {
                    let kt = &cache.k[t * kv_dim + kvh * head_dim..t * kv_dim + (kvh + 1) * head_dim];
                    att_h[t] = dot_f32(qh, kt) * inv_sqrt_hd;
                }
                softmax(att_h);
                let out_h = &mut self.xb[h * head_dim..(h + 1) * head_dim];
                for t in 0..=pos_clamped {
                    let w = att_h[t];
                    let vt = &cache.v[t * kv_dim + kvh * head_dim..t * kv_dim + (kvh + 1) * head_dim];
                    for d in 0..head_dim {
                        out_h[d] += w * vt[d];
                    }
                }
            }

            gemv_q8_0(&mut self.xb2, &lw.wo, &self.xb, dim, dim);
            for i in 0..dim {
                self.x[i] += self.xb2[i];
            }

            // SwiGLU Feed-Forward Network: w2(silu(w1(norm(x))) * w3(norm(x)))
            rmsnorm(&mut self.xb, &self.x, &lw.rms_ffn);
            gemv_q8_0(&mut self.hb, &lw.w1, &self.xb, hidden, dim);
            gemv_q8_0(&mut self.hb2, &lw.w3, &self.xb, hidden, dim);
            for i in 0..hidden {
                self.hb[i] = siluf(self.hb[i]) * self.hb2[i];
            }
            gemv_q8_0(&mut self.xb, &lw.w2, &self.hb, dim, hidden);
            for i in 0..dim {
                self.x[i] += self.xb[i];
            }
        }

        // Final RMSNorm & Logits projection (using NEON GEMV)
        rmsnorm(&mut self.xb, &self.x, &self.rms_final);
        let cls_mat = self.w_cls.as_deref().unwrap_or(&self.tok_emb);
        gemv_q8_0(&mut self.logits, cls_mat, &self.xb, self.hdr.vocab_size, dim);
        &self.logits
    }

    fn sample_next(&mut self, temp_x100: u32, top_k: usize) -> usize {
        if temp_x100 == 0 || top_k <= 1 {
            let mut best_i = 0usize;
            let mut best_v = self.logits[0];
            for (i, &v) in self.logits.iter().enumerate().skip(1) {
                if v > best_v {
                    best_v = v;
                    best_i = i;
                }
            }
            return best_i;
        }

        // Temperature + Top-K sampling
        let temp = (temp_x100 as f32) / 100.0;
        let k = top_k.min(self.logits.len()).max(1);
        let mut pairs: Vec<(usize, f32)> = self
            .logits
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
            if pos >= self.hdr.max_seq {
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
            if next_tok == TOKEN_EOS || pos >= self.hdr.max_seq {
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
