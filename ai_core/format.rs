//! Native NexOS `.nxm` v1 Binary Model Container & Header Validation.

use core::convert::TryInto;

pub const NXM_MAGIC: [u8; 4] = *b"NXM1";
pub const GGUF_MAGIC: [u8; 4] = *b"GGUF";
pub const NXM_VERSION: u32 = 1;
pub const NXM_HEADER_SIZE: usize = 64;

pub const QUANT_F32: u32 = 0;
pub const QUANT_Q8_0: u32 = 1;
pub const Q8_BLOCK_ELEMS: usize = 32;
pub const Q8_BLOCK_BYTES: usize = 36; // 4B f32 scale + 32B i8 weights

pub const FLAG_TIED_CLS: u32 = 1 << 0;
pub const FLAG_CRC32_INTEGRITY: u32 = 1 << 1;

#[derive(Clone, Debug)]
pub struct NxmHeader {
    pub version: u32,
    pub vocab_size: usize,
    pub dim: usize,
    pub hidden_dim: usize,
    pub n_layers: usize,
    pub n_heads: usize,
    pub n_kv_heads: usize,
    pub max_seq: usize,
    pub quant_type: u32,
    pub rope_theta: f32,
    pub flags: u32,
    pub payload_crc32: u32,
    pub payload_len: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct GgufSummary {
    pub version: u32,
    pub tensor_count: u64,
    pub metadata_kv_count: u64,
}

#[derive(Clone, Debug)]
pub enum FormatError {
    TooSmall,
    BadMagic,
    UnsupportedGguf(GgufSummary),
    UnsupportedVersion(u32),
    UnsupportedQuant(u32),
    InvalidHyperparams(&'static str),
    TruncatedData,
    IntegrityMismatch { expected: u32, actual: u32 },
    BudgetExceeded { required_bytes: usize, budget_bytes: usize },
}

fn rd_u32(data: &[u8], off: usize) -> Result<u32, FormatError> {
    let b: [u8; 4] = data
        .get(off..off + 4)
        .ok_or(FormatError::TruncatedData)?
        .try_into()
        .map_err(|_| FormatError::TruncatedData)?;
    Ok(u32::from_le_bytes(b))
}

fn rd_u64(data: &[u8], off: usize) -> Result<u64, FormatError> {
    let b: [u8; 8] = data
        .get(off..off + 8)
        .ok_or(FormatError::TruncatedData)?
        .try_into()
        .map_err(|_| FormatError::TruncatedData)?;
    Ok(u64::from_le_bytes(b))
}

pub fn inspect_gguf(data: &[u8]) -> Option<GgufSummary> {
    if data.len() < 24 || data[0..4] != GGUF_MAGIC {
        return None;
    }
    Some(GgufSummary {
        version: rd_u32(data, 4).ok()?,
        tensor_count: rd_u64(data, 8).ok()?,
        metadata_kv_count: rd_u64(data, 16).ok()?,
    })
}

impl NxmHeader {
    pub fn parse(data: &[u8]) -> Result<Self, FormatError> {
        if data.len() < NXM_HEADER_SIZE {
            if let Some(g) = inspect_gguf(data) {
                return Err(FormatError::UnsupportedGguf(g));
            }
            return Err(FormatError::TooSmall);
        }
        if data[0..4] != NXM_MAGIC {
            if let Some(g) = inspect_gguf(data) {
                return Err(FormatError::UnsupportedGguf(g));
            }
            return Err(FormatError::BadMagic);
        }
        let version = rd_u32(data, 4)?;
        if version != NXM_VERSION {
            return Err(FormatError::UnsupportedVersion(version));
        }

        let vocab_size = rd_u32(data, 8)? as usize;
        let dim = rd_u32(data, 12)? as usize;
        let hidden_dim = rd_u32(data, 16)? as usize;
        let n_layers = rd_u32(data, 20)? as usize;
        let n_heads = rd_u32(data, 24)? as usize;
        let n_kv_heads = rd_u32(data, 28)? as usize;
        let max_seq = rd_u32(data, 32)? as usize;
        let quant_type = rd_u32(data, 36)?;
        let rope_theta = f32::from_bits(rd_u32(data, 40)?);
        let flags = rd_u32(data, 44)?;
        let payload_crc32 = rd_u32(data, 48)?;
        let payload_len = rd_u64(data, 52)?;

        if quant_type != QUANT_Q8_0 {
            return Err(FormatError::UnsupportedQuant(quant_type));
        }
        if vocab_size < 4 || vocab_size > 65536 {
            return Err(FormatError::InvalidHyperparams("vocab_size out of range"));
        }
        if dim == 0 || dim > 8192 || dim % Q8_BLOCK_ELEMS != 0 {
            return Err(FormatError::InvalidHyperparams("dim must be multiple of 32"));
        }
        if hidden_dim == 0 || hidden_dim > 32768 || hidden_dim % Q8_BLOCK_ELEMS != 0 {
            return Err(FormatError::InvalidHyperparams("hidden_dim must be multiple of 32"));
        }
        if n_layers == 0 || n_layers > 64 {
            return Err(FormatError::InvalidHyperparams("n_layers out of range"));
        }
        if n_heads == 0 || dim % n_heads != 0 {
            return Err(FormatError::InvalidHyperparams("dim must divide evenly by n_heads"));
        }
        let head_dim = dim / n_heads;
        if head_dim % 2 != 0 {
            return Err(FormatError::InvalidHyperparams("head_dim must be even for RoPE"));
        }
        if n_kv_heads == 0 || n_heads % n_kv_heads != 0 {
            return Err(FormatError::InvalidHyperparams("n_heads must divide by n_kv_heads"));
        }
        let kv_dim = n_kv_heads * head_dim;
        if kv_dim % Q8_BLOCK_ELEMS != 0 {
            return Err(FormatError::InvalidHyperparams("kv_dim must be multiple of 32"));
        }
        if max_seq == 0 || max_seq > 4096 {
            return Err(FormatError::InvalidHyperparams("max_seq out of range"));
        }

        if (flags & FLAG_CRC32_INTEGRITY) != 0 {
            let actual_payload = &data[NXM_HEADER_SIZE..];
            if (actual_payload.len() as u64) < payload_len {
                return Err(FormatError::TruncatedData);
            }
            if (actual_payload.len() as u64) != payload_len {
                return Err(FormatError::InvalidHyperparams("payload length mismatch"));
            }
            let actual_crc = crate::security::sha256::crc32(actual_payload);
            if actual_crc != payload_crc32 {
                return Err(FormatError::IntegrityMismatch {
                    expected: payload_crc32,
                    actual: actual_crc,
                });
            }
        }

        Ok(Self {
            version,
            vocab_size,
            dim,
            hidden_dim,
            n_layers,
            n_heads,
            n_kv_heads,
            max_seq,
            quant_type,
            rope_theta: if rope_theta > 0.0 { rope_theta } else { 10000.0 },
            flags,
            payload_crc32,
            payload_len,
        })
    }

    #[inline]
    pub fn head_dim(&self) -> usize {
        self.dim / self.n_heads
    }

    #[inline]
    pub fn kv_dim(&self) -> usize {
        self.n_kv_heads * self.head_dim()
    }

    #[inline]
    pub fn q8_matrix_bytes(rows: usize, cols: usize) -> usize {
        rows * (cols / Q8_BLOCK_ELEMS) * Q8_BLOCK_BYTES
    }

    pub fn estimated_runtime_bytes(&self) -> usize {
        let kv_dim = self.kv_dim();
        let tied = (self.flags & FLAG_TIED_CLS) != 0;
        let per_layer_q8 = Self::q8_matrix_bytes(self.dim, self.dim) // wq
            + Self::q8_matrix_bytes(kv_dim, self.dim) * 2 // wk, wv
            + Self::q8_matrix_bytes(self.dim, self.dim) // wo
            + Self::q8_matrix_bytes(self.hidden_dim, self.dim) * 2 // w1, w3
            + Self::q8_matrix_bytes(self.dim, self.hidden_dim); // w2
        let per_layer_f32 = self.dim * 4 * 2; // rms_att + rms_ffn
        let emb_bytes = Self::q8_matrix_bytes(self.vocab_size, self.dim);
        let cls_bytes = if tied { 0 } else { emb_bytes };
        let kv_cache_bytes = self.n_layers * 2 * self.max_seq * kv_dim * 4;
        let rope_bytes = self.max_seq * (self.head_dim() / 2) * 8;
        emb_bytes
            + cls_bytes
            + self.n_layers * (per_layer_q8 + per_layer_f32)
            + self.dim * 4
            + kv_cache_bytes
            + rope_bytes
    }
}
