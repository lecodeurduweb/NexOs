//! Greedy Longest-Match + Byte-Fallback Tokenizer for `.nxm` Models.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::convert::TryInto;

use super::format::FormatError;

pub const TOKEN_PAD: usize = 0;
pub const TOKEN_BOS: usize = 1;
pub const TOKEN_EOS: usize = 2;

#[derive(Clone)]
struct VocabEntry {
    text: String,
    bytes: Vec<u8>,
    score: f32,
}

#[derive(Clone)]
pub struct NxmTokenizer {
    vocab: Vec<VocabEntry>,
    byte_tokens: Vec<Option<usize>>,
}

impl NxmTokenizer {
    #[inline(never)]
    pub fn parse(data: &[u8], off: &mut usize, vocab_size: usize) -> Result<Self, FormatError> {
        let mut vocab = Vec::with_capacity(vocab_size);
        let mut byte_tokens = vec![None; 256];

        for id in 0..vocab_size {
            let score_b: [u8; 4] = data
                .get(*off..*off + 4)
                .ok_or(FormatError::TruncatedData)?
                .try_into()
                .map_err(|_| FormatError::TruncatedData)?;
            let score = f32::from_le_bytes(score_b);
            *off += 4;

            let len_b: [u8; 2] = data
                .get(*off..*off + 2)
                .ok_or(FormatError::TruncatedData)?
                .try_into()
                .map_err(|_| FormatError::TruncatedData)?;
            let tlen = u16::from_le_bytes(len_b) as usize;
            *off += 2;

            let raw = data
                .get(*off..*off + tlen)
                .ok_or(FormatError::TruncatedData)?;
            *off += tlen;

            if raw.len() == 1 && id >= 3 {
                byte_tokens[raw[0] as usize] = Some(id);
            }
            let text = String::from_utf8_lossy(raw).into_owned();
            vocab.push(VocabEntry {
                text,
                bytes: Vec::from(raw),
                score,
            });
        }

        Ok(Self { vocab, byte_tokens })
    }

    pub fn vocab_size(&self) -> usize {
        self.vocab.len()
    }

    /// Encode UTF-8 text into token IDs using longest-match over `.nxm` vocabulary
    /// (with byte fallback). Special tokens 0..3 are never matched from prompt text.
    pub fn encode(&self, prompt: &str, add_bos: bool) -> Vec<usize> {
        let mut ids = Vec::new();
        if add_bos && self.vocab.len() > TOKEN_BOS {
            ids.push(TOKEN_BOS);
        }
        let bytes = prompt.as_bytes();
        let mut pos = 0usize;
        while pos < bytes.len() {
            let mut best_id: Option<usize> = None;
            let mut best_len = 0usize;
            let mut best_score = f32::NEG_INFINITY;

            for (id, entry) in self.vocab.iter().enumerate().skip(3) {
                let elen = entry.bytes.len();
                if elen == 0 || pos + elen > bytes.len() {
                    continue;
                }
                if elen < best_len {
                    continue;
                }
                if &bytes[pos..pos + elen] == entry.bytes.as_slice() {
                    if elen > best_len || entry.score > best_score {
                        best_id = Some(id);
                        best_len = elen;
                        best_score = entry.score;
                    }
                }
            }

            if let Some(id) = best_id {
                ids.push(id);
                pos += best_len;
            } else if let Some(bid) = self.byte_tokens[bytes[pos] as usize] {
                ids.push(bid);
                pos += 1;
            } else {
                pos += 1;
            }
        }
        ids
    }

    pub fn decode_token(&self, id: usize) -> &str {
        if id <= TOKEN_EOS || id >= self.vocab.len() {
            ""
        } else {
            &self.vocab[id].text
        }
    }
}
