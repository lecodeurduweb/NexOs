//! Fast Indexed Longest-Match + Byte-Fallback Tokenizer for `.nxm` Models.
//!
//! Supports both SentencePiece vocabularies (`<0xNN>` hex byte tokens, `'▁'` word boundary)
//! and NexOS custom `.nxm` vocabularies via a first-byte bucket index for O(1)-bucket encoding.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::convert::TryInto;

use super::format::FormatError;
use crate::filesystem::vfs::{self, VfsCursor};
use crate::security::sha256::Crc32;

pub const TOKEN_PAD: usize = 0;
pub const TOKEN_BOS: usize = 1;
pub const TOKEN_EOS: usize = 2;

#[derive(Clone)]
struct VocabEntry {
    raw: Vec<u8>,
    display: String,
    score: f32,
    is_hex_byte: bool,
}

#[derive(Clone)]
pub struct NxmTokenizer {
    vocab: Vec<VocabEntry>,
    byte_tokens: [Option<usize>; 256],
    /// Buckets indexed by `entry.raw[0]` sorted descending by length then score.
    buckets: Vec<Vec<usize>>,
}

fn parse_hex_byte_token(raw: &[u8]) -> Option<u8> {
    if raw.len() == 6 && raw[0] == b'<' && raw[1] == b'0' && raw[2] == b'x' && raw[5] == b'>' {
        let hi = match raw[3] {
            b'0'..=b'9' => raw[3] - b'0',
            b'A'..=b'F' => raw[3] - b'A' + 10,
            b'a'..=b'f' => raw[3] - b'a' + 10,
            _ => return None,
        };
        let lo = match raw[4] {
            b'0'..=b'9' => raw[4] - b'0',
            b'A'..=b'F' => raw[4] - b'A' + 10,
            b'a'..=b'f' => raw[4] - b'a' + 10,
            _ => return None,
        };
        return Some((hi << 4) | lo);
    }
    None
}

fn format_display_piece(raw: &[u8]) -> String {
    if let Some(b) = parse_hex_byte_token(raw) {
        if b.is_ascii() {
            let mut s = String::with_capacity(1);
            s.push(b as char);
            return s;
        }
        return String::new();
    }
    let s = String::from_utf8_lossy(raw);
    if s.contains('\u{2581}') {
        s.replace('\u{2581}', " ")
    } else {
        s.into_owned()
    }
}

impl NxmTokenizer {
    fn finalize(vocab: Vec<VocabEntry>, byte_tokens: [Option<usize>; 256]) -> Self {
        let mut buckets: Vec<Vec<usize>> = (0..256).map(|_| Vec::new()).collect();
        for (id, entry) in vocab.iter().enumerate().skip(3) {
            if entry.is_hex_byte || entry.raw.is_empty() {
                continue;
            }
            buckets[entry.raw[0] as usize].push(id);
        }
        for b in buckets.iter_mut() {
            b.sort_by(|&a, &c| {
                vocab[c]
                    .raw
                    .len()
                    .cmp(&vocab[a].raw.len())
                    .then_with(|| {
                        vocab[c]
                            .score
                            .partial_cmp(&vocab[a].score)
                            .unwrap_or(core::cmp::Ordering::Equal)
                    })
                    .then_with(|| a.cmp(&c))
            });
        }
        Self {
            vocab,
            byte_tokens,
            buckets,
        }
    }

    #[inline(never)]
    pub fn parse(data: &[u8], off: &mut usize, vocab_size: usize) -> Result<Self, FormatError> {
        let mut vocab = Vec::with_capacity(vocab_size);
        let mut byte_tokens = [None; 256];

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

            let mut is_hex_byte = false;
            if id >= 3 {
                if let Some(hb) = parse_hex_byte_token(raw) {
                    byte_tokens[hb as usize] = Some(id);
                    is_hex_byte = true;
                } else if raw.len() == 1 {
                    byte_tokens[raw[0] as usize] = Some(id);
                }
            }
            let display = format_display_piece(raw);
            vocab.push(VocabEntry {
                raw: Vec::from(raw),
                display,
                score,
                is_hex_byte,
            });
        }

        Ok(Self::finalize(vocab, byte_tokens))
    }

    #[inline(never)]
    pub fn parse_from_cursor(
        cur: &mut VfsCursor,
        crc: &mut Crc32,
        vocab_size: usize,
    ) -> Result<Self, FormatError> {
        let mut vocab = Vec::with_capacity(vocab_size);
        let mut byte_tokens = [None; 256];

        for id in 0..vocab_size {
            let mut hdr6 = [0u8; 6];
            vfs::read_cursor_exact(cur, &mut hdr6).map_err(|_| FormatError::TruncatedData)?;
            crc.update(&hdr6);

            let score = f32::from_le_bytes(hdr6[0..4].try_into().unwrap());
            let tlen = u16::from_le_bytes(hdr6[4..6].try_into().unwrap()) as usize;
            if tlen > 1024 {
                return Err(FormatError::InvalidHyperparams("token piece too long"));
            }

            let mut raw = vec![0u8; tlen];
            if tlen > 0 {
                vfs::read_cursor_exact(cur, &mut raw).map_err(|_| FormatError::TruncatedData)?;
                crc.update(&raw);
            }

            let mut is_hex_byte = false;
            if id >= 3 {
                if let Some(hb) = parse_hex_byte_token(&raw) {
                    byte_tokens[hb as usize] = Some(id);
                    is_hex_byte = true;
                } else if raw.len() == 1 {
                    byte_tokens[raw[0] as usize] = Some(id);
                }
            }
            let display = format_display_piece(&raw);
            vocab.push(VocabEntry {
                raw,
                display,
                score,
                is_hex_byte,
            });
        }

        Ok(Self::finalize(vocab, byte_tokens))
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
            let b0 = bytes[pos];
            let mut matched = None;
            for &id in &self.buckets[b0 as usize] {
                let raw = self.vocab[id].raw.as_slice();
                if pos + raw.len() <= bytes.len() && &bytes[pos..pos + raw.len()] == raw {
                    matched = Some((id, raw.len()));
                    break;
                }
            }

            if let Some((id, len)) = matched {
                ids.push(id);
                pos += len;
            } else if let Some(bid) = self.byte_tokens[b0 as usize] {
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
            &self.vocab[id].display
        }
    }
}
