//! FIPS 180-4 SHA-256 & Base64 Decoder (`no_std`, pure Rust).

use alloc::vec::Vec;

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    bit_len: u64,
    buf: [u8; 64],
    buf_len: usize,
}

impl Sha256 {
    pub const fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ],
            bit_len: 0,
            buf: [0; 64],
            buf_len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        for &b in data {
            self.buf[self.buf_len] = b;
            self.buf_len += 1;
            self.bit_len = self.bit_len.wrapping_add(8);
            if self.buf_len == 64 {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let total_bits = self.bit_len;
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;
        if self.buf_len > 56 {
            while self.buf_len < 64 {
                self.buf[self.buf_len] = 0;
                self.buf_len += 1;
            }
            let block = self.buf;
            self.compress(&block);
            self.buf_len = 0;
        }
        while self.buf_len < 56 {
            self.buf[self.buf_len] = 0;
            self.buf_len += 1;
        }
        self.buf[56..64].copy_from_slice(&total_bits.to_be_bytes());
        let block = self.buf;
        self.compress(&block);

        let mut out = [0u8; 32];
        for (i, w) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

/// RFC 2104 / RFC 4231 HMAC-SHA256.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k_block = [0u8; 64];
    if key.len() > 64 {
        let kh = sha256(key);
        k_block[..32].copy_from_slice(&kh);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k_block[i];
        opad[i] ^= k_block[i];
    }

    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize()
}

/// RFC 2898 / RFC 8018 PBKDF2-HMAC-SHA256 producing a 32-byte derived key (`dkLen = 32`, block 1).
pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let iters = iterations.max(1);
    let mut msg = Vec::with_capacity(salt.len() + 4);
    msg.extend_from_slice(salt);
    msg.extend_from_slice(&1u32.to_be_bytes());

    let mut u = hmac_sha256(password, &msg);
    let mut t = u;
    for _ in 1..iters {
        u = hmac_sha256(password, &u);
        for i in 0..32 {
            t[i] ^= u[i];
        }
    }
    t
}

pub fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

pub fn constant_time_slice_eq(a: &[u8], b: &[u8]) -> bool {
    let min_len = a.len().min(b.len());
    let mut diff = a.len() ^ b.len();
    for i in 0..min_len {
        diff |= (a[i] ^ b[i]) as usize;
    }
    diff == 0
}

pub fn decode_base64(input: &[u8]) -> Option<Vec<u8>> {
    fn val(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let trimmed: Vec<u8> = input
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if trimmed.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity((trimmed.len() / 4) * 3);
    for chunk in trimmed.chunks_exact(4) {
        let a = val(chunk[0])?;
        let b = val(chunk[1])?;
        out.push((a << 2) | (b >> 4));
        if chunk[2] != b'=' {
            let c = val(chunk[2])?;
            out.push((b << 4) | (c >> 2));
            if chunk[3] != b'=' {
                let d = val(chunk[3])?;
                out.push((c << 6) | d);
            }
        }
    }
    Some(out)
}

/// Standard IEEE 802.3 CRC-32 (polynomial 0xEDB88320 reflected).
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

