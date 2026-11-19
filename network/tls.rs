//! Pure `no_std` Rust TLS 1.3 Server (`TLS_CHACHA20_POLY1305_SHA256`).
//!
//! Implements RFC 8446 TLS 1.3 with:
//! - FIPS 180-4 SHA-512 (for Ed25519)
//! - RFC 5869 / RFC 8446 HKDF-SHA256 & Key Schedule
//! - RFC 8439 ChaCha20-Poly1305 AEAD
//! - RFC 7748 X25519 ECDHE key exchange
//! - RFC 8032 Ed25519 signatures + minimal DER X.509 v3 self-signed certificate
//!
//! Verified on every boot against RFC test vectors in `self_test()`.

use alloc::vec::Vec;
use core::convert::TryInto;

use crate::arch::timer;
use crate::network::{self, tcp::TcpState};
use crate::scheduler;
use crate::security::csprng;
use crate::security::sha256::{constant_time_slice_eq, hmac_sha256, sha256, Sha256};

pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
const TLS_NAMED_GROUP_X25519: u16 = 0x001d;
const TLS_SIG_ED25519: u16 = 0x0807;

// ============================================================================
// 1. HKDF-SHA256 (RFC 5869 & RFC 8446 Section 7.1)
// ============================================================================

pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let zero_salt = [0u8; 32];
    let s = if salt.is_empty() { &zero_salt[..] } else { salt };
    hmac_sha256(s, ikm)
}

pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], out: &mut [u8]) {
    let mut t = [0u8; 32];
    let mut t_len = 0usize;
    let mut pos = 0usize;
    let mut counter = 1u8;
    while pos < out.len() {
        let mut msg = Vec::with_capacity(t_len + info.len() + 1);
        msg.extend_from_slice(&t[..t_len]);
        msg.extend_from_slice(info);
        msg.push(counter);
        t = hmac_sha256(prk, &msg);
        t_len = 32;
        let take = (out.len() - pos).min(32);
        out[pos..pos + take].copy_from_slice(&t[..take]);
        pos += take;
        counter = counter.wrapping_add(1);
    }
}

pub fn hkdf_expand_label(secret: &[u8; 32], label: &[u8], context: &[u8], out: &mut [u8]) {
    let full_label_len = 6 + label.len();
    let mut info = Vec::with_capacity(4 + full_label_len + context.len());
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info.push(full_label_len as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hkdf_expand(secret, &info, out);
}

fn derive_secret(secret: &[u8; 32], label: &[u8], transcript_hash: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    hkdf_expand_label(secret, label, transcript_hash, &mut out);
    out
}

// ============================================================================
// 2. ChaCha20-Poly1305 AEAD (RFC 8439)
// ============================================================================

#[inline]
fn qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(7);
}

fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];
    state[0] = 0x6170_7865;
    state[1] = 0x3320_646e;
    state[2] = 0x7962_2d32;
    state[3] = 0x6b20_6574;
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
    }
    state[12] = counter;
    state[13] = u32::from_le_bytes(nonce[0..4].try_into().unwrap());
    state[14] = u32::from_le_bytes(nonce[4..8].try_into().unwrap());
    state[15] = u32::from_le_bytes(nonce[8..12].try_into().unwrap());

    let mut work = state;
    for _ in 0..10 {
        qr(&mut work, 0, 4, 8, 12);
        qr(&mut work, 1, 5, 9, 13);
        qr(&mut work, 2, 6, 10, 14);
        qr(&mut work, 3, 7, 11, 15);
        qr(&mut work, 0, 5, 10, 15);
        qr(&mut work, 1, 6, 11, 12);
        qr(&mut work, 2, 7, 8, 13);
        qr(&mut work, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for i in 0..16 {
        let w = work[i].wrapping_add(state[i]);
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

fn chacha20_xor(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    let mut ctr = counter;
    for chunk in data.chunks_mut(64) {
        let ks = chacha20_block(key, ctr, nonce);
        for i in 0..chunk.len() {
            chunk[i] ^= ks[i];
        }
        ctr = ctr.wrapping_add(1);
    }
}

fn poly1305_mac(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    let mut r_bytes = [0u8; 16];
    r_bytes.copy_from_slice(&key[0..16]);
    r_bytes[3] &= 15;
    r_bytes[7] &= 15;
    r_bytes[11] &= 15;
    r_bytes[15] &= 15;
    r_bytes[4] &= 252;
    r_bytes[8] &= 252;
    r_bytes[12] &= 252;

    let t0 = u32::from_le_bytes(r_bytes[0..4].try_into().unwrap()) as u64;
    let t1 = u32::from_le_bytes(r_bytes[4..8].try_into().unwrap()) as u64;
    let t2 = u32::from_le_bytes(r_bytes[8..12].try_into().unwrap()) as u64;
    let t3 = u32::from_le_bytes(r_bytes[12..16].try_into().unwrap()) as u64;

    let r0 = (t0 & 0x3ffffff) as u128;
    let r1 = (((t0 >> 26) | (t1 << 6)) & 0x3ffffff) as u128;
    let r2 = (((t1 >> 20) | (t2 << 12)) & 0x3ffffff) as u128;
    let r3 = (((t2 >> 14) | (t3 << 18)) & 0x3ffffff) as u128;
    let r4 = (t3 >> 8) as u128;

    let s1 = r1 * 5;
    let s2 = r2 * 5;
    let s3 = r3 * 5;
    let s4 = r4 * 5;

    let (mut h0, mut h1, mut h2, mut h3, mut h4) = (0u128, 0u128, 0u128, 0u128, 0u128);

    for chunk in msg.chunks(16) {
        let mut blk = [0u8; 17];
        blk[..chunk.len()].copy_from_slice(chunk);
        blk[chunk.len()] = 1;

        let b0 = u32::from_le_bytes(blk[0..4].try_into().unwrap()) as u128;
        let b1 = u32::from_le_bytes(blk[4..8].try_into().unwrap()) as u128;
        let b2 = u32::from_le_bytes(blk[8..12].try_into().unwrap()) as u128;
        let b3 = u32::from_le_bytes(blk[12..16].try_into().unwrap()) as u128;
        let hibit = (blk[16] as u128) << 24;

        h0 += b0 & 0x3ffffff;
        h1 += ((b0 >> 26) | (b1 << 6)) & 0x3ffffff;
        h2 += ((b1 >> 20) | (b2 << 12)) & 0x3ffffff;
        h3 += ((b2 >> 14) | (b3 << 18)) & 0x3ffffff;
        h4 += (b3 >> 8) | hibit;

        let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        let mut d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        let mut d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        let mut d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        let mut d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

        let mut c = d0 >> 26;
        h0 = d0 & 0x3ffffff;
        d1 += c;
        c = d1 >> 26;
        h1 = d1 & 0x3ffffff;
        d2 += c;
        c = d2 >> 26;
        h2 = d2 & 0x3ffffff;
        d3 += c;
        c = d3 >> 26;
        h3 = d3 & 0x3ffffff;
        d4 += c;
        c = d4 >> 26;
        h4 = d4 & 0x3ffffff;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= 0x3ffffff;
        h1 += c;
    }

    let mut c = h1 >> 26;
    h1 &= 0x3ffffff;
    h2 += c;
    c = h2 >> 26;
    h2 &= 0x3ffffff;
    h3 += c;
    c = h3 >> 26;
    h3 &= 0x3ffffff;
    h4 += c;
    c = h4 >> 26;
    h4 &= 0x3ffffff;
    h0 += c * 5;
    c = h0 >> 26;
    h0 &= 0x3ffffff;
    h1 += c;

    let mut g0 = h0 + 5;
    c = g0 >> 26;
    g0 &= 0x3ffffff;
    let mut g1 = h1 + c;
    c = g1 >> 26;
    g1 &= 0x3ffffff;
    let mut g2 = h2 + c;
    c = g2 >> 26;
    g2 &= 0x3ffffff;
    let mut g3 = h3 + c;
    c = g3 >> 26;
    g3 &= 0x3ffffff;
    let g4 = h4 + c - (1 << 26);

    let borrow = ((g4 as i64) < 0) as u128;
    let keep_g = borrow.wrapping_sub(1); // all 1s if no borrow, 0 if borrow
    let keep_h = !keep_g;
    h0 = (h0 & keep_h) | (g0 & keep_g);
    h1 = (h1 & keep_h) | (g1 & keep_g);
    h2 = (h2 & keep_h) | (g2 & keep_g);
    h3 = (h3 & keep_h) | (g3 & keep_g);
    h4 = (h4 & keep_h) | (g4 & keep_g);

    let f0 = (h0 | (h1 << 26)) & 0xffffffff;
    let f1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff;
    let f2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
    let f3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff;

    let s0 = u32::from_le_bytes(key[16..20].try_into().unwrap()) as u128;
    let s1 = u32::from_le_bytes(key[20..24].try_into().unwrap()) as u128;
    let s2 = u32::from_le_bytes(key[24..28].try_into().unwrap()) as u128;
    let s3 = u32::from_le_bytes(key[28..32].try_into().unwrap()) as u128;

    let w0 = f0 + s0;
    let w1 = f1 + s1 + (w0 >> 32);
    let w2 = f2 + s2 + (w1 >> 32);
    let w3 = f3 + s3 + (w2 >> 32);

    let mut tag = [0u8; 16];
    tag[0..4].copy_from_slice(&(w0 as u32).to_le_bytes());
    tag[4..8].copy_from_slice(&(w1 as u32).to_le_bytes());
    tag[8..12].copy_from_slice(&(w2 as u32).to_le_bytes());
    tag[12..16].copy_from_slice(&(w3 as u32).to_le_bytes());
    tag
}

fn poly1305_aead_tag(otk: &[u8; 32], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    let mut mac_in = Vec::with_capacity(aad.len() + ct.len() + 48);
    mac_in.extend_from_slice(aad);
    let aad_pad = (16 - (aad.len() % 16)) % 16;
    mac_in.resize(mac_in.len() + aad_pad, 0);
    mac_in.extend_from_slice(ct);
    let ct_pad = (16 - (ct.len() % 16)) % 16;
    mac_in.resize(mac_in.len() + ct_pad, 0);
    mac_in.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac_in.extend_from_slice(&(ct.len() as u64).to_le_bytes());
    poly1305_mac(otk, &mac_in)
}

pub fn chacha20_poly1305_seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let blk0 = chacha20_block(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&blk0[..32]);
    let mut out = Vec::from(plaintext);
    chacha20_xor(key, 1, nonce, &mut out);
    let tag = poly1305_aead_tag(&otk, aad, &out);
    csprng::zeroize_bytes(&mut otk);
    out.extend_from_slice(&tag);
    out
}

pub fn chacha20_poly1305_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ct_and_tag: &[u8],
) -> Option<Vec<u8>> {
    if ct_and_tag.len() < 16 {
        return None;
    }
    let ct_len = ct_and_tag.len() - 16;
    let ct = &ct_and_tag[..ct_len];
    let tag = &ct_and_tag[ct_len..];
    let blk0 = chacha20_block(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&blk0[..32]);
    let expected = poly1305_aead_tag(&otk, aad, ct);
    csprng::zeroize_bytes(&mut otk);
    if !constant_time_slice_eq(&expected, tag) {
        return None;
    }
    let mut pt = Vec::from(ct);
    chacha20_xor(key, 1, nonce, &mut pt);
    Some(pt)
}

fn tls_nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut n = *iv;
    let sb = seq.to_be_bytes();
    for i in 0..8 {
        n[4 + i] ^= sb[i];
    }
    n
}

// ============================================================================
// 3. FIPS 180-4 SHA-512 (required for RFC 8032 Ed25519)
// ============================================================================

const K512: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut h: [u64; 8] = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    ];
    let bit_len = (data.len() as u128) * 8;
    let mut msg = Vec::from(data);
    msg.push(0x80);
    while (msg.len() % 128) != 112 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for blk in msg.chunks_exact(128) {
        let mut w = [0u64; 80];
        for i in 0..16 {
            w[i] = u64::from_be_bytes(blk[i * 8..i * 8 + 8].try_into().unwrap());
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K512[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 64];
    for (i, w) in h.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&w.to_be_bytes());
    }
    out
}

// ============================================================================
// 4. Curve25519 GF(2^255 - 19), X25519 (RFC 7748), & Ed25519 (RFC 8032)
// ============================================================================

type Fe = [i64; 16];
const FE_ZERO: Fe = [0; 16];
const FE_ONE: Fe = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const FE_121665: Fe = [0xdb41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const ED_D2: Fe = [
    0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
    0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406,
];
const ED_X: Fe = [
    0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
    0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169,
];
const ED_Y: Fe = [
    0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
];

fn fe_car(o: &mut Fe) {
    for i in 0..16 {
        o[i] += 1 << 16;
        let c = o[i] >> 16;
        let next = if i < 15 { i + 1 } else { 0 };
        let mul = if i == 15 { 38 } else { 1 };
        o[next] += (c - 1) * mul;
        o[i] -= c << 16;
    }
}

fn fe_sel(p: &mut Fe, q: &mut Fe, b: i64) {
    let c = !(b - 1);
    for i in 0..16 {
        let t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

fn fe_add(a: &Fe, b: &Fe) -> Fe {
    let mut o = [0i64; 16];
    for i in 0..16 {
        o[i] = a[i] + b[i];
    }
    o
}

fn fe_sub(a: &Fe, b: &Fe) -> Fe {
    let mut o = [0i64; 16];
    for i in 0..16 {
        o[i] = a[i] - b[i];
    }
    o
}

fn fe_mul(a: &Fe, b: &Fe) -> Fe {
    let mut t = [0i64; 31];
    for i in 0..16 {
        for j in 0..16 {
            t[i + j] += a[i] * b[j];
        }
    }
    for i in 0..15 {
        t[i] += 38 * t[i + 16];
    }
    let mut o = [0i64; 16];
    o.copy_from_slice(&t[..16]);
    fe_car(&mut o);
    fe_car(&mut o);
    o
}

fn fe_sq(a: &Fe) -> Fe {
    fe_mul(a, a)
}

fn fe_inv(a: &Fe) -> Fe {
    let mut c = *a;
    for i in (0..=253).rev() {
        c = fe_sq(&c);
        if i != 2 && i != 4 {
            c = fe_mul(&c, a);
        }
    }
    c
}

fn fe_unpack(n: &[u8; 32]) -> Fe {
    let mut o = [0i64; 16];
    for i in 0..16 {
        o[i] = (n[2 * i] as i64) + ((n[2 * i + 1] as i64) << 8);
    }
    o[15] &= 0x7fff;
    o
}

fn fe_pack(n: &Fe) -> [u8; 32] {
    let mut t = *n;
    fe_car(&mut t);
    fe_car(&mut t);
    fe_car(&mut t);
    let mut m = [0i64; 16];
    for _ in 0..2 {
        m[0] = t[0] - 0xffed;
        for i in 1..15 {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        let b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        fe_sel(&mut t, &mut m, 1 - b);
    }
    let mut o = [0u8; 32];
    for i in 0..16 {
        o[2 * i] = (t[i] & 0xff) as u8;
        o[2 * i + 1] = (t[i] >> 8) as u8;
    }
    o
}

pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let mut z = *scalar;
    z[0] &= 248;
    z[31] &= 127;
    z[31] |= 64;

    let x = fe_unpack(point);
    let mut a = FE_ONE;
    let mut b = x;
    let mut c = FE_ZERO;
    let mut d = FE_ONE;

    for i in (0..=254).rev() {
        let r = ((z[i >> 3] >> (i & 7)) & 1) as i64;
        fe_sel(&mut a, &mut b, r);
        fe_sel(&mut c, &mut d, r);
        let e = fe_add(&a, &c);
        a = fe_sub(&a, &c);
        c = fe_add(&b, &d);
        b = fe_sub(&b, &d);
        d = fe_sq(&e);
        let f = fe_sq(&a);
        a = fe_mul(&c, &a);
        c = fe_mul(&b, &e);
        let e2 = fe_add(&a, &c);
        a = fe_sub(&a, &c);
        b = fe_sq(&a);
        c = fe_sub(&d, &f);
        a = fe_mul(&c, &FE_121665);
        a = fe_add(&a, &d);
        c = fe_mul(&c, &a);
        a = fe_mul(&d, &f);
        d = fe_mul(&b, &x);
        b = fe_sq(&e2);
        fe_sel(&mut a, &mut b, r);
        fe_sel(&mut c, &mut d, r);
    }
    let inv_c = fe_inv(&c);
    fe_pack(&fe_mul(&a, &inv_c))
}

pub fn x25519_public_key(sk: &[u8; 32]) -> [u8; 32] {
    let mut base = [0u8; 32];
    base[0] = 9;
    x25519(sk, &base)
}

// Ed25519 extended point `[X, Y, Z, T]`
fn ed_add(p: &mut [Fe; 4], q: &[Fe; 4]) {
    let mut a = fe_sub(&p[1], &p[0]);
    let t = fe_sub(&q[1], &q[0]);
    a = fe_mul(&a, &t);
    let mut b = fe_add(&p[0], &p[1]);
    let t = fe_add(&q[0], &q[1]);
    b = fe_mul(&b, &t);
    let mut c = fe_mul(&p[3], &q[3]);
    c = fe_mul(&c, &ED_D2);
    let mut d = fe_mul(&p[2], &q[2]);
    d = fe_add(&d, &d);
    let e = fe_sub(&b, &a);
    let f = fe_sub(&d, &c);
    let g = fe_add(&d, &c);
    let h = fe_add(&b, &a);
    p[0] = fe_mul(&e, &f);
    p[1] = fe_mul(&h, &g);
    p[2] = fe_mul(&g, &f);
    p[3] = fe_mul(&e, &h);
}

fn ed_cswap(p: &mut [Fe; 4], q: &mut [Fe; 4], b: i64) {
    for i in 0..4 {
        fe_sel(&mut p[i], &mut q[i], b);
    }
}

fn ed_scalarmult(q: &[Fe; 4], s: &[u8; 32]) -> [Fe; 4] {
    let mut p = [FE_ZERO, FE_ONE, FE_ONE, FE_ZERO];
    let mut qb = *q;
    for i in (0..=255).rev() {
        let b = ((s[i >> 3] >> (i & 7)) & 1) as i64;
        ed_cswap(&mut p, &mut qb, b);
        ed_add(&mut qb, &p);
        let p_copy = p;
        ed_add(&mut p, &p_copy);
        ed_cswap(&mut p, &mut qb, b);
    }
    p
}

fn ed_scalarbase(s: &[u8; 32]) -> [Fe; 4] {
    let q = [ED_X, ED_Y, FE_ONE, fe_mul(&ED_X, &ED_Y)];
    ed_scalarmult(&q, s)
}

fn ed_pack(p: &[Fe; 4]) -> [u8; 32] {
    let zi = fe_inv(&p[2]);
    let tx = fe_mul(&p[0], &zi);
    let ty = fe_mul(&p[1], &zi);
    let mut r = fe_pack(&ty);
    let par = fe_pack(&tx)[0] & 1;
    r[31] ^= par << 7;
    r
}

const ED_L: [u64; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

fn mod_l(r: &mut [u8; 32], x: &mut [i64; 64]) {
    for i in (32..=63).rev() {
        let mut carry = 0i64;
        for j in (i - 32)..(i - 12) {
            x[j] += carry - 16 * x[i] * (ED_L[j - (i - 32)] as i64);
            carry = (x[j] + 128) >> 8;
            x[j] -= carry << 8;
        }
        x[i - 12] += carry;
        x[i] = 0;
    }
    let mut carry = 0i64;
    for j in 0..32 {
        x[j] += carry - (x[31] >> 4) * (ED_L[j] as i64);
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for j in 0..32 {
        x[j] -= carry * (ED_L[j] as i64);
    }
    for i in 0..32 {
        x[i + 1] += x[i] >> 8;
        r[i] = (x[i] & 255) as u8;
    }
}

fn reduce_mod_l(r: &[u8; 64]) -> [u8; 32] {
    let mut x = [0i64; 64];
    for i in 0..64 {
        x[i] = r[i] as i64;
    }
    let mut out = [0u8; 32];
    mod_l(&mut out, &mut x);
    out
}

pub fn ed25519_public_key(seed: &[u8; 32]) -> [u8; 32] {
    let mut d = sha512(seed);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;
    let s: [u8; 32] = d[..32].try_into().unwrap();
    ed_pack(&ed_scalarbase(&s))
}

pub fn ed25519_sign(seed: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    let mut d = sha512(seed);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;
    let a: [u8; 32] = d[..32].try_into().unwrap();
    let pk = ed_pack(&ed_scalarbase(&a));

    let mut r_in = Vec::with_capacity(32 + msg.len());
    r_in.extend_from_slice(&d[32..64]);
    r_in.extend_from_slice(msg);
    let r = reduce_mod_l(&sha512(&r_in));
    let r_pt = ed_pack(&ed_scalarbase(&r));

    let mut h_in = Vec::with_capacity(64 + msg.len());
    h_in.extend_from_slice(&r_pt);
    h_in.extend_from_slice(&pk);
    h_in.extend_from_slice(msg);
    let h = reduce_mod_l(&sha512(&h_in));

    let mut x = [0i64; 64];
    for i in 0..32 {
        x[i] = r[i] as i64;
    }
    for i in 0..32 {
        for j in 0..32 {
            x[i + j] += (h[i] as i64) * (a[j] as i64);
        }
    }
    let mut s_out = [0u8; 32];
    mod_l(&mut s_out, &mut x);

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r_pt);
    sig[32..].copy_from_slice(&s_out);
    sig
}

// ============================================================================
// 5. Minimal DER X.509 v3 Self-Signed Ed25519 Certificate Builder
// ============================================================================

fn der_len(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xff) as u8);
    }
}

fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 4);
    out.push(tag);
    der_len(body.len(), &mut out);
    out.extend_from_slice(body);
    out
}

fn der_seq(items: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    for it in items {
        body.extend_from_slice(it);
    }
    der_tlv(0x30, &body)
}

fn der_set(items: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    for it in items {
        body.extend_from_slice(it);
    }
    der_tlv(0x31, &body)
}

pub fn build_self_signed_ed25519_cert(seed: &[u8; 32], pk: &[u8; 32]) -> Vec<u8> {
    let alg_ed25519 = der_seq(&[der_tlv(0x06, &[0x2b, 0x65, 0x70])]); // OID 1.3.101.112
    let version = der_tlv(0xa0, &der_tlv(0x02, &[0x02])); // v3
    let serial = der_tlv(0x02, &[0x01, 0x4e, 0x58, 0x01]);
    let cn_name = der_seq(&[der_set(&[der_seq(&[
        der_tlv(0x06, &[0x55, 0x04, 0x03]), // CN
        der_tlv(0x0c, b"nexos.local"),
    ])])]);
    let validity = der_seq(&[
        der_tlv(0x17, b"260101000000Z"),
        der_tlv(0x17, b"360101000000Z"),
    ]);
    let mut pk_bits = Vec::with_capacity(33);
    pk_bits.push(0x00); // unused bits = 0
    pk_bits.extend_from_slice(pk);
    let spki = der_seq(&[alg_ed25519.clone(), der_tlv(0x03, &pk_bits)]);

    // Extensions: BasicConstraints(CA:TRUE), SAN(DNS:nexos.local, IP:10.0.2.15, IP:10.77.0.2, IP:127.0.0.1)
    let bc = der_seq(&[
        der_tlv(0x06, &[0x55, 0x1d, 0x13]),
        der_tlv(0x01, &[0xff]),
        der_tlv(0x04, &der_seq(&[der_tlv(0x01, &[0xff])])),
    ]);
    let san_val = der_seq(&[
        der_tlv(0x82, b"nexos.local"),
        der_tlv(0x87, &[10, 0, 2, 15]),
        der_tlv(0x87, &[10, 77, 0, 2]),
        der_tlv(0x87, &[127, 0, 0, 1]),
    ]);
    let san = der_seq(&[
        der_tlv(0x06, &[0x55, 0x1d, 0x11]),
        der_tlv(0x04, &san_val),
    ]);
    let exts = der_tlv(0xa3, &der_seq(&[bc, san]));

    let tbs = der_seq(&[
        version,
        serial,
        alg_ed25519.clone(),
        cn_name.clone(),
        validity,
        cn_name,
        spki,
        exts,
    ]);

    let sig = ed25519_sign(seed, &tbs);
    let mut sig_bits = Vec::with_capacity(65);
    sig_bits.push(0x00);
    sig_bits.extend_from_slice(&sig);

    der_seq(&[tbs, alg_ed25519, der_tlv(0x03, &sig_bits)])
}

// ============================================================================
// 6. RFC 8446 TLS 1.3 Server State Machine
// ============================================================================

struct ServerIdentity {
    ed_seed: [u8; 32],
    cert_der: Vec<u8>,
}

static SERVER_ID: crate::sync::SpinLock<Option<ServerIdentity>> =
    crate::sync::SpinLock::new(None);

fn ensure_server_identity() -> Option<([u8; 32], Vec<u8>)> {
    let mut guard = SERVER_ID.lock();
    if let Some(id) = guard.as_ref() {
        return Some((id.ed_seed, id.cert_der.clone()));
    }
    let mut ed_seed = [0u8; 32];
    csprng::fill_bytes(&mut ed_seed).ok()?;
    let pk = ed25519_public_key(&ed_seed);
    let cert_der = build_self_signed_ed25519_cert(&ed_seed, &pk);
    *guard = Some(ServerIdentity {
        ed_seed,
        cert_der: cert_der.clone(),
    });
    Some((ed_seed, cert_der))
}

pub struct TlsServerConn {
    sock: usize,
    client_app_key: [u8; 32],
    client_app_iv: [u8; 12],
    client_seq: u64,
    server_app_key: [u8; 32],
    server_app_iv: [u8; 12],
    server_seq: u64,
    rx_buf: Vec<u8>,
}

impl Drop for TlsServerConn {
    fn drop(&mut self) {
        csprng::zeroize_bytes(&mut self.client_app_key);
        csprng::zeroize_bytes(&mut self.client_app_iv);
        csprng::zeroize_bytes(&mut self.server_app_key);
        csprng::zeroize_bytes(&mut self.server_app_iv);
    }
}

fn tcp_read_exact_timeout(sock: usize, rx: &mut Vec<u8>, min_len: usize, timeout_ms: u64) -> bool {
    let deadline = timer::uptime_ms() + timeout_ms;
    let mut tmp = [0u8; 2048];
    while rx.len() < min_len && timer::uptime_ms() < deadline {
        let n = network::tcp_recv(sock, &mut tmp);
        if n > 0 {
            rx.extend_from_slice(&tmp[..n]);
            continue;
        }
        if matches!(
            network::tcp_state(sock),
            None | Some(TcpState::Closed | TcpState::CloseWait)
        ) {
            break;
        }
        scheduler::sleep_ms(5);
    }
    rx.len() >= min_len
}

fn read_tls_record(sock: usize, rx: &mut Vec<u8>, timeout_ms: u64) -> Option<(u8, Vec<u8>)> {
    if !tcp_read_exact_timeout(sock, rx, 5, timeout_ms) {
        return None;
    }
    let rtype = rx[0];
    let rlen = u16::from_be_bytes([rx[3], rx[4]]) as usize;
    if rlen > 16640 || !tcp_read_exact_timeout(sock, rx, 5 + rlen, timeout_ms) {
        return None;
    }
    let payload = rx[5..5 + rlen].to_vec();
    rx.drain(..5 + rlen);
    Some((rtype, payload))
}

fn send_tls_record(sock: usize, rtype: u8, payload: &[u8]) {
    let mut rec = Vec::with_capacity(5 + payload.len());
    rec.push(rtype);
    rec.extend_from_slice(&[0x03, 0x03]);
    rec.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    rec.extend_from_slice(payload);
    for chunk in rec.chunks(1400) {
        network::tcp_send(sock, chunk);
    }
}

fn send_encrypted_record(
    sock: usize,
    key: &[u8; 32],
    iv: &[u8; 12],
    seq: &mut u64,
    inner_type: u8,
    content: &[u8],
) -> bool {
    if *seq == u64::MAX {
        return false;
    }
    let mut pt = Vec::with_capacity(content.len() + 1);
    pt.extend_from_slice(content);
    pt.push(inner_type);
    let ct_len = pt.len() + 16;
    let aad = [0x17u8, 0x03, 0x03, (ct_len >> 8) as u8, (ct_len & 0xff) as u8];
    let nonce = tls_nonce(iv, *seq);
    *seq += 1;
    let ct = chacha20_poly1305_seal(key, &nonce, &aad, &pt);
    csprng::zeroize_bytes(&mut pt);
    send_tls_record(sock, 0x17, &ct);
    true
}

fn recv_encrypted_record(
    sock: usize,
    rx: &mut Vec<u8>,
    key: &[u8; 32],
    iv: &[u8; 12],
    seq: &mut u64,
    timeout_ms: u64,
) -> Option<(u8, Vec<u8>)> {
    loop {
        if *seq == u64::MAX {
            return None;
        }
        let (rtype, payload) = read_tls_record(sock, rx, timeout_ms)?;
        if rtype == 0x14 {
            // Skip middlebox ChangeCipherSpec
            continue;
        }
        if rtype == 0x15 {
            // Unencrypted alert
            return None;
        }
        if rtype != 0x17 {
            return None;
        }
        let aad = [
            0x17u8,
            0x03,
            0x03,
            (payload.len() >> 8) as u8,
            (payload.len() & 0xff) as u8,
        ];
        let nonce = tls_nonce(iv, *seq);
        *seq += 1;
        let mut pt = chacha20_poly1305_open(key, &nonce, &aad, &payload)?;
        while pt.last() == Some(&0) {
            pt.pop();
        }
        let inner = pt.pop()?;
        return Some((inner, pt));
    }
}

fn hs_msg(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(msg_type);
    let l = body.len();
    out.push(((l >> 16) & 0xff) as u8);
    out.push(((l >> 8) & 0xff) as u8);
    out.push((l & 0xff) as u8);
    out.extend_from_slice(body);
    out
}

fn parse_client_hello_body(body: &[u8]) -> Option<(&[u8], [u8; 32])> {
    if body.len() < 39 {
        return None;
    }
    let mut off = 2 + 32; // legacy_version + random
    let sid_len = body[off] as usize;
    off += 1;
    if sid_len > 32 || off + sid_len + 2 > body.len() {
        return None;
    }
    let legacy_sid = &body[off..off + sid_len];
    off += sid_len;

    let cs_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2;
    if cs_len < 2 || (cs_len % 2) != 0 || off + cs_len + 1 > body.len() {
        return None;
    }
    let has_chacha = body[off..off + cs_len]
        .chunks_exact(2)
        .any(|c| u16::from_be_bytes([c[0], c[1]]) == TLS_CHACHA20_POLY1305_SHA256);
    if !has_chacha {
        return None;
    }
    off += cs_len;
    let comp_len = body[off] as usize;
    off += 1;
    if comp_len == 0 || off + comp_len + 2 > body.len() {
        return None;
    }
    off += comp_len;
    let ext_total = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2;
    if off + ext_total != body.len() {
        return None;
    }
    let exts = &body[off..off + ext_total];

    let mut supports_tls13 = false;
    let mut client_x25519: Option<[u8; 32]> = None;
    let mut eoff = 0usize;
    while eoff < exts.len() {
        if eoff + 4 > exts.len() {
            return None;
        }
        let etype = u16::from_be_bytes([exts[eoff], exts[eoff + 1]]);
        let elen = u16::from_be_bytes([exts[eoff + 2], exts[eoff + 3]]) as usize;
        eoff += 4;
        if eoff + elen > exts.len() {
            return None;
        }
        let edata = &exts[eoff..eoff + elen];
        if etype == 0x002b && !edata.is_empty() {
            // supported_versions
            let vlen = edata[0] as usize;
            if 1 + vlen == edata.len() && (vlen % 2) == 0 {
                supports_tls13 = edata[1..1 + vlen]
                    .chunks_exact(2)
                    .any(|v| v == [0x03, 0x04]);
            }
        } else if etype == 0x0033 && edata.len() >= 2 {
            // key_share
            let ks_len = u16::from_be_bytes([edata[0], edata[1]]) as usize;
            if 2 + ks_len == edata.len() {
                let mut k = 2usize;
                while k + 4 <= edata.len() {
                    let grp = u16::from_be_bytes([edata[k], edata[k + 1]]);
                    let klen = u16::from_be_bytes([edata[k + 2], edata[k + 3]]) as usize;
                    k += 4;
                    if k + klen > edata.len() {
                        return None;
                    }
                    if grp == TLS_NAMED_GROUP_X25519 && klen == 32 {
                        let mut pk = [0u8; 32];
                        pk.copy_from_slice(&edata[k..k + 32]);
                        client_x25519 = Some(pk);
                    }
                    k += klen;
                }
            }
        }
        eoff += elen;
    }

    let client_pk = client_x25519?;
    if !supports_tls13 {
        return None;
    }
    Some((legacy_sid, client_pk))
}

impl TlsServerConn {
    /// Perform RFC 8446 TLS 1.3 handshake on an accepted TCP socket `sock`.
    pub fn handshake_accept(sock: usize) -> Option<Self> {
        let mut rx = Vec::new();
        let (rtype, ch_record) = read_tls_record(sock, &mut rx, 1500)?;
        if rtype != 0x16 || ch_record.len() < 42 || ch_record[0] != 0x01 {
            return None;
        }
        let ch_len = ((ch_record[1] as usize) << 16)
            | ((ch_record[2] as usize) << 8)
            | (ch_record[3] as usize);
        if 4 + ch_len != ch_record.len() {
            return None;
        }
        let ch_msg = &ch_record[..4 + ch_len];
        let (legacy_sid, client_pk) = parse_client_hello_body(&ch_msg[4..])?;

        // Ephemeral server X25519 key pair + shared secret (RFC 7748 all-zero check)
        let mut srv_x_sk = [0u8; 32];
        if csprng::fill_bytes(&mut srv_x_sk).is_err() {
            csprng::zeroize_bytes(&mut srv_x_sk);
            return None;
        }
        let srv_x_pk = x25519_public_key(&srv_x_sk);
        let mut shared = x25519(&srv_x_sk, &client_pk);
        csprng::zeroize_bytes(&mut srv_x_sk);
        if shared.iter().all(|&b| b == 0) {
            csprng::zeroize_bytes(&mut shared);
            return None;
        }

        // Build ServerHello
        let mut sh_rand = [0u8; 32];
        if csprng::fill_bytes(&mut sh_rand).is_err() {
            csprng::zeroize_bytes(&mut shared);
            return None;
        }
        let mut sh_body = Vec::with_capacity(128);
        sh_body.extend_from_slice(&[0x03, 0x03]); // legacy_version = TLS 1.2
        sh_body.extend_from_slice(&sh_rand);
        sh_body.push(legacy_sid.len() as u8);
        sh_body.extend_from_slice(legacy_sid);
        sh_body.extend_from_slice(&TLS_CHACHA20_POLY1305_SHA256.to_be_bytes());
        sh_body.push(0x00); // legacy_compression_method
        // Extensions: supported_versions (0x002b -> 0x0304) + key_share (0x0033 -> X25519 32B)
        let mut sh_exts = Vec::with_capacity(48);
        sh_exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
        sh_exts.extend_from_slice(&[0x00, 0x33, 0x00, 36, 0x00, 0x1d, 0x00, 32]);
        sh_exts.extend_from_slice(&srv_x_pk);
        sh_body.extend_from_slice(&(sh_exts.len() as u16).to_be_bytes());
        sh_body.extend_from_slice(&sh_exts);
        let sh_msg = hs_msg(0x02, &sh_body);

        let mut transcript = Sha256::new();
        transcript.update(ch_msg);
        transcript.update(&sh_msg);
        let th_sh = transcript.clone().finalize();

        // Send ServerHello + CCS (middlebox compat)
        send_tls_record(sock, 0x16, &sh_msg);
        send_tls_record(sock, 0x14, &[0x01]);

        // TLS 1.3 Key Schedule (handshake)
        let zeros = [0u8; 32];
        let empty_hash = sha256(&[]);
        let mut early_secret = hkdf_extract(&[], &zeros);
        let mut derived_early = derive_secret(&early_secret, b"derived", &empty_hash);
        let mut handshake_secret = hkdf_extract(&derived_early, &shared);
        csprng::zeroize_bytes(&mut shared);
        csprng::zeroize_bytes(&mut early_secret);
        csprng::zeroize_bytes(&mut derived_early);

        let mut client_hs_secret = derive_secret(&handshake_secret, b"c hs traffic", &th_sh);
        let mut server_hs_secret = derive_secret(&handshake_secret, b"s hs traffic", &th_sh);

        let mut srv_hs_key = [0u8; 32];
        let mut srv_hs_iv = [0u8; 12];
        let mut cli_hs_key = [0u8; 32];
        let mut cli_hs_iv = [0u8; 12];
        hkdf_expand_label(&server_hs_secret, b"key", &[], &mut srv_hs_key);
        hkdf_expand_label(&server_hs_secret, b"iv", &[], &mut srv_hs_iv);
        hkdf_expand_label(&client_hs_secret, b"key", &[], &mut cli_hs_key);
        hkdf_expand_label(&client_hs_secret, b"iv", &[], &mut cli_hs_iv);

        let mut srv_hs_seq = 0u64;
        let mut cli_hs_seq = 0u64;

        // 1. EncryptedExtensions
        let ee_msg = hs_msg(0x08, &[0x00, 0x00]);
        transcript.update(&ee_msg);

        // 2. Certificate
        let Some((mut ed_seed, cert_der)) = ensure_server_identity() else {
            csprng::zeroize_bytes(&mut handshake_secret);
            csprng::zeroize_bytes(&mut client_hs_secret);
            csprng::zeroize_bytes(&mut server_hs_secret);
            csprng::zeroize_bytes(&mut srv_hs_key);
            csprng::zeroize_bytes(&mut srv_hs_iv);
            csprng::zeroize_bytes(&mut cli_hs_key);
            csprng::zeroize_bytes(&mut cli_hs_iv);
            return None;
        };
        let entry_len = cert_der.len();
        let list_len = 3 + entry_len + 2;
        let mut cert_body = Vec::with_capacity(4 + list_len);
        cert_body.push(0x00); // certificate_request_context = empty
        cert_body.push(((list_len >> 16) & 0xff) as u8);
        cert_body.push(((list_len >> 8) & 0xff) as u8);
        cert_body.push((list_len & 0xff) as u8);
        cert_body.push(((entry_len >> 16) & 0xff) as u8);
        cert_body.push(((entry_len >> 8) & 0xff) as u8);
        cert_body.push((entry_len & 0xff) as u8);
        cert_body.extend_from_slice(&cert_der);
        cert_body.extend_from_slice(&[0x00, 0x00]); // cert_extensions = empty
        let cert_msg = hs_msg(0x0b, &cert_body);
        transcript.update(&cert_msg);
        let th_cert = transcript.clone().finalize();

        // 3. CertificateVerify (Ed25519)
        let mut cv_input = Vec::with_capacity(64 + 34 + 32);
        cv_input.resize(64, 0x20);
        cv_input.extend_from_slice(b"TLS 1.3, server CertificateVerify\x00");
        cv_input.extend_from_slice(&th_cert);
        let sig = ed25519_sign(&ed_seed, &cv_input);
        csprng::zeroize_bytes(&mut ed_seed);
        let mut cv_body = Vec::with_capacity(4 + 64);
        cv_body.extend_from_slice(&TLS_SIG_ED25519.to_be_bytes());
        cv_body.extend_from_slice(&(64u16).to_be_bytes());
        cv_body.extend_from_slice(&sig);
        let cv_msg = hs_msg(0x0f, &cv_body);
        transcript.update(&cv_msg);
        let th_cv = transcript.clone().finalize();

        // 4. Server Finished
        let mut srv_fin_key = [0u8; 32];
        hkdf_expand_label(&server_hs_secret, b"finished", &[], &mut srv_fin_key);
        let srv_verify = hmac_sha256(&srv_fin_key, &th_cv);
        csprng::zeroize_bytes(&mut srv_fin_key);
        csprng::zeroize_bytes(&mut server_hs_secret);
        let fin_msg = hs_msg(0x14, &srv_verify);
        transcript.update(&fin_msg);
        let th_srv_fin = transcript.clone().finalize();

        // Send all 4 server handshake messages inside encrypted handshake records
        let mut flight = Vec::with_capacity(ee_msg.len() + cert_msg.len() + cv_msg.len() + fin_msg.len());
        flight.extend_from_slice(&ee_msg);
        flight.extend_from_slice(&cert_msg);
        flight.extend_from_slice(&cv_msg);
        flight.extend_from_slice(&fin_msg);
        let sent_ok = send_encrypted_record(sock, &srv_hs_key, &srv_hs_iv, &mut srv_hs_seq, 0x16, &flight);
        csprng::zeroize_bytes(&mut srv_hs_key);
        csprng::zeroize_bytes(&mut srv_hs_iv);
        if !sent_ok {
            csprng::zeroize_bytes(&mut handshake_secret);
            csprng::zeroize_bytes(&mut client_hs_secret);
            csprng::zeroize_bytes(&mut cli_hs_key);
            csprng::zeroize_bytes(&mut cli_hs_iv);
            return None;
        }

        // Derive Application Traffic Keys (from transcript up through server Finished)
        let mut derived_hs = derive_secret(&handshake_secret, b"derived", &empty_hash);
        csprng::zeroize_bytes(&mut handshake_secret);
        let mut master_secret = hkdf_extract(&derived_hs, &zeros);
        csprng::zeroize_bytes(&mut derived_hs);
        let mut client_app_secret = derive_secret(&master_secret, b"c ap traffic", &th_srv_fin);
        let mut server_app_secret = derive_secret(&master_secret, b"s ap traffic", &th_srv_fin);
        csprng::zeroize_bytes(&mut master_secret);

        let mut client_app_key = [0u8; 32];
        let mut client_app_iv = [0u8; 12];
        let mut server_app_key = [0u8; 32];
        let mut server_app_iv = [0u8; 12];
        hkdf_expand_label(&client_app_secret, b"key", &[], &mut client_app_key);
        hkdf_expand_label(&client_app_secret, b"iv", &[], &mut client_app_iv);
        hkdf_expand_label(&server_app_secret, b"key", &[], &mut server_app_key);
        hkdf_expand_label(&server_app_secret, b"iv", &[], &mut server_app_iv);
        csprng::zeroize_bytes(&mut client_app_secret);
        csprng::zeroize_bytes(&mut server_app_secret);

        // Expect Client Finished
        let cli_res = recv_encrypted_record(sock, &mut rx, &cli_hs_key, &cli_hs_iv, &mut cli_hs_seq, 1500);
        csprng::zeroize_bytes(&mut cli_hs_key);
        csprng::zeroize_bytes(&mut cli_hs_iv);
        let Some((inner_type, cli_fin_rec)) = cli_res else {
            csprng::zeroize_bytes(&mut client_hs_secret);
            csprng::zeroize_bytes(&mut client_app_key);
            csprng::zeroize_bytes(&mut client_app_iv);
            csprng::zeroize_bytes(&mut server_app_key);
            csprng::zeroize_bytes(&mut server_app_iv);
            return None;
        };
        if inner_type != 0x16 || cli_fin_rec.len() != 36 || cli_fin_rec[0] != 0x14 {
            csprng::zeroize_bytes(&mut client_hs_secret);
            csprng::zeroize_bytes(&mut client_app_key);
            csprng::zeroize_bytes(&mut client_app_iv);
            csprng::zeroize_bytes(&mut server_app_key);
            csprng::zeroize_bytes(&mut server_app_iv);
            return None;
        }
        let mut cli_fin_key = [0u8; 32];
        hkdf_expand_label(&client_hs_secret, b"finished", &[], &mut cli_fin_key);
        csprng::zeroize_bytes(&mut client_hs_secret);
        let expected_cli_fin = hmac_sha256(&cli_fin_key, &th_srv_fin);
        csprng::zeroize_bytes(&mut cli_fin_key);
        if !constant_time_slice_eq(&cli_fin_rec[4..36], &expected_cli_fin) {
            csprng::zeroize_bytes(&mut client_app_key);
            csprng::zeroize_bytes(&mut client_app_iv);
            csprng::zeroize_bytes(&mut server_app_key);
            csprng::zeroize_bytes(&mut server_app_iv);
            return None;
        }

        Some(Self {
            sock,
            client_app_key,
            client_app_iv,
            client_seq: 0,
            server_app_key,
            server_app_iv,
            server_seq: 0,
            rx_buf: rx,
        })
    }

    pub fn read_app_data(&mut self, timeout_ms: u64) -> Option<Vec<u8>> {
        loop {
            let (inner, data) = recv_encrypted_record(
                self.sock,
                &mut self.rx_buf,
                &self.client_app_key,
                &self.client_app_iv,
                &mut self.client_seq,
                timeout_ms,
            )?;
            match inner {
                0x17 => return Some(data),
                0x16 => continue, // e.g., NewSessionTicket or KeyUpdate ignored
                _ => return None, // close_notify alert or unexpected
            }
        }
    }

    pub fn write_app_data(&mut self, data: &[u8]) {
        for chunk in data.chunks(16384) {
            if !send_encrypted_record(
                self.sock,
                &self.server_app_key,
                &self.server_app_iv,
                &mut self.server_seq,
                0x17,
                chunk,
            ) {
                break;
            }
        }
    }

    pub fn close(mut self) {
        // Send TLS 1.3 close_notify alert (level=1 warning, desc=0 close_notify)
        let _ = send_encrypted_record(
            self.sock,
            &self.server_app_key,
            &self.server_app_iv,
            &mut self.server_seq,
            0x15,
            &[1, 0],
        );
        scheduler::sleep_ms(15);
        network::tcp_close(self.sock);
    }
}

// ============================================================================
// 7. Cryptographic Boot Self-Test (NIST / RFC Test Vectors)
// ============================================================================

pub fn self_test() -> Result<(), &'static str> {
    // 1. SHA-512("abc") FIPS 180-4
    let h512 = sha512(b"abc");
    let exp512: [u8; 8] = [0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba];
    if h512[..8] != exp512 {
        return Err("SHA-512 vector mismatch");
    }

    // 2. HKDF-SHA256 RFC 5869 Test Case 1
    let ikm = [0x0bu8; 22];
    let salt: [u8; 13] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];
    let info: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
    let prk = hkdf_extract(&salt, &ikm);
    let mut okm = [0u8; 42];
    hkdf_expand(&prk, &info, &mut okm);
    if okm[..4] != [0x3c, 0xb2, 0x5f, 0x25] || okm[38..42] != [0x87, 0x18, 0x58, 0x65] {
        return Err("HKDF-SHA256 RFC 5869 mismatch");
    }

    // 3. ChaCha20-Poly1305 RFC 8439 Section 2.8.2
    let key: [u8; 32] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    ];
    let nonce: [u8; 12] = [0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47];
    let aad: [u8; 12] = [0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7];
    let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let ct_tag = chacha20_poly1305_seal(&key, &nonce, &aad, pt);
    let exp_tag: [u8; 16] = [
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
    ];
    if ct_tag[ct_tag.len() - 16..] != exp_tag {
        return Err("ChaCha20-Poly1305 tag mismatch");
    }
    if chacha20_poly1305_open(&key, &nonce, &aad, &ct_tag).as_deref() != Some(&pt[..]) {
        return Err("ChaCha20-Poly1305 open mismatch");
    }

    // 4. X25519 RFC 7748 Section 6.1
    let a_sk: [u8; 32] = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
    ];
    let a_pk = x25519_public_key(&a_sk);
    let exp_apk: [u8; 8] = [0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54];
    if a_pk[..8] != exp_apk {
        return Err("X25519 RFC 7748 mismatch");
    }

    // 5. Ed25519 RFC 8032 Section 7.1 TV1
    let ed_sk: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
    ];
    let ed_pk = ed25519_public_key(&ed_sk);
    let exp_edpk: [u8; 8] = [0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7];
    if ed_pk[..8] != exp_edpk {
        return Err("Ed25519 public key mismatch");
    }
    let ed_sig = ed25519_sign(&ed_sk, b"");
    let exp_sig0: [u8; 8] = [0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72];
    if ed_sig[..8] != exp_sig0 {
        return Err("Ed25519 RFC 8032 signature mismatch");
    }

    // 6. AEAD tamper rejection (flip 1 bit in ciphertext/tag -> must fail)
    let mut tampered = ct_tag;
    let tlen = tampered.len();
    tampered[tlen - 1] ^= 0x01;
    if chacha20_poly1305_open(&key, &nonce, &aad, &tampered).is_some() {
        return Err("ChaCha20-Poly1305 accepted tampered tag!");
    }

    // 7. RFC 7748 X25519 low-order all-zero point produces all-zero shared secret
    let low_order = [0u8; 32];
    if !x25519(&a_sk, &low_order).iter().all(|&b| b == 0) {
        return Err("X25519 zero-point check failed");
    }

    // 8. ClientHello malformed parser checks (odd cipher_suites len, sid_len > 32, truncated)
    let bad_sid = [0u8; 40];
    if parse_client_hello_body(&bad_sid).is_some() {
        return Err("Malformed ClientHello accepted (short/zero)");
    }
    let mut odd_cs = [0u8; 45];
    odd_cs[34] = 0; // sid_len=0
    odd_cs[35] = 0;
    odd_cs[36] = 3; // cs_len=3 (odd!)
    if parse_client_hello_body(&odd_cs).is_some() {
        return Err("Malformed ClientHello accepted (odd cipher_suites len)");
    }

    Ok(())
}
