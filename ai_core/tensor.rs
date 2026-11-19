//! Tensor Math & AArch64 NEON SIMD Kernels (`no_std`).
//!
//! Dispatches inner quantized Q8_0 matrix-vector multiplies and F32 dot products
//! to `arch/arm64/neon_gemv.S`, with scalar reference paths for boot verification.

use core::arch::asm;
use core::convert::TryInto;

use super::format::{Q8_BLOCK_BYTES, Q8_BLOCK_ELEMS};

#[inline(always)]
pub fn sqrtf(x: f32) -> f32 {
    if x <= 0.0 {
        return 0.0;
    }
    let out: f32;
    unsafe {
        asm!("fsqrt {:s}, {:s}", out(vreg) out, in(vreg) x, options(nomem, nostack, preserves_flags));
    }
    out
}

#[inline]
pub fn expf(x: f32) -> f32 {
    if x < -87.0 {
        return 0.0;
    }
    if x > 88.0 {
        return f32::from_bits(0x7F7F_FFFF);
    }
    // Range reduction: e^x = 2^k * e^r, |r| <= ln(2)/2
    const INV_LN2: f32 = 1.4426950408889634;
    const LN2_HI: f32 = 0.693145751953125;
    const LN2_LO: f32 = 1.4286068203094172e-6;

    let kf = (x * INV_LN2 + if x >= 0.0 { 0.5 } else { -0.5 }) as i32;
    let kf_f = kf as f32;
    let r = (x - kf_f * LN2_HI) - kf_f * LN2_LO;

    // 6th-order Taylor/minimax polynomial on [-0.347, 0.347]
    let poly = 1.0
        + r * (1.0
            + r * (0.5
                + r * (0.16666667
                    + r * (0.041666668 + r * (0.008333334 + r * 0.0013888889)))));

    let scale_bits = (((kf + 127).clamp(1, 254)) as u32) << 23;
    poly * f32::from_bits(scale_bits)
}

#[inline]
pub fn lnf(x: f32) -> f32 {
    if x <= 0.0 {
        return -1e30;
    }
    let bits = x.to_bits();
    let exp = ((bits >> 23) & 0xFF) as i32 - 127;
    let mant = f32::from_bits((bits & 0x007F_FFFF) | (127 << 23));
    // Bring mantissa near 1 in [sqrt(0.5), sqrt(2)]
    let (m, e) = if mant > 1.4142135 {
        (mant * 0.5, exp + 1)
    } else {
        (mant, exp)
    };
    let y = (m - 1.0) / (m + 1.0);
    let y2 = y * y;
    let series = 2.0
        * y
        * (1.0
            + y2 * (0.33333334 + y2 * (0.2 + y2 * (0.14285715 + y2 * 0.11111111))));
    series + (e as f32) * 0.69314718
}

#[inline]
pub fn powf(base: f32, exp: f32) -> f32 {
    if base <= 0.0 {
        0.0
    } else if exp == 0.0 {
        1.0
    } else {
        expf(exp * lnf(base))
    }
}

pub fn sin_cos_f32(angle: f32) -> (f32, f32) {
    const TWO_PI: f32 = 6.283185307179586;
    const PI: f32 = 3.141592653589793;
    const HALF_PI: f32 = 1.5707963267948966;

    let mut x = angle;
    let turns = (x / TWO_PI) as i32;
    x -= (turns as f32) * TWO_PI;
    if x > PI {
        x -= TWO_PI;
    } else if x < -PI {
        x += TWO_PI;
    }

    // Reduce into [-pi/2, pi/2] keeping cos sign
    let (rx, cos_sign) = if x > HALF_PI {
        (PI - x, -1.0f32)
    } else if x < -HALF_PI {
        (-PI - x, -1.0f32)
    } else {
        (x, 1.0f32)
    };

    let x2 = rx * rx;
    let s = rx * (1.0 - x2 * (0.16666667 - x2 * (0.008333334 - x2 * 0.0001984127)));
    let c = cos_sign * (1.0 - x2 * (0.5 - x2 * (0.041666668 - x2 * 0.0013888889)));
    (s, c)
}

#[inline]
pub fn siluf(x: f32) -> f32 {
    x / (1.0 + expf(-x))
}

#[inline]
pub fn dot_f32(a: &[f32], b: &[f32]) -> f32 {
    let n = a.len().min(b.len());
    if n == 0 {
        return 0.0;
    }
    unsafe { crate::arch::nexos_neon_dot_f32(a.as_ptr(), b.as_ptr(), n) }
}

pub fn rmsnorm(out: &mut [f32], x: &[f32], weight: &[f32]) {
    let n = x.len();
    let ss = dot_f32(x, x) / (n as f32);
    let inv = 1.0 / sqrtf(ss + 1e-5);
    for i in 0..n {
        out[i] = weight[i] * (x[i] * inv);
    }
}

pub fn softmax(x: &mut [f32]) {
    if x.is_empty() {
        return;
    }
    let mut max_v = x[0];
    for &v in x.iter().skip(1) {
        if v > max_v {
            max_v = v;
        }
    }
    let mut sum = 0.0f32;
    for v in x.iter_mut() {
        let e = expf(*v - max_v);
        *v = e;
        sum += e;
    }
    let inv = if sum > 0.0 { 1.0 / sum } else { 1.0 };
    for v in x.iter_mut() {
        *v *= inv;
    }
}

pub fn dequant_row_q8_0(out: &mut [f32], row_q8: &[u8], cols: usize) {
    let blocks = cols / Q8_BLOCK_ELEMS;
    for b in 0..blocks {
        let off = b * Q8_BLOCK_BYTES;
        let scale = f32::from_le_bytes(row_q8[off..off + 4].try_into().unwrap());
        let qs = &row_q8[off + 4..off + Q8_BLOCK_BYTES];
        let base = b * Q8_BLOCK_ELEMS;
        for i in 0..Q8_BLOCK_ELEMS {
            out[base + i] = (qs[i] as i8 as f32) * scale;
        }
    }
}

pub fn gemv_q8_0_scalar(out: &mut [f32], mat_q8: &[u8], x: &[f32], rows: usize, cols: usize) {
    let blocks_per_row = cols / Q8_BLOCK_ELEMS;
    let row_bytes = blocks_per_row * Q8_BLOCK_BYTES;
    for r in 0..rows {
        let row_slice = &mat_q8[r * row_bytes..(r + 1) * row_bytes];
        let mut acc = 0.0f32;
        for b in 0..blocks_per_row {
            let off = b * Q8_BLOCK_BYTES;
            let scale = f32::from_le_bytes(row_slice[off..off + 4].try_into().unwrap());
            let qs = &row_slice[off + 4..off + Q8_BLOCK_BYTES];
            let x_blk = &x[b * Q8_BLOCK_ELEMS..(b + 1) * Q8_BLOCK_ELEMS];
            let mut bsum = 0.0f32;
            for i in 0..Q8_BLOCK_ELEMS {
                bsum += (qs[i] as i8 as f32) * x_blk[i];
            }
            acc += bsum * scale;
        }
        out[r] = acc;
    }
}

/// Perform Q8_0 quantized matrix-vector multiply using AArch64 NEON SIMD (`neon_gemv.S`).
pub fn gemv_q8_0(out: &mut [f32], mat_q8: &[u8], x: &[f32], rows: usize, cols: usize) {
    if rows == 0 || cols == 0 {
        return;
    }
    if cols % Q8_BLOCK_ELEMS == 0 {
        let expected_bytes = rows * (cols / Q8_BLOCK_ELEMS) * Q8_BLOCK_BYTES;
        if out.len() >= rows && x.len() >= cols && mat_q8.len() >= expected_bytes {
            unsafe {
                crate::arch::nexos_neon_gemv_q8_0(
                    out.as_mut_ptr(),
                    mat_q8.as_ptr(),
                    x.as_ptr(),
                    rows,
                    cols,
                );
            }
            return;
        }
    }
    gemv_q8_0_scalar(out, mat_q8, x, rows, cols);
}

/// Boot self-test comparing NEON SIMD dot/GEMV kernels against scalar IEEE-754 reference.
pub fn self_test() -> Result<(), &'static str> {
    let mut a = [0.0f32; 67];
    let mut b = [0.0f32; 67];
    let mut ref_dot = 0.0f32;
    for i in 0..67 {
        a[i] = ((i as f32) - 31.0) * 0.125;
        b[i] = ((66 - i) as f32) * 0.0625 - 1.5;
        ref_dot += a[i] * b[i];
    }
    let neon_dot = dot_f32(&a, &b);
    if (neon_dot - ref_dot).abs() > 1e-3 {
        return Err("NEON dot_f32 mismatch");
    }

    const ROWS: usize = 16;
    const COLS: usize = 64;
    let blocks_per_row = COLS / Q8_BLOCK_ELEMS;
    let mut mat = [0u8; ROWS * (COLS / Q8_BLOCK_ELEMS) * Q8_BLOCK_BYTES];
    let mut x = [0.0f32; COLS];
    for c in 0..COLS {
        x[c] = ((c as f32) - 29.0) * 0.05;
    }
    for r in 0..ROWS {
        for blk in 0..blocks_per_row {
            let off = (r * blocks_per_row + blk) * Q8_BLOCK_BYTES;
            let scale = 0.025f32 * ((r + blk + 1) as f32);
            mat[off..off + 4].copy_from_slice(&scale.to_le_bytes());
            for i in 0..Q8_BLOCK_ELEMS {
                let val = (((r * 13 + blk * 7 + i * 5) % 121) as i32 - 60) as i8;
                mat[off + 4 + i] = val as u8;
            }
        }
    }

    let mut out_neon = [0.0f32; ROWS];
    let mut out_scalar = [0.0f32; ROWS];
    gemv_q8_0(&mut out_neon, &mat, &x, ROWS, COLS);
    gemv_q8_0_scalar(&mut out_scalar, &mat, &x, ROWS, COLS);

    for r in 0..ROWS {
        if (out_neon[r] - out_scalar[r]).abs() > 1e-3 {
            return Err("NEON gemv_q8_0 mismatch");
        }
    }

    // 64x64 Q8_0 GEMV equivalence test
    const R64: usize = 64;
    const C64: usize = 64;
    let bpr64 = C64 / Q8_BLOCK_ELEMS;
    let mut mat64 = alloc::vec![0u8; R64 * bpr64 * Q8_BLOCK_BYTES];
    let mut x64 = [0.0f32; C64];
    for c in 0..C64 {
        x64[c] = ((c as f32) - 31.5) * 0.03;
    }
    for r in 0..R64 {
        for blk in 0..bpr64 {
            let off = (r * bpr64 + blk) * Q8_BLOCK_BYTES;
            let scale = 0.015f32 * (((r % 7) + blk + 1) as f32);
            mat64[off..off + 4].copy_from_slice(&scale.to_le_bytes());
            for i in 0..Q8_BLOCK_ELEMS {
                let val = (((r * 19 + blk * 11 + i * 3) % 101) as i32 - 50) as i8;
                mat64[off + 4 + i] = val as u8;
            }
        }
    }
    let mut out64_n = [0.0f32; R64];
    let mut out64_s = [0.0f32; R64];
    gemv_q8_0(&mut out64_n, &mat64, &x64, R64, C64);
    gemv_q8_0_scalar(&mut out64_s, &mat64, &x64, R64, C64);
    for r in 0..R64 {
        if (out64_n[r] - out64_s[r]).abs() > 1e-3 {
            return Err("NEON 64x64 gemv_q8_0 mismatch");
        }
    }

    // RMSNorm self-test: unit-weighted output should have mean-square ~ 1.0
    let w_ones = [1.0f32; C64];
    let mut rn_out = [0.0f32; C64];
    rmsnorm(&mut rn_out, &x64, &w_ones);
    let rms_sq = dot_f32(&rn_out, &rn_out) / (C64 as f32);
    if (rms_sq - 1.0).abs() > 1e-3 {
        return Err("RMSNorm normalization check failed");
    }

    // Softmax probability conservation and ordering check
    let mut sm = [-2.0f32, 0.5, 1.5, 3.0];
    softmax(&mut sm);
    let sm_sum: f32 = sm.iter().sum();
    if (sm_sum - 1.0).abs() > 1e-4 || !(sm[0] < sm[1] && sm[1] < sm[2] && sm[2] < sm[3]) {
        return Err("Softmax invariant check failed");
    }

    // SiLU identity at 0 and asymptotic check
    if siluf(0.0).abs() > 1e-6 || (siluf(4.0) - 3.928055).abs() > 1e-2 {
        return Err("SiLU activation check failed");
    }

    Ok(())
}
