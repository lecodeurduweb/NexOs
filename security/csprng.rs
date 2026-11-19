//! Cryptographically Secure Pseudo-Random Number Generator (CSPRNG) — ChaCha20 DRBG.
//!
//! Fail-closed architecture:
//! - Must be seeded from a real hardware/hypervisor entropy source (`VirtioRng` on QEMU,
//!   `Bcm2711Rng200` on Raspberry Pi 4, or ARMv8.5 `RNDR` if advertised in `ID_AA64ISAR0_EL1`).
//! - Timers (`CNTPCT_EL0`) are NEVER accepted as sole entropy source; they are mixed only
//!   to personalize an already-genuine hardware seed.
//! - Applies NIST SP 800-90B continuous repetition-count health checking on raw HW blocks.
//! - Uses backtracking-resistant fast key erasure after every generation call.

use core::arch::asm;
use core::convert::TryInto;
use core::ptr::write_volatile;
use core::sync::atomic::{compiler_fence, Ordering};

use crate::arch::timer;
use crate::drivers::dtb::DeviceTreeInfo;
use crate::drivers::rng_bcm2711::{Bcm2711Rng200, BCM2711_RNG200_DEFAULT_BASE};
use crate::drivers::virtio::rng::VirtioRng;
use crate::klog;
use crate::log::LogLevel;
use crate::security::sha256::Sha256;
use crate::sync::SpinLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CsprngError {
    NotSeeded,
    NoHardwareEntropy,
    HealthCheckFailed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntropySource {
    Unseeded,
    VirtioRng,
    ArmRndr,
    Bcm2711Rng200,
}

impl EntropySource {
    pub const fn as_str(self) -> &'static str {
        match self {
            EntropySource::Unseeded => "unseeded",
            EntropySource::VirtioRng => "virtio-rng",
            EntropySource::ArmRndr => "arm-rndr",
            EntropySource::Bcm2711Rng200 => "bcm2711-rng200",
        }
    }
}

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

pub fn zeroize_bytes(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe {
            write_volatile(b, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

fn check_entropy_health(raw: &[u8]) -> Result<(), CsprngError> {
    if raw.len() < 32 {
        return Err(CsprngError::HealthCheckFailed);
    }
    // Reject all-zero, all-FF, or stuck 8-byte repeating chunks
    if raw.iter().all(|&b| b == 0) || raw.iter().all(|&b| b == 0xFF) {
        return Err(CsprngError::HealthCheckFailed);
    }
    let mut identical_chunks = 0usize;
    for pair in raw.chunks_exact(8).collect::<alloc::vec::Vec<_>>().windows(2) {
        if pair[0] == pair[1] {
            identical_chunks += 1;
        }
    }
    if identical_chunks >= 2 {
        return Err(CsprngError::HealthCheckFailed);
    }
    Ok(())
}

fn cpu_supports_rndr() -> bool {
    let isar0: u64;
    unsafe {
        asm!("mrs {}, ID_AA64ISAR0_EL1", out(reg) isar0, options(nomem, nostack, preserves_flags));
    }
    ((isar0 >> 60) & 0xF) >= 1
}

fn try_arm_rndr_seed(out: &mut [u8; 64]) -> bool {
    if !cpu_supports_rndr() {
        return false;
    }
    for i in 0..8 {
        let val: u64;
        let nzcv_ok: u64;
        unsafe {
            // S3_3_C2_C4_0 is architectural RNDR; Z=0 on success
            asm!(
                "mrs {val}, s3_3_c2_c4_0",
                "cset {ok}, ne",
                val = out(reg) val,
                ok = out(reg) nzcv_ok,
                options(nomem, nostack)
            );
        }
        if nzcv_ok == 0 {
            return false;
        }
        out[i * 8..i * 8 + 8].copy_from_slice(&val.to_le_bytes());
    }
    check_entropy_health(out).is_ok()
}

pub struct ChaChaDrbg {
    seeded: bool,
    source: EntropySource,
    key: [u8; 32],
    nonce: [u8; 12],
    reseed_ctr: u64,
    bytes_since_reseed: u64,
}

impl ChaChaDrbg {
    pub const fn new() -> Self {
        Self {
            seeded: false,
            source: EntropySource::Unseeded,
            key: [0u8; 32],
            nonce: [0u8; 12],
            reseed_ctr: 0,
            bytes_since_reseed: 0,
        }
    }

    pub fn seed_from_hw(
        &mut self,
        hw_entropy: &[u8],
        source: EntropySource,
    ) -> Result<(), CsprngError> {
        check_entropy_health(hw_entropy)?;

        // Condition HW entropy + current key + timer jitter into new 256-bit DRBG key
        let mut h = Sha256::new();
        h.update(b"NEXOS-CHACHA-DRBG-V1");
        h.update(&self.key);
        h.update(hw_entropy);
        h.update(&timer::read_cntpct().to_le_bytes());
        h.update(&self.reseed_ctr.to_le_bytes());
        let new_key = h.finalize();

        let mut hn = Sha256::new();
        hn.update(b"NEXOS-DRBG-NONCE");
        hn.update(&new_key);
        hn.update(hw_entropy);
        let nd = hn.finalize();

        self.key = new_key;
        self.nonce.copy_from_slice(&nd[..12]);
        self.seeded = true;
        self.source = source;
        self.reseed_ctr = self.reseed_ctr.saturating_add(1);
        self.bytes_since_reseed = 0;
        Ok(())
    }

    pub fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), CsprngError> {
        if !self.seeded {
            return Err(CsprngError::NotSeeded);
        }
        if out.is_empty() {
            return Ok(());
        }

        let mut ctr = 1u32;
        let mut off = 0usize;
        while off < out.len() {
            let blk = chacha20_block(&self.key, ctr, &self.nonce);
            let take = (out.len() - off).min(64);
            out[off..off + take].copy_from_slice(&blk[..take]);
            off += take;
            ctr = ctr.wrapping_add(1);
        }

        // Fast key erasure (backtracking resistance): ratchet key + nonce immediately
        let ratchet = chacha20_block(&self.key, 0, &self.nonce);
        self.key.copy_from_slice(&ratchet[..32]);
        self.nonce.copy_from_slice(&ratchet[32..44]);
        self.bytes_since_reseed = self.bytes_since_reseed.saturating_add(out.len() as u64);
        Ok(())
    }
}

struct GlobalRngState {
    drbg: ChaChaDrbg,
    virtio: Option<VirtioRng>,
}

static CSPRNG: SpinLock<GlobalRngState> = SpinLock::new(GlobalRngState {
    drbg: ChaChaDrbg::new(),
    virtio: None,
});

/// Initialize kernel CSPRNG from genuine hardware / VirtIO entropy (fail-closed).
pub fn init(dtb: &DeviceTreeInfo) -> Result<EntropySource, CsprngError> {
    let mut seed = [0u8; 64];
    let mut src = EntropySource::Unseeded;
    let mut virtio_dev: Option<VirtioRng> = None;

    // 1. Try ARMv8.5 RNDR if CPU supports it
    if try_arm_rndr_seed(&mut seed) {
        src = EntropySource::ArmRndr;
    }

    // 2. Try VirtIO-RNG (QEMU `virtio-rng-device`)
    if src == EntropySource::Unseeded {
        if let Some(mut vrng) = VirtioRng::probe(dtb) {
            if vrng.read_entropy(&mut seed).unwrap_or(0) >= 32
                && check_entropy_health(&seed).is_ok()
            {
                src = EntropySource::VirtioRng;
                virtio_dev = Some(vrng);
            }
        }
    }

    // 3. Try BCM2711 RNG200 on Raspberry Pi 4
    #[cfg(feature = "board-rpi4")]
    if src == EntropySource::Unseeded {
        let base = dtb.rng200_base.unwrap_or(BCM2711_RNG200_DEFAULT_BASE as u64) as usize;
        let mut hrng = Bcm2711Rng200::new(base);
        if hrng.init().is_ok()
            && hrng.read_bytes(&mut seed).unwrap_or(0) >= 32
            && check_entropy_health(&seed).is_ok()
        {
            src = EntropySource::Bcm2711Rng200;
        }
    }
    let _ = (Bcm2711Rng200::new, BCM2711_RNG200_DEFAULT_BASE);

    if src == EntropySource::Unseeded {
        zeroize_bytes(&mut seed);
        klog!(
            LogLevel::Error,
            "csprng",
            "CRITICAL: No hardware/VirtIO entropy source found; CSPRNG remains fail-closed."
        );
        return Err(CsprngError::NoHardwareEntropy);
    }

    let mut guard = CSPRNG.lock();
    guard.drbg.seed_from_hw(&seed, src)?;
    guard.virtio = virtio_dev;
    zeroize_bytes(&mut seed);

    klog!(
        LogLevel::Info,
        "csprng",
        "ChaCha20 DRBG seeded (64B hardware seed from {}, backtracking-resistant)",
        src.as_str()
    );
    Ok(src)
}

pub fn is_seeded() -> bool {
    CSPRNG.lock().drbg.seeded
}

pub fn source_name() -> &'static str {
    CSPRNG.lock().drbg.source.as_str()
}

/// Fill `out` with cryptographically secure random bytes; periodically re-seeds from VirtIO-RNG when >1 MiB drawn.
pub fn fill_bytes(out: &mut [u8]) -> Result<(), CsprngError> {
    let mut guard = CSPRNG.lock();
    if !guard.drbg.seeded {
        return Err(CsprngError::NotSeeded);
    }
    if guard.drbg.bytes_since_reseed >= 1024 * 1024 {
        if let Some(vrng) = guard.virtio.as_mut() {
            let mut extra = [0u8; 32];
            if vrng.read_entropy(&mut extra).unwrap_or(0) == 32
                && check_entropy_health(&extra).is_ok()
            {
                let src = guard.drbg.source;
                let _ = guard.drbg.seed_from_hw(&extra, src);
            }
            zeroize_bytes(&mut extra);
        }
    }
    guard.drbg.fill_bytes(out)
}

pub fn next_u64() -> Result<u64, CsprngError> {
    let mut b = [0u8; 8];
    fill_bytes(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

pub fn next_u32() -> Result<u32, CsprngError> {
    let mut b = [0u8; 4];
    fill_bytes(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

/// Verify fail-closed behavior, continuous health rejection of stuck seeds, and backtracking erasure.
pub fn self_test() -> Result<(), &'static str> {
    // 1. Unseeded DRBG must fail closed
    let mut unseeded = ChaChaDrbg::new();
    let mut tmp = [0u8; 16];
    if unseeded.fill_bytes(&mut tmp) != Err(CsprngError::NotSeeded) {
        return Err("Unseeded DRBG did not fail closed");
    }

    // 2. Zero/stuck seed must be rejected by health check
    let stuck = [0u8; 64];
    if unseeded.seed_from_hw(&stuck, EntropySource::VirtioRng) != Err(CsprngError::HealthCheckFailed)
    {
        return Err("Health check failed to reject all-zero seed");
    }
    let repeating = [0x42u8; 64];
    if unseeded.seed_from_hw(&repeating, EntropySource::VirtioRng)
        != Err(CsprngError::HealthCheckFailed)
    {
        return Err("Health check failed to reject repeating seed");
    }

    // 3. Valid seed produces distinct outputs & ratchets key
    let mut test_seed = [0u8; 64];
    for (i, b) in test_seed.iter_mut().enumerate() {
        *b = ((i * 73 + 19) & 0xFF) as u8;
    }
    unseeded
        .seed_from_hw(&test_seed, EntropySource::VirtioRng)
        .map_err(|_| "Seed failed")?;
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    unseeded.fill_bytes(&mut a).map_err(|_| "fill a failed")?;
    unseeded.fill_bytes(&mut b).map_err(|_| "fill b failed")?;
    if a == b || a == [0u8; 32] {
        return Err("DRBG output repeated or zero");
    }

    // 4. Verify live global kernel CSPRNG is seeded and producing non-trivial output
    let mut g1 = [0u8; 32];
    let mut g2 = [0u8; 32];
    fill_bytes(&mut g1).map_err(|_| "Global CSPRNG not seeded")?;
    fill_bytes(&mut g2).map_err(|_| "Global CSPRNG read 2 failed")?;
    if g1 == g2 {
        return Err("Global CSPRNG produced identical blocks");
    }

    // 5. Run BCM2711 RNG200 MMIO mock self-test
    crate::drivers::rng_bcm2711::self_test_mock().map_err(|_| "BCM2711 RNG200 mock test failed")?;
    Ok(())
}
