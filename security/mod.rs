//! NexOS Authentication, Role-Based Access Control (RBAC), Token Sessions,
//! Persistent Credential Store (`/disk/NEXUSERS.DB`), One-Time First-Boot Setup, and Audit Log.

pub mod csprng;
pub mod sha256;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::convert::TryInto;

use crate::arch::timer;
use crate::filesystem::vfs;
use crate::klog;
use crate::log::LogLevel;
use crate::sync::SpinLock;
use sha256::{
    constant_time_eq, constant_time_slice_eq, crc32, decode_base64, hmac_sha256,
    pbkdf2_hmac_sha256, sha256,
};

pub const PBKDF2_ITERATIONS: u32 = 4096;

pub const PERM_READ_METRICS: u32 = 1 << 0;
pub const PERM_MANAGE_SERVICES: u32 = 1 << 1;
pub const PERM_WRITE_VFS: u32 = 1 << 2;
pub const PERM_NET_ADMIN: u32 = 1 << 3;
pub const PERM_AI_ADMIN: u32 = 1 << 4;

const USERS_DB_PATH: &str = "/disk/NEXUSERS.DB";
const USERS_DB_MAGIC: &[u8; 4] = b"NXUS";
const USERS_DB_VERSION: u32 = 1;
const RECORD_SIZE: usize = 1 + 32 + 1 + 16 + 32; // 82 bytes

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Admin,
    Operator,
    Viewer,
    AiAgent,
}

impl Role {
    pub const fn permissions(self) -> u32 {
        match self {
            Role::Admin => {
                PERM_READ_METRICS
                    | PERM_MANAGE_SERVICES
                    | PERM_WRITE_VFS
                    | PERM_NET_ADMIN
                    | PERM_AI_ADMIN
            }
            Role::Operator => PERM_READ_METRICS | PERM_MANAGE_SERVICES,
            Role::Viewer => PERM_READ_METRICS,
            Role::AiAgent => PERM_READ_METRICS,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Operator => "operator",
            Role::Viewer => "viewer",
            Role::AiAgent => "ai-agent",
        }
    }

    const fn to_u8(self) -> u8 {
        match self {
            Role::Admin => 0,
            Role::Operator => 1,
            Role::Viewer => 2,
            Role::AiAgent => 3,
        }
    }

    const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Role::Admin),
            1 => Some(Role::Operator),
            2 => Some(Role::Viewer),
            3 => Some(Role::AiAgent),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityError {
    InvalidCredentials,
    PermissionDenied,
    InvalidToken,
    AccountLocked,
    AlreadyExists,
    NotFound,
    InvalidInput,
    EntropyUnavailable,
}

#[derive(Clone)]
struct UserAccount {
    username: String,
    salt: [u8; 16],
    pw_hash: [u8; 32],
    role: Role,
    failed_attempts: u32,
    locked_until_ms: u64,
}

#[derive(Clone)]
pub struct UserInfo {
    pub username: String,
    pub role: Role,
    pub perms: u32,
    pub failed_attempts: u32,
    pub locked: bool,
}

#[derive(Clone)]
pub struct AuthSession {
    pub username: String,
    pub role: Role,
    pub perms: u32,
    pub token: String,
    pub expires_ms: u64,
}

struct SecurityState {
    initialized: bool,
    users: Vec<UserAccount>,
    sessions: Vec<AuthSession>,
    audit_events: Vec<String>,
    token_seq: u64,
    token_secret: [u8; 32],
    setup_token: Option<[u8; 24]>,
    setup_announced: bool,
}

impl SecurityState {
    const fn new() -> Self {
        Self {
            initialized: false,
            users: Vec::new(),
            sessions: Vec::new(),
            audit_events: Vec::new(),
            token_seq: 1,
            token_secret: [0u8; 32],
            setup_token: None,
            setup_announced: false,
        }
    }

    fn record_audit(&mut self, msg: String) {
        if self.audit_events.len() >= 64 {
            self.audit_events.remove(0);
        }
        self.audit_events.push(msg);
    }

    fn prune_expired_sessions(&mut self, now: u64) {
        self.sessions.retain(|s| now <= s.expires_ms);
    }

    fn has_admin(&self) -> bool {
        self.users.iter().any(|u| u.role == Role::Admin)
    }
}

static SECURITY: SpinLock<SecurityState> = SpinLock::new(SecurityState::new());

fn hash_salted_password(salt: &[u8; 16], password: &str) -> [u8; 32] {
    pbkdf2_hmac_sha256(password.as_bytes(), salt, PBKDF2_ITERATIONS)
}

fn encode_hex_24(bytes: &[u8; 12]) -> [u8; 24] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 24];
    for (i, &b) in bytes.iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0x0F) as usize];
    }
    out
}

fn encode_hex_string(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0F) as usize] as char);
    }
    s
}

fn validate_username(username: &str) -> bool {
    !username.is_empty()
        && username.len() <= 32
        && username
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn serialize_users_db(users: &[UserAccount]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + users.len() * RECORD_SIZE + 4);
    out.extend_from_slice(USERS_DB_MAGIC);
    out.extend_from_slice(&USERS_DB_VERSION.to_le_bytes());
    out.extend_from_slice(&(users.len() as u32).to_le_bytes());
    for u in users {
        let ub = u.username.as_bytes();
        let ulen = ub.len().min(32);
        out.push(ulen as u8);
        let mut uname_buf = [0u8; 32];
        uname_buf[..ulen].copy_from_slice(&ub[..ulen]);
        out.extend_from_slice(&uname_buf);
        out.push(u.role.to_u8());
        out.extend_from_slice(&u.salt);
        out.extend_from_slice(&u.pw_hash);
    }
    let sum = crc32(&out);
    out.extend_from_slice(&sum.to_le_bytes());
    out
}

fn deserialize_users_db(data: &[u8]) -> Result<Vec<UserAccount>, &'static str> {
    if data.len() < 16 || &data[0..4] != USERS_DB_MAGIC {
        return Err("Invalid NEXUSERS.DB header");
    }
    let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
    if version != USERS_DB_VERSION {
        return Err("Unsupported NEXUSERS.DB version");
    }
    let count = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
    let expected_len = 12usize
        .checked_add(count.checked_mul(RECORD_SIZE).ok_or("DB size overflow")?)
        .and_then(|v| v.checked_add(4))
        .ok_or("DB size overflow")?;
    if data.len() != expected_len {
        return Err("Truncated or trailing bytes in NEXUSERS.DB");
    }
    let stored_crc = u32::from_le_bytes(data[data.len() - 4..].try_into().unwrap());
    let calc_crc = crc32(&data[..data.len() - 4]);
    if stored_crc != calc_crc {
        return Err("NEXUSERS.DB CRC-32 mismatch");
    }

    let mut users = Vec::with_capacity(count);
    for i in 0..count {
        let off = 12 + i * RECORD_SIZE;
        let ulen = data[off] as usize;
        if ulen == 0 || ulen > 32 {
            return Err("Invalid username length in NEXUSERS.DB");
        }
        let uname = core::str::from_utf8(&data[off + 1..off + 1 + ulen])
            .map_err(|_| "Invalid UTF-8 username in NEXUSERS.DB")?;
        if !validate_username(uname) {
            return Err("Invalid username chars in NEXUSERS.DB");
        }
        let role = Role::from_u8(data[off + 33]).ok_or("Invalid role in NEXUSERS.DB")?;
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&data[off + 34..off + 50]);
        let mut pw_hash = [0u8; 32];
        pw_hash.copy_from_slice(&data[off + 50..off + 82]);
        users.push(UserAccount {
            username: String::from(uname),
            salt,
            pw_hash,
            role,
            failed_attempts: 0,
            locked_until_ms: 0,
        });
    }
    Ok(users)
}

fn persist_users_locked(users: &[UserAccount]) {
    if !vfs::is_disk_mounted() {
        return;
    }
    let blob = serialize_users_db(users);
    if let Err(e) = vfs::write_file(USERS_DB_PATH, &blob) {
        klog!(LogLevel::Warn, "security", "Failed to save {}: {:?}", USERS_DB_PATH, e);
    } else if let Err(e) = vfs::sync() {
        klog!(LogLevel::Warn, "security", "Failed to sync {}: {:?}", USERS_DB_PATH, e);
    }
}

/// Initialize security subsystem, verify SHA-256 / HMAC / PBKDF2 / CRC-32 vectors,
/// seed token HMAC secret from CSPRNG, load `/disk/NEXUSERS.DB` if present,
/// and generate a one-time setup token if no Admin account exists (zero hardcoded passwords).
pub fn init() {
    // 1. Self-test SHA-256 against NIST/FIPS 180-4 vector ("abc")
    let digest = sha256(b"abc");
    let expected_sha: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    ];
    assert!(constant_time_eq(&digest, &expected_sha), "SHA-256 self-test failed!");

    // 2. Self-test HMAC-SHA256 against RFC 4231 Test Case 2
    let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
    let expected_mac: [u8; 32] = [
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
        0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
        0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
    ];
    assert!(constant_time_eq(&mac, &expected_mac), "HMAC-SHA256 self-test failed!");

    // 3. Self-test PBKDF2-HMAC-SHA256 ("password", "salt", c=1 and c=2)
    let pbk1 = pbkdf2_hmac_sha256(b"password", b"salt", 1);
    let exp_pbk1: [u8; 32] = [
        0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c,
        0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37,
        0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48,
        0x08, 0x05, 0x98, 0x7c, 0xb7, 0x0b, 0xe1, 0x7b,
    ];
    assert!(constant_time_eq(&pbk1, &exp_pbk1), "PBKDF2 c=1 self-test failed!");

    let pbk2 = pbkdf2_hmac_sha256(b"password", b"salt", 2);
    let exp_pbk2: [u8; 32] = [
        0xae, 0x4d, 0x0c, 0x95, 0xaf, 0x6b, 0x46, 0xd3,
        0x2d, 0x0a, 0xdf, 0xf9, 0x28, 0xf0, 0x6d, 0xd0,
        0x2a, 0x30, 0x3f, 0x8e, 0xf3, 0xc2, 0x51, 0xdf,
        0xd6, 0xe2, 0xd8, 0x5a, 0x95, 0x47, 0x4c, 0x43,
    ];
    assert!(constant_time_eq(&pbk2, &exp_pbk2), "PBKDF2 c=2 self-test failed!");

    // 4. Self-test IEEE CRC-32 ("123456789" -> 0xCBF43926)
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926, "CRC-32 self-test failed!");

    // Draw CSPRNG bytes BEFORE locking SECURITY
    let mut tok_secret = [0u8; 32];
    csprng::fill_bytes(&mut tok_secret)
        .expect("CSPRNG must be seeded before security::init()");
    let mut setup_raw = [0u8; 12];
    csprng::fill_bytes(&mut setup_raw)
        .expect("CSPRNG failed generating setup token");

    let mut sec = SECURITY.lock();
    if sec.initialized {
        csprng::zeroize_bytes(&mut tok_secret);
        csprng::zeroize_bytes(&mut setup_raw);
        return;
    }

    sec.token_secret = tok_secret;
    csprng::zeroize_bytes(&mut tok_secret);

    let mut loaded_from_disk = false;
    if vfs::is_disk_mounted() {
        if let Ok(raw) = vfs::read_file(USERS_DB_PATH) {
            match deserialize_users_db(&raw) {
                Ok(users) => {
                    sec.users = users;
                    loaded_from_disk = true;
                }
                Err(e) => {
                    klog!(LogLevel::Error, "security", "Rejected {}: {}", USERS_DB_PATH, e);
                }
            }
        }
    }

    if !sec.has_admin() {
        sec.setup_token = Some(encode_hex_24(&setup_raw));
    } else {
        sec.setup_token = None;
    }
    csprng::zeroize_bytes(&mut setup_raw);

    sec.initialized = true;
    klog!(
        LogLevel::Info,
        "security",
        "RBAC + PBKDF2-HMAC-SHA256 ({} iters) initialized (CSPRNG active, db_loaded={}, users={})",
        PBKDF2_ITERATIONS,
        loaded_from_disk,
        sec.users.len()
    );
}

/// Returns `true` when no Admin account exists and initial provisioning is required.
pub fn needs_setup() -> bool {
    !SECURITY.lock().has_admin()
}

/// Emit the one-time setup token (once per boot) if initial setup is required.
pub fn announce_setup_status() {
    let mut sec = SECURITY.lock();
    if sec.setup_announced {
        return;
    }
    sec.setup_announced = true;
    if !sec.has_admin() {
        if let Some(tok) = sec.setup_token {
            let tok_str = core::str::from_utf8(&tok).unwrap_or("");
            klog!(
                LogLevel::Warn,
                "security",
                "FIRST-BOOT SETUP REQUIRED: one-time setup token={}",
                tok_str
            );
        }
    } else {
        klog!(
            LogLevel::Info,
            "security",
            "Credential store ready ({} persisted account(s), setup locked).",
            sec.users.len()
        );
    }
}

/// Complete initial first-boot provisioning via HTTP/HTTPS using the UART one-time setup token.
pub fn complete_initial_setup_with_token(
    setup_token: &str,
    username: &str,
    password: &str,
) -> Result<(), SecurityError> {
    if !validate_username(username) || password.len() < 8 {
        return Err(SecurityError::InvalidInput);
    }
    let mut salt = [0u8; 16];
    csprng::fill_bytes(&mut salt).map_err(|_| SecurityError::EntropyUnavailable)?;

    let mut sec = SECURITY.lock();
    if sec.has_admin() {
        return Err(SecurityError::AlreadyExists);
    }
    let Some(expected) = sec.setup_token else {
        return Err(SecurityError::PermissionDenied);
    };
    if !constant_time_slice_eq(&expected, setup_token.trim().as_bytes()) {
        let now = timer::uptime_ms();
        sec.record_audit(format!("[{} ms] SETUP_BAD_TOKEN user={}", now, username));
        return Err(SecurityError::PermissionDenied);
    }

    if sec.users.iter().any(|u| u.username == username) {
        return Err(SecurityError::AlreadyExists);
    }

    let pw_hash = hash_salted_password(&salt, password);
    sec.users.push(UserAccount {
        username: String::from(username),
        salt,
        pw_hash,
        role: Role::Admin,
        failed_attempts: 0,
        locked_until_ms: 0,
    });
    if let Some(ref mut tok) = sec.setup_token {
        csprng::zeroize_bytes(tok);
    }
    sec.setup_token = None;
    persist_users_locked(&sec.users);

    let now = timer::uptime_ms();
    sec.record_audit(format!("[{} ms] SETUP_COMPLETE admin={}", now, username));
    klog!(LogLevel::Info, "security", "First-boot Admin '{}' provisioned and setup locked.", username);
    Ok(())
}

/// Complete initial first-boot provisioning from physical UART EL0 console (`SYS_SECURITY`).
pub fn complete_initial_setup_local(username: &str, password: &str) -> Result<(), SecurityError> {
    if !validate_username(username) || password.len() < 8 {
        return Err(SecurityError::InvalidInput);
    }
    let mut salt = [0u8; 16];
    csprng::fill_bytes(&mut salt).map_err(|_| SecurityError::EntropyUnavailable)?;

    let mut sec = SECURITY.lock();
    if sec.has_admin() {
        return Err(SecurityError::AlreadyExists);
    }
    if sec.users.iter().any(|u| u.username == username) {
        return Err(SecurityError::AlreadyExists);
    }

    let pw_hash = hash_salted_password(&salt, password);
    sec.users.push(UserAccount {
        username: String::from(username),
        salt,
        pw_hash,
        role: Role::Admin,
        failed_attempts: 0,
        locked_until_ms: 0,
    });
    if let Some(ref mut tok) = sec.setup_token {
        csprng::zeroize_bytes(tok);
    }
    sec.setup_token = None;
    persist_users_locked(&sec.users);

    let now = timer::uptime_ms();
    sec.record_audit(format!("[{} ms] SETUP_COMPLETE_LOCAL admin={}", now, username));
    klog!(LogLevel::Info, "security", "First-boot Admin '{}' provisioned via UART console.", username);
    Ok(())
}

/// Boot RBAC + authentication + DB roundtrip self-test using ephemeral CSPRNG passwords.
/// Removes all temporary test accounts and sessions before returning so zero default credentials exist.
pub fn self_test_rbac() {
    let mut raw_a = [0u8; 16];
    let mut raw_b = [0u8; 16];
    csprng::fill_bytes(&mut raw_a).expect("CSPRNG failure in RBAC self-test");
    csprng::fill_bytes(&mut raw_b).expect("CSPRNG failure in RBAC self-test");
    let pw_a = encode_hex_string(&raw_a);
    let pw_b = encode_hex_string(&raw_b);
    csprng::zeroize_bytes(&mut raw_a);
    csprng::zeroize_bytes(&mut raw_b);

    let mut salt_a = [0u8; 16];
    let mut salt_b = [0u8; 16];
    csprng::fill_bytes(&mut salt_a).expect("CSPRNG salt");
    csprng::fill_bytes(&mut salt_b).expect("CSPRNG salt");

    let adm_name = "__st_adm";
    let vwr_name = "__st_vwr";

    {
        let mut sec = SECURITY.lock();
        sec.users.push(UserAccount {
            username: String::from(adm_name),
            salt: salt_a,
            pw_hash: hash_salted_password(&salt_a, &pw_a),
            role: Role::Admin,
            failed_attempts: 0,
            locked_until_ms: 0,
        });
        sec.users.push(UserAccount {
            username: String::from(vwr_name),
            salt: salt_b,
            pw_hash: hash_salted_password(&salt_b, &pw_b),
            role: Role::Viewer,
            failed_attempts: 0,
            locked_until_ms: 0,
        });

        // Verify NEXUSERS.DB serialize/deserialize + tamper detection in memory
        let blob = serialize_users_db(&sec.users);
        let parsed = deserialize_users_db(&blob).expect("NEXUSERS.DB roundtrip failed");
        assert_eq!(parsed.len(), sec.users.len());
        let mut tampered = blob;
        let last = tampered.len() - 5;
        tampered[last] ^= 0x01;
        assert!(deserialize_users_db(&tampered).is_err(), "Corrupt NEXUSERS.DB CRC must fail!");
    }

    assert_eq!(
        authenticate(adm_name, "wrong-password").err(),
        Some(SecurityError::InvalidCredentials)
    );
    let viewer = authenticate(vwr_name, &pw_b).expect("ephemeral viewer auth");
    assert!(authorize(&viewer, PERM_READ_METRICS, "st_read").is_ok());
    assert_eq!(
        authorize(&viewer, PERM_MANAGE_SERVICES, "st_svc"),
        Err(SecurityError::PermissionDenied)
    );
    let admin = authenticate(adm_name, &pw_a).expect("ephemeral admin auth");
    assert!(authorize(&admin, PERM_MANAGE_SERVICES, "st_svc").is_ok());
    assert!(validate_token(&admin.token).is_ok());

    // Remove temporary accounts and sessions cleanly
    {
        let mut sec = SECURITY.lock();
        sec.users.retain(|u| u.username != adm_name && u.username != vwr_name);
        sec.sessions.retain(|s| s.username != adm_name && s.username != vwr_name);
    }
}

fn make_token(secret: &[u8; 32], username: &str, seq: u64) -> String {
    let mut msg = Vec::with_capacity(username.len() + 32);
    msg.extend_from_slice(username.as_bytes());
    msg.extend_from_slice(&timer::read_cntpct().to_le_bytes());
    msg.extend_from_slice(&seq.to_le_bytes());
    let mut rnd = [0u8; 16];
    if csprng::fill_bytes(&mut rnd).is_ok() {
        msg.extend_from_slice(&rnd);
    }
    let d = hmac_sha256(secret, &msg);
    encode_hex_string(&d)
}

/// Authenticate username + password using constant-time PBKDF2-HMAC-SHA256 comparison,
/// failure lockout backoff (after 5 failures), and dummy derivation when user is absent.
pub fn authenticate(username: &str, password: &str) -> Result<AuthSession, SecurityError> {
    let mut sec = SECURITY.lock();
    let now = timer::uptime_ms();
    let mut matched: Option<Role> = None;
    let mut found_idx: Option<usize> = None;

    for (idx, u) in sec.users.iter().enumerate() {
        if constant_time_slice_eq(u.username.as_bytes(), username.as_bytes()) {
            found_idx = Some(idx);
        }
    }

    if let Some(idx) = found_idx {
        if sec.users[idx].locked_until_ms > now {
            sec.record_audit(format!("[{} ms] AUTH_LOCKED user={}", now, username));
            klog!(LogLevel::Warn, "audit", "AUTH_LOCKED user={}", username);
            return Err(SecurityError::AccountLocked);
        }
        let u = &sec.users[idx];
        let candidate = hash_salted_password(&u.salt, password);
        if constant_time_eq(&u.pw_hash, &candidate) {
            matched = Some(u.role);
        }
    } else {
        // Constant-work dummy PBKDF2 so unknown usernames have identical latency
        let dummy_salt = *b"NX_DUMMY_SALT_00";
        let dummy_hash = [0u8; 32];
        let candidate = hash_salted_password(&dummy_salt, password);
        let _ = constant_time_eq(&dummy_hash, &candidate);
    }

    sec.prune_expired_sessions(now);

    match matched {
        Some(role) => {
            if let Some(idx) = found_idx {
                sec.users[idx].failed_attempts = 0;
                sec.users[idx].locked_until_ms = 0;
            }
            sec.token_seq += 1;
            let seq = sec.token_seq;
            let secret = sec.token_secret;
            let token = make_token(&secret, username, seq);
            let sess = AuthSession {
                username: String::from(username),
                role,
                perms: role.permissions(),
                token,
                expires_ms: now + 3_600_000,
            };
            if sec.sessions.len() >= 32 {
                sec.sessions.remove(0);
            }
            sec.sessions.push(sess.clone());
            sec.record_audit(format!("[{} ms] AUTH_OK user={} role={}", now, username, role.as_str()));
            klog!(LogLevel::Info, "audit", "AUTH_OK user={} role={}", username, role.as_str());
            Ok(sess)
        }
        None => {
            if let Some(idx) = found_idx {
                let fails = sec.users[idx].failed_attempts.saturating_add(1);
                sec.users[idx].failed_attempts = fails;
                if fails >= 5 {
                    let backoff_ms = 2000u64 << (fails - 5).min(4);
                    sec.users[idx].locked_until_ms = now + backoff_ms;
                    sec.record_audit(format!(
                        "[{} ms] LOCKOUT user={} fails={} backoff={}ms",
                        now, username, fails, backoff_ms
                    ));
                }
            }
            sec.record_audit(format!("[{} ms] AUTH_FAIL user={}", now, username));
            klog!(LogLevel::Warn, "audit", "AUTH_FAIL user={}", username);
            Err(SecurityError::InvalidCredentials)
        }
    }
}

pub fn create_user(username: &str, password: &str, role: Role) -> Result<(), SecurityError> {
    if !validate_username(username) || password.len() < 8 {
        return Err(SecurityError::InvalidInput);
    }
    let mut salt = [0u8; 16];
    csprng::fill_bytes(&mut salt).map_err(|_| SecurityError::EntropyUnavailable)?;

    let mut sec = SECURITY.lock();
    if sec.users.iter().any(|u| u.username == username) {
        return Err(SecurityError::AlreadyExists);
    }
    let pw_hash = hash_salted_password(&salt, password);
    sec.users.push(UserAccount {
        username: String::from(username),
        salt,
        pw_hash,
        role,
        failed_attempts: 0,
        locked_until_ms: 0,
    });
    if role == Role::Admin {
        if let Some(ref mut tok) = sec.setup_token {
            csprng::zeroize_bytes(tok);
        }
        sec.setup_token = None;
    }
    persist_users_locked(&sec.users);
    let now = timer::uptime_ms();
    sec.record_audit(format!("[{} ms] USER_CREATE user={} role={}", now, username, role.as_str()));
    Ok(())
}

pub fn delete_user(username: &str) -> Result<(), SecurityError> {
    let mut sec = SECURITY.lock();
    let Some(pos) = sec.users.iter().position(|u| u.username == username) else {
        return Err(SecurityError::NotFound);
    };
    if sec.users[pos].role == Role::Admin {
        let admin_count = sec.users.iter().filter(|u| u.role == Role::Admin).count();
        if admin_count <= 1 {
            return Err(SecurityError::PermissionDenied);
        }
    }
    sec.users.remove(pos);
    sec.sessions.retain(|s| s.username != username);
    persist_users_locked(&sec.users);
    let now = timer::uptime_ms();
    sec.record_audit(format!("[{} ms] USER_DELETE user={}", now, username));
    Ok(())
}

pub fn list_users() -> Vec<UserInfo> {
    let now = timer::uptime_ms();
    SECURITY
        .lock()
        .users
        .iter()
        .map(|u| UserInfo {
            username: u.username.clone(),
            role: u.role,
            perms: u.role.permissions(),
            failed_attempts: u.failed_attempts,
            locked: u.locked_until_ms > now,
        })
        .collect()
}

/// Record unauthenticated or malformed HTTP authentication attempts in the audit log.
pub fn record_http_auth_fail(reason: &str) {
    let now = timer::uptime_ms();
    let mut sec = SECURITY.lock();
    sec.record_audit(format!("[{} ms] HTTP_AUTH_FAIL reason={}", now, reason));
}

/// Authenticate HTTP `Authorization: Basic ...` or `Bearer ...` header value.
pub fn authenticate_http_header(header_val: &str) -> Result<AuthSession, SecurityError> {
    let trimmed = header_val.trim();
    if let Some(b64) = trimmed.strip_prefix("Basic ") {
        let raw = decode_base64(b64.as_bytes()).ok_or(SecurityError::InvalidCredentials)?;
        let cred = core::str::from_utf8(&raw).map_err(|_| SecurityError::InvalidCredentials)?;
        let (user, pass) = cred
            .split_once(':')
            .ok_or(SecurityError::InvalidCredentials)?;
        authenticate(user, pass)
    } else if let Some(tok) = trimmed.strip_prefix("Bearer ") {
        validate_token(tok.trim())
    } else {
        Err(SecurityError::InvalidCredentials)
    }
}

pub fn validate_token(token: &str) -> Result<AuthSession, SecurityError> {
    let now = timer::uptime_ms();
    let mut sec = SECURITY.lock();
    sec.prune_expired_sessions(now);
    let mut found: Option<AuthSession> = None;
    for s in sec.sessions.iter() {
        if constant_time_slice_eq(s.token.as_bytes(), token.as_bytes()) {
            found = Some(s.clone());
        }
    }
    found.ok_or(SecurityError::InvalidToken)
}

pub fn authorize(session: &AuthSession, required_perm: u32, action: &str) -> Result<(), SecurityError> {
    if (session.perms & required_perm) == required_perm {
        Ok(())
    } else {
        let now = timer::uptime_ms();
        let mut sec = SECURITY.lock();
        sec.record_audit(format!(
            "[{} ms] PERM_DENIED user={} role={} action={}",
            now,
            session.username,
            session.role.as_str(),
            action
        ));
        klog!(
            LogLevel::Warn,
            "audit",
            "PERM_DENIED user={} role={} action={}",
            session.username,
            session.role.as_str(),
            action
        );
        Err(SecurityError::PermissionDenied)
    }
}

pub fn recent_audit_events() -> Vec<String> {
    SECURITY.lock().audit_events.clone()
}
