//! Kernel structured logging, serial printing macros, and in-memory log ring buffer.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

use crate::arch::timer;
use crate::sync::SpinLock;

const LOG_RING_CAP: usize = 96;
const LOG_MSG_MAX: usize = 160;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
}

impl LogLevel {
    pub const fn tag(self) -> &'static str {
        match self {
            LogLevel::Error => "ERR ",
            LogLevel::Warn => "WARN",
            LogLevel::Info => "INFO",
            LogLevel::Debug => "DBG ",
        }
    }
}

#[derive(Clone, Copy)]
pub struct LogRecord {
    pub seq: u64,
    pub uptime_ms: u64,
    pub level: LogLevel,
    pub subsys: [u8; 16],
    pub subsys_len: usize,
    pub msg: [u8; LOG_MSG_MAX],
    pub msg_len: usize,
}

impl LogRecord {
    const fn empty() -> Self {
        Self {
            seq: 0,
            uptime_ms: 0,
            level: LogLevel::Info,
            subsys: [0; 16],
            subsys_len: 0,
            msg: [0; LOG_MSG_MAX],
            msg_len: 0,
        }
    }

    pub fn subsys_str(&self) -> &str {
        core::str::from_utf8(&self.subsys[..self.subsys_len]).unwrap_or("")
    }

    pub fn msg_str(&self) -> &str {
        core::str::from_utf8(&self.msg[..self.msg_len]).unwrap_or("")
    }
}

struct LogRing {
    records: [LogRecord; LOG_RING_CAP],
    head: usize,
    count: usize,
    seq: u64,
}

impl LogRing {
    const fn new() -> Self {
        Self {
            records: [LogRecord::empty(); LOG_RING_CAP],
            head: 0,
            count: 0,
            seq: 0,
        }
    }

    fn push(&mut self, level: LogLevel, subsys: &str, msg: &[u8]) {
        self.seq += 1;
        let idx = self.head;
        self.head = (self.head + 1) % LOG_RING_CAP;
        if self.count < LOG_RING_CAP {
            self.count += 1;
        }
        let rec = &mut self.records[idx];
        rec.seq = self.seq;
        rec.uptime_ms = timer::uptime_ms();
        rec.level = level;
        let sb = subsys.as_bytes();
        let slen = sb.len().min(rec.subsys.len());
        rec.subsys[..slen].copy_from_slice(&sb[..slen]);
        rec.subsys_len = slen;
        let mlen = msg.len().min(rec.msg.len());
        rec.msg[..mlen].copy_from_slice(&msg[..mlen]);
        rec.msg_len = mlen;
    }
}

static LOG_RING: SpinLock<LogRing> = SpinLock::new(LogRing::new());

struct FixedBuf {
    buf: [u8; LOG_MSG_MAX],
    len: usize,
}

impl Write for FixedBuf {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let avail = self.buf.len().saturating_sub(self.len);
        let n = bytes.len().min(avail);
        self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
        Ok(())
    }
}

pub fn _print(args: core::fmt::Arguments<'_>) {
    crate::drivers::uart::write_fmt(args);
}

pub fn _log_record(level: LogLevel, subsys: &str, args: core::fmt::Arguments<'_>) {
    let mut fb = FixedBuf {
        buf: [0; LOG_MSG_MAX],
        len: 0,
    };
    let _ = fb.write_fmt(args);
    {
        let mut ring = LOG_RING.lock();
        ring.push(level, subsys, &fb.buf[..fb.len]);
    }
    let msg = core::str::from_utf8(&fb.buf[..fb.len]).unwrap_or("");
    crate::drivers::uart::write_fmt(format_args!("[{}][{}] {}\n", level.tag(), subsys, msg));
}

pub fn recent_records(limit: usize) -> Vec<LogRecord> {
    let ring = LOG_RING.lock();
    let take = limit.min(ring.count);
    let mut out = Vec::with_capacity(take);
    let start = (ring.head + LOG_RING_CAP - take) % LOG_RING_CAP;
    for i in 0..take {
        out.push(ring.records[(start + i) % LOG_RING_CAP]);
    }
    out
}

pub fn format_recent(limit: usize) -> String {
    let recs = recent_records(limit);
    let mut s = String::new();
    for r in recs {
        s.push_str(&format!(
            "#{:03} [{:>6} ms][{}][{}] {}\n",
            r.seq,
            r.uptime_ms,
            r.level.tag(),
            r.subsys_str(),
            r.msg_str()
        ));
    }
    s
}

#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => {{
        $crate::log::_print(format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! kprintln {
    () => {
        $crate::kprint!("\n")
    };
    ($($arg:tt)*) => {{
        $crate::log::_print(format_args!("{}\n", format_args!($($arg)*)));
    }};
}

#[macro_export]
macro_rules! klog {
    ($level:expr, $subsys:expr, $($arg:tt)*) => {{
        $crate::log::_log_record($level, $subsys, format_args!($($arg)*));
    }};
}
