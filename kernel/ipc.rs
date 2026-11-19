//! Bounded Inter-Process & Kernel-User Communication (IPC) Channels.
//!
//! Provides named message channels with bounded FIFO queues (16 messages x 512B),
//! SMP-safe `SpinLock` state, and blocking `WaitQueue` notification.

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;

use crate::sync::{SpinLock, WaitQueue};

pub const MAX_IPC_CHANNELS: usize = 32;
pub const MAX_IPC_MSG_SIZE: usize = 512;
pub const MAX_IPC_QUEUE_LEN: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpcError {
    NotFound,
    Full,
    WouldBlock,
    InvalidName,
    TooManyChannels,
    MessageTooLarge,
}

#[derive(Clone)]
pub struct IpcMessage {
    pub sender_pid: u64,
    pub payload: Vec<u8>,
}

struct IpcChannel {
    id: u64,
    name: String,
    queue: VecDeque<IpcMessage>,
    rx_waitq: WaitQueue,
}

struct IpcRegistry {
    next_id: u64,
    channels: Vec<IpcChannel>,
}

impl IpcRegistry {
    const fn new() -> Self {
        Self {
            next_id: 1,
            channels: Vec::new(),
        }
    }
}

static IPC: SpinLock<IpcRegistry> = SpinLock::new(IpcRegistry::new());

/// Create a new named IPC channel or return the existing ID if already created.
pub fn create_or_open(name: &str) -> Result<u64, IpcError> {
    if name.is_empty() || name.len() > 48 {
        return Err(IpcError::InvalidName);
    }
    let mut reg = IPC.lock();
    if let Some(ch) = reg.channels.iter().find(|c| c.name == name) {
        return Ok(ch.id);
    }
    if reg.channels.len() >= MAX_IPC_CHANNELS {
        return Err(IpcError::TooManyChannels);
    }
    let id = reg.next_id;
    reg.next_id += 1;
    reg.channels.push(IpcChannel {
        id,
        name: String::from(name),
        queue: VecDeque::with_capacity(MAX_IPC_QUEUE_LEN),
        rx_waitq: WaitQueue::new(),
    });
    Ok(id)
}

pub fn find_channel(name: &str) -> Option<u64> {
    IPC.lock()
        .channels
        .iter()
        .find(|c| c.name == name)
        .map(|c| c.id)
}

pub fn send(chan_id: u64, sender_pid: u64, data: &[u8]) -> Result<(), IpcError> {
    if data.len() > MAX_IPC_MSG_SIZE {
        return Err(IpcError::MessageTooLarge);
    }
    let mut reg = IPC.lock();
    let ch = reg
        .channels
        .iter_mut()
        .find(|c| c.id == chan_id)
        .ok_or(IpcError::NotFound)?;
    if ch.queue.len() >= MAX_IPC_QUEUE_LEN {
        return Err(IpcError::Full);
    }
    ch.queue.push_back(IpcMessage {
        sender_pid,
        payload: Vec::from(data),
    });
    ch.rx_waitq.wake_one();
    Ok(())
}

pub fn try_recv(chan_id: u64) -> Result<IpcMessage, IpcError> {
    let mut reg = IPC.lock();
    let ch = reg
        .channels
        .iter_mut()
        .find(|c| c.id == chan_id)
        .ok_or(IpcError::NotFound)?;
    ch.queue.pop_front().ok_or(IpcError::WouldBlock)
}

pub fn recv(chan_id: u64, blocking: bool) -> Result<IpcMessage, IpcError> {
    if !blocking {
        return try_recv(chan_id);
    }
    loop {
        match try_recv(chan_id) {
            Ok(msg) => return Ok(msg),
            Err(IpcError::WouldBlock) => {
                crate::scheduler::sleep_ms(5);
            }
            Err(e) => return Err(e),
        }
    }
}

pub fn channel_count() -> usize {
    IPC.lock().channels.len()
}

/// Deterministic kernel IPC roundtrip, empty WouldBlock, and overflow verification.
pub fn self_test() -> Result<(), IpcError> {
    let cid = create_or_open("sys.selftest")?;
    if !matches!(try_recv(cid), Err(IpcError::WouldBlock)) {
        return Err(IpcError::NotFound);
    }
    send(cid, 0, b"nexos-ipc-ping")?;
    let msg = recv(cid, false)?;
    if msg.payload != b"nexos-ipc-ping" {
        return Err(IpcError::NotFound);
    }
    for i in 0..MAX_IPC_QUEUE_LEN {
        send(cid, i as u64, b"fill")?;
    }
    if !matches!(send(cid, 99, b"overflow"), Err(IpcError::Full)) {
        return Err(IpcError::Full);
    }
    for _ in 0..MAX_IPC_QUEUE_LEN {
        let _ = try_recv(cid)?;
    }
    Ok(())
}
