//! RFC 793 TCP State Machine & Socket Table (No-Std Server & Client Support).

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use super::eth::Ipv4Addr;
use super::ipv4::{transport_checksum, IP_PROTO_TCP};

pub const MAX_TCP_SOCKETS: usize = 32;
pub const TCP_MSS: usize = 1460;
const MAX_SYN_RETRIES: u8 = 5;
const MAX_DATA_RETRIES: u8 = 8;
const HALF_OPEN_TIMEOUT_MS: u64 = 4_000;
const TEARDOWN_TIMEOUT_MS: u64 = 6_000;

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    LastAck,
    TimeWait,
}

#[derive(Clone, Copy, Debug)]
pub struct TcpSegment<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub payload: &'a [u8],
}

pub fn parse_tcp(buf: &[u8], src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> Option<TcpSegment<'_>> {
    if buf.len() < 20 {
        return None;
    }
    let data_off = ((buf[12] >> 4) as usize) * 4;
    if data_off < 20 || data_off > buf.len() {
        return None;
    }
    if transport_checksum(src_ip, dst_ip, IP_PROTO_TCP, buf) != 0 {
        return None;
    }
    Some(TcpSegment {
        src_port: u16::from_be_bytes([buf[0], buf[1]]),
        dst_port: u16::from_be_bytes([buf[2], buf[3]]),
        seq: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
        ack: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
        flags: buf[13],
        window: u16::from_be_bytes([buf[14], buf[15]]),
        payload: &buf[data_off..],
    })
}

pub fn build_tcp(
    out: &mut [u8],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
) -> Option<usize> {
    let include_mss = (flags & TCP_SYN) != 0;
    let hdr_len = if include_mss { 24 } else { 20 };
    let total = hdr_len + payload.len();
    if out.len() < total || total > 1480 {
        return None;
    }
    out[0..2].copy_from_slice(&src_port.to_be_bytes());
    out[2..4].copy_from_slice(&dst_port.to_be_bytes());
    out[4..8].copy_from_slice(&seq.to_be_bytes());
    out[8..12].copy_from_slice(&ack.to_be_bytes());
    out[12] = ((hdr_len / 4) as u8) << 4;
    out[13] = flags;
    out[14..16].copy_from_slice(&window.to_be_bytes());
    out[16..18].copy_from_slice(&[0, 0]);
    out[18..20].copy_from_slice(&[0, 0]);
    if include_mss {
        out[20] = 2; // Kind: MSS
        out[21] = 4; // Len
        out[22..24].copy_from_slice(&(TCP_MSS as u16).to_be_bytes());
    }
    out[hdr_len..total].copy_from_slice(payload);
    let csum = transport_checksum(src_ip, dst_ip, IP_PROTO_TCP, &out[..total]);
    out[16..18].copy_from_slice(&csum.to_be_bytes());
    Some(total)
}

pub struct OutgoingTcpSegment {
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub payload: Vec<u8>,
}

pub struct TcpSocket {
    pub active: bool,
    pub state: TcpState,
    pub local_port: u16,
    pub remote_ip: Ipv4Addr,
    pub remote_port: u16,
    pub iss: u32,
    pub snd_una: u32,
    pub snd_nxt: u32,
    pub rcv_nxt: u32,
    pub rx_buf: VecDeque<u8>,
    pub accepted: bool,
    pub parent_listener: Option<usize>,
    pub echo_mode: bool,
    pub last_tx_ms: u64,
    pub unacked_payload: Vec<u8>,
    pub unacked_flags: u8,
    pub retx_count: u8,
    pub state_since_ms: u64,
    pub close_at_ms: u64,
}

impl TcpSocket {
    const fn empty() -> Self {
        Self {
            active: false,
            state: TcpState::Closed,
            local_port: 0,
            remote_ip: Ipv4Addr::UNSPECIFIED,
            remote_port: 0,
            iss: 0,
            snd_una: 0,
            snd_nxt: 0,
            rcv_nxt: 0,
            rx_buf: VecDeque::new(),
            accepted: false,
            parent_listener: None,
            echo_mode: false,
            last_tx_ms: 0,
            unacked_payload: Vec::new(),
            unacked_flags: 0,
            retx_count: 0,
            state_since_ms: 0,
            close_at_ms: 0,
        }
    }

    fn reset(&mut self) {
        self.active = false;
        self.state = TcpState::Closed;
        self.local_port = 0;
        self.remote_ip = Ipv4Addr::UNSPECIFIED;
        self.remote_port = 0;
        self.rx_buf.clear();
        self.unacked_payload.clear();
        self.unacked_flags = 0;
        self.retx_count = 0;
        self.state_since_ms = 0;
        self.accepted = false;
        self.parent_listener = None;
        self.echo_mode = false;
    }
}

#[derive(Clone, Copy)]
pub struct TcpSocketInfo {
    pub id: usize,
    pub state: TcpState,
    pub local_port: u16,
    pub remote_ip: Ipv4Addr,
    pub remote_port: u16,
    pub rx_queued: usize,
    pub echo_mode: bool,
}

pub struct TcpTable {
    sockets: [TcpSocket; MAX_TCP_SOCKETS],
    isn_counter: u32,
    ephemeral_port: u16,
}

impl TcpTable {
    pub const fn new() -> Self {
        const EMPTY: TcpSocket = TcpSocket::empty();
        Self {
            sockets: [EMPTY; MAX_TCP_SOCKETS],
            isn_counter: 0x4E45_5800,
            ephemeral_port: 49152,
        }
    }

    fn next_isn(&mut self, now_ms: u64) -> u32 {
        self.isn_counter = self.isn_counter.wrapping_add(64_001 + (now_ms as u32 & 0xFFFF));
        if let Ok(r) = crate::security::csprng::next_u32() {
            self.isn_counter ^ r
        } else {
            self.isn_counter
        }
    }

    fn alloc_slot(&mut self) -> Option<usize> {
        for (i, s) in self.sockets.iter().enumerate() {
            if !s.active {
                return Some(i);
            }
        }
        None
    }

    pub fn listen(&mut self, port: u16, echo_mode: bool) -> Option<usize> {
        for (i, s) in self.sockets.iter().enumerate() {
            if s.active && s.state == TcpState::Listen && s.local_port == port {
                return Some(i);
            }
        }
        let id = self.alloc_slot()?;
        let s = &mut self.sockets[id];
        s.reset();
        s.active = true;
        s.state = TcpState::Listen;
        s.local_port = port;
        s.echo_mode = echo_mode;
        Some(id)
    }

    pub fn connect(
        &mut self,
        remote_ip: Ipv4Addr,
        remote_port: u16,
        now_ms: u64,
    ) -> Option<(usize, OutgoingTcpSegment)> {
        let id = self.alloc_slot()?;
        let local_port = self.ephemeral_port;
        self.ephemeral_port = if self.ephemeral_port >= 65000 {
            49152
        } else {
            self.ephemeral_port + 1
        };
        let isn = self.next_isn(now_ms);
        let s = &mut self.sockets[id];
        s.reset();
        s.active = true;
        s.state = TcpState::SynSent;
        s.local_port = local_port;
        s.remote_ip = remote_ip;
        s.remote_port = remote_port;
        s.iss = isn;
        s.snd_una = isn;
        s.snd_nxt = isn.wrapping_add(1);
        s.last_tx_ms = now_ms;
        s.state_since_ms = now_ms;
        s.retx_count = 0;
        s.unacked_flags = TCP_SYN;

        let seg = OutgoingTcpSegment {
            dst_ip: remote_ip,
            src_port: local_port,
            dst_port: remote_port,
            seq: isn,
            ack: 0,
            flags: TCP_SYN,
            payload: Vec::new(),
        };
        Some((id, seg))
    }

    pub fn accept(&mut self, listener_id: usize) -> Option<usize> {
        for (i, s) in self.sockets.iter_mut().enumerate() {
            if s.active
                && s.parent_listener == Some(listener_id)
                && !s.accepted
                && (s.state == TcpState::Established || s.state == TcpState::CloseWait)
            {
                s.accepted = true;
                return Some(i);
            }
        }
        None
    }

    pub fn state(&self, id: usize) -> Option<TcpState> {
        self.sockets.get(id).filter(|s| s.active).map(|s| s.state)
    }

    pub fn recv(&mut self, id: usize, out: &mut [u8]) -> usize {
        let Some(s) = self.sockets.get_mut(id) else {
            return 0;
        };
        if !s.active {
            return 0;
        }
        let n = out.len().min(s.rx_buf.len());
        for b in out.iter_mut().take(n) {
            *b = s.rx_buf.pop_front().unwrap_or(0);
        }
        n
    }

    pub fn send(&mut self, id: usize, data: &[u8], now_ms: u64) -> Vec<OutgoingTcpSegment> {
        let mut out = Vec::new();
        let Some(s) = self.sockets.get_mut(id) else {
            return out;
        };
        if !s.active || (s.state != TcpState::Established && s.state != TcpState::CloseWait) {
            return out;
        }
        for chunk in data.chunks(TCP_MSS) {
            let seq = s.snd_nxt;
            s.snd_nxt = s.snd_nxt.wrapping_add(chunk.len() as u32);
            s.last_tx_ms = now_ms;
            s.unacked_flags = TCP_ACK | TCP_PSH;
            s.unacked_payload.extend_from_slice(chunk);
            out.push(OutgoingTcpSegment {
                dst_ip: s.remote_ip,
                src_port: s.local_port,
                dst_port: s.remote_port,
                seq,
                ack: s.rcv_nxt,
                flags: TCP_ACK | TCP_PSH,
                payload: chunk.to_vec(),
            });
        }
        out
    }

    pub fn close(&mut self, id: usize, now_ms: u64) -> Option<OutgoingTcpSegment> {
        let s = self.sockets.get_mut(id)?;
        if !s.active {
            return None;
        }
        match s.state {
            TcpState::Listen | TcpState::SynSent => {
                s.reset();
                None
            }
            TcpState::SynReceived | TcpState::Established => {
                let seq = s.snd_nxt;
                s.snd_nxt = s.snd_nxt.wrapping_add(1);
                s.state = TcpState::FinWait1;
                s.last_tx_ms = now_ms;
                s.state_since_ms = now_ms;
                s.retx_count = 0;
                s.unacked_flags = TCP_FIN | TCP_ACK;
                Some(OutgoingTcpSegment {
                    dst_ip: s.remote_ip,
                    src_port: s.local_port,
                    dst_port: s.remote_port,
                    seq,
                    ack: s.rcv_nxt,
                    flags: TCP_FIN | TCP_ACK,
                    payload: Vec::new(),
                })
            }
            TcpState::CloseWait => {
                let seq = s.snd_nxt;
                s.snd_nxt = s.snd_nxt.wrapping_add(1);
                s.state = TcpState::LastAck;
                s.last_tx_ms = now_ms;
                s.state_since_ms = now_ms;
                s.retx_count = 0;
                s.unacked_flags = TCP_FIN | TCP_ACK;
                Some(OutgoingTcpSegment {
                    dst_ip: s.remote_ip,
                    src_port: s.local_port,
                    dst_port: s.remote_port,
                    seq,
                    ack: s.rcv_nxt,
                    flags: TCP_FIN | TCP_ACK,
                    payload: Vec::new(),
                })
            }
            _ => None,
        }
    }

    /// Process an incoming TCP segment and return any immediate outgoing segments.
    pub fn on_segment(
        &mut self,
        src_ip: Ipv4Addr,
        seg: &TcpSegment<'_>,
        now_ms: u64,
    ) -> Vec<OutgoingTcpSegment> {
        let mut out = Vec::new();

        // 1. Match established / non-Listen 4-tuple first
        let mut matched_idx = None;
        let mut listen_idx = None;
        for (i, s) in self.sockets.iter().enumerate() {
            if !s.active {
                continue;
            }
            if s.state != TcpState::Listen
                && s.local_port == seg.dst_port
                && s.remote_port == seg.src_port
                && s.remote_ip == src_ip
            {
                matched_idx = Some(i);
                break;
            }
            if s.state == TcpState::Listen && s.local_port == seg.dst_port {
                listen_idx = Some(i);
            }
        }

        if let Some(id) = matched_idx {
            let s = &mut self.sockets[id];
            if (seg.flags & TCP_RST) != 0 {
                s.reset();
                return out;
            }

            if s.state == TcpState::SynSent {
                if (seg.flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK)
                    && seg.ack == s.snd_nxt
                {
                    s.snd_una = seg.ack;
                    s.rcv_nxt = seg.seq.wrapping_add(1);
                    s.state = TcpState::Established;
                    s.state_since_ms = now_ms;
                    s.retx_count = 0;
                    s.unacked_flags = 0;
                    s.unacked_payload.clear();
                    out.push(OutgoingTcpSegment {
                        dst_ip: src_ip,
                        src_port: s.local_port,
                        dst_port: s.remote_port,
                        seq: s.snd_nxt,
                        ack: s.rcv_nxt,
                        flags: TCP_ACK,
                        payload: Vec::new(),
                    });
                }
                return out;
            }

            // Advance snd_una on valid ACK
            if (seg.flags & TCP_ACK) != 0 {
                let acked = seg.ack.wrapping_sub(s.snd_una) as usize;
                let max_inflight = s.snd_nxt.wrapping_sub(s.snd_una) as usize;
                if acked > 0 && acked <= max_inflight {
                    s.snd_una = seg.ack;
                    s.retx_count = 0;
                    if s.state == TcpState::SynReceived {
                        if (seg.flags & TCP_SYN) == 0 && seg.seq == s.rcv_nxt {
                            s.state = TcpState::Established;
                            s.state_since_ms = now_ms;
                            s.unacked_flags = 0;
                        }
                    } else if s.state == TcpState::FinWait1 && s.snd_una == s.snd_nxt {
                        s.state = TcpState::FinWait2;
                        s.state_since_ms = now_ms;
                        s.unacked_flags = 0;
                    } else if s.state == TcpState::LastAck && s.snd_una == s.snd_nxt {
                        s.reset();
                        return out;
                    } else {
                        let drop_bytes = acked.min(s.unacked_payload.len());
                        s.unacked_payload.drain(..drop_bytes);
                        if s.unacked_payload.is_empty() {
                            s.unacked_flags = 0;
                        }
                    }
                }
            }

            let mut need_ack = false;
            // Accept in-order payload
            if !seg.payload.is_empty() && seg.seq == s.rcv_nxt {
                let echo_mode = s.echo_mode;
                if !echo_mode {
                    if s.rx_buf.len() + seg.payload.len() <= 32 * 1024 {
                        s.rx_buf.extend(seg.payload);
                    }
                }
                s.rcv_nxt = s.rcv_nxt.wrapping_add(seg.payload.len() as u32);
                need_ack = true;

                if echo_mode && s.state == TcpState::Established {
                    let seq = s.snd_nxt;
                    s.snd_nxt = s.snd_nxt.wrapping_add(seg.payload.len() as u32);
                    s.last_tx_ms = now_ms;
                    out.push(OutgoingTcpSegment {
                        dst_ip: s.remote_ip,
                        src_port: s.local_port,
                        dst_port: s.remote_port,
                        seq,
                        ack: s.rcv_nxt,
                        flags: TCP_ACK | TCP_PSH,
                        payload: seg.payload.to_vec(),
                    });
                    need_ack = false; // piggybacked
                }
            } else if !seg.payload.is_empty() {
                need_ack = true;
            }

            // Handle FIN
            if (seg.flags & TCP_FIN) != 0 && seg.seq.wrapping_add(seg.payload.len() as u32) == s.rcv_nxt
            {
                s.rcv_nxt = s.rcv_nxt.wrapping_add(1);
                need_ack = true;
                match s.state {
                    TcpState::Established => {
                        if s.echo_mode {
                            // Auto-close echo connection cleanly
                            let ack_seg_seq = s.snd_nxt;
                            s.snd_nxt = s.snd_nxt.wrapping_add(1);
                            s.state = TcpState::LastAck;
                            out.push(OutgoingTcpSegment {
                                dst_ip: s.remote_ip,
                                src_port: s.local_port,
                                dst_port: s.remote_port,
                                seq: ack_seg_seq,
                                ack: s.rcv_nxt,
                                flags: TCP_FIN | TCP_ACK,
                                payload: Vec::new(),
                            });
                            need_ack = false;
                        } else {
                            s.state = TcpState::CloseWait;
                        }
                    }
                    TcpState::FinWait1 => {
                        s.state = TcpState::TimeWait;
                        s.close_at_ms = now_ms + 500;
                    }
                    TcpState::FinWait2 => {
                        s.state = TcpState::TimeWait;
                        s.close_at_ms = now_ms + 500;
                    }
                    _ => {}
                }
            }

            if need_ack {
                out.push(OutgoingTcpSegment {
                    dst_ip: s.remote_ip,
                    src_port: s.local_port,
                    dst_port: s.remote_port,
                    seq: s.snd_nxt,
                    ack: s.rcv_nxt,
                    flags: TCP_ACK,
                    payload: Vec::new(),
                });
            }
            return out;
        }

        // 2. Passive open on listening socket
        if let Some(lid) = listen_idx {
            if (seg.flags & TCP_SYN) != 0 && (seg.flags & TCP_ACK) == 0 {
                let echo_mode = self.sockets[lid].echo_mode;
                let local_port = self.sockets[lid].local_port;
                if let Some(cid) = self.alloc_slot() {
                    let isn = self.next_isn(now_ms);
                    let c = &mut self.sockets[cid];
                    c.reset();
                    c.active = true;
                    c.state = TcpState::SynReceived;
                    c.local_port = local_port;
                    c.remote_ip = src_ip;
                    c.remote_port = seg.src_port;
                    c.iss = isn;
                    c.snd_una = isn;
                    c.snd_nxt = isn.wrapping_add(1);
                    c.rcv_nxt = seg.seq.wrapping_add(1);
                    c.parent_listener = Some(lid);
                    c.echo_mode = echo_mode;
                    c.last_tx_ms = now_ms;
                    c.state_since_ms = now_ms;
                    c.retx_count = 0;
                    c.unacked_flags = TCP_SYN | TCP_ACK;
                    out.push(OutgoingTcpSegment {
                        dst_ip: src_ip,
                        src_port: local_port,
                        dst_port: seg.src_port,
                        seq: isn,
                        ack: c.rcv_nxt,
                        flags: TCP_SYN | TCP_ACK,
                        payload: Vec::new(),
                    });
                    return out;
                }
            }
        }

        // 3. Unmatched non-RST -> send RST
        if (seg.flags & TCP_RST) == 0 {
            let (seq, ack, flags) = if (seg.flags & TCP_ACK) != 0 {
                (seg.ack, 0, TCP_RST)
            } else {
                (
                    0,
                    seg.seq
                        .wrapping_add(seg.payload.len() as u32)
                        .wrapping_add(if (seg.flags & (TCP_SYN | TCP_FIN)) != 0 { 1 } else { 0 }),
                    TCP_RST | TCP_ACK,
                )
            };
            out.push(OutgoingTcpSegment {
                dst_ip: src_ip,
                src_port: seg.dst_port,
                dst_port: seg.src_port,
                seq,
                ack,
                flags,
                payload: Vec::new(),
            });
        }

        out
    }

    pub fn tick(&mut self, now_ms: u64) -> Vec<OutgoingTcpSegment> {
        let mut out = Vec::new();
        for s in self.sockets.iter_mut() {
            if !s.active {
                continue;
            }
            if s.state == TcpState::TimeWait && now_ms >= s.close_at_ms {
                s.reset();
                continue;
            }
            if matches!(s.state, TcpState::SynSent | TcpState::SynReceived)
                && now_ms.saturating_sub(s.state_since_ms) >= HALF_OPEN_TIMEOUT_MS
            {
                s.reset();
                continue;
            }
            if matches!(s.state, TcpState::FinWait1 | TcpState::FinWait2 | TcpState::LastAck)
                && now_ms.saturating_sub(s.state_since_ms) >= TEARDOWN_TIMEOUT_MS
            {
                s.reset();
                continue;
            }
            if s.snd_una != s.snd_nxt && now_ms.saturating_sub(s.last_tx_ms) >= 400 {
                s.last_tx_ms = now_ms;
                s.retx_count = s.retx_count.saturating_add(1);
                if s.state == TcpState::SynSent || s.state == TcpState::SynReceived {
                    if s.retx_count > MAX_SYN_RETRIES {
                        s.reset();
                        continue;
                    }
                    out.push(OutgoingTcpSegment {
                        dst_ip: s.remote_ip,
                        src_port: s.local_port,
                        dst_port: s.remote_port,
                        seq: s.snd_una,
                        ack: s.rcv_nxt,
                        flags: s.unacked_flags,
                        payload: Vec::new(),
                    });
                } else if matches!(s.state, TcpState::FinWait1 | TcpState::LastAck) {
                    if s.retx_count > MAX_SYN_RETRIES {
                        s.reset();
                        continue;
                    }
                    out.push(OutgoingTcpSegment {
                        dst_ip: s.remote_ip,
                        src_port: s.local_port,
                        dst_port: s.remote_port,
                        seq: s.snd_nxt.wrapping_sub(1),
                        ack: s.rcv_nxt,
                        flags: TCP_FIN | TCP_ACK,
                        payload: Vec::new(),
                    });
                } else if !s.unacked_payload.is_empty() {
                    if s.retx_count > MAX_DATA_RETRIES {
                        s.reset();
                        continue;
                    }
                    let chunk_len = s.unacked_payload.len().min(TCP_MSS);
                    out.push(OutgoingTcpSegment {
                        dst_ip: s.remote_ip,
                        src_port: s.local_port,
                        dst_port: s.remote_port,
                        seq: s.snd_una,
                        ack: s.rcv_nxt,
                        flags: TCP_ACK | TCP_PSH,
                        payload: s.unacked_payload[..chunk_len].to_vec(),
                    });
                }
            }
        }
        out
    }

    pub fn info_list(&self) -> Vec<TcpSocketInfo> {
        let mut list = Vec::new();
        for (i, s) in self.sockets.iter().enumerate() {
            if s.active {
                list.push(TcpSocketInfo {
                    id: i,
                    state: s.state,
                    local_port: s.local_port,
                    remote_ip: s.remote_ip,
                    remote_port: s.remote_port,
                    rx_queued: s.rx_buf.len(),
                    echo_mode: s.echo_mode,
                });
            }
        }
        list
    }
}
