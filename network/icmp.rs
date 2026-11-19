//! ICMP (Echo Request / Echo Reply) Protocol Module.

use super::eth::Ipv4Addr;
use super::ipv4::internet_checksum;

pub const ICMP_TYPE_ECHO_REPLY: u8 = 0;
pub const ICMP_TYPE_ECHO_REQUEST: u8 = 8;

#[derive(Clone, Copy, Debug)]
pub struct IcmpEcho<'a> {
    pub msg_type: u8,
    pub code: u8,
    pub id: u16,
    pub seq: u16,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug)]
pub struct PingReplyRecord {
    pub valid: bool,
    pub src: Ipv4Addr,
    pub id: u16,
    pub seq: u16,
    pub recv_cntpct: u64,
    pub ttl: u8,
    pub payload_len: usize,
}

impl PingReplyRecord {
    pub const fn empty() -> Self {
        Self {
            valid: false,
            src: Ipv4Addr::UNSPECIFIED,
            id: 0,
            seq: 0,
            recv_cntpct: 0,
            ttl: 0,
            payload_len: 0,
        }
    }
}

pub fn parse_icmp(buf: &[u8]) -> Option<IcmpEcho<'_>> {
    if buf.len() < 8 {
        return None;
    }
    if internet_checksum(buf) != 0 {
        return None;
    }
    Some(IcmpEcho {
        msg_type: buf[0],
        code: buf[1],
        id: u16::from_be_bytes([buf[4], buf[5]]),
        seq: u16::from_be_bytes([buf[6], buf[7]]),
        payload: &buf[8..],
    })
}

pub fn build_icmp_echo(
    out: &mut [u8],
    msg_type: u8,
    id: u16,
    seq: u16,
    payload: &[u8],
) -> Option<usize> {
    let total = 8 + payload.len();
    if out.len() < total {
        return None;
    }
    out[0] = msg_type;
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
    out[4..6].copy_from_slice(&id.to_be_bytes());
    out[6..8].copy_from_slice(&seq.to_be_bytes());
    out[8..total].copy_from_slice(payload);
    let csum = internet_checksum(&out[..total]);
    out[2..4].copy_from_slice(&csum.to_be_bytes());
    Some(total)
}
