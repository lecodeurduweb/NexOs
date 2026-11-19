//! UDP Header Parser & Builder.

use super::eth::Ipv4Addr;
use super::ipv4::{transport_checksum, IP_PROTO_UDP};

pub const UDP_HEADER_LEN: usize = 8;

pub struct UdpPacket<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

pub fn parse_udp(buf: &[u8]) -> Option<UdpPacket<'_>> {
    if buf.len() < UDP_HEADER_LEN {
        return None;
    }
    let src_port = u16::from_be_bytes([buf[0], buf[1]]);
    let dst_port = u16::from_be_bytes([buf[2], buf[3]]);
    let len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    if len < UDP_HEADER_LEN || len > buf.len() {
        return None;
    }
    Some(UdpPacket {
        src_port,
        dst_port,
        payload: &buf[UDP_HEADER_LEN..len],
    })
}

pub fn build_udp(
    out: &mut [u8],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<usize> {
    let total = UDP_HEADER_LEN + payload.len();
    if out.len() < total || total > 1480 {
        return None;
    }
    out[0..2].copy_from_slice(&src_port.to_be_bytes());
    out[2..4].copy_from_slice(&dst_port.to_be_bytes());
    out[4..6].copy_from_slice(&(total as u16).to_be_bytes());
    out[6..8].copy_from_slice(&[0, 0]);
    out[UDP_HEADER_LEN..total].copy_from_slice(payload);
    let csum = transport_checksum(src_ip, dst_ip, IP_PROTO_UDP, &out[..total]);
    out[6..8].copy_from_slice(&csum.to_be_bytes());
    Some(total)
}
