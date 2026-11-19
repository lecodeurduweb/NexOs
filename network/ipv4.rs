//! IPv4 Header Parser/Builder, Checksums, and Subnet Routing.

use super::eth::Ipv4Addr;

pub const IPV4_HEADER_LEN: usize = 20;
pub const IP_PROTO_ICMP: u8 = 1;
pub const IP_PROTO_TCP: u8 = 6;
pub const IP_PROTO_UDP: u8 = 17;

#[derive(Clone, Copy, Debug)]
pub struct Ipv4Packet<'a> {
    pub ihl: usize,
    pub total_len: usize,
    pub id: u16,
    pub ttl: u8,
    pub proto: u8,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub payload: &'a [u8],
}

pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn transport_checksum(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, payload: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    sum += u16::from_be_bytes([src.0[0], src.0[1]]) as u32;
    sum += u16::from_be_bytes([src.0[2], src.0[3]]) as u32;
    sum += u16::from_be_bytes([dst.0[0], dst.0[1]]) as u32;
    sum += u16::from_be_bytes([dst.0[2], dst.0[3]]) as u32;
    sum += proto as u32;
    sum += payload.len() as u32;

    let mut i = 0;
    while i + 1 < payload.len() {
        sum += u16::from_be_bytes([payload[i], payload[i + 1]]) as u32;
        i += 2;
    }
    if i < payload.len() {
        sum += (payload[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let res = !(sum as u16);
    if res == 0 && proto == IP_PROTO_UDP {
        0xFFFF
    } else {
        res
    }
}

pub fn parse_ipv4(buf: &[u8]) -> Option<Ipv4Packet<'_>> {
    if buf.len() < IPV4_HEADER_LEN {
        return None;
    }
    let ver = buf[0] >> 4;
    let ihl = ((buf[0] & 0x0F) as usize) * 4;
    if ver != 4 || ihl < IPV4_HEADER_LEN || buf.len() < ihl {
        return None;
    }
    let total_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if total_len < ihl || total_len > buf.len() {
        return None;
    }
    if internet_checksum(&buf[..ihl]) != 0 {
        return None;
    }
    let id = u16::from_be_bytes([buf[4], buf[5]]);
    let ttl = buf[8];
    let proto = buf[9];
    let src = Ipv4Addr([buf[12], buf[13], buf[14], buf[15]]);
    let dst = Ipv4Addr([buf[16], buf[17], buf[18], buf[19]]);
    Some(Ipv4Packet {
        ihl,
        total_len,
        id,
        ttl,
        proto,
        src,
        dst,
        payload: &buf[ihl..total_len],
    })
}

pub fn build_ipv4(
    out: &mut [u8],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: u8,
    id: u16,
    payload: &[u8],
) -> Option<usize> {
    let total = IPV4_HEADER_LEN + payload.len();
    if out.len() < total || total > 1500 {
        return None;
    }
    out[0] = 0x45;
    out[1] = 0;
    out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    out[4..6].copy_from_slice(&id.to_be_bytes());
    out[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // Don't Fragment
    out[8] = 64; // TTL
    out[9] = proto;
    out[10..12].copy_from_slice(&[0, 0]);
    out[12..16].copy_from_slice(&src.0);
    out[16..20].copy_from_slice(&dst.0);
    let csum = internet_checksum(&out[..IPV4_HEADER_LEN]);
    out[10..12].copy_from_slice(&csum.to_be_bytes());
    out[IPV4_HEADER_LEN..total].copy_from_slice(payload);
    Some(total)
}

/// Determine next-hop IPv4 address based on subnet mask and default gateway.
pub fn next_hop(local_ip: Ipv4Addr, mask: Ipv4Addr, gateway: Ipv4Addr, dst: Ipv4Addr) -> Ipv4Addr {
    if dst == Ipv4Addr::BROADCAST {
        return Ipv4Addr::BROADCAST;
    }
    let l = local_ip.to_u32();
    let m = mask.to_u32();
    let d = dst.to_u32();
    if m != 0 && (l & m) == (d & m) {
        dst
    } else if gateway != Ipv4Addr::UNSPECIFIED {
        gateway
    } else {
        dst
    }
}
