//! IPv6 Link-Local & ICMPv6 (Neighbor Discovery / Echo) Dual-Stack Support.
//!
//! Derives an RFC 4291 EUI-64 link-local address (`fe80::...`) from the NIC MAC,
//! parses/builds IPv6 packets (40-byte header), and handles ICMPv6 Neighbor
//! Solicitation & Echo Request/Reply with RFC 4443 checksum calculation.

use core::fmt;

use crate::network::eth::MacAddr;

pub const IPV6_HEADER_LEN: usize = 40;
pub const IP_PROTO_ICMPV6: u8 = 58;
pub const ICMPV6_ECHO_REQUEST: u8 = 128;
pub const ICMPV6_ECHO_REPLY: u8 = 129;
pub const ICMPV6_NEIGHBOR_SOLICIT: u8 = 135;
pub const ICMPV6_NEIGHBOR_ADVERT: u8 = 136;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ipv6Addr(pub [u8; 16]);

impl Ipv6Addr {
    pub const UNSPECIFIED: Self = Self([0; 16]);
    pub const ALL_NODES_MULTICAST: Self =
        Self([0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    /// Derive RFC 4291 link-local `fe80::` IPv6 address from a 48-bit MAC address.
    pub const fn from_eui64(mac: MacAddr) -> Self {
        let mut a = [0u8; 16];
        a[0] = 0xFE;
        a[1] = 0x80;
        a[8] = mac.0[0] ^ 0x02;
        a[9] = mac.0[1];
        a[10] = mac.0[2];
        a[11] = 0xFF;
        a[12] = 0xFE;
        a[13] = mac.0[3];
        a[14] = mac.0[4];
        a[15] = mac.0[5];
        Self(a)
    }

    pub const fn solicited_node_multicast(self) -> Self {
        Self([
            0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xFF, self.0[13], self.0[14], self.0[15],
        ])
    }

    pub const fn is_multicast(self) -> bool {
        self.0[0] == 0xFF
    }
}

impl fmt::Display for Ipv6Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for i in 0..8 {
            if i > 0 {
                f.write_str(":")?;
            }
            let w = u16::from_be_bytes([self.0[i * 2], self.0[i * 2 + 1]]);
            write!(f, "{:x}", w)?;
        }
        Ok(())
    }
}

pub struct Ipv6Packet<'a> {
    pub next_header: u8,
    pub hop_limit: u8,
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub payload: &'a [u8],
}

pub fn parse_ipv6(buf: &[u8]) -> Option<Ipv6Packet<'_>> {
    if buf.len() < IPV6_HEADER_LEN {
        return None;
    }
    let version = buf[0] >> 4;
    if version != 6 {
        return None;
    }
    let plen = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    if IPV6_HEADER_LEN + plen > buf.len() {
        return None;
    }
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&buf[8..24]);
    dst.copy_from_slice(&buf[24..40]);
    Some(Ipv6Packet {
        next_header: buf[6],
        hop_limit: buf[7],
        src: Ipv6Addr(src),
        dst: Ipv6Addr(dst),
        payload: &buf[IPV6_HEADER_LEN..IPV6_HEADER_LEN + plen],
    })
}

pub fn build_ipv6(
    out: &mut [u8],
    src: Ipv6Addr,
    dst: Ipv6Addr,
    next_header: u8,
    hop_limit: u8,
    payload: &[u8],
) -> Option<usize> {
    let total = IPV6_HEADER_LEN + payload.len();
    if out.len() < total || payload.len() > u16::MAX as usize {
        return None;
    }
    out[0..4].copy_from_slice(&[0x60, 0x00, 0x00, 0x00]); // Version=6
    out[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    out[6] = next_header;
    out[7] = hop_limit;
    out[8..24].copy_from_slice(&src.0);
    out[24..40].copy_from_slice(&dst.0);
    out[IPV6_HEADER_LEN..total].copy_from_slice(payload);
    Some(total)
}

pub fn icmpv6_checksum(src: Ipv6Addr, dst: Ipv6Addr, icmpv6_payload: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in src.0.chunks_exact(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    for chunk in dst.0.chunks_exact(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    let len = icmpv6_payload.len() as u32;
    sum += len >> 16;
    sum += len & 0xFFFF;
    sum += IP_PROTO_ICMPV6 as u32;

    let mut i = 0;
    while i + 1 < icmpv6_payload.len() {
        sum += u16::from_be_bytes([icmpv6_payload[i], icmpv6_payload[i + 1]]) as u32;
        i += 2;
    }
    if i < icmpv6_payload.len() {
        sum += (icmpv6_payload[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build an ICMPv6 Neighbor Advertisement or Echo Reply in `out`.
pub fn handle_icmpv6(
    our_ip6: Ipv6Addr,
    our_mac: MacAddr,
    pkt: &Ipv6Packet<'_>,
    out_buf: &mut [u8],
) -> Option<(Ipv6Addr, usize)> {
    let data = pkt.payload;
    if data.len() < 8 {
        return None;
    }
    match data[0] {
        ICMPV6_ECHO_REQUEST => {
            if out_buf.len() < data.len() {
                return None;
            }
            out_buf[..data.len()].copy_from_slice(data);
            out_buf[0] = ICMPV6_ECHO_REPLY;
            out_buf[1] = 0;
            out_buf[2] = 0;
            out_buf[3] = 0;
            let csum = icmpv6_checksum(our_ip6, pkt.src, &out_buf[..data.len()]);
            out_buf[2..4].copy_from_slice(&csum.to_be_bytes());
            Some((pkt.src, data.len()))
        }
        ICMPV6_NEIGHBOR_SOLICIT if data.len() >= 24 => {
            let mut target = [0u8; 16];
            target.copy_from_slice(&data[8..24]);
            if Ipv6Addr(target) != our_ip6 {
                return None;
            }
            // Build 32-byte Neighbor Advertisement (flags R=0, S=1, O=1 + Target Link-Layer Option)
            if out_buf.len() < 32 {
                return None;
            }
            out_buf[0..32].fill(0);
            out_buf[0] = ICMPV6_NEIGHBOR_ADVERT;
            out_buf[4] = 0x60; // Solicited + Override
            out_buf[8..24].copy_from_slice(&our_ip6.0);
            out_buf[24] = 2; // Option Type = Target Link-Layer Address
            out_buf[25] = 1; // Length = 1 (8 bytes)
            out_buf[26..32].copy_from_slice(&our_mac.0);
            let dst = if pkt.src == Ipv6Addr::UNSPECIFIED {
                Ipv6Addr::ALL_NODES_MULTICAST
            } else {
                pkt.src
            };
            let csum = icmpv6_checksum(our_ip6, dst, &out_buf[..32]);
            out_buf[2..4].copy_from_slice(&csum.to_be_bytes());
            Some((dst, 32))
        }
        _ => None,
    }
}

pub fn self_test() -> Result<(), &'static str> {
    let mac = MacAddr([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
    let ip6 = Ipv6Addr::from_eui64(mac);
    if ip6.0[0] != 0xFE || ip6.0[1] != 0x80 || ip6.0[8] != 0x50 || ip6.0[11] != 0xFF {
        return Err("EUI-64 derivation mismatch");
    }
    let mut buf = [0u8; 96];
    let payload = [ICMPV6_ECHO_REQUEST, 0, 0, 0, 0, 1, 0, 1, b'O', b'K'];
    let n = build_ipv6(&mut buf, ip6, Ipv6Addr::ALL_NODES_MULTICAST, IP_PROTO_ICMPV6, 64, &payload)
        .ok_or("build_ipv6 failed")?;
    let parsed = parse_ipv6(&buf[..n]).ok_or("parse_ipv6 failed")?;
    if parsed.next_header != IP_PROTO_ICMPV6 || parsed.payload != payload {
        return Err("IPv6 roundtrip mismatch");
    }
    let mut icmp_out = [0u8; 64];
    let (_, rlen) = handle_icmpv6(ip6, mac, &parsed, &mut icmp_out).ok_or("handle_icmpv6 failed")?;
    if rlen != payload.len() || icmp_out[0] != ICMPV6_ECHO_REPLY {
        return Err("ICMPv6 echo reply mismatch");
    }
    Ok(())
}
