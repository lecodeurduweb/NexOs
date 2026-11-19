//! Ethernet II Framing & Address Primitives.

use core::fmt;

pub const ETH_HEADER_LEN: usize = 14;
pub const ETH_TYPE_IPV4: u16 = 0x0800;
pub const ETH_TYPE_ARP: u16 = 0x0806;
pub const ETH_TYPE_IPV6: u16 = 0x86DD;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const BROADCAST: Self = Self([0xFF; 6]);
    pub const ZERO: Self = Self([0; 6]);
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ipv4Addr(pub [u8; 4]);

impl Ipv4Addr {
    pub const UNSPECIFIED: Self = Self([0, 0, 0, 0]);
    pub const BROADCAST: Self = Self([255, 255, 255, 255]);

    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self([a, b, c, d])
    }

    pub const fn to_u32(self) -> u32 {
        u32::from_be_bytes(self.0)
    }

    pub const fn from_u32(v: u32) -> Self {
        Self(v.to_be_bytes())
    }

    pub fn parse(s: &str) -> Option<Self> {
        let mut octets = [0u8; 4];
        let mut count = 0usize;
        for part in s.split('.') {
            if count >= 4 || part.is_empty() {
                return None;
            }
            let val: u16 = part.parse().ok()?;
            if val > 255 {
                return None;
            }
            octets[count] = val as u8;
            count += 1;
        }
        if count == 4 {
            Some(Self(octets))
        } else {
            None
        }
    }
}

impl fmt::Display for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

pub struct EthFrame<'a> {
    pub dst: MacAddr,
    pub src: MacAddr,
    pub ethertype: u16,
    pub payload: &'a [u8],
}

pub fn parse_eth(buf: &[u8]) -> Option<EthFrame<'_>> {
    if buf.len() < ETH_HEADER_LEN {
        return None;
    }
    let mut dst = [0u8; 6];
    let mut src = [0u8; 6];
    dst.copy_from_slice(&buf[0..6]);
    src.copy_from_slice(&buf[6..12]);
    let ethertype = u16::from_be_bytes([buf[12], buf[13]]);
    Some(EthFrame {
        dst: MacAddr(dst),
        src: MacAddr(src),
        ethertype,
        payload: &buf[ETH_HEADER_LEN..],
    })
}

pub fn build_eth(out: &mut [u8], dst: MacAddr, src: MacAddr, ethertype: u16, payload: &[u8]) -> Option<usize> {
    let total = ETH_HEADER_LEN + payload.len();
    if out.len() < total {
        return None;
    }
    out[0..6].copy_from_slice(&dst.0);
    out[6..12].copy_from_slice(&src.0);
    out[12..14].copy_from_slice(&ethertype.to_be_bytes());
    out[ETH_HEADER_LEN..total].copy_from_slice(payload);
    // Pad Ethernet payload to minimum 60 bytes (before FCS)
    if total < 60 && out.len() >= 60 {
        for b in &mut out[total..60] {
            *b = 0;
        }
        Some(60)
    } else {
        Some(total)
    }
}
