//! DHCPv4 Client (Discover -> Offer -> Request -> Ack).

use super::eth::{Ipv4Addr, MacAddr};

pub const DHCP_CLIENT_PORT: u16 = 68;
pub const DHCP_SERVER_PORT: u16 = 67;
const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

pub const DHCP_DISCOVER: u8 = 1;
pub const DHCP_OFFER: u8 = 2;
pub const DHCP_REQUEST: u8 = 3;
pub const DHCP_ACK: u8 = 5;

#[derive(Clone, Copy, Debug)]
pub struct DhcpOffer {
    pub msg_type: u8,
    pub xid: u32,
    pub your_ip: Ipv4Addr,
    pub server_ip: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub router: Ipv4Addr,
    pub dns_server: Ipv4Addr,
    pub lease_secs: u32,
}

pub fn build_discover(out: &mut [u8], mac: MacAddr, xid: u32) -> Option<usize> {
    if out.len() < 300 {
        return None;
    }
    build_base(out, mac, xid);
    let mut off = 240;
    // Option 53: DHCP Message Type = Discover (1)
    out[off..off + 3].copy_from_slice(&[53, 1, DHCP_DISCOVER]);
    off += 3;
    // Option 55: Parameter Request List (1=Subnet, 3=Router, 6=DNS)
    out[off..off + 5].copy_from_slice(&[55, 3, 1, 3, 6]);
    off += 5;
    // Option 255: End
    out[off] = 255;
    off += 1;
    // Pad to 300 bytes (BOOTP min 300)
    while off < 300 {
        out[off] = 0;
        off += 1;
    }
    Some(off)
}

pub fn build_request(
    out: &mut [u8],
    mac: MacAddr,
    xid: u32,
    requested_ip: Ipv4Addr,
    server_ip: Ipv4Addr,
) -> Option<usize> {
    if out.len() < 300 {
        return None;
    }
    build_base(out, mac, xid);
    let mut off = 240;
    // Option 53: DHCP Message Type = Request (3)
    out[off..off + 3].copy_from_slice(&[53, 1, DHCP_REQUEST]);
    off += 3;
    // Option 50: Requested IP Address
    out[off] = 50;
    out[off + 1] = 4;
    out[off + 2..off + 6].copy_from_slice(&requested_ip.0);
    off += 6;
    // Option 54: Server Identifier
    out[off] = 54;
    out[off + 1] = 4;
    out[off + 2..off + 6].copy_from_slice(&server_ip.0);
    off += 6;
    // Option 255: End
    out[off] = 255;
    off += 1;
    while off < 300 {
        out[off] = 0;
        off += 1;
    }
    Some(off)
}

fn build_base(out: &mut [u8], mac: MacAddr, xid: u32) {
    for b in out.iter_mut().take(240) {
        *b = 0;
    }
    out[0] = 1; // BOOTREQUEST
    out[1] = 1; // Ethernet
    out[2] = 6; // HLEN
    out[3] = 0; // HOPS
    out[4..8].copy_from_slice(&xid.to_be_bytes());
    out[10..12].copy_from_slice(&0x8000u16.to_be_bytes()); // Broadcast flag
    out[28..34].copy_from_slice(&mac.0);
    out[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
}

pub fn parse_reply(buf: &[u8], expected_xid: u32) -> Option<DhcpOffer> {
    if buf.len() < 240 {
        return None;
    }
    if buf[0] != 2 {
        return None; // Not BOOTREPLY
    }
    let xid = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if xid != expected_xid {
        return None;
    }
    if buf[236..240] != DHCP_MAGIC_COOKIE {
        return None;
    }
    let your_ip = Ipv4Addr([buf[16], buf[17], buf[18], buf[19]]);
    let mut server_ip = Ipv4Addr([buf[20], buf[21], buf[22], buf[23]]);
    let mut subnet_mask = Ipv4Addr::new(255, 255, 255, 0);
    let mut router = Ipv4Addr::UNSPECIFIED;
    let mut dns_server = Ipv4Addr::UNSPECIFIED;
    let mut lease_secs = 3600u32;
    let mut msg_type = 0u8;

    let mut off = 240;
    while off < buf.len() {
        let code = buf[off];
        off += 1;
        if code == 0 {
            continue;
        }
        if code == 255 {
            break;
        }
        if off >= buf.len() {
            break;
        }
        let len = buf[off] as usize;
        off += 1;
        if off + len > buf.len() {
            break;
        }
        let val = &buf[off..off + len];
        match code {
            1 if len >= 4 => subnet_mask = Ipv4Addr([val[0], val[1], val[2], val[3]]),
            3 if len >= 4 => router = Ipv4Addr([val[0], val[1], val[2], val[3]]),
            6 if len >= 4 => dns_server = Ipv4Addr([val[0], val[1], val[2], val[3]]),
            51 if len >= 4 => lease_secs = u32::from_be_bytes([val[0], val[1], val[2], val[3]]),
            53 if len >= 1 => msg_type = val[0],
            54 if len >= 4 => server_ip = Ipv4Addr([val[0], val[1], val[2], val[3]]),
            _ => {}
        }
        off += len;
    }

    if msg_type == 0 {
        return None;
    }
    Some(DhcpOffer {
        msg_type,
        xid,
        your_ip,
        server_ip,
        subnet_mask,
        router,
        dns_server,
        lease_secs,
    })
}
