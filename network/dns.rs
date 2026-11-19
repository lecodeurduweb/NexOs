//! DNS (RFC 1035) UDP A-Record Resolver.

use super::eth::Ipv4Addr;

pub const DNS_PORT: u16 = 53;

#[derive(Clone, Copy, Debug)]
pub struct DnsAnswer {
    pub txid: u16,
    pub ip: Ipv4Addr,
    pub ttl: u32,
}

/// Build a DNS standard query for an `A` record (`IN`).
pub fn build_query(out: &mut [u8], txid: u16, hostname: &str) -> Option<usize> {
    if out.len() < 20 || hostname.is_empty() || hostname.len() > 250 {
        return None;
    }
    // 12-byte DNS header
    out[0..2].copy_from_slice(&txid.to_be_bytes());
    out[2..4].copy_from_slice(&0x0100u16.to_be_bytes()); // RD=1
    out[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    out[6..8].copy_from_slice(&0u16.to_be_bytes());
    out[8..10].copy_from_slice(&0u16.to_be_bytes());
    out[10..12].copy_from_slice(&0u16.to_be_bytes());

    let mut off = 12usize;
    for label in hostname.trim_end_matches('.').split('.') {
        let lb = label.as_bytes();
        if lb.is_empty() || lb.len() > 63 || off + 1 + lb.len() + 5 > out.len() {
            return None;
        }
        out[off] = lb.len() as u8;
        off += 1;
        out[off..off + lb.len()].copy_from_slice(lb);
        off += lb.len();
    }
    out[off] = 0; // root label
    off += 1;
    out[off..off + 2].copy_from_slice(&1u16.to_be_bytes()); // QTYPE = A (1)
    out[off + 2..off + 4].copy_from_slice(&1u16.to_be_bytes()); // QCLASS = IN (1)
    off += 4;
    Some(off)
}

fn skip_dns_name(buf: &[u8], mut off: usize) -> Option<usize> {
    let mut jumps = 0usize;
    while off < buf.len() {
        let b = buf[off];
        if (b & 0xC0) == 0xC0 {
            if off + 2 > buf.len() {
                return None;
            }
            return Some(off + 2);
        } else if b == 0 {
            return Some(off + 1);
        } else if (b & 0xC0) != 0 {
            return None;
        } else {
            let len = b as usize;
            if len > 63 || off + 1 + len > buf.len() {
                return None;
            }
            off += 1 + len;
            jumps += 1;
            if jumps > 64 {
                return None;
            }
        }
    }
    None
}

fn parse_dns_qname(buf: &[u8], mut off: usize) -> Option<(alloc::string::String, usize)> {
    let mut name = alloc::string::String::new();
    let mut jumped = false;
    let mut end_off = 0usize;
    let mut steps = 0usize;

    while off < buf.len() {
        let b = buf[off];
        if (b & 0xC0) == 0xC0 {
            if off + 2 > buf.len() {
                return None;
            }
            if !jumped {
                end_off = off + 2;
                jumped = true;
            }
            let ptr = (((b & 0x3F) as usize) << 8) | (buf[off + 1] as usize);
            if ptr >= buf.len() {
                return None;
            }
            off = ptr;
        } else if b == 0 {
            if !jumped {
                end_off = off + 1;
            }
            return Some((name, end_off));
        } else {
            let len = b as usize;
            if len > 63 || off + 1 + len > buf.len() {
                return None;
            }
            if !name.is_empty() {
                name.push('.');
            }
            let lbl = core::str::from_utf8(&buf[off + 1..off + 1 + len]).ok()?;
            name.push_str(lbl);
            off += 1 + len;
        }
        steps += 1;
        if steps > 64 {
            return None;
        }
    }
    None
}

/// Parse DNS response packet and extract the first `A` (IPv4) record matching
/// `expected_txid` and optional `expected_host`.
pub fn parse_response_for(
    buf: &[u8],
    expected_txid: u16,
    expected_host: Option<&str>,
) -> Option<DnsAnswer> {
    if buf.len() < 12 {
        return None;
    }
    let txid = u16::from_be_bytes([buf[0], buf[1]]);
    if txid != expected_txid {
        return None;
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if (flags & 0x8000) == 0 || (flags & 0x000F) != 0 {
        return None; // Not a response or RCODE != NOERROR
    }
    let qdcount = (u16::from_be_bytes([buf[4], buf[5]]) as usize).min(16);
    let ancount = (u16::from_be_bytes([buf[6], buf[7]]) as usize).min(32);

    let mut off = 12usize;
    let mut question_matched = expected_host.is_none();
    for _ in 0..qdcount {
        let (qname, next_off) = parse_dns_qname(buf, off)?;
        off = next_off;
        if off + 4 > buf.len() {
            return None;
        }
        if let Some(exp) = expected_host {
            if qname.eq_ignore_ascii_case(exp.trim_end_matches('.')) {
                question_matched = true;
            }
        }
        off += 4; // QTYPE + QCLASS
    }
    if !question_matched {
        return None;
    }

    for _ in 0..ancount {
        off = skip_dns_name(buf, off)?;
        if off + 10 > buf.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([buf[off], buf[off + 1]]);
        let rclass = u16::from_be_bytes([buf[off + 2], buf[off + 3]]);
        let ttl = u32::from_be_bytes([buf[off + 4], buf[off + 5], buf[off + 6], buf[off + 7]]);
        let rdlen = u16::from_be_bytes([buf[off + 8], buf[off + 9]]) as usize;
        off += 10;
        if off + rdlen > buf.len() {
            return None;
        }
        if rtype == 1 && rclass == 1 && rdlen == 4 {
            let ip = Ipv4Addr([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
            return Some(DnsAnswer { txid, ip, ttl });
        }
        off += rdlen;
    }
    None
}

pub fn parse_response(buf: &[u8], expected_txid: u16) -> Option<DnsAnswer> {
    parse_response_for(buf, expected_txid, None)
}
