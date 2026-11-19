//! ARP (Address Resolution Protocol) Cache & Pending Packet Queue.

use alloc::vec::Vec;

use super::eth::{Ipv4Addr, MacAddr};

pub const ARP_PACKET_LEN: usize = 28;
const ARP_OP_REQUEST: u16 = 1;
const ARP_OP_REPLY: u16 = 2;
const ARP_CACHE_SIZE: usize = 16;

#[derive(Clone, Copy)]
pub struct ArpEntry {
    pub ip: Ipv4Addr,
    pub mac: MacAddr,
    pub valid: bool,
    pub updated_ms: u64,
}

impl ArpEntry {
    const fn empty() -> Self {
        Self {
            ip: Ipv4Addr::UNSPECIFIED,
            mac: MacAddr::ZERO,
            valid: false,
            updated_ms: 0,
        }
    }
}

pub struct PendingIpPacket {
    pub next_hop: Ipv4Addr,
    pub ip_bytes: Vec<u8>,
}

pub struct ArpTable {
    entries: [ArpEntry; ARP_CACHE_SIZE],
    pending: Vec<PendingIpPacket>,
}

impl ArpTable {
    pub const fn new() -> Self {
        Self {
            entries: [ArpEntry::empty(); ARP_CACHE_SIZE],
            pending: Vec::new(),
        }
    }

    pub fn lookup(&self, ip: Ipv4Addr) -> Option<MacAddr> {
        for e in &self.entries {
            if e.valid && e.ip == ip {
                return Some(e.mac);
            }
        }
        None
    }

    pub fn insert(&mut self, ip: Ipv4Addr, mac: MacAddr, now_ms: u64) {
        if ip == Ipv4Addr::UNSPECIFIED
            || ip == Ipv4Addr::BROADCAST
            || !is_valid_unicast_mac(mac)
        {
            return;
        }
        for e in &mut self.entries {
            if e.valid && e.ip == ip {
                e.mac = mac;
                e.updated_ms = now_ms;
                return;
            }
        }
        let mut slot = 0usize;
        let mut oldest = u64::MAX;
        for (i, e) in self.entries.iter().enumerate() {
            if !e.valid {
                slot = i;
                break;
            }
            if e.updated_ms < oldest {
                oldest = e.updated_ms;
                slot = i;
            }
        }
        self.entries[slot] = ArpEntry {
            ip,
            mac,
            valid: true,
            updated_ms: now_ms,
        };
    }

    pub fn queue_pending(&mut self, next_hop: Ipv4Addr, ip_packet: &[u8]) {
        if self.pending.len() >= 8 {
            self.pending.remove(0);
        }
        self.pending.push(PendingIpPacket {
            next_hop,
            ip_bytes: ip_packet.to_vec(),
        });
    }

    pub fn drain_ready(&mut self, resolved_ip: Ipv4Addr) -> Vec<Vec<u8>> {
        let mut ready = Vec::new();
        let mut idx = 0usize;
        while idx < self.pending.len() {
            if self.pending[idx].next_hop == resolved_ip {
                ready.push(self.pending.remove(idx).ip_bytes);
            } else {
                idx += 1;
            }
        }
        ready
    }

    pub fn entries(&self) -> &[ArpEntry] {
        &self.entries
    }
}

pub fn is_valid_unicast_mac(mac: MacAddr) -> bool {
    mac != MacAddr::ZERO && (mac.0[0] & 0x01) == 0
}

pub struct ArpPacket {
    pub op: u16,
    pub sender_mac: MacAddr,
    pub sender_ip: Ipv4Addr,
    pub target_mac: MacAddr,
    pub target_ip: Ipv4Addr,
}

pub fn parse_arp(buf: &[u8]) -> Option<ArpPacket> {
    if buf.len() < ARP_PACKET_LEN {
        return None;
    }
    let htype = u16::from_be_bytes([buf[0], buf[1]]);
    let ptype = u16::from_be_bytes([buf[2], buf[3]]);
    if htype != 1 || ptype != 0x0800 || buf[4] != 6 || buf[5] != 4 {
        return None;
    }
    let op = u16::from_be_bytes([buf[6], buf[7]]);
    let mut smac = [0u8; 6];
    let mut sip = [0u8; 4];
    let mut tmac = [0u8; 6];
    let mut tip = [0u8; 4];
    smac.copy_from_slice(&buf[8..14]);
    sip.copy_from_slice(&buf[14..18]);
    tmac.copy_from_slice(&buf[18..24]);
    tip.copy_from_slice(&buf[24..28]);
    Some(ArpPacket {
        op,
        sender_mac: MacAddr(smac),
        sender_ip: Ipv4Addr(sip),
        target_mac: MacAddr(tmac),
        target_ip: Ipv4Addr(tip),
    })
}

pub fn build_arp_request(out: &mut [u8], src_mac: MacAddr, src_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Option<usize> {
    build_arp(out, ARP_OP_REQUEST, src_mac, src_ip, MacAddr::ZERO, target_ip)
}

pub fn build_arp_reply(
    out: &mut [u8],
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    target_mac: MacAddr,
    target_ip: Ipv4Addr,
) -> Option<usize> {
    build_arp(out, ARP_OP_REPLY, src_mac, src_ip, target_mac, target_ip)
}

fn build_arp(
    out: &mut [u8],
    op: u16,
    smac: MacAddr,
    sip: Ipv4Addr,
    tmac: MacAddr,
    tip: Ipv4Addr,
) -> Option<usize> {
    if out.len() < ARP_PACKET_LEN {
        return None;
    }
    out[0..2].copy_from_slice(&1u16.to_be_bytes()); // Ethernet
    out[2..4].copy_from_slice(&0x0800u16.to_be_bytes()); // IPv4
    out[4] = 6;
    out[5] = 4;
    out[6..8].copy_from_slice(&op.to_be_bytes());
    out[8..14].copy_from_slice(&smac.0);
    out[14..18].copy_from_slice(&sip.0);
    out[18..24].copy_from_slice(&tmac.0);
    out[24..28].copy_from_slice(&tip.0);
    Some(ARP_PACKET_LEN)
}
