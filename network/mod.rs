//! NexOS Independent Network Stack (Ethernet II, ARP, IPv4, ICMP, UDP, DHCP, DNS, TCP).

pub mod arp;
pub mod dhcp;
pub mod dns;
pub mod eth;
pub mod icmp;
pub mod ipv4;
pub mod ipv6;
pub mod tcp;
pub mod tls;
pub mod udp;

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::arch::timer;
use crate::drivers::dtb::DeviceTreeInfo;
use crate::drivers::net::NetDevice;
use crate::drivers::virtio::net::VirtioNet;
use crate::klog;
use crate::log::LogLevel;
use crate::scheduler;
use crate::sync::SpinLock;

use arp::{build_arp_reply, build_arp_request, is_valid_unicast_mac, parse_arp, ArpTable};
use dhcp::{
    build_discover, build_request, parse_reply, DhcpOffer, DHCP_ACK, DHCP_CLIENT_PORT, DHCP_OFFER,
    DHCP_SERVER_PORT,
};
use dns::{build_query, parse_response_for, DnsAnswer, DNS_PORT};
use eth::{build_eth, parse_eth, Ipv4Addr, MacAddr, ETH_TYPE_ARP, ETH_TYPE_IPV4, ETH_TYPE_IPV6};
use icmp::{
    build_icmp_echo, parse_icmp, PingReplyRecord, ICMP_TYPE_ECHO_REPLY, ICMP_TYPE_ECHO_REQUEST,
};
use ipv4::{
    build_ipv4, next_hop, parse_ipv4, IP_PROTO_ICMP, IP_PROTO_TCP, IP_PROTO_UDP,
};
use ipv6::{build_ipv6, handle_icmpv6, parse_ipv6, Ipv6Addr, IP_PROTO_ICMPV6};
use tcp::{build_tcp, parse_tcp, OutgoingTcpSegment, TcpState, TcpTable};
use udp::{build_udp, parse_udp};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigSource {
    Unconfigured,
    Dhcp,
    StaticFallback,
}

#[derive(Clone, Copy, Debug)]
pub struct PingResult {
    pub seq: u16,
    pub rtt_us: u64,
    pub ttl: u8,
    pub bytes: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct NetStats {
    pub initialized: bool,
    pub mac: MacAddr,
    pub ip: Ipv4Addr,
    pub link_local_ipv6: Ipv6Addr,
    pub mask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub dns: Ipv4Addr,
    pub config_source: ConfigSource,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

struct NetStack {
    dev: Box<dyn NetDevice>,
    mac: MacAddr,
    ip: Ipv4Addr,
    ip6: Ipv6Addr,
    mask: Ipv4Addr,
    gateway: Ipv4Addr,
    dns: Ipv4Addr,
    config_source: ConfigSource,
    arp: ArpTable,
    tcp: TcpTable,
    ip_id: u16,
    rx_packets: u64,
    tx_packets: u64,
    rx_bytes: u64,
    tx_bytes: u64,
    last_dhcp_offer: Option<DhcpOffer>,
    last_dns_answer: Option<DnsAnswer>,
    expected_dns_port: u16,
    expected_dns_host: Option<String>,
    last_ping_reply: PingReplyRecord,
}

impl NetStack {
    fn new(dev: Box<dyn NetDevice>) -> Self {
        let mac = MacAddr(dev.mac_addr());
        let ip6 = Ipv6Addr::from_eui64(mac);
        Self {
            dev,
            mac,
            ip: Ipv4Addr::UNSPECIFIED,
            ip6,
            mask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: Ipv4Addr::UNSPECIFIED,
            dns: Ipv4Addr::UNSPECIFIED,
            config_source: ConfigSource::Unconfigured,
            arp: ArpTable::new(),
            tcp: TcpTable::new(),
            ip_id: 1,
            rx_packets: 0,
            tx_packets: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            last_dhcp_offer: None,
            last_dns_answer: None,
            expected_dns_port: 0,
            expected_dns_host: None,
            last_ping_reply: PingReplyRecord::empty(),
        }
    }

    fn send_eth_raw(&mut self, dst_mac: MacAddr, ethertype: u16, payload: &[u8]) {
        let mut frame = [0u8; 1600];
        if let Some(len) = build_eth(&mut frame, dst_mac, self.mac, ethertype, payload) {
            if self.dev.send_frame(&frame[..len]).is_ok() {
                self.tx_packets += 1;
                self.tx_bytes += len as u64;
            }
        }
    }

    fn send_arp_request_for(&mut self, target_ip: Ipv4Addr) {
        let mut pkt = [0u8; 32];
        if let Some(n) = build_arp_request(&mut pkt, self.mac, self.ip, target_ip) {
            self.send_eth_raw(MacAddr::BROADCAST, ETH_TYPE_ARP, &pkt[..n]);
        }
    }

    fn send_ip_packet(&mut self, dst_ip: Ipv4Addr, proto: u8, payload: &[u8]) {
        let mut ip_pkt = [0u8; 1514];
        let id = self.ip_id;
        self.ip_id = self.ip_id.wrapping_add(1);
        let Some(ip_len) = build_ipv4(&mut ip_pkt, self.ip, dst_ip, proto, id, payload) else {
            return;
        };

        if dst_ip == Ipv4Addr::BROADCAST {
            self.send_eth_raw(MacAddr::BROADCAST, ETH_TYPE_IPV4, &ip_pkt[..ip_len]);
            return;
        }

        let nh = next_hop(self.ip, self.mask, self.gateway, dst_ip);
        if let Some(dst_mac) = self.arp.lookup(nh) {
            self.send_eth_raw(dst_mac, ETH_TYPE_IPV4, &ip_pkt[..ip_len]);
        } else {
            self.arp.queue_pending(nh, &ip_pkt[..ip_len]);
            self.send_arp_request_for(nh);
        }
    }

    fn send_tcp_segments(&mut self, segs: Vec<OutgoingTcpSegment>) {
        let mut buf = [0u8; 1500];
        for s in segs {
            if let Some(n) = build_tcp(
                &mut buf,
                self.ip,
                s.dst_ip,
                s.src_port,
                s.dst_port,
                s.seq,
                s.ack,
                s.flags,
                32768,
                &s.payload,
            ) {
                self.send_ip_packet(s.dst_ip, IP_PROTO_TCP, &buf[..n]);
            }
        }
    }

    fn send_udp_packet(&mut self, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16, payload: &[u8]) {
        let mut buf = [0u8; 1500];
        if let Some(n) = build_udp(&mut buf, self.ip, dst_ip, src_port, dst_port, payload) {
            self.send_ip_packet(dst_ip, IP_PROTO_UDP, &buf[..n]);
        }
    }

    fn flush_arp_pending(&mut self, resolved_ip: Ipv4Addr, mac: MacAddr) {
        if resolved_ip == Ipv4Addr::UNSPECIFIED || !is_valid_unicast_mac(mac) {
            return;
        }
        let ready = self.arp.drain_ready(resolved_ip);
        for ip_pkt in ready {
            self.send_eth_raw(mac, ETH_TYPE_IPV4, &ip_pkt);
        }
    }

    fn handle_frame(&mut self, frame: &[u8]) {
        let now_ms = timer::uptime_ms();
        let Some(eth) = parse_eth(frame) else {
            return;
        };
        let is_ipv6_mcast = eth.ethertype == ETH_TYPE_IPV6 && eth.dst.0[0] == 0x33 && eth.dst.0[1] == 0x33;
        if eth.dst != self.mac && eth.dst != MacAddr::BROADCAST && !is_ipv6_mcast {
            return;
        }

        match eth.ethertype {
            ETH_TYPE_ARP => {
                if let Some(arp) = parse_arp(eth.payload) {
                    if !is_valid_unicast_mac(arp.sender_mac)
                        || arp.sender_ip == Ipv4Addr::UNSPECIFIED
                        || (self.ip != Ipv4Addr::UNSPECIFIED && arp.sender_ip == self.ip)
                    {
                        return;
                    }
                    self.arp.insert(arp.sender_ip, arp.sender_mac, now_ms);
                    self.flush_arp_pending(arp.sender_ip, arp.sender_mac);
                    if arp.op == 1 && arp.target_ip == self.ip && self.ip != Ipv4Addr::UNSPECIFIED {
                        let mut reply = [0u8; 32];
                        if let Some(n) = build_arp_reply(
                            &mut reply,
                            self.mac,
                            self.ip,
                            arp.sender_mac,
                            arp.sender_ip,
                        ) {
                            self.send_eth_raw(arp.sender_mac, ETH_TYPE_ARP, &reply[..n]);
                        }
                    }
                }
            }
            ETH_TYPE_IPV4 => {
                let Some(ip) = parse_ipv4(eth.payload) else {
                    return;
                };
                // Opportunistically learn sender MAC ONLY for on-subnet sources (never spoof gateway MAC from off-subnet packets)
                if is_valid_unicast_mac(eth.src)
                    && ip.src != Ipv4Addr::UNSPECIFIED
                    && ip.src != self.ip
                {
                    let nh = next_hop(self.ip, self.mask, self.gateway, ip.src);
                    if nh == ip.src {
                        self.arp.insert(ip.src, eth.src, now_ms);
                        self.flush_arp_pending(ip.src, eth.src);
                    }
                }

                // Allow broadcast/unconfigured packets for DHCP; otherwise require our IP
                if self.ip != Ipv4Addr::UNSPECIFIED
                    && ip.dst != self.ip
                    && ip.dst != Ipv4Addr::BROADCAST
                {
                    return;
                }

                match ip.proto {
                    IP_PROTO_ICMP => {
                        if let Some(icmp) = parse_icmp(ip.payload) {
                            if icmp.msg_type == ICMP_TYPE_ECHO_REQUEST && self.ip != Ipv4Addr::UNSPECIFIED {
                                let mut out = [0u8; 1480];
                                if let Some(n) = build_icmp_echo(
                                    &mut out,
                                    ICMP_TYPE_ECHO_REPLY,
                                    icmp.id,
                                    icmp.seq,
                                    icmp.payload,
                                ) {
                                    self.send_ip_packet(ip.src, IP_PROTO_ICMP, &out[..n]);
                                }
                            } else if icmp.msg_type == ICMP_TYPE_ECHO_REPLY {
                                self.last_ping_reply = PingReplyRecord {
                                    valid: true,
                                    src: ip.src,
                                    id: icmp.id,
                                    seq: icmp.seq,
                                    recv_cntpct: timer::read_cntpct(),
                                    ttl: ip.ttl,
                                    payload_len: icmp.payload.len(),
                                };
                            }
                        }
                    }
                    IP_PROTO_UDP => {
                        if let Some(udp) = parse_udp(ip.payload) {
                            if udp.dst_port == DHCP_CLIENT_PORT && udp.src_port == DHCP_SERVER_PORT {
                                if let Some(offer) = parse_reply(udp.payload, 0x4E45_5831) {
                                    self.last_dhcp_offer = Some(offer);
                                }
                            } else if udp.src_port == DNS_PORT
                                && self.expected_dns_port != 0
                                && udp.dst_port == self.expected_dns_port
                            {
                                if udp.payload.len() >= 12 {
                                    let txid = u16::from_be_bytes([udp.payload[0], udp.payload[1]]);
                                    if let Some(ans) = parse_response_for(
                                        udp.payload,
                                        txid,
                                        self.expected_dns_host.as_deref(),
                                    ) {
                                        self.last_dns_answer = Some(ans);
                                    }
                                }
                            }
                        }
                    }
                    IP_PROTO_TCP => {
                        if let Some(seg) = parse_tcp(ip.payload, ip.src, ip.dst) {
                            let out = self.tcp.on_segment(ip.src, &seg, now_ms);
                            self.send_tcp_segments(out);
                        }
                    }
                    _ => {}
                }
            }
            ETH_TYPE_IPV6 => {
                if let Some(pkt) = parse_ipv6(eth.payload) {
                    let for_us = pkt.dst == self.ip6
                        || pkt.dst == self.ip6.solicited_node_multicast()
                        || pkt.dst == Ipv6Addr::ALL_NODES_MULTICAST;
                    if for_us && pkt.next_header == IP_PROTO_ICMPV6 {
                        let mut icmp_out = [0u8; 1280];
                        if let Some((dst6, ilen)) =
                            handle_icmpv6(self.ip6, self.mac, &pkt, &mut icmp_out)
                        {
                            let mut ip6_pkt = [0u8; 1340];
                            if let Some(plen) = build_ipv6(
                                &mut ip6_pkt,
                                self.ip6,
                                dst6,
                                IP_PROTO_ICMPV6,
                                64,
                                &icmp_out[..ilen],
                            ) {
                                self.send_eth_raw(eth.src, ETH_TYPE_IPV6, &ip6_pkt[..plen]);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn poll_locked(&mut self) {
        let mut rx_buf = [0u8; 2048];
        for _ in 0..16 {
            if let Some(len) = self.dev.recv_frame(&mut rx_buf) {
                self.rx_packets += 1;
                self.rx_bytes += len as u64;
                self.handle_frame(&rx_buf[..len]);
            } else {
                break;
            }
        }
        let now_ms = timer::uptime_ms();
        let retx = self.tcp.tick(now_ms);
        if !retx.is_empty() {
            self.send_tcp_segments(retx);
        }
    }
}

static NET_STACK: SpinLock<Option<NetStack>> = SpinLock::new(None);

/// Probe board NIC (VirtIO-Net on QEMU `virt`, or GENET v5 on Raspberry Pi 4),
/// run IPv6 + mock GENET checks, perform DHCP discovery (with static fallback),
/// and start TCP Echo service + net-poll task.
pub fn init(dtb: &DeviceTreeInfo) -> bool {
    match ipv6::self_test() {
        Ok(()) => klog!(LogLevel::Info, "net", "IPv6 link-local & ICMPv6 self-test OK"),
        Err(e) => klog!(LogLevel::Error, "net", "IPv6 self-test failed: {}", e),
    }
    match crate::drivers::net::genet::self_test_mock() {
        Ok(()) => klog!(
            LogLevel::Info,
            "genet",
            "[mock] BCM2711 GENET v5 MMIO ring & MAC self-test OK"
        ),
        Err(e) => klog!(LogLevel::Error, "genet", "[mock] GENET self-test failed: {:?}", e),
    }
    match tls::self_test() {
        Ok(()) => klog!(
            LogLevel::Info,
            "tls",
            "TLS 1.3 crypto self-test OK (SHA-512, HKDF, ChaCha20-Poly1305, X25519, Ed25519)"
        ),
        Err(e) => panic!("TLS 1.3 crypto self-test failed: {}", e),
    }

    #[allow(unused_mut)]
    let mut dev: Option<Box<dyn NetDevice>> = None;

    if let Some(vnet) = VirtioNet::probe(dtb) {
        dev = Some(Box::new(vnet));
    }

    #[cfg(feature = "board-rpi4")]
    if dev.is_none() {
        if let Some(genet_base) = dtb.genet_base {
            let mut genet = crate::drivers::net::genet::Bcm2711Genet::new(genet_base as usize);
            if let Some(m) = dtb.genet_mac {
                genet.set_mac_addr(m);
            }
            if genet.init().is_ok() {
                dev = Some(Box::new(genet));
            }
        }
    }

    let Some(nic) = dev else {
        klog!(LogLevel::Info, "net", "No network interface detected.");
        return false;
    };

    let mac = MacAddr(nic.mac_addr());
    {
        let mut guard = NET_STACK.lock();
        *guard = Some(NetStack::new(nic));
    }

    // Attempt DHCPv4 configuration (Discover -> Offer -> Request -> Ack)
    let dhcp_ok = try_dhcp(800);
    if !dhcp_ok {
        let mut guard = NET_STACK.lock();
        if let Some(st) = guard.as_mut() {
            st.ip = Ipv4Addr::new(10, 77, 0, 2);
            st.mask = Ipv4Addr::new(255, 255, 255, 0);
            st.gateway = Ipv4Addr::new(10, 77, 0, 1);
            st.dns = Ipv4Addr::new(10, 77, 0, 1);
            st.config_source = ConfigSource::StaticFallback;
            // Announce presence with gratuitous ARP
            let mut garp = [0u8; 32];
            if let Some(n) = build_arp_request(&mut garp, st.mac, st.ip, st.gateway) {
                st.send_eth_raw(MacAddr::BROADCAST, ETH_TYPE_ARP, &garp[..n]);
            }
        }
    }

    // Start built-in TCP Echo listener on port 7070 for Stage 11 validation
    let _ = tcp_listen_mode(7070, true);

    let st = stats();
    klog!(
        LogLevel::Info,
        "net",
        "Network ready ({:?}): MAC={} IP={} IPv6={} MASK={} GW={} DNS={} | TCP Echo :7070",
        st.config_source,
        mac,
        st.ip,
        st.link_local_ipv6,
        st.mask,
        st.gateway,
        st.dns
    );

    // Spawn background polling thread
    scheduler::spawn_kernel("net-poll", 160, net_poll_worker, 0);
    true
}

fn net_poll_worker(_: usize) -> ! {
    loop {
        poll();
        scheduler::sleep_ms(10);
    }
}

pub fn poll() {
    let mut guard = NET_STACK.lock();
    if let Some(st) = guard.as_mut() {
        st.poll_locked();
    }
}

pub fn try_dhcp(timeout_ms: u64) -> bool {
    let xid = 0x4E45_5831u32;
    {
        let mut guard = NET_STACK.lock();
        let Some(st) = guard.as_mut() else {
            return false;
        };
        st.last_dhcp_offer = None;
        let mut pkt = [0u8; 320];
        if let Some(n) = build_discover(&mut pkt, st.mac, xid) {
            st.send_udp_packet(Ipv4Addr::BROADCAST, DHCP_CLIENT_PORT, DHCP_SERVER_PORT, &pkt[..n]);
        }
    }

    let deadline = timer::uptime_ms() + timeout_ms;
    let mut offer_opt = None;
    let mut retried = false;
    let half = timer::uptime_ms() + timeout_ms / 2;

    while timer::uptime_ms() < deadline {
        {
            let mut guard = NET_STACK.lock();
            if let Some(st) = guard.as_mut() {
                st.poll_locked();
                if let Some(off) = st.last_dhcp_offer.take() {
                    if off.msg_type == DHCP_OFFER {
                        offer_opt = Some(off);
                        break;
                    }
                }
                if !retried && timer::uptime_ms() >= half {
                    retried = true;
                    let mut pkt = [0u8; 320];
                    if let Some(n) = build_discover(&mut pkt, st.mac, xid) {
                        st.send_udp_packet(
                            Ipv4Addr::BROADCAST,
                            DHCP_CLIENT_PORT,
                            DHCP_SERVER_PORT,
                            &pkt[..n],
                        );
                    }
                }
            }
        }
        scheduler::sleep_ms(10);
    }

    let Some(offer) = offer_opt else {
        return false;
    };

    {
        let mut guard = NET_STACK.lock();
        if let Some(st) = guard.as_mut() {
            st.last_dhcp_offer = None;
            let mut pkt = [0u8; 320];
            if let Some(n) = build_request(&mut pkt, st.mac, xid, offer.your_ip, offer.server_ip) {
                st.send_udp_packet(
                    Ipv4Addr::BROADCAST,
                    DHCP_CLIENT_PORT,
                    DHCP_SERVER_PORT,
                    &pkt[..n],
                );
            }
        }
    }

    let ack_deadline = timer::uptime_ms() + 800;
    while timer::uptime_ms() < ack_deadline {
        {
            let mut guard = NET_STACK.lock();
            if let Some(st) = guard.as_mut() {
                st.poll_locked();
                if let Some(ack) = st.last_dhcp_offer.take() {
                    if ack.msg_type == DHCP_ACK {
                        st.ip = ack.your_ip;
                        st.mask = ack.subnet_mask;
                        st.gateway = if ack.router != Ipv4Addr::UNSPECIFIED {
                            ack.router
                        } else {
                            offer.router
                        };
                        st.dns = if ack.dns_server != Ipv4Addr::UNSPECIFIED {
                            ack.dns_server
                        } else {
                            st.gateway
                        };
                        st.config_source = ConfigSource::Dhcp;
                        klog!(
                            LogLevel::Info,
                            "dhcp",
                            "DHCP ACK lease={} IP={} gw={} dns={} (lease {}s)",
                            ack.server_ip,
                            st.ip,
                            st.gateway,
                            st.dns,
                            ack.lease_secs
                        );
                        return true;
                    }
                }
            }
        }
        scheduler::sleep_ms(10);
    }
    false
}

pub fn ping(dst: Ipv4Addr, count: u16, timeout_ms: u64) -> Vec<PingResult> {
    let mut results = Vec::new();
    let freq = timer::read_cntfrq().max(1);
    let ping_id = 0x4E58u16;

    for seq in 1..=count {
        let send_cnt = timer::read_cntpct();
        {
            let mut guard = NET_STACK.lock();
            let Some(st) = guard.as_mut() else {
                break;
            };
            st.last_ping_reply.valid = false;
            let mut out = [0u8; 64];
            let payload = b"NexOS-ICMP-Echo-Test";
            if let Some(n) = build_icmp_echo(&mut out, ICMP_TYPE_ECHO_REQUEST, ping_id, seq, payload)
            {
                st.send_ip_packet(dst, IP_PROTO_ICMP, &out[..n]);
            }
        }

        let deadline = timer::uptime_ms() + timeout_ms;
        while timer::uptime_ms() < deadline {
            {
                let mut guard = NET_STACK.lock();
                if let Some(st) = guard.as_mut() {
                    st.poll_locked();
                    if st.last_ping_reply.valid
                        && st.last_ping_reply.id == ping_id
                        && st.last_ping_reply.seq == seq
                    {
                        let r = st.last_ping_reply;
                        st.last_ping_reply.valid = false;
                        let delta_cnt = r.recv_cntpct.saturating_sub(send_cnt);
                        let rtt_us = (delta_cnt * 1_000_000) / freq;
                        results.push(PingResult {
                            seq,
                            rtt_us,
                            ttl: r.ttl,
                            bytes: r.payload_len + 8,
                        });
                        break;
                    }
                }
            }
            scheduler::sleep_ms(10);
        }
    }
    results
}

pub fn dns_resolve(hostname: &str, timeout_ms: u64) -> Option<Ipv4Addr> {
    let txid = ((timer::uptime_ms() as u16) ^ 0x4E58).max(1);
    let src_port = 53000 + (txid & 0x03FF);
    let dns_ip = {
        let mut guard = NET_STACK.lock();
        let st = guard.as_mut()?;
        if st.dns == Ipv4Addr::UNSPECIFIED {
            return None;
        }
        st.last_dns_answer = None;
        st.expected_dns_port = src_port;
        st.expected_dns_host = Some(String::from(hostname));
        let mut q = [0u8; 300];
        let qlen = build_query(&mut q, txid, hostname)?;
        let target = st.dns;
        st.send_udp_packet(target, src_port, DNS_PORT, &q[..qlen]);
        target
    };
    let _ = dns_ip;

    let deadline = timer::uptime_ms() + timeout_ms;
    while timer::uptime_ms() < deadline {
        {
            let mut guard = NET_STACK.lock();
            if let Some(st) = guard.as_mut() {
                st.poll_locked();
                if let Some(ans) = st.last_dns_answer.take() {
                    if ans.txid == txid {
                        st.expected_dns_port = 0;
                        st.expected_dns_host = None;
                        return Some(ans.ip);
                    }
                }
            }
        }
        scheduler::sleep_ms(10);
    }
    if let Some(st) = NET_STACK.lock().as_mut() {
        st.expected_dns_port = 0;
        st.expected_dns_host = None;
    }
    None
}

pub fn stats() -> NetStats {
    let guard = NET_STACK.lock();
    match guard.as_ref() {
        Some(st) => NetStats {
            initialized: true,
            mac: st.mac,
            ip: st.ip,
            link_local_ipv6: st.ip6,
            mask: st.mask,
            gateway: st.gateway,
            dns: st.dns,
            config_source: st.config_source,
            rx_packets: st.rx_packets,
            tx_packets: st.tx_packets,
            rx_bytes: st.rx_bytes,
            tx_bytes: st.tx_bytes,
        },
        None => NetStats {
            initialized: false,
            mac: MacAddr::ZERO,
            ip: Ipv4Addr::UNSPECIFIED,
            link_local_ipv6: Ipv6Addr::UNSPECIFIED,
            mask: Ipv4Addr::UNSPECIFIED,
            gateway: Ipv4Addr::UNSPECIFIED,
            dns: Ipv4Addr::UNSPECIFIED,
            config_source: ConfigSource::Unconfigured,
            rx_packets: 0,
            tx_packets: 0,
            rx_bytes: 0,
            tx_bytes: 0,
        },
    }
}

pub fn ifconfig_summary() -> String {
    let guard = NET_STACK.lock();
    let Some(st) = guard.as_ref() else {
        return String::from("  No network device initialized.\n");
    };
    let mut s = format!(
        "  {} ({:?}) link={}\n    MAC:  {}\n    IPv4: {} / {}  GW: {}  DNS: {}\n    IPv6: {}/64\n    RX:   {} pkts ({} B) | TX: {} pkts ({} B)\n  ARP table:\n",
        st.dev.name(),
        st.config_source,
        if st.dev.link_up() { "UP" } else { "DOWN" },
        st.mac,
        st.ip,
        st.mask,
        st.gateway,
        st.dns,
        st.ip6,
        st.rx_packets,
        st.rx_bytes,
        st.tx_packets,
        st.tx_bytes
    );
    for e in st.arp.entries() {
        if e.valid {
            s.push_str(&format!("    {} -> {}\n", e.ip, e.mac));
        }
    }
    s
}

pub fn netstat_summary() -> String {
    let guard = NET_STACK.lock();
    let Some(st) = guard.as_ref() else {
        return String::from("  Network inactive.\n");
    };
    let mut s = String::from("  TCP Sockets:\n");
    for sock in st.tcp.info_list() {
        s.push_str(&format!(
            "    [{}] {:?} :{} <-> {}:{} (rx={}B{})\n",
            sock.id,
            sock.state,
            sock.local_port,
            sock.remote_ip,
            sock.remote_port,
            sock.rx_queued,
            if sock.echo_mode { ", echo" } else { "" }
        ));
    }
    s
}

// --- TCP Server/Client API (used by Stage 11 & Stage 13 HTTP Admin) ---

pub fn tcp_listen(port: u16) -> Option<usize> {
    tcp_listen_mode(port, false)
}

fn tcp_listen_mode(port: u16, echo_mode: bool) -> Option<usize> {
    let mut guard = NET_STACK.lock();
    guard.as_mut()?.tcp.listen(port, echo_mode)
}

pub fn tcp_accept(listener_id: usize) -> Option<usize> {
    let mut guard = NET_STACK.lock();
    let st = guard.as_mut()?;
    st.poll_locked();
    st.tcp.accept(listener_id)
}

pub fn tcp_recv(sock_id: usize, out: &mut [u8]) -> usize {
    let mut guard = NET_STACK.lock();
    let Some(st) = guard.as_mut() else {
        return 0;
    };
    st.poll_locked();
    st.tcp.recv(sock_id, out)
}

pub fn tcp_send(sock_id: usize, data: &[u8]) {
    let mut guard = NET_STACK.lock();
    if let Some(st) = guard.as_mut() {
        let now = timer::uptime_ms();
        let segs = st.tcp.send(sock_id, data, now);
        st.send_tcp_segments(segs);
    }
}

pub fn tcp_close(sock_id: usize) {
    let mut guard = NET_STACK.lock();
    if let Some(st) = guard.as_mut() {
        let now = timer::uptime_ms();
        if let Some(seg) = st.tcp.close(sock_id, now) {
            st.send_tcp_segments(alloc::vec![seg]);
        }
    }
}

pub fn tcp_state(sock_id: usize) -> Option<TcpState> {
    let guard = NET_STACK.lock();
    guard.as_ref()?.tcp.state(sock_id)
}
