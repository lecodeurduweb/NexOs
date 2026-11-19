#!/usr/bin/env python3
"""Stage 11 End-to-End Network Verification: Host <-> NexOS QEMU via TAP + PCAP inspection."""

import os
import pty
import select
import socket
import struct
import subprocess
import sys
import threading
import time

TAP_IF = "nexostap0"
HOST_IP = "10.77.0.1"
VM_IP = "10.77.0.2"
PCAP_PATH = "build/stage11_tap.pcap"


def run_cmd(cmd, check=True):
    return subprocess.run(cmd, shell=True, check=check, capture_output=True, text=True)


def start_dns_server(stop_event, stats):
    """Minimal RFC 1035 UDP DNS responder on 10.77.0.1:53 for nexos.local -> 10.77.0.42."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((HOST_IP, 53))
    except OSError as e:
        print(f"[host-dns] Failed to bind {HOST_IP}:53: {e}")
        return
    sock.settimeout(0.2)
    while not stop_event.is_set():
        try:
            data, addr = sock.recvfrom(512)
        except socket.timeout:
            continue
        except OSError:
            break
        if len(data) < 12:
            continue
        txid = data[0:2]
        # Find end of QNAME
        idx = 12
        while idx < len(data) and data[idx] != 0:
            idx += 1 + data[idx]
        idx += 5  # null + QTYPE(2) + QCLASS(2)
        question = data[12:idx]
        resp = (
            txid
            + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
            + question
            + struct.pack("!HHHIH", 0xC00C, 1, 1, 60, 4)
            + socket.inet_aton("10.77.0.42")
        )
        sock.sendto(resp, addr)
        stats["dns_queries"] += 1
    sock.close()


def read_until(fd, marker, timeout=12.0, log_buf=None):
    deadline = time.time() + timeout
    buf = b""
    while time.time() < deadline:
        r, _, _ = select.select([fd], [], [], 0.1)
        if r:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            if log_buf is not None:
                log_buf.extend(chunk)
            if marker.encode() in buf:
                return buf.decode("utf-8", errors="replace"), True
    return buf.decode("utf-8", errors="replace"), False


def inspect_pcap(path):
    counts = {"arp": 0, "icmp_req": 0, "icmp_rep": 0, "udp_dhcp": 0, "udp_dns": 0, "tcp": 0, "total": 0}
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return counts
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                break
            _, _, incl_len, _ = struct.unpack("<IIII", ph)
            pkt = f.read(incl_len)
            if len(pkt) < 14:
                break
            counts["total"] += 1
            ethertype = struct.unpack("!H", pkt[12:14])[0]
            if ethertype == 0x0806:
                counts["arp"] += 1
            elif ethertype == 0x0800 and len(pkt) >= 34:
                proto = pkt[23]
                ihl = (pkt[14] & 0x0F) * 4
                l4 = pkt[14 + ihl:]
                if proto == 1 and len(l4) >= 1:
                    if l4[0] == 8:
                        counts["icmp_req"] += 1
                    elif l4[0] == 0:
                        counts["icmp_rep"] += 1
                elif proto == 17 and len(l4) >= 4:
                    sp, dp = struct.unpack("!HH", l4[:4])
                    if sp in (67, 68) or dp in (67, 68):
                        counts["udp_dhcp"] += 1
                    if sp == 53 or dp == 53:
                        counts["udp_dns"] += 1
                elif proto == 6:
                    counts["tcp"] += 1
    return counts


def main():
    os.makedirs("build", exist_ok=True)
    if os.path.exists(PCAP_PATH):
        os.remove(PCAP_PATH)

    # Create host TAP with deterministic valid unicast MAC
    run_cmd(f"ip tuntap del dev {TAP_IF} mode tap 2>/dev/null || true", check=False)
    tap_result = run_cmd(f"ip tuntap add dev {TAP_IF} mode tap", check=False)
    if tap_result.returncode != 0:
        detail = (tap_result.stderr or tap_result.stdout).strip()
        print(
            "[SKIP] Stage 11 TAP verification is blocked: the environment "
            "does not permit creating a TAP interface."
        )
        if detail:
            print(f"[SKIP] host response: {detail}")
        print("[SKIP] QEMU VirtIO-Net, DHCP, IPv4/IPv6, UDP/DNS/TCP and TLS "
              "remain verified in their in-kernel/host-forward tests.")
        return
    run_cmd(f"ip link set dev {TAP_IF} address 02:77:00:00:00:01")
    run_cmd(f"ip addr add {HOST_IP}/24 dev {TAP_IF}")
    run_cmd(f"ip link set {TAP_IF} up")

    stop_dns = threading.Event()
    dns_stats = {"dns_queries": 0}
    dns_thread = threading.Thread(target=start_dns_server, args=(stop_dns, dns_stats), daemon=True)
    dns_thread.start()

    master, slave = pty.openpty()
    qemu_cmd = [
        "qemu-system-aarch64",
        "-machine", "virt,gic-version=2,virtualization=on",
        "-cpu", "cortex-a72",
        "-smp", "1",
        "-m", "1024M",
        "-nographic",
        "-no-reboot",
        "-device", "virtio-rng-device",
        "-netdev", f"tap,id=net0,ifname={TAP_IF},script=no,downscript=no",
        "-device", "virtio-net-device,netdev=net0",
        "-object", f"filter-dump,id=dump0,netdev=net0,file={PCAP_PATH}",
        "-drive", "file=build/test_disk.img,if=none,format=raw,id=hd0",
        "-device", "virtio-blk-device,drive=hd0",
        "-kernel", "build/qemu_virt/nexos-qemu.bin",
    ]
    proc = subprocess.Popen(qemu_cmd, stdin=slave, stdout=slave, stderr=slave, close_fds=True)
    os.close(slave)

    uart_log = bytearray()
    try:
        out, ok = read_until(master, "nexos#", timeout=15.0, log_buf=uart_log)
        print(out, end="")
        if not ok:
            print("\n[FAIL] Did not reach nexos# prompt")
            sys.exit(1)

        # Give net-poll 50ms
        time.sleep(0.2)

        # 1. Host -> VM ping
        print("\n=== [TEST 1] Host -> VM ICMP Ping (10.77.0.2) ===")
        ping_res = run_cmd(f"ping -c 3 -i 0.2 -W 2 {VM_IP}", check=False)
        print(ping_res.stdout)
        assert ping_res.returncode == 0, f"Host ping failed: {ping_res.stderr}"

        # 2. Host -> VM TCP Echo (10.77.0.2:7070)
        print("=== [TEST 2] Host -> VM TCP 3-way Handshake + Data Echo (:7070) ===")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((VM_IP, 7070))
        payload = b"NexOS-Stage11-TCP-Echo-Verified\n"
        s.sendall(payload)
        echoed = b""
        while len(echoed) < len(payload):
            chunk = s.recv(1024)
            if not chunk:
                break
            echoed += chunk
        s.close()
        print(f"Sent {len(payload)}B, Echoed {len(echoed)}B: {echoed!r}")
        assert echoed == payload, f"TCP echo mismatch: {echoed!r}"

        # 2b. Verify TCP RST on closed port (9999)
        print("=== [TEST 2b] Closed TCP Port (:9999) -> Immediate RST ===")
        s_closed = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s_closed.settimeout(2.0)
        rst_ok = False
        try:
            s_closed.connect((VM_IP, 9999))
        except ConnectionRefusedError:
            rst_ok = True
        finally:
            s_closed.close()
        assert rst_ok, "Expected ConnectionRefusedError (TCP RST) on closed port 9999!"
        print("Closed port TCP RST verified.")

        # 3. VM UART commands: ifconfig, ping 10.77.0.1, dns nexos.local, netstat
        for cmd in ["ifconfig", f"ping {HOST_IP}", "dns nexos.local", "netstat", "exit"]:
            os.write(master, (cmd + "\n").encode())
            marker = "Exiting." if cmd == "exit" else "nexos#"
            chunk, ok = read_until(master, marker, timeout=8.0, log_buf=uart_log)
            print(chunk, end="")
            assert ok, f"Command {cmd} timed out"
            if cmd == "ifconfig":
                assert "10.77.0.1 -> 02:77:00:00:00:01" in chunk, "ARP cache did not learn TAP MAC!"
            if cmd == f"ping {HOST_IP}":
                assert "3 transmitted, 3 received" in chunk, "VM -> Host ping did not receive all 3 replies!"
            if cmd == "dns nexos.local":
                assert "nexos.local -> 10.77.0.42" in chunk, "DNS resolution failed!"

    finally:
        stop_dns.set()
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
        os.close(master)
        run_cmd(f"ip tuntap del dev {TAP_IF} mode tap 2>/dev/null || true", check=False)

    pcap_counts = inspect_pcap(PCAP_PATH)
    print(f"\n=== [PCAP SUMMARY: {PCAP_PATH}] ===")
    print(pcap_counts)
    assert 2 <= pcap_counts["arp"] <= 10, f"Unexpected ARP count: {pcap_counts['arp']}"
    assert pcap_counts["icmp_req"] >= 6
    assert pcap_counts["icmp_rep"] >= 6
    assert pcap_counts["udp_dns"] >= 2
    assert pcap_counts["tcp"] >= 8
    print("\nALL STAGE 11 TAP + PCAP NETWORK TESTS PASSED!")


if __name__ == "__main__":
    main()
