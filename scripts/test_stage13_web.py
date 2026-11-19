#!/usr/bin/env python3
"""Stage 13-14 End-to-End Verification: First-Boot Setup, Zero Hardcoded Passwords,
Authenticated HTTP/1.1 & TLS 1.3 Web Admin, RBAC, Storage, AI Core, and Persistence."""

import base64
import json
import os
import pty
import re
import secrets
import select
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request


def http_req(url, method="GET", headers=None, data=None):
    req = urllib.request.Request(url, method=method, headers=headers or {}, data=data)
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")


def https_req(url, method="GET", headers=None, data=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    req = urllib.request.Request(url, method=method, headers=headers or {}, data=data)
    try:
        with urllib.request.urlopen(req, timeout=6.0, context=ctx) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")


def raw_tls_probe(host, port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    with socket.create_connection((host, port), timeout=5.0) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            return tls.cipher()


def raw_http(host, port, payload_bytes):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(4.0)
    s.connect((host, port))
    s.sendall(payload_bytes)
    chunks = []
    while True:
        try:
            d = s.recv(4096)
            if not d:
                break
            chunks.append(d)
        except socket.timeout:
            break
    s.close()
    raw = b"".join(chunks).decode("utf-8", errors="replace")
    first_line = raw.split("\r\n", 1)[0]
    code = int(first_line.split()[1]) if len(first_line.split()) >= 2 else 0
    return code, raw


def basic_auth(user, pw):
    tok = base64.b64encode(f"{user}:{pw}".encode()).decode()
    return {"Authorization": f"Basic {tok}"}


def main():
    # Start from a clean unprovisioned FAT32 disk image
    subprocess.run(["python3", "scripts/mk_test_disk.py"], check=True)

    master, slave = pty.openpty()
    proc = subprocess.Popen(["./run.sh"], stdin=slave, stdout=slave, stderr=slave, close_fds=True)
    os.close(slave)

    buf = b""
    deadline = time.time() + 30.0
    try:
        while time.time() < deadline:
            r, _, _ = select.select([master], [], [], 0.1)
            if r:
                buf += os.read(master, 4096)
                if b"HTTPS TLS 1.3 Admin server listening on TCP :443" in buf:
                    break
        assert b"HTTP/1.1 Admin server listening on TCP :80" in buf, "Web admin HTTP :80 did not start!"
        assert b"HTTPS TLS 1.3 Admin server listening on TCP :443" in buf, "Web admin HTTPS :443 did not start!"
        time.sleep(0.25)

        uart_text = buf.decode("utf-8", errors="replace")
        m = re.search(r"one-time setup token=([0-9a-f]{24})", uart_text)
        assert m, f"Expected first-boot CSPRNG setup token on UART!\n{uart_text}"
        setup_token = m.group(1)

        base = "http://127.0.0.1:18080"
        sbase = "https://127.0.0.1:18443"

        # 0. Setup status & zero hardcoded passwords verification
        code, body = http_req(f"{base}/api/v1/setup/status")
        assert code == 200
        st = json.loads(body)
        assert st["needs_setup"] is True and st["csprng_seeded"] is True
        print(f"[0] First-boot setup required OK (csprng={st['csprng_source']}, token={setup_token[:6]}...)")

        for old_u, old_p in [("admin", "nexos-admin-2026"), ("viewer", "nexos-view-2026")]:
            code, _ = http_req(f"{base}/api/metrics", headers=basic_auth(old_u, old_p))
            assert code == 401, f"Legacy default password {old_u} must NOT work!"

        # Wrong setup token -> 403 Forbidden
        admin_pw = "Adm-" + secrets.token_hex(8)
        code, _ = http_req(
            f"{base}/api/v1/setup",
            method="POST",
            headers={"Content-Type": "application/json"},
            data=json.dumps({"token": "000000000000000000000000", "username": "rootadm", "password": admin_pw}).encode(),
        )
        assert code == 403

        # Valid one-time token over TLS 1.3 -> 201 Created
        code, body = https_req(
            f"{sbase}/api/v1/setup",
            method="POST",
            headers={"Content-Type": "application/json"},
            data=json.dumps({"token": setup_token, "username": "rootadm", "password": admin_pw}).encode(),
        )
        print(f"[0b] TLS 1.3 POST /api/v1/setup -> HTTP {code}: {body.strip()}")
        assert code == 201 and json.loads(body)["role"] == "admin"

        # Repeat setup must be locked -> 409 Conflict
        code, _ = http_req(
            f"{base}/api/v1/setup",
            method="POST",
            headers={"Content-Type": "application/json"},
            data=json.dumps({"token": setup_token, "username": "evil", "password": admin_pw}).encode(),
        )
        assert code == 409

        # 1. Unauthenticated -> 401
        code, body = http_req(f"{base}/api/metrics")
        print(f"[1] Unauthenticated GET /api/metrics -> HTTP {code}: {body.strip()}")
        assert code == 401

        # 2. Wrong password & unknown user -> 401
        code, _ = http_req(f"{base}/api/metrics", headers=basic_auth("rootadm", "badpass"))
        assert code == 401
        code, _ = http_req(f"{base}/api/metrics", headers=basic_auth("nobody", "badpass"))
        assert code == 401

        # 3. Admin login -> Bearer token
        code, body = https_req(f"{sbase}/api/login", method="POST", headers=basic_auth("rootadm", admin_pw))
        print(f"[2] Admin POST /api/login -> HTTP {code}")
        assert code == 200
        token = json.loads(body)["token"]
        assert len(token) == 64
        bearer = {"Authorization": f"Bearer {token}"}

        # Provision ephemeral RBAC test accounts via /api/v1/users
        ops_pw = "Ops-" + secrets.token_hex(6)
        view_pw = "View-" + secrets.token_hex(6)
        ai_pw = "Ai-" + secrets.token_hex(6)
        for u, p, r in [("ops1", ops_pw, "operator"), ("view1", view_pw, "viewer"), ("ai1", ai_pw, "ai-agent")]:
            c, _ = https_req(f"{sbase}/api/v1/users?user={u}&pass={p}&role={r}", method="POST", headers=bearer)
            assert c == 201

        # Cannot delete sole admin rootadm -> 403
        code, _ = https_req(f"{sbase}/api/v1/users?user=rootadm", method="DELETE", headers=bearer)
        assert code == 403

        # 4. Viewer & ai-agent read-only RBAC checks
        code, body = http_req(f"{base}/api/metrics", headers=basic_auth("view1", view_pw))
        assert code == 200
        metrics = json.loads(body)
        assert metrics["ram_total_mib"] == 1024
        assert metrics["pa_bits"] == 44
        assert metrics["net_ip"] == "10.0.2.15"
        assert metrics["auth_role"] == "viewer"

        code, body = http_req(f"{base}/api/metrics", headers=basic_auth("ai1", ai_pw))
        assert code == 200 and json.loads(body)["auth_role"] == "ai-agent"

        # 5. Viewer & ai-agent trying POST /api/services/restart -> 403 Forbidden (RBAC)
        code, _ = http_req(f"{base}/api/services/restart?name=health-svc", method="POST", headers=basic_auth("view1", view_pw))
        assert code == 403
        code, _ = http_req(f"{base}/api/services/restart?name=health-svc", method="POST", headers=basic_auth("ai1", ai_pw))
        assert code == 403

        # Operator CAN restart services -> 200
        code, body = http_req(f"{base}/api/services/restart?name=health-svc", method="POST", headers=basic_auth("ops1", ops_pw))
        assert code == 200 and json.loads(body)["restarted"] == "health-svc"

        # Admin Bearer token POST /api/services/restart?name=health-svc -> 200
        code, body = http_req(f"{base}/api/services/restart?name=health-svc", method="POST", headers=bearer)
        assert code == 200 and json.loads(body)["restarted"] == "health-svc"

        # JSON-injection / special characters escaping check
        code, body = http_req(
            f"{base}/api/services/restart?name=x%22%2C%22injected%22%3Atrue",
            method="POST",
            headers=bearer,
        )
        assert code == 404 and "injected" not in json.loads(body)

        # 405 Method Not Allowed, 400 Bad Request, 413 Payload Too Large
        code, _ = http_req(f"{base}/api/services/restart?name=health-svc", method="GET", headers=bearer)
        assert code == 405
        code, _ = raw_http("127.0.0.1", 18080, b"BADLINE\r\n\r\n")
        assert code == 400
        big_hdr = b"GET /api/metrics HTTP/1.1\r\nHost: x\r\nX-Pad: " + (b"A" * 2100) + b"\r\n\r\n"
        code, _ = raw_http("127.0.0.1", 18080, big_hdr)
        assert code == 413

        # 6. GET /api/services & GET / & GET /api/logs
        code, body = http_req(f"{base}/api/services", headers=bearer)
        assert code == 200
        svcs = {s["name"]: s for s in json.loads(body)["services"]}
        assert svcs["health-svc"]["restarts"] >= 3
        assert svcs["web-admin"]["state"] == "Running"
        assert svcs["ai-core"]["state"] == "Running"

        code, html = http_req(f"{base}/")
        print(f"[6] GET / -> HTTP {code} ({len(html)} bytes HTML dashboard)")
        assert code == 200 and "NexOS Headless Server Admin" in html and "First-Boot Administrator Provisioning" in html

        code, logs = http_req(f"{base}/api/logs", headers=bearer)
        assert code == 200 and "Restarted service 'health-svc'" in logs

        # 7. TLS 1.3 (:443) Cipher & /api/v1/system + /api/v1/tasks + /api/v1/network
        cipher = raw_tls_probe("127.0.0.1", 18443)
        print(f"[7] TLS 1.3 handshake cipher: {cipher}")
        assert cipher[1] == "TLSv1.3" and "CHACHA20_POLY1305" in cipher[0]

        code, body = https_req(f"{sbase}/api/v1/system", headers=bearer)
        assert code == 200
        sys_v1 = json.loads(body)
        assert sys_v1["tls"] is True and sys_v1["online_cpus"] == 4 and sys_v1["disk_mounted"] is True

        code, body = https_req(f"{sbase}/api/v1/tasks", headers=bearer)
        assert code == 200 and any(t["name"] == "ai-core" for t in json.loads(body)["tasks"])

        code, body = https_req(f"{sbase}/api/v1/network", headers=bearer)
        assert code == 200
        net_v1 = json.loads(body)
        assert net_v1["ip"] == "10.0.2.15" and net_v1["ipv6"].startswith("fe80:")

        # 8. /api/v1/storage & /api/v1/files CRUD + NEXUSERS.DB persistence check
        code, body = https_req(f"{sbase}/api/v1/storage?path=/disk", headers=bearer)
        assert code == 200
        disk_names = {e["name"] for e in json.loads(body)["entries"]}
        assert "MODEL.NXM" in disk_names and "HELLO.TXT" in disk_names and "NEXUSERS.DB" in disk_names

        code, _ = https_req(
            f"{sbase}/api/v1/files?path=/ram/viewer_denied.txt",
            method="POST",
            headers=basic_auth("view1", view_pw),
            data=b"nope",
        )
        assert code == 403

        code, body = https_req(
            f"{sbase}/api/v1/files?path=/ram/tls_test.txt",
            method="POST",
            headers=bearer,
            data=b"NexOS-TLS13-File-OK\n",
        )
        assert code == 200 and json.loads(body)["bytes"] == 20
        code, body = https_req(f"{sbase}/api/v1/files?path=/ram/tls_test.txt", headers=bearer)
        assert code == 200 and body == "NexOS-TLS13-File-OK\n"

        # 9. AI Core over TLS 1.3
        code, body = https_req(f"{sbase}/api/v1/ai", headers=bearer)
        assert code == 200
        ai_st = json.loads(body)
        assert ai_st["initialized"] is True and ai_st["neon_verified"] is True and ai_st["model_loaded"] is True

        code, body = https_req(f"{sbase}/api/v1/ai/agents", headers=bearer)
        assert code == 200
        agents = json.loads(body)["agents"]
        assert {a["name"] for a in agents} >= {"system", "network", "security", "memory", "storage", "process", "diagnostic", "repair"}

        code, body = https_req(
            f"{sbase}/api/v1/ai/diagnose?prompt=diagnose%20memory",
            method="POST",
            headers=bearer,
        )
        assert code == 200
        diagnosis = json.loads(body)
        assert diagnosis["agent"] == "memory" and "pa_bits" in diagnosis["observation"]

        code, body = https_req(
            f"{sbase}/api/v1/ai/chat",
            method="POST",
            headers=bearer,
            data=json.dumps({"prompt": "check network"}).encode(),
        )
        assert code == 200
        chat = json.loads(body)
        assert chat["agent"] == "network" and chat["llm_required_for_natural_language"] is True

        code, body = https_req(f"{sbase}/api/v1/ai/memory", headers=bearer)
        assert code == 200
        assert isinstance(json.loads(body)["memory"], list)

        code, body = https_req(
            f"{sbase}/api/v1/ai/repair/request?service=health-svc",
            method="POST",
            headers=bearer,
        )
        assert code == 202
        repair = json.loads(body)
        assert repair["approval_required"] is True

        code, body = https_req(
            f"{sbase}/api/v1/ai/repair/approve?id={repair['approval_id']}&token={repair['approval_token']}",
            method="POST",
            headers=bearer,
        )
        assert code == 200
        repair_result = json.loads(body)
        assert repair_result["verified"] is True

        code, body = https_req(f"{sbase}/api/v1/ai/infer?prompt=nexos%20status", method="POST", headers=bearer)
        assert code == 200
        ai_inf = json.loads(body)
        assert "arm64 neon q8 inference engine active" in ai_inf["output"]

        code, body = https_req(f"{sbase}/api/v1/ai/bench", method="POST", headers=bearer)
        assert code == 200
        ai_b = json.loads(body)
        assert ai_b["kernel"] == "NEON_Q8_0" and ai_b["tokens_per_sec_x100"] > 0

        code, _ = https_req(f"{sbase}/api/v1/ai/unload", method="POST", headers=basic_auth("view1", view_pw))
        assert code == 403
        code, body = https_req(f"{sbase}/api/v1/ai/unload", method="POST", headers=bearer)
        assert code == 200 and json.loads(body)["was_loaded"] is True
        code, body = https_req(f"{sbase}/api/v1/ai/load?path=/disk/BAD.GGF", method="POST", headers=bearer)
        assert code == 400 and "GGUF" in body
        code, body = https_req(f"{sbase}/api/v1/ai/load?path=/disk/CORRUPT.NXM", method="POST", headers=bearer)
        assert code == 400 and "CRC-32" in body, f"Expected CRC-32 rejection, got {code}: {body}"
        code, body = https_req(f"{sbase}/api/v1/ai/load?path=/disk/MODEL.NXM", method="POST", headers=bearer)
        assert code == 200 and json.loads(body)["loaded"] is True

        # 10. Users CRUD + 5-failure lockout (429) + /api/v1/audit
        audit_pw = "Aud-" + secrets.token_hex(6)
        code, _ = https_req(f"{sbase}/api/v1/users?user=audituser&pass={audit_pw}&role=operator", method="POST", headers=bearer)
        assert code == 201
        for _ in range(5):
            fc, _ = https_req(f"{sbase}/api/v1/system", headers=basic_auth("audituser", "wrongpass123"))
            assert fc == 401
        lc, lbody = https_req(f"{sbase}/api/v1/system", headers=basic_auth("audituser", audit_pw))
        assert lc == 429 and "account_locked" in lbody

        code, _ = https_req(f"{sbase}/api/v1/users?user=audituser", method="DELETE", headers=bearer)
        assert code == 200
        code, _ = https_req(f"{sbase}/api/v1/services/stop?name=health-svc", method="POST", headers=bearer)
        assert code == 200
        code, _ = https_req(f"{sbase}/api/v1/services/start?name=health-svc", method="POST", headers=bearer)
        assert code == 200
        code, body = https_req(f"{sbase}/api/v1/audit", headers=bearer)
        assert code == 200 and len(json.loads(body)["events"]) >= 5
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
        os.close(master)

    # 11. Persistence across cold reboot using the SAME build/test_disk.img
    master2, slave2 = pty.openpty()
    proc2 = subprocess.Popen(["./run.sh"], stdin=slave2, stdout=slave2, stderr=slave2, close_fds=True)
    os.close(slave2)
    buf2 = b""
    try:
        deadline2 = time.time() + 30.0
        while time.time() < deadline2:
            r, _, _ = select.select([master2], [], [], 0.1)
            if r:
                buf2 += os.read(master2, 4096)
                if b"HTTPS TLS 1.3 Admin server listening on TCP :443" in buf2:
                    break
        assert b"HTTPS TLS 1.3 Admin server listening on TCP :443" in buf2, "Rebooted QEMU did not start HTTPS!"
        time.sleep(0.25)
        uart2 = buf2.decode("utf-8", errors="replace")
        assert "db_loaded=true" in uart2, f"Expected db_loaded=true on reboot!\n{uart2}"
        assert "setup locked" in uart2, f"Expected credential store setup locked on reboot!\n{uart2}"
        assert "one-time setup token=" not in uart2, "Rebooted provisioned disk must NOT emit setup token!"

        code, body = http_req(f"http://127.0.0.1:18080/api/v1/setup/status")
        assert code == 200 and json.loads(body)["needs_setup"] is False
        code, body = https_req(
            f"https://127.0.0.1:18443/api/login",
            method="POST",
            headers=basic_auth("rootadm", admin_pw),
        )
        assert code == 200 and len(json.loads(body)["token"]) == 64
        reboot_bearer = {"Authorization": f"Bearer {json.loads(body)['token']}"}
        code, body = https_req(
            f"https://127.0.0.1:18443/api/v1/ai/memory",
            headers=reboot_bearer,
        )
        assert code == 200
        reboot_memory = json.loads(body)["memory"]
        assert isinstance(reboot_memory, list)
        print("[11] Cold-reboot /disk/NEXUSERS.DB persistence + locked setup + TLS 1.3 login VERIFIED!")
        print("\nALL STAGE 13-14 ZERO-DEFAULT-PASSWORD + TLS 1.3 + AI + RBAC + PERSISTENCE TESTS PASSED!")
    finally:
        proc2.terminate()
        try:
            proc2.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc2.kill()
        os.close(master2)


if __name__ == "__main__":
    main()

