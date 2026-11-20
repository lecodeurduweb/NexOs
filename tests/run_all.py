#!/usr/bin/env python3
"""NexOS Unified End-to-End QEMU & Host Verification Suite (Stages 1-14).

Every step is reported with a real status:
  PASS    - executed and succeeded
  FAIL    - executed and failed (full output is kept in build/test-logs/)
  SKIP    - executed but explicitly skipped itself (exit code 77)
  BLOCKED - could not run because of the environment (missing tool, etc.)
A SKIP or BLOCKED step is never counted as a PASS. The overall exit code is
non-zero as soon as one step is FAIL.
"""

import json
import os
import shutil
import subprocess
import sys
import time

LOG_DIR = os.path.join("build", "test-logs")
SKIP_EXIT_CODE = 77
RESULTS = []


def record(label, status, detail="", seconds=0.0):
    RESULTS.append({"step": label, "status": status, "detail": detail, "seconds": round(seconds, 1)})
    print(f"[{status}] {label}" + (f" -- {detail}" if detail else ""))


def run_step(label, cmd, required_tools=()):
    print("\n============================================================")
    print(f"  RUNNING: {label}")
    print("============================================================", flush=True)
    missing = [t for t in required_tools if shutil.which(t) is None]
    if missing:
        record(label, "BLOCKED", f"missing tools: {', '.join(missing)}")
        return
    slug = "".join(c if c.isalnum() else "_" for c in label)[:60]
    log_path = os.path.join(LOG_DIR, f"{slug}.log")
    t0 = time.time()
    with open(log_path, "wb") as log:
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in proc.stdout:
            sys.stdout.buffer.write(line)
            sys.stdout.flush()
            log.write(line)
        proc.wait()
    dt = time.time() - t0
    if proc.returncode == 0:
        record(label, "PASS", seconds=dt)
    elif proc.returncode == SKIP_EXIT_CODE:
        record(label, "SKIP", f"step skipped itself (exit {SKIP_EXIT_CODE}); see {log_path}", dt)
    else:
        record(label, "FAIL", f"exit code {proc.returncode}; full log: {log_path}", dt)


STAGE3_SCRIPT = r'''
import os, pty, select, subprocess, sys, time
LOG = os.path.join("build", "test-logs", "stage3_uart_transcript.txt")
master, slave = pty.openpty()
proc = subprocess.Popen(["./run.sh"], stdin=slave, stdout=slave, stderr=slave, close_fds=True)
os.close(slave)
buf = b""
boot_timeout = float(os.environ.get("NEXOS_BOOT_TIMEOUT", "90"))
deadline = time.time() + boot_timeout
prompt_seen = False
while time.time() < deadline:
    r, _, _ = select.select([master], [], [], 0.1)
    if r:
        try:
            buf += os.read(master, 4096)
        except OSError:
            break
        if b"nexos#" in buf:
            prompt_seen = True
            break
    if proc.poll() is not None:
        break

def dump_and_fail(reason):
    txt = buf.decode("utf-8", errors="replace")
    with open(LOG, "w") as f: f.write(txt)
    print("\n----- STAGE 3 FAILURE: " + reason + " -----")
    print("----- UART transcript (also saved to " + LOG + ") -----")
    print(txt)
    print("----- end of transcript -----")
    sys.exit(1)

if not prompt_seen:
    proc.terminate(); proc.wait()
    dump_and_fail("shell prompt 'nexos#' not seen within %.0fs (qemu exit=%s)" % (boot_timeout, proc.returncode))

cmds = [b"uname\n", b"info\n", b"devs\n", b"users\n", b"ls /disk\n", b"cat /disk/NEXOS.TXT\n", b"mmaptest\n", b"ipctest\n", b"ai status\n", b"ai ask nexos status\n", b"ai bench\n", b"ai unload\n", b"ai load /disk/BAD.GGF\n", b"ai load /disk/CORRUPT.NXM\n", b"ai load /disk/MODEL.NXM\n", b"services\n", b"exit\n"]
for cmd in cmds:
    os.write(master, cmd)
    # wait for the next prompt instead of a fixed sleep (bounded at 10s per command)
    cmd_deadline = time.time() + 10
    before = len(buf)
    while time.time() < cmd_deadline:
        r, _, _ = select.select([master], [], [], 0.1)
        if r:
            try: buf += os.read(master, 4096)
            except OSError: break
        if b"nexos#" in buf[before:] or cmd == b"exit\n":
            time.sleep(0.2)
            break
proc.terminate(); proc.wait()
txt = buf.decode("utf-8", errors="replace")
with open(LOG, "w") as f: f.write(txt)

checks = [
    ("source=virtio-rng", "CSPRNG not seeded from VirtIO-RNG"),
    ("CSPRNG self-test OK", "CSPRNG self-test"),
    ("BCM2711 RNG200 [mock] OK", "RNG200 mock"),
    ("Stage 3 exception test passed", "exceptions"),
    ("Stage 5 verified", "stage 5"), ("Stage 6 verified", "stage 6"),
    ("Stage 7 verified", "stage 7"), ("Stage 8 verified", "stage 8"),
    ("Reclaimed 3 exited Stage 8 task(s).", "task reclaim"),
    ("SMP 4-core concurrency verified", "SMP"),
    ("IPC channel self-test OK", "IPC"),
    ("BlockCache verified", "block cache"),
    ("[mock] BCM2711 EMMC2 MMIO self-test OK", "EMMC2 mock"),
    ("[mock] BCM2711 GENET v5 MMIO ring & MAC self-test OK", "GENET mock"),
    ("IPv6 link-local & ICMPv6 self-test OK", "IPv6"),
    ("TLS 1.3 crypto self-test OK", "TLS 1.3"),
    ("[EL0-probe] Syscall EFAULT & W^X checks OK.", "EL0 probe"),
    ("Stage 9 EL0->EL1 isolation verified", "EL0 isolation"),
    ("FAT32 write+readback+mkdir/rm+sync verified", "FAT32"),
    ("Stage 12 verified", "stage 12"),
    ("AArch64 NEON SIMD kernels verified", "NEON"),
    ("Auto-loaded model: /disk/MODEL.NXM", "model autoload"),
    ("NexOS 0.1.0 aarch64 headless-server (userspace EL0)", "uname"),
    ("mmaptest OK", "mmap"),
    ("ipctest OK: hello-ipc-el0", "ipc EL0"),
    ("arm64 neon q8 inference engine active", "ai status"),
    ("[ai-bench] NEON Q8_0:", "ai bench"),
    ("Unsupported external GGUF v3", "GGUF rejection"),
    ("CRC-32 integrity check failed", "CRC32 rejection"),
]
failed = [name for needle, name in checks if needle not in txt]
if "nexos# info" in txt and "nexos# devs" in txt:
    if "el0-probe" in txt.split("nexos# info")[1].split("nexos# devs")[0]:
        failed.append("exited el0-probe leaked in task table")
else:
    failed.append("info/devs prompts not found in transcript")
if failed:
    dump_and_fail("missing markers: " + ", ".join(failed))
print("CORE STAGES 1-14 (CSPRNG, SMP, IPC, CACHE, TLS1.3, MMAP, AI NEON Q8_0 + CRC32) VERIFIED! (%d markers)" % len(checks))
'''


def main():
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(os.path.join(LOG_DIR, "stage3_script.py"), "w") as f:
        f.write(STAGE3_SCRIPT)

    run_step("1. Build QEMU virt + RPi4 kernel8.img + EL0 init.bin", "./build.sh all",
             required_tools=("cargo", "aarch64-linux-gnu-gcc"))
    if RESULTS[-1]["status"] != "PASS":
        return finish(abort_reason="build failed; remaining steps NOT TESTED")
    run_step("1b. Build RPi4 MBR + FAT32 Bootable SD Image", "./build.sh sd")
    run_step(
        "1c. Verify ELF W^X Segment Permissions (no RWE segments)",
        """python3 -c '
import subprocess
for elf in ["build/userspace/init.elf", "build/qemu_virt/nexos-qemu.elf", "build/rpi4/nexos-rpi4.elf"]:
    out = subprocess.check_output(["aarch64-linux-gnu-readelf", "-lW", elf], text=True)
    assert "LOAD" in out, f"{elf}: no LOAD segment\\n{out}"
    assert "RWE" not in out, f"{elf} has RWX/RWE segment!\\n{out}"
print("ELF segment W^X check OK (no RWE in init.elf, nexos-qemu.elf, nexos-rpi4.elf).")
'""",
        required_tools=("aarch64-linux-gnu-readelf",),
    )
    run_step(
        "1d. Verify RPi4 SD Image MBR + FAT32 Layout",
        """python3 -c '
import struct
with open("build/rpi4/nexos-rpi4-sd.img", "rb") as f:
    mbr = f.read(512)
    assert mbr[510:512] == b"\\x55\\xAA", "bad MBR signature"
    assert mbr[446] == 0x80 and mbr[446 + 4] == 0x0C, "partition 1 not bootable FAT32 LBA"
    part_lba = struct.unpack_from("<I", mbr, 446 + 8)[0]
    f.seek(part_lba * 512)
    bpb = f.read(512)
    assert bpb[510:512] == b"\\x55\\xAA" and bpb[82:90] == b"FAT32   ", "bad FAT32 BPB"
    rsvd = struct.unpack_from("<H", bpb, 14)[0]
    nfats = bpb[16]
    fatsz = struct.unpack_from("<I", bpb, 36)[0]
    f.seek((part_lba + rsvd + nfats * fatsz) * 512)
    root = f.read(512)
    names = [root[i*32:i*32+11] for i in range(4)]
    for n in (b"KERNEL8 IMG", b"CONFIG  TXT", b"CMDLINE TXT", b"README  TXT"):
        assert n in names, f"{n!r} missing from root dir: {names}"
print("RPi4 SD MBR + FAT32 layout verified (KERNEL8.IMG, CONFIG.TXT, CMDLINE.TXT, README.TXT).")
'""",
    )
    run_step("2. Create GPT + FAT32 test disk image", "python3 scripts/mk_test_disk.py build/test_disk.img")
    run_step(
        "2b. Verify convert_to_nxm.py Offline Converter + CRC-32 Verification",
        """python3 -c '
import json, os, struct, subprocess, tempfile
with tempfile.TemporaryDirectory() as td:
    jp = os.path.join(td, "mini.json"); np_out = os.path.join(td, "mini.nxm")
    spec = {
        "config": {"dim": 32, "hidden_dim": 64, "n_layers": 1, "n_heads": 2, "n_kv_heads": 2, "max_seq": 16},
        "vocab": [["<pad>", -10.0], ["<bos>", -10.0], ["<eos>", -10.0], ["ok", 5.0]],
        "tok_emb": [0.1] * (4 * 32),
        "layers": [{"rms_att": [1.0] * 32, "wq": [0.1] * (32 * 32), "wk": [0.1] * (32 * 32),
                    "wv": [0.1] * (32 * 32), "wo": [0.1] * (32 * 32), "rms_ffn": [1.0] * 32,
                    "w1": [0.1] * (64 * 32), "w2": [0.1] * (32 * 64), "w3": [0.1] * (64 * 32)}],
        "rms_final": [1.0] * 32, "w_cls": [0.1] * (4 * 32),
    }
    with open(jp, "w") as f: json.dump(spec, f)
    subprocess.run(["python3", "scripts/convert_to_nxm.py", "-i", jp, "-o", np_out], check=True)
    assert json.loads(subprocess.check_output(["python3", "scripts/convert_to_nxm.py", "--verify", np_out], text=True))["crc32_verified"] is True
    l2p = os.path.join(td, "l2c.bin"); l2_out = os.path.join(td, "l2c.nxm")
    hdr = struct.pack("<7i", 32, 64, 1, 2, 2, 4, 16)
    n_f = (4 * 32) + 32 + 4 * (32 * 32) + 32 + 2 * (64 * 32) + (32 * 64) + 32
    with open(l2p, "wb") as f: f.write(hdr + struct.pack(f"<{n_f}f", *([0.05] * n_f)))
    subprocess.run(["python3", "scripts/convert_to_nxm.py", "-i", l2p, "-o", l2_out, "--format", "llama2c"], check=True)
    assert json.loads(subprocess.check_output(["python3", "scripts/convert_to_nxm.py", "--verify", l2_out], text=True))["crc32_verified"] is True
print("convert_to_nxm.py (JSON + llama2.c + CRC-32 --verify) passed!")
'""",
    )
    run_step(
        "3. Stage 1-10 & 12-14 UART Boot, CSPRNG, MMU, Sched, EL0, VFS/FAT32, CORRUPT.NXM, RBAC, Watchdog",
        f"python3 {os.path.join(LOG_DIR, 'stage3_script.py')}",
        required_tools=("qemu-system-aarch64",),
    )
    run_step("4. Stage 11 TAP Bidirectional ICMP/ARP/DNS/TCP + PCAP Verification",
             "python3 scripts/test_stage11_net.py", required_tools=("qemu-system-aarch64",))
    run_step("5. Stage 13-14 First-Boot Setup + HTTPS TLS 1.3 + AI Core + RBAC + Persistence",
             "python3 scripts/test_stage13_web.py", required_tools=("qemu-system-aarch64",))
    return finish()


def finish(abort_reason=None):
    print("\n============================================================")
    print("  NexOS VERIFICATION REPORT")
    print("============================================================")
    for r in RESULTS:
        print(f"  {r['status']:<8} {r['seconds']:>6.1f}s  {r['step']}" + (f"\n           {r['detail']}" if r["detail"] else ""))
    counts = {s: sum(1 for r in RESULTS if r["status"] == s) for s in ("PASS", "FAIL", "SKIP", "BLOCKED")}
    print(f"\n  PASS={counts['PASS']} FAIL={counts['FAIL']} SKIP={counts['SKIP']} BLOCKED={counts['BLOCKED']}")
    if abort_reason:
        print(f"  ABORTED: {abort_reason}")
    print("  PHYSICAL RASPBERRY PI 4 VALIDATION: NOT PERFORMED BY THIS SUITE.")
    print("============================================================")
    with open(os.path.join(LOG_DIR, "report.json"), "w") as f:
        json.dump({"results": RESULTS, "counts": counts, "aborted": abort_reason}, f, indent=2)
    bad = counts["FAIL"] > 0 or abort_reason is not None
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
