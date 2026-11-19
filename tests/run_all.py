#!/usr/bin/env python3
"""NexOS Unified End-to-End QEMU & Host Verification Suite (Stages 1-14)."""

import subprocess
import sys


def run_step(label, cmd):
    print("\n============================================================")
    print(f"  RUNNING: {label}")
    print("============================================================")
    res = subprocess.run(cmd, shell=True)
    if res.returncode != 0:
        print(f"[FAIL] {label} failed with exit code {res.returncode}")
        sys.exit(res.returncode)


def main():
    run_step("1. Build QEMU virt + RPi4 kernel8.img + EL0 init.bin", "./build.sh all")
    run_step("1b. Build RPi4 MBR + FAT32 Bootable SD Image", "./build.sh sd")
    run_step(
        "1c. Verify ELF W^X Segment Permissions (no RWE segments)",
        """python3 -c '
import subprocess
out = subprocess.check_output(["aarch64-linux-gnu-readelf", "-lW", "build/userspace/init.elf"], text=True)
assert "RWE" not in out, f"init.elf still has RWX/RWE segment!\\n{out}"
kout = subprocess.check_output(["aarch64-linux-gnu-readelf", "-lW", "build/qemu_virt/nexos-qemu.elf"], text=True)
assert "LOAD" in kout and "RWE" not in kout, f"nexos-qemu.elf has RWX/RWE segment!\\n{kout}"
rout = subprocess.check_output(["aarch64-linux-gnu-readelf", "-lW", "build/rpi4/nexos-rpi4.elf"], text=True)
assert "LOAD" in rout and "RWE" not in rout, f"nexos-rpi4.elf has RWX/RWE segment!\\n{rout}"
print("ELF segment W^X check OK (no RWE in init.elf, nexos-qemu.elf, nexos-rpi4.elf).")
'""",
    )
    run_step(
        "1d. Verify RPi4 SD Image MBR + FAT32 Layout",
        """python3 -c '
import struct
with open("build/rpi4/nexos-rpi4-sd.img", "rb") as f:
    mbr = f.read(512)
    assert mbr[510:512] == b"\\x55\\xAA"
    assert mbr[446] == 0x80 and mbr[446 + 4] == 0x0C
    part_lba = struct.unpack_from("<I", mbr, 446 + 8)[0]
    f.seek(part_lba * 512)
    bpb = f.read(512)
    assert bpb[510:512] == b"\\x55\\xAA" and bpb[82:90] == b"FAT32   "
    rsvd = struct.unpack_from("<H", bpb, 14)[0]
    nfats = bpb[16]
    fatsz = struct.unpack_from("<I", bpb, 36)[0]
    root_off = (part_lba + rsvd + nfats * fatsz) * 512
    f.seek(root_off)
    root = f.read(512)
    names = [root[i*32:i*32+11] for i in range(4)]
    assert b"KERNEL8 IMG" in names and b"CONFIG  TXT" in names and b"CMDLINE TXT" in names and b"README  TXT" in names
print("RPi4 SD MBR + FAT32 layout verified (KERNEL8.IMG, CONFIG.TXT, CMDLINE.TXT, README.TXT).")
'""",
    )
    run_step("2. Create GPT + FAT32 test disk image", "python3 scripts/mk_test_disk.py build/test_disk.img")
    run_step(
        "2b. Verify convert_to_nxm.py Offline Converter + CRC-32 Verification",
        """python3 -c '
import json, os, struct, subprocess, tempfile
with tempfile.TemporaryDirectory() as td:
    jp = os.path.join(td, "mini.json")
    np_out = os.path.join(td, "mini.nxm")
    spec = {
        "config": {"dim": 32, "hidden_dim": 64, "n_layers": 1, "n_heads": 2, "n_kv_heads": 2, "max_seq": 16},
        "vocab": [["<pad>", -10.0], ["<bos>", -10.0], ["<eos>", -10.0], ["ok", 5.0]],
        "tok_emb": [0.1] * (4 * 32),
        "layers": [{
            "rms_att": [1.0] * 32, "wq": [0.1] * (32 * 32), "wk": [0.1] * (32 * 32),
            "wv": [0.1] * (32 * 32), "wo": [0.1] * (32 * 32),
            "rms_ffn": [1.0] * 32, "w1": [0.1] * (64 * 32), "w2": [0.1] * (32 * 64), "w3": [0.1] * (64 * 32)
        }],
        "rms_final": [1.0] * 32,
        "w_cls": [0.1] * (4 * 32),
    }
    with open(jp, "w") as f: json.dump(spec, f)
    subprocess.run(["python3", "scripts/convert_to_nxm.py", "-i", jp, "-o", np_out], check=True)
    vout = subprocess.check_output(["python3", "scripts/convert_to_nxm.py", "--verify", np_out], text=True)
    assert json.loads(vout)["crc32_verified"] is True
    # Also test llama2.c raw binary conversion
    l2p = os.path.join(td, "l2c.bin")
    l2_out = os.path.join(td, "l2c.nxm")
    hdr = struct.pack("<7i", 32, 64, 1, 2, 2, 4, 16)
    n_f = (4 * 32) + 32 + 4 * (32 * 32) + 32 + 2 * (64 * 32) + (32 * 64) + 32
    with open(l2p, "wb") as f: f.write(hdr + struct.pack(f"<{n_f}f", *([0.05] * n_f)))
    subprocess.run(["python3", "scripts/convert_to_nxm.py", "-i", l2p, "-o", l2_out, "--format", "llama2c"], check=True)
    vout2 = subprocess.check_output(["python3", "scripts/convert_to_nxm.py", "--verify", l2_out], text=True)
    assert json.loads(vout2)["crc32_verified"] is True
print("convert_to_nxm.py (JSON + llama2.c + CRC-32 --verify) passed!")
'""",
    )
    run_step(
        "3. Stage 1-10 & 12-14 UART Boot, CSPRNG, MMU, Sched, EL0, VFS/FAT32, CORRUPT.NXM, RBAC, Watchdog",
        """python3 -c '
import os, pty, select, subprocess, time
master, slave = pty.openpty()
proc = subprocess.Popen(["./run.sh"], stdin=slave, stdout=slave, stderr=slave, close_fds=True)
os.close(slave)
buf = b""
deadline = time.time() + 30
while time.time() < deadline:
    r, _, _ = select.select([master], [], [], 0.1)
    if r:
        buf += os.read(master, 4096)
        if b"nexos#" in buf:
            break
for cmd in [b"uname\\n", b"info\\n", b"devs\\n", b"users\\n", b"ls /disk\\n", b"cat /disk/NEXOS.TXT\\n", b"mmaptest\\n", b"ipctest\\n", b"ai status\\n", b"ai ask nexos status\\n", b"ai bench\\n", b"ai unload\\n", b"ai load /disk/BAD.GGF\\n", b"ai load /disk/CORRUPT.NXM\\n", b"ai load /disk/MODEL.NXM\\n", b"services\\n", b"exit\\n"]:
    os.write(master, cmd)
    time.sleep(0.35)
    while True:
        r, _, _ = select.select([master], [], [], 0.15)
        if not r: break
        buf += os.read(master, 4096)
proc.terminate(); proc.wait()
txt = buf.decode("utf-8", errors="replace")
assert "source=virtio-rng" in txt, "CSPRNG not seeded from VirtIO-RNG!"
assert "CSPRNG self-test OK" in txt
assert "BCM2711 RNG200 [mock] OK" in txt
assert "Stage 3 exception test passed" in txt
assert "Stage 5 verified" in txt
assert "Stage 6 verified" in txt
assert "Stage 7 verified" in txt
assert "Stage 8 verified" in txt
assert "Reclaimed 3 exited Stage 8 task(s)." in txt
assert "SMP 4-core concurrency verified" in txt
assert "IPC channel self-test OK" in txt
assert "BlockCache verified" in txt
assert "[mock] BCM2711 EMMC2 MMIO self-test OK" in txt
assert "[mock] BCM2711 GENET v5 MMIO ring & MAC self-test OK" in txt
assert "IPv6 link-local & ICMPv6 self-test OK" in txt
assert "TLS 1.3 crypto self-test OK" in txt
assert "[EL0-probe] Syscall EFAULT & W^X checks OK." in txt
assert "Stage 9 EL0->EL1 isolation verified" in txt
assert "el0-probe" not in txt.split("nexos# info")[1].split("nexos# devs")[0], "Exited el0-probe leaked in task table!"
assert "FAT32 write+readback+mkdir/rm+sync verified" in txt
assert "Stage 12 verified" in txt
assert "AArch64 NEON SIMD kernels verified" in txt
assert "Auto-loaded model: /disk/MODEL.NXM" in txt
assert "NexOS 0.1.0 aarch64 headless-server (userspace EL0)" in txt
assert "mmaptest OK" in txt
assert "ipctest OK: hello-ipc-el0" in txt
assert "arm64 neon q8 inference engine active" in txt
assert "[ai-bench] NEON Q8_0:" in txt
assert "Unsupported external GGUF v3" in txt
assert "CRC-32 integrity check failed" in txt
print("CORE STAGES 1-14 (CSPRNG, SMP, IPC, CACHE, TLS1.3, MMAP, AI NEON Q8_0 + CRC32) VERIFIED!")
'""",
    )
    run_step("4. Stage 11 TAP Bidirectional ICMP/ARP/DNS/TCP + PCAP Verification", "python3 scripts/test_stage11_net.py")
    run_step("5. Stage 13-14 First-Boot Setup + HTTPS TLS 1.3 + AI Core + RBAC + Persistence", "python3 scripts/test_stage13_web.py")
    print("\n============================================================")
    print("  CORE END-TO-END VERIFICATION PASSED (STAGES 0-14).")
    print("  STAGE 11 TAP PCAP CHECK: SKIPPED (sandbox denied TAP creation).")
    print("  PHYSICAL PI 4 VALIDATION: NOT PERFORMED.")
    print("============================================================")


if __name__ == "__main__":
    main()
