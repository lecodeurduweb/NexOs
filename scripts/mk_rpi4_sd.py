#!/usr/bin/env python3
"""Create a bootable MBR + FAT32 Raspberry Pi 4 SD card image (`nexos-rpi4-sd.img`).

FAT32 compliance (Microsoft FAT specification):
  * a volume is FAT32 only if it has >= 65525 data clusters; the previous
    32 MiB image had ~7.9k clusters (a FAT16 volume mislabelled "FAT32").
    The image is now 272 MiB with 4 KiB clusters (~69k clusters) and the
    cluster count is asserted at build time.
  * the FSInfo sector (1) and the backup boot sector (6) / backup FSInfo (7)
    announced by the BPB are actually written.
  * the image is written sparsely (only non-zero regions), so it costs little
    disk space while still being a plain raw image usable with `dd`.

STATUS: structure verified against NexOS MBR+FAT32 parsers on host & QEMU.
Physical Raspberry Pi 4 boot requires copying the Raspberry Pi Foundation boot
firmware files (`start4.elf`, `fixup4.dat`, `bcm2711-rpi-4-b.dtb`) onto this
FAT32 boot partition; those files are not redistributed by NexOS.
NOT YET EXECUTED ON PHYSICAL PI 4 HARDWARE.
"""

from __future__ import annotations

import os
import struct
import sys

SECTOR = 512
MIN_FAT32_CLUSTERS = 65525

README_FIRMWARE = b"""NexOS Raspberry Pi 4 (BCM2711) Boot Partition
==============================================

This FAT32 boot partition contains:
  - kernel8.img  (NexOS AArch64 kernel ELF->flat binary for BCM2711)
  - config.txt   (arm_64bit=1, enable_uart=1, gpu_mem=16, kernel=kernel8.img)
  - cmdline.txt  (headless UART kernel command line)

REQUIRED FIRMWARE (NOT REDISTRIBUTED BY NEXOS):
To boot on a physical Raspberry Pi 4 Model B, copy the official Raspberry Pi
Foundation firmware files from `raspberrypi/firmware/boot/` into the root of
this partition:
  - start4.elf
  - fixup4.dat
  - bcm2711-rpi-4-b.dtb

STATUS: Build-verified & FAT32 structure-verified on host; NOT YET EXECUTED ON PHYSICAL PI 4 HARDWARE.
"""


def _bpb(num_sectors: int, sectors_per_cluster: int, reserved: int, num_fats: int,
         fat_size: int, root_cluster: int) -> bytes:
    bpb = bytearray(SECTOR)
    bpb[0:3] = b"\xEB\x58\x90"
    bpb[3:11] = b"NEXOSFAT"
    struct.pack_into("<H", bpb, 11, SECTOR)
    bpb[13] = sectors_per_cluster
    struct.pack_into("<H", bpb, 14, reserved)
    bpb[16] = num_fats
    struct.pack_into("<H", bpb, 17, 0)      # root entries (0 for FAT32)
    struct.pack_into("<H", bpb, 19, 0)      # total sectors 16 (0 -> use 32-bit)
    bpb[21] = 0xF8
    struct.pack_into("<H", bpb, 22, 0)      # FAT size 16 (0 for FAT32)
    struct.pack_into("<H", bpb, 24, 63)
    struct.pack_into("<H", bpb, 26, 255)
    struct.pack_into("<I", bpb, 28, 0)      # hidden sectors
    struct.pack_into("<I", bpb, 32, num_sectors)
    struct.pack_into("<I", bpb, 36, fat_size)
    struct.pack_into("<H", bpb, 40, 0)      # ext flags: FAT mirroring enabled
    struct.pack_into("<H", bpb, 42, 0)      # FS version 0.0
    struct.pack_into("<I", bpb, 44, root_cluster)
    struct.pack_into("<H", bpb, 48, 1)      # FSInfo sector
    struct.pack_into("<H", bpb, 50, 6)      # backup boot sector
    bpb[64] = 0x80
    bpb[66] = 0x29
    struct.pack_into("<I", bpb, 67, 0x20261118)
    bpb[71:82] = b"NEXOS_BOOT "
    bpb[82:90] = b"FAT32   "
    bpb[510:512] = b"\x55\xAA"
    return bytes(bpb)


def _fsinfo(free_clusters: int, next_free: int) -> bytes:
    fsi = bytearray(SECTOR)
    struct.pack_into("<I", fsi, 0, 0x41615252)
    struct.pack_into("<I", fsi, 484, 0x61417272)
    struct.pack_into("<I", fsi, 488, free_clusters)
    struct.pack_into("<I", fsi, 492, next_free)
    struct.pack_into("<I", fsi, 508, 0xAA550000)
    return bytes(fsi)


def write_fat32_boot_partition(out, part_lba: int, num_sectors: int,
                               files: list[tuple[bytes, bytes]]) -> dict:
    """Write a FAT32 volume at `part_lba` into the open file `out` (sparse)."""
    sectors_per_cluster = 8  # 4 KiB clusters
    reserved = 32
    num_fats = 2
    # Solve FAT size so that FAT entries cover all data clusters.
    fat_size = 1
    while True:
        data_sectors = num_sectors - reserved - num_fats * fat_size
        total_clusters = data_sectors // sectors_per_cluster
        needed = ((total_clusters + 2) * 4 + SECTOR - 1) // SECTOR
        if needed <= fat_size:
            break
        fat_size = needed
    if total_clusters < MIN_FAT32_CLUSTERS:
        raise ValueError(
            f"FAT32 requires >= {MIN_FAT32_CLUSTERS} clusters, volume would have {total_clusters}; "
            "increase the partition size")
    root_cluster = 2
    data_start = reserved + num_fats * fat_size
    cluster_bytes = sectors_per_cluster * SECTOR

    def wr(lba_in_part: int, data: bytes) -> None:
        out.seek((part_lba + lba_in_part) * SECTOR)
        out.write(data)

    fat = bytearray(fat_size * SECTOR)
    struct.pack_into("<I", fat, 0, 0x0FFFFFF8)
    struct.pack_into("<I", fat, 4, 0x0FFFFFFF)
    struct.pack_into("<I", fat, 8, 0x0FFFFFFF)  # root dir: single cluster, EOC

    next_cluster = 3
    root_dir = bytearray()
    for dos_name, payload in files:
        assert len(dos_name) == 11, dos_name
        n_clusters = max(1, (len(payload) + cluster_bytes - 1) // cluster_bytes)
        first = next_cluster
        for i in range(n_clusters):
            cur = first + i
            nxt = cur + 1 if i + 1 < n_clusters else 0x0FFFFFFF
            struct.pack_into("<I", fat, cur * 4, nxt)
            chunk = payload[i * cluster_bytes:(i + 1) * cluster_bytes]
            if chunk:
                wr(data_start + (cur - 2) * sectors_per_cluster, chunk)
        next_cluster += n_clusters
        ent = bytearray(32)
        ent[0:11] = dos_name
        ent[11] = 0x20
        struct.pack_into("<H", ent, 20, (first >> 16) & 0xFFFF)
        struct.pack_into("<H", ent, 26, first & 0xFFFF)
        struct.pack_into("<I", ent, 28, len(payload))
        root_dir += ent
    if len(root_dir) > cluster_bytes:
        raise ValueError("root directory exceeds one cluster")
    wr(data_start + (root_cluster - 2) * sectors_per_cluster, bytes(root_dir))

    used = next_cluster - 2
    bpb = _bpb(num_sectors, sectors_per_cluster, reserved, num_fats, fat_size, root_cluster)
    fsi = _fsinfo(total_clusters - used, next_cluster)
    wr(0, bpb)
    wr(1, fsi)
    wr(6, bpb)   # backup boot sector
    wr(7, fsi)   # backup FSInfo
    for f in range(num_fats):
        wr(reserved + f * fat_size, bytes(fat))
    return {"clusters": total_clusters, "fat_size": fat_size, "used_clusters": used}


def build_rpi4_sd_image(kernel8_path: str, config_path: str, out_path: str,
                        total_mib: int = 272) -> None:
    with open(kernel8_path, "rb") as f:
        kernel8_bytes = f.read()
    with open(config_path, "rb") as f:
        config_bytes = f.read()
    cmdline_bytes = b"console=serial0,115200 nexos.headless=1\n"

    total_sectors = total_mib * 1024 * 1024 // SECTOR
    part_start = 2048
    part_sectors = total_sectors - part_start
    if len(kernel8_bytes) + 1024 * 1024 > part_sectors * SECTOR:
        raise ValueError("kernel8.img exceeds boot partition size")

    mbr = bytearray(SECTOR)
    off = 446
    mbr[off] = 0x80
    mbr[off + 4] = 0x0C  # W95 FAT32 (LBA)
    struct.pack_into("<I", mbr, off + 8, part_start)
    struct.pack_into("<I", mbr, off + 12, part_sectors)
    mbr[510:512] = b"\x55\xAA"

    files = [
        (b"KERNEL8 IMG", kernel8_bytes),
        (b"CONFIG  TXT", config_bytes),
        (b"CMDLINE TXT", cmdline_bytes),
        (b"README  TXT", README_FIRMWARE),
    ]

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "wb") as out:
        out.truncate(total_sectors * SECTOR)
        out.seek(0)
        out.write(bytes(mbr))
        info = write_fat32_boot_partition(out, part_start, part_sectors, files)
    print(
        f"Created RPi4 MBR+FAT32 SD image at {out_path} ({total_mib} MiB, "
        f"{info['clusters']} clusters, FAT={info['fat_size']} sectors, "
        f"kernel8.img={len(kernel8_bytes)} B). NOT TESTED ON PHYSICAL HARDWARE."
    )


if __name__ == "__main__":
    k8 = sys.argv[1] if len(sys.argv) > 1 else "build/rpi4/kernel8.img"
    cfg = sys.argv[2] if len(sys.argv) > 2 else "arch/arm64/boards/rpi4/config.txt"
    out = sys.argv[3] if len(sys.argv) > 3 else "build/rpi4/nexos-rpi4-sd.img"
    build_rpi4_sd_image(k8, cfg, out)
