#!/usr/bin/env python3
"""Create a bootable MBR + FAT32 Raspberry Pi 4 SD card image (`nexos-rpi4-sd.img`).

STATUS: Image structure is verified against NexOS MBR+FAT32 parsers on host & QEMU.
Physical Raspberry Pi 4 boot requires copying Raspberry Pi Foundation proprietary
boot firmware files (`start4.elf`, `fixup4.dat`, `bcm2711-rpi-4-b.dtb`) onto this
FAT32 boot partition; those proprietary blobs are not redistributed by NexOS.
"""

from __future__ import annotations

import os
import struct
import sys


README_FIRMWARE = b"""NexOS Raspberry Pi 4 (BCM2711) Boot Partition
==============================================

This FAT32 boot partition contains:
  - kernel8.img  (NexOS AArch64 kernel ELF->flat binary for BCM2711)
  - config.txt   (arm_64bit=1, enable_uart=1, gpu_mem=16, kernel=kernel8.img)
  - cmdline.txt  (headless UART kernel command line)

REQUIRED PROPRIETARY FIRMWARE (NOT REDISTRIBUTED):
To boot on a physical Raspberry Pi 4 Model B, copy the official Raspberry Pi
Foundation firmware files from `raspberrypi/firmware/boot/` into the root of
this partition:
  - start4.elf
  - fixup4.dat
  - bcm2711-rpi-4-b.dtb

STATUS: Build-verified & FAT32 structure-verified on host; NOT YET EXECUTED ON PHYSICAL PI 4 HARDWARE.
"""


def make_fat32_boot_partition(
    num_sectors: int,
    files: list[tuple[bytes, bytes]],
) -> bytearray:
    buf = bytearray(num_sectors * 512)
    bytes_per_sector = 512
    sectors_per_cluster = 8  # 4 KiB clusters
    reserved_sectors = 32
    num_fats = 2
    total_clusters = (num_sectors - reserved_sectors) // sectors_per_cluster
    fat_size_sectors = ((total_clusters + 2) * 4 + 511) // 512
    root_cluster = 2

    bpb = bytearray(512)
    bpb[0:3] = b"\xEB\x58\x90"
    bpb[3:11] = b"NEXOSFAT"
    struct.pack_into("<H", bpb, 11, bytes_per_sector)
    bpb[13] = sectors_per_cluster
    struct.pack_into("<H", bpb, 14, reserved_sectors)
    bpb[16] = num_fats
    struct.pack_into("<H", bpb, 17, 0)
    struct.pack_into("<H", bpb, 19, 0)
    bpb[21] = 0xF8
    struct.pack_into("<H", bpb, 22, 0)
    struct.pack_into("<H", bpb, 24, 63)
    struct.pack_into("<H", bpb, 26, 255)
    struct.pack_into("<I", bpb, 32, num_sectors)
    struct.pack_into("<I", bpb, 36, fat_size_sectors)
    struct.pack_into("<H", bpb, 40, 0)
    struct.pack_into("<H", bpb, 42, 0)
    struct.pack_into("<I", bpb, 44, root_cluster)
    struct.pack_into("<H", bpb, 48, 1)
    struct.pack_into("<H", bpb, 50, 6)
    bpb[64] = 0x80
    bpb[66] = 0x29
    struct.pack_into("<I", bpb, 67, 0x20261118)
    bpb[71:82] = b"NEXOS_BOOT "
    bpb[82:90] = b"FAT32   "
    bpb[510:512] = b"\x55\xAA"
    buf[0:512] = bpb

    fat_bytes = bytearray(fat_size_sectors * 512)
    struct.pack_into("<I", fat_bytes, 0, 0x0FFFFFF8)
    struct.pack_into("<I", fat_bytes, 4, 0x0FFFFFFF)
    struct.pack_into("<I", fat_bytes, 8, 0x0FFFFFFF)  # root dir cluster 2

    data_start_lba = reserved_sectors + num_fats * fat_size_sectors
    cluster_size = sectors_per_cluster * bytes_per_sector
    next_cluster = 3
    root_off = data_start_lba * 512

    for idx, (dos_name, payload) in enumerate(files):
        n_clusters = max(1, (len(payload) + cluster_size - 1) // cluster_size)
        first_cluster = next_cluster
        for c_idx in range(n_clusters):
            cur_c = first_cluster + c_idx
            nxt = (cur_c + 1) if (c_idx + 1 < n_clusters) else 0x0FFFFFFF
            struct.pack_into("<I", fat_bytes, cur_c * 4, nxt)
            c_lba = data_start_lba + (cur_c - 2) * sectors_per_cluster
            chunk = payload[c_idx * cluster_size : (c_idx + 1) * cluster_size]
            buf[c_lba * 512 : c_lba * 512 + len(chunk)] = chunk
        next_cluster += n_clusters

        ent = bytearray(32)
        ent[0:11] = dos_name
        ent[11] = 0x20
        struct.pack_into("<H", ent, 20, (first_cluster >> 16) & 0xFFFF)
        struct.pack_into("<H", ent, 26, first_cluster & 0xFFFF)
        struct.pack_into("<I", ent, 28, len(payload))
        buf[root_off + idx * 32 : root_off + (idx + 1) * 32] = ent

    for f in range(num_fats):
        off = (reserved_sectors + f * fat_size_sectors) * 512
        buf[off : off + len(fat_bytes)] = fat_bytes

    return buf


def build_rpi4_sd_image(kernel8_path: str, config_path: str, out_path: str) -> None:
    with open(kernel8_path, "rb") as f:
        kernel8_bytes = f.read()
    with open(config_path, "rb") as f:
        config_bytes = f.read()

    cmdline_bytes = b"console=serial0,115200 nexos.headless=1 root=/dev/mmcblk0p1\n"

    total_sectors = 65536  # 32 MiB SD card image
    part_start = 2048
    part_sectors = total_sectors - part_start
    if len(kernel8_bytes) + 256 * 1024 > part_sectors * 512:
        raise ValueError("kernel8.img exceeds 32 MiB boot partition size")

    disk = bytearray(total_sectors * 512)

    # Bootable MBR Partition 1 (0x0C = W95 FAT32 LBA, active=0x80)
    mbr = bytearray(512)
    off = 446
    mbr[off] = 0x80
    mbr[off + 4] = 0x0C
    struct.pack_into("<I", mbr, off + 8, part_start)
    struct.pack_into("<I", mbr, off + 12, part_sectors)
    mbr[510:512] = b"\x55\xAA"
    disk[0:512] = mbr

    files = [
        (b"KERNEL8 IMG", kernel8_bytes),
        (b"CONFIG  TXT", config_bytes),
        (b"CMDLINETXT".replace(b"CMDLINETXT", b"CMDLINE TXT"), cmdline_bytes),
        (b"README  TXT", README_FIRMWARE),
    ]
    fat = make_fat32_boot_partition(part_sectors, files)
    disk[part_start * 512 : part_start * 512 + len(fat)] = fat

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(disk)
    print(
        f"Created RPi4 MBR+FAT32 SD image at {out_path} ({len(disk) // (1024 * 1024)} MiB, "
        f"kernel8.img={len(kernel8_bytes)} B)"
    )


if __name__ == "__main__":
    k8 = sys.argv[1] if len(sys.argv) > 1 else "build/rpi4/kernel8.img"
    cfg = sys.argv[2] if len(sys.argv) > 2 else "arch/arm64/boards/rpi4/config.txt"
    out = sys.argv[3] if len(sys.argv) > 3 else "build/rpi4/nexos-rpi4-sd.img"
    build_rpi4_sd_image(k8, cfg, out)
