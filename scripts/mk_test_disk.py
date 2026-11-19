#!/usr/bin/env python3
"""Generate a 16 MiB raw disk image with GPT partition table + FAT32 partition 1."""

import os
import struct
import sys
import zlib


def make_fat32_partition(num_sectors: int) -> bytearray:
    buf = bytearray(num_sectors * 512)
    bytes_per_sector = 512
    sectors_per_cluster = 8  # 4 KiB clusters
    reserved_sectors = 32
    num_fats = 2
    total_clusters = (num_sectors - reserved_sectors) // sectors_per_cluster
    fat_size_sectors = ((total_clusters + 2) * 4 + 511) // 512
    root_cluster = 2

    # Boot sector / BPB (512 bytes)
    bpb = bytearray(512)
    bpb[0:3] = b"\xEB\x58\x90"
    bpb[3:11] = b"NEXOSFAT"
    struct.pack_into("<H", bpb, 11, bytes_per_sector)
    bpb[13] = sectors_per_cluster
    struct.pack_into("<H", bpb, 14, reserved_sectors)
    bpb[16] = num_fats
    struct.pack_into("<H", bpb, 17, 0)  # root_entry_count = 0 for FAT32
    struct.pack_into("<H", bpb, 19, 0)  # total_sectors_16 = 0
    bpb[21] = 0xF8  # media
    struct.pack_into("<H", bpb, 22, 0)  # fat_size_16 = 0
    struct.pack_into("<H", bpb, 24, 63)
    struct.pack_into("<H", bpb, 26, 255)
    struct.pack_into("<I", bpb, 32, num_sectors)
    struct.pack_into("<I", bpb, 36, fat_size_sectors)
    struct.pack_into("<H", bpb, 40, 0)  # ext_flags
    struct.pack_into("<H", bpb, 42, 0)  # fs_version
    struct.pack_into("<I", bpb, 44, root_cluster)
    struct.pack_into("<H", bpb, 48, 1)  # fs_info
    struct.pack_into("<H", bpb, 50, 6)  # backup_boot_sector
    bpb[64] = 0x80
    bpb[66] = 0x29
    struct.pack_into("<I", bpb, 67, 0x20261116)
    bpb[71:82] = b"NEXOSDISK  "
    bpb[82:90] = b"FAT32   "
    bpb[510:512] = b"\x55\xAA"
    buf[0:512] = bpb

    # Root directory at cluster 2 (4 KiB = 128 x 32B entries; clusters start at 3)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)
    from mk_test_model import build_bad_gguf_stub, build_corrupt_nxm_bytes, build_nxm_bytes

    files = [
        (b"HELLO   TXT", b"Hello from VirtIO-BLK GPT FAT32 on NexOS!\n"),
        (b"MODEL   NXM", build_nxm_bytes()),
        (b"CORRUPT NXM", build_corrupt_nxm_bytes()),
        (b"BAD     GGF", build_bad_gguf_stub()),
    ]

    fat_bytes = bytearray(fat_size_sectors * 512)
    struct.pack_into("<I", fat_bytes, 0, 0x0FFFFFF8)
    struct.pack_into("<I", fat_bytes, 4, 0x0FFFFFFF)
    struct.pack_into("<I", fat_bytes, 8, 0x0FFFFFFF)  # cluster 2: root dir EOC

    data_start_lba = reserved_sectors + num_fats * fat_size_sectors
    cluster_size = sectors_per_cluster * bytes_per_sector  # 4096 bytes
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
        ent[11] = 0x20  # Archive
        struct.pack_into("<H", ent, 20, (first_cluster >> 16) & 0xFFFF)
        struct.pack_into("<H", ent, 26, first_cluster & 0xFFFF)
        struct.pack_into("<I", ent, 28, len(payload))
        buf[root_off + idx * 32 : root_off + (idx + 1) * 32] = ent

    for f in range(num_fats):
        off = (reserved_sectors + f * fat_size_sectors) * 512
        buf[off : off + len(fat_bytes)] = fat_bytes

    return buf


def build_gpt_disk(out_path: str) -> None:
    total_sectors = 32768  # 16 MiB
    part_start = 2048
    part_sectors = total_sectors - 2048 - 64
    part_last = part_start + part_sectors - 1

    disk = bytearray(total_sectors * 512)

    # Protective MBR (type 0xEE)
    mbr = bytearray(512)
    mbr[446 + 4] = 0xEE
    struct.pack_into("<I", mbr, 446 + 8, 1)
    struct.pack_into("<I", mbr, 446 + 12, total_sectors - 1)
    mbr[510:512] = b"\x55\xAA"
    disk[0:512] = mbr

    # GPT Partition Entry Array (128 entries * 128 bytes = 32 sectors at LBA 2)
    entries = bytearray(128 * 128)
    # Basic data partition GUID (EBD0A0A2-B9E5-4433-87C0-68B6B72699C7)
    type_guid = bytes.fromhex("a2a0d0ebe5b9334487c068b6b72699c7")
    uniq_guid = bytes.fromhex("112233445566778899aabbccddeeff01")
    entries[0:16] = type_guid
    entries[16:32] = uniq_guid
    struct.pack_into("<Q", entries, 32, part_start)
    struct.pack_into("<Q", entries, 40, part_last)
    name_utf16 = "NEXOS_DATA".encode("utf-16le")
    entries[56 : 56 + len(name_utf16)] = name_utf16
    disk[2 * 512 : 2 * 512 + len(entries)] = entries

    entries_crc = zlib.crc32(entries) & 0xFFFFFFFF

    # Primary GPT Header at LBA 1
    hdr = bytearray(512)
    hdr[0:8] = b"EFI PART"
    struct.pack_into("<I", hdr, 8, 0x00010000)  # Revision 1.0
    struct.pack_into("<I", hdr, 12, 92)         # HeaderSize
    struct.pack_into("<Q", hdr, 24, 1)          # MyLBA
    struct.pack_into("<Q", hdr, 32, total_sectors - 1)  # AlternateLBA
    struct.pack_into("<Q", hdr, 40, 34)         # FirstUsableLBA
    struct.pack_into("<Q", hdr, 48, total_sectors - 34)  # LastUsableLBA
    hdr[56:72] = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
    struct.pack_into("<Q", hdr, 72, 2)          # PartitionEntryLBA
    struct.pack_into("<I", hdr, 80, 128)        # NumberOfPartitionEntries
    struct.pack_into("<I", hdr, 84, 128)        # SizeOfPartitionEntry
    struct.pack_into("<I", hdr, 88, entries_crc)
    hdr_crc = zlib.crc32(hdr[0:92]) & 0xFFFFFFFF
    struct.pack_into("<I", hdr, 16, hdr_crc)
    disk[512:1024] = hdr

    # Write FAT32 partition into LBA part_start
    fat_part = make_fat32_partition(part_sectors)
    disk[part_start * 512 : part_start * 512 + len(fat_part)] = fat_part

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(disk)
    print(f"Created GPT + FAT32 disk image at {out_path} ({len(disk) // (1024 * 1024)} MiB)")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "build/test_disk.img"
    build_gpt_disk(target)
