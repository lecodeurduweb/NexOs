# NexOS — Budgets Ressources & Mesures Réelles (`docs/BUDGETS.md`)

> **Règle d'intégrité** : Toute mesure de la colonne *Mesuré (QEMU `virt`)* provient d'exécutions réelles relevées sur QEMU `7.2.22` (`-machine virt,gic-version=2,virtualization=on -cpu cortex-a72 -smp 4 -m 1024M`). Les mesures sur matériel Raspberry Pi 4 réel restent **NON TESTÉ SUR MATÉRIEL**.

## 1. Budgets Mémoire (Cible : Raspberry Pi 4 — 8 Gio RAM)

| Composant | Plafond Cible | Mesuré (QEMU `virt`) | Mesuré (Pi 4 Réel) | Notes |
|---|---|---|---|---|
| Image noyau chargée (`.text`+`.rodata`+`.data`+`.bss`+pile) | ≤ 32 Mio | `404 072 B` (`395 KiB` `.bin` / `546 KiB` `.elf`) | *NON TESTÉ SUR MATÉRIEL* (`408 168 B` `kernel8.img`) | 3 segments W^X ; `0x40080000` QEMU / `0x80000` Pi 4 |
| Allocateur physique (bitmap) | ≤ 4 Mio | **64 Kio** pour 1 Gio RAM (`256 Kio` pour 8 Gio) | *NON TESTÉ SUR MATÉRIEL* | Bitmap dynamique à `0x40000000` |
| Heap noyau (`memory/heap.rs`) | ≤ 128 Mio | **413–426 Kio utilisés / 3 276–3 354 Kio mappés** (plafond 64 Mio) | *NON TESTÉ SUR MATÉRIEL* | Inclut buffers TLS/VFS/AI |
| Userspace EL0 (`init.bin` + piles noyau tâches) | ≤ 512 Mio | `12 288 B` `init.bin` (`0` seg `RWE`), ~350 Kio total | *NON TESTÉ SUR MATÉRIEL* | Libération auto via `reap_exited()` |
| NexOS AI Core (`ai_core/`) | ≤ 5 120 Mio (5 Gio défaut) | **168 Kio** modèle actif (`/disk/MODEL.NXM`, budget 61 025 Kio sous QEMU 1G) | *NON TESTÉ SUR MATÉRIEL* | Zéro swap SD ; budget borné `effective_budget_bytes()` |
| Marge libre système | ≥ ~1,8 Gio | **1 018 Mio libres** sur `1 024 Mio` | *NON TESTÉ SUR MATÉRIEL* | Régions réservées DTB respectées |

## 2. Journal des Mesures Réelles Vérifiées (`tests/run_all.py`)

- **CPU & SMP** : `MIDR_EL1 = 0x410fd083` (Cortex-A72), `PARange = 44 bits`, `CNTFRQ_EL0 = 62,5 MHz` (`100 Hz`), `4/4` cœurs en ligne (`online_mask=0b1111`), `mutex_sum=100`.
- **Temps de démarrage (QEMU `virt` 4 cœurs)** : ~**760–1 320 ms** jusqu'au shell EL0 + HTTP `:80` + HTTPS TLS 1.3 `:443` + auto-chargement `MODEL.NXM`.
- **Stockage (`virtio-blk` + GPT + FAT32)** : disque `16 MiB`, lecture/écriture/mkdir/rm/sync `/disk`, cache (`hits=381, misses=467`), `EMMC2` validé par **mock MMIO**.
- **Réseau (`virtio-net` + TAP `10.77.0.2` + TLS 1.3)** : Ping hôte↔VM `0,38–5,89 ms`, `29` pkts PCAP (`2` ARP, `6` ICMP req/rep, `2` DHCP, `2` DNS, `11` TCP), handshake `TLSv1.3` (`TLS_CHACHA20_POLY1305_SHA256`), `GENET v5` validé par **mock MMIO**.
- **IA Native NEON Q8_0 (`ai_core/`)** : **`429,05 – 488,35 tok/s`** mesurés par `CNTPCT_EL0` (`13` tokens en `26,6–30,3 ms` sur modèle test `dim=64`, `2` couches).
