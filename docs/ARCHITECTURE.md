# NexOS — Architecture Système (`docs/ARCHITECTURE.md`)

NexOS est un système d'exploitation **serveur headless indépendant** (bare-metal ARM64, écrit en Rust `no_std`, assembleur AArch64 et C freestanding EL0), sans dépendance Linux.

## 1. Couches & Organisation du Code

- **`boot/entry.S`** : Point d'entrée AArch64 (`_start` et `_secondary_start`), descente EL3/EL2 → EL1, activation FPU/NEON (`CPACR_EL1.FPEN=0b11`), initialisation pile/BSS, préservation DTB (`x0`).
- **`arch/arm64/`** :
  - `mod.rs` + `neon_gemv.S` : registres système, `VBAR_EL1` (`exceptions.rs`, `vectors.S` avec `TrapFrame` 816 B sauvegardant `x0..x30` et `Q0..Q31`), `mmu.rs` (44-bit PA, pages 4K `W^X`, `map_user_region`/`unmap_user_region`), `smp.rs` (PSCI `CPU_ON`, `SYSTEM_OFF/RESET`), `timer.rs` (`CNTPCT_EL0`, tick 100 Hz).
  - `boards/{qemu_virt,rpi4}/` : isolation carte stricte (`linker.ld`, `config.txt`, constantes d'amorçage pré-DTB).
- **`kernel/`** : `main.rs`, `log.rs` (tampon circulaire), `ipc.rs` (canaux bornés avec réveil `WaitQueue`), `services.rs` (supervision + watchdog), `sync.rs` (`SpinLock`, `Mutex`, `Semaphore`, `WaitQueue`), `syscall.rs` (30 appels `0..29` avec validation `AT S1E0R/W`).
- **`memory/`** : `phys.rs` (bitmap physique dynamique respectant DTB `memreserve` et zones DMA < 4 Go), `heap.rs` (allocateur noyau à `VA=0x2000_0000_0000`, plafond `64 Mio`).
- **`scheduler/`** : ordonnanceur préemptif à priorités SMP 4 cœurs (`quantum = 20 ms`), affinité CPU, threads noyau/EL0, `reap_exited()`.
- **`drivers/`** : `dtb.rs`, `gicv2.rs`, `uart/` (`pl011.rs`, `mini_uart.rs`), `virtio/{blk,net}.rs`, `block/{ramdisk,cache,sd_emmc2}.rs`, `net/genet.rs`.
- **`filesystem/`** : `part.rs` (MBR/GPT), `fat32.rs` (lecture/écriture/mkdir/rm + sync), `vfs.rs` (`/ram`, `/disk`, blocage traversée `..`).
- **`network/`** : Ethernet II, ARP, IPv4, ICMP, UDP, DHCP, DNS, TCP, IPv6/ICMPv6, et `tls.rs` (TLS 1.3 RFC 8446 pur Rust).
- **`security/`** : `sha256.rs` (SHA-256, HMAC, PBKDF2), `mod.rs` (4 rôles RBAC, sessions Bearer HMAC, lockout exponentiel, audit).
- **`web-admin/`** : serveur HTTP/1.1 (`:80`) + HTTPS TLS 1.3 (`:443`) + endpoints `/api/v1/*`.
- **`ai_core/`** : format `.nxm` v1 (`format.rs`), tokenizer (`tokenizer.rs`), noyaux NEON/math (`tensor.rs`), Transformer causal Q8_0 + cache KV (`model.rs`), gestion budget RAM (`mod.rs`).
- **`userspace/`** : `crt0.S`, `user.ld`, `init.c` (sonde d'isolation EL0 + shell interactif EL0).

## 2. Séparation Matérielle QEMU vs Raspberry Pi 4

| Élément | QEMU `virt` (`[TESTÉ (QEMU)]`) | Raspberry Pi 4 BCM2711 (`[COMPILÉ / NON TESTÉ SUR MATÉRIEL]`) |
|---|---|---|
| Adresse de chargement | `0x40080000` (`nexos-qemu.bin`) | `0x00080000` (`kernel8.img`) via `start4.elf` |
| Timer `CNTFRQ_EL0` | `62.5 MHz` | `54 MHz` (lu dynamiquement au boot) |
| Interruptions | GICv2 `0x08000000` / `0x08010000` | GIC-400 `0xFF841000` / `0xFF842000` (lu via DTB) |
| Stockage bloc | `VirtioBlk` MMIO | `Bcm2711Emmc2` (testé uniquement par **mock MMIO** sous QEMU) |
| Interface réseau | `VirtioNet` MMIO | `Bcm2711Genet` v5 (testé uniquement par **mock MMIO** sous QEMU) |
