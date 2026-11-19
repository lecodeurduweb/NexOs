# NexOS — Document de Reprise (`HANDOFF.md`)

## 1. État Réel Actuel
- **Étapes 0 à 14 + Finalisation** : `TESTÉ (QEMU)` sur QEMU `virt` (`gic-version=2`, `cortex-a72`, SMP 4 cœurs, VirtIO-RNG/Blk/Net).
- **Durcissements complets appliqués** :
  - **Zéro mot de passe codé en dur** : CSPRNG ChaCha20 DRBG amorcé par `VirtioRng` (QEMU) / `BCM2711 RNG200` (Pi 4), provisioning premier démarrage via UART (`setup`) ou HTTPS TLS 1.3 (`POST /api/v1/setup` + jeton CSPRNG 24 hex chars), et persistance à froid sur `/disk/NEXUSERS.DB` et `/disk/AIMEM.DB` (tous deux bloqués `403` sur `/api/v1/files`).
  - **Séparation `W^X` et isolation EL0** : `.text` RX, `.rodata` RO+NX, `.data`/`.bss`/Heap RW+NX ; `init.elf`, `nexos-qemu.elf` et `nexos-rpi4.elf` vérifiés `0` segment `RWE` ; syscalls `0..30` validés par `AT S1E0R/W` ; piles noyau `64 KiB`.
  - **AI Arena multi-Go & Streaming VFS** : `memory/ai_arena.rs` (`VA=0x300000000000`, aperture `+16 GiB`, réserve OS `128 MiB`, plafond `7.5 GiB` sur Pi 4 8 Go), chargement par curseur `VfsCursor`/`FatFileCursor` par tranches `64 KiB`, `arena_used=0 B` garanti au déchargement.
  - **Stockage, Réseau & TLS 1.3** : `CachedBlockDevice` write-back, FAT32 (`/disk`, `/ram`), Ethernet/ARP/IPv4/DHCP/ICMP/UDP/DNS/TCP, IPv6/ICMPv6, et **TLS 1.3** (`X25519` + `ChaCha20-Poly1305` + `Ed25519`), dashboard SPA HTML (`GET /`, `16 300 B`) + `/api/v1/*`.
  - **NexOS AI Core + Modèle Réel + Agent Autonome (`ai_core/`)** : noyaux assembleur NEON (`neon_gemv.S`), contrôle CRC-32 (`CORRUPT.NXM` rejeté), rejet GGUF, convertisseur `scripts/convert_to_nxm.py`, validation modèle réel préentraîné **`stories260K`** (`STORIES.NXM`, `159–167 tok/s`), et agent autonome (`agent.rs`, `14` outils, `diagnose`, réparation RBAC vérifiée, `rollback`, filtre injection).
- **Artefacts Raspberry Pi 4 (`BCM2711`)** : `build/rpi4/kernel8.img`, `config.txt` et `build/rpi4/nexos-rpi4-sd.img` (`./build.sh sd`) sont **`COMPILÉ / NON TESTÉ SUR MATÉRIEL`** (QEMU 7.2.22 ne fournit pas `raspi4b`). `Bcm2711Emmc2`, `Bcm2711Genet`, `Bcm2711Rng200`, `Bcm2711Gpio` et `Bcm2711Mailbox` sont validés par **mock MMIO sous QEMU**. `VL805 PCIe xHCI USB` et `VideoCore VI HDMI/3D` sont `NON IMPLÉMENTÉ` (serveur headless).

## 2. Architecture et Arborescence Active
```text
/
├── Cargo.toml / .cargo/config.toml
├── build.sh / run.sh / FINAL_REPORT.md
├── boot/entry.S
├── arch/arm64/
│   ├── mod.rs, vectors.S, exceptions.rs, timer.rs, mmu.rs, smp.rs, neon_gemv.S
│   └── boards/{mod.rs, qemu_virt/*, rpi4/*}
├── kernel/{main.rs, log.rs, ipc.rs, services.rs, sync.rs, syscall.rs}
├── drivers/
│   ├── mod.rs, dtb.rs, gicv2.rs, rng_bcm2711.rs [MOCK MMIO], uart/*
│   ├── gpio_bcm2711.rs [MOCK MMIO], mailbox_bcm2711.rs [MOCK MMIO]
│   ├── block/{mod.rs, ramdisk.rs, cache.rs, sd_emmc2.rs [MOCK MMIO]}
│   ├── net/{mod.rs, genet.rs [MOCK MMIO]}
│   └── virtio/{mod.rs, blk.rs, net.rs, rng.rs}
├── filesystem/{mod.rs, part.rs, fat32.rs, vfs.rs}
├── network/{mod.rs, eth.rs, arp.rs, ipv4.rs, icmp.rs, udp.rs, dhcp.rs, dns.rs, tcp.rs, ipv6.rs, tls.rs}
├── security/{mod.rs, sha256.rs, csprng.rs}
├── web-admin/mod.rs
├── ai_core/{mod.rs, format.rs, tokenizer.rs, tensor.rs, model.rs, agent.rs}
├── memory/{mod.rs, phys.rs, heap.rs, ai_arena.rs}
├── scheduler/mod.rs
├── userspace/{user.ld, crt0.S, init.c}
├── scripts/{mk_test_model.py, mk_test_disk.py, convert_to_nxm.py, mk_rpi4_sd.py, test_stage11_net.py, test_stage13_web.py}
├── tests/run_all.py
└── docs/*.md
```

## 3. Commandes de Build et Test
- Build complet : `./build.sh all && ./build.sh sd`
- Suite complète bout-en-bout QEMU : `python3 tests/run_all.py`
- Lancement interactif QEMU : `./run.sh` (`http://127.0.0.1:18080`, `https://127.0.0.1:18443`)

## 4. Prochaine Étape Matérielle (Hors Émulation)
1. Flasher `build/rpi4/nexos-rpi4-sd.img` (ou copier `kernel8.img` + `config.txt` sur microSD FAT32 avec `start4.elf`, `fixup4.dat`, `bcm2711-rpi-4-b.dtb`, `overlays/disable-bt.dtbo`) et suivre [`docs/HARDWARE_TEST.md`](docs/HARDWARE_TEST.md) sur un Raspberry Pi 4 Model B 8 Go réel via adaptateur USB-UART 3,3 V.
2. Valider `Bcm2711Emmc2`, `Bcm2711Genet`, `Bcm2711Rng200`, `Bcm2711Gpio`, `Bcm2711Mailbox` et `bcm2711_hw_watchdog` sur le silicium BCM2711 physique.
