# NexOS — Document de Reprise (`HANDOFF.md`)

## 1. État Réel Actuel
- **Étapes 0 à 14** : `TESTÉ (QEMU)` sur QEMU `virt` (`gic-version=2`, `cortex-a72`, SMP 4 cœurs, VirtIO-RNG/Blk/Net).
- **Durcissements complets appliqués** :
  - **Zéro mot de passe codé en dur** : CSPRNG ChaCha20 DRBG amorcé par `VirtioRng` (QEMU) / `BCM2711 RNG200` (Pi 4), provisioning premier démarrage via UART (`setup`) ou HTTPS TLS 1.3 (`POST /api/v1/setup` + jeton CSPRNG 24 hex chars), et persistance sur `/disk/NEXUSERS.DB` vérifiée à froid.
  - **Séparation `W^X` et isolation EL0** : `.text` RX, `.rodata` RO+NX, `.data`/`.bss`/Heap RW+NX ; `init.elf`, `nexos-qemu.elf` et `nexos-rpi4.elf` vérifiés `0` segment `RWE` ; syscalls `0..30` validés par `AT S1E0R/W` ; piles noyau par tâche portées à `64 KiB` et `NxmModel` alloué sur le tas (`Box<NxmModel>`).
  - **Stockage, Réseau & TLS 1.3** : `CachedBlockDevice` write-back, FAT32 (`/disk`, `/ram`), Ethernet/ARP/IPv4/DHCP/ICMP/UDP/DNS/TCP, IPv6/ICMPv6, et **TLS 1.3** (`X25519` + `ChaCha20-Poly1305` + `Ed25519`), dashboard SPA HTML (`GET /`) + `/api/v1/*`.
  - **NexOS AI Core (`.nxm` v1 Q8_0 + NEON)** : noyaux assembleur AArch64 NEON (`neon_gemv.S`), contrôle d'intégrité CRC-32 (`CORRUPT.NXM` rejeté), rejet GGUF diagnostique, convertisseur hôte `scripts/convert_to_nxm.py` (`JSON` et `llama2.c`).
- **Artefacts Raspberry Pi 4 (`BCM2711`)** : `build/rpi4/kernel8.img`, `config.txt` et image SD bootable `build/rpi4/nexos-rpi4-sd.img` (`./build.sh sd`) sont **`COMPILÉ / NON TESTÉ SUR MATÉRIEL`** (QEMU 7.2.22 ne fournit pas `raspi4b`). `Bcm2711Emmc2`, `Bcm2711Genet` et `Bcm2711Rng200` sont validés par **mock MMIO sous QEMU**.

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
│   ├── mod.rs, dtb.rs, gicv2.rs, rng_bcm2711.rs, uart/*
│   ├── block/{mod.rs, ramdisk.rs, cache.rs, sd_emmc2.rs [MOCK MMIO]}
│   ├── net/{mod.rs, genet.rs [MOCK MMIO]}
│   └── virtio/{mod.rs, blk.rs, net.rs, rng.rs}
├── filesystem/{mod.rs, part.rs, fat32.rs, vfs.rs}
├── network/{mod.rs, eth.rs, arp.rs, ipv4.rs, icmp.rs, udp.rs, dhcp.rs, dns.rs, tcp.rs, ipv6.rs, tls.rs}
├── security/{mod.rs, sha256.rs, csprng.rs}
├── web-admin/mod.rs
├── ai_core/{mod.rs, format.rs, tokenizer.rs, tensor.rs, model.rs}
├── memory/{mod.rs, phys.rs, heap.rs}
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
2. Valider `Bcm2711Emmc2`, `Bcm2711Genet`, `Bcm2711Rng200` et `bcm2711_hw_watchdog` sur le silicium BCM2711 physique.

## 5. Modifications de cette reprise
- Correction de `build.sh`: ajout de `-B/usr/bin/aarch64-linux-gnu-` pour assembler/linker correctement le userspace EL0.
- Durcissement CSPRNG dans `kernel/main.rs`: arrêt explicite du boot si aucune source d'entropie matérielle/hyperviseur n'est disponible.
- Durcissement du test TAP: absence de capacité `CAP_NET_ADMIN` rend le test explicite `SKIP`, sans déclarer successivement le réseau bidirectionnel validé.
- Création de l'audit technique courant dans `AUDIT.md`.

## 6. Résultats exacts
- Build QEMU et RPi4: réussi.
- Smoke boot QEMU + shell EL0: réussi.
- Suite réseau HTTPS/persistence/TLS: réussi.
- Suite TAP bidirectionnelle: bloquée localement par absence de création d'interface TAP, limitation de sandbox.
- Validation Raspberry Pi 4 physique: non réalisée.

## 7. Travaux récents
- Ajout de `ai_core/agents.rs`: coordinateur déterministe avec agents système, réseau, sécurité, mémoire, stockage, processus, diagnostic et réparation.
- Ajout des endpoints `/api/v1/ai/agents`, `/history`, `/chat` et `/diagnose`.
- Ajout de `scripts/nexos_ai_gateway.py`: passerelle locale Ollama/OpenAI-compatible avec authentification gateway et approbation à deux facteurs pour les actions de réparation.
- Remplacement du placeholder React par un tableau de bord live utilisant les API NexOS.
- Ajout des artefacts `nexos.img`, `kernel.elf` et `kernel.map` au build Raspberry Pi.
- Mise à jour du manifest frontend `esbuild` pour corriger la résolution Vite.

## 8. Prochaine tâche précise
1. Relancer `python3 scripts/test_stage13_web.py` lorsque l'autorisation du terminal est disponible.
2. Vérifier les nouveaux endpoints agents `/api/v1/ai/{agents,history,chat,diagnose}`.
3. Tester la passerelle avec un Ollama local, une clé API externe uniquement hors dépôt ou un endpoint OpenAI-compatible approuvé.
4. Flasher `build/rpi4/nexos-rpi4-sd.img` sur un Raspberry Pi 4 réel et valider UART, EMMC2, GENET, RNG200 et USB.

## 9. AI memory and repair continuation
- Added `ai_core/memory.rs` persistent `/disk/NEXOS_AI_MEMORY.DB` with 32-entry bounded history and CRC validation.
- Added `/api/v1/ai/memory`.
- Added allowlisted `restart_service` approval flow: CSPRNG token, 5-minute expiry, target verification.
- Added `/api/v1/ai/repair/request` and `/api/v1/ai/repair/approve`.
- Added `/api/v1/ai/memory` and repair assertions to `scripts/test_stage13_web.py`.
- Added `tests/test_ai_gateway.py`, with 3 passing gateway unit tests.
- `scripts/test_stage13_web.py` passed with AI memory and repair assertions.
