# NexOS — Rapport Technique Final (`FINAL_REPORT.md`)

> **Règle d'honnêteté absolue** : Chaque composant ci-dessous est strictement qualifié selon la preuve observée après la dernière modification :
> - `TESTÉ (QEMU)` : exécuté sous `qemu-system-aarch64 7.2.22` (`-machine virt,gic-version=2,virtualization=on -cpu cortex-a72 -smp 4 -m 1024M`) avec code de retour `0`.
> - `TESTÉ PAR MOCK MMIO` : logique pilote BCM2711 éprouvée sur registres MMIO simulés en RAM sous QEMU (aucun accès au silicium physique).
> - `COMPILÉ / NON TESTÉ SUR MATÉRIEL` : compilé sans avertissement pour `board-rpi4` (`BCM2711`), non exécuté sur un Raspberry Pi 4 physique (QEMU 7.2.22 ne fournit pas `raspi4b`).
> - `NON IMPLÉMENTÉ` : périphérique volontairement absent ou hors périmètre serveur headless.

---

## 1. Matrice Complète de Vérification

| Domaine / Étape | Statut QEMU `virt` | Statut Raspberry Pi 4 (`BCM2711`) | Preuve & Mesures Observées |
|---|---|---|---|
| **Build & Tooling (`./build.sh all`, `./build.sh sd`)** | `TESTÉ (QEMU)` | `COMPILÉ / NON TESTÉ SUR MATÉRIEL` | `0` warning ; `init.bin` (`12 288 B`), `nexos-qemu.bin` (`524 608 B`), `kernel8.img` (`532 800 B`), `nexos-rpi4-sd.img` (`32 MiB`) |
| **Permissions ELF `W^X` (`readelf -lW`)** | `TESTÉ (QEMU)` | `COMPILÉ / NON TESTÉ SUR MATÉRIEL` | `0` segment `RWE` vérifié dans `init.elf`, `nexos-qemu.elf` et `nexos-rpi4.elf` |
| **Boot ARM64 EL2→EL1 & SMP 4 cœurs** | `TESTÉ (QEMU)` | `COMPILÉ / NON TESTÉ SUR MATÉRIEL` | `MIDR_EL1=0x410fd083` (Cortex-A72), `4/4` cœurs en ligne (`online_mask=0b1111`), PSCI `CPU_ON` |
| **UART (`PL011` / `mini_uart`) & Exceptions `VBAR_EL1`** | `TESTÉ (QEMU)` | `COMPILÉ / NON TESTÉ SUR MATÉRIEL` | `BRK #0x42` + `ERET`, `TrapFrame` 816 B (`x0..x30` + `Q0..Q31` NEON) |
| **DTB + GICv2 + ARM Generic Timer (`100 Hz`)** | `TESTÉ (QEMU)` | `COMPILÉ / NON TESTÉ SUR MATÉRIEL` | RAM `1024 MiB`, `4` CPUs, `32` slots VirtIO, GICv2 `INTID=30`, `CNTFRQ_EL0=62.5 MHz` |
| **MMU 4K `W^X` (`44-bit PA`) & Heap Noyau** | `TESTÉ (QEMU)` | `COMPILÉ / NON TESTÉ SUR MATÉRIEL` | `IPS=4`, garde page `0x0`, `heap` `445 KiB used / 3 276 KiB mapped`, plafond `64 MiB` |
| **AI Memory Arena (`memory/ai_arena.rs`)** | `TESTÉ (QEMU)` | `COMPILÉ / NON TESTÉ SUR MATÉRIEL` | Aperture `+16 GiB` (`VA=0x300000000000`), budget `890 MiB` (QEMU 1G) / `7.5 GiB` max (Pi 4 8G), réserve OS `128 MiB`, `arena_used=0 B` au déchargement |
| **Ordonnanceur SMP + IPC + Stacks 64 KiB** | `TESTÉ (QEMU)` | `COMPILÉ / NON TESTÉ SUR MATÉRIEL` | `mutex_sum=100`, `IPC channel self-test OK`, `reap_exited()` (3 tâches libérées) |
| **Userspace EL0 (`init.bin`, syscalls `0..30`)** | `TESTÉ (QEMU)` | `COMPILÉ / NON TESTÉ SUR MATÉRIEL` | `EC=0x24` contenu, `AT S1E0R/W`, `SYS_MMAP` W+X rejeté, `SYS_AI_CMD` ops `0..10`, `SYS_SECURITY=30` |
| **VFS & Stockage (`BlockCache`, GPT, FAT32, streaming)** | `TESTÉ (QEMU)` | `TESTÉ PAR MOCK MMIO` (`EMMC2`) | Disque `16 MiB` VirtIO-BLK R/W/mkdir/rm/sync ; lecture streamée par curseur (`VfsCursor`/`FatFileCursor`) ; `EMMC2` mock MMIO OK |
| **BCM2711 GPIO & Property Mailbox** | — | `TESTÉ PAR MOCK MMIO` | `drivers/{gpio_bcm2711,mailbox_bcm2711}.rs` éprouvés par self-test registres MMIO simulés sous QEMU (`NON TESTÉ SUR MATÉRIEL`) |
| **Réseau & TLS 1.3 (`VirtioNet`, `GENET v5`)** | `TESTÉ (QEMU)` | `TESTÉ PAR MOCK MMIO` (`GENET`) | TAP `10.77.0.2`: ping `1.7–3.6 ms`, DNS `:53`, TCP `:7070`, `RST :9999`, PCAP `29` pkts ; `TLS_CHACHA20_POLY1305_SHA256` + Ed25519 |
| **CSPRNG & Durcissement Sécurité** | `TESTÉ (QEMU)` | `TESTÉ PAR MOCK MMIO` (`RNG200`) | `virtio-rng` ; **0 mot de passe codé en dur** ; `/disk/NEXUSERS.DB` persistant ; `/api/v1/files` bloque `NEXUSERS.DB`/`AIMEM.DB`/`..` (`403`) |
| **Web Admin HTTP `:80` / HTTPS TLS 1.3 `:443` + SPA** | `TESTÉ (QEMU)` | `COMPILÉ / NON TESTÉ SUR MATÉRIEL` | SPA `16 300 B` (`GET /`), `/api/v1/setup` (`201`→`409`), `/api/v1/{system,tasks,storage,files,network,users,audit,services,ai,ai/*}` |
| **NexOS AI Core + Modèle Réel Préentraîné (`stories260K`)** | `TESTÉ (QEMU)` | `COMPILÉ / NON TESTÉ SUR MATÉRIEL` | NEON `dot_f32` & `gemv_q8_0` ; `MODEL.NXM` (`228 KiB` Arena, `336–491 tok/s`) ; **`STORIES.NXM` (`stories260K`, `1 008 KiB` Arena, `159–167 tok/s`)** ; rejet GGUF & `CORRUPT.NXM` |
| **Assistant IA Autonome (`ai_core/agent.rs`)** | `TESTÉ (QEMU)` | `COMPILÉ / NON TESTÉ SUR MATÉRIEL` | `14` outils, mémoire `/disk/AIMEM.DB` persistée à froid (`6` tours, `1` réparation), diagnostic, réparation RBAC vérifiée + rollback, filtre anti-exfiltration |
| **Périphériques Pi 4 hors périmètre (USB xHCI VL805, VideoCore VI HDMI/3D)** | — | `NON IMPLÉMENTÉ` | Non implémenté : NexOS est un OS serveur headless piloté via UART et Ethernet |
| **Exécution sur Silicium BCM2711 Physique** | — | **`NON TESTÉ SUR MATÉRIEL`** | Pas de carte Raspberry Pi 4 physique ni d'émulateur `raspi4b` dans QEMU 7.2.22 |

---

## 2. Architecture Mémoire IA (`memory/ai_arena.rs`)

1. **Élimination du plafond 64 Mio du tas noyau** :
   - Les poids de modèles et les caches KV ne sont plus alloués sur le tas noyau (`64 MiB`).
   - `AiArena` réserve l'aperture virtuelle `AI_ARENA_VA_BASE = 0x0000_3000_0000_0000` (`+16 GiB`, `L0[96]` partagé avant création des tables EL0) et mappe à la demande des pages `4 KiB` directement depuis `memory::phys`.
2. **Protection du noyau & des services** :
   - Réserve OS stricte (`MIN_SYSTEM_RESERVE_BYTES = 128 MiB`) protégée contre toute allocation IA (`AI Arena OOM: protected OS memory reserve`).
   - Plafond dynamique jusqu'à `7.5 GiB` (`DEFAULT_AI_CEILING_BYTES`) sur Raspberry Pi 4 8 Go (`890 MiB` effectifs sous QEMU `1024 MiB`).
   - Libération intégrale des cadres physiques et pages virtuelles lors du déchargement (`ai unload` / `POST /api/v1/ai/unload` → `arena_used=0 B`).
3. **Chargement progressif par curseur VFS** :
   - `VfsCursor` / `FatFileCursor` diffusent les fichiers `.nxm` par morceaux de `64 KiB` directement dans `AiBuffer`, sans copier le fichier entier sur le tas noyau.

---

## 3. NexOS AI Core, Modèle Réel & Assistant Autonome

- **Validation avec modèle réel préentraîné (`stories260K`)** :
  - `scripts/convert_to_nxm.py` convertit le checkpoint `llama2.c` `stories260K.bin` + tokenizer `tok512.bin` (`vocab=512`, `dim=64`, `hidden=172`, `5` couches, `8` têtes Q, `4` têtes KV GQA, `max_seq=512`, padding Q8_0 générique pour dimensions non multiples de 32) en `STORIES.NXM` (`307 023 B`, CRC-32 vérifié).
  - Sous QEMU `virt`, `STORIES.NXM` consomme `1 008 KiB` dans `AiArena` (`640 KiB` KV cache) et génère du texte cohérent à `159–167 tok/s`.
- **Assistant IA Autonome (`ai_core/agent.rs`, `/disk/AIMEM.DB`)** :
  - `14` outils autorisés, journal conversationnel et historique des réparations persistés sur `/disk/AIMEM.DB` (vérifiés à travers redémarrage à froid).
  - Diagnostic santé (`ai diag`, `POST /api/v1/ai/diagnose`), réparation contrôlée par RBAC (`admin`/`operator` uniquement, refus `403` pour `viewer`/`ai-agent`), vérification post-réparation, et annulation (`ai rollback`, `POST /api/v1/ai/rollback`).
  - Filtre de sécurité `security_filter` bloquant les tentatives d'exfiltration/injection visant `NEXUSERS.DB` ou `AIMEM.DB` (y compris via `/api/v1/files`, renvoyant `403`).

---

## 4. Instructions de Déploiement sur Raspberry Pi 4 (Matériel Réel)

1. Construire l'image SD bootable MBR + FAT32 (`NON TESTÉ SUR MATÉRIEL`) :
   ```bash
   ./build.sh all
   ./build.sh sd
   # Produit : build/rpi4/nexos-rpi4-sd.img (32 MiB)
   ```
2. Flasher `build/rpi4/nexos-rpi4-sd.img` sur microSD (ou copier `build/rpi4/kernel8.img` + `build/rpi4/config.txt` sur partition FAT32 LBA `0x0c`).
3. Ajouter les firmwares officiels Raspberry Pi (`raspberrypi/firmware/boot/`) : `start4.elf`, `fixup4.dat`, `bcm2711-rpi-4-b.dtb`, `overlays/disable-bt.dtbo`.
4. Suivre la procédure USB-UART 3,3 V (`115200 8N1` GPIO 14/15) dans [`docs/HARDWARE_TEST.md`](docs/HARDWARE_TEST.md).

