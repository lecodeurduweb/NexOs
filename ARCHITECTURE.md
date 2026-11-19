# NexOS — Architecture Système

NexOS est un système d'exploitation **serveur headless indépendant** (non basé sur Linux) pour architecture **ARM64 / AArch64**, ciblant :
1. **QEMU `virt`** (`gic-version=2`, `cortex-a72`) pour le développement, la validation automatisée et les tests réseau/stockage.
2. **Raspberry Pi 4 Model B — 8 Go RAM (BCM2711, Cortex-A72)** comme cible matérielle serveur de référence.

## Principes Architecturaux

1. **Séparation stricte Générique / Architecture / Carte**
   - `boot/` : Point d'entrée AArch64 (`entry.S`), passage EL2 → EL1, initialisation pile/BSS, préservation du pointeur DTB (`x0`).
   - `arch/arm64/` : Abstractions CPU AArch64 (registres système, exceptions/vecteurs, MMU 4K, cache/TLB, détection `ID_AA64MMFR0_EL1.PARange`, timer générique ARM).
   - `arch/arm64/boards/qemu_virt/` : Configuration spécifique QEMU `virt` (linker script `0x40080000`, adresse d'amorçage UART PL011 pré-DTB documentée).
   - `arch/arm64/boards/rpi4/` : Configuration spécifique Raspberry Pi 4 (linker script `0x80000`, `config.txt`, `kernel8.img`, contrôleur ARM Local BCM2711, spécificités Mini-UART/PL011, limitations DMA BCM2711).
   - `kernel/` : Cœur générique indépendant de la carte (`main.rs`, `log.rs` avec tampon circulaire, `services.rs` + watchdog, `syscall.rs`).
   - `drivers/` : Pilotes périphériques découplés par traits et découverts via DTB (`uart/`, `gicv2.rs`, `block/` [`ramdisk`, `sd_emmc2` Pi 4], `net/` [`genet` Pi 4], `virtio/` [`blk`, `net`]).
   - `filesystem/` : VFS (`/ram`, `/disk`), parseur de partitions MBR/GPT, système de fichiers FAT32 lecture/écriture.
   - `network/` : Pile réseau indépendante (`eth`, `arp`, `ipv4`, `icmp`, `udp`, `dhcp`, `dns`, `tcp`, `ipv6`, `tls` TLS 1.3).
   - `security/` : `PBKDF2-HMAC-SHA256` (4096 it.), RBAC (`Admin`/`Operator`/`Viewer`/`AiAgent`), sessions Bearer, lockout backoff et audit.
   - `web-admin/` : Serveur HTTP/1.1 (`:80`) et HTTPS TLS 1.3 (`:443`) exposant l'API `/api/v1/*`.
   - `ai_core/` + `arch/arm64/neon_gemv.S` : Moteur d'inférence natif ARM64 NEON SIMD `.nxm` v1 Q8_0 (zéro dépendance Linux/Python/llama.cpp).
   - `memory/` : Gestionnaire mémoire physique (respectant la largeur PA détectée et les zones réservées DTB + DMA), MMU (tables de pages L0–L3), allocateur de tas noyau (`heap`).
   - `scheduler/` : Ordonnanceur préemptif SMP 4 cœurs à priorités, changement de contexte AArch64 (`x0..x30` + `Q0..Q31`), threads noyau et processus EL0.

2. **Découverte Matérielle par Device Tree (DTB)**
   - Aucune adresse de périphérique spécifique à une carte n'est codée en dur après l'amorçage initial.
   - L'adresse du DTB transmise dans `x0` par QEMU ou le firmware VideoCore est analysée dès l'étape 4 pour extraire :
     - Les régions RAM (`memory` / `reg`), y compris au-delà de 4 Go sur Pi 4 8 Go.
     - Les régions réservées (`memreserve` et `/reserved-memory`, ex. GPU/firmware VideoCore).
     - Les périphériques (`compatible`, `reg`, `interrupts`), incluant la vérification du contrôleur d'interruptions GICv2 (`arm,gic-400` ou `arm,cortex-a15-gic`).

3. **Adresses Physiques et 8 Go RAM**
   - Lecture dynamique de `ID_AA64MMFR0_EL1.PARange` au démarrage (le Cortex-A72 supporte 44 bits, soit 16 Tio d'espace physique adressable).
   - Le Pi 4 8 Go expose de la RAM physique au-dessus de 4 Gio et impose des contraintes DMA (fenêtre 30 bits / 32 bits sur certains contrôleurs BCM2711). La couche `memory/` sépare les zones DMA des zones haute mémoire.

4. **Deux Chemins de Démarrage Distincts**
   - **QEMU `virt`** : Chargement direct de l'ELF noyau (`nexos-qemu.elf`) à `0x40080000` (DTB placé par QEMU à `0x40000000` et passé dans `x0`).
   - **Raspberry Pi 4** : Firmware VideoCore (`start4.elf`) → `config.txt` (`arm_64bit=1`) → `kernel8.img` binaire brut chargé à `0x80000` + DTB fourni par le firmware dans `x0`.

5. **Conception Headless & Budget Serveur**
   - Aucune interface graphique, aucun pilote vidéo/audio/HID.
   - Console unique : UART (PL011 QEMU / UART Pi 4), puis administration distante par Ethernet (HTTP authentifié).
   - Isolation stricte des services et API versionnée à permissions limitées pour `ai-core/` (qui reste hors noyau, sans accès matériel direct).
