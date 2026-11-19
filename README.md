# NexOS — OS Serveur ARM64 Headless

**NexOS** est un système d'exploitation serveur indépendant (**bare-metal**, écrit en **Rust `no_std`**, **assembleur AArch64** et userspace **C freestanding EL0**), sans noyau Linux ni runtime tiers :
- **Environnement de validation** : **QEMU `virt`** (`gic-version=2`, CPU `cortex-a72`, SMP 4 cœurs, VirtIO-Blk/Net).
- **Cible matérielle** : **Raspberry Pi 4 Model B — 8 Go RAM** (`BCM2711`, Quad-core Cortex-A72) — artéfacts `kernel8.img` compilés, **NON TESTÉS SUR MATÉRIEL RÉEL**.

## Capacités Réellement Vérifiées (QEMU `virt`)
- **Noyau SMP 4 cœurs AArch64** : transition EL2/EL3 → EL1, réveil des cœurs 1..3 par PSCI, tables de vecteurs `VBAR_EL1` (sauvegarde complète `x0..x30` + NEON `Q0..Q31`), GICv2 + Timer ARM `100 Hz`, MMU 4K `W^X` (`44-bit PA`), allocateur physique + tas `64 Mio`.
- **Ordonnanceur & IPC** : ordonnanceur préemptif multi-cœurs, `WaitQueue`/`Mutex`/`Semaphore`, canaux IPC inter-tâches, `reap_exited()`.
- **Userspace EL0 isolé (`init.bin`, 31 syscalls `0..30`)** : shell UART interactif (`setup`, `users`, `ai`, ...), validation stricte `AT S1E0R/W`, `SYS_MMAP` (`W^X` rejeté), threads EL0, IPC, VFS, réseau et `SYS_SECURITY = 30`.
- **Stockage & Réseau complets** : `BlockCache` LRU write-back, `VirtIO-BLK`, partitionnement MBR/GPT, FAT32 lecture/écriture (`/disk`), `/ram` ; Ethernet/ARP/IPv4/DHCP/ICMP/UDP/DNS/TCP + IPv6 link-local/ICMPv6 + **TLS 1.3** (`X25519` + `ChaCha20-Poly1305` + `Ed25519` avec CSPRNG `VirtioRng` / `RNG200`).
- **Sécurité & Administration Distante (`/`, `/api/v1/*`)** : **zéro mot de passe codé en dur**, provisioning initial UART (`setup`) ou HTTPS (`POST /api/v1/setup` par jeton éphémère CSPRNG), base chiffrée/salée persistante `/disk/NEXUSERS.DB`, `PBKDF2-HMAC-SHA256` (4096 itérations), 4 rôles RBAC, verrouillage `429`, journal d'audit, dashboard SPA HTML (`GET /`) HTTP `:80` & HTTPS TLS 1.3 `:443`.
- **NexOS AI Core natif (`ai_core/` + `neon_gemv.S`)** : moteur Transformer causal Q8_0 en espace noyau `no_std` avec noyaux vectoriels NEON (`fmla`/`sxtl`), format `.nxm` v1 à contrôle d'intégrité CRC-32 (`convert_to_nxm.py`), cache KV, contrôle budget RAM, rejet diagnostique GGUF, exposé via EL0 (`ai`) et `/api/v1/ai/*`.

## Documentation
- [Rapport final (`FINAL_REPORT.md`)](FINAL_REPORT.md)
- [État exact du projet (`STATUS.md`)](STATUS.md)
- [Architecture système (`docs/ARCHITECTURE.md`)](docs/ARCHITECTURE.md)
- [Guide de compilation (`docs/BUILD.md`)](docs/BUILD.md)
- [Installation & déploiement (`docs/INSTALLATION.md`)](docs/INSTALLATION.md)
- [Protocole matériel Pi 4 réel (`docs/HARDWARE_TEST.md`)](docs/HARDWARE_TEST.md)
- [Appels système EL0 `SVC #0` (`docs/SYSTEM_CALLS.md`)](docs/SYSTEM_CALLS.md)
- [Pile réseau & TLS 1.3 (`docs/NETWORK.md`)](docs/NETWORK.md)
- [Sécurité, RBAC & chiffrement (`docs/SECURITY.md`)](docs/SECURITY.md)
- [Conception NexOS AI Core (`docs/AI_CORE_DESIGN.md`)](docs/AI_CORE_DESIGN.md)
- [Utilisation & format `.nxm` (`docs/AI_CORE_USAGE.md`)](docs/AI_CORE_USAGE.md)
- [Budgets mémoire & mesures (`docs/BUDGETS.md`)](docs/BUDGETS.md)

## Démarrage Rapide & Tests Automatisés (QEMU)
```bash
./build.sh all
./build.sh sd
python3 scripts/mk_test_disk.py build/test_disk.img
./run.sh
# Suite complète (build, ELF W^X, image SD Pi 4, convertisseur .nxm, boot SMP, réseau TAP/PCAP, setup + TLS 1.3 + AI Core + persistance) :
python3 tests/run_all.py
```
