# NexOS - Audit Technique Integral

Date: 2026-11-19
Environnement audité: Linux x86_64, rustc 1.100.0, Cargo 1.100.0, rustup stable, QEMU AArch64 7.2.22, binutils/GCC AArch64 15.2.

## Etat de reference

La compilation de référence échoue initialement dans `build.sh` lorsque GCC croisé assemble `crt0.S`: GCC appelait l'assembleur `/usr/bin/as` hôte avec `-EL`. Le script a été corrigé avec `-B/usr/bin/aarch64-linux-gnu-`, ce qui force les outils `aarch64-linux-gnu-as/ld`.

La construction complète passe ensuite:

- `./build.sh all`: compile les binaires EL0, QEMU virt et Raspberry Pi 4.
- `./build.sh sd`: produit une image MBR + FAT32 de 32 MiB.
- Smoke boot QEMU: EL2 -> EL1, 4 cœurs, DTB, GIC, timer, MMU, heap, IPC, stockage, réseau, RBAC, AI Core et shell EL0.
- `scripts/test_stage13_web.py`: passe sur HTTP/1.1, HTTPS, setup premier boot, login, RBAC et persistance.
- `scripts/convert_to_nxm.py --verify`: passe pour les formats JSON et llama2.c.
- Test de réseau TAP: non exécutable dans l'environnement courant, car la création `ip tuntap` est interdite par les capacités réseau/sandbox. Le test termine maintenant explicitement en `SKIP`, sans masquer une panne.

## Legende

NON COMMENCE, EN DEVELOPPEMENT, IMPLEMENTE, COMPILE, TESTE (QEMU), VALIDE (materiel).

## Audit par fonctionnalite

| Domaine | Etat | Preuves / limites |
|---|---|---|
| Chaîne Rust AArch64 | COMPILE | cible `aarch64-unknown-none` installée, build release QEMU/RPi4 et userspace. |
| LLD / objcopy / GCC croisé | COMPILE | `ld.lld`, `aarch64-linux-gnu-gcc/as/objcopy/readelf` disponibles. Correctif userspace ajouté. |
| QEMU AArch64 | TESTE (QEMU) | boot virt, GICv2, Cortex-A72, SMP4, VirtIO-RNG/Blk/Net. |
| Image Raspberry Pi 4 | COMPILE | `kernel8.img`, ELF, `config.txt`, image SD MBR+FAT32 générés. |
| Boot ARM64 / EL2-EL1 | TESTE (QEMU) | `_start`, BSS, piles, FP/SIMD, EL2→EL1 vérifiés sous QEMU. |
| Raspberry Pi 4 boot firmware | NON VALIDE | firmware propriétaire requis hors dépôt; aucun matériel disponible dans cette session. |
| Exceptions / vecteurs | TESTE (QEMU) | sauvegarde registre/NEON, BRK #0x42, reprise ERET et faute EL0 testées. |
| DTB | TESTE (QEMU) | RAM, réservations, GIC, UART, timer, CPUs et VirtIO lus depuis DTB. |
| GICv2 / timer | TESTE (QEMU) | GICv2 + ticks 100 Hz vérifiés. Pi4 GIC-400 non validé physiquement. |
| MMU / W^X | TESTE (QEMU) | tables L0-L3, 44-bit PA, RX/RO/RW/NX, tests AT EL0/EL1. |
| Allocateur physique / heap | TESTE (QEMU) | bitmap 1 GiB, heap 64 MiB, croissant et coalescent. |
| SMP / ordonnanceur | TESTE (QEMU) | quatre cœurs, préemption, priorités, IPC, mutex/semaphore et réclamation. |
| Syscalls / EL0 | TESTE (QEMU) | 31 syscalls, pointeurs AT, W^X, shell interactif et faute EL0 contenue. |
| Threads / IPC | TESTE (QEMU) | spawn/join, self-test IPC, IPC inter-tâches. |
| VFS / RAMFS / FAT32 | TESTE (QEMU) | MBR/GPT, VirtIO-Blk, cache, FAT32 R/W/mkdir/rm/sync. |
| EMMC2 Pi4 | EN DEVELOPPEMENT | implémentation MMIO réelle présente; autodiagnostic seulement en machine d'état `mock MMIO`, aucune carte/siège matériel. |
| UART / GPIO Pi4 | IMPLEMENTE / NON VALIDE | Mini-UART/PL011 et GPIO 14/15 implémentés, non exécutés sur Pi4 réel. |
| Virtio UART/Bloc/Net/RNG | TESTE (QEMU) | périphériques VirtIO effectivement exercés sous QEMU. |
| GENET BCM2711 | EN DEVELOPPEMENT | pilote MMIO/ring réel dans le code; self-test simulé/mock, aucune validation PHY. |
| Ethernet/ARP/IPv4 | IMPLEMENTE | implémentations présentes; DHCP/paquets vérifiés avec virtio-net sous QEMU. |
| ICMP/DNS/DHCP/UDP/TCP | TESTE (QEMU) | proxy QEMU/hostforward testés, TAP bidirectionnel bloqué par l'environnement. |
| IPv6/ICMPv6 | IMPLEMENTE | lien-local et self-test présents; matériel réel non validé. |
| TLS 1.3 | TESTE (QEMU) | X25519, ChaCha20-Poly1305, Ed25519, handshake host Python/OpenSSL observée. |
| Sécurité/CSPRNG | TESTE (QEMU) | VirtIO-RNG utilisé, auto-test, health checks; démarrage rendu `panic` si aucune entropie matérielle. BCM2711 RNG200 seul mock. |
| RBAC / utilisateurs | TESTE (QEMU) | 4 rôles, PBKDF2, salage, setup éphémère, verrouillage, audit et persistance. |
| Services / watchdog | TESTE (QEMU) | registre, reprise de service, journal, watchdog actifs. |
| Administration web | TESTE (QEMU) | SPA embarquée, HTTP 80, HTTPS 443, API v1 et TLS 1.3. |
| Stockage longue durée | TESTE (QEMU) | FAT32 persistant dans image disque; reset à froid testé. |
| AI Core / .nxm | TESTE (QEMU) | modèle synthétique, CRC-32, rejet GGUF, kernels NEON vs scalaire. Ce n'est pas un moteur de service LLM professionnel. |
| Interface React externe | NON INTEGREE | `src/App.tsx` est un placeholder hors runtime noyau; l'interface NexOS réelle est embarquée dans `web-admin/mod.rs`. |
| Validation matérielle | NON COMMENCE | aucun Pi4/RPi4 8 Go connecté ni preuve UART/PHY/EMMC/GENET disponible. |
| Coordinateur IA / agents | IMPLEMENTE | routage déterministe, observations live, historique et API; compilation QEMU réussie. |
| Passerelle IA externe | IMPLEMENTEE HORS NOYAU | gateway Ollama/OpenAI-compatible, Bearer gateway, contexte NexOS et approbations pour réparation; fournisseur externe non testé dans cette session. |
| Interface React | COMPILEE | build Vite/type-check réussis; tableau de bord est séparé du noyau et doit être servi publiquement ou embarqué ultérieurement. |

## Anomalies corrigées

1. Build userspace: outil croisé forcé pour éviter l'assembleur hôte.
2. CSPRNG: le boot refuse maintenant de continuer si aucune entropie réelle n'est disponible.
3. Test réseau TAP: distingue l'absence de capacité réseau d'une erreur de protocole.

## Risques fonctionnels restants

- Le binaire Pi4 est compilé, mais non démarré physiquement.
- `Bcm2711Emmc2`, `Bcm2711Genet`, `Bcm2711Rng200` et watchdog n'ont pas de preuve physique.
- Le test TAP dépend de `CAP_NET_ADMIN`/création d'interface.
- Le TLS utilise des implémentations internes minimales plutôt que une bibliothèque externe largement auditee; elles sont testées mais la mission sécurité exige une validation cryptographique indépendante avant production.
- Les pilotes USB ne sont pas une couche complète vérifiable.
- L'intégrité du boot Pi4 dépend du firmware VideoCore fourni séparément sur la carte SD.

