# NexOS — Feuille de Route (Roadmap)

Les étapes suivent un ordre strict : chaque étape doit être **compilée et testée sous QEMU** (ou marquée bloquée avec justification technique) avant de passer à la suivante.

| Étape | Composant | Critère de Validation |
|---|---|---|
| 0 | Environnement & Outillage | `rustc` (`aarch64-unknown-none`), `ld.lld`/`aarch64-linux-gnu-ld`, `qemu-system-aarch64`, `./build.sh`, `./run.sh`, compilation test OK |
| 1 | Boot ARM64 (`entry.S`, EL2→EL1, pile, BSS) | Message de boot visible sur UART sous QEMU `virt` |
| 2 | Pilote UART (PL011 QEMU ; module Pi 4 séparé) + macros log | Sortie formatée fiable (`kprintln!`, niveaux de log) sous QEMU |
| 3 | Exceptions, table de vecteurs VBAR_EL1, dump registres | Exception provoquée volontairement capturée et affichée proprement |
| 4 | Parseur DTB (mémoire, réservations, périphériques, IRQ) | Carte mémoire et nœuds clés lus dynamiquement depuis le DTB QEMU |
| 5 | Pilote GICv2 (vérifié via DTB) + Timer générique ARM | Tick périodique d'interruption visible et mesuré sous QEMU |
| 6 | Mémoire physique (PARange dynamique, zones) + MMU L0–L3 | MMU active (`SCTLR_EL1.M=1`), allocations/libérations de pages testées |
| 7 | Heap du noyau (`alloc` / allocateur dynamique) | Tests d'allocation/réallocation/libération noyau sous QEMU |
| 8 | Threads noyau + ordonnanceur préemptif à priorités | Plusieurs threads en alternance préemptive sur interruption timer |
| 9 | Syscalls, EL0, isolation, premier binaire userspace + shell UART | Shell interactif minimal exécuté en EL0 communiquant via syscalls |
| 10 | VFS + Stockage (`ramdisk` → `virtio-blk` → MBR/GPT → FAT32 → SD Pi 4) | Lecture/écriture vérifiées avec contrôle d'erreurs à chaque couche |
| 11 | Réseau (`virtio-net` QEMU, GENET Pi 4) : Eth/ARP/IPv4/ICMP/UDP/DHCP/TCP/DNS | Échange réel de paquets VM↔Hôte (ping bidirectionnel, TCP, capture) |
| 12 | Gestionnaire de services, journalisation, auth/permissions, watchdog | Cycle de vie de services, comptes, permissions vérifiés |
| 13 | Administration Web minimale (HTTP authentifié) | Métriques réelles (CPU, RAM, processus, services, logs) servies via HTTP |
| 14 | NexOS AI Core (conception ou démon hors ligne borné) | API système documentée, contraintes mémoire/thermiques respectées |
