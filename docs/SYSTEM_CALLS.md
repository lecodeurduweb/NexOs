# NexOS — Interface Appels Système EL0 (`docs/SYSTEM_CALLS.md`)

Les tâches userspace s'exécutent en **EL0** dans leur propre espace d'adressage `TTBR0_EL1` (`0x0000_0100_0000_0000 .. 0x0000_0200_0000_0000`) et appellent le noyau via `SVC #0` (`x8` = numéro d'appel, `x0..x4` = arguments, valeur de retour dans `x0`).

Tout pointeur utilisateur est vérifié par instruction matérielle `AT S1E0R` / `AT S1E0W` avant lecture/écriture noyau ; les pointeurs invalides ou hors plage renvoient `-14` (`EFAULT`).

## Table Complète des Appels Système (`0..29`)

| Numéro | Nom | Arguments (`a0..a4`) | Retour / Effet |
|---|---|---|---|
| `0` | `SYS_WRITE` | `fd`, `buf`, `len (<=4096)` | Écrit vers l'UART PL011 (`\n` → `\r\n`), retourne octets écrits |
| `1` | `SYS_READ` | `fd`, `buf`, `len (<=256)` | Lit les octets disponibles sur l'UART (non bloquant) |
| `2` | `SYS_EXIT` | `exit_code` | Termine la tâche EL0 courante et déclenche l'ordonnanceur |
| `3` | `SYS_YIELD` | — | Cède le quantum CPU immédiatement |
| `4` | `SYS_GETPID` | — | Retourne l'ID de la tâche courante |
| `5` | `SYS_UPTIME_MS` | — | Retourne l'uptime système en millisecondes (`CNTPCT_EL0`) |
| `6` | `SYS_SYSINFO` | `out_buf`, `out_len` | Formate carte, PA, RAM, Heap et liste des tâches |
| `7` | `SYS_SLEEP_MS` | `ms` | Endort la tâche courante (`WaitQueue` timer) |
| `8` | `SYS_VFS_LIST` | `path`, `plen`, `out_buf`, `out_len` | Liste un répertoire VFS (`/`, `/ram`, `/disk`) |
| `9` | `SYS_VFS_READ` | `path`, `plen`, `out_buf`, `out_len` | Lit un fichier VFS (rejet `..` → `-5` `EIO`) |
| `10` | `SYS_VFS_WRITE` | `path`, `plen`, `data`, `dlen` | Écrit un fichier VFS (`/ram` ou `/disk` FAT32) |
| `11` | `SYS_NET_INFO` | `out_buf`, `out_len` | Retourne l'état interface, IPv4/IPv6, table ARP |
| `12` | `SYS_NET_PING` | `ip_str`, `ilen`, `out_buf`, `out_len` | Envoie 3 paquets ICMP Echo et mesure les RTT (`us`) |
| `13` | `SYS_NET_DNS` | `host`, `hlen`, `out_buf`, `out_len` | Résout un enregistrement DNS A (`UDP/53`) |
| `14` | `SYS_NET_STAT` | `out_buf`, `out_len` | Liste les sockets TCP actifs et en écoute |
| `15` | `SYS_SVC_LIST` | `out_buf`, `out_len` | Liste les services supervisés et leur état watchdog |
| `16` | `SYS_SVC_CTRL` | `name`, `nlen`, `op (0=stop,1=restart,2=start)` | Contrôle un service supervisé |
| `17` | `SYS_DMESG` | `out_buf`, `out_len` | Lit les 16 dernières lignes du tampon circulaire noyau |
| `18` | `SYS_MMAP` | `va_hint`, `len`, `prot (bit1=W, bit2=X)` | Alloue des pages EL0 ; rejette `W+X` (`-22` `EINVAL`) |
| `19` | `SYS_MUNMAP` | `va`, `len` | Démappe et libère les cadres physiques |
| `20` | `SYS_THREAD_SPAWN` | `entry_va`, `arg0`, `stack_bytes` | Crée un thread EL0 partageant `TTBR0_EL1` |
| `21` | `SYS_THREAD_JOIN` | `tid`, `timeout_ms` | Attend la fin du thread et libère ses ressources |
| `22` | `SYS_IPC_SEND` | `chan_id (0=open)`, `ptr`, `len` | Ouvre/crée un canal ou envoie un message IPC borné |
| `23` | `SYS_IPC_RECV` | `chan_id`, `buf`, `cap`, `blocking (0|1)` | Reçoit un message IPC (`-11` `EAGAIN` si vide) |
| `24` | `SYS_VFS_MKDIR` | `path`, `plen` | Crée un répertoire sur `/ram` ou `/disk` |
| `25` | `SYS_VFS_REMOVE` | `path`, `plen` | Supprime un fichier ou répertoire vide |
| `26` | `SYS_VFS_SYNC` | — | Force le vidage (`flush`) des secteurs sales du `BlockCache` |
| `27` | `SYS_DEV_LIST` | `out_buf`, `out_len` | Liste DTB, GICv2, VirtIO, BCM2711, NIC et VFS |
| `28` | `SYS_POWER` | `op (0=off, 1=reset)` | Éteint ou redémarre le système via PSCI |
| `29` | `SYS_AI_CMD` | `op (0..4)`, `arg`, `alen`, `out`, `out_cap` | Pilote `ai_core` (`0=status, 1=load, 2=ask, 3=bench, 4=unload`) |
