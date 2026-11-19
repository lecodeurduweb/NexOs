# NexOS — Protocole de Tests (`TESTING.md`)

## 1. Lancement Manuel Sous QEMU `virt` (`[TESTÉ (QEMU)]`)

```bash
./build.sh all
python3 scripts/mk_test_disk.py build/test_disk.img
./run.sh
```
Paramètres QEMU utilisés :
- `-machine virt,gic-version=2,virtualization=on` (teste **EL2 → EL1**, GICv2 partagé conceptuellement avec GIC-400 Pi 4)
- `-cpu cortex-a72 -smp 4 -m 1024M`
- `-netdev user,id=net0,hostfwd=tcp::18080-:80,hostfwd=tcp::18443-:443 -device virtio-net-device,netdev=net0`
- `-nographic -no-reboot`

## 2. Suite Automatisée de Bout en Bout (`tests/run_all.py`)

```bash
python3 tests/run_all.py
```
Étapes vérifiées :
1. `./build.sh all` & `./build.sh sd` (`qemu_virt`, `rpi4`, `init.bin` et image SD `nexos-rpi4-sd.img` MBR+FAT32).
1b–1d. Vérification ELF `W^X` (`readelf -lW` : `0` segment `RWE` dans `init.elf`, `nexos-qemu.elf` et `nexos-rpi4.elf`) + validation de l'image SD RPi4 (`KERNEL8.IMG`, `CONFIG.TXT`, `CMDLINE.TXT`, `README.TXT`).
2–2b. `scripts/mk_test_disk.py` (`MODEL.NXM`, `STORIES.NXM`, `CORRUPT.NXM`, `BAD.GGF`, `HELLO.TXT`) + test du convertisseur hôte `scripts/convert_to_nxm.py --verify` (JSON, padding Q8_0 `hidden_dim=44`, `llama2.c`, modèle réel `stories260K.bin` + `tok512.bin`).
3. Boot SMP 4 cœurs, CSPRNG (`VirtioRng` + `RNG200` mock), exception `brk #0x42`, DTB, GICv2 + timer 100 Hz, MMU 4K, Heap, **AI Arena**, ordonnanceur + IPC, isolation EL0→EL1 (`mmaptest`, `ipctest`), VFS/FAT32, mocks MMIO (`EMMC2`, `GENET v5`, `GPIO`, `Property Mailbox`), TLS 1.3 self-test, RBAC, Watchdog, IA NEON (`ai status`, `ai arena`, `ai ask`, `ai bench`, `ai unload` -> `arena_used=0 B`, rejet GGUF & CRC-32 `CORRUPT.NXM`, `ai load /disk/STORIES.NXM` + génération cohérente, `ai diag`, `ai chat`, `ai history`).
4. `scripts/test_stage11_net.py` : échange réel VM↔Hôte sur TAP (`10.77.0.1` ↔ `10.77.0.2`), ping bidirectionnel, DNS UDP/53, TCP Echo `:7070`, `RST :9999`, PCAP `29` paquets.
5. `scripts/test_stage13_web.py` : provisioning premier démarrage par jeton CSPRNG (`/api/v1/setup`), **zéro mot de passe codé en dur**, HTML SPA (`GET /`, `16 300 B`), HTTP/1.1 `:80` + HTTPS **TLS 1.3** `:443` (`TLS_CHACHA20_POLY1305_SHA256`), `/api/v1/*`, protection `403` sur `/api/v1/files` pour `NEXUSERS.DB`/`AIMEM.DB`/`..`, inférence `STORIES.NXM`, agent autonome (`/api/v1/ai/{tools,chat,diagnose,repair,rollback,history}`, RBAC, filtre injection), et persistance à froid `/disk/NEXUSERS.DB` + `/disk/AIMEM.DB` après redémarrage QEMU.

## 3. Matériel Réel (Raspberry Pi 4)

QEMU 7.2.22 ne fournit pas la machine `raspi4b`. Les artéfacts Pi 4 (`kernel8.img`, `config.txt`, `nexos-rpi4-sd.img`) sont compilés sans erreur mais marqués **NON TESTÉS SUR MATÉRIEL**. Voir [`docs/HARDWARE_TEST.md`](docs/HARDWARE_TEST.md).
