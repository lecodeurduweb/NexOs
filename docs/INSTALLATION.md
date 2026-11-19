# NexOS — Installation & Déploiement (`docs/INSTALLATION.md`)

## 1. Déploiement Sous QEMU `virt` (`[TESTÉ (QEMU)]`)

```bash
./build.sh qemu
python3 scripts/mk_test_disk.py build/test_disk.img
./run.sh
```
Paramètres par défaut de `./run.sh` :
- Machine : `virt,gic-version=2,virtualization=on` (teste EL2 → EL1)
- CPU : `cortex-a72`, `-smp 4`, `-m 1024M`
- Réseau SLIRP : redirections `127.0.0.1:18080 -> 10.0.2.15:80` (HTTP) et `127.0.0.1:18443 -> 10.0.2.15:443` (HTTPS TLS 1.3)
- Stockage : `-drive file=build/test_disk.img,if=none,format=raw,id=hd0 -device virtio-blk-device,drive=hd0`

### Accès Admin Après Boot (~0.8–1.5 s)
- Console série UART : prompt `nexos#` (shell EL0).
- Web Admin TLS 1.3 : `curl -k https://127.0.0.1:18443/api/v1/system -u admin:nexos-admin-2026`
- *(Modifier les comptes par défaut via `POST /api/v1/users` / rotation avant toute exposition réseau.)*

## 2. Préparation Carte SD pour Raspberry Pi 4 (`[COMPILÉ / NON TESTÉ SUR MATÉRIEL]`)

> **Avertissement** : `kernel8.img` et `config.txt` n'ont **pas encore été démarrés sur un Raspberry Pi 4 physique**. Suivez impérativement [`HARDWARE_TEST.md`](HARDWARE_TEST.md) avec un adaptateur USB-UART 3.3 V lors du premier essai.

1. Formater la première partition de la carte microSD (table MBR, type `0x0c`) en FAT32.
2. Copier les fichiers officiels du firmware Raspberry Pi 4 (`start4.elf`, `fixup4.dat`, `bcm2711-rpi-4-b.dtb`, `overlays/disable-bt.dtbo`).
3. Compiler et copier NexOS :
   ```bash
   ./build.sh rpi4
   cp build/rpi4/kernel8.img /mnt/sd/kernel8.img
   cp build/rpi4/config.txt  /mnt/sd/config.txt
   ```
4. Optionnel : copier un modèle `.nxm` v1 à la racine FAT32 sous le nom `MODEL.NXM` (chargement automatique au démarrage lorsque `/disk` est monté).
