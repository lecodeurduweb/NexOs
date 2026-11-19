# Protocole de Démarrage et Test Matériel — Raspberry Pi 4 Model B (8 Go)

> **AVERTISSEMENT D'INTÉGRITÉ** : Les artefacts Raspberry Pi 4 (`build/rpi4/kernel8.img`, `build/rpi4/config.txt`) générés par `./build.sh rpi4` sont **COMPILÉS** mais **NON TESTÉS SUR MATÉRIEL RÉEL** (QEMU `7.2.22` ne fournit pas de machine `raspi4b`). Ne jamais présumer qu'une validation QEMU `virt` garantit le fonctionnement sur BCM2711 physique sans exécuter ce protocole.

---

## 1. Matériel Requis

1. **Raspberry Pi 4 Model B (8 Go RAM)** — SoC BCM2711 (Cortex-A72).
2. **Alimentation USB-C 5 V / 3 A stable** (ne jamais alimenter via les broches UART).
3. **Carte microSD** (8 Go ou plus).
4. **Adaptateur USB-UART TTL 3,3 V** (FT232RL, CP2102, CH340G en mode 3,3 V).
   - **CRITIQUE** : Les GPIO du BCM2711 sont limités à **3,3 V** (non tolérants 5 V / RS-232).
5. *(Optionnel pour diagnostics ultérieurs)* Câble Ethernet RJ45 sur réseau local.

---

## 2. Préparation de la Carte microSD

1. Créez une table de partitions **MBR (DOS)** avec une première partition primaire **FAT32 LBA** (type `0x0c`, minimum 128 Mio, idéalement 512 Mio–1 Gio). Formatez-la en FAT32 (`mkfs.vfat -F 32 -n NEXOSBOOT /dev/sdX1`).
2. Copiez à la racine de la partition FAT32 les fichiers officiels du firmware Raspberry Pi 4 (dépôt `raspberrypi/firmware`, répertoire `boot/`) :
   - `start4.elf` *(firmware VideoCore Pi 4)*
   - `fixup4.dat` *(table de correction mémoire VideoCore)*
   - `bcm2711-rpi-4-b.dtb` *(Device Tree officiel BCM2711)*
   - `overlays/disable-bt.dtbo` *(dossier `/overlays/disable-bt.dtbo` requis par `dtoverlay=disable-bt` pour basculer PL011 UART0 vers GPIO 14/15)*
   - *(Note : `bootcode.bin` réside dans l'EEPROM SPI du Pi 4 et n'est pas requis sur la SD.)*
3. Compilez NexOS pour Pi 4 et copiez les artefacts générés à la racine de la partition FAT32 :
   ```bash
   ./build.sh rpi4
   cp build/rpi4/kernel8.img /mnt/sd/kernel8.img
   cp build/rpi4/config.txt  /mnt/sd/config.txt
   sync
   ```

---

## 3. Configuration Raspberry Pi 4 (`config.txt`)

Le fichier `arch/arm64/boards/rpi4/config.txt` (copié vers `build/rpi4/config.txt`) contient :
```ini
# Force le démarrage AArch64 (charge kernel8.img à 0x80000, x0 = DTB)
arm_64bit=1

# Active l'UART et le journal de boot 2nd-stage de start4.elf (115200 8N1)
enable_uart=1
uart_2ndstage=1

# Image noyau explicite
kernel=kernel8.img

# Split GPU minimal pour serveur headless (libère le maximum de RAM < 1 Go)
gpu_mem=16

# Désactive le Bluetooth sur PL011 et route UART0 (PL011) sur GPIO 14/15 ALT0
dtoverlay=disable-bt
```

**Important (mode périphérique BCM2711)** : Ne ajoutez **pas** `arm_peri_high=1` dans `config.txt` — le code d'amorçage pré-DTB (`arch/arm64/boards/rpi4/mod.rs`) suppose le mode bas-périphérique par défaut (`0xFE00_0000`).

---

## 4. Câblage et Connexion UART

Sur le connecteur GPIO 40 broches du Raspberry Pi 4 :
- **Pin 6 (GND)** ↔ **GND** de l'adaptateur USB-UART
- **Pin 8 (GPIO 14 / TXD0)** ↔ **RXD** de l'adaptateur USB-UART
- **Pin 10 (GPIO 15 / RXD0)** ↔ **TXD** de l'adaptateur USB-UART
- *(Laissez la broche VCC/3V3/5V de l'adaptateur débranchée.)*

Paramètres du terminal série : **115200 bauds, 8N1, sans contrôle de flux (hardware/software flow control = OFF)**.

Exemple sous Linux avec capture automatique dans un fichier log :
```bash
picocom -b 115200 --flow n -g rpi4_uart_boot.log /dev/ttyUSB0
# ou
screen -L -Logfile rpi4_uart_boot.log /dev/ttyUSB0 115200
```

---

## 5. Messages Attendus au Démarrage Réel

1. **Étape Firmware VideoCore (`uart_2ndstage=1`)** : Lignes initiales de l'EEPROM et `start4.elf` indiquant la détection RAM (8 Go), le chargement de `bcm2711-rpi-4-b.dtb`, l'overlay `disable-bt` et le chargement de `kernel8.img` à `0x00080000`.
2. **Étape Noyau NexOS (`boot/entry.S` → `kernel/main.rs`)** :
   ```text
   ============================================================
     NexOS ARM64 Headless Server OS — v0.1.0
   ============================================================
   [INFO][boot] Board: rpi4 (BCM2711) [NON TESTE SUR MATERIEL]
   [INFO][boot] Exception Level: boot EL2 -> active EL1
   [INFO][cpu] MIDR_EL1 = 0x410fd083, PARange = 44-bit physical addressing
   [INFO][mem] Kernel image: 0x00080000..0x000d8000 (... KiB), BSS: ...
   [INFO][dtb] DTB pointer from x0 = 0x...
   [INFO][uart] Serial console active (115200 8N1)
   [INFO][exc] VBAR_EL1 installed at 0x00080800
   ...
   [INFO][exc] Stage 3 exception test passed (resumed cleanly after ERET).
   [INFO][dtb] Parsed DTB: model="Raspberry Pi 4 Model B Rev ...", total RAM=... MiB
   [INFO][dtb]   GIC: V2 ("arm,gic-400") GICD=0xff841000 GICC=0xff842000
   [INFO][gicv2] Initialized GICv2 ("arm,gic-400"): ...
   [INFO][timer] ARM Generic Timer started: CNTFRQ=54000000 Hz, tick=100 Hz (...), GIC INTID=30
   [INFO][phys] Physical allocator ready: PARange=44-bit, ...
   [INFO][mmu] MMU enabled (W^X: .text=0x80000..0x... RX, .ro=... RO): L0=0x..., IPS=4 (44-bit PA)
   [INFO][kernel] Boot stages 1-14 complete. Entering idle WFI loop.

   [EL0-shell] NexOS Userspace Shell started in EL0 (pid=...)
   nexos#
   ```
3. **Remarque sur les étapes avancées sur Pi 4 (`NON TESTÉ SUR MATÉRIEL`)** :
   - Les cœurs secondaires 1..3 sont réveillés via PSCI SMC/parking spin-table (`_secondary_start`).
   - Sous `board-rpi4`, si `Bcm2711Emmc2::init()` réussit et détecte une partition MBR/GPT FAT32, celle-ci est montée sur `/disk` (y compris `/disk/MODEL.NXM` si présent).
   - `Bcm2711Genet` et `Bcm2711Emmc2` restent validés uniquement par **mock MMIO sous QEMU** (`NON TESTÉS SUR MATÉRIEL RÉEL`).

---

## 6. Diagnostic d'un Échec de Démarrage

| Symptôme observé | Cause probable | Vérification à effectuer |
|---|---|---|
| **LED verte ACT reste fixe ou clignote 4× / 7×**, **aucun** texte UART | Carte SD illisible, partition non FAT32 LBA, ou `start4.elf` / `fixup4.dat` manquant | Vérifier l'ordre TX/RX, la masse GND commune, la table MBR + FAT32 (`0x0c`), et la présence de `start4.elf`/`fixup4.dat` |
| **Logs `start4.elf` visibles**, puis **silence total** après le saut vers `kernel8.img` | `overlays/disable-bt.dtbo` absent sur la SD (PL011 resté sur BT au lieu de GPIO 14/15), `arm_peri_high=1` activé, ou crash très précoce avant `init_early_console()` | Vérifier `/overlays/disable-bt.dtbo` et `config.txt` ; retirer `uart_2ndstage` uniquement pour test si besoin |
| **Caractères illisibles / corrompus** après `Serial console active` | Débit != 115200 ou mauvais clock PL011 (si firmware configuré hors 48 MHz) | Vérifier 115200 8N1 et l'absence de `init_uart_clock` exotique dans `config.txt` |
| **Blocage sur `Parsed DTB` / `GICv2` / `MMU enabled`** | Mauvais offset DTB (`ranges`/GIC-400), exception synchrone `EL1` ou page MMIO manquante | Relever la dernière ligne UART et tout `EXCEPTION DUMP` (`ESR_EL1`, `ELR_EL1`, `FAR_EL1`) |
| **Blocage après `waiting for periodic ticks...`** | Interruptions GIC-400 Non-Secure (`GICD_CTLR`/`GICC_PMR`/PPI 14) non délivrées au cœur 0 | Vérifier `GIC-400` IIDR/TYPER et la configuration groupe/priorité Non-Secure |

---

## 7. Comment Récupérer et Transmettre les Informations de Diagnostic

En cas d'échec ou d'anomalie sur matériel réel, conservez et transmettez :
1. Le fichier de **capture UART complète** (`rpi4_uart_boot.log`), incluant les messages VideoCore (`uart_2ndstage=1`).
2. La **révision exacte du Raspberry Pi 4** et la version de l'EEPROM SPI (affichées par `uart_2ndstage=1` au début du log).
3. Le contenu exact de la partition FAT32 (`ls -laR /mnt/sd`) et le contenu complet de `config.txt`.
4. Le comportement des LED **PWR (rouge)** et **ACT (verte)** (clignotements éventuels).
5. L'identifiant exact du commit compilé (`git rev-parse HEAD`) et le condensé SHA-256 du fichier copié (`sha256sum build/rpi4/kernel8.img`).
