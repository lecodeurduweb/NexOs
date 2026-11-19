# NexOS — Guide de Compilation (`docs/BUILD.md`)

## 1. Prérequis (Debian 12 x86_64)

1. **Outils système & QEMU** :
   ```bash
   apt-get update
   apt-get install -y --no-install-recommends \
     qemu-system-arm lld llvm binutils-aarch64-linux-gnu gcc-aarch64-linux-gnu \
     device-tree-compiler iproute2 iputils-ping curl ca-certificates
   ```
2. **Chaîne Rust (`rustup`, cible bare-metal `aarch64-unknown-none`)** :
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
     sh -s -- -y --default-toolchain stable --target aarch64-unknown-none --profile minimal
   export PATH="$HOME/.cargo/bin:$PATH"
   ```

## 2. Commandes de Build (`./build.sh`)

`./build.sh` compile d'abord le binaire userspace EL0 (`userspace/init.bin`), puis le noyau Rust `no_std` avec `lld` et les linker scripts propres à chaque carte :

- **Toutes les cibles (`qemu_virt` + `rpi4` + `init.bin`)** :
  ```bash
  ./build.sh all
  ```
  Artéfacts mesurés :
  - `build/userspace/init.bin` (`12 288 B`) & `build/userspace/init.elf` (`0` segment `RWE`)
  - `build/qemu_virt/nexos-qemu.bin` (`404 072 B` / `395 KiB`) & `nexos-qemu.elf` (`546 KiB`)
  - `build/rpi4/kernel8.img` (`408 168 B` / `399 KiB`) & `nexos-rpi4.elf` (`553 KiB`) — **NON TESTÉS SUR MATÉRIEL**
  - `build/rpi4/config.txt` (`606 B`)

- **Cibles individuelles** :
  ```bash
  ./build.sh qemu   # QEMU virt uniquement
  ./build.sh rpi4   # Raspberry Pi 4 uniquement (NON TESTÉ SUR MATÉRIEL)
  PROFILE=debug ./build.sh qemu
  ```

## 3. Génération du Disque FAT32 & Modèle IA `.nxm`

```bash
python3 scripts/mk_test_disk.py build/test_disk.img
```
Génère une image GPT `16 MiB` contenant une partition FAT32 avec `HELLO.TXT`, `MODEL.NXM` (`103 262 B`, Q8_0 2 couches) et `BAD.GGF` (sonde de rejet GGUF).

## 4. Suite Automatisée de Validation (QEMU)

```bash
python3 tests/run_all.py
```
Exécute `./build.sh all`, la vérification ELF `W^X` (`readelf`), la création du disque FAT32/`.nxm`, le test boot SMP 4 cœurs + EL0 + AI NEON, le test réseau TAP/PCAP (`scripts/test_stage11_net.py`) et le test Web Admin HTTP + TLS 1.3 + `/api/v1/*` (`scripts/test_stage13_web.py`).
