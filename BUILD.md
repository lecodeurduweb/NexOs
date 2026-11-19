# NexOS — Guide de Compilation (`BUILD.md`)

## Prérequis (Environnement Debian 12 x86_64)

1. **Outils système** :
   ```bash
   apt-get update
   apt-get install -y --no-install-recommends \
     qemu-system-arm lld llvm binutils-aarch64-linux-gnu gcc-aarch64-linux-gnu \
     make xz-utils device-tree-compiler ca-certificates curl
   ```
2. **Chaîne Rust (`rustup`, cible `aarch64-unknown-none`)** :
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
     sh -s -- -y --default-toolchain stable --target aarch64-unknown-none --profile minimal
   export PATH="$HOME/.cargo/bin:$PATH"
   ```

## Commandes de Build

*(Voir également [`docs/BUILD.md`](docs/BUILD.md) et [`docs/INSTALLATION.md`](docs/INSTALLATION.md).)*

- **Tout compiler (QEMU `virt` + Raspberry Pi 4 `kernel8.img`)** :
  ```bash
  ./build.sh all
  ```
- **Compiler uniquement QEMU `virt`** :
  ```bash
  ./build.sh qemu
  # Produit : build/qemu_virt/nexos-qemu.elf et build/qemu_virt/nexos-qemu.bin
  ```
- **Compiler uniquement Raspberry Pi 4 (`kernel8.img` + `config.txt`)** :
  ```bash
  ./build.sh rpi4
  # Produit : build/rpi4/kernel8.img, build/rpi4/nexos-rpi4.elf, build/rpi4/config.txt
  # ATTENTION : Marqué NON TESTÉ SUR MATÉRIEL.
  ```
- **Générer l'image SD bootable MBR + FAT32 pour Raspberry Pi 4** :
  ```bash
  ./build.sh sd
  # Produit : build/rpi4/nexos-rpi4-sd.img (32 MiB, NON TESTÉ SUR MATÉRIEL)
  ```
- **Profil debug (non optimisé)** :
  ```bash
  PROFILE=debug ./build.sh qemu
  ```
