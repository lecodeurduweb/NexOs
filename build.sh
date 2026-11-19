#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.cargo/bin:$PATH"

TARGET="${1:-all}"
PROFILE="${PROFILE:-release}"

CARGO_PROFILE_FLAG=""
TARGET_SUBDIR="debug"
if [[ "$PROFILE" == "release" ]]; then
    CARGO_PROFILE_FLAG="--release"
    TARGET_SUBDIR="release"
fi

OBJCOPY=""
if command -v llvm-objcopy >/dev/null 2>&1; then
    OBJCOPY="llvm-objcopy"
elif command -v aarch64-linux-gnu-objcopy >/dev/null 2>&1; then
    OBJCOPY="aarch64-linux-gnu-objcopy"
else
    echo "ERROR: Neither llvm-objcopy nor aarch64-linux-gnu-objcopy found." >&2
    exit 1
fi

build_userspace() {
    echo "==> Building NexOS EL0 userspace (userspace/init.bin)..."
    mkdir -p build/userspace
    aarch64-linux-gnu-gcc -ffreestanding -nostdlib -nostartfiles -static -O2 -Wall -Wextra \
        -mgeneral-regs-only -Wl,-T,userspace/user.ld -Wl,--build-id=none \
        userspace/crt0.S userspace/init.c -o build/userspace/init.elf
    "$OBJCOPY" -O binary build/userspace/init.elf build/userspace/init.bin
    ls -lh build/userspace/init.elf build/userspace/init.bin
}

build_qemu() {
    build_userspace
    echo "==> Building NexOS for QEMU virt (gic-version=2, cortex-a72) [${PROFILE}]..."
    mkdir -p build/qemu_virt
    RUSTFLAGS="-C relocation-model=static -C code-model=small -C link-arg=-Tarch/arm64/boards/qemu_virt/linker.ld" \
        cargo build $CARGO_PROFILE_FLAG --no-default-features --features board-qemu-virt --target aarch64-unknown-none
    cp "target/aarch64-unknown-none/${TARGET_SUBDIR}/nexos-kernel" "build/qemu_virt/nexos-qemu.elf"
    "$OBJCOPY" -O binary "build/qemu_virt/nexos-qemu.elf" "build/qemu_virt/nexos-qemu.bin"
    ls -lh build/qemu_virt/nexos-qemu.elf build/qemu_virt/nexos-qemu.bin
}

build_rpi4() {
    build_userspace
    echo "==> Building NexOS for Raspberry Pi 4 (BCM2711) [${PROFILE}]..."
    mkdir -p build/rpi4
    RUSTFLAGS="-C relocation-model=static -C code-model=small -C link-arg=-Tarch/arm64/boards/rpi4/linker.ld" \
        cargo build $CARGO_PROFILE_FLAG --no-default-features --features board-rpi4 --target aarch64-unknown-none
    cp "target/aarch64-unknown-none/${TARGET_SUBDIR}/nexos-kernel" "build/rpi4/nexos-rpi4.elf"
    "$OBJCOPY" -O binary "build/rpi4/nexos-rpi4.elf" "build/rpi4/kernel8.img"
    cp "arch/arm64/boards/rpi4/config.txt" "build/rpi4/config.txt"
    echo "    NOTE: Pi 4 artifacts (kernel8.img, config.txt) are NON TESTÉS SUR MATÉRIEL."
    ls -lh build/rpi4/nexos-rpi4.elf build/rpi4/kernel8.img build/rpi4/config.txt
}

build_sd() {
    if [[ ! -f "build/rpi4/kernel8.img" ]]; then
        build_rpi4
    fi
    echo "==> Building Raspberry Pi 4 MBR + FAT32 SD Card Image..."
    python3 scripts/mk_rpi4_sd.py build/rpi4/kernel8.img arch/arm64/boards/rpi4/config.txt build/rpi4/nexos-rpi4-sd.img
    ls -lh build/rpi4/nexos-rpi4-sd.img
}

case "$TARGET" in
    qemu|qemu_virt)
        build_qemu
        ;;
    rpi4)
        build_rpi4
        ;;
    sd)
        build_sd
        ;;
    all)
        build_qemu
        build_rpi4
        ;;
    *)
        echo "Usage: $0 [qemu|rpi4|sd|all]" >&2
        exit 1
        ;;
esac
