#!/usr/bin/env bash
set -euo pipefail

KERNEL_BIN="build/qemu_virt/nexos-qemu.bin"
if [[ ! -f "$KERNEL_BIN" ]]; then
    echo "Kernel Image not found at $KERNEL_BIN, building first..."
    ./build.sh qemu
fi

QEMU_MEM="${QEMU_MEM:-1024M}"
QEMU_SMP="${QEMU_SMP:-4}"
QEMU_NET="${QEMU_NET:--netdev user,id=net0,hostfwd=tcp::18080-:80,hostfwd=tcp::18443-:443 -device virtio-net-device,netdev=net0}"
QEMU_BLK=""
if [[ -f "build/test_disk.img" ]]; then
    QEMU_BLK="-drive file=build/test_disk.img,if=none,format=raw,id=hd0 -device virtio-blk-device,drive=hd0"
fi
QEMU_EXTRA_ARGS="${QEMU_EXTRA_ARGS:-}"

echo "==> Launching NexOS on QEMU virt (gic-version=2, virtualization=on, cpu=cortex-a72, smp=${QEMU_SMP}, ram=${QEMU_MEM})"
echo "    Press Ctrl-A then X to exit QEMU."

exec qemu-system-aarch64 \
    -machine virt,gic-version=2,virtualization=on \
    -cpu cortex-a72 \
    -smp "${QEMU_SMP}" \
    -m "${QEMU_MEM}" \
    -nographic \
    -no-reboot \
    -device virtio-rng-device \
    ${QEMU_NET} \
    ${QEMU_BLK} \
    -kernel "${KERNEL_BIN}" \
    ${QEMU_EXTRA_ARGS}
