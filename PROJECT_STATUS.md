# NexOS - Project Status

Status date: 2026-11-19

## Summary

NexOS is an independent ARM64/AArch64 bare-metal operating system project. Its kernel, userspace shell, memory manager, scheduler, filesystem, network stack, security subsystem and native AI engine compile and have been exercised on QEMU.

This project is not Linux and does not use a Linux kernel or distribution.

## Implemented and QEMU-tested

- AArch64 entry point and EL2/EL1 transition.
- Four-core SMP bring-up and preemptive scheduler.
- 4-level 4K MMU, physical allocator and kernel heap.
- ARM64 exception vectors and timer/GICv2.
- EL0 userspace, 31 syscalls, pointer validation and W^X separation.
- RamFS, FAT32, GPT/MBR, block cache and VirtIO-Blk.
- Ethernet, ARP, IPv4, IPv6, ICMP, DHCP, DNS, UDP and TCP.
- Native TLS 1.3 primitives and authenticated HTTP/HTTPS administration.
- CSPRNG, PBKDF2, RBAC, sessions, setup provisioning and audit.
- Native NEON Q8_0 `.nxm` inference engine.
- Kernel AI agent coordinator with system, network, security, memory, storage, process, diagnostic and repair roles.
- Host-side AI gateway for local Ollama or an OpenAI-compatible provider.
- React administration interface backed by live NexOS API endpoints.

## Compiled, not physically validated

- Raspberry Pi 4 `kernel8.img`, ELF and FAT32 SD image.
- BCM2711 EMMC2, GENET, RNG200, local timers/watchdog and USB.
- All low-level Raspberry Pi physical peripherals.

## Environment-blocked

- TAP/PCAP host networking test: TAP creation is denied by `TUNSETIFF: Operation not permitted`.
- Physical Raspberry Pi 4 validation: no hardware was available.

*** Add File: /home/louis/Documents/NexOs/nexos-arm64-server-os(3)/IMPLEMENTATION_STATUS.md
# NexOS - Implementation Status

## Status legend

- **Implemented**: source behavior exists.
- **Compiled**: built successfully for the target.
- **QEMU-tested**: exercised in QEMU.
- **Hardware-blocked**: implementation exists but physical validation is unavailable.
- **External-service-ready**: host service/client exists but requires a separately deployed provider.

| Area | State | Evidence / limitation |
|---|---|---|
| ARM64 boot | QEMU-tested | EL2→EL1 and SMP boot under `qemu-system-aarch64` |
| MMU/heap | QEMU-tested | 4K tables, W^X, physical allocator and heap |
| Scheduler | QEMU-tested | four-core priority scheduling and context switching |
| Syscalls/EL0 | QEMU-tested | shell and fault isolation |
| Storage | QEMU-tested | RAMFS, FAT32, VirtIO-Blk, cache |
| EMMC2 | Hardware-blocked | real register model plus mock MMIO test only |
| Network | Partially QEMU-tested | VirtIO-Net stack; TAP test blocked |
| GENET | Hardware-blocked | register/ring implementation but mock MMIO verification only |
| USB | Not complete | no real device stack verified |
| Security | QEMU-tested | CSPRNG, PBKDF2, RBAC, setup, sessions and audit |
| Web API | QEMU-tested | setup, auth, metrics, services, VFS, users and AI endpoints |
| Embedded dashboard | Implemented/QEMU-tested | live API HTML embedded in kernel |
| React dashboard | Compiled | Vite production build passes; not embedded in kernel image |
| Native AI engine | QEMU-tested | synthetic `.nxm` model and NEON kernels |
| AI agents | Implemented/QEMU build | deterministic routing and live observations |
| External AI gateway | External-service-ready | local implementation; provider call not tested as external credentialed service |
| Repair approval | Implemented | allowlisted host gateway and approval-token flow; not an uncontrolled privileged AI action |
| RPi4 image | Compiled | boot structure valid; not executed on physical hardware |

