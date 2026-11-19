# NexOS Raspberry Pi 4 Hardware Validation

No physical Raspberry Pi 4 validation has been performed in this session.

## Compile-time artifacts

- `build/rpi4/kernel8.img`
- `build/rpi4/nexos-rpi4.elf`
- `build/rpi4/kernel.elf`
- `build/rpi4/kernel.map`
- `build/rpi4/nexos.img`
- `build/rpi4/nexos-rpi4-sd.img`

The SD image is MBR/FAT32. It does not include proprietary Raspberry Pi boot firmware.

## Required physical procedure

1. Obtain official `start4.elf`, `fixup4.dat`, `bcm2711-rpi-4-b.dtb` and required overlays.
2. Copy firmware, `kernel8.img`, `config.txt` and `cmdline.txt` to a FAT32 boot partition.
3. Connect a USB-UART adapter at 3.3 V to GPIO 14 TXD and GPIO 15 RXD.
4. Boot and verify the initial UART banner and EL2/EL1 transition.
5. Verify the four Cortex-A72 cores and timer/GIC.
6. Verify RNG200 entropy before provisioning credentials.
7. Verify EMMC2/SD partition and FAT32 read/write/sync after cold reboot.
8. Verify GENET link speed, MAC, DHCP or static IPv4, ARP and TCP/UDP exchange.
9. Verify HTTPS via a local certificate, and physically record the UART setup token.
10. Verify reboot, watchdog, USB storage and interface behavior.

## Explicitly not validated

- Physical UART/PL011
- GPIO pull configuration
- BCM2711 mailbox/firmware clocks
- EMMC2 SD controller
- GENET PHY
- RNG200
- Watchdog
- DMA
- USB
- 8 GiB RAM region and 30/32-bit DMA constraints
- Four-core SMP on real Cortex-A72 hardware

