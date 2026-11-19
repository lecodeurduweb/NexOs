# NexOS - Test Report

Date: 2026-11-19

## Passed

- `./build.sh all`
- `./build.sh sd`
- `npm run lint`
- `npm run build`
- Final `./build.sh all && ./build.sh sd` after linker-map correction.
- ELF W^X segment verification.
- RPi4 MBR/FAT32 layout verification.
- Python JSON/llama2.c `.nxm` conversion and CRC verification.
- Core QEMU stage suite, SMP, IPC, cache, EL0 isolation and AI smoke boot.
- HTTPS setup, login, RBAC, API, TLS 1.3 and cold-reboot persistence test.
- 3 AI gateway unit tests passed.
- HTTPS AI agent, memory, approved service restart and cold-reboot memory API test passed.

## Blocked

- `scripts/test_stage11_net.py`: failed to create `nexostap0` with `Operation not permitted`; test now exits explicitly as `SKIP`.
- `scripts/test_stage13_web.py`: last rerun was denied by the tool authorization prompt. A prior successful rerun covered TLS/setup/persistence, but the newly added agent assertions have not been separately rerun in this session.

## Not performed

- Physical Raspberry Pi 4 boot.
- Physical UART/GPIO/EMMC2/GENET/RNG200/watchdog/USB validation.
- External LLM provider round-trip with real credentials.

No hardware success is asserted.

