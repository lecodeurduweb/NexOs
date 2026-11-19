//! NexOS Kernel Entry Point & Core Orchestrator.
//!
//! Independent headless ARM64/AArch64 server operating system.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::arch::global_asm;
use core::panic::PanicInfo;

#[path = "../ai_core/mod.rs"]
pub mod ai_core;
#[path = "../arch/arm64/mod.rs"]
pub mod arch;
#[path = "../drivers/mod.rs"]
pub mod drivers;
#[path = "../filesystem/mod.rs"]
pub mod filesystem;
pub mod ipc;
pub mod log;
#[path = "../memory/mod.rs"]
pub mod memory;
#[path = "../network/mod.rs"]
pub mod network;
#[path = "../scheduler/mod.rs"]
pub mod scheduler;
#[path = "../security/mod.rs"]
pub mod security;
pub mod services;
pub mod sync;
pub mod syscall;
#[path = "../web-admin/mod.rs"]
pub mod web_admin;

use log::LogLevel;

global_asm!(include_str!("../boot/entry.S"));

extern "C" {
    static __kernel_start: u8;
    static __text_end: u8;
    static __rodata_end: u8;
    static __kernel_end: u8;
    static __bss_start: u8;
    static __bss_end: u8;
    static __stack_bottom: u8;
    static __stack_top: u8;
}

/// Entry point called from `boot/entry.S` once in EL1 with stack and BSS ready.
///
/// Arguments:
/// - `dtb_ptr`: physical address of the Device Tree Blob passed in `x0`.
/// - `boot_el`: Exception Level at initial boot (`3`, `2`, or `1`).
#[no_mangle]
pub extern "C" fn kernel_entry(dtb_ptr: usize, boot_el: u64) -> ! {
    // Stage 1 & 2: Initialize early serial console for the active board
    arch::boards::active::init_early_console();

    kprintln!();
    kprintln!("============================================================");
    kprintln!("  NexOS ARM64 Headless Server OS — v0.1.0");
    kprintln!("============================================================");

    let current_el = arch::current_el();
    let midr = arch::midr_el1();
    let pa_bits = arch::physical_address_bits();
    let kernel_start = unsafe { &__kernel_start as *const u8 as usize };
    let text_end = unsafe { &__text_end as *const u8 as usize };
    let rodata_end = unsafe { &__rodata_end as *const u8 as usize };
    let kernel_end = unsafe { &__kernel_end as *const u8 as usize };
    let bss_start = unsafe { &__bss_start as *const u8 as usize };
    let bss_end = unsafe { &__bss_end as *const u8 as usize };

    klog!(LogLevel::Info, "boot", "Board: {}", arch::boards::active::BOARD_NAME);
    klog!(
        LogLevel::Info,
        "boot",
        "Exception Level: boot EL{} -> active EL{}",
        boot_el,
        current_el
    );
    klog!(
        LogLevel::Info,
        "cpu",
        "MIDR_EL1 = {:#010x}, PARange = {}-bit physical addressing",
        midr,
        pa_bits
    );
    klog!(
        LogLevel::Info,
        "mem",
        "Kernel image: {:#010x}..{:#010x} ({} KiB), BSS: {:#010x}..{:#010x}",
        kernel_start,
        kernel_end,
        (kernel_end - kernel_start) / 1024,
        bss_start,
        bss_end
    );
    klog!(LogLevel::Info, "dtb", "DTB pointer from x0 = {:#010x}", dtb_ptr);
    klog!(LogLevel::Info, "uart", "Serial console active (115200 8N1)");

    // Stage 3: Install exception vector table and verify deliberate exception capture
    arch::exceptions::init();
    arch::exceptions::run_self_test();

    // Stage 4: Parse live Device Tree Blob (DTB) from x0
    match drivers::dtb::parse(dtb_ptr) {
        Ok(dtb) => {
            klog!(
                LogLevel::Info,
                "dtb",
                "Parsed DTB: model=\"{}\", size={} bytes, total RAM={} MiB",
                dtb.model_str(),
                dtb.dtb_size,
                dtb.total_ram_bytes() / (1024 * 1024)
            );
            for i in 0..dtb.mem_count {
                let r = dtb.mem_regions[i];
                klog!(
                    LogLevel::Info,
                    "dtb",
                    "  RAM[{}]: {:#014x}..{:#014x} ({} MiB)",
                    i,
                    r.base,
                    r.base.saturating_add(r.size),
                    r.size / (1024 * 1024)
                );
            }
            for i in 0..dtb.rsv_count {
                let r = dtb.rsv_regions[i];
                klog!(
                    LogLevel::Info,
                    "dtb",
                    "  RSV[{}]: {:#014x}..{:#014x} ({} KiB)",
                    i,
                    r.base,
                    r.base.saturating_add(r.size),
                    r.size / 1024
                );
            }
            klog!(
                LogLevel::Info,
                "dtb",
                "  GIC: {:?} (\"{}\") GICD={:#x} GICC={:#x}",
                dtb.gic.version,
                dtb.gic.compatible_str(),
                dtb.gic.gicd_base,
                dtb.gic.gicc_base
            );
            if dtb.uart.found {
                klog!(
                    LogLevel::Info,
                    "dtb",
                    "  UART: base={:#x} size={:#x} irq={:?} mini_uart={}",
                    dtb.uart.base,
                    dtb.uart.size,
                    dtb.uart.irq,
                    dtb.uart.is_mini_uart
                );
                if !dtb.uart.is_mini_uart && dtb.uart.base != 0 {
                    drivers::uart::bind_pl011_base(dtb.uart.base as usize);
                } else if dtb.uart.is_mini_uart {
                    klog!(
                        LogLevel::Warn,
                        "uart",
                        "DTB active UART is Mini-UART (base={:#x}); ensure dtoverlay=disable-bt is set in config.txt for PL011.",
                        dtb.uart.base
                    );
                }
            }
            if dtb.timer.found {
                klog!(
                    LogLevel::Info,
                    "dtb",
                    "  ARM Timer IRQs: sec={:?} ns={:?} virt={:?} hyp={:?}",
                    dtb.timer.sec_phys_irq,
                    dtb.timer.ns_phys_irq,
                    dtb.timer.virt_irq,
                    dtb.timer.hyp_irq
                );
            }
            klog!(
                LogLevel::Info,
                "dtb",
                "  CPUs: {}, VirtIO MMIO slots: {} (PSCI HVC={})",
                dtb.cpu_count,
                dtb.virtio_count,
                dtb.psci_hvc
            );

            // Stage 5: Initialize GICv2 and ARM Generic Timer from DTB
            if let Err(e) = drivers::gicv2::init(&dtb.gic) {
                klog!(LogLevel::Error, "gicv2", "Init failed: {}", e);
            } else if let Err(e) = arch::timer::init(&dtb.timer) {
                klog!(LogLevel::Error, "timer", "Init failed: {}", e);
            } else {
                arch::exceptions::enable_irq();
                klog!(LogLevel::Info, "irq", "CPU IRQs enabled (DAIF.I=0); waiting for periodic ticks...");
                while arch::timer::ticks() < 30 {
                    arch::wfi();
                }
                klog!(
                    LogLevel::Info,
                    "kernel",
                    "Stage 5 verified: {} periodic timer ticks observed (uptime={} ms).",
                    arch::timer::ticks(),
                    arch::timer::uptime_ms()
                );
                arch::timer::set_periodic_log(false);
            }

            // Stage 6: Physical memory allocator + AArch64 MMU
            if let Err(e) = memory::phys::init(&dtb, kernel_start, kernel_end) {
                klog!(LogLevel::Error, "phys", "Init failed: {}", e);
            } else if let Err(e) =
                arch::mmu::init_and_enable(&dtb, kernel_start, text_end, rodata_end, kernel_end)
            {
                klog!(LogLevel::Error, "mmu", "Enable failed: {}", e);
            } else {
                // Verify physical allocation, write/read through MMU, AT S1E1R translation, and free
                let p1 = memory::phys::alloc_frame().expect("alloc_frame p1");
                let p2 = memory::phys::alloc_frame_below(0x4000_0000); // test < 1GiB DMA check
                let test_va: u64 = 0x0000_1000_0000_0000;
                arch::mmu::map_page_4k(
                    arch::mmu::kernel_l0_paddr(),
                    test_va,
                    p1,
                    arch::mmu::MemAttr::NormalRw,
                )
                .expect("map_page_4k test_va");
                arch::mmu::invalidate_tlb_all();

                unsafe {
                    core::ptr::write_volatile(test_va as *mut u64, 0xCAFE_BABE_1234_5678);
                    let read_back = core::ptr::read_volatile(test_va as *const u64);
                    assert_eq!(read_back, 0xCAFE_BABE_1234_5678);
                }

                let translated = arch::mmu::translate_el1(test_va);
                let kern_translated = arch::mmu::translate_el1(kernel_start as u64);
                klog!(
                    LogLevel::Info,
                    "mmu",
                    "Stage 6 verified: VA {:#x} -> PA {:?} (expected {:#x}), kernel PA={:?}, DMA<1G={:?}",
                    test_va,
                    translated,
                    p1,
                    kern_translated,
                    p2
                );
                if let Some(frame2) = p2 {
                    let _ = memory::phys::free_frame(frame2);
                }
                let _ = memory::phys::free_frame(p1);

                // Stage 7: Kernel heap allocator (`alloc` crate)
                if let Err(e) = memory::heap::init() {
                    klog!(LogLevel::Error, "heap", "Init failed: {}", e);
                } else {
                    {
                        let b = Box::new(0xDEAD_BEEF_CAFE_BABEu64);
                        let mut v = Vec::with_capacity(256);
                        for i in 0..256u32 {
                            v.push(i * 3);
                        }
                        let mut s = String::from("NexOS-Heap-OK:");
                        s.push_str("v0.1");
                        assert_eq!(*b, 0xDEAD_BEEF_CAFE_BABE);
                        assert_eq!(v[255], 255 * 3);
                        assert_eq!(s, "NexOS-Heap-OK:v0.1");
                        let st_mid = memory::heap::stats();
                        klog!(
                            LogLevel::Info,
                            "heap",
                            "Live allocs={}: used={} B, free={} KiB",
                            st_mid.active_allocs,
                            st_mid.used_bytes,
                            st_mid.free_bytes / 1024
                        );
                    }
                    // Verify dynamic heap growth (>512 KiB) and coalescence on drop
                    {
                        let big: Vec<u8> = alloc::vec![0x5A; 700 * 1024];
                        assert_eq!(big[700 * 1024 - 1], 0x5A);
                    }
                    let st_end = memory::heap::stats();
                    klog!(
                        LogLevel::Info,
                        "heap",
                        "Stage 7 verified: after drop active_allocs={}, mapped={} KiB, free={} KiB",
                        st_end.active_allocs,
                        st_end.mapped_bytes / 1024,
                        st_end.free_bytes / 1024
                    );

                    // Stage 7b: Fail-closed Hardware/VirtIO CSPRNG (ChaCha20 DRBG)
                    if let Err(e) = security::csprng::init(&dtb) {
                        panic!("CRITICAL: CSPRNG entropy unavailable: {:?}", e);
                    }
                    security::csprng::self_test().expect("CSPRNG self-test failed");
                    klog!(
                        LogLevel::Info,
                        "csprng",
                        "CSPRNG self-test OK (source={}, BCM2711 RNG200 [mock] OK).",
                        security::csprng::source_name()
                    );

                    // Stage 8 + SMP: Initialize scheduler and boot secondary CPU cores
                    scheduler::init();
                    let online_cpus = arch::smp::boot_secondary_cpus(&dtb);
                    klog!(
                        LogLevel::Info,
                        "smp",
                        "Active cores: {}/{} (online_mask={:#04b})",
                        online_cpus,
                        dtb.cpu_count.max(1),
                        arch::smp::online_mask()
                    );
                    run_stage8_scheduler_test();
                    let reaped = scheduler::reap_exited();
                    if reaped > 0 {
                        klog!(LogLevel::Info, "sched", "Reclaimed {} remaining task(s).", reaped);
                    }

                    ipc::self_test().expect("IPC self-test failed");
                    klog!(LogLevel::Info, "ipc", "IPC channel self-test OK (roundtrip, WouldBlock, capacity Full).");

                    // Stage 10 (pre-shell init): VFS + progressive storage with write-error checks
                    run_stage10_storage(&dtb);

                    // Stage 11: Network stack (VirtIO-Net / RPi4 GENET, DHCP/Static, ICMP, UDP, DNS, TCP)
                    network::init(&dtb);

                    // Stage 12: Service manager, log ring, RBAC auth/permissions, watchdog
                    run_stage12_services_and_security();

                    // Stage 14: Native NexOS AI Core (NEON SIMD + .nxm Q8_0 inference)
                    ai_core::init();

                    // Stage 13: Minimal authenticated HTTP/1.1 (:80) & TLS 1.3 (:443) Web Admin
                    web_admin::start();

                    // Stage 9: EL0 isolation, syscalls, first user program + UART shell
                    run_stage9_userspace();
                }
            }
        }
        Err(e) => {
            klog!(LogLevel::Error, "dtb", "Failed to parse DTB at {:#x}: {}", dtb_ptr, e);
        }
    }

    klog!(LogLevel::Info, "kernel", "Boot stages 1-14 complete. Entering idle WFI loop.");

    loop {
        arch::wfi();
    }
}

fn run_stage10_storage(dtb: &drivers::dtb::DeviceTreeInfo) {
    use drivers::block::{cache, ramdisk::RamDisk, sd_emmc2, BlockDevice, BlockError};
    use filesystem::part::{parse_partitions, PartitionBlockDevice};
    use filesystem::vfs::{self, OwnedDiskPartition, VfsError};

    // Level 1: RamDisk read/write + write-error verification (OOB + ReadOnly)
    let mut rd = RamDisk::new(64);
    let mut sec = [0xA5u8; 512];
    rd.write_blocks(10, &sec).expect("ramdisk write");
    let mut read_back = [0u8; 512];
    rd.read_blocks(10, &mut read_back).expect("ramdisk read");
    assert_eq!(read_back, sec);
    assert_eq!(rd.write_blocks(64, &sec), Err(BlockError::OutOfBounds));
    rd.set_read_only(true);
    assert_eq!(rd.write_blocks(0, &sec), Err(BlockError::ReadOnly));
    klog!(
        LogLevel::Info,
        "storage",
        "Level 1 (RamDisk): R/W OK, OOB & ReadOnly write errors verified."
    );

    // BlockCache write-back & eviction self-test
    let cstats = cache::self_test().expect("BlockCache self_test");
    klog!(
        LogLevel::Info,
        "cache",
        "BlockCache verified (hits={}, misses={}, dirty_writes={}, evictions={}, flushes={}).",
        cstats.hits,
        cstats.misses,
        cstats.dirty_writes,
        cstats.evictions,
        cstats.flushes
    );

    // Mock BCM2711 EMMC2 SD controller self-test (deterministic MMIO simulation)
    sd_emmc2::self_test_mock().expect("EMMC2 mock self_test");
    klog!(
        LogLevel::Info,
        "emmc2",
        "[mock] BCM2711 EMMC2 MMIO self-test OK (CMD0/8/ACMD41/2/3/9/7/17/24 + OOB)."
    );

    // Level 2: VFS /ram + subdirectories + invalid path write error check
    vfs::init_ramfs();
    vfs::write_file("/ram/boot.log", b"ramfs-ok").expect("vfs ram write");
    assert_eq!(vfs::read_file("/ram/boot.log").unwrap(), b"ramfs-ok");
    vfs::mkdir("/ram/sub").expect("vfs ram mkdir");
    vfs::write_file("/ram/sub/test.txt", b"sub-ok").expect("vfs ram sub write");
    assert_eq!(vfs::read_file("/ram/sub/test.txt").unwrap(), b"sub-ok");
    vfs::remove("/ram/sub/test.txt").expect("vfs ram rm file");
    vfs::remove("/ram/sub").expect("vfs ram rmdir");
    assert_eq!(
        vfs::write_file("/invalid/foo", b"x"),
        Err(VfsError::InvalidPath)
    );
    klog!(
        LogLevel::Info,
        "vfs",
        "Level 2 (VFS /ram): R/W, mkdir/rm & InvalidPath error verified."
    );

    // Helper closure to mount & verify FAT32 partition #1 on `/disk`
    let verify_and_mount = |part_dev: OwnedDiskPartition, label: &'static str| {
        match vfs::mount_fat32_disk(part_dev) {
            Ok(()) => {
                let entries = vfs::list_dir("/disk").expect("list /disk");
                let hello_str = vfs::read_file("/disk/HELLO.TXT")
                    .ok()
                    .and_then(|v| String::from_utf8(v).ok())
                    .unwrap_or_default();
                klog!(
                    LogLevel::Info,
                    "fat32",
                    "Level 4 (FAT32 /disk via {}): {} entries, HELLO.TXT=\"{}\"",
                    label,
                    entries.len(),
                    hello_str.trim()
                );
                // Verify persistent write, subdirectory mkdir/read/remove, and cache sync
                vfs::write_file("/disk/NEXOS.TXT", b"NexOS-FAT32-Write-OK\n")
                    .expect("fat32 write");
                let check = vfs::read_file("/disk/NEXOS.TXT").expect("fat32 readback");
                assert_eq!(check, b"NexOS-FAT32-Write-OK\n");

                let _ = vfs::remove("/disk/NXSUB/T.TXT");
                let _ = vfs::remove("/disk/NXSUB");
                vfs::mkdir("/disk/NXSUB").expect("fat32 mkdir");
                vfs::write_file("/disk/NXSUB/T.TXT", b"sub-fat32").expect("fat32 sub write");
                assert_eq!(vfs::read_file("/disk/NXSUB/T.TXT").unwrap(), b"sub-fat32");
                vfs::remove("/disk/NXSUB/T.TXT").expect("fat32 sub rm");
                vfs::remove("/disk/NXSUB").expect("fat32 sub rmdir");
                vfs::sync().expect("fat32 sync");
                let cs = vfs::cache_stats();
                klog!(
                    LogLevel::Info,
                    "fat32",
                    "FAT32 write+readback+mkdir/rm+sync verified (/disk/NEXOS.TXT, cache={:?}).",
                    cs.map(|c| (c.hits, c.misses, c.dirty_writes))
                );
            }
            Err(e) => {
                klog!(LogLevel::Warn, "fat32", "FAT32 mount skipped/failed ({}): {:?}", label, e);
            }
        }
    };

    // Level 3 & 4: VirtIO-BLK (QEMU) -> MBR/GPT Partitions -> CachedBlockDevice -> FAT32 -> VFS /disk
    if let Some(mut vblk) = drivers::virtio::blk::VirtioBlk::probe(dtb) {
        let cap = vblk.block_count();
        assert_eq!(vblk.write_blocks(cap, &sec), Err(BlockError::OutOfBounds));

        match parse_partitions(&mut vblk) {
            Ok(parts) if !parts.is_empty() => {
                let p0 = parts[0];
                klog!(
                    LogLevel::Info,
                    "part",
                    "Level 3 ({:?}): Partition #{} start_lba={} sectors={} ({} MiB)",
                    p0.scheme,
                    p0.index,
                    p0.start_lba,
                    p0.sector_count,
                    (p0.sector_count * 512) / (1024 * 1024)
                );
                {
                    let mut pdev = PartitionBlockDevice::new(&mut vblk, p0).expect("part wrap");
                    assert_eq!(
                        vfs::_verify_partition_bounds(&mut pdev),
                        Err(BlockError::OutOfBounds)
                    );
                }
                let owned_part = OwnedDiskPartition::new(vblk, p0.start_lba, p0.sector_count)
                    .expect("owned partition")
                    .with_label("virtio-blk0p1");
                verify_and_mount(owned_part, "virtio-blk0");
            }
            Ok(_) => klog!(LogLevel::Warn, "part", "No MBR/GPT partitions found on virtio-blk0."),
            Err(e) => klog!(LogLevel::Error, "part", "Partition scan error: {:?}", e),
        }
    } else {
        klog!(LogLevel::Info, "storage", "No virtio-blk device attached.");
    }

    // Level 5: Raspberry Pi 4 EMMC2 SD controller -> MBR/GPT + FAT32 /disk (NON TESTÉ SUR MATÉRIEL)
    #[cfg(feature = "board-rpi4")]
    if !vfs::is_disk_mounted() {
        if let Some(emmc_base) = dtb.emmc2_base {
            let mut sd = drivers::block::sd_emmc2::Bcm2711Emmc2::new(emmc_base as usize);
            match sd.init() {
                Ok(()) => {
                    klog!(
                        LogLevel::Info,
                        "emmc2",
                        "BCM2711 EMMC2 SD ready ({} sectors) [NON TESTÉ SUR MATÉRIEL]",
                        sd.block_count()
                    );
                    if let Ok(parts) = parse_partitions(&mut sd) {
                        if let Some(p0) = parts.first().copied() {
                            if let Ok(owned) =
                                OwnedDiskPartition::new(sd, p0.start_lba, p0.sector_count)
                            {
                                verify_and_mount(owned.with_label("mmcblk0p1"), "bcm2711-emmc2");
                            }
                        }
                    }
                }
                Err(e) => klog!(LogLevel::Warn, "emmc2", "BCM2711 EMMC2 init skipped/failed: {:?}", e),
            }
        }
    }
    let _ = &mut sec;
    let _ = &verify_and_mount;
}

static INIT_USER_BIN: &[u8] = include_bytes!("../build/userspace/init.bin");

fn run_stage9_userspace() {
    klog!(
        LogLevel::Info,
        "user",
        "Loading EL0 userspace binary ({} bytes)...",
        INIT_USER_BIN.len()
    );

    // 1. Verify hardware EL0 -> EL1 isolation: probe attempts illegal kernel read
    let probe_l0 = arch::mmu::create_user_l0().expect("create_user_l0 probe");
    let (entry, stack_top) =
        arch::mmu::map_user_binary(probe_l0, INIT_USER_BIN).expect("map_user_binary probe");
    let probe_pid = scheduler::spawn_user("el0-probe", 150, probe_l0, entry, stack_top, 1);

    while !scheduler::is_task_exited(probe_pid) {
        arch::wfi();
    }
    let _ = scheduler::reap_exited();
    klog!(
        LogLevel::Info,
        "isol",
        "Stage 9 EL0->EL1 isolation verified: offending task pid={} terminated & reaped safely.",
        probe_pid
    );

    // 2. Launch interactive EL0 UART shell
    let shell_l0 = arch::mmu::create_user_l0().expect("create_user_l0 shell");
    let (s_entry, s_stack) =
        arch::mmu::map_user_binary(shell_l0, INIT_USER_BIN).expect("map_user_binary shell");
    let shell_pid = scheduler::spawn_user("el0-shell", 128, shell_l0, s_entry, s_stack, 0);
    klog!(
        LogLevel::Info,
        "user",
        "Spawned EL0 shell pid={} at VA {:#x} (SP_EL0={:#x})",
        shell_pid,
        s_entry,
        s_stack
    );
}

fn run_stage8_scheduler_test() {
    use core::sync::atomic::{AtomicUsize, Ordering};

    static WORKER_A_STEPS: AtomicUsize = AtomicUsize::new(0);
    static WORKER_B_STEPS: AtomicUsize = AtomicUsize::new(0);
    static WORKER_HI_STEPS: AtomicUsize = AtomicUsize::new(0);
    static DONE_COUNT: AtomicUsize = AtomicUsize::new(0);

    // CPU-bound worker (NO yield_now!): relies purely on timer-IRQ preemption
    fn cpu_worker(which: usize) -> ! {
        let mut last_other = 0usize;
        let mut switches_seen = 0usize;
        for step in 1..=60 {
            // Burn ~2-3 ms per step so each worker spans multiple 20 ms quanta
            for _ in 0..800_000 {
                arch::nop();
            }
            if which == 0 {
                WORKER_A_STEPS.store(step, Ordering::Release);
                let b = WORKER_B_STEPS.load(Ordering::Acquire);
                if b != last_other {
                    last_other = b;
                    switches_seen += 1;
                }
            } else {
                WORKER_B_STEPS.store(step, Ordering::Release);
                let a = WORKER_A_STEPS.load(Ordering::Acquire);
                if a != last_other {
                    last_other = a;
                    switches_seen += 1;
                }
            }
            if step % 20 == 0 {
                klog!(
                    LogLevel::Info,
                    "sched",
                    "Worker-{} (prio=128) step={} (preemptions_observed={})",
                    if which == 0 { "A" } else { "B" },
                    step,
                    switches_seen
                );
            }
        }
        DONE_COUNT.fetch_add(1, Ordering::AcqRel);
        scheduler::exit_current();
    }

    // High-priority periodic monitor waking via sleep_ms and preempting A/B
    fn high_prio_monitor(_: usize) -> ! {
        for i in 1..=3 {
            scheduler::sleep_ms(40);
            WORKER_HI_STEPS.store(i, Ordering::Release);
            klog!(
                LogLevel::Info,
                "sched",
                "HighPrio-Monitor (prio=200) woke #{} (A={}, B={})",
                i,
                WORKER_A_STEPS.load(Ordering::Acquire),
                WORKER_B_STEPS.load(Ordering::Acquire)
            );
        }
        DONE_COUNT.fetch_add(1, Ordering::AcqRel);
        scheduler::exit_current();
    }

    scheduler::spawn_kernel("worker-a", 128, cpu_worker, 0);
    scheduler::spawn_kernel("worker-b", 128, cpu_worker, 1);
    scheduler::spawn_kernel("monitor-hi", 200, high_prio_monitor, 0);

    // Idle loop waits until all 3 test tasks finish
    while DONE_COUNT.load(Ordering::Acquire) < 3 {
        arch::wfi();
    }

    klog!(
        LogLevel::Info,
        "sched",
        "Stage 8 verified: A={}, B={}, HighPrio={}, total_context_switches={}",
        WORKER_A_STEPS.load(Ordering::Acquire),
        WORKER_B_STEPS.load(Ordering::Acquire),
        WORKER_HI_STEPS.load(Ordering::Acquire),
        scheduler::total_switches()
    );
    let reaped_s8 = scheduler::reap_exited();
    klog!(LogLevel::Info, "sched", "Reclaimed {} exited Stage 8 task(s).", reaped_s8);

    // SMP Multi-Core Concurrency Verification (pinned per-core workers + Mutex + Semaphore)
    let online = arch::smp::online_cpus();
    if online > 1 {
        use core::sync::atomic::AtomicU8;
        use sync::{Mutex, Semaphore};

        static CPU_SEEN_MASK: AtomicU8 = AtomicU8::new(0);
        static SHARED_SUM: Mutex<u64> = Mutex::new(0);
        static DONE_SEM: Semaphore = Semaphore::new(0);

        CPU_SEEN_MASK.store(0, Ordering::Release);
        *SHARED_SUM.lock() = 0;

        fn smp_pinned_worker(target_cpu: usize) -> ! {
            let actual_cpu = arch::smp::cpu_id();
            assert_eq!(actual_cpu, target_cpu, "Pinned worker ran on wrong CPU!");
            CPU_SEEN_MASK.fetch_or(1u8 << actual_cpu, Ordering::AcqRel);
            for _ in 0..25 {
                let mut guard = SHARED_SUM.lock();
                *guard += 1;
            }
            DONE_SEM.release();
            scheduler::exit_current();
        }

        for cpu in 0..online {
            scheduler::spawn_kernel_on(
                "smp-worker",
                160,
                1u8 << cpu,
                smp_pinned_worker,
                cpu,
            );
        }
        for _ in 0..online {
            DONE_SEM.acquire();
        }

        let mask = CPU_SEEN_MASK.load(Ordering::Acquire);
        let sum = *SHARED_SUM.lock();
        assert_eq!(mask, arch::smp::online_mask());
        assert_eq!(sum, (online as u64) * 25);
        // Yield briefly so last worker reaches exit state before reaping
        scheduler::sleep_ms(15);
        let reaped_smp = scheduler::reap_exited();
        klog!(
            LogLevel::Info,
            "smp",
            "SMP {}-core concurrency verified: cpu_mask={:#04b}, mutex_sum={}, sem=OK (reaped={})",
            online,
            mask,
            sum,
            reaped_smp
        );
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    klog!(LogLevel::Error, "panic", "KERNEL PANIC: {}", info);
    arch::halt_forever();
}

fn run_stage12_services_and_security() {
    use core::sync::atomic::{AtomicUsize, Ordering};
    use services::RestartPolicy;

    security::init();
    security::self_test_rbac();
    security::announce_setup_status();

    services::init();

    static HEALTH_RUNS: AtomicUsize = AtomicUsize::new(0);
    fn health_daemon(_: usize) -> ! {
        let run = HEALTH_RUNS.fetch_add(1, Ordering::AcqRel) + 1;
        services::heartbeat("health-svc");
        if run == 1 {
            // Simulate daemon crash on first run so watchdog detects and restarts it
            klog!(LogLevel::Warn, "health-svc", "Simulated daemon exit on run #1");
            scheduler::exit_current();
        }
        loop {
            services::heartbeat("health-svc");
            scheduler::sleep_ms(100);
        }
    }

    services::register_daemon(
        "health-svc",
        "Supervised server health heartbeat daemon",
        Some("net-stack"),
        140,
        RestartPolicy::Always,
        300,
        health_daemon,
        0,
    )
    .expect("register health-svc");

    // Wait for crash -> watchdog detection -> automatic restart (run #2)
    let deadline = arch::timer::uptime_ms() + 1000;
    while HEALTH_RUNS.load(Ordering::Acquire) < 2 && arch::timer::uptime_ms() < deadline {
        scheduler::sleep_ms(20);
    }
    let restarts = services::snapshot()
        .into_iter()
        .find(|s| s.name == "health-svc")
        .map(|s| s.restarts)
        .unwrap_or(0);
    assert!(restarts >= 1, "Watchdog did not restart health-svc!");
    klog!(
        LogLevel::Info,
        "svc",
        "Stage 12 verified: RBAC auth/permissions OK, watchdog restarted 'health-svc' (restarts={}).",
        restarts
    );
}
