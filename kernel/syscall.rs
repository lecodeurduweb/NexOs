//! Kernel System Call Dispatcher (`SVC #0` from EL0).
//!
//! Enforces strict user virtual address validation (`USER_VA_BASE..USER_VA_END`)
//! on all user pointers so EL0 programs can never trick EL1 into reading or
//! overwriting kernel memory or MMIO peripherals.

use core::fmt::Write;
use core::slice;

use crate::arch::exceptions::TrapFrame;
use crate::arch::mmu;
use crate::arch::timer;
use crate::drivers::uart;
use crate::klog;
use crate::log::LogLevel;
use crate::memory::{heap, phys};
use crate::scheduler;

pub const SYS_WRITE: u64 = 0;
pub const SYS_READ: u64 = 1;
pub const SYS_EXIT: u64 = 2;
pub const SYS_YIELD: u64 = 3;
pub const SYS_GETPID: u64 = 4;
pub const SYS_UPTIME_MS: u64 = 5;
pub const SYS_SYSINFO: u64 = 6;
pub const SYS_SLEEP_MS: u64 = 7;
pub const SYS_VFS_LIST: u64 = 8;
pub const SYS_VFS_READ: u64 = 9;
pub const SYS_VFS_WRITE: u64 = 10;
pub const SYS_NET_INFO: u64 = 11;
pub const SYS_NET_PING: u64 = 12;
pub const SYS_NET_DNS: u64 = 13;
pub const SYS_NET_STAT: u64 = 14;
pub const SYS_SVC_LIST: u64 = 15;
pub const SYS_SVC_CTRL: u64 = 16;
pub const SYS_DMESG: u64 = 17;
pub const SYS_MMAP: u64 = 18;
pub const SYS_MUNMAP: u64 = 19;
pub const SYS_THREAD_SPAWN: u64 = 20;
pub const SYS_THREAD_JOIN: u64 = 21;
pub const SYS_IPC_SEND: u64 = 22;
pub const SYS_IPC_RECV: u64 = 23;
pub const SYS_VFS_MKDIR: u64 = 24;
pub const SYS_VFS_REMOVE: u64 = 25;
pub const SYS_VFS_SYNC: u64 = 26;
pub const SYS_DEV_LIST: u64 = 27;
pub const SYS_POWER: u64 = 28;
pub const SYS_AI_CMD: u64 = 29;
pub const SYS_SECURITY: u64 = 30;

const EAGAIN: i64 = -11;
const EACCES: i64 = -13;
const EFAULT: i64 = -14;
const EEXIST: i64 = -17;
const EINVAL: i64 = -22;
const EIO: i64 = -5;
const ENOSYS: i64 = -38;

fn validate_user_ptr(ptr: u64, len: u64, need_write: bool) -> Option<usize> {
    if mmu::verify_user_range(ptr, len, need_write) {
        Some(ptr as usize)
    } else {
        None
    }
}

struct BufWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Write for BufWriter<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let avail = self.buf.len().saturating_sub(self.pos);
        let n = bytes.len().min(avail);
        self.buf[self.pos..self.pos + n].copy_from_slice(&bytes[..n]);
        self.pos += n;
        Ok(())
    }
}

/// Handle an EL0 `SVC #0` system call. Returns the `TrapFrame` SP to restore.
pub fn handle_syscall(frame: &mut TrapFrame) -> usize {
    let tf_ptr = frame as *mut TrapFrame as usize;
    let num = frame.x[8];
    let a0 = frame.x[0];
    let a1 = frame.x[1];
    let a2 = frame.x[2];

    match num {
        SYS_WRITE => {
            let _fd = a0;
            let len = a2.min(4096);
            if let Some(addr) = validate_user_ptr(a1, len, false) {
                let bytes = unsafe { slice::from_raw_parts(addr as *const u8, len as usize) };
                for &b in bytes {
                    if b == b'\n' {
                        uart::write_byte(b'\r');
                    }
                    uart::write_byte(b);
                }
                frame.x[0] = len;
            } else {
                frame.x[0] = EFAULT as u64;
            }
            tf_ptr
        }
        SYS_READ => {
            let _fd = a0;
            let len = a2.min(256);
            if let Some(addr) = validate_user_ptr(a1, len, true) {
                let out = unsafe { slice::from_raw_parts_mut(addr as *mut u8, len as usize) };
                let mut read = 0usize;
                while read < out.len() {
                    if let Some(b) = uart::read_byte() {
                        out[read] = b;
                        read += 1;
                    } else {
                        break;
                    }
                }
                frame.x[0] = read as u64;
            } else {
                frame.x[0] = EFAULT as u64;
            }
            tf_ptr
        }
        SYS_EXIT => {
            let pid = scheduler::current_task_id();
            klog!(
                LogLevel::Info,
                "syscall",
                "EL0 task pid={} exited with code {}",
                pid,
                a0 as i64
            );
            scheduler::mark_current_exited();
            scheduler::schedule_from_trap(tf_ptr, true)
        }
        SYS_YIELD => scheduler::schedule_from_trap(tf_ptr, true),
        SYS_GETPID => {
            frame.x[0] = scheduler::current_task_id();
            tf_ptr
        }
        SYS_UPTIME_MS => {
            frame.x[0] = timer::uptime_ms();
            tf_ptr
        }
        SYS_SYSINFO => {
            let len = a1.min(1024);
            if let Some(addr) = validate_user_ptr(a0, len, true) {
                let out = unsafe { slice::from_raw_parts_mut(addr as *mut u8, len as usize) };
                let ps = phys::stats();
                let hs = heap::stats();
                let tasks = scheduler::snapshot();
                let mut w = BufWriter { buf: out, pos: 0 };
                let _ = writeln!(
                    w,
                    "  Board: {} | PARange: {}-bit | Uptime: {} ms",
                    crate::arch::boards::active::BOARD_NAME,
                    ps.pa_bits,
                    timer::uptime_ms()
                );
                let _ = writeln!(
                    w,
                    "  RAM: {} MiB free / {} MiB total | Heap: {} KiB used / {} KiB mapped",
                    (ps.free_frames * phys::PAGE_SIZE) / (1024 * 1024),
                    (ps.total_frames * phys::PAGE_SIZE) / (1024 * 1024),
                    hs.used_bytes / 1024,
                    hs.mapped_bytes / 1024
                );
                let _ = writeln!(
                    w,
                    "  Tasks ({} total, {} ctx switches):",
                    tasks.len(),
                    scheduler::total_switches()
                );
                for t in tasks.iter() {
                    let _ = writeln!(
                        w,
                        "    pid={} name={} prio={} el={} state={:?} ticks={}",
                        t.id,
                        t.name_str(),
                        t.priority,
                        if t.is_user { "EL0" } else { "EL1" },
                        t.state,
                        t.ticks_run
                    );
                }
                frame.x[0] = w.pos as u64;
            } else {
                frame.x[0] = EFAULT as u64;
            }
            tf_ptr
        }
        SYS_SLEEP_MS => {
            scheduler::prepare_current_sleep_ms(a0);
            frame.x[0] = 0;
            scheduler::schedule_from_trap(tf_ptr, true)
        }
        SYS_VFS_LIST => {
            // a0=path_ptr, a1=path_len, a2=out_buf (len=1024 fixed/or a3)
            let plen = a1.min(128);
            let out_len = frame.x[3].min(1024);
            if let (Some(paddr), Some(oaddr)) = (
                validate_user_ptr(a0, plen, false),
                validate_user_ptr(a2, out_len, true),
            ) {
                let path_bytes = unsafe { slice::from_raw_parts(paddr as *const u8, plen as usize) };
                let out = unsafe { slice::from_raw_parts_mut(oaddr as *mut u8, out_len as usize) };
                if let Ok(path) = core::str::from_utf8(path_bytes) {
                    match crate::filesystem::vfs::list_dir(path) {
                        Ok(entries) => {
                            let mut w = BufWriter { buf: out, pos: 0 };
                            for e in entries {
                                let kind = if e.is_dir { "DIR " } else { "FILE" };
                                let _ = writeln!(w, "  {} {:>8}  {}", kind, e.size, e.name);
                            }
                            frame.x[0] = w.pos as u64;
                        }
                        Err(_) => frame.x[0] = EIO as u64,
                    }
                } else {
                    frame.x[0] = EFAULT as u64;
                }
            } else {
                frame.x[0] = EFAULT as u64;
            }
            tf_ptr
        }
        SYS_VFS_READ => {
            // a0=path_ptr, a1=path_len, a2=out_buf, a3(x3)=out_len
            let plen = a1.min(128);
            let out_len = frame.x[3].min(4096);
            if let (Some(paddr), Some(oaddr)) = (
                validate_user_ptr(a0, plen, false),
                validate_user_ptr(a2, out_len, true),
            ) {
                let path_bytes = unsafe { slice::from_raw_parts(paddr as *const u8, plen as usize) };
                let out = unsafe { slice::from_raw_parts_mut(oaddr as *mut u8, out_len as usize) };
                if let Ok(path) = core::str::from_utf8(path_bytes) {
                    match crate::filesystem::vfs::read_file(path) {
                        Ok(data) => {
                            let n = data.len().min(out.len());
                            out[..n].copy_from_slice(&data[..n]);
                            frame.x[0] = n as u64;
                        }
                        Err(_) => frame.x[0] = EIO as u64,
                    }
                } else {
                    frame.x[0] = EFAULT as u64;
                }
            } else {
                frame.x[0] = EFAULT as u64;
            }
            tf_ptr
        }
        SYS_VFS_WRITE => {
            // a0=path_ptr, a1=path_len, a2=data_ptr, a3(x3)=data_len
            let plen = a1.min(128);
            let dlen = frame.x[3].min(4096);
            if let (Some(paddr), Some(daddr)) = (
                validate_user_ptr(a0, plen, false),
                validate_user_ptr(a2, dlen, false),
            ) {
                let path_bytes = unsafe { slice::from_raw_parts(paddr as *const u8, plen as usize) };
                let data = unsafe { slice::from_raw_parts(daddr as *const u8, dlen as usize) };
                if let Ok(path) = core::str::from_utf8(path_bytes) {
                    match crate::filesystem::vfs::write_file(path, data) {
                        Ok(()) => frame.x[0] = dlen,
                        Err(_) => frame.x[0] = EIO as u64,
                    }
                } else {
                    frame.x[0] = EFAULT as u64;
                }
            } else {
            frame.x[0] = EFAULT as u64;
            }
            tf_ptr
        }
        SYS_NET_INFO => {
            let out_len = a1.min(1024);
            if let Some(oaddr) = validate_user_ptr(a0, out_len, true) {
                let out = unsafe { slice::from_raw_parts_mut(oaddr as *mut u8, out_len as usize) };
                let s = crate::network::ifconfig_summary();
                let b = s.as_bytes();
                let n = b.len().min(out.len());
                out[..n].copy_from_slice(&b[..n]);
                frame.x[0] = n as u64;
            } else {
                frame.x[0] = EFAULT as u64;
            }
            tf_ptr
        }
        SYS_NET_STAT => {
            let out_len = a1.min(1024);
            if let Some(oaddr) = validate_user_ptr(a0, out_len, true) {
                let out = unsafe { slice::from_raw_parts_mut(oaddr as *mut u8, out_len as usize) };
                let s = crate::network::netstat_summary();
                let b = s.as_bytes();
                let n = b.len().min(out.len());
                out[..n].copy_from_slice(&b[..n]);
                frame.x[0] = n as u64;
            } else {
                frame.x[0] = EFAULT as u64;
            }
            tf_ptr
        }
        SYS_NET_PING => {
            // a0=ip_str_ptr, a1=ip_str_len, a2=out_buf, a3=out_len
            let ilen = a1.min(32);
            let out_len = frame.x[3].min(1024);
            if let (Some(iaddr), Some(oaddr)) = (
                validate_user_ptr(a0, ilen, false),
                validate_user_ptr(a2, out_len, true),
            ) {
                let ip_bytes = unsafe { slice::from_raw_parts(iaddr as *const u8, ilen as usize) };
                let out = unsafe { slice::from_raw_parts_mut(oaddr as *mut u8, out_len as usize) };
                let mut w = BufWriter { buf: out, pos: 0 };
                if let Ok(ip_str) = core::str::from_utf8(ip_bytes) {
                    if let Some(ip) = crate::network::eth::Ipv4Addr::parse(ip_str) {
                        let replies = crate::network::ping(ip, 3, 1000);
                        for r in &replies {
                            let _ = writeln!(
                                w,
                                "  64 bytes from {}: icmp_seq={} ttl={} time={}.{:03} ms",
                                ip,
                                r.seq,
                                r.ttl,
                                r.rtt_us / 1000,
                                r.rtt_us % 1000
                            );
                        }
                        let _ = writeln!(
                            w,
                            "  --- {} ping: 3 transmitted, {} received ---",
                            ip,
                            replies.len()
                        );
                        frame.x[0] = w.pos as u64;
                    } else {
                        frame.x[0] = EIO as u64;
                    }
                } else {
                    frame.x[0] = EFAULT as u64;
                }
            } else {
                frame.x[0] = EFAULT as u64;
            }
            tf_ptr
        }
        SYS_NET_DNS => {
            // a0=host_ptr, a1=host_len, a2=out_buf, a3=out_len
            let hlen = a1.min(128);
            let out_len = frame.x[3].min(256);
            if let (Some(haddr), Some(oaddr)) = (
                validate_user_ptr(a0, hlen, false),
                validate_user_ptr(a2, out_len, true),
            ) {
                let host_bytes = unsafe { slice::from_raw_parts(haddr as *const u8, hlen as usize) };
                let out = unsafe { slice::from_raw_parts_mut(oaddr as *mut u8, out_len as usize) };
                let mut w = BufWriter { buf: out, pos: 0 };
                if let Ok(host) = core::str::from_utf8(host_bytes) {
                    if let Some(ip) = crate::network::dns_resolve(host, 1500) {
                        let _ = writeln!(w, "  {} -> {}", host, ip);
                        frame.x[0] = w.pos as u64;
                    } else {
                        frame.x[0] = EIO as u64;
                    }
                } else {
                    frame.x[0] = EFAULT as u64;
                }
            } else {
                frame.x[0] = EFAULT as u64;
            }
            tf_ptr
        }
        SYS_SVC_LIST => {
            let out_len = a1.min(1024);
            if let Some(oaddr) = validate_user_ptr(a0, out_len, true) {
                let out = unsafe { slice::from_raw_parts_mut(oaddr as *mut u8, out_len as usize) };
                let s = crate::services::format_status();
                let b = s.as_bytes();
                let n = b.len().min(out.len());
                out[..n].copy_from_slice(&b[..n]);
                frame.x[0] = n as u64;
            } else {
                frame.x[0] = EFAULT as u64;
            }
            tf_ptr
        }
        SYS_SVC_CTRL => {
            // a0=name_ptr, a1=name_len, a2=op (0=stop, 1=restart, 2=start)
            let nlen = a1.min(64);
            if let Some(naddr) = validate_user_ptr(a0, nlen, false) {
                let nb = unsafe { slice::from_raw_parts(naddr as *const u8, nlen as usize) };
                if let Ok(name) = core::str::from_utf8(nb) {
                    let res = match a2 {
                        0 => crate::services::stop_service(name).map(|_| 0u64),
                        2 => crate::services::start_service(name),
                        _ => crate::services::restart_service(name),
                    };
                    frame.x[0] = match res {
                        Ok(pid) => pid,
                        Err(_) => EIO as u64,
                    };
                } else {
                    frame.x[0] = EFAULT as u64;
                }
            } else {
                frame.x[0] = EFAULT as u64;
            }
            tf_ptr
        }
        SYS_DMESG => {
            let out_len = a1.min(2048);
            if let Some(oaddr) = validate_user_ptr(a0, out_len, true) {
                let out = unsafe { slice::from_raw_parts_mut(oaddr as *mut u8, out_len as usize) };
                let s = crate::log::format_recent(16);
                let b = s.as_bytes();
                let n = b.len().min(out.len());
                out[..n].copy_from_slice(&b[..n]);
                frame.x[0] = n as u64;
            } else {
                frame.x[0] = EFAULT as u64;
            }
            tf_ptr
        }
        SYS_MMAP => {
            // a0=va_hint, a1=len_bytes, a2=prot_flags (bit 1=write, bit 2=exec -> reject W+X)
            let writable = (a2 & 2) != 0;
            let executable = (a2 & 4) != 0;
            if (writable && executable) || a1 == 0 {
                frame.x[0] = EINVAL as u64;
            } else {
                let ttbr0 = scheduler::current_ttbr0();
                match mmu::map_user_region(ttbr0, a0, a1, writable) {
                    Ok(va) => frame.x[0] = va,
                    Err(_) => frame.x[0] = EINVAL as u64,
                }
            }
            tf_ptr
        }
        SYS_MUNMAP => {
            let ttbr0 = scheduler::current_ttbr0();
            match mmu::unmap_user_region(ttbr0, a0, a1) {
                Ok(freed) => frame.x[0] = freed as u64,
                Err(_) => frame.x[0] = EINVAL as u64,
            }
            tf_ptr
        }
        SYS_THREAD_SPAWN => {
            // a0=entry_va, a1=arg0, a2=stack_bytes
            let stack_bytes = if a2 == 0 { 16384 } else { a2.min(262144) };
            let ttbr0 = scheduler::current_ttbr0();
            if a0 < mmu::USER_VA_BASE || a0 >= mmu::USER_VA_END {
                frame.x[0] = EFAULT as u64;
            } else if let Ok(sbase) = mmu::map_user_region(ttbr0, 0, stack_bytes, true) {
                let aligned_bytes = ((stack_bytes + phys::PAGE_SIZE as u64 - 1)
                    / phys::PAGE_SIZE as u64)
                    * phys::PAGE_SIZE as u64;
                let tid = scheduler::spawn_user_thread(
                    "el0-thread",
                    128,
                    ttbr0,
                    a0,
                    sbase + aligned_bytes,
                    a1,
                );
                frame.x[0] = tid;
            } else {
                frame.x[0] = EIO as u64;
            }
            tf_ptr
        }
        SYS_THREAD_JOIN => {
            // a0=tid, a1=timeout_ms
            match scheduler::join_task(a0, a1) {
                Some(code) => {
                    let _ = scheduler::reap_exited();
                    frame.x[0] = code as u64;
                }
                None => frame.x[0] = EAGAIN as u64,
            }
            tf_ptr
        }
        SYS_IPC_SEND => {
            // If a0 == 0: create/open channel named a1[..a2], returns chan_id.
            // If a0 > 0: send payload a1[..a2] to channel a0.
            let len = a2.min(crate::ipc::MAX_IPC_MSG_SIZE as u64);
            if let Some(paddr) = validate_user_ptr(a1, len, false) {
                let bytes = unsafe { slice::from_raw_parts(paddr as *const u8, len as usize) };
                if a0 == 0 {
                    match core::str::from_utf8(bytes)
                        .ok()
                        .map(crate::ipc::create_or_open)
                    {
                        Some(Ok(cid)) => frame.x[0] = cid,
                        _ => frame.x[0] = EINVAL as u64,
                    }
                } else {
                    let pid = scheduler::current_task_id();
                    match crate::ipc::send(a0, pid, bytes) {
                        Ok(()) => frame.x[0] = len,
                        Err(crate::ipc::IpcError::Full) => frame.x[0] = EAGAIN as u64,
                        Err(_) => frame.x[0] = EIO as u64,
                    }
                }
            } else {
                frame.x[0] = EFAULT as u64;
            }
            tf_ptr
        }
        SYS_IPC_RECV => {
            // a0=chan_id, a1=out_buf, a2=out_cap, a3(x3)=blocking(0|1)
            let cap = a2.min(crate::ipc::MAX_IPC_MSG_SIZE as u64);
            if let Some(oaddr) = validate_user_ptr(a1, cap, true) {
                let out = unsafe { slice::from_raw_parts_mut(oaddr as *mut u8, cap as usize) };
                let blocking = frame.x[3] != 0;
                match crate::ipc::recv(a0, blocking) {
                    Ok(msg) => {
                        let n = msg.payload.len().min(out.len());
                        out[..n].copy_from_slice(&msg.payload[..n]);
                        frame.x[0] = n as u64;
                    }
                    Err(crate::ipc::IpcError::WouldBlock) => frame.x[0] = EAGAIN as u64,
                    Err(_) => frame.x[0] = EIO as u64,
                }
            } else {
                frame.x[0] = EFAULT as u64;
            }
            tf_ptr
        }
        SYS_VFS_MKDIR => {
            let plen = a1.min(128);
            if let Some(paddr) = validate_user_ptr(a0, plen, false) {
                let pb = unsafe { slice::from_raw_parts(paddr as *const u8, plen as usize) };
                frame.x[0] = match core::str::from_utf8(pb)
                    .ok()
                    .map(crate::filesystem::vfs::mkdir)
                {
                    Some(Ok(())) => 0,
                    _ => EIO as u64,
                };
            } else {
                frame.x[0] = EFAULT as u64;
            }
            tf_ptr
        }
        SYS_VFS_REMOVE => {
            let plen = a1.min(128);
            if let Some(paddr) = validate_user_ptr(a0, plen, false) {
                let pb = unsafe { slice::from_raw_parts(paddr as *const u8, plen as usize) };
                frame.x[0] = match core::str::from_utf8(pb)
                    .ok()
                    .map(crate::filesystem::vfs::remove)
                {
                    Some(Ok(())) => 0,
                    _ => EIO as u64,
                };
            } else {
                frame.x[0] = EFAULT as u64;
            }
            tf_ptr
        }
        SYS_VFS_SYNC => {
            frame.x[0] = match crate::filesystem::vfs::sync() {
                Ok(()) => 0,
                Err(_) => EIO as u64,
            };
            tf_ptr
        }
        SYS_DEV_LIST => {
            let out_len = a1.min(1024);
            if let Some(oaddr) = validate_user_ptr(a0, out_len, true) {
                let out = unsafe { slice::from_raw_parts_mut(oaddr as *mut u8, out_len as usize) };
                let mut w = BufWriter { buf: out, pos: 0 };
                let _ = writeln!(w, "  Hardware & Virtual Devices:");
                if let Some(dtb) = crate::drivers::dtb::cached() {
                    let _ = writeln!(
                        w,
                        "    DTB Model: {} ({} CPUs online={}/{})",
                        dtb.model_str(),
                        dtb.cpu_count,
                        crate::arch::smp::online_cpus(),
                        dtb.cpu_count.max(1)
                    );
                    let _ = writeln!(
                        w,
                        "    GICv2: GICD={:#x} GICC={:#x} | UART={:#x} (mini={})",
                        dtb.gic.gicd_base, dtb.gic.gicc_base, dtb.uart.base, dtb.uart.is_mini_uart
                    );
                    let _ = writeln!(w, "    VirtIO-MMIO slots: {}", dtb.virtio_count);
                    if let Some(eb) = dtb.emmc2_base {
                        let _ = writeln!(w, "    BCM2711 EMMC2: {:#x}", eb);
                    }
                    if let Some(gb) = dtb.genet_base {
                        let _ = writeln!(w, "    BCM2711 GENET: {:#x}", gb);
                    }
                    if let Some(rb) = dtb.rng200_base {
                        let _ = writeln!(w, "    BCM2711 RNG200: {:#x}", rb);
                    }
                }
                let _ = writeln!(
                    w,
                    "    CSPRNG: seeded={} source={}",
                    crate::security::csprng::is_seeded(),
                    crate::security::csprng::source_name()
                );
                let ns = crate::network::stats();
                let _ = writeln!(
                    w,
                    "    NIC: init={} ip4={} ip6={}",
                    ns.initialized, ns.ip, ns.link_local_ipv6
                );
                let _ = writeln!(
                    w,
                    "    VFS /disk mounted={} cache={:?}",
                    crate::filesystem::vfs::is_disk_mounted(),
                    crate::filesystem::vfs::cache_stats().map(|c| (c.hits, c.misses))
                );
                frame.x[0] = w.pos as u64;
            } else {
                frame.x[0] = EFAULT as u64;
            }
            tf_ptr
        }
        SYS_POWER => {
            if a0 == 0 {
                klog!(LogLevel::Info, "power", "PSCI SYSTEM_OFF requested by EL0.");
                crate::arch::smp::psci_system_off();
            } else {
                klog!(LogLevel::Info, "power", "PSCI SYSTEM_RESET requested by EL0.");
                crate::arch::smp::psci_system_reset();
            }
        }
        SYS_AI_CMD => {
            // (a0=op, a1=arg_ptr, a2=arg_len, a3=out_ptr, a4=out_cap)
            // op: 0=status, 1=load, 2=ask, 3=bench, 4=unload
            let alen = a2.min(256);
            let out_len = frame.x[4].min(2048);
            let Some(oaddr) = validate_user_ptr(frame.x[3], out_len, true) else {
                frame.x[0] = EFAULT as u64;
                return tf_ptr;
            };
            let arg_str: &str = if alen > 0 {
                let Some(aaddr) = validate_user_ptr(a1, alen, false) else {
                    frame.x[0] = EFAULT as u64;
                    return tf_ptr;
                };
                let arg_bytes = unsafe { slice::from_raw_parts(aaddr as *const u8, alen as usize) };
                let Ok(s) = core::str::from_utf8(arg_bytes) else {
                    frame.x[0] = EFAULT as u64;
                    return tf_ptr;
                };
                s
            } else {
                ""
            };

            let out = unsafe { slice::from_raw_parts_mut(oaddr as *mut u8, out_len as usize) };
            let mut w = BufWriter { buf: out, pos: 0 };

            match a0 {
                0 => {
                    let st = crate::ai_core::status();
                    let _ = writeln!(
                        w,
                        "  NexOS AI Core: init={} neon_simd={} loaded={}",
                        st.initialized, st.neon_verified, st.model_loaded
                    );
                    let _ = writeln!(
                        w,
                        "    Model: {} (ram={} KiB, budget={} KiB)",
                        st.model_path,
                        st.model_ram_bytes / 1024,
                        st.active_budget_bytes / 1024
                    );
                    let _ = writeln!(
                        w,
                        "    Arch: dim={} layers={} heads={} vocab={} max_seq={}",
                        st.dim, st.n_layers, st.n_heads, st.vocab_size, st.max_seq
                    );
                    let _ = writeln!(
                        w,
                        "    Stats: inferences={} last_speed={}.{:02} tok/s",
                        st.total_inferences,
                        st.last_tokens_per_sec_x100 / 100,
                        st.last_tokens_per_sec_x100 % 100
                    );
                    frame.x[0] = w.pos as u64;
                }
                1 => {
                    let path = if arg_str.trim().is_empty() {
                        "/disk/MODEL.NXM"
                    } else {
                        arg_str.trim()
                    };
                    match crate::ai_core::load_from_vfs(path) {
                        Ok(info) => {
                            let _ = writeln!(w, "  AI model loaded: {}", info);
                            frame.x[0] = w.pos as u64;
                        }
                        Err(e) => {
                            let _ = writeln!(w, "  AI load failed: {}", e);
                            frame.x[0] = w.pos as u64;
                        }
                    }
                }
                2 => {
                    let prompt = if arg_str.trim().is_empty() {
                        "nexos status"
                    } else {
                        arg_str.trim()
                    };
                    match crate::ai_core::infer(prompt, 24, 0, 1) {
                        Ok(res) => {
                            let _ = writeln!(w, "  AI> {}", res.output);
                            let _ = writeln!(
                                w,
                                "  [stats: prompt_toks={} gen_toks={} elapsed_us={} speed={}.{:02} tok/s aborted={}]",
                                res.prompt_tokens,
                                res.generated_tokens,
                                res.elapsed_us,
                                res.tokens_per_sec_x100 / 100,
                                res.tokens_per_sec_x100 % 100,
                                res.aborted
                            );
                            frame.x[0] = w.pos as u64;
                        }
                        Err(e) => {
                            let _ = writeln!(w, "  AI infer error: {}", e);
                            frame.x[0] = EIO as u64;
                        }
                    }
                }
                3 => match crate::ai_core::benchmark(16) {
                    Ok(res) => {
                        let _ = writeln!(
                            w,
                            "  [ai-bench] NEON Q8_0: gen_toks={} elapsed_us={} ({} ms) speed={}.{:02} tok/s output=\"{}\"",
                            res.generated_tokens,
                            res.elapsed_us,
                            res.elapsed_ms,
                            res.tokens_per_sec_x100 / 100,
                            res.tokens_per_sec_x100 % 100,
                            res.output
                        );
                        frame.x[0] = w.pos as u64;
                    }
                    Err(e) => {
                        let _ = writeln!(w, "  AI bench error: {}", e);
                        frame.x[0] = EIO as u64;
                    }
                },
                4 => {
                    let had = crate::ai_core::unload();
                    let _ = writeln!(w, "  AI model unloaded (was_loaded={})", had);
                    frame.x[0] = w.pos as u64;
                }
                _ => {
                    frame.x[0] = EINVAL as u64;
                }
            }
            tf_ptr
        }
        SYS_SECURITY => {
            // a0=op:
            //   0: status -> returns needs_setup (1 or 0)
            //   1: local initial setup -> (a1=user_ptr, a2=user_len, a3=pass_ptr, a4=pass_len)
            //   2: list users -> (a1=out_buf, a2=out_cap)
            match a0 {
                0 => {
                    frame.x[0] = if crate::security::needs_setup() { 1 } else { 0 };
                }
                1 => {
                    let ulen = a2.min(64);
                    let plen = frame.x[4].min(128);
                    let (Some(uaddr), Some(paddr)) = (
                        validate_user_ptr(a1, ulen, false),
                        validate_user_ptr(frame.x[3], plen, false),
                    ) else {
                        frame.x[0] = EFAULT as u64;
                        return tf_ptr;
                    };
                    let ub = unsafe { slice::from_raw_parts(uaddr as *const u8, ulen as usize) };
                    let pb = unsafe { slice::from_raw_parts(paddr as *const u8, plen as usize) };
                    let (Ok(user), Ok(pass)) = (core::str::from_utf8(ub), core::str::from_utf8(pb)) else {
                        frame.x[0] = EINVAL as u64;
                        return tf_ptr;
                    };
                    frame.x[0] = match crate::security::complete_initial_setup_local(user, pass) {
                        Ok(()) => 0,
                        Err(crate::security::SecurityError::AlreadyExists) => EEXIST as u64,
                        Err(crate::security::SecurityError::InvalidInput) => EINVAL as u64,
                        Err(_) => EACCES as u64,
                    };
                }
                2 => {
                    let cap = a2.min(1024);
                    let Some(oaddr) = validate_user_ptr(a1, cap, true) else {
                        frame.x[0] = EFAULT as u64;
                        return tf_ptr;
                    };
                    let out = unsafe { slice::from_raw_parts_mut(oaddr as *mut u8, cap as usize) };
                    let mut w = BufWriter { buf: out, pos: 0 };
                    let users = crate::security::list_users();
                    let _ = writeln!(w, "  Needs initial setup: {}", crate::security::needs_setup());
                    for u in users {
                        let _ = writeln!(
                            w,
                            "    {} (role={}, fails={}, locked={})",
                            u.username,
                            u.role.as_str(),
                            u.failed_attempts,
                            u.locked
                        );
                    }
                    frame.x[0] = w.pos as u64;
                }
                _ => {
                    frame.x[0] = EINVAL as u64;
                }
            }
            tf_ptr
        }
        _ => {
            frame.x[0] = ENOSYS as u64;
            tf_ptr
        }
    }
}
