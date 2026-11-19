//! NexOS Service Lifecycle Manager & Watchdog Supervisor.
//!
//! Tracks managed services (state, dependencies, restart policy, PID, restart count)
//! and supervises registered daemons via heartbeat & exit checks.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::arch::timer;
use crate::klog;
use crate::log::LogLevel;
use crate::scheduler;
use crate::sync::SpinLock;

const MAX_SERVICES: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceState {
    Stopped,
    Running,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartPolicy {
    Never,
    OnFailure,
    Always,
}

#[derive(Clone)]
pub struct ServiceSnapshot {
    pub name: String,
    pub description: String,
    pub state: ServiceState,
    pub restart_policy: RestartPolicy,
    pub autostart: bool,
    pub depends_on: Option<String>,
    pub task_id: Option<u64>,
    pub restarts: u32,
    pub watchdog_timeout_ms: u64,
}

struct ManagedService {
    name: String,
    description: String,
    state: ServiceState,
    restart_policy: RestartPolicy,
    autostart: bool,
    depends_on: Option<String>,
    task_id: Option<u64>,
    entry: Option<fn(usize) -> !>,
    arg: usize,
    priority: u8,
    restarts: u32,
    last_heartbeat_ms: u64,
    watchdog_timeout_ms: u64,
    events: Vec<String>,
}

impl ManagedService {
    fn log_event(&mut self, msg: String) {
        if self.events.len() >= 16 {
            self.events.remove(0);
        }
        self.events.push(msg);
    }
}

struct ServiceRegistry {
    initialized: bool,
    services: Vec<ManagedService>,
}

impl ServiceRegistry {
    const fn new() -> Self {
        Self {
            initialized: false,
            services: Vec::new(),
        }
    }
}

static SERVICES: SpinLock<ServiceRegistry> = SpinLock::new(ServiceRegistry::new());

pub fn init() {
    {
        let mut reg = SERVICES.lock();
        if reg.initialized {
            return;
        }
        reg.initialized = true;
    }

    register_builtin(
        "storage-vfs",
        "VFS (/ram + /disk FAT32) & block layer",
        None,
        ServiceState::Running,
    );
    register_builtin(
        "net-stack",
        "VirtIO-Net/GENET + IPv4/ICMP/UDP/DHCP/DNS/TCP",
        None,
        ServiceState::Running,
    );
    register_builtin(
        "tcp-echo",
        "TCP Echo diagnostic daemon (:7070)",
        Some("net-stack"),
        ServiceState::Running,
    );

    scheduler::spawn_kernel("watchdog", 210, watchdog_worker, 0);
    klog!(
        LogLevel::Info,
        "svc",
        "Service Manager & Watchdog active ({} core services registered)",
        snapshot().len()
    );
}

fn register_builtin(
    name: &str,
    description: &str,
    depends_on: Option<&str>,
    state: ServiceState,
) {
    let mut reg = SERVICES.lock();
    if reg.services.len() >= MAX_SERVICES {
        return;
    }
    reg.services.push(ManagedService {
        name: String::from(name),
        description: String::from(description),
        state,
        restart_policy: RestartPolicy::Never,
        autostart: true,
        depends_on: depends_on.map(String::from),
        task_id: None,
        entry: None,
        arg: 0,
        priority: 128,
        restarts: 0,
        last_heartbeat_ms: timer::uptime_ms(),
        watchdog_timeout_ms: 0,
        events: alloc::vec![format!("[{} ms] initialized builtin", timer::uptime_ms())],
    });
}

/// Register and optionally start a supervised kernel service daemon.
pub fn register_daemon(
    name: &str,
    description: &str,
    depends_on: Option<&str>,
    priority: u8,
    restart_policy: RestartPolicy,
    watchdog_timeout_ms: u64,
    entry: fn(usize) -> !,
    arg: usize,
) -> Result<(), &'static str> {
    {
        let reg = SERVICES.lock();
        if reg.services.len() >= MAX_SERVICES {
            return Err("Service registry full");
        }
        if let Some(dep) = depends_on {
            let dep_ok = reg
                .services
                .iter()
                .any(|s| s.name == dep && s.state == ServiceState::Running);
            if !dep_ok {
                return Err("Service dependency not running");
            }
        }
    }

    let pid = scheduler::spawn_kernel(name, priority, entry, arg);
    let now = timer::uptime_ms();
    let mut reg = SERVICES.lock();
    reg.services.push(ManagedService {
        name: String::from(name),
        description: String::from(description),
        state: ServiceState::Running,
        restart_policy,
        autostart: true,
        depends_on: depends_on.map(String::from),
        task_id: Some(pid),
        entry: Some(entry),
        arg,
        priority,
        restarts: 0,
        last_heartbeat_ms: now,
        watchdog_timeout_ms,
        events: alloc::vec![format!("[{} ms] started pid={}", now, pid)],
    });
    klog!(LogLevel::Info, "svc", "Started service '{}' (pid={}, wdog={}ms)", name, pid, watchdog_timeout_ms);
    Ok(())
}

pub fn heartbeat(service_name: &str) {
    let now = timer::uptime_ms();
    let mut reg = SERVICES.lock();
    if let Some(s) = reg.services.iter_mut().find(|s| s.name == service_name) {
        s.last_heartbeat_ms = now;
    }
}

pub fn stop_service(name: &str) -> Result<(), &'static str> {
    let task_to_kill = {
        let mut reg = SERVICES.lock();
        let Some(s) = reg.services.iter_mut().find(|s| s.name == name) else {
            return Err("Service not found");
        };
        s.state = ServiceState::Stopped;
        s.task_id.take()
    };
    if let Some(pid) = task_to_kill {
        let _ = scheduler::kill_task(pid);
        let _ = scheduler::reap_exited();
    }
    let now = timer::uptime_ms();
    {
        let mut reg = SERVICES.lock();
        if let Some(s) = reg.services.iter_mut().find(|s| s.name == name) {
            s.log_event(format!("[{} ms] stopped", now));
        }
    }
    klog!(LogLevel::Info, "svc", "Stopped service '{}'", name);
    Ok(())
}

pub fn start_service(name: &str) -> Result<u64, &'static str> {
    let (state, entry_opt, arg, prio, dep_opt) = {
        let reg = SERVICES.lock();
        let s = reg
            .services
            .iter()
            .find(|s| s.name == name)
            .ok_or("Service not found")?;
        (s.state, s.entry, s.arg, s.priority, s.depends_on.clone())
    };
    if state == ServiceState::Running {
        return Err("Service already running");
    }
    if let Some(dep) = dep_opt {
        let reg = SERVICES.lock();
        let dep_ok = reg
            .services
            .iter()
            .any(|s| s.name == dep && s.state == ServiceState::Running);
        if !dep_ok {
            return Err("Dependency service is not running");
        }
    }
    let new_pid = if let Some(entry) = entry_opt {
        scheduler::spawn_kernel(name, prio, entry, arg)
    } else {
        0
    };
    let now = timer::uptime_ms();
    let mut reg = SERVICES.lock();
    if let Some(s) = reg.services.iter_mut().find(|s| s.name == name) {
        s.task_id = if new_pid > 0 { Some(new_pid) } else { None };
        s.state = ServiceState::Running;
        s.last_heartbeat_ms = now;
        s.log_event(format!("[{} ms] started pid={}", now, new_pid));
    }
    klog!(LogLevel::Info, "svc", "Started service '{}' (pid={})", name, new_pid);
    Ok(new_pid)
}

pub fn set_autostart(name: &str, enabled: bool) -> Result<(), &'static str> {
    let mut reg = SERVICES.lock();
    let s = reg
        .services
        .iter_mut()
        .find(|s| s.name == name)
        .ok_or("Service not found")?;
    s.autostart = enabled;
    Ok(())
}

pub fn service_logs(name: &str) -> Option<Vec<String>> {
    SERVICES
        .lock()
        .services
        .iter()
        .find(|s| s.name == name)
        .map(|s| s.events.clone())
}

pub fn restart_service(name: &str) -> Result<u64, &'static str> {
    let (entry_opt, arg, prio, old_pid, dep_opt) = {
        let reg = SERVICES.lock();
        let s = reg
            .services
            .iter()
            .find(|s| s.name == name)
            .ok_or("Service not found")?;
        (s.entry, s.arg, s.priority, s.task_id, s.depends_on.clone())
    };

    if let Some(dep) = dep_opt {
        let reg = SERVICES.lock();
        let dep_ok = reg
            .services
            .iter()
            .any(|s| s.name == dep && s.state == ServiceState::Running);
        if !dep_ok {
            return Err("Dependency service is not running");
        }
    }

    if let Some(pid) = old_pid {
        let _ = scheduler::kill_task(pid);
        let _ = scheduler::reap_exited();
    }

    if let Some(entry) = entry_opt {
        let new_pid = scheduler::spawn_kernel(name, prio, entry, arg);
        let now = timer::uptime_ms();
        let mut reg = SERVICES.lock();
        if let Some(s) = reg.services.iter_mut().find(|s| s.name == name) {
            s.task_id = Some(new_pid);
            s.state = ServiceState::Running;
            s.restarts += 1;
            s.last_heartbeat_ms = now;
            s.log_event(format!("[{} ms] restarted pid={}", now, new_pid));
        }
        klog!(LogLevel::Info, "svc", "Restarted service '{}' (new pid={})", name, new_pid);
        Ok(new_pid)
    } else {
        let mut reg = SERVICES.lock();
        if let Some(s) = reg.services.iter_mut().find(|s| s.name == name) {
            s.state = ServiceState::Running;
            s.restarts += 1;
            let now = timer::uptime_ms();
            s.last_heartbeat_ms = now;
            s.log_event(format!("[{} ms] reset builtin", now));
        }
        klog!(LogLevel::Info, "svc", "Reset built-in service '{}'", name);
        Ok(0)
    }
}

pub fn snapshot() -> Vec<ServiceSnapshot> {
    let reg = SERVICES.lock();
    reg.services
        .iter()
        .map(|s| ServiceSnapshot {
            name: s.name.clone(),
            description: s.description.clone(),
            state: s.state,
            restart_policy: s.restart_policy,
            autostart: s.autostart,
            depends_on: s.depends_on.clone(),
            task_id: s.task_id,
            restarts: s.restarts,
            watchdog_timeout_ms: s.watchdog_timeout_ms,
        })
        .collect()
}

pub fn format_status() -> String {
    let list = snapshot();
    let mut out = format!("  Managed Services ({}):\n", list.len());
    for s in list {
        out.push_str(&format!(
            "    {:<14} state={:?} pid={:?} restarts={} policy={:?} auto={} dep={:?}\n",
            s.name, s.state, s.task_id, s.restarts, s.restart_policy, s.autostart, s.depends_on
        ));
    }
    out
}

fn watchdog_worker(_: usize) -> ! {
    loop {
        scheduler::sleep_ms(40);
        let _ = scheduler::reap_exited();
        let now = timer::uptime_ms();
        let mut to_restart: Vec<(String, &'static str)> = Vec::new();

        {
            let mut reg = SERVICES.lock();
            for s in reg.services.iter_mut() {
                if s.state != ServiceState::Running {
                    continue;
                }
                let mut fault_reason: Option<&'static str> = None;
                if let Some(pid) = s.task_id {
                    if scheduler::is_task_exited(pid) {
                        fault_reason = Some("task exited unexpectedly");
                    }
                }
                if fault_reason.is_none()
                    && s.watchdog_timeout_ms > 0
                    && now.saturating_sub(s.last_heartbeat_ms) > s.watchdog_timeout_ms
                {
                    fault_reason = Some("heartbeat timeout");
                }
                if let Some(reason) = fault_reason {
                    match s.restart_policy {
                        RestartPolicy::Always | RestartPolicy::OnFailure => {
                            to_restart.push((s.name.clone(), reason));
                        }
                        RestartPolicy::Never => {
                            s.state = ServiceState::Failed;
                            klog!(LogLevel::Warn, "watchdog", "Service '{}' failed ({})", s.name, reason);
                        }
                    }
                }
            }
        }

        for (name, reason) in to_restart {
            klog!(
                LogLevel::Warn,
                "watchdog",
                "Recovering service '{}' (reason: {})...",
                name,
                reason
            );
            let _ = restart_service(&name);
        }

        #[cfg(feature = "board-rpi4")]
        bcm2711_hw_watchdog::kick(0xF_FFFF);
    }
}

/// Raspberry Pi 4 (BCM2711) hardware PM Watchdog helper (NON TESTÉ SUR MATÉRIEL).
#[cfg(feature = "board-rpi4")]
pub mod bcm2711_hw_watchdog {
    const BCM2711_PM_BASE: usize = 0xFE10_0000;
    const PM_RSTC: usize = 0x1C;
    const PM_WDOG: usize = 0x24;
    const PM_PASSWORD: u32 = 0x5A00_0000;

    pub fn kick(timeout_ticks: u32) {
        if !crate::arch::mmu::is_pm_wdog_mapped() {
            return;
        }
        unsafe {
            core::ptr::write_volatile(
                (BCM2711_PM_BASE + PM_WDOG) as *mut u32,
                PM_PASSWORD | (timeout_ticks & 0x000F_FFFF),
            );
            let cur = core::ptr::read_volatile((BCM2711_PM_BASE + PM_RSTC) as *const u32);
            core::ptr::write_volatile(
                (BCM2711_PM_BASE + PM_RSTC) as *mut u32,
                PM_PASSWORD | (cur & !0x30) | 0x20,
            );
        }
    }

    pub fn trigger_immediate_reset() -> ! {
        if crate::arch::mmu::is_pm_wdog_mapped() {
            kick(10);
        }
        crate::arch::halt_forever()
    }
}
