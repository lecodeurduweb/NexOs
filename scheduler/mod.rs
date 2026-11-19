//! Preemptive Priority-Based SMP Kernel & User Task Scheduler (Cortex-A72 4-Core).
//!
//! - Uses unified `TrapFrame` switching via `vectors.S` (`rust_exception_handler`
//!   returns the `sp` of the task to resume, followed by `sched_post_switch` once
//!   `sp` has left the outgoing task's kernel stack).
//! - Priority levels `0..=255` (`0` = Per-CPU Idle, `128` = Normal, `192` = High, `240` = Critical).
//! - Round-robin quantum preemption among runnable tasks eligible by `affinity_mask`.
//! - Supports `sleep_ms`, `block_current`/`wake_task`, `join_task`, CPU affinity,
//!   voluntary yield (`svc #1`), SGI #0 IPI wakeup across cores, and per-task `ttbr0_paddr`.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::arch::exceptions::TrapFrame;
use crate::arch::mmu;
use crate::arch::smp;
use crate::arch::timer::{self, TICK_HZ};
use crate::drivers::dtb::MAX_CPUS;
use crate::drivers::gicv2;
use crate::klog;
use crate::log::LogLevel;
use crate::sync::SpinLock;

const TASK_STACK_SIZE: usize = 64 * 1024; // 64 KiB per task kernel stack
const DEFAULT_QUANTUM_TICKS: u64 = 2; // 20 ms time slice at 100 Hz

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskState {
    Ready,
    Running,
    Sleeping,
    Blocked,
    Transitioning,
    Exited,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskInfo {
    pub id: u64,
    pub parent_id: u64,
    pub name: [u8; 24],
    pub name_len: usize,
    pub priority: u8,
    pub state: TaskState,
    pub ticks_run: u64,
    pub switches: u64,
    pub is_user: bool,
    pub last_cpu: u8,
    pub affinity_mask: u8,
}

impl TaskInfo {
    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("?")
    }
}

struct Task {
    id: u64,
    parent_id: u64,
    name: String,
    priority: u8,
    state: TaskState,
    pending_state: TaskState,
    saved_tf: usize,
    _kstack: Option<Box<[u8]>>,
    ttbr0_paddr: u64,
    wake_tick: u64,
    ticks_run: u64,
    quantum_left: u64,
    switches: u64,
    is_user: bool,
    owns_l0: bool,
    affinity_mask: u8,
    running_on_cpu: Option<usize>,
    last_cpu: u8,
    exit_code: i64,
}

struct SchedulerState {
    initialized: bool,
    tasks: Vec<Task>,
    current_idx: [Option<usize>; MAX_CPUS],
    idle_idx: [Option<usize>; MAX_CPUS],
    next_id: u64,
    total_switches: u64,
}

impl SchedulerState {
    const fn empty() -> Self {
        Self {
            initialized: false,
            tasks: Vec::new(),
            current_idx: [None; MAX_CPUS],
            idle_idx: [None; MAX_CPUS],
            next_id: 1,
            total_switches: 0,
        }
    }
}

static SCHEDULER: SpinLock<SchedulerState> = SpinLock::new(SchedulerState::empty());
static SCHED_ACTIVE: AtomicBool = AtomicBool::new(false);
static NEED_RESCHED: [AtomicBool; MAX_CPUS] = [
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
];
static PENDING_RELEASE_ID: [AtomicU64; MAX_CPUS] = [
    AtomicU64::new(u64::MAX),
    AtomicU64::new(u64::MAX),
    AtomicU64::new(u64::MAX),
    AtomicU64::new(u64::MAX),
    AtomicU64::new(u64::MAX),
    AtomicU64::new(u64::MAX),
    AtomicU64::new(u64::MAX),
    AtomicU64::new(u64::MAX),
];
static IDLE_TICKS: AtomicU64 = AtomicU64::new(0);

extern "C" fn kernel_thread_exit_trampoline() -> ! {
    exit_current();
}

pub fn is_active() -> bool {
    SCHED_ACTIVE.load(Ordering::Acquire)
}

/// Initialize the SMP scheduler and register CPU 0's boot thread as its idle task (ID 0).
pub fn init() {
    let mut sched = SCHEDULER.lock();
    if sched.initialized {
        return;
    }
    sched.tasks.push(Task {
        id: 0,
        parent_id: 0,
        name: String::from("kernel-idle-0"),
        priority: 0,
        state: TaskState::Running,
        pending_state: TaskState::Running,
        saved_tf: 0,
        _kstack: None,
        ttbr0_paddr: mmu::kernel_l0_paddr(),
        wake_tick: 0,
        ticks_run: 0,
        quantum_left: DEFAULT_QUANTUM_TICKS,
        switches: 1,
        is_user: false,
        owns_l0: false,
        affinity_mask: 1 << 0,
        running_on_cpu: Some(0),
        last_cpu: 0,
        exit_code: 0,
    });
    sched.current_idx[0] = Some(0);
    sched.idle_idx[0] = Some(0);
    sched.initialized = true;
    SCHED_ACTIVE.store(true, Ordering::Release);
    klog!(
        LogLevel::Info,
        "sched",
        "Preemptive SMP priority scheduler initialized (quantum={} ticks / {} ms)",
        DEFAULT_QUANTUM_TICKS,
        (DEFAULT_QUANTUM_TICKS * 1000) / TICK_HZ
    );
}

/// Pre-allocate an idle task slot for secondary CPU `cpu_idx` before it boots.
pub fn prepare_cpu_idle(cpu_idx: usize) {
    if cpu_idx == 0 || cpu_idx >= MAX_CPUS {
        return;
    }
    let mut sched = SCHEDULER.lock();
    if !sched.initialized || sched.idle_idx[cpu_idx].is_some() {
        return;
    }
    let id = sched.next_id;
    sched.next_id += 1;
    let idx = sched.tasks.len();
    sched.tasks.push(Task {
        id,
        parent_id: 0,
        name: alloc::format!("kernel-idle-{}", cpu_idx),
        priority: 0,
        state: TaskState::Running,
        pending_state: TaskState::Running,
        saved_tf: 0,
        _kstack: None, // Uses SECONDARY_BOOT_STACKS[cpu_idx]
        ttbr0_paddr: mmu::kernel_l0_paddr(),
        wake_tick: 0,
        ticks_run: 0,
        quantum_left: DEFAULT_QUANTUM_TICKS,
        switches: 1,
        is_user: false,
        owns_l0: false,
        affinity_mask: 1u8 << cpu_idx,
        running_on_cpu: Some(cpu_idx),
        last_cpu: cpu_idx as u8,
        exit_code: 0,
    });
    sched.idle_idx[cpu_idx] = Some(idx);
    sched.current_idx[cpu_idx] = Some(idx);
}

/// Called on secondary CPU `cpu_idx` when it finishes arch bringup.
pub fn secondary_init(cpu_idx: usize) {
    if cpu_idx < MAX_CPUS {
        NEED_RESCHED[cpu_idx].store(true, Ordering::Release);
    }
}

fn compute_kick_mask_locked(sched: &SchedulerState, affinity_mask: u8, my_cpu: usize) -> u8 {
    let online = smp::online_mask();
    let mut mask = 0u8;
    for c in 0..MAX_CPUS {
        let bit = 1u8 << c;
        if c != my_cpu && (online & bit) != 0 && (affinity_mask & bit) != 0 {
            if sched.current_idx[c] == sched.idle_idx[c] {
                mask |= bit;
                NEED_RESCHED[c].store(true, Ordering::Release);
            }
        }
    }
    mask
}

/// Spawn a new EL1 kernel thread on any CPU matching `affinity_mask`.
pub fn spawn_kernel_on(
    name: &str,
    priority: u8,
    affinity_mask: u8,
    entry: fn(usize) -> !,
    arg: usize,
) -> u64 {
    let mut kstack = alloc::vec![0u8; TASK_STACK_SIZE].into_boxed_slice();
    let stack_top = (kstack.as_mut_ptr() as usize + TASK_STACK_SIZE) & !0xF;
    let tf_addr = stack_top - core::mem::size_of::<TrapFrame>();

    unsafe {
        let tf = &mut *(tf_addr as *mut TrapFrame);
        *tf = core::mem::zeroed();
        tf.x[0] = arg as u64;
        tf.x[30] = kernel_thread_exit_trampoline as *const () as usize as u64;
        tf.elr_el1 = entry as *const () as usize as u64;
        tf.spsr_el1 = 0x05; // EL1h, IRQs enabled
    }

    let my_cpu = smp::cpu_id();
    let eff_affinity = if affinity_mask == 0 { 0xFF } else { affinity_mask };
    let (id, kick_mask) = {
        let mut sched = SCHEDULER.lock();
        let parent_id = sched.current_idx[my_cpu]
            .and_then(|i| sched.tasks.get(i))
            .map(|t| t.id)
            .unwrap_or(0);
        let id = sched.next_id;
        sched.next_id += 1;
        sched.tasks.push(Task {
            id,
            parent_id,
            name: String::from(name),
            priority: priority.max(1),
            state: TaskState::Ready,
            pending_state: TaskState::Ready,
            saved_tf: tf_addr,
            _kstack: Some(kstack),
            ttbr0_paddr: mmu::kernel_l0_paddr(),
            wake_tick: 0,
            ticks_run: 0,
            quantum_left: DEFAULT_QUANTUM_TICKS,
            switches: 0,
            is_user: false,
            owns_l0: false,
            affinity_mask: eff_affinity,
            running_on_cpu: None,
            last_cpu: my_cpu as u8,
            exit_code: 0,
        });
        NEED_RESCHED[my_cpu].store(true, Ordering::Release);
        let km = compute_kick_mask_locked(&sched, eff_affinity, my_cpu);
        (id, km)
    };
    if kick_mask != 0 {
        gicv2::send_sgi(gicv2::SGI_RESCHED_IRQ, kick_mask);
    }
    id
}

/// Spawn a new EL1 kernel thread eligible on any online CPU.
pub fn spawn_kernel(name: &str, priority: u8, entry: fn(usize) -> !, arg: usize) -> u64 {
    spawn_kernel_on(name, priority, 0xFF, entry, arg)
}

/// Spawn an EL0 user task with dedicated page table `ttbr0_paddr`, user entry PC, and user SP.
pub fn spawn_user(
    name: &str,
    priority: u8,
    ttbr0_paddr: u64,
    user_entry: u64,
    user_sp: u64,
    arg0: u64,
) -> u64 {
    spawn_user_inner(name, priority, ttbr0_paddr, true, user_entry, user_sp, arg0)
}

/// Spawn an EL0 user thread sharing an existing `ttbr0_paddr` address space (`owns_l0 = false`).
pub fn spawn_user_thread(
    name: &str,
    priority: u8,
    ttbr0_paddr: u64,
    user_entry: u64,
    user_sp: u64,
    arg0: u64,
) -> u64 {
    spawn_user_inner(name, priority, ttbr0_paddr, false, user_entry, user_sp, arg0)
}

fn spawn_user_inner(
    name: &str,
    priority: u8,
    ttbr0_paddr: u64,
    owns_l0: bool,
    user_entry: u64,
    user_sp: u64,
    arg0: u64,
) -> u64 {
    let mut kstack = alloc::vec![0u8; TASK_STACK_SIZE].into_boxed_slice();
    let stack_top = (kstack.as_mut_ptr() as usize + TASK_STACK_SIZE) & !0xF;
    let tf_addr = stack_top - core::mem::size_of::<TrapFrame>();

    unsafe {
        let tf = &mut *(tf_addr as *mut TrapFrame);
        *tf = core::mem::zeroed();
        tf.x[0] = arg0;
        tf.sp_el0 = user_sp;
        tf.elr_el1 = user_entry;
        tf.spsr_el1 = 0x0; // EL0t, IRQs enabled
    }

    let my_cpu = smp::cpu_id();
    let (id, kick_mask) = {
        let mut sched = SCHEDULER.lock();
        let parent_id = sched.current_idx[my_cpu]
            .and_then(|i| sched.tasks.get(i))
            .map(|t| t.id)
            .unwrap_or(0);
        let id = sched.next_id;
        sched.next_id += 1;
        sched.tasks.push(Task {
            id,
            parent_id,
            name: String::from(name),
            priority: priority.max(1),
            state: TaskState::Ready,
            pending_state: TaskState::Ready,
            saved_tf: tf_addr,
            _kstack: Some(kstack),
            ttbr0_paddr,
            wake_tick: 0,
            ticks_run: 0,
            quantum_left: DEFAULT_QUANTUM_TICKS,
            switches: 0,
            is_user: true,
            owns_l0,
            affinity_mask: 0xFF,
            running_on_cpu: None,
            last_cpu: my_cpu as u8,
            exit_code: 0,
        });
        NEED_RESCHED[my_cpu].store(true, Ordering::Release);
        let km = compute_kick_mask_locked(&sched, 0xFF, my_cpu);
        (id, km)
    };
    if kick_mask != 0 {
        gicv2::send_sgi(gicv2::SGI_RESCHED_IRQ, kick_mask);
    }
    id
}

/// Voluntary yield from EL1 using synchronous `svc #1`.
#[inline]
pub fn yield_now() {
    if SCHED_ACTIVE.load(Ordering::Acquire) {
        unsafe {
            asm!("svc #1", options(nostack));
        }
    }
}

/// Prepare current task to enter `Blocked` state on next yield (called before WaitQueue check).
pub fn prepare_block() {
    let cpu = smp::cpu_id();
    let mut sched = SCHEDULER.lock();
    if let Some(idx) = sched.current_idx[cpu] {
        if sched.idle_idx[cpu] != Some(idx) && idx < sched.tasks.len() {
            sched.tasks[idx].pending_state = TaskState::Blocked;
        }
    }
}

/// Cancel a pending block before calling `yield_now()`.
pub fn cancel_block() {
    let cpu = smp::cpu_id();
    let mut sched = SCHEDULER.lock();
    if let Some(idx) = sched.current_idx[cpu] {
        if idx < sched.tasks.len() {
            sched.tasks[idx].pending_state = TaskState::Running;
        }
    }
}

/// Wake a blocked or sleeping task by ID (safe even if task is currently `Transitioning`).
pub fn wake_task(id: u64) {
    let my_cpu = smp::cpu_id();
    let kick_mask = {
        let mut sched = SCHEDULER.lock();
        let mut aff = 0u8;
        if let Some(t) = sched.tasks.iter_mut().find(|t| t.id == id) {
            if t.state != TaskState::Exited {
                t.pending_state = TaskState::Ready;
                if t.state == TaskState::Blocked || t.state == TaskState::Sleeping {
                    t.state = TaskState::Ready;
                    aff = t.affinity_mask;
                }
            }
        }
        if aff != 0 {
            NEED_RESCHED[my_cpu].store(true, Ordering::Release);
            compute_kick_mask_locked(&sched, aff, my_cpu)
        } else {
            0
        }
    };
    if kick_mask != 0 {
        gicv2::send_sgi(gicv2::SGI_RESCHED_IRQ, kick_mask);
    }
}

/// Put current kernel task to sleep for at least `ms` milliseconds.
pub fn sleep_ms(ms: u64) {
    let ticks_to_wait = ((ms * TICK_HZ) + 999) / 1000;
    let wake = timer::ticks() + ticks_to_wait.max(1);
    let cpu = smp::cpu_id();
    let is_idle = {
        let mut sched = SCHEDULER.lock();
        match sched.current_idx[cpu] {
            None => true,
            Some(idx) if sched.idle_idx[cpu] == Some(idx) => true,
            Some(idx) => {
                if idx < sched.tasks.len() {
                    sched.tasks[idx].pending_state = TaskState::Sleeping;
                    sched.tasks[idx].wake_tick = wake;
                }
                false
            }
        }
    };
    if is_idle {
        while timer::ticks() < wake {
            crate::arch::wfi();
        }
    } else {
        yield_now();
    }
}

/// Terminate the current task with optional exit code and switch away.
pub fn exit_current_with_code(code: i64) -> ! {
    let cpu = smp::cpu_id();
    {
        let mut sched = SCHEDULER.lock();
        if let Some(idx) = sched.current_idx[cpu] {
            if sched.idle_idx[cpu] != Some(idx) && idx < sched.tasks.len() {
                sched.tasks[idx].pending_state = TaskState::Exited;
                sched.tasks[idx].exit_code = code;
            }
        }
    }
    yield_now();
    loop {
        crate::arch::wfi();
    }
}

/// Terminate the current task and switch to another runnable task.
pub fn exit_current() -> ! {
    exit_current_with_code(0)
}

/// Called from timer IRQ handler on every CPU tick.
pub fn on_timer_tick() {
    on_timer_tick_cpu(smp::cpu_id());
}

pub fn on_timer_tick_cpu(cpu: usize) {
    if !SCHED_ACTIVE.load(Ordering::Acquire) || cpu >= MAX_CPUS {
        return;
    }
    let now = timer::ticks();
    let kick_mask = {
        let mut sched = SCHEDULER.lock();
        if !sched.initialized {
            return;
        }
        let cur_idx = match sched.current_idx[cpu] {
            Some(i) => i,
            None => return,
        };
        let cur_is_idle = sched.idle_idx[cpu] == Some(cur_idx);
        let cur_prio = sched.tasks[cur_idx].priority;

        let mut higher_woke = false;
        let mut woken_aff = 0u8;
        for t in sched.tasks.iter_mut() {
            if t.state == TaskState::Sleeping && now >= t.wake_tick {
                t.state = TaskState::Ready;
                t.pending_state = TaskState::Ready;
                woken_aff |= t.affinity_mask;
                if t.priority > cur_prio {
                    higher_woke = true;
                }
            }
        }

        if cur_is_idle {
            IDLE_TICKS.fetch_add(1, Ordering::Relaxed);
        }

        sched.tasks[cur_idx].ticks_run += 1;
        if sched.tasks[cur_idx].quantum_left > 0 {
            sched.tasks[cur_idx].quantum_left -= 1;
        }

        if higher_woke || sched.tasks[cur_idx].quantum_left == 0 || cur_is_idle {
            NEED_RESCHED[cpu].store(true, Ordering::Release);
        }

        if woken_aff != 0 {
            compute_kick_mask_locked(&sched, woken_aff, cpu)
        } else {
            0
        }
    };
    if kick_mask != 0 {
        gicv2::send_sgi(gicv2::SGI_RESCHED_IRQ, kick_mask);
    }
}

/// Select next runnable task eligible on `cpu` and return the `TrapFrame` pointer to restore.
pub fn schedule_from_trap(current_tf: usize, force_switch: bool) -> usize {
    if !SCHED_ACTIVE.load(Ordering::Acquire) {
        return current_tf;
    }
    let cpu = smp::cpu_id();
    if cpu >= MAX_CPUS {
        return current_tf;
    }
    if !force_switch && !NEED_RESCHED[cpu].load(Ordering::Acquire) {
        return current_tf;
    }

    let mut sched = SCHEDULER.lock();
    if !sched.initialized || sched.tasks.is_empty() {
        return current_tf;
    }

    let cur_idx = match sched.current_idx[cpu] {
        Some(i) if i < sched.tasks.len() => i,
        _ => return current_tf,
    };
    let cpu_bit = 1u8 << cpu;
    let cur_is_idle = sched.idle_idx[cpu] == Some(cur_idx);

    sched.tasks[cur_idx].saved_tf = current_tf;
    if sched.tasks[cur_idx].pending_state == TaskState::Running {
        sched.tasks[cur_idx].pending_state = TaskState::Ready;
    }
    let desired_cur_next = sched.tasks[cur_idx].pending_state;

    // Can `cur_idx` remain on this CPU if nothing higher is ready?
    let cur_can_continue = desired_cur_next == TaskState::Ready
        && !cur_is_idle
        && (sched.tasks[cur_idx].affinity_mask & cpu_bit) != 0;

    // Find highest priority among Ready tasks eligible for `cpu`
    let mut best_prio: u8 = 0;
    let mut any_ready = false;
    for (idx, t) in sched.tasks.iter().enumerate() {
        if idx == cur_idx {
            continue;
        }
        if t.priority == 0 {
            continue; // Idle tasks are strictly per-CPU fallback only
        }
        if t.state == TaskState::Ready && (t.affinity_mask & cpu_bit) != 0 {
            if !any_ready || t.priority > best_prio {
                best_prio = t.priority;
                any_ready = true;
            }
        }
    }

    if cur_can_continue && (!any_ready || sched.tasks[cur_idx].priority > best_prio) {
        sched.tasks[cur_idx].state = TaskState::Running;
        sched.tasks[cur_idx].pending_state = TaskState::Running;
        sched.tasks[cur_idx].quantum_left = DEFAULT_QUANTUM_TICKS;
        NEED_RESCHED[cpu].store(false, Ordering::Release);
        return current_tf;
    }

    // Round-robin pick among eligible Ready tasks with `best_prio` (or `cur_idx` if tied)
    let len = sched.tasks.len();
    let mut next_idx = sched.idle_idx[cpu].unwrap_or(0);

    if any_ready && (!cur_can_continue || best_prio >= sched.tasks[cur_idx].priority) {
        for offset in 1..=len {
            let cand = (cur_idx + offset) % len;
            let t = &sched.tasks[cand];
            if cand != cur_idx
                && t.priority == best_prio
                && t.state == TaskState::Ready
                && (t.affinity_mask & cpu_bit) != 0
            {
                next_idx = cand;
                break;
            }
        }
    } else if cur_can_continue {
        next_idx = cur_idx;
    }

    if next_idx == cur_idx {
        sched.tasks[cur_idx].state = TaskState::Running;
        sched.tasks[cur_idx].pending_state = TaskState::Running;
        sched.tasks[cur_idx].quantum_left = DEFAULT_QUANTUM_TICKS;
        NEED_RESCHED[cpu].store(false, Ordering::Release);
        return current_tf;
    }

    // Defer making `cur_idx` Ready/Sleeping/Blocked/Exited until `sched_post_switch`
    // after `vectors.S` moves `sp` onto `next_idx`'s kernel stack.
    let cur_id = sched.tasks[cur_idx].id;
    sched.tasks[cur_idx].state = TaskState::Transitioning;
    PENDING_RELEASE_ID[cpu].store(cur_id, Ordering::Release);

    let prev_ttbr0 = sched.tasks[cur_idx].ttbr0_paddr;
    let next_ttbr0 = sched.tasks[next_idx].ttbr0_paddr;
    sched.tasks[next_idx].state = TaskState::Running;
    sched.tasks[next_idx].pending_state = TaskState::Running;
    sched.tasks[next_idx].running_on_cpu = Some(cpu);
    sched.tasks[next_idx].last_cpu = cpu as u8;
    sched.tasks[next_idx].quantum_left = DEFAULT_QUANTUM_TICKS;
    sched.tasks[next_idx].switches += 1;
    sched.total_switches += 1;
    sched.current_idx[cpu] = Some(next_idx);
    NEED_RESCHED[cpu].store(false, Ordering::Release);

    let next_tf = sched.tasks[next_idx].saved_tf;
    if next_ttbr0 != 0 && next_ttbr0 != prev_ttbr0 {
        unsafe {
            asm!(
                "msr TTBR0_EL1, {ttbr}",
                "tlbi vmalle1",
                "dsb sy",
                "isb",
                ttbr = in(reg) next_ttbr0,
                options(nostack)
            );
        }
    }
    next_tf
}

/// Finalize the outgoing task's state transition once `vectors.S` has switched `SP`
/// to the incoming task's kernel stack.
#[no_mangle]
pub extern "C" fn sched_post_switch() {
    let cpu = smp::cpu_id();
    if cpu >= MAX_CPUS {
        return;
    }
    let rel_id = PENDING_RELEASE_ID[cpu].swap(u64::MAX, Ordering::AcqRel);
    if rel_id == u64::MAX {
        return;
    }
    let mut sched = SCHEDULER.lock();
    if let Some(t) = sched.tasks.iter_mut().find(|t| t.id == rel_id) {
        if t.state == TaskState::Transitioning {
            let final_state = match t.pending_state {
                TaskState::Sleeping | TaskState::Blocked | TaskState::Exited => t.pending_state,
                _ => TaskState::Ready,
            };
            t.state = final_state;
            t.pending_state = final_state;
            t.running_on_cpu = None;
        }
    }
}

/// Reclaim `_kstack` and private EL0 page tables of exited tasks that are no longer running on any CPU.
pub fn reap_exited() -> usize {
    let mut to_drop: Vec<Task> = Vec::new();
    {
        let mut sched = SCHEDULER.lock();
        if !sched.initialized {
            return 0;
        }
        let mut i = 1usize;
        while i < sched.tasks.len() {
            let t = &sched.tasks[i];
            let is_any_idle = t.priority == 0;
            let is_active_anywhere = sched.current_idx.iter().any(|&c| c == Some(i));
            if !is_any_idle
                && !is_active_anywhere
                && t.state == TaskState::Exited
                && t.running_on_cpu.is_none()
            {
                let old_last = sched.tasks.len() - 1;
                let removed = sched.tasks.swap_remove(i);
                if old_last != i {
                    for slot in sched.current_idx.iter_mut() {
                        if *slot == Some(old_last) {
                            *slot = Some(i);
                        }
                    }
                    for slot in sched.idle_idx.iter_mut() {
                        if *slot == Some(old_last) {
                            *slot = Some(i);
                        }
                    }
                }
                to_drop.push(removed);
            } else {
                i += 1;
            }
        }
    }
    let count = to_drop.len();
    for task in to_drop {
        if task.is_user && task.owns_l0 && task.ttbr0_paddr != 0 {
            mmu::free_user_l0(task.ttbr0_paddr);
        }
        drop(task);
    }
    if count > 0 {
        mmu::invalidate_tlb_all();
    }
    count
}

pub fn current_task_id() -> u64 {
    let cpu = smp::cpu_id();
    let sched = SCHEDULER.lock();
    if !sched.initialized {
        return 0;
    }
    sched.current_idx[cpu]
        .and_then(|i| sched.tasks.get(i))
        .map(|t| t.id)
        .unwrap_or(0)
}

pub fn current_ttbr0() -> u64 {
    let cpu = smp::cpu_id();
    let sched = SCHEDULER.lock();
    sched.current_idx[cpu]
        .and_then(|i| sched.tasks.get(i))
        .map(|t| t.ttbr0_paddr)
        .unwrap_or_else(mmu::kernel_l0_paddr)
}

pub fn mark_current_exited() {
    let cpu = smp::cpu_id();
    let mut sched = SCHEDULER.lock();
    if let Some(idx) = sched.current_idx[cpu] {
        if sched.idle_idx[cpu] != Some(idx) && idx < sched.tasks.len() {
            sched.tasks[idx].pending_state = TaskState::Exited;
        }
    }
}

pub fn prepare_current_sleep_ms(ms: u64) {
    let ticks_to_wait = ((ms * TICK_HZ) + 999) / 1000;
    let wake = timer::ticks() + ticks_to_wait.max(1);
    let cpu = smp::cpu_id();
    let mut sched = SCHEDULER.lock();
    if let Some(idx) = sched.current_idx[cpu] {
        if sched.idle_idx[cpu] != Some(idx) && idx < sched.tasks.len() {
            sched.tasks[idx].pending_state = TaskState::Sleeping;
            sched.tasks[idx].wake_tick = wake;
        }
    }
}

pub fn is_task_exited(id: u64) -> bool {
    let sched = SCHEDULER.lock();
    sched
        .tasks
        .iter()
        .find(|t| t.id == id)
        .map(|t| t.state == TaskState::Exited)
        .unwrap_or(true)
}

pub fn join_task(id: u64, timeout_ms: u64) -> Option<i64> {
    if timeout_ms == 0 {
        let sched = SCHEDULER.lock();
        return match sched.tasks.iter().find(|t| t.id == id) {
            Some(t) if t.state == TaskState::Exited => Some(t.exit_code),
            None => Some(0),
            _ => None,
        };
    }
    let deadline = timer::uptime_ms() + timeout_ms;
    loop {
        {
            let sched = SCHEDULER.lock();
            match sched.tasks.iter().find(|t| t.id == id) {
                Some(t) if t.state == TaskState::Exited => return Some(t.exit_code),
                None => return Some(0),
                _ => {}
            }
        }
        if timeout_ms > 0 && timer::uptime_ms() >= deadline {
            return None;
        }
        sleep_ms(10);
    }
}

pub fn kill_task(id: u64) -> bool {
    if id == 0 {
        return false;
    }
    let my_cpu = smp::cpu_id();
    let mut sched = SCHEDULER.lock();
    if let Some(t) = sched.tasks.iter_mut().find(|t| t.id == id) {
        if t.priority == 0 {
            return false; // Never kill per-CPU idle tasks
        }
        t.pending_state = TaskState::Exited;
        if t.state != TaskState::Running && t.state != TaskState::Transitioning {
            t.state = TaskState::Exited;
        }
        NEED_RESCHED[my_cpu].store(true, Ordering::Release);
        true
    } else {
        false
    }
}

pub fn total_switches() -> u64 {
    SCHEDULER.lock().total_switches
}

pub fn snapshot() -> Vec<TaskInfo> {
    let sched = SCHEDULER.lock();
    let mut out = Vec::with_capacity(sched.tasks.len());
    for t in sched.tasks.iter() {
        let mut buf = [0u8; 24];
        let nb = t.name.as_bytes();
        let n = nb.len().min(24);
        buf[..n].copy_from_slice(&nb[..n]);
        out.push(TaskInfo {
            id: t.id,
            parent_id: t.parent_id,
            name: buf,
            name_len: n,
            priority: t.priority,
            state: t.state,
            ticks_run: t.ticks_run,
            switches: t.switches,
            is_user: t.is_user,
            last_cpu: t.last_cpu,
            affinity_mask: t.affinity_mask,
        });
    }
    out
}
