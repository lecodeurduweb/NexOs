//! Synchronization primitives for NexOS SMP (ARM64).
//!
//! - `SpinLock<T>`: IRQ-masking SMP spinlock (safe in interrupt & scheduler contexts).
//! - `WaitQueue`: Task blocking queue integrated with the SMP scheduler (`no lost wakeups`).
//! - `Mutex<T>`: Sleeping mutex for longer critical sections (VFS, network, AI buffers).
//! - `Semaphore`: Counting semaphore built on `SpinLock` + `WaitQueue`.

use alloc::collections::VecDeque;
use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

pub struct SpinLock<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for SpinLock<T> {}
unsafe impl<T: Send> Send for SpinLock<T> {}

pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
    saved_daif: u64,
}

#[inline(always)]
fn save_and_disable_irq() -> u64 {
    let daif: u64;
    unsafe {
        core::arch::asm!(
            "mrs {}, DAIF",
            "msr DAIFSet, #2",
            out(reg) daif,
            options(nomem, nostack)
        );
    }
    daif
}

#[inline(always)]
fn restore_daif(daif: u64) {
    unsafe {
        core::arch::asm!(
            "msr DAIF, {}",
            in(reg) daif,
            options(nomem, nostack)
        );
    }
}

impl<T> SpinLock<T> {
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(value),
        }
    }

    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        let saved_daif = save_and_disable_irq();
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.locked.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
        SpinLockGuard {
            lock: self,
            saved_daif,
        }
    }

    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        let saved_daif = save_and_disable_irq();
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(SpinLockGuard {
                lock: self,
                saved_daif,
            })
        } else {
            restore_daif(saved_daif);
            None
        }
    }
}

impl<T> Deref for SpinLockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for SpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for SpinLockGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
        restore_daif(self.saved_daif);
    }
}

/// Queue of blocked task IDs waiting for an event.
pub struct WaitQueue {
    waiters: SpinLock<VecDeque<u64>>,
}

impl WaitQueue {
    pub const fn new() -> Self {
        Self {
            waiters: SpinLock::new(VecDeque::new()),
        }
    }

    /// Block current task until `cond()` becomes true (immune to lost wakeups).
    pub fn wait_until<F: FnMut() -> bool>(&self, mut cond: F) {
        loop {
            if cond() {
                return;
            }
            if !crate::scheduler::is_active() {
                core::hint::spin_loop();
                continue;
            }
            let tid = crate::scheduler::current_task_id();
            if tid == 0 {
                // Idle task cannot block; wait for IRQ/event
                crate::arch::wfi();
                continue;
            }
            {
                let mut q = self.waiters.lock();
                if !q.contains(&tid) {
                    q.push_back(tid);
                }
                crate::scheduler::prepare_block();
            }
            if cond() {
                crate::scheduler::cancel_block();
                let mut q = self.waiters.lock();
                q.retain(|&id| id != tid);
                return;
            }
            crate::scheduler::yield_now();
        }
    }

    pub fn wake_one(&self) -> bool {
        let tid = {
            let mut q = self.waiters.lock();
            q.pop_front()
        };
        if let Some(id) = tid {
            crate::scheduler::wake_task(id);
            true
        } else {
            false
        }
    }

    pub fn wake_all(&self) -> usize {
        let ids: alloc::vec::Vec<u64> = {
            let mut q = self.waiters.lock();
            q.drain(..).collect()
        };
        let n = ids.len();
        for id in ids {
            crate::scheduler::wake_task(id);
        }
        n
    }
}

/// Sleeping mutex that yields the CPU to other tasks when contended.
pub struct Mutex<T> {
    locked: AtomicBool,
    waitq: WaitQueue,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for Mutex<T> {}
unsafe impl<T: Send> Send for Mutex<T> {}

pub struct MutexGuard<'a, T> {
    mutex: &'a Mutex<T>,
}

impl<T> Mutex<T> {
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            waitq: WaitQueue::new(),
            data: UnsafeCell::new(value),
        }
    }

    pub fn lock(&self) -> MutexGuard<'_, T> {
        loop {
            if self
                .locked
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return MutexGuard { mutex: self };
            }
            self.waitq.wait_until(|| !self.locked.load(Ordering::Relaxed));
        }
    }

    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(MutexGuard { mutex: self })
        } else {
            None
        }
    }
}

impl<T> Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.mutex.data.get() }
    }
}

impl<T> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.mutex.data.get() }
    }
}

impl<T> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        self.mutex.locked.store(false, Ordering::Release);
        self.mutex.waitq.wake_one();
    }
}

/// Counting semaphore for bounding concurrent workers or signaling completion.
pub struct Semaphore {
    count: SpinLock<usize>,
    waitq: WaitQueue,
}

impl Semaphore {
    pub const fn new(initial: usize) -> Self {
        Self {
            count: SpinLock::new(initial),
            waitq: WaitQueue::new(),
        }
    }

    pub fn acquire(&self) {
        self.waitq.wait_until(|| {
            let mut c = self.count.lock();
            if *c > 0 {
                *c -= 1;
                true
            } else {
                false
            }
        });
    }

    pub fn release(&self) {
        {
            let mut c = self.count.lock();
            *c += 1;
        }
        self.waitq.wake_one();
    }

    pub fn available(&self) -> usize {
        *self.count.lock()
    }
}
