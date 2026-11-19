//! Kernel Heap Allocator (`GlobalAlloc`) with Coalescing Free-List.
//!
//! Backed by non-contiguous 4 KiB physical frames mapped virtually into a
//! contiguous kernel heap VA space (`0x0000_2000_0000_0000..`), enforcing the
//! kernel heap budget ceiling (64 MiB max).

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;

use crate::arch::mmu::{self, MemAttr};
use crate::klog;
use crate::log::LogLevel;
use crate::memory::phys::{self, PAGE_SIZE};
use crate::sync::SpinLock;

pub const KERNEL_HEAP_VA_BASE: u64 = 0x0000_2000_0000_0000;
pub const INITIAL_HEAP_PAGES: usize = 128; // 512 KiB initial heap
pub const MAX_HEAP_BYTES: usize = 64 * 1024 * 1024; // 64 MiB hard cap

#[repr(C)]
struct FreeBlock {
    size: usize,
    next: *mut FreeBlock,
}

#[repr(C)]
struct AllocHeader {
    block_start: usize,
    block_size: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct HeapStats {
    pub mapped_bytes: usize,
    pub free_bytes: usize,
    pub used_bytes: usize,
    pub active_allocs: usize,
}

struct LinkedListHeap {
    initialized: bool,
    mapped_end: usize,
    head: *mut FreeBlock,
    total_bytes: usize,
    free_bytes: usize,
    active_allocs: usize,
}

unsafe impl Send for LinkedListHeap {}

impl LinkedListHeap {
    const fn empty() -> Self {
        Self {
            initialized: false,
            mapped_end: KERNEL_HEAP_VA_BASE as usize,
            head: null_mut(),
            total_bytes: 0,
            free_bytes: 0,
            active_allocs: 0,
        }
    }

    #[inline]
    fn align_up(addr: usize, align: usize) -> usize {
        (addr + align - 1) & !(align - 1)
    }

    unsafe fn insert_free_block(&mut self, addr: usize, size: usize) {
        if size < core::mem::size_of::<FreeBlock>() {
            return;
        }
        let block = addr as *mut FreeBlock;
        (*block).size = size;
        (*block).next = null_mut();

        let mut prev: *mut FreeBlock = null_mut();
        let mut curr = self.head;
        while !curr.is_null() && (curr as usize) < addr {
            prev = curr;
            curr = (*curr).next;
        }

        // Insert between prev and curr
        (*block).next = curr;
        if prev.is_null() {
            self.head = block;
        } else {
            (*prev).next = block;
        }

        self.free_bytes += size;

        // Coalesce with next
        if !curr.is_null() && addr + size == (curr as usize) {
            (*block).size += (*curr).size;
            (*block).next = (*curr).next;
        }

        // Coalesce with prev
        if !prev.is_null() && (prev as usize) + (*prev).size == addr {
            (*prev).size += (*block).size;
            (*prev).next = (*block).next;
        }
    }

    unsafe fn grow(&mut self, min_bytes: usize) -> bool {
        let pages_needed = ((min_bytes + PAGE_SIZE - 1) / PAGE_SIZE).max(16);
        let add_bytes = pages_needed * PAGE_SIZE;
        if self.total_bytes + add_bytes > MAX_HEAP_BYTES {
            return false;
        }

        let region_start = self.mapped_end;
        let l0 = mmu::kernel_l0_paddr();
        let mut mapped_ok = 0usize;
        for i in 0..pages_needed {
            let va = (region_start + i * PAGE_SIZE) as u64;
            let Some(pa) = phys::alloc_frame() else {
                break;
            };
            if mmu::map_page_4k(l0, va, pa, MemAttr::NormalRw).is_err() {
                let _ = phys::free_frame(pa);
                break;
            }
            mapped_ok += PAGE_SIZE;
        }

        if mapped_ok == 0 {
            return false;
        }

        mmu::invalidate_tlb_all();
        self.mapped_end += mapped_ok;
        self.total_bytes += mapped_ok;
        self.insert_free_block(region_start, mapped_ok);
        true
    }

    unsafe fn alloc(&mut self, layout: Layout) -> *mut u8 {
        if !self.initialized {
            return null_mut();
        }
        let align = layout.align().max(core::mem::align_of::<AllocHeader>()).max(16);
        let req_size = layout.size().max(1);
        let header_size = core::mem::size_of::<AllocHeader>();

        for _attempt in 0..2 {
            let mut prev: *mut FreeBlock = null_mut();
            let mut curr = self.head;

            while !curr.is_null() {
                let block_addr = curr as usize;
                let block_size = (*curr).size;

                let payload_addr = Self::align_up(block_addr + header_size, align);
                let header_addr = payload_addr - header_size;
                let total_end = Self::align_up(payload_addr + req_size, 16);
                let needed_from_block = total_end - block_addr;

                if needed_from_block <= block_size {
                    // Remove curr from free list
                    let next = (*curr).next;
                    if prev.is_null() {
                        self.head = next;
                    } else {
                        (*prev).next = next;
                    }
                    self.free_bytes -= block_size;

                    // Return front slack if large enough
                    let front_slack = header_addr - block_addr;
                    if front_slack >= core::mem::size_of::<FreeBlock>() {
                        self.insert_free_block(block_addr, front_slack);
                    }

                    // Return tail slack if large enough
                    let alloc_start = if front_slack >= core::mem::size_of::<FreeBlock>() {
                        header_addr
                    } else {
                        block_addr
                    };
                    let alloc_size = total_end - alloc_start;
                    let tail_slack = (block_addr + block_size) - total_end;
                    let final_block_size = if tail_slack >= core::mem::size_of::<FreeBlock>() {
                        self.insert_free_block(total_end, tail_slack);
                        alloc_size
                    } else {
                        alloc_size + tail_slack
                    };

                    let hdr = header_addr as *mut AllocHeader;
                    (*hdr).block_start = alloc_start;
                    (*hdr).block_size = final_block_size;
                    self.active_allocs += 1;
                    return payload_addr as *mut u8;
                }

                prev = curr;
                curr = (*curr).next;
            }

            // Need more virtual/physical backing
            if !self.grow(req_size + align + header_size + PAGE_SIZE) {
                break;
            }
        }
        null_mut()
    }

    unsafe fn dealloc(&mut self, ptr: *mut u8) {
        if ptr.is_null() || !self.initialized {
            return;
        }
        let hdr = (ptr as usize - core::mem::size_of::<AllocHeader>()) as *const AllocHeader;
        let start = (*hdr).block_start;
        let size = (*hdr).block_size;
        self.active_allocs = self.active_allocs.saturating_sub(1);
        self.insert_free_block(start, size);
    }
}

pub struct KernelAllocator {
    inner: SpinLock<LinkedListHeap>,
}

impl KernelAllocator {
    pub const fn new() -> Self {
        Self {
            inner: SpinLock::new(LinkedListHeap::empty()),
        }
    }
}

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.inner.lock().alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        self.inner.lock().dealloc(ptr);
    }
}

#[global_allocator]
static KERNEL_HEAP: KernelAllocator = KernelAllocator::new();

/// Initialize kernel heap by mapping `INITIAL_HEAP_PAGES` into virtual memory.
pub fn init() -> Result<(), &'static str> {
    let l0 = mmu::kernel_l0_paddr();
    if l0 == 0 {
        return Err("Cannot initialize heap before MMU");
    }

    let initial_bytes = INITIAL_HEAP_PAGES * PAGE_SIZE;
    for i in 0..INITIAL_HEAP_PAGES {
        let va = KERNEL_HEAP_VA_BASE + (i * PAGE_SIZE) as u64;
        let pa = phys::alloc_frame().ok_or("Out of physical memory during heap init")?;
        mmu::map_page_4k(l0, va, pa, MemAttr::NormalRw)?;
    }
    mmu::invalidate_tlb_all();

    {
        let mut guard = KERNEL_HEAP.inner.lock();
        guard.initialized = true;
        guard.mapped_end = KERNEL_HEAP_VA_BASE as usize + initial_bytes;
        guard.total_bytes = initial_bytes;
        unsafe {
            guard.insert_free_block(KERNEL_HEAP_VA_BASE as usize, initial_bytes);
        }
    }

    klog!(
        LogLevel::Info,
        "heap",
        "Kernel heap initialized: VA={:#x}, initial={} KiB, max={} MiB",
        KERNEL_HEAP_VA_BASE,
        initial_bytes / 1024,
        MAX_HEAP_BYTES / (1024 * 1024)
    );

    Ok(())
}

pub fn stats() -> HeapStats {
    let guard = KERNEL_HEAP.inner.lock();
    HeapStats {
        mapped_bytes: guard.total_bytes,
        free_bytes: guard.free_bytes,
        used_bytes: guard.total_bytes.saturating_sub(guard.free_bytes),
        active_allocs: guard.active_allocs,
    }
}
