//! Physical Page Frame Allocator (4 KiB pages).
//!
//! - Detects architectural physical address width via `ID_AA64MMFR0_EL1.PARange`.
//! - Consumes RAM regions and reserved regions dynamically from the parsed DTB.
//! - Places its allocation bitmap dynamically inside free RAM (no static BSS bloat
//!   for 8 GiB systems: 8 GiB = 2,097,152 pages = 256 KiB bitmap).
//! - Enforces reserved regions (kernel image, DTB blob, VideoCore/firmware) and
//!   provides DMA-constrained allocation (`alloc_frame_below`) for BCM2711 30/32-bit DMA.

use core::ptr::write_bytes;
use core::slice;

use crate::arch;
use crate::drivers::dtb::DeviceTreeInfo;
use crate::klog;
use crate::log::LogLevel;
use crate::sync::SpinLock;

pub const PAGE_SIZE: usize = 4096;
pub const PAGE_SHIFT: usize = 12;

#[derive(Clone, Copy, Debug)]
pub struct PhysMemStats {
    pub pa_bits: u8,
    pub max_phys_addr: u64,
    pub total_frames: usize,
    pub free_frames: usize,
    pub used_frames: usize,
    pub dma32_free_frames: usize,
    pub bitmap_paddr: u64,
    pub bitmap_bytes: usize,
}

struct PhysAllocator {
    initialized: bool,
    pa_bits: u8,
    max_phys_addr: u64,
    bitmap_ptr: *mut u64,
    bitmap_words: usize,
    max_frame_index: usize,
    total_frames: usize,
    free_frames: usize,
}

unsafe impl Send for PhysAllocator {}

impl PhysAllocator {
    const fn empty() -> Self {
        Self {
            initialized: false,
            pa_bits: 40,
            max_phys_addr: 0,
            bitmap_ptr: core::ptr::null_mut(),
            bitmap_words: 0,
            max_frame_index: 0,
            total_frames: 0,
            free_frames: 0,
        }
    }

    #[inline]
    fn bitmap(&self) -> &[u64] {
        unsafe { slice::from_raw_parts(self.bitmap_ptr, self.bitmap_words) }
    }

    #[inline]
    fn bitmap_mut(&mut self) -> &mut [u64] {
        unsafe { slice::from_raw_parts_mut(self.bitmap_ptr, self.bitmap_words) }
    }

    #[inline]
    fn is_used(&self, frame: usize) -> bool {
        if frame >= self.max_frame_index {
            return true;
        }
        let word = frame / 64;
        let bit = frame % 64;
        (self.bitmap()[word] & (1u64 << bit)) != 0
    }

    #[inline]
    fn mark_used(&mut self, frame: usize) {
        if frame < self.max_frame_index {
            let word = frame / 64;
            let bit = frame % 64;
            let mask = 1u64 << bit;
            let bm = self.bitmap_mut();
            if (bm[word] & mask) == 0 {
                bm[word] |= mask;
                self.free_frames = self.free_frames.saturating_sub(1);
            }
        }
    }

    #[inline]
    fn mark_free(&mut self, frame: usize) {
        if frame < self.max_frame_index {
            let word = frame / 64;
            let bit = frame % 64;
            let mask = 1u64 << bit;
            let bm = self.bitmap_mut();
            if (bm[word] & mask) != 0 {
                bm[word] &= !mask;
                self.free_frames += 1;
            }
        }
    }

    fn mark_range_used(&mut self, start: u64, size: u64) {
        if size == 0 {
            return;
        }
        let first = (start as usize) / PAGE_SIZE;
        let end_addr = start.saturating_add(size).min(self.max_phys_addr);
        let last = ((end_addr as usize).saturating_add(PAGE_SIZE - 1)) / PAGE_SIZE;
        for f in first..last.min(self.max_frame_index) {
            self.mark_used(f);
        }
    }

    fn mark_range_free(&mut self, start: u64, size: u64) {
        if size == 0 {
            return;
        }
        let aligned_start = (start + (PAGE_SIZE as u64 - 1)) & !(PAGE_SIZE as u64 - 1);
        let end_addr = start.saturating_add(size).min(self.max_phys_addr) & !(PAGE_SIZE as u64 - 1);
        if end_addr <= aligned_start {
            return;
        }
        let first = (aligned_start as usize) / PAGE_SIZE;
        let last = (end_addr as usize) / PAGE_SIZE;
        for f in first..last.min(self.max_frame_index) {
            if self.is_used(f) {
                self.mark_free(f);
                self.total_frames += 1;
            }
        }
    }

    fn alloc_frame_below(&mut self, max_addr: u64) -> Option<u64> {
        if !self.initialized || self.free_frames == 0 {
            return None;
        }
        let limit_frame = ((max_addr.min(self.max_phys_addr)) as usize / PAGE_SIZE)
            .min(self.max_frame_index);
        let max_word = (limit_frame + 63) / 64;

        for w in 0..max_word.min(self.bitmap_words) {
            let word_val = self.bitmap()[w];
            if word_val != u64::MAX {
                let tz = (!word_val).trailing_zeros() as usize;
                let frame = w * 64 + tz;
                if frame < limit_frame {
                    self.mark_used(frame);
                    let paddr = (frame * PAGE_SIZE) as u64;
                    unsafe {
                        write_bytes(paddr as *mut u8, 0, PAGE_SIZE);
                    }
                    return Some(paddr);
                }
            }
        }
        None
    }

    fn alloc_contiguous_frames(&mut self, count: usize) -> Option<u64> {
        if !self.initialized || count == 0 || self.free_frames < count {
            return None;
        }
        let mut run = 0usize;
        let mut start = 0usize;
        for f in 1..self.max_frame_index {
            if !self.is_used(f) {
                if run == 0 {
                    start = f;
                }
                run += 1;
                if run == count {
                    for k in start..start + count {
                        self.mark_used(k);
                        let paddr = (k * PAGE_SIZE) as u64;
                        unsafe {
                            write_bytes(paddr as *mut u8, 0, PAGE_SIZE);
                        }
                    }
                    return Some((start * PAGE_SIZE) as u64);
                }
            } else {
                run = 0;
            }
        }
        None
    }

    fn free_frame(&mut self, paddr: u64) -> Result<(), &'static str> {
        if (paddr & (PAGE_SIZE as u64 - 1)) != 0 {
            return Err("free_frame: unaligned physical address");
        }
        let frame = (paddr as usize) / PAGE_SIZE;
        if frame >= self.max_frame_index {
            return Err("free_frame: physical address out of range");
        }
        if !self.is_used(frame) {
            return Err("free_frame: double free detected");
        }
        self.mark_free(frame);
        Ok(())
    }

    fn count_free_below(&self, max_addr: u64) -> usize {
        if !self.initialized {
            return 0;
        }
        let limit_frame = ((max_addr.min(self.max_phys_addr)) as usize / PAGE_SIZE)
            .min(self.max_frame_index);
        let mut count = 0usize;
        let full_words = limit_frame / 64;
        let bm = self.bitmap();
        for &w in bm.iter().take(full_words.min(self.bitmap_words)) {
            count += (!w).count_ones() as usize;
        }
        let rem = limit_frame % 64;
        if rem > 0 && full_words < self.bitmap_words {
            let mask = (1u64 << rem) - 1;
            count += ((!bm[full_words]) & mask).count_ones() as usize;
        }
        count
    }
}

static PHYS: SpinLock<PhysAllocator> = SpinLock::new(PhysAllocator::empty());

fn overlaps(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
    a_start < b_end && b_start < a_end
}

/// Find a contiguous aligned region of `size` bytes inside DTB RAM that does not
/// collide with the kernel image or any DTB reserved region.
fn find_bitmap_placement(
    dtb: &DeviceTreeInfo,
    kernel_start: u64,
    kernel_end: u64,
    needed_bytes: u64,
    arch_limit: u64,
) -> Option<u64> {
    let needed_aligned = (needed_bytes + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);

    for i in 0..dtb.mem_count {
        let reg = dtb.mem_regions[i];
        let reg_start = (reg.base + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);
        let reg_end = reg.base.saturating_add(reg.size).min(arch_limit) & !(PAGE_SIZE as u64 - 1);

        let mut cand = reg_start.max(PAGE_SIZE as u64);
        while cand.saturating_add(needed_aligned) <= reg_end {
            let cand_end = cand + needed_aligned;
            let mut collision_end = None;

            if overlaps(cand, cand_end, kernel_start, kernel_end) {
                collision_end = Some(kernel_end);
            } else {
                for r in &dtb.rsv_regions[..dtb.rsv_count] {
                    let rs = r.base & !(PAGE_SIZE as u64 - 1);
                    let re = (r.base.saturating_add(r.size) + PAGE_SIZE as u64 - 1)
                        & !(PAGE_SIZE as u64 - 1);
                    if overlaps(cand, cand_end, rs, re) {
                        collision_end = Some(re);
                        break;
                    }
                }
            }

            match collision_end {
                None => return Some(cand),
                Some(next) => {
                    cand = (next + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);
                }
            }
        }
    }
    None
}

/// Initialize the physical page allocator from DTB regions and CPU `PARange`.
pub fn init(dtb: &DeviceTreeInfo, kernel_start: usize, kernel_end: usize) -> Result<(), &'static str> {
    let pa_bits = arch::physical_address_bits();
    let arch_limit: u64 = if pa_bits >= 64 {
        u64::MAX
    } else {
        1u64 << pa_bits
    };

    if dtb.mem_count == 0 {
        return Err("No RAM regions reported in DTB");
    }

    let mut highest_phys = 0u64;
    for i in 0..dtb.mem_count {
        let r = dtb.mem_regions[i];
        let end = r.base.saturating_add(r.size).min(arch_limit);
        if end > highest_phys {
            highest_phys = end;
        }
    }

    let max_frame_index = (highest_phys as usize) / PAGE_SIZE;
    if max_frame_index == 0 {
        return Err("Usable physical memory is zero");
    }

    let bitmap_words = (max_frame_index + 63) / 64;
    let bitmap_bytes = bitmap_words * 8;

    let kstart = (kernel_start as u64) & !(PAGE_SIZE as u64 - 1);
    let kend = ((kernel_end as u64) + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);

    let bitmap_paddr = find_bitmap_placement(dtb, kstart, kend, bitmap_bytes as u64, arch_limit)
        .ok_or("Unable to place physical memory bitmap in free RAM")?;

    // Initialize bitmap memory to all 1s (all frames reserved by default)
    let bm_slice = unsafe { slice::from_raw_parts_mut(bitmap_paddr as *mut u64, bitmap_words) };
    for w in bm_slice.iter_mut() {
        *w = u64::MAX;
    }

    let mut alloc = PHYS.lock();
    alloc.initialized = true;
    alloc.pa_bits = pa_bits;
    alloc.max_phys_addr = highest_phys;
    alloc.bitmap_ptr = bitmap_paddr as *mut u64;
    alloc.bitmap_words = bitmap_words;
    alloc.max_frame_index = max_frame_index;
    alloc.total_frames = 0;
    alloc.free_frames = 0;

    // Free all DTB RAM regions
    for i in 0..dtb.mem_count {
        let r = dtb.mem_regions[i];
        alloc.mark_range_free(r.base, r.size);
    }

    // Reserve physical frame 0 (null guard), kernel image, bitmap, and DTB reserved regions
    alloc.mark_used(0);
    alloc.mark_range_used(kstart, kend - kstart);
    alloc.mark_range_used(bitmap_paddr, bitmap_bytes as u64);
    for i in 0..dtb.rsv_count {
        let r = dtb.rsv_regions[i];
        alloc.mark_range_used(r.base, r.size);
    }

    let free_mib = (alloc.free_frames * PAGE_SIZE) / (1024 * 1024);
    let total_mib = (alloc.total_frames * PAGE_SIZE) / (1024 * 1024);
    klog!(
        LogLevel::Info,
        "phys",
        "Physical allocator ready: PARange={}-bit, span_top={:#x}, total={} MiB ({} pages), free={} MiB ({} pages), bitmap={} KiB @ {:#x}",
        pa_bits,
        highest_phys,
        total_mib,
        alloc.total_frames,
        free_mib,
        alloc.free_frames,
        (bitmap_bytes + 1023) / 1024,
        bitmap_paddr
    );

    Ok(())
}

/// Allocate one zeroed 4 KiB physical page anywhere within detected RAM.
pub fn alloc_frame() -> Option<u64> {
    let mut guard = PHYS.lock();
    let max = guard.max_phys_addr;
    guard.alloc_frame_below(max)
}

/// Allocate one zeroed 4 KiB physical page strictly below `max_phys_addr` (e.g. 1 GiB / 4 GiB DMA).
pub fn alloc_frame_below(max_phys_addr: u64) -> Option<u64> {
    PHYS.lock().alloc_frame_below(max_phys_addr)
}

/// Allocate `count` physically contiguous zeroed 4 KiB pages.
pub fn alloc_contiguous_frames(count: usize) -> Option<u64> {
    PHYS.lock().alloc_contiguous_frames(count)
}

/// Return a 4 KiB physical frame back to the allocator.
pub fn free_frame(paddr: u64) -> Result<(), &'static str> {
    PHYS.lock().free_frame(paddr)
}

pub fn stats() -> PhysMemStats {
    let guard = PHYS.lock();
    let dma32_free = guard.count_free_below(1u64 << 32);
    PhysMemStats {
        pa_bits: guard.pa_bits,
        max_phys_addr: guard.max_phys_addr,
        total_frames: guard.total_frames,
        free_frames: guard.free_frames,
        used_frames: guard.total_frames.saturating_sub(guard.free_frames),
        dma32_free_frames: dma32_free,
        bitmap_paddr: guard.bitmap_ptr as u64,
        bitmap_bytes: guard.bitmap_words * 8,
    }
}
