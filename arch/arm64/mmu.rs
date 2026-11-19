//! ARM64 (AArch64) 4-Level MMU (4 KiB granule, L0–L3) & Cache Activation.
//!
//! - Uses architectural `PARange` from `ID_AA64MMFR0_EL1` to program `TCR_EL1.IPS`
//!   dynamically (supporting 44-bit / 16 TiB physical addressing on Cortex-A72).
//! - Enforces W^X section permissions for the kernel (`.text` RX, `.rodata` RO+NX,
//!   `.data`/`.bss`/stack RW+NX) and EL0 (`init.bin` RX, stack/bss RW+NX).
//! - Provides hardware-authoritative EL0 pointer validation (`AT S1E0R`/`AT S1E0W`)
//!   and per-process page table reclamation (`free_user_l0`).

use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::arch;
use crate::drivers::dtb::DeviceTreeInfo;
use crate::klog;
use crate::log::LogLevel;
use crate::memory::phys::{self, PAGE_SIZE};
use crate::sync::SpinLock;

const PTE_VALID: u64 = 1 << 0;
const PTE_TABLE_OR_PAGE: u64 = 1 << 1; // 1 = Table (L0..L2) or 4K Page (L3); 0 = Block (L1/L2)
const PTE_ATTR_SHIFT: u64 = 2;
const PTE_AP_EL1_RW: u64 = 0b00 << 6;
const PTE_AP_USER_RW: u64 = 0b01 << 6;
const PTE_AP_EL1_RO: u64 = 0b10 << 6;
const PTE_AP_USER_RO: u64 = 0b11 << 6;
const PTE_SH_INNER: u64 = 0b11 << 8;
const PTE_AF: u64 = 1 << 10; // Access Flag (must be 1 to avoid access flag fault)
const PTE_PXN: u64 = 1 << 53;
const PTE_UXN: u64 = 1 << 54;

pub const USER_VA_BASE: u64 = 0x0000_0100_0000_0000; // L0[2]
pub const USER_STACK_TOP: u64 = 0x0000_0100_0010_0000;
pub const USER_MMAP_BASE: u64 = 0x0000_0100_0100_0000;
pub const USER_VA_END: u64 = 0x0000_0100_1000_0000;

const MAIR_IDX_NORMAL_WB: u64 = 0; // 0xFF
const MAIR_IDX_DEVICE: u64 = 1; // 0x00
const MAIR_IDX_NORMAL_NC: u64 = 2; // 0x44

const ADDR_MASK_4K: u64 = 0x0000_FFFF_FFFF_F000;
const BLOCK_2M: u64 = 2 * 1024 * 1024;

#[derive(Clone, Copy)]
pub enum MemAttr {
    KernelCode,
    KernelRodata,
    KernelData,
    NormalRw,
    DeviceMmio,
    UserRx,
    UserRw,
}

impl MemAttr {
    fn to_pte_flags(self) -> u64 {
        match self {
            MemAttr::KernelCode => {
                (MAIR_IDX_NORMAL_WB << PTE_ATTR_SHIFT) | PTE_AP_EL1_RO | PTE_SH_INNER | PTE_AF | PTE_UXN
            }
            MemAttr::KernelRodata => {
                (MAIR_IDX_NORMAL_WB << PTE_ATTR_SHIFT)
                    | PTE_AP_EL1_RO
                    | PTE_SH_INNER
                    | PTE_AF
                    | PTE_PXN
                    | PTE_UXN
            }
            MemAttr::KernelData | MemAttr::NormalRw => {
                (MAIR_IDX_NORMAL_WB << PTE_ATTR_SHIFT)
                    | PTE_AP_EL1_RW
                    | PTE_SH_INNER
                    | PTE_AF
                    | PTE_PXN
                    | PTE_UXN
            }
            MemAttr::DeviceMmio => {
                (MAIR_IDX_DEVICE << PTE_ATTR_SHIFT) | PTE_AP_EL1_RW | PTE_AF | PTE_PXN | PTE_UXN
            }
            MemAttr::UserRx => {
                (MAIR_IDX_NORMAL_WB << PTE_ATTR_SHIFT) | PTE_AP_USER_RO | PTE_SH_INNER | PTE_AF | PTE_PXN
            }
            MemAttr::UserRw => {
                (MAIR_IDX_NORMAL_WB << PTE_ATTR_SHIFT)
                    | PTE_AP_USER_RW
                    | PTE_SH_INNER
                    | PTE_AF
                    | PTE_PXN
                    | PTE_UXN
            }
        }
    }
}

#[repr(C, align(4096))]
pub struct PageTable {
    entries: [u64; 512],
}

static KERNEL_L0_PADDR: AtomicU64 = AtomicU64::new(0);
static PAGE_TABLE_LOCK: SpinLock<()> = SpinLock::new(());
static PM_WDOG_MAPPED: AtomicBool = AtomicBool::new(false);

unsafe fn get_or_alloc_table(parent: &mut PageTable, idx: usize) -> Result<&'static mut PageTable, &'static str> {
    let entry = parent.entries[idx];
    if (entry & PTE_VALID) != 0 {
        if (entry & PTE_TABLE_OR_PAGE) == 0 {
            return Err("Encountered block descriptor where table was expected");
        }
        let next_paddr = entry & ADDR_MASK_4K;
        Ok(&mut *(next_paddr as *mut PageTable))
    } else {
        let frame = phys::alloc_frame().ok_or("Out of physical memory for page table")?;
        parent.entries[idx] = frame | PTE_VALID | PTE_TABLE_OR_PAGE;
        Ok(&mut *(frame as *mut PageTable))
    }
}

/// Map a single 4 KiB page `va -> pa` in the table rooted at `l0_paddr`.
pub fn map_page_4k(l0_paddr: u64, va: u64, pa: u64, attr: MemAttr) -> Result<(), &'static str> {
    let l0_idx = ((va >> 39) & 0x1FF) as usize;
    let l1_idx = ((va >> 30) & 0x1FF) as usize;
    let l2_idx = ((va >> 21) & 0x1FF) as usize;
    let l3_idx = ((va >> 12) & 0x1FF) as usize;

    let _guard = PAGE_TABLE_LOCK.lock();
    unsafe {
        let l0 = &mut *(l0_paddr as *mut PageTable);
        let l1 = get_or_alloc_table(l0, l0_idx)?;
        let l2 = get_or_alloc_table(l1, l1_idx)?;
        let l3 = get_or_alloc_table(l2, l2_idx)?;
        l3.entries[l3_idx] = (pa & ADDR_MASK_4K) | PTE_VALID | PTE_TABLE_OR_PAGE | attr.to_pte_flags();
    }
    Ok(())
}

/// Unmap a single 4 KiB page `va` from `l0_paddr`, returning the unmapped PA if present.
pub fn unmap_page_4k(l0_paddr: u64, va: u64) -> Result<Option<u64>, &'static str> {
    let l0_idx = ((va >> 39) & 0x1FF) as usize;
    let l1_idx = ((va >> 30) & 0x1FF) as usize;
    let l2_idx = ((va >> 21) & 0x1FF) as usize;
    let l3_idx = ((va >> 12) & 0x1FF) as usize;

    let _guard = PAGE_TABLE_LOCK.lock();
    unsafe {
        let l0 = &*(l0_paddr as *const PageTable);
        let l0_ent = l0.entries[l0_idx];
        if (l0_ent & PTE_VALID) == 0 || (l0_ent & PTE_TABLE_OR_PAGE) == 0 {
            return Ok(None);
        }
        let l1 = &*((l0_ent & ADDR_MASK_4K) as *const PageTable);
        let l1_ent = l1.entries[l1_idx];
        if (l1_ent & PTE_VALID) == 0 || (l1_ent & PTE_TABLE_OR_PAGE) == 0 {
            return Ok(None);
        }
        let l2 = &*((l1_ent & ADDR_MASK_4K) as *const PageTable);
        let l2_ent = l2.entries[l2_idx];
        if (l2_ent & PTE_VALID) == 0 || (l2_ent & PTE_TABLE_OR_PAGE) == 0 {
            return Ok(None);
        }
        let l3 = &mut *((l2_ent & ADDR_MASK_4K) as *mut PageTable);
        let old = l3.entries[l3_idx];
        if (old & PTE_VALID) != 0 {
            l3.entries[l3_idx] = 0;
            Ok(Some(old & ADDR_MASK_4K))
        } else {
            Ok(None)
        }
    }
}

/// Map a 2 MiB block `va -> pa` in L2 (for large RAM/MMIO spans).
pub fn map_block_2m(l0_paddr: u64, va: u64, pa: u64, attr: MemAttr) -> Result<(), &'static str> {
    if (va & (BLOCK_2M - 1)) != 0 || (pa & (BLOCK_2M - 1)) != 0 {
        return Err("map_block_2m requires 2 MiB alignment");
    }
    let l0_idx = ((va >> 39) & 0x1FF) as usize;
    let l1_idx = ((va >> 30) & 0x1FF) as usize;
    let l2_idx = ((va >> 21) & 0x1FF) as usize;

    let _guard = PAGE_TABLE_LOCK.lock();
    unsafe {
        let l0 = &mut *(l0_paddr as *mut PageTable);
        let l1 = get_or_alloc_table(l0, l0_idx)?;
        let l2 = get_or_alloc_table(l1, l1_idx)?;
        // Block descriptor has bit 1 = 0
        l2.entries[l2_idx] = (pa & !(BLOCK_2M - 1)) | PTE_VALID | attr.to_pte_flags();
    }
    Ok(())
}

/// Identity-map an arbitrary physical range `[start, start + size)` using 2 MiB
/// blocks where aligned and 4 KiB pages for edges.
pub fn identity_map_range(l0_paddr: u64, start: u64, size: u64, attr: MemAttr) -> Result<(), &'static str> {
    let mut cur = start & !(PAGE_SIZE as u64 - 1);
    let end = (start.saturating_add(size) + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);

    while cur < end {
        if (cur & (BLOCK_2M - 1)) == 0 && (end - cur) >= BLOCK_2M {
            map_block_2m(l0_paddr, cur, cur, attr)?;
            cur += BLOCK_2M;
        } else {
            map_page_4k(l0_paddr, cur, cur, attr)?;
            cur += PAGE_SIZE as u64;
        }
    }
    Ok(())
}

/// Query hardware address translation for EL1 read using `AT S1E1R`.
pub fn translate_el1(va: u64) -> Option<u64> {
    let par: u64;
    unsafe {
        asm!(
            "mrs {daif}, DAIF",
            "msr DAIFSet, #2",
            "at s1e1r, {va}",
            "isb",
            "mrs {par}, PAR_EL1",
            "msr DAIF, {daif}",
            daif = out(reg) _,
            va = in(reg) va,
            par = out(reg) par,
            options(nostack)
        );
    }
    if (par & 1) == 0 {
        Some((par & 0x0000_FFFF_FFFF_F000) | (va & 0xFFF))
    } else {
        None
    }
}

/// Hardware-verify that every 4 KiB page in `[va, va + len)` is mapped in the
/// active `TTBR0_EL1` and permits EL0 read (or write if `write == true`).
/// Prevents EL1 from panicking on unmapped or read-only user pointers in syscalls.
pub fn verify_user_range(va: u64, len: u64, write: bool) -> bool {
    if va < USER_VA_BASE {
        return false;
    }
    let Some(end) = va.checked_add(len) else {
        return false;
    };
    if end > USER_VA_END {
        return false;
    }
    if len == 0 {
        return true;
    }

    let mut page = va & !(PAGE_SIZE as u64 - 1);
    while page < end {
        let par: u64;
        unsafe {
            if write {
                asm!(
                    "mrs {daif}, DAIF",
                    "msr DAIFSet, #2",
                    "at s1e0w, {va}",
                    "isb",
                    "mrs {par}, PAR_EL1",
                    "msr DAIF, {daif}",
                    daif = out(reg) _,
                    va = in(reg) page,
                    par = out(reg) par,
                    options(nostack)
                );
            } else {
                asm!(
                    "mrs {daif}, DAIF",
                    "msr DAIFSet, #2",
                    "at s1e0r, {va}",
                    "isb",
                    "mrs {par}, PAR_EL1",
                    "msr DAIF, {daif}",
                    daif = out(reg) _,
                    va = in(reg) page,
                    par = out(reg) par,
                    options(nostack)
                );
            }
        }
        if (par & 1) != 0 {
            return false;
        }
        page += PAGE_SIZE as u64;
    }
    true
}

#[inline]
fn dcache_line_size() -> usize {
    let ctr: u64;
    unsafe {
        asm!("mrs {}, CTR_EL0", out(reg) ctr, options(nomem, nostack));
    }
    let dmin_line = ((ctr >> 16) & 0xF) as usize;
    let sz = 4usize << dmin_line;
    if (16..=512).contains(&sz) {
        sz
    } else {
        64
    }
}

/// Clean data cache lines by VA to Point of Coherency (`DC CVAC`) for non-coherent DMA TX.
pub fn dcache_clean_range(addr: usize, len: usize) {
    let line = dcache_line_size();
    let mut cur = addr & !(line - 1);
    let end = addr.saturating_add(len);
    unsafe {
        while cur < end {
            asm!("dc cvac, {p}", p = in(reg) cur, options(nostack));
            cur += line;
        }
        asm!("dsb sy", options(nostack));
    }
}

/// Clean and invalidate data cache lines by VA (`DC CIVAC`) for non-coherent DMA RX.
pub fn dcache_invalidate_range(addr: usize, len: usize) {
    let line = dcache_line_size();
    let mut cur = addr & !(line - 1);
    let end = addr.saturating_add(len);
    unsafe {
        while cur < end {
            asm!("dc civac, {p}", p = in(reg) cur, options(nostack));
            cur += line;
        }
        asm!("dsb sy", options(nostack));
    }
}

/// Broadcast TLB invalidation across all Inner-Shareable SMP cores.
#[inline]
pub fn invalidate_tlb_all() {
    unsafe {
        asm!("tlbi vmalle1is", "dsb ish", "isb", options(nostack));
    }
}

pub fn kernel_l0_paddr() -> u64 {
    KERNEL_L0_PADDR.load(Ordering::Acquire)
}

pub fn is_pm_wdog_mapped() -> bool {
    PM_WDOG_MAPPED.load(Ordering::Acquire)
}

/// Return current `(MAIR_EL1, TCR_EL1, KERNEL_L0_PADDR)` for secondary core MMU init.
pub fn current_mmu_regs() -> (u64, u64, u64) {
    let mair: u64;
    let tcr: u64;
    unsafe {
        asm!("mrs {}, MAIR_EL1", out(reg) mair, options(nomem, nostack));
        asm!("mrs {}, TCR_EL1", out(reg) tcr, options(nomem, nostack));
    }
    (mair, tcr, kernel_l0_paddr())
}

/// Create a per-process L0 page table inheriting EL1-only kernel mappings
/// (`AP_EL1`, `UXN=1`) while leaving `L0[2]` (`USER_VA_BASE`) private per process.
pub fn create_user_l0() -> Result<u64, &'static str> {
    let user_l0 = phys::alloc_frame().ok_or("Out of physical memory for user L0")?;
    let kern_l0 = kernel_l0_paddr();
    if kern_l0 == 0 {
        return Err("Kernel MMU not initialized");
    }
    unsafe {
        let src = &*(kern_l0 as *const PageTable);
        let dst = &mut *(user_l0 as *mut PageTable);
        dst.entries.copy_from_slice(&src.entries);
        // Ensure private user slot L0[2] starts empty
        dst.entries[2] = 0;
    }
    Ok(user_l0)
}

/// Reclaim all private EL0 frames and L1/L2/L3 tables inside `L0[2]` without freeing `user_l0`.
unsafe fn free_user_slot2(l0: &mut PageTable) {
    let l1_ent = l0.entries[2];
    if (l1_ent & PTE_VALID) != 0 && (l1_ent & PTE_TABLE_OR_PAGE) != 0 {
        let l1_pa = l1_ent & ADDR_MASK_4K;
        let l1 = &*(l1_pa as *const PageTable);
        for &l2_ent in l1.entries.iter() {
            if (l2_ent & PTE_VALID) != 0 && (l2_ent & PTE_TABLE_OR_PAGE) != 0 {
                let l2_pa = l2_ent & ADDR_MASK_4K;
                let l2 = &*(l2_pa as *const PageTable);
                for &l3_ent in l2.entries.iter() {
                    if (l3_ent & PTE_VALID) != 0 && (l3_ent & PTE_TABLE_OR_PAGE) != 0 {
                        let l3_pa = l3_ent & ADDR_MASK_4K;
                        let l3 = &*(l3_pa as *const PageTable);
                        for &page_ent in l3.entries.iter() {
                            if (page_ent & PTE_VALID) != 0 {
                                let _ = phys::free_frame(page_ent & ADDR_MASK_4K);
                            }
                        }
                        let _ = phys::free_frame(l3_pa);
                    }
                }
                let _ = phys::free_frame(l2_pa);
            }
        }
        let _ = phys::free_frame(l1_pa);
    }
    l0.entries[2] = 0;
}

/// Reclaim all private EL0 frames and L1/L2/L3/L0 tables inside `L0[2]` for an exited task.
/// Note: Must NOT be called while `TTBR0_EL1 == user_l0`.
pub fn free_user_l0(user_l0: u64) {
    let kern_l0 = kernel_l0_paddr();
    if user_l0 == 0 || user_l0 == kern_l0 {
        return;
    }
    unsafe {
        let l0 = &mut *(user_l0 as *mut PageTable);
        free_user_slot2(l0);
        let _ = phys::free_frame(user_l0);
    }
}

/// Map an embedded flat EL0 binary into `user_l0` at `USER_VA_BASE` with W^X:
/// - Binary `.text`/`.rodata` pages are mapped `UserRx` (RO + Execute, never writable).
/// - 2 `.bss`/data pages and 4 stack pages below `USER_STACK_TOP` are mapped `UserRw` (RW + Non-Execute).
/// Returns `(entry_va, user_stack_top)`. Rolls back mapped pages/tables on OOM.
pub fn map_user_binary(user_l0: u64, image: &[u8]) -> Result<(u64, u64), &'static str> {
    if image.is_empty() {
        return Err("Empty user binary image");
    }
    let pages = (image.len() + PAGE_SIZE - 1) / PAGE_SIZE;
    for i in 0..pages {
        let Some(frame) = phys::alloc_frame() else {
            unsafe { free_user_slot2(&mut *(user_l0 as *mut PageTable)) };
            return Err("Out of physical memory for user image");
        };
        let offset = i * PAGE_SIZE;
        let copy_len = (image.len() - offset).min(PAGE_SIZE);
        unsafe {
            core::ptr::copy_nonoverlapping(image.as_ptr().add(offset), frame as *mut u8, copy_len);
        }
        let va = USER_VA_BASE + (offset as u64);
        if let Err(e) = map_page_4k(user_l0, va, frame, MemAttr::UserRx) {
            let _ = phys::free_frame(frame);
            unsafe { free_user_slot2(&mut *(user_l0 as *mut PageTable)) };
            return Err(e);
        }
    }

    // Also provide 2 extra RW non-executable zeroed pages after image for user .bss / small globals
    for extra in 0..2 {
        let Some(frame) = phys::alloc_frame() else {
            unsafe { free_user_slot2(&mut *(user_l0 as *mut PageTable)) };
            return Err("Out of physical memory for user bss");
        };
        let va = USER_VA_BASE + ((pages + extra) * PAGE_SIZE) as u64;
        if let Err(e) = map_page_4k(user_l0, va, frame, MemAttr::UserRw) {
            let _ = phys::free_frame(frame);
            unsafe { free_user_slot2(&mut *(user_l0 as *mut PageTable)) };
            return Err(e);
        }
    }

    // Map 16 KiB (4 pages) non-executable user stack below USER_STACK_TOP
    for s in 1..=4 {
        let Some(frame) = phys::alloc_frame() else {
            unsafe { free_user_slot2(&mut *(user_l0 as *mut PageTable)) };
            return Err("Out of physical memory for user stack");
        };
        let va = USER_STACK_TOP - (s * PAGE_SIZE) as u64;
        if let Err(e) = map_page_4k(user_l0, va, frame, MemAttr::UserRw) {
            let _ = phys::free_frame(frame);
            unsafe { free_user_slot2(&mut *(user_l0 as *mut PageTable)) };
            return Err(e);
        }
    }

    invalidate_tlb_all();
    Ok((USER_VA_BASE, USER_STACK_TOP))
}

/// Allocate and map an anonymous zeroed EL0 region in `[USER_MMAP_BASE, USER_VA_END)`.
pub fn map_user_region(
    user_l0: u64,
    va_hint: u64,
    len_bytes: u64,
    writable: bool,
) -> Result<u64, &'static str> {
    if len_bytes == 0 || len_bytes > 16 * 1024 * 1024 {
        return Err("Invalid mmap length");
    }
    let pages = ((len_bytes + PAGE_SIZE as u64 - 1) / PAGE_SIZE as u64) as usize;
    let attr = if writable { MemAttr::UserRw } else { MemAttr::UserRx };

    // Locate a free contiguous virtual slot starting at va_hint (or USER_MMAP_BASE)
    let mut base = if va_hint >= USER_MMAP_BASE && va_hint < USER_VA_END {
        va_hint & !(PAGE_SIZE as u64 - 1)
    } else {
        USER_MMAP_BASE
    };

    'find_slot: loop {
        let Some(end) = base.checked_add((pages * PAGE_SIZE) as u64) else {
            return Err("mmap address overflow");
        };
        if end > USER_VA_END {
            return Err("Out of user virtual address space");
        }
        // Probe whether any page in [base, end) is already present in user_l0
        for p in 0..pages {
            let va = base + (p * PAGE_SIZE) as u64;
            if is_page_mapped_in_l0(user_l0, va) {
                base = va + PAGE_SIZE as u64;
                continue 'find_slot;
            }
        }
        break;
    }

    for p in 0..pages {
        let Some(frame) = phys::alloc_frame() else {
            for r in 0..p {
                if let Ok(Some(pa)) = unmap_page_4k(user_l0, base + (r * PAGE_SIZE) as u64) {
                    let _ = phys::free_frame(pa);
                }
            }
            invalidate_tlb_all();
            return Err("Out of physical memory for user mmap");
        };
        let va = base + (p * PAGE_SIZE) as u64;
        if let Err(e) = map_page_4k(user_l0, va, frame, attr) {
            let _ = phys::free_frame(frame);
            for r in 0..p {
                if let Ok(Some(pa)) = unmap_page_4k(user_l0, base + (r * PAGE_SIZE) as u64) {
                    let _ = phys::free_frame(pa);
                }
            }
            invalidate_tlb_all();
            return Err(e);
        }
    }
    invalidate_tlb_all();
    Ok(base)
}

/// Unmap a user mmap region in `[USER_MMAP_BASE, USER_VA_END)` and free physical frames.
pub fn unmap_user_region(user_l0: u64, va: u64, len_bytes: u64) -> Result<usize, &'static str> {
    if va < USER_MMAP_BASE || (va & (PAGE_SIZE as u64 - 1)) != 0 || len_bytes == 0 {
        return Err("Invalid munmap range");
    }
    let pages = ((len_bytes + PAGE_SIZE as u64 - 1) / PAGE_SIZE as u64) as usize;
    let Some(end) = va.checked_add((pages * PAGE_SIZE) as u64) else {
        return Err("munmap overflow");
    };
    if end > USER_VA_END {
        return Err("munmap out of bounds");
    }
    let mut freed = 0usize;
    for p in 0..pages {
        if let Ok(Some(pa)) = unmap_page_4k(user_l0, va + (p * PAGE_SIZE) as u64) {
            let _ = phys::free_frame(pa);
            freed += 1;
        }
    }
    invalidate_tlb_all();
    Ok(freed)
}

fn is_page_mapped_in_l0(l0_paddr: u64, va: u64) -> bool {
    let l0_idx = ((va >> 39) & 0x1FF) as usize;
    let l1_idx = ((va >> 30) & 0x1FF) as usize;
    let l2_idx = ((va >> 21) & 0x1FF) as usize;
    let l3_idx = ((va >> 12) & 0x1FF) as usize;
    let _guard = PAGE_TABLE_LOCK.lock();
    unsafe {
        let l0 = &*(l0_paddr as *const PageTable);
        let e0 = l0.entries[l0_idx];
        if (e0 & PTE_VALID) == 0 || (e0 & PTE_TABLE_OR_PAGE) == 0 {
            return false;
        }
        let l1 = &*((e0 & ADDR_MASK_4K) as *const PageTable);
        let e1 = l1.entries[l1_idx];
        if (e1 & PTE_VALID) == 0 || (e1 & PTE_TABLE_OR_PAGE) == 0 {
            return false;
        }
        let l2 = &*((e1 & ADDR_MASK_4K) as *const PageTable);
        let e2 = l2.entries[l2_idx];
        if (e2 & PTE_VALID) == 0 || (e2 & PTE_TABLE_OR_PAGE) == 0 {
            return false;
        }
        let l3 = &*((e2 & ADDR_MASK_4K) as *const PageTable);
        (l3.entries[l3_idx] & PTE_VALID) != 0
    }
}

/// Build kernel page tables from DTB regions + discovered MMIO and enable MMU with W^X.
pub fn init_and_enable(
    dtb: &DeviceTreeInfo,
    kernel_start: usize,
    text_end: usize,
    rodata_end: usize,
    kernel_end: usize,
) -> Result<(), &'static str> {
    let l0_paddr = phys::alloc_frame().ok_or("Failed to allocate L0 page table")?;
    KERNEL_L0_PADDR.store(l0_paddr, Ordering::Release);

    // Split the 2M region covering kernel_start..kernel_end into 4K pages to enforce W^X:
    //   [kstart, text_end)     -> KernelCode   (RO + Exec in EL1, UXN=1)
    //   [text_end, rodata_end) -> KernelRodata (RO + PXN=1 + UXN=1)
    //   [rodata_end, kend)     -> KernelData   (RW + PXN=1 + UXN=1)
    let kstart = (kernel_start as u64) & !(PAGE_SIZE as u64 - 1);
    let ktext_end = ((text_end as u64) + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);
    let kro_end = ((rodata_end as u64) + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);
    let kend = ((kernel_end as u64) + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);
    let kblock_start = kstart & !(BLOCK_2M - 1);
    let kblock_end = (kend + BLOCK_2M - 1) & !(BLOCK_2M - 1);

    for i in 0..dtb.mem_count {
        let r = dtb.mem_regions[i];
        let r_start = r.base & !(PAGE_SIZE as u64 - 1);
        let r_end = (r.base.saturating_add(r.size) + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);

        let mut cur = r_start;
        while cur < r_end {
            if cur >= kblock_start && cur < kblock_end {
                // Keep page 0 (0x0..0x1000) unmapped as a null-pointer guard and to protect
                // BCM2711 armstub8 secondary-core spin-table mailboxes (0xD8..0xF0).
                if cur != 0 {
                    let attr = if cur >= kstart && cur < ktext_end {
                        MemAttr::KernelCode
                    } else if cur >= ktext_end && cur < kro_end {
                        MemAttr::KernelRodata
                    } else {
                        MemAttr::KernelData
                    };
                    map_page_4k(l0_paddr, cur, cur, attr)?;
                }
                cur += PAGE_SIZE as u64;
            } else if (cur & (BLOCK_2M - 1)) == 0 && (r_end - cur) >= BLOCK_2M {
                map_block_2m(l0_paddr, cur, cur, MemAttr::NormalRw)?;
                cur += BLOCK_2M;
            } else {
                map_page_4k(l0_paddr, cur, cur, MemAttr::NormalRw)?;
                cur += PAGE_SIZE as u64;
            }
        }
    }

    // 2. Identity-map DTB-discovered MMIO peripherals as Device-nGnRnE (PXN+UXN)
    if dtb.uart.found && dtb.uart.base != 0 {
        let sz = dtb.uart.size.max(PAGE_SIZE as u64);
        identity_map_range(l0_paddr, dtb.uart.base, sz, MemAttr::DeviceMmio)?;
    } else {
        #[cfg(feature = "board-qemu-virt")]
        identity_map_range(
            l0_paddr,
            crate::arch::boards::active::EARLY_PL011_BASE as u64,
            PAGE_SIZE as u64,
            MemAttr::DeviceMmio,
        )?;
    }

    if dtb.gic.gicd_base != 0 {
        identity_map_range(
            l0_paddr,
            dtb.gic.gicd_base,
            dtb.gic.gicd_size.max(0x10000),
            MemAttr::DeviceMmio,
        )?;
    }
    if dtb.gic.gicc_base != 0 {
        identity_map_range(
            l0_paddr,
            dtb.gic.gicc_base,
            dtb.gic.gicc_size.max(0x10000),
            MemAttr::DeviceMmio,
        )?;
    }

    for i in 0..dtb.virtio_count {
        let v = dtb.virtio_mmio[i];
        identity_map_range(l0_paddr, v.base, v.size.max(0x1000), MemAttr::DeviceMmio)?;
    }

    if let Some(genet) = dtb.genet_base {
        identity_map_range(l0_paddr, genet, 0x10000, MemAttr::DeviceMmio)?;
    }
    if let Some(emmc2) = dtb.emmc2_base {
        identity_map_range(l0_paddr, emmc2, 0x1000, MemAttr::DeviceMmio)?;
    }
    if let Some(rng200) = dtb.rng200_base {
        identity_map_range(l0_paddr, rng200, 0x1000, MemAttr::DeviceMmio)?;
    }

    #[cfg(feature = "board-rpi4")]
    {
        identity_map_range(l0_paddr, 0xFE00_0000, 0x0188_0000, MemAttr::DeviceMmio)?;
        identity_map_range(l0_paddr, 0xFE10_0000, 0x1000, MemAttr::DeviceMmio)?;
        PM_WDOG_MAPPED.store(true, Ordering::Release);
    }

    // 3. Configure MAIR_EL1 and TCR_EL1 (with dynamic IPS from ID_AA64MMFR0_EL1.PARange)
    let mair: u64 = (0xFF << (MAIR_IDX_NORMAL_WB * 8))
        | (0x00 << (MAIR_IDX_DEVICE * 8))
        | (0x44 << (MAIR_IDX_NORMAL_NC * 8));

    let pa_range = arch::id_aa64mmfr0_el1() & 0x7;
    let ips = pa_range.min(5);

    let tcr: u64 = 16
        | (1 << 8)
        | (1 << 10)
        | (0b11 << 12)
        | (0b00 << 14)
        | (1 << 23) // EPD1=1
        | (ips << 32);

    unsafe {
        asm!(
            "tlbi vmalle1",
            "dsb sy",
            "isb",
            "msr MAIR_EL1, {mair}",
            "msr TCR_EL1, {tcr}",
            "msr TTBR0_EL1, {ttbr0}",
            "dsb sy",
            "isb",
            "ic iallu",
            "dsb sy",
            "isb",
            mair = in(reg) mair,
            tcr = in(reg) tcr,
            ttbr0 = in(reg) l0_paddr,
            options(nostack)
        );

        let mut sctlr: u64;
        asm!("mrs {}, SCTLR_EL1", out(reg) sctlr, options(nomem, nostack));
        sctlr |= (1 << 0) | (1 << 2) | (1 << 12); // M, C, I
        sctlr &= !(1 << 19); // WXN = 0
        asm!(
            "msr SCTLR_EL1, {sctlr}",
            "isb",
            sctlr = in(reg) sctlr,
            options(nostack)
        );
    }

    klog!(
        LogLevel::Info,
        "mmu",
        "MMU enabled (W^X: .text={:#x}..{:#x} RX, .ro={:#x}..{:#x} RO): L0={:#x}, IPS={} ({}-bit PA)",
        kstart,
        ktext_end,
        ktext_end,
        kro_end,
        l0_paddr,
        ips,
        arch::physical_address_bits()
    );

    Ok(())
}
