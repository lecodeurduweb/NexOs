//! Flattened Device Tree (FDT / DTB) parser — zero-allocation, `no_std`.
//!
//! Parses the live DTB passed in `x0` by QEMU or Raspberry Pi VideoCore firmware.
//! Extracts physical memory regions (including > 4 GiB), reserved memory
//! (`memreserve` and `/reserved-memory`), GIC interrupt controller (verifying
//! GICv2 compatibility), UART, ARM generic timer IRQs, and VirtIO MMIO devices,
//! with parent bus `ranges` translation (for BCM2711 `/soc` compatibility).

use core::slice;
use core::str;

const FDT_MAGIC: u32 = 0xD00D_FEED;
const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;
const FDT_END: u32 = 9;

pub const MAX_MEM_REGIONS: usize = 16;
pub const MAX_RSV_REGIONS: usize = 32;
pub const MAX_VIRTIO_MMIO: usize = 32;
pub const MAX_CPUS: usize = 8;

#[derive(Clone, Copy, Debug)]
pub struct CpuInfo {
    pub mpidr: u64,
    pub release_addr: u64,
    pub use_psci: bool,
}

impl CpuInfo {
    pub const fn empty() -> Self {
        Self {
            mpidr: 0,
            release_addr: 0,
            use_psci: false,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PhysRegion {
    pub base: u64,
    pub size: u64,
}

impl PhysRegion {
    pub const fn empty() -> Self {
        Self { base: 0, size: 0 }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GicVersion {
    Unknown,
    V2,
    V3,
}

#[derive(Clone, Copy, Debug)]
pub struct GicInfo {
    pub version: GicVersion,
    pub gicd_base: u64,
    pub gicd_size: u64,
    pub gicc_base: u64,
    pub gicc_size: u64,
    pub compatible_len: usize,
    pub compatible_buf: [u8; 48],
}

impl GicInfo {
    pub const fn empty() -> Self {
        Self {
            version: GicVersion::Unknown,
            gicd_base: 0,
            gicd_size: 0,
            gicc_base: 0,
            gicc_size: 0,
            compatible_len: 0,
            compatible_buf: [0; 48],
        }
    }

    pub fn compatible_str(&self) -> &str {
        str::from_utf8(&self.compatible_buf[..self.compatible_len]).unwrap_or("")
    }
}

#[derive(Clone, Copy, Debug)]
pub struct UartInfo {
    pub found: bool,
    pub base: u64,
    pub size: u64,
    pub irq: Option<u32>,
    pub is_mini_uart: bool,
}

impl UartInfo {
    pub const fn empty() -> Self {
        Self {
            found: false,
            base: 0,
            size: 0,
            irq: None,
            is_mini_uart: false,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TimerInfo {
    pub found: bool,
    pub sec_phys_irq: Option<u32>,
    pub ns_phys_irq: Option<u32>,
    pub virt_irq: Option<u32>,
    pub hyp_irq: Option<u32>,
}

impl TimerInfo {
    pub const fn empty() -> Self {
        Self {
            found: false,
            sec_phys_irq: None,
            ns_phys_irq: None,
            virt_irq: None,
            hyp_irq: None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct VirtioMmioInfo {
    pub base: u64,
    pub size: u64,
    pub irq: Option<u32>,
}

impl VirtioMmioInfo {
    pub const fn empty() -> Self {
        Self {
            base: 0,
            size: 0,
            irq: None,
        }
    }
}

#[derive(Clone, Copy)]
pub struct DeviceTreeInfo {
    pub dtb_base: u64,
    pub dtb_size: u64,
    pub model_len: usize,
    pub model_buf: [u8; 64],
    pub mem_regions: [PhysRegion; MAX_MEM_REGIONS],
    pub mem_count: usize,
    pub rsv_regions: [PhysRegion; MAX_RSV_REGIONS],
    pub rsv_count: usize,
    pub gic: GicInfo,
    pub uart: UartInfo,
    pub timer: TimerInfo,
    pub virtio_mmio: [VirtioMmioInfo; MAX_VIRTIO_MMIO],
    pub virtio_count: usize,
    pub cpus: [CpuInfo; MAX_CPUS],
    pub cpu_count: usize,
    pub psci_hvc: bool,
    pub psci_cpu_on_id: u32,
    pub genet_base: Option<u64>,
    pub genet_mac: Option<[u8; 6]>,
    pub emmc2_base: Option<u64>,
    pub rng200_base: Option<u64>,
}

impl DeviceTreeInfo {
    pub const fn empty() -> Self {
        Self {
            dtb_base: 0,
            dtb_size: 0,
            model_len: 0,
            model_buf: [0; 64],
            mem_regions: [PhysRegion::empty(); MAX_MEM_REGIONS],
            mem_count: 0,
            rsv_regions: [PhysRegion::empty(); MAX_RSV_REGIONS],
            rsv_count: 0,
            gic: GicInfo::empty(),
            uart: UartInfo::empty(),
            timer: TimerInfo::empty(),
            virtio_mmio: [VirtioMmioInfo::empty(); MAX_VIRTIO_MMIO],
            virtio_count: 0,
            cpus: [CpuInfo::empty(); MAX_CPUS],
            cpu_count: 0,
            psci_hvc: false,
            psci_cpu_on_id: 0xC400_0003,
            genet_base: None,
            genet_mac: None,
            emmc2_base: None,
            rng200_base: None,
        }
    }

    pub fn model_str(&self) -> &str {
        str::from_utf8(&self.model_buf[..self.model_len]).unwrap_or("unknown")
    }

    pub fn total_ram_bytes(&self) -> u64 {
        let mut sum = 0u64;
        for i in 0..self.mem_count {
            sum = sum.saturating_add(self.mem_regions[i].size);
        }
        sum
    }

    fn push_mem(&mut self, base: u64, size: u64) {
        if size > 0 && self.mem_count < MAX_MEM_REGIONS {
            self.mem_regions[self.mem_count] = PhysRegion { base, size };
            self.mem_count += 1;
        }
    }

    fn push_rsv(&mut self, base: u64, size: u64) {
        if size > 0 && self.rsv_count < MAX_RSV_REGIONS {
            self.rsv_regions[self.rsv_count] = PhysRegion { base, size };
            self.rsv_count += 1;
        }
    }
}

#[derive(Clone, Copy)]
struct RangeEntry {
    child_bus_addr: u64,
    parent_phys_addr: u64,
    size: u64,
}

impl RangeEntry {
    const fn empty() -> Self {
        Self {
            child_bus_addr: 0,
            parent_phys_addr: 0,
            size: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct NodeFrame {
    addr_cells: u32,
    size_cells: u32,
    range_count: usize,
    ranges: [RangeEntry; 8],
    is_reserved_mem_parent: bool,
}

impl NodeFrame {
    const fn default_root() -> Self {
        Self {
            addr_cells: 2,
            size_cells: 1,
            range_count: 0,
            ranges: [RangeEntry::empty(); 8],
            is_reserved_mem_parent: false,
        }
    }
}

#[inline]
fn read_be32(data: &[u8], off: usize) -> Option<u32> {
    let b = data.get(off..off + 4)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

#[inline]
fn read_be64(data: &[u8], off: usize) -> Option<u64> {
    let b = data.get(off..off + 8)?;
    Some(u64::from_be_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

fn read_cells(data: &[u8], off: usize, cells: u32) -> Option<u64> {
    match cells {
        0 => Some(0),
        1 => read_be32(data, off).map(|v| v as u64),
        2 => read_be64(data, off),
        _ => None,
    }
}

fn cstr_from_bytes(bytes: &[u8]) -> &str {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    str::from_utf8(&bytes[..len]).unwrap_or("")
}

fn compat_contains(prop: &[u8], needle: &str) -> bool {
    let mut start = 0;
    while start < prop.len() {
        let end = prop[start..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| start + p)
            .unwrap_or(prop.len());
        if let Ok(s) = str::from_utf8(&prop[start..end]) {
            if s == needle {
                return true;
            }
        }
        start = end + 1;
    }
    false
}

/// Convert a 3-cell GIC interrupt specifier `<type, num, flags>` into ARM GIC INTID.
fn decode_gic_irq(spec_type: u32, irq_num: u32) -> Option<u32> {
    match spec_type {
        0 => Some(32 + irq_num), // SPI
        1 => Some(16 + irq_num), // PPI
        _ => None,
    }
}

fn translate_bus_addr(stack: &[NodeFrame], depth: usize, mut addr: u64) -> u64 {
    // Walk up from parent (depth - 1) toward root applying `ranges` translations
    let mut lvl = depth;
    while lvl > 0 {
        lvl -= 1;
        let frame = &stack[lvl];
        if frame.range_count > 0 {
            for r in &frame.ranges[..frame.range_count] {
                if addr >= r.child_bus_addr && addr < r.child_bus_addr.saturating_add(r.size) {
                    addr = r.parent_phys_addr + (addr - r.child_bus_addr);
                    break;
                }
            }
        }
    }
    addr
}

static PARSED_DTB: crate::sync::SpinLock<Option<DeviceTreeInfo>> = crate::sync::SpinLock::new(None);

pub fn cached() -> Option<DeviceTreeInfo> {
    *PARSED_DTB.lock()
}

/// Parse the DTB located at `dtb_phys_addr`.
pub fn parse(dtb_phys_addr: usize) -> Result<DeviceTreeInfo, &'static str> {
    if dtb_phys_addr == 0 || (dtb_phys_addr & 0x7) != 0 {
        return Err("Invalid DTB physical pointer");
    }

    // Read header (40 bytes) first to get totalsize
    let hdr = unsafe { slice::from_raw_parts(dtb_phys_addr as *const u8, 40) };
    let magic = read_be32(hdr, 0).ok_or("DTB truncated header")?;
    if magic != FDT_MAGIC {
        return Err("DTB bad magic (expected 0xD00DFEED)");
    }

    let totalsize = read_be32(hdr, 4).ok_or("DTB totalsize")? as usize;
    if !(40..=4 * 1024 * 1024).contains(&totalsize) {
        return Err("DTB totalsize out of sane bounds");
    }

    let off_dt_struct = read_be32(hdr, 8).ok_or("DTB off_dt_struct")? as usize;
    let off_dt_strings = read_be32(hdr, 12).ok_or("DTB off_dt_strings")? as usize;
    let off_mem_rsvmap = read_be32(hdr, 16).ok_or("DTB off_mem_rsvmap")? as usize;
    let size_dt_strings = read_be32(hdr, 32).ok_or("DTB size_dt_strings")? as usize;
    let size_dt_struct = read_be32(hdr, 36).ok_or("DTB size_dt_struct")? as usize;

    let dtb = unsafe { slice::from_raw_parts(dtb_phys_addr as *const u8, totalsize) };
    let dt_struct = dtb
        .get(off_dt_struct..off_dt_struct + size_dt_struct)
        .ok_or("DTB dt_struct out of bounds")?;
    let dt_strings = dtb
        .get(off_dt_strings..off_dt_strings + size_dt_strings)
        .ok_or("DTB dt_strings out of bounds")?;

    let mut info = DeviceTreeInfo::empty();
    info.dtb_base = dtb_phys_addr as u64;
    info.dtb_size = totalsize as u64;

    // Reserve the DTB blob itself so stage 6 physical allocator never overwrites it
    info.push_rsv(info.dtb_base, info.dtb_size);

    // Parse FDT memreserve table
    let mut rsv_off = off_mem_rsvmap;
    while rsv_off + 16 <= totalsize {
        let addr = read_be64(dtb, rsv_off).unwrap_or(0);
        let size = read_be64(dtb, rsv_off + 8).unwrap_or(0);
        if addr == 0 && size == 0 {
            break;
        }
        info.push_rsv(addr, size);
        rsv_off += 16;
    }

    // Walk dt_struct tokens
    const MAX_DEPTH: usize = 16;
    let mut stack = [NodeFrame::default_root(); MAX_DEPTH];
    let mut depth: usize = 0;

    // Per-node temporary property accumulator
    let mut node_name_buf = [0u8; 64];
    let mut node_name_len = 0usize;
    let mut dev_type_buf = [0u8; 32];
    let mut dev_type_len = 0usize;
    let mut compat_buf = [0u8; 256];
    let mut compat_len = 0usize;
    let mut reg_buf = [0u8; 128];
    let mut reg_len = 0usize;
    let mut irq_buf = [0u8; 128];
    let mut irq_len = 0usize;
    let mut psci_method_hvc = false;
    let mut psci_cpu_on_val: Option<u32> = None;
    let mut enable_method_psci = false;
    let mut cpu_release_addr = 0u64;
    let mut local_mac: Option<[u8; 6]> = None;
    let mut node_disabled = false;

    let finalize_node = |info: &mut DeviceTreeInfo,
                         stack: &[NodeFrame; MAX_DEPTH],
                         depth: usize,
                         node_name: &str,
                         dev_type: &str,
                         compat: &[u8],
                         reg: &[u8],
                         irq: &[u8],
                         psci_hvc: bool,
                         psci_cpu_on: Option<u32>,
                         cpu_psci: bool,
                         cpu_rel: u64,
                         mac_opt: Option<[u8; 6]>,
                         disabled: bool| {
        if depth < 2 {
            return;
        }
        let parent = &stack[depth - 2];
        let ac = parent.addr_cells;
        let sc = parent.size_cells;
        let entry_bytes = ((ac + sc) * 4) as usize;

        // Decode `reg` pairs using parent's #address-cells / #size-cells
        let read_reg_pair = |idx: usize| -> Option<(u64, u64)> {
            if entry_bytes == 0 {
                return None;
            }
            let off = idx * entry_bytes;
            if off + entry_bytes > reg.len() {
                return None;
            }
            let raw_addr = read_cells(reg, off, ac)?;
            let size = read_cells(reg, off + (ac as usize) * 4, sc)?;
            let phys_addr = translate_bus_addr(stack, depth - 1, raw_addr);
            Some((phys_addr, size))
        };

        // Memory nodes
        if dev_type == "memory" || node_name.starts_with("memory@") || node_name == "memory" {
            let mut idx = 0;
            while let Some((base, size)) = read_reg_pair(idx) {
                info.push_mem(base, size);
                idx += 1;
            }
        }

        // Reserved memory children
        if depth >= 2 && stack[depth - 2].is_reserved_mem_parent {
            let mut idx = 0;
            while let Some((base, size)) = read_reg_pair(idx) {
                info.push_rsv(base, size);
                idx += 1;
            }
        }

        // Ignore disabled device nodes (e.g. BCM2711 uart1..uart5 with status = "disabled")
        if disabled {
            return;
        }

        // GIC interrupt controller
        if compat_contains(compat, "arm,gic-400") || compat_contains(compat, "arm,cortex-a15-gic") {
            info.gic.version = GicVersion::V2;
            let label = if compat_contains(compat, "arm,gic-400") {
                "arm,gic-400"
            } else {
                "arm,cortex-a15-gic"
            };
            let lb = label.as_bytes();
            let n = lb.len().min(info.gic.compatible_buf.len());
            info.gic.compatible_buf[..n].copy_from_slice(&lb[..n]);
            info.gic.compatible_len = n;
            if let Some((b, s)) = read_reg_pair(0) {
                info.gic.gicd_base = b;
                info.gic.gicd_size = s;
            }
            if let Some((b, s)) = read_reg_pair(1) {
                info.gic.gicc_base = b;
                info.gic.gicc_size = s;
            }
        } else if compat_contains(compat, "arm,gic-v3") && info.gic.version == GicVersion::Unknown
        {
            info.gic.version = GicVersion::V3;
            let lb = b"arm,gic-v3";
            info.gic.compatible_buf[..lb.len()].copy_from_slice(lb);
            info.gic.compatible_len = lb.len();
            if let Some((b, s)) = read_reg_pair(0) {
                info.gic.gicd_base = b;
                info.gic.gicd_size = s;
            }
        }

        // UART (PL011 or BCM2835 Mini-UART)
        if !info.uart.found && compat_contains(compat, "arm,pl011") {
            if let Some((b, s)) = read_reg_pair(0) {
                info.uart.found = true;
                info.uart.base = b;
                info.uart.size = s;
                info.uart.is_mini_uart = false;
                if irq.len() >= 12 {
                    if let (Some(t), Some(n)) = (read_be32(irq, 0), read_be32(irq, 4)) {
                        info.uart.irq = decode_gic_irq(t, n);
                    }
                }
            }
        } else if !info.uart.found && compat_contains(compat, "brcm,bcm2835-aux-uart") {
            if let Some((b, s)) = read_reg_pair(0) {
                info.uart.found = true;
                info.uart.base = b;
                info.uart.size = s;
                info.uart.is_mini_uart = true;
                if irq.len() >= 12 {
                    if let (Some(t), Some(n)) = (read_be32(irq, 0), read_be32(irq, 4)) {
                        info.uart.irq = decode_gic_irq(t, n);
                    }
                }
            }
        }

        // ARM Generic Timer
        if compat_contains(compat, "arm,armv8-timer") || compat_contains(compat, "arm,armv7-timer") {
            info.timer.found = true;
            let mut idx = 0;
            let mut slot = 0;
            while idx + 12 <= irq.len() && slot < 4 {
                if let (Some(t), Some(n)) = (read_be32(irq, idx), read_be32(irq, idx + 4)) {
                    let intid = decode_gic_irq(t, n);
                    match slot {
                        0 => info.timer.sec_phys_irq = intid,
                        1 => info.timer.ns_phys_irq = intid,
                        2 => info.timer.virt_irq = intid,
                        3 => info.timer.hyp_irq = intid,
                        _ => {}
                    }
                }
                idx += 12;
                slot += 1;
            }
        }

        // VirtIO MMIO slots (for Stage 10/11)
        if compat_contains(compat, "virtio,mmio") && info.virtio_count < MAX_VIRTIO_MMIO {
            if let Some((b, s)) = read_reg_pair(0) {
                let irq_id = if irq.len() >= 12 {
                    match (read_be32(irq, 0), read_be32(irq, 4)) {
                        (Some(t), Some(n)) => decode_gic_irq(t, n),
                        _ => None,
                    }
                } else {
                    None
                };
                info.virtio_mmio[info.virtio_count] = VirtioMmioInfo {
                    base: b,
                    size: s,
                    irq: irq_id,
                };
                info.virtio_count += 1;
            }
        }

        // CPU nodes (`cpu@...`, device_type = "cpu")
        if (dev_type == "cpu" || node_name.starts_with("cpu@")) && info.cpu_count < MAX_CPUS {
            let mpidr = if ac == 1 {
                read_be32(reg, 0).map(|v| v as u64)
            } else {
                read_be64(reg, 0)
            }
            .unwrap_or(info.cpu_count as u64);
            let idx = info.cpu_count;
            info.cpus[idx] = CpuInfo {
                mpidr,
                release_addr: cpu_rel,
                use_psci: cpu_psci,
            };
            info.cpu_count += 1;
        }

        // PSCI conduit & function IDs
        if compat_contains(compat, "arm,psci-0.2") || compat_contains(compat, "arm,psci-1.0") {
            if psci_hvc {
                info.psci_hvc = true;
            }
            if let Some(id) = psci_cpu_on {
                info.psci_cpu_on_id = id;
            }
        }

        // BCM2711 GENET / EMMC2
        if compat_contains(compat, "brcm,bcm2711-genet-v5") {
            if let Some((b, _)) = read_reg_pair(0) {
                info.genet_base = Some(b);
            }
            if mac_opt.is_some() {
                info.genet_mac = mac_opt;
            }
        }
        if compat_contains(compat, "brcm,bcm2711-emmc2") {
            if let Some((b, _)) = read_reg_pair(0) {
                info.emmc2_base = Some(b);
            }
        }
        if compat_contains(compat, "brcm,bcm2711-rng200")
            || compat_contains(compat, "brcm,bcm2838-rng200")
        {
            if let Some((b, _)) = read_reg_pair(0) {
                info.rng200_base = Some(b);
            }
        }
    };

    let mut off = 0usize;
    let mut active_node_finalized = true;

    while off + 4 <= dt_struct.len() {
        let token = read_be32(dt_struct, off).unwrap_or(FDT_END);
        off += 4;
        match token {
            FDT_BEGIN_NODE => {
                // Finalize parent properties before descending into child
                if !active_node_finalized {
                    let nname = str::from_utf8(&node_name_buf[..node_name_len]).unwrap_or("");
                    let dtype = str::from_utf8(&dev_type_buf[..dev_type_len]).unwrap_or("");
                    finalize_node(
                        &mut info,
                        &stack,
                        depth,
                        nname,
                        dtype,
                        &compat_buf[..compat_len],
                        &reg_buf[..reg_len],
                        &irq_buf[..irq_len],
                        psci_method_hvc,
                        psci_cpu_on_val,
                        enable_method_psci,
                        cpu_release_addr,
                        local_mac,
                        node_disabled,
                    );
                }

                let name = cstr_from_bytes(&dt_struct[off..]);
                let raw_len = name.len() + 1;
                off = (off + raw_len + 3) & !3;

                if depth < MAX_DEPTH {
                    let parent_is_rsv = name == "reserved-memory";
                    stack[depth] = NodeFrame {
                        addr_cells: 2,
                        size_cells: 1,
                        range_count: 0,
                        ranges: [RangeEntry::empty(); 8],
                        is_reserved_mem_parent: parent_is_rsv,
                    };
                }
                depth += 1;

                let nb = name.as_bytes();
                node_name_len = nb.len().min(node_name_buf.len());
                node_name_buf[..node_name_len].copy_from_slice(&nb[..node_name_len]);
                dev_type_len = 0;
                compat_len = 0;
                reg_len = 0;
                irq_len = 0;
                psci_method_hvc = false;
                psci_cpu_on_val = None;
                enable_method_psci = false;
                cpu_release_addr = 0;
                local_mac = None;
                node_disabled = false;
                active_node_finalized = false;
            }
            FDT_END_NODE => {
                if !active_node_finalized {
                    let nname = str::from_utf8(&node_name_buf[..node_name_len]).unwrap_or("");
                    let dtype = str::from_utf8(&dev_type_buf[..dev_type_len]).unwrap_or("");
                    finalize_node(
                        &mut info,
                        &stack,
                        depth,
                        nname,
                        dtype,
                        &compat_buf[..compat_len],
                        &reg_buf[..reg_len],
                        &irq_buf[..irq_len],
                        psci_method_hvc,
                        psci_cpu_on_val,
                        enable_method_psci,
                        cpu_release_addr,
                        local_mac,
                        node_disabled,
                    );
                    active_node_finalized = true;
                }
                if depth > 0 {
                    depth -= 1;
                }
            }
            FDT_PROP => {
                let len = read_be32(dt_struct, off).ok_or("FDT_PROP len")? as usize;
                let nameoff = read_be32(dt_struct, off + 4).ok_or("FDT_PROP nameoff")? as usize;
                off += 8;
                let val = dt_struct
                    .get(off..off + len)
                    .ok_or("FDT_PROP value out of bounds")?;
                off = (off + len + 3) & !3;

                let pname = if nameoff < dt_strings.len() {
                    cstr_from_bytes(&dt_strings[nameoff..])
                } else {
                    ""
                };

                let cur_idx = depth.saturating_sub(1);
                if cur_idx < MAX_DEPTH {
                    match pname {
                        "#address-cells" => {
                            if let Some(v) = read_be32(val, 0) {
                                stack[cur_idx].addr_cells = v;
                            }
                        }
                        "#size-cells" => {
                            if let Some(v) = read_be32(val, 0) {
                                stack[cur_idx].size_cells = v;
                            }
                        }
                        "ranges" if !val.is_empty() => {
                            // child-bus-addr (cur.addr_cells) | parent-bus-addr (parent.addr_cells) | len (cur.size_cells)
                            let cac = stack[cur_idx].addr_cells;
                            let pac = if cur_idx > 0 {
                                stack[cur_idx - 1].addr_cells
                            } else {
                                2
                            };
                            let csc = stack[cur_idx].size_cells;
                            let stride = ((cac + pac + csc) * 4) as usize;
                            let mut roff = 0usize;
                            while stride > 0
                                && roff + stride <= val.len()
                                && stack[cur_idx].range_count < 8
                            {
                                let c_addr = read_cells(val, roff, cac).unwrap_or(0);
                                let p_addr =
                                    read_cells(val, roff + (cac as usize) * 4, pac).unwrap_or(0);
                                let r_sz = read_cells(val, roff + ((cac + pac) as usize) * 4, csc)
                                    .unwrap_or(0);
                                let idx = stack[cur_idx].range_count;
                                stack[cur_idx].ranges[idx] = RangeEntry {
                                    child_bus_addr: c_addr,
                                    parent_phys_addr: p_addr,
                                    size: r_sz,
                                };
                                stack[cur_idx].range_count += 1;
                                roff += stride;
                            }
                        }
                        "model" if depth == 1 => {
                            let s = cstr_from_bytes(val);
                            let sb = s.as_bytes();
                            let n = sb.len().min(info.model_buf.len());
                            info.model_buf[..n].copy_from_slice(&sb[..n]);
                            info.model_len = n;
                        }
                        "device_type" => {
                            let s = cstr_from_bytes(val);
                            let sb = s.as_bytes();
                            dev_type_len = sb.len().min(dev_type_buf.len());
                            dev_type_buf[..dev_type_len].copy_from_slice(&sb[..dev_type_len]);
                        }
                        "compatible" => {
                            compat_len = val.len().min(compat_buf.len());
                            compat_buf[..compat_len].copy_from_slice(&val[..compat_len]);
                        }
                        "reg" => {
                            reg_len = val.len().min(reg_buf.len());
                            reg_buf[..reg_len].copy_from_slice(&val[..reg_len]);
                        }
                        "interrupts" => {
                            irq_len = val.len().min(irq_buf.len());
                            irq_buf[..irq_len].copy_from_slice(&val[..irq_len]);
                        }
                        "method" => {
                            if cstr_from_bytes(val) == "hvc" {
                                psci_method_hvc = true;
                            }
                        }
                        "cpu_on" => {
                            if let Some(id) = read_be32(val, 0) {
                                psci_cpu_on_val = Some(id);
                            }
                        }
                        "enable-method" => {
                            if cstr_from_bytes(val) == "psci" {
                                enable_method_psci = true;
                            }
                        }
                        "cpu-release-addr" => {
                            if let Some(a) = read_be64(val, 0) {
                                cpu_release_addr = a;
                            } else if let Some(a32) = read_be32(val, 0) {
                                cpu_release_addr = a32 as u64;
                            }
                        }
                        "local-mac-address" | "mac-address" => {
                            if val.len() == 6 {
                                let mut m = [0u8; 6];
                                m.copy_from_slice(val);
                                local_mac = Some(m);
                            }
                        }
                        "status" => {
                            let st = cstr_from_bytes(val);
                            if st != "okay" && st != "ok" {
                                node_disabled = true;
                            }
                        }
                        _ => {}
                    }
                }
            }
            FDT_NOP => {}
            FDT_END => break,
            _ => return Err("Unknown FDT token encountered"),
        }
    }

    *PARSED_DTB.lock() = Some(info);
    Ok(info)
}
