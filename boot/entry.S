/* NexOS AArch64 Boot Entry (boot/entry.S)
 *
 * Contract at _start:
 *   - x0 contains the physical address of the Device Tree Blob (DTB)
 *     provided by QEMU or VideoCore firmware. Must be preserved!
 *   - Primary core (MPIDR_EL1[7:0] == 0) proceeds; secondary cores park in WFE.
 *   - Drops cleanly from EL3 -> EL2 -> EL1 (EL1h) if booted in a higher EL.
 *   - Enables FP/SIMD (CPACR_EL1.FPEN) before entering Rust.
 *   - Initializes EL1 stack (__stack_top) and zeroes .bss (__bss_start..__bss_end).
 *   - Calls kernel_entry(dtb_ptr: usize, boot_el: u64).
 */

.section .text.boot, "ax"
.global _start
.global _secondary_start

_start:
    /* Standard 64-byte ARM64 Image header (Documentation/arch/arm64/booting.rst)
     * - QEMU `virt` loads Image at 0x40000000 + 0x80000 = 0x40080000 and sets x0 = DTB.
     * - RPi4 firmware loads kernel8.img at 0x0 + 0x80000 = 0x80000 and sets x0 = DTB.
     */
    b       _boot_start             /* code0: executable branch */
    .word   0                       /* code1 */
    .quad   0x80000                 /* text_offset: 512 KiB */
    .quad   (__kernel_end - _start) /* image_size */
    .quad   0xA                     /* flags: LE, 4K pages, flexible placement */
    .quad   0                       /* res2 */
    .quad   0                       /* res3 */
    .quad   0                       /* res4 */
    .ascii  "ARM\x64"               /* magic = 0x644d5241 */
    .word   0                       /* res5 */

_boot_start:
    /* Preserve DTB physical address (x0) in callee-saved x19 */
    mov     x19, x0

    /* Park secondary cores (affinity 0 != 0) until released via SECONDARY_RELEASE_ADDRS */
    mrs     x1, mpidr_el1
    and     x1, x1, #0xFF
    cbz     x1, .Lprimary_core

    cmp     x1, #8
    b.hs    .Lhalt

.Lpark_core:
    adrp    x2, SECONDARY_RELEASE_ADDRS
    add     x2, x2, :lo12:SECONDARY_RELEASE_ADDRS
    ldr     x3, [x2, x1, lsl #3]
    cbnz    x3, .Lpark_release
    wfe
    b       .Lpark_core

.Lpark_release:
    br      x3

.Lprimary_core:
    /* Capture initial Exception Level in callee-saved x20 */
    mrs     x1, CurrentEL
    lsr     x1, x1, #2
    and     x1, x1, #3
    mov     x20, x1

    /* If started in EL3, drop to EL2 */
    cmp     x1, #3
    b.ne    .Lcheck_el2

    mov     x2, #0x501              /* SCR_EL3: RW=1 (AArch64), HCE=1, NS=1 */
    msr     SCR_EL3, x2
    mov     x2, #0x3C9              /* SPSR_EL3: DAIF masked, EL2h (0b1001) */
    msr     SPSR_EL3, x2
    adr     x2, .Lat_el2
    msr     ELR_EL3, x2
    eret

.Lcheck_el2:
    cmp     x1, #2
    b.ne    .Lat_el1

.Lat_el2:
    /* Configure EL2 -> EL1 transition (RW=1 for AArch64 EL1, clear all trap/virt bits) */
    mov     x2, #(1 << 31)          /* HCR_EL2.RW = 1: EL1 executes in AArch64 */
    msr     HCR_EL2, x2

    /* Allow EL1 access to physical counter/timer */
    mrs     x2, CNTHCTL_EL2
    orr     x2, x2, #3              /* EL1PCTEN | EL1PCEN */
    msr     CNTHCTL_EL2, x2
    msr     CNTVOFF_EL2, xzr

    /* Do not trap FP/SIMD from EL1 to EL2 */
    mov     x2, #0x33FF
    msr     CPTR_EL2, x2

    /* Initialize SCTLR_EL1 with RES1 bits (MMU off, caches off, LE) */
    movz    x2, #0x0800
    movk    x2, #0x30D0, lsl #16
    msr     SCTLR_EL1, x2

    mov     x2, #0x3C5              /* SPSR_EL2: DAIF masked, EL1h (0b0101) */
    msr     SPSR_EL2, x2
    adr     x2, .Lat_el1
    msr     ELR_EL2, x2
    eret

.Lat_el1:
    /* Ensure all interrupts are masked while setting up early EL1 state */
    msr     DAIFSet, #0xF

    /* Enable FP/SIMD in EL1 (CPACR_EL1.FPEN = 0b11) before any Rust code runs */
    mov     x2, #(3 << 20)
    msr     CPACR_EL1, x2
    ic      iallu
    dsb     sy
    isb

    /* Set up 16-byte aligned EL1 boot stack */
    adrp    x2, __stack_top
    add     x2, x2, :lo12:__stack_top
    mov     sp, x2

    /* Zero .bss section (16-byte aligned by linker script) */
    adrp    x2, __bss_start
    add     x2, x2, :lo12:__bss_start
    adrp    x3, __bss_end
    add     x3, x3, :lo12:__bss_end

.Lbss_zero_loop:
    cmp     x2, x3
    b.hs    .Lbss_zero_done
    stp     xzr, xzr, [x2], #16
    b       .Lbss_zero_loop

.Lbss_zero_done:
    /* Pass preserved DTB pointer (x0) and initial boot EL (x1) to Rust */
    mov     x0, x19
    mov     x1, x20
    bl      kernel_entry

.Lhalt:
    wfe
    b       .Lhalt

/* Secondary CPU entry point (PSCI CPU_ON / spin-table / park-table).
 * Executed with MMU OFF on CPU > 0.
 */
_secondary_start:
    mrs     x1, CurrentEL
    lsr     x1, x1, #2
    and     x1, x1, #3

    cmp     x1, #3
    b.ne    .Lsec_check_el2
    mov     x2, #0x501
    msr     SCR_EL3, x2
    mov     x2, #0x3C9
    msr     SPSR_EL3, x2
    adr     x2, .Lsec_at_el2
    msr     ELR_EL3, x2
    eret

.Lsec_check_el2:
    cmp     x1, #2
    b.ne    .Lsec_at_el1

.Lsec_at_el2:
    mov     x2, #(1 << 31)
    msr     HCR_EL2, x2
    mrs     x2, CNTHCTL_EL2
    orr     x2, x2, #3
    msr     CNTHCTL_EL2, x2
    msr     CNTVOFF_EL2, xzr
    mov     x2, #0x33FF
    msr     CPTR_EL2, x2
    movz    x2, #0x0800
    movk    x2, #0x30D0, lsl #16
    msr     SCTLR_EL1, x2
    mov     x2, #0x3C5
    msr     SPSR_EL2, x2
    adr     x2, .Lsec_at_el1
    msr     ELR_EL2, x2
    eret

.Lsec_at_el1:
    msr     DAIFSet, #0xF
    mov     x2, #(3 << 20)
    msr     CPACR_EL1, x2
    ic      iallu
    dsb     sy
    isb

    mrs     x19, mpidr_el1
    and     x19, x19, #0xFF

    /* Configure MMU from SECONDARY_MMU_CFG ([0]=MAIR, [1]=TCR, [2]=TTBR0) */
    adrp    x2, SECONDARY_MMU_CFG
    add     x2, x2, :lo12:SECONDARY_MMU_CFG
    ldr     x3, [x2, #0]
    ldr     x4, [x2, #8]
    ldr     x5, [x2, #16]
    msr     MAIR_EL1, x3
    msr     TCR_EL1, x4
    msr     TTBR0_EL1, x5
    msr     TTBR1_EL1, xzr
    isb
    tlbi    vmalle1
    dsb     sy
    isb

    /* Enable MMU (M=1), Data Cache (C=1), Instruction Cache (I=1) with RES1 bits */
    movz    x2, #0x1805
    movk    x2, #0x30D0, lsl #16
    msr     SCTLR_EL1, x2
    isb

    /* Install per-CPU EL1 stack and shared exception vector table */
    adrp    x2, SECONDARY_STACK_TOPS
    add     x2, x2, :lo12:SECONDARY_STACK_TOPS
    ldr     x3, [x2, x19, lsl #3]
    mov     sp, x3

    adrp    x2, __exception_vectors
    add     x2, x2, :lo12:__exception_vectors
    msr     VBAR_EL1, x2
    isb

    mov     x0, x19
    bl      secondary_cpu_entry
    b       .Lhalt
