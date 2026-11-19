/* NexOS AArch64 Exception Vector Table (arch/arm64/vectors.S)
 *
 * VBAR_EL1 must be 2048-byte aligned (2^11), with 16 slots of 128 bytes each.
 * TrapFrame layout (816 bytes, 16-byte aligned):
 *   [sp + 0x000..0x0F0] : x0..x29 (15 pairs)
 *   [sp + 0x0F0]        : x30 (LR), sp_el0
 *   [sp + 0x100]        : elr_el1, spsr_el1
 *   [sp + 0x110]        : esr_el1, far_el1
 *   [sp + 0x120..0x320] : q0..q31 (16 pairs of 128-bit NEON/FP registers)
 *   [sp + 0x320]        : fpcr, fpsr
 *
 * Total size = 0x330 = 816 bytes (divisible by 16).
 */

.macro VECTOR_STUB vec_id
    sub     sp, sp, #816
    stp     x0, x1, [sp, #0x000]
    mov     x1, #\vec_id
    b       .Lsave_context_rest
.endm

.section .text
.balign 2048
.global __exception_vectors
__exception_vectors:
    /* Group 0: Current EL with SP0 */
    .balign 128
    VECTOR_STUB 0
    .balign 128
    VECTOR_STUB 1
    .balign 128
    VECTOR_STUB 2
    .balign 128
    VECTOR_STUB 3

    /* Group 1: Current EL with SPx */
    .balign 128
    VECTOR_STUB 4
    .balign 128
    VECTOR_STUB 5
    .balign 128
    VECTOR_STUB 6
    .balign 128
    VECTOR_STUB 7

    /* Group 2: Lower EL using AArch64 */
    .balign 128
    VECTOR_STUB 8
    .balign 128
    VECTOR_STUB 9
    .balign 128
    VECTOR_STUB 10
    .balign 128
    VECTOR_STUB 11

    /* Group 3: Lower EL using AArch32 */
    .balign 128
    VECTOR_STUB 12
    .balign 128
    VECTOR_STUB 13
    .balign 128
    VECTOR_STUB 14
    .balign 128
    VECTOR_STUB 15

.Lsave_context_rest:
    stp     x2,  x3,  [sp, #0x010]
    stp     x4,  x5,  [sp, #0x020]
    stp     x6,  x7,  [sp, #0x030]
    stp     x8,  x9,  [sp, #0x040]
    stp     x10, x11, [sp, #0x050]
    stp     x12, x13, [sp, #0x060]
    stp     x14, x15, [sp, #0x070]
    stp     x16, x17, [sp, #0x080]
    stp     x18, x19, [sp, #0x090]
    stp     x20, x21, [sp, #0x0A0]
    stp     x22, x23, [sp, #0x0B0]
    stp     x24, x25, [sp, #0x0C0]
    stp     x26, x27, [sp, #0x0D0]
    stp     x28, x29, [sp, #0x0E0]

    mrs     x10, sp_el0
    stp     x30, x10, [sp, #0x0F0]

    mrs     x11, elr_el1
    mrs     x12, spsr_el1
    stp     x11, x12, [sp, #0x100]

    mrs     x13, esr_el1
    mrs     x14, far_el1
    stp     x13, x14, [sp, #0x110]

    /* Save full NEON/FP state so Rust SIMD loops cannot be corrupted across traps */
    stp     q0,  q1,  [sp, #0x120]
    stp     q2,  q3,  [sp, #0x140]
    stp     q4,  q5,  [sp, #0x160]
    stp     q6,  q7,  [sp, #0x180]
    stp     q8,  q9,  [sp, #0x1A0]
    stp     q10, q11, [sp, #0x1C0]
    stp     q12, q13, [sp, #0x1E0]
    stp     q14, q15, [sp, #0x200]
    stp     q16, q17, [sp, #0x220]
    stp     q18, q19, [sp, #0x240]
    stp     q20, q21, [sp, #0x260]
    stp     q22, q23, [sp, #0x280]
    stp     q24, q25, [sp, #0x2A0]
    stp     q26, q27, [sp, #0x2C0]
    stp     q28, q29, [sp, #0x2E0]
    stp     q30, q31, [sp, #0x300]

    mrs     x15, fpcr
    mrs     x16, fpsr
    add     x17, sp, #0x320
    stp     x15, x16, [x17]

    mov     x0, sp
    /* x1 already holds vec_id from VECTOR_STUB */
    bl      rust_exception_handler
    mov     sp, x0
    bl      sched_post_switch

.Lrestore_context:
    add     x17, sp, #0x320
    ldp     x15, x16, [x17]
    msr     fpcr, x15
    msr     fpsr, x16

    ldp     q0,  q1,  [sp, #0x120]
    ldp     q2,  q3,  [sp, #0x140]
    ldp     q4,  q5,  [sp, #0x160]
    ldp     q6,  q7,  [sp, #0x180]
    ldp     q8,  q9,  [sp, #0x1A0]
    ldp     q10, q11, [sp, #0x1C0]
    ldp     q12, q13, [sp, #0x1E0]
    ldp     q14, q15, [sp, #0x200]
    ldp     q16, q17, [sp, #0x220]
    ldp     q18, q19, [sp, #0x240]
    ldp     q20, q21, [sp, #0x260]
    ldp     q22, q23, [sp, #0x280]
    ldp     q24, q25, [sp, #0x2A0]
    ldp     q26, q27, [sp, #0x2C0]
    ldp     q28, q29, [sp, #0x2E0]
    ldp     q30, q31, [sp, #0x300]

    ldp     x11, x12, [sp, #0x100]
    msr     elr_el1, x11
    msr     spsr_el1, x12

    ldp     x30, x10, [sp, #0x0F0]
    msr     sp_el0, x10

    ldp     x0,  x1,  [sp, #0x000]
    ldp     x2,  x3,  [sp, #0x010]
    ldp     x4,  x5,  [sp, #0x020]
    ldp     x6,  x7,  [sp, #0x030]
    ldp     x8,  x9,  [sp, #0x040]
    ldp     x10, x11, [sp, #0x050]
    ldp     x12, x13, [sp, #0x060]
    ldp     x14, x15, [sp, #0x070]
    ldp     x16, x17, [sp, #0x080]
    ldp     x18, x19, [sp, #0x090]
    ldp     x20, x21, [sp, #0x0A0]
    ldp     x22, x23, [sp, #0x0B0]
    ldp     x24, x25, [sp, #0x0C0]
    ldp     x26, x27, [sp, #0x0D0]
    ldp     x28, x29, [sp, #0x0E0]

    add     sp, sp, #816
    eret
