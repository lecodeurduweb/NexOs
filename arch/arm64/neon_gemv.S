/* NexOS AArch64 NEON SIMD Kernels for Native AI Core
 *
 * Registers used: ONLY caller-saved GPRs (x0-x7) and caller-saved NEON
 * registers (v0-v7, v16-v18). Full TrapFrame q0-q31 save/restore in vectors.S
 * makes these loops completely safe under SMP timer preemption.
 */

.section .text
.balign 16
.global nexos_neon_dot_f32
.type nexos_neon_dot_f32, %function
/* float nexos_neon_dot_f32(const float *a, const float *b, usize n) */
nexos_neon_dot_f32:
    movi    v0.4s, #0
    cmp     x2, #4
    b.lo    .Ldot_tail_prep

.Ldot_vec_loop:
    ld1     {v1.4s}, [x0], #16
    ld1     {v2.4s}, [x1], #16
    fmla    v0.4s, v1.4s, v2.4s
    sub     x2, x2, #4
    cmp     x2, #4
    b.hs    .Ldot_vec_loop

.Ldot_tail_prep:
    faddp   v0.4s, v0.4s, v0.4s
    faddp   s0, v0.2s
    cbz     x2, .Ldot_done

.Ldot_tail:
    ldr     s1, [x0], #4
    ldr     s2, [x1], #4
    fmadd   s0, s1, s2, s0
    subs    x2, x2, #1
    b.ne    .Ldot_tail

.Ldot_done:
    ret

.balign 16
.global nexos_neon_gemv_q8_0
.type nexos_neon_gemv_q8_0, %function
/* void nexos_neon_gemv_q8_0(float *out, const u8 *mat_q8, const float *x, usize rows, usize cols)
 * Precondition: cols > 0 and (cols % 32) == 0.
 * Q8_0 block layout (36 bytes): [f32 scale (4B LE), i8 weights[32] (32B)].
 */
nexos_neon_gemv_q8_0:
    cbz     x3, .Lgemv_done
    lsr     x5, x4, #5              /* blocks_per_row = cols / 32 */
    cbz     x5, .Lgemv_done

.Lrow_loop:
    fmov    s0, wzr                 /* row accumulator = 0.0f */
    mov     x6, x2                  /* x_ptr = x */
    mov     x7, x5                  /* blk_cnt = blocks_per_row */

.Lblk_loop:
    ldr     s1, [x1], #4            /* block scale */
    ld1     {v2.16b, v3.16b}, [x1], #32

    /* Weights 0..15 (v2) */
    sxtl    v4.8h, v2.8b
    sxtl2   v5.8h, v2.16b

    sxtl    v6.4s, v4.4h
    sxtl2   v7.4s, v4.8h
    scvtf   v6.4s, v6.4s
    scvtf   v7.4s, v7.4s
    ldp     q16, q17, [x6], #32
    fmul    v18.4s, v6.4s, v16.4s
    fmla    v18.4s, v7.4s, v17.4s

    sxtl    v6.4s, v5.4h
    sxtl2   v7.4s, v5.8h
    scvtf   v6.4s, v6.4s
    scvtf   v7.4s, v7.4s
    ldp     q16, q17, [x6], #32
    fmla    v18.4s, v6.4s, v16.4s
    fmla    v18.4s, v7.4s, v17.4s

    /* Weights 16..31 (v3) */
    sxtl    v4.8h, v3.8b
    sxtl2   v5.8h, v3.16b

    sxtl    v6.4s, v4.4h
    sxtl2   v7.4s, v4.8h
    scvtf   v6.4s, v6.4s
    scvtf   v7.4s, v7.4s
    ldp     q16, q17, [x6], #32
    fmla    v18.4s, v6.4s, v16.4s
    fmla    v18.4s, v7.4s, v17.4s

    sxtl    v6.4s, v5.4h
    sxtl2   v7.4s, v5.8h
    scvtf   v6.4s, v6.4s
    scvtf   v7.4s, v7.4s
    ldp     q16, q17, [x6], #32
    fmla    v18.4s, v6.4s, v16.4s
    fmla    v18.4s, v7.4s, v17.4s

    faddp   v18.4s, v18.4s, v18.4s
    faddp   s18, v18.2s
    fmadd   s0, s18, s1, s0

    subs    x7, x7, #1
    b.ne    .Lblk_loop

    str     s0, [x0], #4
    subs    x3, x3, #1
    b.ne    .Lrow_loop

.Lgemv_done:
    ret
