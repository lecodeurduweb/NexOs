/* NexOS EL0 Userspace Runtime Entry (userspace/crt0.S) */
.section .text.entry, "ax"
.global _user_start
.global nexos_syscall
.global nexos_syscall4
.global nexos_syscall5

_user_start:
    /* x0 may contain user argument (e.g., mode flag: 0=shell, 1=fault_probe) */
    bl      user_main
    /* If user_main returns, invoke SYS_EXIT (x8 = 2) */
    mov     x8, #2
    svc     #0
1:
    b       1b

/* long nexos_syscall(u64 num, u64 a0, u64 a1, u64 a2) */
nexos_syscall:
    mov     x8, x0
    mov     x0, x1
    mov     x1, x2
    mov     x2, x3
    svc     #0
    ret

/* long nexos_syscall4(u64 num, u64 a0, u64 a1, u64 a2, u64 a3) */
nexos_syscall4:
    mov     x8, x0
    mov     x0, x1
    mov     x1, x2
    mov     x2, x3
    mov     x3, x4
    svc     #0
    ret

/* long nexos_syscall5(u64 num, u64 a0, u64 a1, u64 a2, u64 a3, u64 a4) */
nexos_syscall5:
    mov     x8, x0
    mov     x0, x1
    mov     x1, x2
    mov     x2, x3
    mov     x3, x4
    mov     x4, x5
    svc     #0
    ret
