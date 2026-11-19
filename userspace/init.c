/* NexOS First EL0 User Program & Minimal Interactive UART Shell */
#include <stdint.h>
#include <stddef.h>

#define SYS_WRITE     0
#define SYS_READ      1
#define SYS_EXIT      2
#define SYS_YIELD     3
#define SYS_GETPID    4
#define SYS_UPTIME_MS 5
#define SYS_SYSINFO   6
#define SYS_SLEEP_MS  7
#define SYS_VFS_LIST  8
#define SYS_VFS_READ  9
#define SYS_VFS_WRITE 10
#define SYS_NET_INFO  11
#define SYS_NET_PING  12
#define SYS_NET_DNS   13
#define SYS_NET_STAT  14
#define SYS_SVC_LIST  15
#define SYS_SVC_CTRL     16
#define SYS_DMESG        17
#define SYS_MMAP         18
#define SYS_MUNMAP       19
#define SYS_THREAD_SPAWN 20
#define SYS_THREAD_JOIN  21
#define SYS_IPC_SEND     22
#define SYS_IPC_RECV     23
#define SYS_VFS_MKDIR    24
#define SYS_VFS_REMOVE   25
#define SYS_VFS_SYNC     26
#define SYS_DEV_LIST     27
#define SYS_POWER        28
#define SYS_AI_CMD       29
#define SYS_SECURITY     30

extern long nexos_syscall(uint64_t num, uint64_t a0, uint64_t a1, uint64_t a2);
extern long nexos_syscall4(uint64_t num, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3);
extern long nexos_syscall5(uint64_t num, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4);

static size_t u_strlen(const char *s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

static int u_strcmp(const char *a, const char *b) {
    while (*a && (*a == *b)) {
        a++;
        b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

static int u_strncmp(const char *a, const char *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i] || a[i] == 0) {
            return (unsigned char)a[i] - (unsigned char)b[i];
        }
    }
    return 0;
}

static void u_puts(const char *s) {
    nexos_syscall(SYS_WRITE, 1, (uint64_t)(uintptr_t)s, (uint64_t)u_strlen(s));
}

static void u_put_u64(uint64_t v) {
    char buf[24];
    int idx = 0;
    if (v == 0) {
        u_puts("0");
        return;
    }
    while (v > 0 && idx < 23) {
        buf[idx++] = (char)('0' + (v % 10));
        v /= 10;
    }
    while (idx > 0) {
        char c = buf[--idx];
        nexos_syscall(SYS_WRITE, 1, (uint64_t)(uintptr_t)&c, 1);
    }
}

static uint64_t read_current_el_safe_probe(void) {
    /* Verify we are truly in EL0 by reading NZCV or trying a harmless EL0 op.
     * Note: reading CurrentEL from EL0 traps as illegal instruction! */
    return 0;
}

static void print_sysinfo(void) {
    char buf[1024];
    long n = nexos_syscall(SYS_SYSINFO, (uint64_t)(uintptr_t)buf, sizeof(buf) - 1, 0);
    if (n > 0) {
        buf[n] = 0;
        u_puts(buf);
    }
}

static void run_command(const char *cmd) {
    if (cmd[0] == 0) {
        return;
    } else if (u_strcmp(cmd, "help") == 0) {
        u_puts("NexOS EL0 Shell commands:\n");
        u_puts("  help               - show this help\n");
        u_puts("  uname              - print OS & privilege level\n");
        u_puts("  pid                - print current EL0 task ID\n");
        u_puts("  uptime             - print system uptime in ms\n");
        u_puts("  info | ps | mem    - print kernel memory & SMP task snapshot\n");
        u_puts("  devs               - list DTB/VirtIO/BCM2711/VFS/NIC devices\n");
        u_puts("  ls [path]          - list VFS directory (default /)\n");
        u_puts("  cat <path>         - read file via VFS\n");
        u_puts("  write <path> <txt> - write file via VFS\n");
        u_puts("  mkdir <path>       - create directory via VFS\n");
        u_puts("  rm <path>          - remove file or empty directory\n");
        u_puts("  sync               - flush dirty BlockCache sectors to disk\n");
        u_puts("  ifconfig           - show NIC, IPv4/IPv6, ARP & stats\n");
        u_puts("  ping <ip>          - send 3 ICMP echo requests\n");
        u_puts("  dns <host>         - resolve DNS A record\n");
        u_puts("  netstat            - list active/listening TCP sockets\n");
        u_puts("  services           - list managed services & watchdog state\n");
        u_puts("  svc <start|stop|restart> <name> - control a managed service\n");
        u_puts("  mmaptest           - verify SYS_MMAP / W^X rejection / SYS_MUNMAP\n");
        u_puts("  ipctest            - verify SYS_IPC_SEND / SYS_IPC_RECV\n");
        u_puts("  ai <status|load|ask|bench|unload> - native NexOS AI Core CLI\n");
        u_puts("  setup <user> <pass> - provision initial Admin on first boot\n");
        u_puts("  users              - list configured RBAC users & setup status\n");
        u_puts("  dmesg              - show recent kernel ring-buffer logs\n");
        u_puts("  echo <text>        - print text via SYS_WRITE\n");
        u_puts("  fault              - attempt illegal EL0 read of kernel RAM\n");
        u_puts("  reboot             - reset system via PSCI\n");
        u_puts("  exit               - exit EL0 shell task\n");
    } else if (u_strcmp(cmd, "uname") == 0) {
        u_puts("NexOS 0.1.0 aarch64 headless-server (userspace EL0)\n");
    } else if (u_strcmp(cmd, "pid") == 0) {
        long pid = nexos_syscall(SYS_GETPID, 0, 0, 0);
        u_puts("pid=");
        u_put_u64((uint64_t)pid);
        u_puts("\n");
    } else if (u_strcmp(cmd, "uptime") == 0) {
        long ms = nexos_syscall(SYS_UPTIME_MS, 0, 0, 0);
        u_puts("uptime=");
        u_put_u64((uint64_t)ms);
        u_puts(" ms\n");
    } else if (u_strcmp(cmd, "info") == 0 || u_strcmp(cmd, "ps") == 0 || u_strcmp(cmd, "mem") == 0) {
        print_sysinfo();
    } else if (u_strcmp(cmd, "devs") == 0) {
        char out[1024];
        long n = nexos_syscall(SYS_DEV_LIST, (uint64_t)(uintptr_t)out, sizeof(out) - 1, 0);
        if (n >= 0) {
            out[n] = 0;
            u_puts(out);
        } else {
            u_puts("devs error\n");
        }
    } else if (u_strcmp(cmd, "ls") == 0 || u_strncmp(cmd, "ls ", 3) == 0) {
        const char *path = (cmd[2] == ' ' && cmd[3] != 0) ? (cmd + 3) : "/";
        char out[1024];
        long n = nexos_syscall4(SYS_VFS_LIST, (uint64_t)(uintptr_t)path,
                                (uint64_t)u_strlen(path), (uint64_t)(uintptr_t)out,
                                sizeof(out) - 1);
        if (n >= 0) {
            out[n] = 0;
            u_puts(out);
        } else {
            u_puts("ls error\n");
        }
    } else if (u_strncmp(cmd, "cat ", 4) == 0) {
        const char *path = cmd + 4;
        char out[1024];
        long n = nexos_syscall4(SYS_VFS_READ, (uint64_t)(uintptr_t)path,
                                (uint64_t)u_strlen(path), (uint64_t)(uintptr_t)out,
                                sizeof(out) - 1);
        if (n >= 0) {
            out[n] = 0;
            u_puts(out);
            if (n == 0 || out[n - 1] != '\n') u_puts("\n");
        } else {
            u_puts("cat error (not found)\n");
        }
    } else if (u_strncmp(cmd, "write ", 6) == 0) {
        const char *rest = cmd + 6;
        const char *sp = rest;
        while (*sp && *sp != ' ') sp++;
        if (*sp == ' ') {
            size_t plen = (size_t)(sp - rest);
            const char *txt = sp + 1;
            long n = nexos_syscall4(SYS_VFS_WRITE, (uint64_t)(uintptr_t)rest,
                                    (uint64_t)plen, (uint64_t)(uintptr_t)txt,
                                    (uint64_t)u_strlen(txt));
            if (n >= 0) {
                u_puts("wrote ");
                u_put_u64((uint64_t)n);
                u_puts(" bytes\n");
            } else {
                u_puts("write error\n");
            }
        } else {
            u_puts("usage: write <path> <text>\n");
        }
    } else if (u_strncmp(cmd, "mkdir ", 6) == 0) {
        const char *p = cmd + 6;
        long r = nexos_syscall(SYS_VFS_MKDIR, (uint64_t)(uintptr_t)p, (uint64_t)u_strlen(p), 0);
        u_puts(r == 0 ? "mkdir ok\n" : "mkdir error\n");
    } else if (u_strncmp(cmd, "rm ", 3) == 0) {
        const char *p = cmd + 3;
        long r = nexos_syscall(SYS_VFS_REMOVE, (uint64_t)(uintptr_t)p, (uint64_t)u_strlen(p), 0);
        u_puts(r == 0 ? "rm ok\n" : "rm error\n");
    } else if (u_strcmp(cmd, "sync") == 0) {
        long r = nexos_syscall(SYS_VFS_SYNC, 0, 0, 0);
        u_puts(r == 0 ? "sync ok\n" : "sync error\n");
    } else if (u_strcmp(cmd, "ifconfig") == 0) {
        char out[1024];
        long n = nexos_syscall(SYS_NET_INFO, (uint64_t)(uintptr_t)out, sizeof(out) - 1, 0);
        if (n >= 0) {
            out[n] = 0;
            u_puts(out);
        } else {
            u_puts("ifconfig error\n");
        }
    } else if (u_strcmp(cmd, "netstat") == 0) {
        char out[1024];
        long n = nexos_syscall(SYS_NET_STAT, (uint64_t)(uintptr_t)out, sizeof(out) - 1, 0);
        if (n >= 0) {
            out[n] = 0;
            u_puts(out);
        } else {
            u_puts("netstat error\n");
        }
    } else if (u_strncmp(cmd, "ping ", 5) == 0) {
        const char *ip = cmd + 5;
        char out[1024];
        long n = nexos_syscall4(SYS_NET_PING, (uint64_t)(uintptr_t)ip,
                                (uint64_t)u_strlen(ip), (uint64_t)(uintptr_t)out,
                                sizeof(out) - 1);
        if (n >= 0) {
            out[n] = 0;
            u_puts(out);
        } else {
            u_puts("ping error\n");
        }
    } else if (u_strncmp(cmd, "dns ", 4) == 0) {
        const char *host = cmd + 4;
        char out[256];
        long n = nexos_syscall4(SYS_NET_DNS, (uint64_t)(uintptr_t)host,
                                (uint64_t)u_strlen(host), (uint64_t)(uintptr_t)out,
                                sizeof(out) - 1);
        if (n >= 0) {
            out[n] = 0;
            u_puts(out);
        } else {
            u_puts("dns resolution failed\n");
        }
    } else if (u_strcmp(cmd, "services") == 0) {
        char out[1024];
        long n = nexos_syscall(SYS_SVC_LIST, (uint64_t)(uintptr_t)out, sizeof(out) - 1, 0);
        if (n >= 0) {
            out[n] = 0;
            u_puts(out);
        } else {
            u_puts("services error\n");
        }
    } else if (u_strncmp(cmd, "svc restart ", 12) == 0) {
        const char *name = cmd + 12;
        long r = nexos_syscall(SYS_SVC_CTRL, (uint64_t)(uintptr_t)name, (uint64_t)u_strlen(name), 1);
        if (r >= 0) {
            u_puts("service restarted\n");
        } else {
            u_puts("svc restart failed\n");
        }
    } else if (u_strncmp(cmd, "svc start ", 10) == 0) {
        const char *name = cmd + 10;
        long r = nexos_syscall(SYS_SVC_CTRL, (uint64_t)(uintptr_t)name, (uint64_t)u_strlen(name), 2);
        u_puts(r >= 0 ? "service started\n" : "svc start failed\n");
    } else if (u_strncmp(cmd, "svc stop ", 9) == 0) {
        const char *name = cmd + 9;
        long r = nexos_syscall(SYS_SVC_CTRL, (uint64_t)(uintptr_t)name, (uint64_t)u_strlen(name), 0);
        u_puts(r >= 0 ? "service stopped\n" : "svc stop failed\n");
    } else if (u_strcmp(cmd, "mmaptest") == 0) {
        /* Verify W+X rejection (prot = 2|4 = 6) */
        long r_wx = nexos_syscall(SYS_MMAP, 0, 4096, 6);
        long va = nexos_syscall(SYS_MMAP, 0, 4096, 2);
        if (r_wx == -22 && va > 0) {
            volatile uint64_t *p = (volatile uint64_t *)(uintptr_t)va;
            p[0] = 0x4E45584F534D4D50ULL;
            uint64_t rb = p[0];
            long freed = nexos_syscall(SYS_MUNMAP, (uint64_t)va, 4096, 0);
            long post_unmap = nexos_syscall(SYS_WRITE, 1, (uint64_t)va, 8);
            if (rb == 0x4E45584F534D4D50ULL && freed == 1 && post_unmap == -14) {
                u_puts("mmaptest OK (W^X rejected, RW mapped/verified, munmap EFAULT OK)\n");
            } else {
                u_puts("mmaptest read/unmap mismatch\n");
            }
        } else {
            u_puts("mmaptest alloc failed\n");
        }
    } else if (u_strcmp(cmd, "ipctest") == 0) {
        const char *cname = "el0.test";
        long cid = nexos_syscall(SYS_IPC_SEND, 0, (uint64_t)(uintptr_t)cname, (uint64_t)u_strlen(cname));
        const char *msg = "hello-ipc-el0";
        long sr = (cid > 0) ? nexos_syscall(SYS_IPC_SEND, (uint64_t)cid, (uint64_t)(uintptr_t)msg, (uint64_t)u_strlen(msg)) : -1;
        char rbuf[64];
        long rr = (sr > 0) ? nexos_syscall4(SYS_IPC_RECV, (uint64_t)cid, (uint64_t)(uintptr_t)rbuf, sizeof(rbuf) - 1, 0) : -1;
        if (rr > 0) {
            rbuf[rr] = 0;
            u_puts("ipctest OK: ");
            u_puts(rbuf);
            u_puts("\n");
        } else {
            u_puts("ipctest failed\n");
        }
    } else if (u_strcmp(cmd, "ai") == 0 || u_strncmp(cmd, "ai ", 3) == 0) {
        const char *sub = (cmd[2] == ' ') ? (cmd + 3) : "status";
        uint64_t op = 0;
        const char *arg = "";
        if (u_strcmp(sub, "status") == 0) { op = 0; }
        else if (u_strncmp(sub, "load ", 5) == 0) { op = 1; arg = sub + 5; }
        else if (u_strcmp(sub, "load") == 0) { op = 1; arg = "/disk/MODEL.NXM"; }
        else if (u_strncmp(sub, "ask ", 4) == 0) { op = 2; arg = sub + 4; }
        else if (u_strcmp(sub, "bench") == 0) { op = 3; }
        else if (u_strcmp(sub, "unload") == 0) { op = 4; }
        else { op = 0; }
        char out[1536];
        long n = nexos_syscall5(SYS_AI_CMD, op, (uint64_t)(uintptr_t)arg, (uint64_t)u_strlen(arg),
                                (uint64_t)(uintptr_t)out, sizeof(out) - 1);
        if (n >= 0) {
            out[n] = 0;
            u_puts(out);
        } else {
            u_puts("ai command unavailable/failed\n");
        }
    } else if (u_strcmp(cmd, "users") == 0) {
        char out[1024];
        long n = nexos_syscall(SYS_SECURITY, 2, (uint64_t)(uintptr_t)out, sizeof(out) - 1);
        if (n >= 0) {
            out[n] = 0;
            u_puts(out);
        } else {
            u_puts("users error\n");
        }
    } else if (u_strncmp(cmd, "setup ", 6) == 0) {
        const char *rest = cmd + 6;
        const char *sp = rest;
        while (*sp && *sp != ' ') sp++;
        if (*sp == ' ' && sp > rest && *(sp + 1) != 0) {
            size_t ulen = (size_t)(sp - rest);
            const char *pass = sp + 1;
            long r = nexos_syscall5(SYS_SECURITY, 1, (uint64_t)(uintptr_t)rest, (uint64_t)ulen,
                                    (uint64_t)(uintptr_t)pass, (uint64_t)u_strlen(pass));
            if (r == 0) {
                u_puts("Initial admin created and persisted.\n");
            } else if (r == -17) {
                u_puts("Setup already locked (admin already exists).\n");
            } else {
                u_puts("Setup failed (username 1..32 alnum/-/_ and password >= 8 chars).\n");
            }
        } else {
            u_puts("usage: setup <username> <password>\n");
        }
    } else if (u_strcmp(cmd, "reboot") == 0) {
        u_puts("Rebooting via PSCI...\n");
        nexos_syscall(SYS_POWER, 1, 0, 0);
    } else if (u_strcmp(cmd, "dmesg") == 0) {
        char out[2048];
        long n = nexos_syscall(SYS_DMESG, (uint64_t)(uintptr_t)out, sizeof(out) - 1, 0);
        if (n >= 0) {
            out[n] = 0;
            u_puts(out);
        } else {
            u_puts("dmesg error\n");
        }
    } else if (u_strncmp(cmd, "echo ", 5) == 0) {
        u_puts(cmd + 5);
        u_puts("\n");
    } else if (u_strcmp(cmd, "fault") == 0) {
        u_puts("Attempting illegal EL0 read at kernel address 0x40080000...\n");
        volatile uint64_t *kern_ptr = (volatile uint64_t *)0x40080000ULL;
        (void)*kern_ptr;
    } else {
        u_puts("Unknown command: ");
        u_puts(cmd);
        u_puts(" (type 'help')\n");
    }
}

int user_main(uint64_t mode) {
    (void)read_current_el_safe_probe();

    /* Mode 1: automated EL0 isolation + syscall EFAULT / W^X verification probe */
    if (mode == 1) {
        long pid = nexos_syscall(SYS_GETPID, 0, 0, 0);
        u_puts("[EL0-probe] Running in EL0 (pid=");
        u_put_u64((uint64_t)pid);
        u_puts("). Testing syscall EFAULT & W^X checks...\n");

        long r_unmapped = nexos_syscall(SYS_WRITE, 1, 0x0000010005000000ULL, 16);
        long r_wx_write = nexos_syscall(SYS_READ, 0, 0x0000010000000000ULL, 8);
        const char *trav = "/ram/../secret";
        char tmp[16];
        long r_trav = nexos_syscall4(SYS_VFS_READ, (uint64_t)(uintptr_t)trav,
                                     (uint64_t)u_strlen(trav),
                                     (uint64_t)(uintptr_t)tmp, sizeof(tmp));
        if (r_unmapped == -14 && r_wx_write == -14 && r_trav == -5) {
            u_puts("[EL0-probe] Syscall EFAULT & W^X checks OK.\n");
        } else {
            u_puts("[EL0-probe] ERROR: unexpected negative check result!\n");
            return 2;
        }

        u_puts("[EL0-probe] Probing illegal kernel RAM read 0x40080000...\n");
        volatile uint64_t *kern_ptr = (volatile uint64_t *)0x40080000ULL;
        (void)*kern_ptr;
        u_puts("[EL0-probe] ERROR: kernel read did NOT fault!\n");
        return 1;
    }

    /* Mode 0: Interactive EL0 UART shell */
    long pid = nexos_syscall(SYS_GETPID, 0, 0, 0);
    u_puts("\n[EL0-shell] NexOS Userspace Shell started in EL0 (pid=");
    u_put_u64((uint64_t)pid);
    u_puts(")\n");
    print_sysinfo();
    u_puts("nexos# ");

    char line[128];
    size_t len = 0;

    for (;;) {
        char ch = 0;
        long r = nexos_syscall(SYS_READ, 0, (uint64_t)(uintptr_t)&ch, 1);
        if (r <= 0) {
            nexos_syscall(SYS_SLEEP_MS, 10, 0, 0);
            continue;
        }
        if (ch == '\r' || ch == '\n') {
            u_puts("\n");
            line[len] = 0;
            if (u_strcmp(line, "exit") == 0) {
                u_puts("[EL0-shell] Exiting.\n");
                return 0;
            }
            run_command(line);
            len = 0;
            u_puts("nexos# ");
        } else if ((ch == 0x7f || ch == '\b') && len > 0) {
            len--;
            u_puts("\b \b");
        } else if (ch >= 0x20 && ch < 0x7f && len + 1 < sizeof(line)) {
            line[len++] = ch;
            nexos_syscall(SYS_WRITE, 1, (uint64_t)(uintptr_t)&ch, 1);
        }
    }
}
