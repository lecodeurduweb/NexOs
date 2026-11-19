/* NexOS Linker Script — QEMU 'virt' machine
 *
 * QEMU 'virt' RAM begins at physical address 0x40000000.
 * QEMU places the generated Device Tree Blob (DTB) at 0x40000000 and passes
 * its physical address in register x0 at kernel entry.
 * We link the kernel at 0x40080000 (512 KiB offset) to avoid overlapping the DTB.
 */
ENTRY(_start)

MEMORY
{
    RAM (rwx) : ORIGIN = 0x40080000, LENGTH = 64M
}

SECTIONS
{
    . = 0x40080000;
    __kernel_start = .;

    .text : ALIGN(4096) {
        KEEP(*(.text.boot))
        *(.text .text.*)
        . = ALIGN(4096);
    } > RAM
    __text_end = .;

    .rodata : ALIGN(4096) {
        *(.rodata .rodata.*)
        . = ALIGN(4096);
    } > RAM
    __rodata_end = .;

    .data : ALIGN(4096) {
        *(.data .data.*)
    } > RAM

    . = ALIGN(16);
    __bss_start = .;
    .bss (NOLOAD) : ALIGN(16) {
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(16);
    } > RAM
    __bss_end = .;

    /* Initial 128 KiB kernel boot stack (grows downward, 16-byte aligned) */
    . = ALIGN(4096);
    __stack_bottom = .;
    . += 0x20000;
    . = ALIGN(16);
    __stack_top = .;

    __kernel_end = .;

    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}
