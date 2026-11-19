/* NexOS Linker Script — Raspberry Pi 4 Model B (BCM2711, AArch64)
 *
 * VideoCore firmware (start4.elf) with arm_64bit=1 loads kernel8.img
 * at physical address 0x80000 and passes the DTB physical address in x0.
 */
ENTRY(_start)

MEMORY
{
    RAM (rwx) : ORIGIN = 0x80000, LENGTH = 64M
}

SECTIONS
{
    . = 0x80000;
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
