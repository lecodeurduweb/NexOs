/* NexOS EL0 Userspace Linker Script
 * Mapped at isolated user virtual address 0x0000_0100_0000_0000 (L0[2]).
 */
ENTRY(_user_start)

PHDRS
{
    rx PT_LOAD FLAGS(5); /* R | X */
    rw PT_LOAD FLAGS(6); /* R | W */
}

SECTIONS
{
    . = 0x0000010000000000;

    .text : ALIGN(4096) {
        KEEP(*(.text.entry))
        *(.text .text.*)
        . = ALIGN(4096);
    } :rx

    .rodata : ALIGN(4096) {
        *(.rodata .rodata.*)
        . = ALIGN(4096);
    } :rx

    .data : ALIGN(4096) {
        *(.data .data.*)
    } :rw

    .bss : ALIGN(4096) {
        *(.bss .bss.*)
        *(COMMON)
    } :rw

    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
        *(.interp)
        *(.dynamic)
        *(.dynsym)
        *(.dynstr)
        *(.gnu.hash)
        *(.hash)
        *(.got*)
    }
}
