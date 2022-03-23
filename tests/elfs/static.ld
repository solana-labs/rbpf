PHDRS {
    /*header PT_PHDR FILEHDR PHDRS;*/
    prog PT_LOAD FLAGS(5);
    stack PT_GNU_STACK FLAGS(6);
    heap PT_NULL FLAGS(6);
}

SECTIONS {
    .text 0x100000000 : {
        *(.text*)
    } :prog
    .rodata : {
        *(.rodata*)
    } :prog
    .stack 0x200000000 (NOLOAD) : {
        . = .;
    } :stack
    .heap 0x300000000 (NOLOAD) : {
        *(.bss*)
    } :heap
    /DISCARD/ : {
        *(.data*)
        *(*.hash)
        *(.eh_frame)
        *(.dynamic)
        *(*.dyn*)
    }
}
