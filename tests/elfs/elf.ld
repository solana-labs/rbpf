SECTIONS
{
  .text 0x000000000 : { *(.text*) } :text
  .rodata 0x100000000 : { *(.rodata*) } :rodata
  .bss.stack 0x200000000 : { *(.bss.stack*) } :stack
  .bss.heap 0x300000000 : { *(.bss.heap*) } :heap
  .dynsym 0xFFFFFFFF00000000 : { *(.dynsym) } :dynsym
  .dynstr : { *(.dynstr) } :other
  .dynamic : { *(.dynamic) } :other
  .symtab : { *(.symtab) } :other
  .shstrtab : { *(.shstrtab) } :other
  .strtab : { *(.strtab) } :other
  /DISCARD/ : {
      *(.comment*)
      *(.eh_frame*)
      *(*hash*)
      *(.bss*)
      *(.data*)
      *(.rel.dyn*)
    }
}

PHDRS
{
  text PT_LOAD FLAGS(1);
  rodata PT_LOAD FLAGS(4);
  stack PT_GNU_STACK FLAGS(6);
  heap PT_LOAD FLAGS(6);
  dynsym PT_NULL FLAGS(0);
  other PT_NULL FLAGS(0);
}
