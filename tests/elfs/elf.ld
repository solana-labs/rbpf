PHDRS
{
  text PT_LOAD ;
  rodata PT_LOAD ;
  stack PT_GNU_STACK ;
  heap PT_LOAD ;
  dynsym PT_LOAD ;
  other PT_NULL ;
}

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
