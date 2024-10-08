PHDRS
{
  text PT_LOAD ;
  rodata PT_LOAD ;
  stack PT_GNU_STACK ;
  heap PT_LOAD ;
  other PT_NULL ;
}

SECTIONS
{
  # . = SIZEOF_HEADERS;
  .text 0x100000000 : { *(.text*) } :text
  .rodata : { *(.rodata*) } :rodata
  .stack 0x200000000 : { *(.bss.stack*) } :stack
  .heap 0x300000000 : { *(.bss.heap*) } :heap
  .symtab : { *(.symtab) } :other
  .shstrtab : { *(.shstrtab) } :other
  .strtab : { *(.strtab) } :other
  /DISCARD/ : {
      *(.comment*)
      *(.eh_frame*)
      *(*hash*)
      *(.bss*)
      *(.data*)
      *(.rel*)
      *(.dyn*)
    }
}
