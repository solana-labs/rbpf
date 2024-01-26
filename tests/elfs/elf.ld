PHDRS
{
  text PT_LOAD ;
  rodata PT_LOAD ;
  stack PT_GNU_STACK ;
  heap PT_NULL ;
  other PT_DYNAMIC ;
}

SECTIONS
{
  # . = SIZEOF_HEADERS;
  .text 0x100000000 : { *(.text*) } :text
  .rodata : { *(.rodata*) } :rodata
  .stack 0x200000000 : { *(.bss.stack*) } :stack
  .heap 0x300000000 : { *(.bss.heap*) } :heap
  . = 0xF00000000 ;
  .data.rel.ro : { *(.data.rel.ro*) } :other
  .dynamic : { *(.dynamic) } :other
  .dynsym : { *(.dynsym) } :other
  .dynstr : { *(.dynstr) } :other
  .rel.dyn : { *(.rel.dyn) } :other
  .data : { *(.data*) } :other
  /DISCARD/ : {
      *(.eh_frame*)
      *(.gnu.hash*)
      *(.hash*)
      *(.bss*)
    }
}
