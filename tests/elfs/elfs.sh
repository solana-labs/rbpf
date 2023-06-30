#!/bin/bash -ex

# Requires Latest release of Solana's custom LLVM
#https://github.com/solana-labs/llvm-builder/releases

LLVM_DIR=../../../solana/sdk/sbf/dependencies/sbf-tools/llvm/bin/
CC_FLAGS="-Werror -target sbf -mcpu=sbfv2 -O2 -fno-builtin -fPIC"
LD_FLAGS="-z notext -shared --Bdynamic -entry entrypoint --script elf.ld"

"$LLVM_DIR"clang $CC_FLAGS -o noop.o -c noop.c
"$LLVM_DIR"ld.lld $LD_FLAGS -o noop.so noop.o
rm noop.o

"$LLVM_DIR"clang $CC_FLAGS -o noro.o -c noro.c
"$LLVM_DIR"ld.lld $LD_FLAGS -o noro.so noro.o
rm noro.o

"$LLVM_DIR"clang $CC_FLAGS -o empty_rodata.o -c empty_rodata.c
"$LLVM_DIR"ld.lld $LD_FLAGS -o empty_rodata.so empty_rodata.o
rm empty_rodata.o

"$LLVM_DIR"clang $CC_FLAGS -o unresolved_syscall.o -c unresolved_syscall.c
"$LLVM_DIR"ld.lld $LD_FLAGS -o unresolved_syscall.so unresolved_syscall.o
rm unresolved_syscall.o

"$LLVM_DIR"clang $CC_FLAGS -o entrypoint.o -c entrypoint.c
"$LLVM_DIR"clang $CC_FLAGS -o multiple_file.o -c multiple_file.c
"$LLVM_DIR"ld.lld $LD_FLAGS -o multiple_file.so entrypoint.o multiple_file.o
rm entrypoint.o
rm multiple_file.o

"$LLVM_DIR"clang $CC_FLAGS -o relative_call.o -c relative_call.c
"$LLVM_DIR"ld.lld $LD_FLAGS -o relative_call.so relative_call.o
rm relative_call.o

"$LLVM_DIR"clang $CC_FLAGS -o reloc_64_64.o -c reloc_64_64.c
"$LLVM_DIR"ld.lld $LD_FLAGS -o reloc_64_64.so reloc_64_64.o
rm reloc_64_64.o

"$LLVM_DIR"clang $CC_FLAGS -o reloc_64_64_high_vaddr.o -c reloc_64_64.c
"$LLVM_DIR"ld.lld -z notext -shared --Bdynamic -entry entrypoint --nmagic --section-start=.text=0x100000000 -o reloc_64_64_high_vaddr.so reloc_64_64_high_vaddr.o
rm reloc_64_64_high_vaddr.o

"$LLVM_DIR"clang $CC_FLAGS -o reloc_64_relative.o -c reloc_64_relative.c
"$LLVM_DIR"ld.lld $LD_FLAGS -o reloc_64_relative.so reloc_64_relative.o
rm reloc_64_relative.o

"$LLVM_DIR"clang $CC_FLAGS -o reloc_64_relative_high_vaddr.o -c reloc_64_relative.c
"$LLVM_DIR"ld.lld $LD_FLAGS --section-start=.text=0x100000000 -o reloc_64_relative_high_vaddr.so reloc_64_relative_high_vaddr.o
rm reloc_64_relative_high_vaddr.o

"$LLVM_DIR"clang $CC_FLAGS -o reloc_64_relative_data.o -c reloc_64_relative_data.c
"$LLVM_DIR"ld.lld $LD_FLAGS -o reloc_64_relative_data.so reloc_64_relative_data.o
rm reloc_64_relative_data.o

"$LLVM_DIR"clang $CC_FLAGS -o reloc_64_relative_data_high_vaddr.o -c reloc_64_relative_data.c
"$LLVM_DIR"ld.lld $LD_FLAGS --section-start=.text=0x100000000 -o reloc_64_relative_data_high_vaddr.so reloc_64_relative_data_high_vaddr.o
rm reloc_64_relative_data_high_vaddr.o

"$LLVM_DIR"clang $CC_FLAGS -o reloc_64_relative_data_pre_sbfv2.o -c reloc_64_relative_data.c
"$LLVM_DIR"ld.lld $LD_FLAGS -o reloc_64_relative_data_pre_sbfv2.so reloc_64_relative_data_pre_sbfv2.o
rm reloc_64_relative_data_pre_sbfv2.o

"$LLVM_DIR"clang $CC_FLAGS -o scratch_registers.o -c scratch_registers.c
"$LLVM_DIR"ld.lld $LD_FLAGS -o scratch_registers.so scratch_registers.o
rm scratch_registers.o

"$LLVM_DIR"clang $CC_FLAGS -o pass_stack_reference.o -c pass_stack_reference.c
"$LLVM_DIR"ld.lld $LD_FLAGS -o pass_stack_reference.so pass_stack_reference.o
rm pass_stack_reference.o

"$LLVM_DIR"clang $CC_FLAGS -o writable_data_section.o -c writable_data_section.c
"$LLVM_DIR"ld.lld $LD_FLAGS -o writable_data_section.so writable_data_section.o
rm writable_data_section.o

"$LLVM_DIR"clang $CC_FLAGS -o bss_section.o -c bss_section.c
"$LLVM_DIR"ld.lld $LD_FLAGS -o bss_section.so bss_section.o
rm bss_section.o

"$LLVM_DIR"clang $CC_FLAGS -o rodata.o -c rodata.c
"$LLVM_DIR"ld.lld $LD_FLAGS -o rodata.so rodata.o
rm rodata.o

"$LLVM_DIR"clang $CC_FLAGS -mcpu=generic -o rodata.o -c rodata.c
"$LLVM_DIR"ld.lld $LD_FLAGS -o rodata_sbpfv1.so rodata.o
rm rodata.o

"$LLVM_DIR"clang $CC_FLAGS -o rodata_high_vaddr.o -c rodata.c
"$LLVM_DIR"ld.lld -z notext -shared --Bdynamic -entry entrypoint --nmagic --section-start=.text=0x100000000 --section-start=.rodata=0x100000020 -o rodata_high_vaddr.so rodata_high_vaddr.o
rm rodata_high_vaddr.o

"$LLVM_DIR"clang $CC_FLAGS -o syscall_static_unknown.o -c syscall_static_unknown.c
"$LLVM_DIR"ld.lld $LD_FLAGS -o syscall_static_unknown.so syscall_static_unknown.o
rm syscall_static_unknown.o

"$LLVM_DIR"clang $CC_FLAGS -o syscall_static.o -c syscall_static.c
"$LLVM_DIR"ld.lld $LD_FLAGS -o syscall_static.so syscall_static.o
rm syscall_static.o

"$LLVM_DIR"clang $CC_FLAGS -o program_headers_overflow.o -c rodata.c
"$LLVM_DIR"ld.lld -z notext -shared --Bdynamic -entry entrypoint --script program_headers_overflow.ld --noinhibit-exec -o program_headers_overflow.so program_headers_overflow.o
rm program_headers_overflow.o

"$LLVM_DIR"clang $CC_FLAGS -fdebug-prefix-map=$(pwd)=. -o scratch_registers_debug.o -c scratch_registers.c
"$LLVM_DIR"ld.lld -z notext -shared --Bdynamic -entry entrypoint --section-start=.text=0x1000 -o scratch_registers_debug.so scratch_registers_debug.o
rm scratch_registers_debug.o

"$LLVM_DIR"clang $CC_FLAGS -o struct_func_pointer.o -c struct_func_pointer.c
"$LLVM_DIR"ld.lld $LD_FLAGS -o struct_func_pointer.so struct_func_pointer.o
rm struct_func_pointer.o
