#!/bin/bash -ex

# Requires Latest release of Solana's custom LLVM
# https://github.com/solana-labs/platform-tools/releases

TOOLCHAIN=../../../agave/sdk/sbf/dependencies/platform-tools
RC_COMMON="$TOOLCHAIN/rust/bin/rustc --target sbf-solana-solana --crate-type lib -C panic=abort -C opt-level=2"
RC="$RC_COMMON -C target_cpu=sbfv2"
RC_V1="$RC_COMMON -C target_cpu=generic"
LD_COMMON="$TOOLCHAIN/llvm/bin/ld.lld -z notext -shared --Bdynamic -entry entrypoint"
LD="$LD_COMMON --script elf.ld"
LD_V1="$LD_COMMON --script elf_sbpfv0.ld"

$RC -o strict_header.o strict_header.rs
$LD -o strict_header.so strict_header.o

$RC_V1 -o relative_call.o relative_call.rs
$LD_V1 -o relative_call_sbpfv0.so relative_call.o

$RC_V1 -o syscall_reloc_64_32.o syscall_reloc_64_32.rs
$LD_V1 -o syscall_reloc_64_32_sbpfv0.so syscall_reloc_64_32.o

$RC_V1 -o bss_section.o bss_section.rs
$LD_V1 -o bss_section_sbpfv0.so bss_section.o

$RC_V1 -o data_section.o data_section.rs
$LD_V1 -o data_section_sbpfv0.so data_section.o

$RC_V1 -o rodata_section.o rodata_section.rs
$LD_V1 -o rodata_section_sbpfv0.so rodata_section.o

$RC -o program_headers_overflow.o rodata_section.rs
"$TOOLCHAIN"/llvm/bin/ld.lld -z notext -shared --Bdynamic -entry entrypoint --script program_headers_overflow.ld --noinhibit-exec -o program_headers_overflow.so program_headers_overflow.o

$RC_V1 -o struct_func_pointer.o struct_func_pointer.rs
$LD_V1 -o struct_func_pointer_sbpfv0.so struct_func_pointer.o

$RC_V1 -o reloc_64_64.o reloc_64_64.rs
$LD_V1 -o reloc_64_64_sbpfv0.so reloc_64_64.o

$RC_V1 -o reloc_64_relative.o reloc_64_relative.rs
$LD_V1 -o reloc_64_relative_sbpfv0.so reloc_64_relative.o

$RC_V1 -o reloc_64_relative_data.o reloc_64_relative_data.rs
$LD_V1 -o reloc_64_relative_data_sbpfv0.so reloc_64_relative_data.o

# $RC_V1 -o callx_unaligned.o callx_unaligned.rs
# $LD_V1 -o callx_unaligned.so callx_unaligned.o

rm *.o
