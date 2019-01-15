#!/bin/bash -ex

# Requires Latest release of Solana's custom LLVM
#https://github.com/solana-labs/llvm-builder/releases

LLVM_DIR=../../../solana/sdk/bpf/llvm-native/bin/

"$LLVM_DIR"clang -Werror -target bpf -O2 -fno-builtin -fPIC -o noop.o -c noop.c
"$LLVM_DIR"ld.lld -z notext -shared --Bdynamic -o noop.so noop.o
rm noop.o

"$LLVM_DIR"clang -Werror -target bpf -O2 -fno-builtin -fPIC -o unresolved_helper.o -c unresolved_helper.c
"$LLVM_DIR"ld.lld -z notext -shared --Bdynamic -o unresolved_helper.so unresolved_helper.o
rm unresolved_helper.o

"$LLVM_DIR"clang -Werror -target bpf -O2 -fno-builtin -fPIC -o entrypoint.o -c entrypoint.c
"$LLVM_DIR"clang -Werror -target bpf -O2 -fno-builtin -fPIC -o helper.o -c helper.c
"$LLVM_DIR"ld.lld -z notext -shared --Bdynamic -entry entrypoint -o multiple_file.so entrypoint.o helper.o
rm entrypoint.o
rm helper.o

"$LLVM_DIR"clang -Werror -target bpf -O2 -fno-builtin -fPIC -o relative_call.o -c relative_call.c
"$LLVM_DIR"ld.lld -z notext -shared --Bdynamic -entry entrypoint -o relative_call.so relative_call.o
rm relative_call.o

"$LLVM_DIR"clang -Werror -target bpf -O2 -fno-builtin -fPIC -o scratch_registers.o -c scratch_registers.c
"$LLVM_DIR"ld.lld -z notext -shared --Bdynamic -entry entrypoint -o scratch_registers.so scratch_registers.o
rm scratch_registers.o

"$LLVM_DIR"clang -Werror -target bpf -O2 -fno-builtin -fPIC -o pass_stack_reference.o -c pass_stack_reference.c
"$LLVM_DIR"ld.lld -z notext -shared --Bdynamic -entry entrypoint -o pass_stack_reference.so pass_stack_reference.o
rm pass_stack_reference.o