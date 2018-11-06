#!/bin/bash -ex

# Requires LLVM 7.x or newer
#http://releases.llvm.org/download.html

/usr/local/opt/llvm/bin/clang -Werror -target bpf -O2 -emit-llvm -fno-builtin -o noop.bc -c noop.c
/usr/local/opt/llvm/bin/llc -march=bpf -filetype=obj -o noop.o noop.bc
rm noop.bc

