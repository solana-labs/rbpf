// Copyright 2020 Solana Maintainers <maintainers@solana.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![feature(test)]

extern crate solana_rbpf;
extern crate test;

use solana_rbpf::{
    ebpf::hash_symbol_name,
    error::EbpfError,
    memory_region::MemoryMapping,
    user_error::UserError,
    vm::{DefaultInstructionMeter, EbpfVm, Executable, Syscall},
};
use std::{fs::File, io::Read};
use test::Bencher;

type ExecResult = Result<u64, EbpfError<UserError>>;

fn bpf_syscall_u64(
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    memory_mapping: &MemoryMapping,
) -> ExecResult {
    println!(
        "dump_64: {:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:?}",
        arg1, arg2, arg3, arg4, arg5, memory_mapping as *const _
    );
    Ok(0)
}

#[bench]
fn bench_load_elf(bencher: &mut Bencher) {
    let mut file = File::open("tests/elfs/noro.so").unwrap();
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();
    bencher.iter(|| Executable::<UserError>::from_elf(&elf, None).unwrap());
}

#[bench]
fn bench_load_elf_and_init_vm_without_syscall(bencher: &mut Bencher) {
    let mut file = File::open("tests/elfs/noro.so").unwrap();
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();
    bencher.iter(|| {
        let executable = Executable::<UserError>::from_elf(&elf, None).unwrap();
        let _vm = EbpfVm::<UserError, DefaultInstructionMeter>::new(executable.as_ref(), &[], &[])
            .unwrap();
    });
}

#[bench]
fn bench_load_elf_and_init_vm_with_syscall(bencher: &mut Bencher) {
    let mut file = File::open("tests/elfs/noro.so").unwrap();
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();
    bencher.iter(|| {
        let executable = Executable::<UserError>::from_elf(&elf, None).unwrap();
        let mut vm =
            EbpfVm::<UserError, DefaultInstructionMeter>::new(executable.as_ref(), &[], &[])
                .unwrap();
        vm.register_syscall(
            hash_symbol_name(b"log_64"),
            Syscall::Function(bpf_syscall_u64),
        )
        .unwrap();
    });
}
