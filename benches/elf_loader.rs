// Copyright 2020 Solana Maintainers <maintainers@solana.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![feature(test)]

extern crate solana_rbpf;
extern crate test;
extern crate test_utils;

use solana_rbpf::{
    ebpf::hash_symbol_name,
    user_error::UserError,
    vm::{Config, DefaultInstructionMeter, EbpfVm, Executable},
};
use std::{fs::File, io::Read};
use test::Bencher;
use test_utils::bpf_syscall_u64;

#[bench]
fn bench_load_elf(bencher: &mut Bencher) {
    let mut file = File::open("tests/elfs/noro.so").unwrap();
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();
    bencher.iter(|| {
        Executable::<UserError, DefaultInstructionMeter>::from_elf(&elf, None, Config::default())
            .unwrap()
    });
}

#[bench]
fn bench_load_elf_and_init_vm_without_syscall(bencher: &mut Bencher) {
    let mut file = File::open("tests/elfs/noro.so").unwrap();
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();
    bencher.iter(|| {
        let executable = Executable::<UserError, DefaultInstructionMeter>::from_elf(
            &elf,
            None,
            Config::default(),
        )
        .unwrap();
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
        let mut executable = Executable::<UserError, DefaultInstructionMeter>::from_elf(
            &elf,
            None,
            Config::default(),
        )
        .unwrap();
        executable
            .register_syscall(hash_symbol_name(b"log_64"), bpf_syscall_u64)
            .unwrap();
        let mut _vm =
            EbpfVm::<UserError, DefaultInstructionMeter>::new(executable.as_ref(), &[], &[])
                .unwrap();
    });
}
