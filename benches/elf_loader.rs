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
    user_error::UserError,
    vm::{Config, DefaultInstructionMeter, Executable, SyscallObject, SyscallRegistry},
};
use std::{fs::File, io::Read};
use test::Bencher;
use test_utils::BpfSyscallU64;

#[bench]
fn bench_load_elf(bencher: &mut Bencher) {
    let mut file = File::open("tests/elfs/noro.so").unwrap();
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();
    bencher.iter(|| {
        <dyn Executable<UserError, DefaultInstructionMeter>>::from_elf(
            &elf,
            None,
            Config::default(),
        )
        .unwrap()
    });
}

#[bench]
fn bench_load_elf_without_syscall(bencher: &mut Bencher) {
    let mut file = File::open("tests/elfs/noro.so").unwrap();
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();
    bencher.iter(|| {
        let executable = <dyn Executable<UserError, DefaultInstructionMeter>>::from_elf(
            &elf,
            None,
            Config::default(),
        )
        .unwrap();
        executable
    });
}

#[bench]
fn bench_load_elf_with_syscall(bencher: &mut Bencher) {
    let mut file = File::open("tests/elfs/noro.so").unwrap();
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();
    bencher.iter(|| {
        let mut executable = <dyn Executable<UserError, DefaultInstructionMeter>>::from_elf(
            &elf,
            None,
            Config::default(),
        )
        .unwrap();
        let mut syscall_registry = SyscallRegistry::default();
        syscall_registry
            .register_syscall_by_name::<UserError, _>(b"log_64", BpfSyscallU64::call)
            .unwrap();
        executable.set_syscall_registry(syscall_registry);
        executable
    });
}
