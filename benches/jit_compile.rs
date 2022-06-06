// Copyright 2020 Solana Maintainers <maintainers@solana.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![feature(test)]

extern crate solana_rbpf;
extern crate test;

use solana_rbpf::{
    elf::Executable,
    user_error::UserError,
    vm::{Config, EbpfVm, SyscallRegistry, TestInstructionMeter, VerifiedExecutable},
};
use std::{fs::File, io::Read};
use test::Bencher;
use test_utils::TautologyVerifier;

#[bench]
fn bench_init_vm(bencher: &mut Bencher) {
    let mut file = File::open("tests/elfs/pass_stack_reference.so").unwrap();
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();
    let executable = Executable::<UserError, TestInstructionMeter>::from_elf(
        &elf,
        Config::default(),
        SyscallRegistry::default(),
    )
    .unwrap();
    let verified_executable =
        VerifiedExecutable::<TautologyVerifier, UserError, TestInstructionMeter>::from_executable(
            executable,
        )
        .unwrap();
    bencher.iter(|| EbpfVm::new(&verified_executable, &mut [], Vec::new()).unwrap());
}

#[cfg(not(windows))]
#[bench]
fn bench_jit_compile(bencher: &mut Bencher) {
    let mut file = File::open("tests/elfs/pass_stack_reference.so").unwrap();
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();
    let executable = Executable::<UserError, TestInstructionMeter>::from_elf(
        &elf,
        Config::default(),
        SyscallRegistry::default(),
    )
    .unwrap();
    let mut verified_executable =
        VerifiedExecutable::<TautologyVerifier, UserError, TestInstructionMeter>::from_executable(
            executable,
        )
        .unwrap();
    bencher.iter(|| verified_executable.jit_compile().unwrap());
}
