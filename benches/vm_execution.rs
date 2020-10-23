// Copyright 2020 Solana Maintainers <maintainers@solana.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![feature(test)]

extern crate solana_rbpf;
extern crate test;

use solana_rbpf::{
    user_error::UserError,
    vm::{Config, DefaultInstructionMeter, EbpfVm, Executable},
};
use std::{fs::File, io::Read};
use test::Bencher;

#[bench]
fn bench_init_interpreter_execution(bencher: &mut Bencher) {
    let mut file = File::open("tests/elfs/pass_stack_reference.so").unwrap();
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();
    let executable =
        Executable::<UserError, DefaultInstructionMeter>::from_elf(&elf, None, Config::default())
            .unwrap();
    let mut vm =
        EbpfVm::<UserError, DefaultInstructionMeter>::new(executable.as_ref(), &[], &[]).unwrap();
    bencher.iter(|| {
        vm.execute_program_interpreted(&mut DefaultInstructionMeter {})
            .unwrap()
    });
}

#[cfg(not(windows))]
#[bench]
fn bench_init_jit_execution(bencher: &mut Bencher) {
    let mut file = File::open("tests/elfs/pass_stack_reference.so").unwrap();
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();
    let mut executable =
        Executable::<UserError, DefaultInstructionMeter>::from_elf(&elf, None, Config::default())
            .unwrap();
    executable.jit_compile().unwrap();
    let mut vm =
        EbpfVm::<UserError, DefaultInstructionMeter>::new(executable.as_ref(), &[], &[]).unwrap();
    bencher.iter(|| {
        vm.execute_program_jit(&mut DefaultInstructionMeter {})
            .unwrap()
    });
}
