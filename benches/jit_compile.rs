// Copyright 2020 Solana <alexander@solana.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![feature(test)]

extern crate solana_rbpf;
extern crate test;

use solana_rbpf::{user_error::UserError, vm::EbpfVm};
use std::{fs::File, io::Read};
use test::Bencher;

#[bench]
fn bench_init_vm(bencher: &mut Bencher) {
    let mut file = File::open("tests/elfs/pass_stack_reference.so").unwrap();
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();
    let executable = EbpfVm::<UserError>::create_executable_from_elf(&elf, None).unwrap();
    bencher.iter(|| EbpfVm::<UserError>::new(executable.as_ref(), &[], &[]).unwrap());
}

#[bench]
fn bench_jit_compile(bencher: &mut Bencher) {
    let mut file = File::open("tests/elfs/pass_stack_reference.so").unwrap();
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();
    let executable = EbpfVm::<UserError>::create_executable_from_elf(&elf, None).unwrap();
    bencher.iter(|| {
        let mut vm = EbpfVm::<UserError>::new(executable.as_ref(), &[], &[]).unwrap();
        vm.jit_compile().unwrap()
    });
}
