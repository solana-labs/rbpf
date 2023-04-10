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
    verifier::{RequisiteVerifier, TautologyVerifier},
    vm::{BuiltInProgram, Config, TestContextObject},
};
use std::{fs::File, io::Read, sync::Arc};
use test::Bencher;
use test_utils::create_vm;

#[bench]
fn bench_init_vm(bencher: &mut Bencher) {
    let mut file = File::open("tests/elfs/pass_stack_reference.so").unwrap();
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();
    let executable = Executable::<TautologyVerifier, TestContextObject>::from_elf(
        &elf,
        Arc::new(BuiltInProgram::new_loader(Config::default())),
    )
    .unwrap();
    let verified_executable =
        Executable::<RequisiteVerifier, TestContextObject>::verified(executable).unwrap();
    bencher.iter(|| {
        let mut context_object = TestContextObject::default();
        create_vm!(
            _vm,
            &verified_executable,
            &mut context_object,
            stack,
            heap,
            Vec::new(),
            None
        );
    });
}

#[cfg(not(windows))]
#[bench]
fn bench_jit_compile(bencher: &mut Bencher) {
    let mut file = File::open("tests/elfs/pass_stack_reference.so").unwrap();
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();
    let executable = Executable::<TautologyVerifier, TestContextObject>::from_elf(
        &elf,
        Arc::new(BuiltInProgram::new_loader(Config::default())),
    )
    .unwrap();
    let mut verified_executable =
        Executable::<RequisiteVerifier, TestContextObject>::verified(executable).unwrap();
    bencher.iter(|| verified_executable.jit_compile().unwrap());
}
