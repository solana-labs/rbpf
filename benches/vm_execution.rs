// Copyright 2020 Solana Maintainers <maintainers@solana.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![feature(test)]

extern crate solana_rbpf;
extern crate test;

use solana_rbpf::{
    ebpf,
    elf::Executable,
    memory_region::MemoryRegion,
    vm::{Config, EbpfVm, SyscallRegistry, TestContextObject, VerifiedExecutable},
};
use std::{fs::File, io::Read};
use test::Bencher;
use test_utils::TautologyVerifier;

#[bench]
fn bench_init_interpreter_execution(bencher: &mut Bencher) {
    let mut file = File::open("tests/elfs/pass_stack_reference.so").unwrap();
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();
    let executable = Executable::<TestContextObject>::from_elf(
        &elf,
        Config::default(),
        SyscallRegistry::default(),
    )
    .unwrap();
    let verified_executable =
        VerifiedExecutable::<TautologyVerifier, TestContextObject>::from_executable(executable)
            .unwrap();
    let mut context_object = TestContextObject::default();
    let mut vm = EbpfVm::new(
        &verified_executable,
        &mut context_object,
        &mut [],
        Vec::new(),
    )
    .unwrap();
    bencher.iter(|| {
        vm.program_environment.context_object.remaining = 29;
        vm.execute_program_interpreted().unwrap()
    });
}

#[cfg(not(windows))]
#[bench]
fn bench_init_jit_execution(bencher: &mut Bencher) {
    let mut file = File::open("tests/elfs/pass_stack_reference.so").unwrap();
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();
    let executable = Executable::<TestContextObject>::from_elf(
        &elf,
        Config::default(),
        SyscallRegistry::default(),
    )
    .unwrap();
    let mut verified_executable =
        VerifiedExecutable::<TautologyVerifier, TestContextObject>::from_executable(executable)
            .unwrap();
    verified_executable.jit_compile().unwrap();
    let mut context_object = TestContextObject::default();
    let mut vm = EbpfVm::new(
        &verified_executable,
        &mut context_object,
        &mut [],
        Vec::new(),
    )
    .unwrap();
    bencher.iter(|| {
        vm.program_environment.context_object.remaining = 29;
        vm.execute_program_jit().unwrap()
    });
}

#[cfg(not(windows))]
fn bench_jit_vs_interpreter(
    bencher: &mut Bencher,
    assembly: &str,
    config: Config,
    instruction_meter: u64,
    mem: &mut [u8],
) {
    let executable = solana_rbpf::assembler::assemble::<TestContextObject>(
        assembly,
        config,
        SyscallRegistry::default(),
    )
    .unwrap();
    let mut verified_executable =
        VerifiedExecutable::<TautologyVerifier, TestContextObject>::from_executable(executable)
            .unwrap();
    verified_executable.jit_compile().unwrap();
    let mut context_object = TestContextObject::default();
    let mem_region = MemoryRegion::new_writable(mem, ebpf::MM_INPUT_START);
    let mut vm = EbpfVm::new(
        &verified_executable,
        &mut context_object,
        &mut [],
        vec![mem_region],
    )
    .unwrap();
    let interpreter_summary = bencher
        .bench(|bencher| {
            bencher.iter(|| {
                vm.program_environment.context_object.remaining = instruction_meter;
                let result = vm.execute_program_interpreted();
                assert!(result.is_ok(), "{:?}", result);
                assert_eq!(vm.get_total_instruction_count(), instruction_meter);
            });
            Ok(())
        })
        .unwrap()
        .unwrap();
    let jit_summary = bencher
        .bench(|bencher| {
            bencher.iter(|| {
                vm.program_environment.context_object.remaining = instruction_meter;
                let result = vm.execute_program_jit();
                assert!(result.is_ok(), "{:?}", result);
                assert_eq!(vm.get_total_instruction_count(), instruction_meter);
            });
            Ok(())
        })
        .unwrap()
        .unwrap();
    println!(
        "jit_vs_interpreter_ratio={}",
        interpreter_summary.mean / jit_summary.mean
    );
}

#[cfg(not(windows))]
#[bench]
fn bench_jit_vs_interpreter_address_translation(bencher: &mut Bencher) {
    bench_jit_vs_interpreter(
        bencher,
        "
    ldxb r0, [r1]
    add r1, 1
    mov r0, r1
    and r0, 0xFFFFFF
    jlt r0, 0x20000, -5
    exit",
        Config::default(),
        655361,
        &mut [0; 0x20000],
    );
}

static ADDRESS_TRANSLATION_STACK_CODE: &str = "
    mov r1, r2
    and r1, 4095
    mov r3, r10
    sub r3, r1
    sub r3, 1
    ldxb r4, [r3]
    add r2, 1
    jlt r2, 0x10000, -8
    exit";

#[cfg(not(windows))]
#[bench]
fn bench_jit_vs_interpreter_address_translation_stack_fixed(bencher: &mut Bencher) {
    bench_jit_vs_interpreter(
        bencher,
        ADDRESS_TRANSLATION_STACK_CODE,
        Config {
            dynamic_stack_frames: false,
            ..Config::default()
        },
        524289,
        &mut [],
    );
}

#[cfg(not(windows))]
#[bench]
fn bench_jit_vs_interpreter_address_translation_stack_dynamic(bencher: &mut Bencher) {
    bench_jit_vs_interpreter(
        bencher,
        ADDRESS_TRANSLATION_STACK_CODE,
        Config {
            dynamic_stack_frames: true,
            ..Config::default()
        },
        524289,
        &mut [],
    );
}

#[cfg(not(windows))]
#[bench]
fn bench_jit_vs_interpreter_empty_for_loop(bencher: &mut Bencher) {
    bench_jit_vs_interpreter(
        bencher,
        "
    mov r1, r2
    and r1, 1023
    add r2, 1
    jlt r2, 0x10000, -4
    exit",
        Config::default(),
        262145,
        &mut [0; 0],
    );
}

#[cfg(not(windows))]
#[bench]
fn bench_jit_vs_interpreter_call_depth_fixed(bencher: &mut Bencher) {
    bench_jit_vs_interpreter(
        bencher,
        "
    mov r6, 0
    add r6, 1
    mov r1, 18
    call function_foo
    jlt r6, 1024, -4
    exit
    function_foo:
    stw [r10-4], 0x11223344
    mov r6, r1
    jgt r6, 0, +1
    exit
    mov r1, r6
    sub r1, 1
    call function_foo
    exit",
        Config {
            dynamic_stack_frames: false,
            ..Config::default()
        },
        137218,
        &mut [],
    );
}

#[cfg(not(windows))]
#[bench]
fn bench_jit_vs_interpreter_call_depth_dynamic(bencher: &mut Bencher) {
    bench_jit_vs_interpreter(
        bencher,
        "
    mov r6, 0
    add r6, 1
    mov r1, 18
    call function_foo
    jlt r6, 1024, -4
    exit
    function_foo:
    sub r11, 4
    stw [r10-4], 0x11223344
    mov r6, r1
    jeq r6, 0, +3
    mov r1, r6
    sub r1, 1
    call function_foo
    add r11, 4
    exit",
        Config {
            dynamic_stack_frames: true,
            ..Config::default()
        },
        176130,
        &mut [],
    );
}
