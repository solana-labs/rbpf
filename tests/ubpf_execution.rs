#![allow(clippy::integer_arithmetic)]
#![cfg(feature = "jit")]
// Copyright 2020 Solana Maintainers <maintainers@solana.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

extern crate byteorder;
extern crate libc;
extern crate solana_rbpf;
extern crate test_utils;
extern crate thiserror;

use byteorder::{ByteOrder, LittleEndian};
#[cfg(all(not(windows), target_arch = "x86_64"))]
use rand::{rngs::SmallRng, RngCore, SeedableRng};
use solana_rbpf::{
    assembler::assemble,
    ebpf,
    elf::{register_bpf_function, ElfError, Executable},
    error::EbpfError,
    memory_region::{AccessType, MemoryMapping, MemoryRegion},
    syscalls::{self, BpfSyscallContext, Result},
    user_error::UserError,
    verifier::RequisiteVerifier,
    vm::{
        Config, EbpfVm, SyscallObject, SyscallRegistry, TestInstructionMeter, VerifiedExecutable,
    },
};
use std::{collections::BTreeMap, fs::File, io::Read};
use test_utils::{PROG_TCP_PORT_80, TCP_SACK_ASM, TCP_SACK_MATCH, TCP_SACK_NOMATCH};

macro_rules! test_interpreter_and_jit {
    (register, $syscall_registry:expr, $location:expr => $syscall_init:expr; $syscall_function:expr) => {
        $syscall_registry
            .register_syscall_by_name($location, $syscall_init, $syscall_function)
            .unwrap();
    };
    (bind, $vm:expr, $syscall_context:expr) => {
        $vm.bind_syscall_context_objects($syscall_context).unwrap();
    };
    ($executable:expr, $mem:tt, $syscall_context:expr, $check:block, $expected_instruction_count:expr) => {
        #[allow(unused_mut)]
        let mut check_closure = $check;
        #[allow(unused_mut)]
        let mut verified_executable = VerifiedExecutable::<
            RequisiteVerifier,
            UserError,
            TestInstructionMeter,
        >::from_executable($executable)
        .unwrap();
        let (instruction_count_interpreter, _tracer_interpreter) = {
            let mut mem = $mem;
            let mem_region = MemoryRegion::new_writable(&mut mem, ebpf::MM_INPUT_START);

            let mut vm = EbpfVm::new(&verified_executable, &mut [], vec![mem_region]).unwrap();
            test_interpreter_and_jit!(bind, vm, $syscall_context);
            let result = vm.execute_program_interpreted(&mut TestInstructionMeter {
                remaining: $expected_instruction_count,
            });
            assert!(check_closure(&vm, result));
            (vm.get_total_instruction_count(), vm.get_tracer().clone())
        };
        #[cfg(all(not(windows), target_arch = "x86_64"))]
        {
            #[allow(unused_mut)]
            let mut check_closure = $check;
            let compilation_result = verified_executable.jit_compile();
            let mut mem = $mem;
            let mem_region = MemoryRegion::new_writable(&mut mem, ebpf::MM_INPUT_START);
            let mut vm = EbpfVm::new(&verified_executable, &mut [], vec![mem_region]).unwrap();
            match compilation_result {
                Err(err) => assert!(check_closure(&vm, Err(err))),
                Ok(()) => {
                    test_interpreter_and_jit!(bind, vm, $syscall_context);
                    let result = vm.execute_program_jit(&mut TestInstructionMeter {
                        remaining: $expected_instruction_count,
                    });
                    let tracer_jit = vm.get_tracer();
                    if !check_closure(&vm, result)
                        || !solana_rbpf::vm::Tracer::compare(&_tracer_interpreter, tracer_jit)
                    {
                        let analysis = solana_rbpf::static_analysis::Analysis::from_executable(
                            verified_executable.get_executable(),
                        )
                        .unwrap();
                        let stdout = std::io::stdout();
                        _tracer_interpreter
                            .write(&mut stdout.lock(), &analysis)
                            .unwrap();
                        tracer_jit.write(&mut stdout.lock(), &analysis).unwrap();
                        panic!();
                    }
                    if verified_executable
                        .get_executable()
                        .get_config()
                        .enable_instruction_meter
                    {
                        let instruction_count_jit = vm.get_total_instruction_count();
                        assert_eq!(instruction_count_interpreter, instruction_count_jit);
                    }
                }
            }
        }
        if verified_executable
            .get_executable()
            .get_config()
            .enable_instruction_meter
        {
            assert_eq!(instruction_count_interpreter, $expected_instruction_count);
        }
    };
}

macro_rules! test_interpreter_and_jit_asm {
    ($source:tt, $config:tt, $mem:tt, ($($location:expr => $syscall_init:expr; $syscall_function:expr),* $(,)?), $syscall_context:expr, $check:block, $expected_instruction_count:expr) => {
        #[allow(unused_mut)]
        {
            let mut syscall_registry = SyscallRegistry::default();
            $(test_interpreter_and_jit!(register, syscall_registry, $location => $syscall_init; $syscall_function);)*
            let mut executable = assemble($source, $config, syscall_registry).unwrap();
            test_interpreter_and_jit!(executable, $mem, $syscall_context, $check, $expected_instruction_count);
        }
    };
    ($source:tt, $mem:tt, ($($location:expr => $syscall_init:expr; $syscall_function:expr),* $(,)?), $syscall_context:expr, $check:block, $expected_instruction_count:expr) => {
        #[allow(unused_mut)]
        {
            let config = Config {
                enable_instruction_tracing: true,
                ..Config::default()
            };
            test_interpreter_and_jit_asm!($source, config, $mem, ($($location => $syscall_init; $syscall_function),*), $syscall_context, $check, $expected_instruction_count);
        }
    };
}

macro_rules! test_interpreter_and_jit_elf {
    ($source:tt, $config:tt, $mem:tt, ($($location:expr => $syscall_init:expr; $syscall_function:expr),* $(,)?), $syscall_context:expr, $check:block, $expected_instruction_count:expr) => {
        let mut file = File::open($source).unwrap();
        let mut elf = Vec::new();
        file.read_to_end(&mut elf).unwrap();
        #[allow(unused_mut)]
        {
            let mut syscall_registry = SyscallRegistry::default();
            $(test_interpreter_and_jit!(register, syscall_registry, $location => $syscall_init; $syscall_function);)*
            let mut executable = Executable::<UserError, TestInstructionMeter>::from_elf(&elf, $config, syscall_registry).unwrap();
            test_interpreter_and_jit!(executable, $mem, $syscall_context, $check, $expected_instruction_count);
        }
    };
    ($source:tt, $mem:tt, ($($location:expr => $syscall_init:expr; $syscall_function:expr),* $(,)?), $syscall_context:expr, $check:block, $expected_instruction_count:expr) => {
        let config = Config {
            enable_instruction_tracing: true,
            ..Config::default()
        };
        test_interpreter_and_jit_elf!($source, config, $mem, ($($location => $syscall_init; $syscall_function),*), $syscall_context, $check, $expected_instruction_count);
    };
}

// BPF_ALU : Arithmetic and Logic

#[test]
fn test_mov() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r1, 1
        mov32 r0, r1
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x1 } },
        3
    );
}

#[test]
fn test_mov32_imm_large() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, -1
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0xffffffff } },
        2
    );
}

#[test]
fn test_mov_large() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r1, -1
        mov32 r0, r1
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0xffffffff } },
        3
    );
}

#[test]
fn test_bounce() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 1
        mov r6, r0
        mov r7, r6
        mov r8, r7
        mov r9, r8
        mov r0, r9
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x1 } },
        7
    );
}

#[test]
fn test_add32() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov32 r1, 2
        add32 r0, 1
        add32 r0, r1
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x3 } },
        5
    );
}

#[test]
fn test_neg32() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 2
        neg32 r0
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0xfffffffe } },
        3
    );
}

#[test]
fn test_neg64() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 2
        neg r0
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0xfffffffffffffffe } },
        3
    );
}

#[test]
fn test_alu32_arithmetic() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov32 r1, 1
        mov32 r2, 2
        mov32 r3, 3
        mov32 r4, 4
        mov32 r5, 5
        mov32 r6, 6
        mov32 r7, 7
        mov32 r8, 8
        mov32 r9, 9
        add32 r0, 23
        add32 r0, r7
        sub32 r0, 13
        sub32 r0, r1
        mul32 r0, 7
        mul32 r0, r3
        div32 r0, 2
        div32 r0, r4
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x2a } },
        19
    );
}

#[test]
fn test_alu64_arithmetic() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 0
        mov r1, 1
        mov r2, 2
        mov r3, 3
        mov r4, 4
        mov r5, 5
        mov r6, 6
        mov r7, 7
        mov r8, 8
        mov r9, 9
        add r0, 23
        add r0, r7
        sub r0, 13
        sub r0, r1
        mul r0, 7
        mul r0, r3
        div r0, 2
        div r0, r4
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x2a } },
        19
    );
}

#[test]
fn test_mul128() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, r1
        mov r2, 30
        mov r3, 0
        mov r4, 20
        mov r5, 0
        mul64 r3, r4
        mul64 r5, r2
        add64 r5, r3
        mov64 r0, r2
        rsh64 r0, 0x20
        mov64 r3, r4
        rsh64 r3, 0x20
        mov64 r6, r3
        mul64 r6, r0
        add64 r5, r6
        lsh64 r4, 0x20
        rsh64 r4, 0x20
        mov64 r6, r4
        mul64 r6, r0
        lsh64 r2, 0x20
        rsh64 r2, 0x20
        mul64 r4, r2
        mov64 r0, r4
        rsh64 r0, 0x20
        add64 r0, r6
        mov64 r6, r0
        rsh64 r6, 0x20
        add64 r5, r6
        mul64 r3, r2
        lsh64 r0, 0x20
        rsh64 r0, 0x20
        add64 r0, r3
        mov64 r2, r0
        rsh64 r2, 0x20
        add64 r5, r2
        stxdw [r1+0x8], r5
        lsh64 r0, 0x20
        lsh64 r4, 0x20
        rsh64 r4, 0x20
        or64 r0, r4
        stxdw [r1+0x0], r0
        exit",
        [0; 16],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 600 } },
        42
    );
}

#[test]
fn test_alu32_logic() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov32 r1, 1
        mov32 r2, 2
        mov32 r3, 3
        mov32 r4, 4
        mov32 r5, 5
        mov32 r6, 6
        mov32 r7, 7
        mov32 r8, 8
        or32 r0, r5
        or32 r0, 0xa0
        and32 r0, 0xa3
        mov32 r9, 0x91
        and32 r0, r9
        lsh32 r0, 22
        lsh32 r0, r8
        rsh32 r0, 19
        rsh32 r0, r7
        xor32 r0, 0x03
        xor32 r0, r2
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x11 } },
        21
    );
}

#[test]
fn test_alu64_logic() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 0
        mov r1, 1
        mov r2, 2
        mov r3, 3
        mov r4, 4
        mov r5, 5
        mov r6, 6
        mov r7, 7
        mov r8, 8
        or r0, r5
        or r0, 0xa0
        and r0, 0xa3
        mov r9, 0x91
        and r0, r9
        lsh r0, 32
        lsh r0, 22
        lsh r0, r8
        rsh r0, 32
        rsh r0, 19
        rsh r0, r7
        xor r0, 0x03
        xor r0, r2
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x11 } },
        23
    );
}

#[test]
fn test_arsh32_high_shift() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 8
        lddw r1, 0x100000001
        arsh32 r0, r1
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x4 } },
        4
    );
}

#[test]
fn test_arsh32_imm() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0xf8
        lsh32 r0, 28
        arsh32 r0, 16
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0xffff8000 } },
        4
    );
}

#[test]
fn test_arsh32_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0xf8
        mov32 r1, 16
        lsh32 r0, 28
        arsh32 r0, r1
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0xffff8000 } },
        5
    );
}

#[test]
fn test_arsh64() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 1
        lsh r0, 63
        arsh r0, 55
        mov32 r1, 5
        arsh r0, r1
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0xfffffffffffffff8 } },
        6
    );
}

#[test]
fn test_lsh64_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 0x1
        mov r7, 4
        lsh r0, r7
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x10 } },
        4
    );
}

#[test]
fn test_rhs32_imm() {
    test_interpreter_and_jit_asm!(
        "
        xor r0, r0
        sub r0, 1
        rsh32 r0, 8
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x00ffffff } },
        4
    );
}

#[test]
fn test_rsh64_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 0x10
        mov r7, 4
        rsh r0, r7
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x1 } },
        4
    );
}

#[test]
fn test_be16() {
    test_interpreter_and_jit_asm!(
        "
        ldxh r0, [r1]
        be16 r0
        exit",
        [0x11, 0x22],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x1122 } },
        3
    );
}

#[test]
fn test_be16_high() {
    test_interpreter_and_jit_asm!(
        "
        ldxdw r0, [r1]
        be16 r0
        exit",
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x1122 } },
        3
    );
}

#[test]
fn test_be32() {
    test_interpreter_and_jit_asm!(
        "
        ldxw r0, [r1]
        be32 r0
        exit",
        [0x11, 0x22, 0x33, 0x44],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x11223344 } },
        3
    );
}

#[test]
fn test_be32_high() {
    test_interpreter_and_jit_asm!(
        "
        ldxdw r0, [r1]
        be32 r0
        exit",
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x11223344 } },
        3
    );
}

#[test]
fn test_be64() {
    test_interpreter_and_jit_asm!(
        "
        ldxdw r0, [r1]
        be64 r0
        exit",
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x1122334455667788 } },
        3
    );
}

#[test]
fn test_le16() {
    test_interpreter_and_jit_asm!(
        "
        ldxh r0, [r1]
        le16 r0
        exit",
        [0x22, 0x11],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x1122 } },
        3
    );
}

#[test]
fn test_le16_high() {
    test_interpreter_and_jit_asm!(
        "
        ldxdw r0, [r1]
        le16 r0
        exit",
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x2211 } },
        3
    );
}

#[test]
fn test_le32() {
    test_interpreter_and_jit_asm!(
        "
        ldxw r0, [r1]
        le32 r0
        exit",
        [0x44, 0x33, 0x22, 0x11],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x11223344 } },
        3
    );
}

#[test]
fn test_le32_high() {
    test_interpreter_and_jit_asm!(
        "
        ldxdw r0, [r1]
        le32 r0
        exit",
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x44332211 } },
        3
    );
}

#[test]
fn test_le64() {
    test_interpreter_and_jit_asm!(
        "
        ldxdw r0, [r1]
        le64 r0
        exit",
        [0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x1122334455667788 } },
        3
    );
}

#[test]
fn test_mul32_imm() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 3
        mul32 r0, 4
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0xc } },
        3
    );
}

#[test]
fn test_mul32_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 3
        mov r1, 4
        mul32 r0, r1
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0xc } },
        4
    );
}

#[test]
fn test_mul32_reg_overflow() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 0x40000001
        mov r1, 4
        mul32 r0, r1
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x4 } },
        4
    );
}

#[test]
fn test_mul64_imm() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 0x40000001
        mul r0, 4
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x100000004 } },
        3
    );
}

#[test]
fn test_mul64_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 0x40000001
        mov r1, 4
        mul r0, r1
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x100000004 } },
        4
    );
}

#[test]
fn test_div32_high_divisor() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 12
        lddw r1, 0x100000004
        div32 r0, r1
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x3 } },
        4
    );
}

#[test]
fn test_div32_imm() {
    test_interpreter_and_jit_asm!(
        "
        lddw r0, 0x10000000c
        div32 r0, 4
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x3 } },
        3
    );
}

#[test]
fn test_div32_reg() {
    test_interpreter_and_jit_asm!(
        "
        lddw r0, 0x10000000c
        mov r1, 4
        div32 r0, r1
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x3 } },
        4
    );
}

#[test]
fn test_sdiv32_imm() {
    test_interpreter_and_jit_asm!(
        "
        lddw r0, 0x180000000
        sdiv32 r0, 4
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0xFFFFFFFFE0000000 } },
        3
    );
}

#[test]
fn test_sdiv32_neg_imm() {
    test_interpreter_and_jit_asm!(
        "
        lddw r0, 0x10000000c
        sdiv32 r0, -1
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() as i64 == -0xc } },
        3
    );
}

#[test]
fn test_sdiv32_reg() {
    test_interpreter_and_jit_asm!(
        "
        lddw r0, 0x180000000
        mov r1, 4
        sdiv32 r0, r1
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0xFFFFFFFFE0000000 } },
        4
    );
}

#[test]
fn test_sdiv32_neg_reg() {
    test_interpreter_and_jit_asm!(
        "
        lddw r0, 0x10000000c
        mov r1, -1
        sdiv32 r0, r1
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() as i64 == -0xc } },
        4
    );
}

#[test]
fn test_div64_imm() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 0xc
        lsh r0, 32
        div r0, 4
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x300000000 } },
        4
    );
}

#[test]
fn test_div64_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 0xc
        lsh r0, 32
        mov r1, 4
        div r0, r1
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x300000000 } },
        5
    );
}

#[test]
fn test_sdiv64_imm() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 0xc
        lsh r0, 32
        sdiv r0, 4
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x300000000 } },
        4
    );
}

#[test]
fn test_sdiv64_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 0xc
        lsh r0, 32
        mov r1, 4
        sdiv r0, r1
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x300000000 } },
        5
    );
}

#[test]
fn test_err_div64_by_zero_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 1
        mov32 r1, 0
        div r0, r1
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| matches!(res.unwrap_err(), EbpfError::DivideByZero(pc) if pc == 31) },
        3
    );
}

#[test]
fn test_err_div32_by_zero_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 1
        mov32 r1, 0
        div32 r0, r1
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| matches!(res.unwrap_err(), EbpfError::DivideByZero(pc) if pc == 31) },
        3
    );
}

#[test]
fn test_err_sdiv64_by_zero_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 1
        mov32 r1, 0
        sdiv r0, r1
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| matches!(res.unwrap_err(), EbpfError::DivideByZero(pc) if pc == 31) },
        3
    );
}

#[test]
fn test_err_sdiv32_by_zero_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 1
        mov32 r1, 0
        sdiv32 r0, r1
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| matches!(res.unwrap_err(), EbpfError::DivideByZero(pc) if pc == 31) },
        3
    );
}

#[test]
fn test_err_sdiv64_overflow_imm() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 0x80
        lsh r0, 56
        sdiv r0, -1
        exit",
        [],
        (),
        0,
        {
            |_vm, res: Result| matches!(res.unwrap_err(), EbpfError::DivideOverflow(pc) if pc == 31)
        },
        3
    );
}

#[test]
fn test_err_sdiv64_overflow_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 0x80
        lsh r0, 56
        mov r1, -1
        sdiv r0, r1
        exit",
        [],
        (),
        0,
        {
            |_vm, res: Result| matches!(res.unwrap_err(), EbpfError::DivideOverflow(pc) if pc == 32)
        },
        4
    );
}

#[test]
fn test_err_sdiv32_overflow_imm() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 0x80
        lsh r0, 24
        sdiv32 r0, -1
        exit",
        [],
        (),
        0,
        {
            |_vm, res: Result| matches!(res.unwrap_err(), EbpfError::DivideOverflow(pc) if pc == 31)
        },
        3
    );
}

#[test]
fn test_err_sdiv32_overflow_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 0x80
        lsh r0, 24
        mov r1, -1
        sdiv32 r0, r1
        exit",
        [],
        (),
        0,
        {
            |_vm, res: Result| matches!(res.unwrap_err(), EbpfError::DivideOverflow(pc) if pc == 32)
        },
        4
    );
}

#[test]
fn test_mod32() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 5748
        mod32 r0, 92
        mov32 r1, 13
        mod32 r0, r1
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x5 } },
        5
    );
}

#[test]
fn test_mod32_imm() {
    test_interpreter_and_jit_asm!(
        "
        lddw r0, 0x100000003
        mod32 r0, 3
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x0 } },
        3
    );
}

#[test]
fn test_mod64() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, -1316649930
        lsh r0, 32
        or r0, 0x100dc5c8
        mov32 r1, 0xdde263e
        lsh r1, 32
        or r1, 0x3cbef7f3
        mod r0, r1
        mod r0, 0x658f1778
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x30ba5a04 } },
        9
    );
}

#[test]
fn test_err_mod64_by_zero_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 1
        mov32 r1, 0
        mod r0, r1
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| matches!(res.unwrap_err(), EbpfError::DivideByZero(pc) if pc == 31) },
        3
    );
}

#[test]
fn test_err_mod_by_zero_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 1
        mov32 r1, 0
        mod32 r0, r1
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| matches!(res.unwrap_err(), EbpfError::DivideByZero(pc) if pc == 31) },
        3
    );
}

// BPF_LD : Loads

#[test]
fn test_ldxb() {
    test_interpreter_and_jit_asm!(
        "
        ldxb r0, [r1+2]
        exit",
        [0xaa, 0xbb, 0x11, 0xcc, 0xdd],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x11 } },
        2
    );
}

#[test]
fn test_ldxh() {
    test_interpreter_and_jit_asm!(
        "
        ldxh r0, [r1+2]
        exit",
        [0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x2211 } },
        2
    );
}

#[test]
fn test_ldxw() {
    test_interpreter_and_jit_asm!(
        "
        ldxw r0, [r1+2]
        exit",
        [
            0xaa, 0xbb, 0x11, 0x22, 0x33, 0x44, 0xcc, 0xdd, //
        ],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x44332211 } },
        2
    );
}

#[test]
fn test_ldxh_same_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, r1
        sth [r0], 0x1234
        ldxh r0, [r0]
        exit",
        [0xff, 0xff],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x1234 } },
        4
    );
}

#[test]
fn test_lldxdw() {
    test_interpreter_and_jit_asm!(
        "
        ldxdw r0, [r1+2]
        exit",
        [
            0xaa, 0xbb, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, //
            0x77, 0x88, 0xcc, 0xdd, //
        ],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x8877665544332211 } },
        2
    );
}

#[test]
fn test_err_ldxdw_oob() {
    test_interpreter_and_jit_asm!(
        "
        ldxdw r0, [r1+6]
        exit",
        [
            0xaa, 0xbb, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, //
            0x77, 0x88, 0xcc, 0xdd, //
        ],
        (),
        0,
        {
            |_vm, res: Result| {
                matches!(res.unwrap_err(),
                    EbpfError::AccessViolation(pc, access_type, vm_addr, len, name)
                    if access_type == AccessType::Load && pc == 29 && vm_addr == 0x400000006 && len == 8 && name == "input"
                )
            }
        },
        1
    );
}

#[test]
fn test_err_ldxdw_nomem() {
    test_interpreter_and_jit_asm!(
        "
        ldxdw r0, [r1+6]
        exit",
        [],
        (),
        0,
        {
            |_vm, res: Result| {
                matches!(res.unwrap_err(),
                    EbpfError::AccessViolation(pc, access_type, vm_addr, len, name)
                    if access_type == AccessType::Load && pc == 29 && vm_addr == 0x400000006 && len == 8 && name == "input"
                )
            }
        },
        1
    );
}

#[test]
fn test_ldxb_all() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, r1
        ldxb r9, [r0+0]
        lsh r9, 0
        ldxb r8, [r0+1]
        lsh r8, 4
        ldxb r7, [r0+2]
        lsh r7, 8
        ldxb r6, [r0+3]
        lsh r6, 12
        ldxb r5, [r0+4]
        lsh r5, 16
        ldxb r4, [r0+5]
        lsh r4, 20
        ldxb r3, [r0+6]
        lsh r3, 24
        ldxb r2, [r0+7]
        lsh r2, 28
        ldxb r1, [r0+8]
        lsh r1, 32
        ldxb r0, [r0+9]
        lsh r0, 36
        or r0, r1
        or r0, r2
        or r0, r3
        or r0, r4
        or r0, r5
        or r0, r6
        or r0, r7
        or r0, r8
        or r0, r9
        exit",
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, //
            0x08, 0x09, //
        ],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x9876543210 } },
        31
    );
}

#[test]
fn test_ldxh_all() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, r1
        ldxh r9, [r0+0]
        be16 r9
        lsh r9, 0
        ldxh r8, [r0+2]
        be16 r8
        lsh r8, 4
        ldxh r7, [r0+4]
        be16 r7
        lsh r7, 8
        ldxh r6, [r0+6]
        be16 r6
        lsh r6, 12
        ldxh r5, [r0+8]
        be16 r5
        lsh r5, 16
        ldxh r4, [r0+10]
        be16 r4
        lsh r4, 20
        ldxh r3, [r0+12]
        be16 r3
        lsh r3, 24
        ldxh r2, [r0+14]
        be16 r2
        lsh r2, 28
        ldxh r1, [r0+16]
        be16 r1
        lsh r1, 32
        ldxh r0, [r0+18]
        be16 r0
        lsh r0, 36
        or r0, r1
        or r0, r2
        or r0, r3
        or r0, r4
        or r0, r5
        or r0, r6
        or r0, r7
        or r0, r8
        or r0, r9
        exit",
        [
            0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, //
            0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07, //
            0x00, 0x08, 0x00, 0x09, //
        ],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x9876543210 } },
        41
    );
}

#[test]
fn test_ldxh_all2() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, r1
        ldxh r9, [r0+0]
        be16 r9
        ldxh r8, [r0+2]
        be16 r8
        ldxh r7, [r0+4]
        be16 r7
        ldxh r6, [r0+6]
        be16 r6
        ldxh r5, [r0+8]
        be16 r5
        ldxh r4, [r0+10]
        be16 r4
        ldxh r3, [r0+12]
        be16 r3
        ldxh r2, [r0+14]
        be16 r2
        ldxh r1, [r0+16]
        be16 r1
        ldxh r0, [r0+18]
        be16 r0
        or r0, r1
        or r0, r2
        or r0, r3
        or r0, r4
        or r0, r5
        or r0, r6
        or r0, r7
        or r0, r8
        or r0, r9
        exit",
        [
            0x00, 0x01, 0x00, 0x02, 0x00, 0x04, 0x00, 0x08, //
            0x00, 0x10, 0x00, 0x20, 0x00, 0x40, 0x00, 0x80, //
            0x01, 0x00, 0x02, 0x00, //
        ],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x3ff } },
        31
    );
}

#[test]
fn test_ldxw_all() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, r1
        ldxw r9, [r0+0]
        be32 r9
        ldxw r8, [r0+4]
        be32 r8
        ldxw r7, [r0+8]
        be32 r7
        ldxw r6, [r0+12]
        be32 r6
        ldxw r5, [r0+16]
        be32 r5
        ldxw r4, [r0+20]
        be32 r4
        ldxw r3, [r0+24]
        be32 r3
        ldxw r2, [r0+28]
        be32 r2
        ldxw r1, [r0+32]
        be32 r1
        ldxw r0, [r0+36]
        be32 r0
        or r0, r1
        or r0, r2
        or r0, r3
        or r0, r4
        or r0, r5
        or r0, r6
        or r0, r7
        or r0, r8
        or r0, r9
        exit",
        [
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, //
            0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08, //
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, //
            0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08, 0x00, //
            0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, //
        ],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x030f0f } },
        31
    );
}

#[test]
fn test_lddw() {
    test_interpreter_and_jit_asm!(
        "
        lddw r0, 0x1122334455667788
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x1122334455667788 } },
        2
    );
    test_interpreter_and_jit_asm!(
        "
        lddw r0, 0x0000000080000000
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x80000000 } },
        2
    );
}

#[test]
fn test_stb() {
    test_interpreter_and_jit_asm!(
        "
        stb [r1+2], 0x11
        ldxb r0, [r1+2]
        exit",
        [0xaa, 0xbb, 0xff, 0xcc, 0xdd],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x11 } },
        3
    );
}

#[test]
fn test_sth() {
    test_interpreter_and_jit_asm!(
        "
        sth [r1+2], 0x2211
        ldxh r0, [r1+2]
        exit",
        [
            0xaa, 0xbb, 0xff, 0xff, 0xcc, 0xdd, //
        ],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x2211 } },
        3
    );
}

#[test]
fn test_stw() {
    test_interpreter_and_jit_asm!(
        "
        stw [r1+2], 0x44332211
        ldxw r0, [r1+2]
        exit",
        [
            0xaa, 0xbb, 0xff, 0xff, 0xff, 0xff, 0xcc, 0xdd, //
        ],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x44332211 } },
        3
    );
}

#[test]
fn test_stdw() {
    test_interpreter_and_jit_asm!(
        "
        stdw [r1+2], 0x44332211
        ldxdw r0, [r1+2]
        exit",
        [
            0xaa, 0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //
            0xff, 0xff, 0xcc, 0xdd, //
        ],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x44332211 } },
        3
    );
}

#[test]
fn test_stxb() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r2, 0x11
        stxb [r1+2], r2
        ldxb r0, [r1+2]
        exit",
        [
            0xaa, 0xbb, 0xff, 0xcc, 0xdd, //
        ],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x11 } },
        4
    );
}

#[test]
fn test_stxh() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r2, 0x2211
        stxh [r1+2], r2
        ldxh r0, [r1+2]
        exit",
        [
            0xaa, 0xbb, 0xff, 0xff, 0xcc, 0xdd, //
        ],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x2211 } },
        4
    );
}

#[test]
fn test_stxw() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r2, 0x44332211
        stxw [r1+2], r2
        ldxw r0, [r1+2]
        exit",
        [
            0xaa, 0xbb, 0xff, 0xff, 0xff, 0xff, 0xcc, 0xdd, //
        ],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x44332211 } },
        4
    );
}

#[test]
fn test_stxdw() {
    test_interpreter_and_jit_asm!(
        "
        mov r2, -2005440939
        lsh r2, 32
        or r2, 0x44332211
        stxdw [r1+2], r2
        ldxdw r0, [r1+2]
        exit",
        [
            0xaa, 0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //
            0xff, 0xff, 0xcc, 0xdd, //
        ],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x8877665544332211 } },
        6
    );
}

#[test]
fn test_stxb_all() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 0xf0
        mov r2, 0xf2
        mov r3, 0xf3
        mov r4, 0xf4
        mov r5, 0xf5
        mov r6, 0xf6
        mov r7, 0xf7
        mov r8, 0xf8
        stxb [r1], r0
        stxb [r1+1], r2
        stxb [r1+2], r3
        stxb [r1+3], r4
        stxb [r1+4], r5
        stxb [r1+5], r6
        stxb [r1+6], r7
        stxb [r1+7], r8
        ldxdw r0, [r1]
        be64 r0
        exit",
        [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //
        ],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0xf0f2f3f4f5f6f7f8 } },
        19
    );
}

#[test]
fn test_stxb_all2() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, r1
        mov r1, 0xf1
        mov r9, 0xf9
        stxb [r0], r1
        stxb [r0+1], r9
        ldxh r0, [r0]
        be16 r0
        exit",
        [0xff, 0xff],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0xf1f9 } },
        8
    );
}

#[test]
fn test_stxb_chain() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, r1
        ldxb r9, [r0+0]
        stxb [r0+1], r9
        ldxb r8, [r0+1]
        stxb [r0+2], r8
        ldxb r7, [r0+2]
        stxb [r0+3], r7
        ldxb r6, [r0+3]
        stxb [r0+4], r6
        ldxb r5, [r0+4]
        stxb [r0+5], r5
        ldxb r4, [r0+5]
        stxb [r0+6], r4
        ldxb r3, [r0+6]
        stxb [r0+7], r3
        ldxb r2, [r0+7]
        stxb [r0+8], r2
        ldxb r1, [r0+8]
        stxb [r0+9], r1
        ldxb r0, [r0+9]
        exit",
        [
            0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
            0x00, 0x00, //
        ],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x2a } },
        21
    );
}

// BPF_JMP : Branches

#[test]
fn test_exit_without_value() {
    test_interpreter_and_jit_asm!(
        "
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x0 } },
        1
    );
}

#[test]
fn test_exit() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 0
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x0 } },
        2
    );
}

#[test]
fn test_early_exit() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 3
        exit
        mov r0, 4
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x3 } },
        2
    );
}

#[test]
fn test_ja() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 1
        ja +1
        mov r0, 2
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x1 } },
        3
    );
}

#[test]
fn test_jeq_imm() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov32 r1, 0xa
        jeq r1, 0xb, +4
        mov32 r0, 1
        mov32 r1, 0xb
        jeq r1, 0xb, +1
        mov32 r0, 2
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x1 } },
        7
    );
}

#[test]
fn test_jeq_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov32 r1, 0xa
        mov32 r2, 0xb
        jeq r1, r2, +4
        mov32 r0, 1
        mov32 r1, 0xb
        jeq r1, r2, +1
        mov32 r0, 2
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x1 } },
        8
    );
}

#[test]
fn test_jge_imm() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov32 r1, 0xa
        jge r1, 0xb, +4
        mov32 r0, 1
        mov32 r1, 0xc
        jge r1, 0xb, +1
        mov32 r0, 2
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x1 } },
        7
    );
}

#[test]
fn test_jge_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov32 r1, 0xa
        mov32 r2, 0xb
        jge r1, r2, +4
        mov32 r0, 1
        mov32 r1, 0xb
        jge r1, r2, +1
        mov32 r0, 2
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x1 } },
        8
    );
}

#[test]
fn test_jle_imm() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov32 r1, 5
        jle r1, 4, +1
        jle r1, 6, +1
        exit
        jle r1, 5, +1
        exit
        mov32 r0, 1
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x1 } },
        7
    );
}

#[test]
fn test_jle_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 0
        mov r1, 5
        mov r2, 4
        mov r3, 6
        jle r1, r2, +2
        jle r1, r1, +1
        exit
        jle r1, r3, +1
        exit
        mov r0, 1
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x1 } },
        9
    );
}

#[test]
fn test_jgt_imm() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov32 r1, 5
        jgt r1, 6, +2
        jgt r1, 5, +1
        jgt r1, 4, +1
        exit
        mov32 r0, 1
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x1 } },
        7
    );
}

#[test]
fn test_jgt_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 0
        mov r1, 5
        mov r2, 6
        mov r3, 4
        jgt r1, r2, +2
        jgt r1, r1, +1
        jgt r1, r3, +1
        exit
        mov r0, 1
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x1 } },
        9
    );
}

#[test]
fn test_jlt_imm() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov32 r1, 5
        jlt r1, 4, +2
        jlt r1, 5, +1
        jlt r1, 6, +1
        exit
        mov32 r0, 1
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x1 } },
        7
    );
}

#[test]
fn test_jlt_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 0
        mov r1, 5
        mov r2, 4
        mov r3, 6
        jlt r1, r2, +2
        jlt r1, r1, +1
        jlt r1, r3, +1
        exit
        mov r0, 1
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x1 } },
        9
    );
}

#[test]
fn test_jne_imm() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov32 r1, 0xb
        jne r1, 0xb, +4
        mov32 r0, 1
        mov32 r1, 0xa
        jne r1, 0xb, +1
        mov32 r0, 2
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x1 } },
        7
    );
}

#[test]
fn test_jne_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov32 r1, 0xb
        mov32 r2, 0xb
        jne r1, r2, +4
        mov32 r0, 1
        mov32 r1, 0xa
        jne r1, r2, +1
        mov32 r0, 2
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x1 } },
        8
    );
}

#[test]
fn test_jset_imm() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov32 r1, 0x7
        jset r1, 0x8, +4
        mov32 r0, 1
        mov32 r1, 0x9
        jset r1, 0x8, +1
        mov32 r0, 2
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x1 } },
        7
    );
}

#[test]
fn test_jset_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov32 r1, 0x7
        mov32 r2, 0x8
        jset r1, r2, +4
        mov32 r0, 1
        mov32 r1, 0x9
        jset r1, r2, +1
        mov32 r0, 2
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x1 } },
        8
    );
}

#[test]
fn test_jsge_imm() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov r1, -2
        jsge r1, -1, +5
        jsge r1, 0, +4
        mov32 r0, 1
        mov r1, -1
        jsge r1, -1, +1
        mov32 r0, 2
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x1 } },
        8
    );
}

#[test]
fn test_jsge_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov r1, -2
        mov r2, -1
        mov32 r3, 0
        jsge r1, r2, +5
        jsge r1, r3, +4
        mov32 r0, 1
        mov r1, r2
        jsge r1, r2, +1
        mov32 r0, 2
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x1 } },
        10
    );
}

#[test]
fn test_jsle_imm() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov r1, -2
        jsle r1, -3, +1
        jsle r1, -1, +1
        exit
        mov32 r0, 1
        jsle r1, -2, +1
        mov32 r0, 2
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x1 } },
        7
    );
}

#[test]
fn test_jsle_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov r1, -1
        mov r2, -2
        mov32 r3, 0
        jsle r1, r2, +1
        jsle r1, r3, +1
        exit
        mov32 r0, 1
        mov r1, r2
        jsle r1, r2, +1
        mov32 r0, 2
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x1 } },
        10
    );
}

#[test]
fn test_jsgt_imm() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov r1, -2
        jsgt r1, -1, +4
        mov32 r0, 1
        mov32 r1, 0
        jsgt r1, -1, +1
        mov32 r0, 2
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x1 } },
        7
    );
}

#[test]
fn test_jsgt_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov r1, -2
        mov r2, -1
        jsgt r1, r2, +4
        mov32 r0, 1
        mov32 r1, 0
        jsgt r1, r2, +1
        mov32 r0, 2
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x1 } },
        8
    );
}

#[test]
fn test_jslt_imm() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov r1, -2
        jslt r1, -3, +2
        jslt r1, -2, +1
        jslt r1, -1, +1
        exit
        mov32 r0, 1
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x1 } },
        7
    );
}

#[test]
fn test_jslt_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov r1, -2
        mov r2, -3
        mov r3, -1
        jslt r1, r1, +2
        jslt r1, r2, +1
        jslt r1, r3, +1
        exit
        mov32 r0, 1
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x1 } },
        9
    );
}

// Call Stack

#[test]
fn test_stack1() {
    test_interpreter_and_jit_asm!(
        "
        mov r1, 51
        stdw [r10-16], 0xab
        stdw [r10-8], 0xcd
        and r1, 1
        lsh r1, 3
        mov r2, r10
        add r2, r1
        ldxdw r0, [r2-16]
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0xcd } },
        9
    );
}

#[test]
fn test_stack2() {
    test_interpreter_and_jit_asm!(
        "
        stb [r10-4], 0x01
        stb [r10-3], 0x02
        stb [r10-2], 0x03
        stb [r10-1], 0x04
        mov r1, r10
        mov r2, 0x4
        sub r1, r2
        syscall BpfMemFrob
        mov r1, 0
        ldxb r2, [r10-4]
        ldxb r3, [r10-3]
        ldxb r4, [r10-2]
        ldxb r5, [r10-1]
        syscall BpfGatherBytes
        xor r0, 0x2a2a2a2a
        exit",
        [],
        (
            b"BpfMemFrob" => syscalls::BpfMemFrob::init::<BpfSyscallContext, UserError>; syscalls::BpfMemFrob::call,
            b"BpfGatherBytes" => syscalls::BpfGatherBytes::init::<BpfSyscallContext, UserError>; syscalls::BpfGatherBytes::call,
        ),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x01020304 } },
        16
    );
}

#[test]
fn test_string_stack() {
    test_interpreter_and_jit_asm!(
        "
        mov r1, 0x78636261
        stxw [r10-8], r1
        mov r6, 0x0
        stxb [r10-4], r6
        stxb [r10-12], r6
        mov r1, 0x79636261
        stxw [r10-16], r1
        mov r1, r10
        add r1, -8
        mov r2, r1
        syscall BpfStrCmp
        mov r1, r0
        mov r0, 0x1
        lsh r1, 0x20
        rsh r1, 0x20
        jne r1, 0x0, +11
        mov r1, r10
        add r1, -8
        mov r2, r10
        add r2, -16
        syscall BpfStrCmp
        mov r1, r0
        lsh r1, 0x20
        rsh r1, 0x20
        mov r0, 0x1
        jeq r1, r6, +1
        mov r0, 0x0
        exit",
        [],
        (
            b"BpfStrCmp" => syscalls::BpfStrCmp::init::<BpfSyscallContext, UserError>; syscalls::BpfStrCmp::call,
        ),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x0 } },
        28
    );
}

#[test]
fn test_err_fixed_stack_out_of_bound() {
    let config = Config {
        dynamic_stack_frames: false,
        max_call_depth: 3,
        ..Config::default()
    };
    test_interpreter_and_jit_asm!(
        "
        stb [r10-0x4000], 0
        exit",
        config,
        [],
        (),
        0,
        {
            |_vm, res: Result| {
                matches!(res.unwrap_err(),
                    EbpfError::AccessViolation(pc, access_type, vm_addr, len, name)
                    if access_type == AccessType::Store && pc == 29 && vm_addr == 0x1FFFFD000 && len == 1 && name == "program"
                )
            }
        },
        1
    );
}

#[test]
fn test_err_dynamic_stack_out_of_bound() {
    let config = Config {
        dynamic_stack_frames: true,
        max_call_depth: 3,
        ..Config::default()
    };

    // The stack goes from MM_STACK_START + config.stack_size() to MM_STACK_START

    // Check that accessing MM_STACK_START - 1 fails
    test_interpreter_and_jit_asm!(
        "
        stb [r10-0x3001], 0
        exit",
        config,
        [],
        (),
        0,
        {
            |_vm, res: Result| {
                matches!(res.unwrap_err(),
                    EbpfError::AccessViolation(pc, access_type, vm_addr, len, region)
                    if access_type == AccessType::Store && pc == 29 && vm_addr == ebpf::MM_STACK_START - 1 && len == 1 && region == "program"
                )
            }
        },
        1
    );

    // Check that accessing MM_STACK_START + expected_stack_len fails
    test_interpreter_and_jit_asm!(
        "
        stb [r10], 0
        exit",
        config,
        [],
        (),
        0,
        {
            |_vm, res: Result| {
                matches!(res.unwrap_err(),
                    EbpfError::AccessViolation(pc, access_type, vm_addr, len, region)
                    if access_type == AccessType::Store && pc == 29 && vm_addr == ebpf::MM_STACK_START + config.stack_size() as u64 && len == 1 && region == "stack"
                )
            }
        },
        1
    );
}

#[test]
fn test_err_dynamic_stack_ptr_overflow() {
    let config = Config {
        dynamic_stack_frames: true,
        ..Config::default()
    };

    // See the comment in CallFrames::resize_stack() for the reason why it's
    // safe to let the stack pointer overflow

    // stack_ptr -= stack_ptr + 1
    test_interpreter_and_jit_asm!(
        "
        sub r11, 0x7FFFFFFF
        sub r11, 0x7FFFFFFF
        sub r11, 0x7FFFFFFF
        sub r11, 0x7FFFFFFF
        sub r11, 0x14005
        call foo
        exit
        foo:
        stb [r10], 0
        exit",
        config,
        [],
        (),
        0,
        {
            |_vm, res: Result| {
                matches!(res.unwrap_err(),
                    EbpfError::AccessViolation(pc, access_type, vm_addr, len, region)
                    if access_type == AccessType::Store && pc == 29 + 7 && vm_addr == u64::MAX && len == 1 && region == "unknown"
                )
            }
        },
        7
    );
}

#[test]
fn test_dynamic_stack_frames_empty() {
    let config = Config {
        dynamic_stack_frames: true,
        ..Config::default()
    };

    // Check that unless explicitly resized the stack doesn't grow
    test_interpreter_and_jit_asm!(
        "
        call foo
        exit
        foo:
        mov r0, r10
        exit",
        config,
        [],
        (),
        0,
        { |_vm, res: Result| res.unwrap() == ebpf::MM_STACK_START + config.stack_size() as u64 },
        4
    );
}

#[test]
fn test_dynamic_frame_ptr() {
    let config = Config {
        dynamic_stack_frames: true,
        ..Config::default()
    };

    // Check that upon entering a function (foo) the frame pointer is advanced
    // to the top of the stack
    test_interpreter_and_jit_asm!(
        "
        sub r11, 8
        call foo
        exit
        foo:
        mov r0, r10
        exit",
        config,
        [],
        (),
        0,
        {
            |_vm, res: Result| res.unwrap() == ebpf::MM_STACK_START + config.stack_size() as u64 - 8
        },
        5
    );

    // And check that when exiting a function (foo) the caller's frame pointer
    // is restored
    test_interpreter_and_jit_asm!(
        "
        sub r11, 8
        call foo
        mov r0, r10
        exit
        foo:
        exit
        ",
        config,
        [],
        (),
        0,
        { |_vm, res: Result| res.unwrap() == ebpf::MM_STACK_START + config.stack_size() as u64 },
        5
    );
}

#[test]
fn test_entrypoint_exit() {
    // With fixed frames we used to exit the entrypoint when we reached an exit
    // instruction and the stack size was 1 * config.stack_frame_size, which
    // meant that we were in the entrypoint's frame.  With dynamic frames we
    // can't infer anything from the stack size so we track call depth
    // explicitly. Make sure exit still works with both fixed and dynamic
    // frames.
    for dynamic_stack_frames in [false, true] {
        let config = Config {
            dynamic_stack_frames,
            ..Config::default()
        };

        // This checks that when foo exits we don't stop execution even if the
        // stack is empty (stack size and call depth are decoupled)
        test_interpreter_and_jit_asm!(
            "
            entrypoint:
            call foo
            mov r0, 42
            exit
            foo:
            mov r0, 12
            exit",
            config,
            [],
            (),
            0,
            { |_vm, res: Result| { res.unwrap() == 42 } },
            5
        );
    }
}

#[test]
fn test_stack_call_depth_tracking() {
    for dynamic_stack_frames in [false, true] {
        let config = Config {
            dynamic_stack_frames,
            max_call_depth: 2,
            ..Config::default()
        };

        // Given max_call_depth=2, make sure that two sibling calls don't
        // trigger CallDepthExceeded. In other words ensure that we correctly
        // pop frames in the interpreter and decrement
        // EnvironmentStackSlot::CallDepth on ebpf::EXIT in the jit.
        test_interpreter_and_jit_asm!(
            "
            call foo
            call foo
            exit
            foo:
            exit
            ",
            config,
            [],
            (),
            0,
            { |_vm, res: Result| { res.is_ok() } },
            5
        );

        // two nested calls should trigger CallDepthExceeded instead
        test_interpreter_and_jit_asm!(
            "
            entrypoint:
            call foo
            exit
            foo:
            call bar
            exit
            bar:
            exit
            ",
            config,
            [],
            (),
            0,
            {
                |_vm, res: Result| {
                    matches!(res.unwrap_err(),
                        EbpfError::CallDepthExceeded(pc, depth)
                        if pc == 29 + 2 && depth == config.max_call_depth
                    )
                }
            },
            2
        );
    }
}

#[test]
fn test_err_mem_access_out_of_bound() {
    let mem = [0; 512];
    let mut prog = [0; 32];
    prog[0] = ebpf::LD_DW_IMM;
    prog[16] = ebpf::ST_B_IMM;
    prog[24] = ebpf::EXIT;
    for address in [0x2u64, 0x8002u64, 0x80000002u64, 0x8000000000000002u64] {
        LittleEndian::write_u32(&mut prog[4..], address as u32);
        LittleEndian::write_u32(&mut prog[12..], (address >> 32) as u32);
        let config = Config::default();
        let mut bpf_functions = BTreeMap::new();
        let syscall_registry = SyscallRegistry::default();
        register_bpf_function(
            &config,
            &mut bpf_functions,
            &syscall_registry,
            0,
            "entrypoint",
        )
        .unwrap();
        #[allow(unused_mut)]
        let mut executable = Executable::<UserError, TestInstructionMeter>::from_text_bytes(
            &prog,
            config,
            syscall_registry,
            bpf_functions,
        )
        .unwrap();
        test_interpreter_and_jit!(
            executable,
            mem,
            0,
            {
                |_vm, res: Result| {
                    matches!(res.unwrap_err(),
                        EbpfError::AccessViolation(pc, access_type, vm_addr, len, name)
                        if access_type == AccessType::Store && pc == 31 && vm_addr == address && len == 1 && name == "unknown"
                    )
                }
            },
            2
        );
    }
}

// CALL_IMM & CALL_REG : Procedure Calls

#[test]
fn test_relative_call() {
    test_interpreter_and_jit_elf!(
        "tests/elfs/relative_call.so",
        [1],
        (
            b"log" => syscalls::BpfSyscallString::init::<BpfSyscallContext, UserError>; syscalls::BpfSyscallString::call,
        ),
        0,
        { |_vm, res: Result| { res.unwrap() == 2 } },
        14
    );
}

#[test]
fn test_bpf_to_bpf_scratch_registers() {
    test_interpreter_and_jit_elf!(
        "tests/elfs/scratch_registers.so",
        [1],
        (
            b"log_64" => syscalls::BpfSyscallU64::init::<BpfSyscallContext, UserError>; syscalls::BpfSyscallU64::call,
        ),
        0,
        { |_vm, res: Result| { res.unwrap() == 112 } },
        41
    );
}

#[test]
fn test_bpf_to_bpf_pass_stack_reference() {
    test_interpreter_and_jit_elf!(
        "tests/elfs/pass_stack_reference.so",
        [],
        (),
        0,
        { |_vm, res: Result| res.unwrap() == 42 },
        29
    );
}

#[test]
fn test_syscall_parameter_on_stack() {
    test_interpreter_and_jit_asm!(
        "
        mov64 r1, r10
        add64 r1, -0x100
        mov64 r2, 0x1
        syscall BpfSyscallString
        mov64 r0, 0x0
        exit",
        [],
        (
            b"BpfSyscallString" => syscalls::BpfSyscallString::init::<BpfSyscallContext, UserError>; syscalls::BpfSyscallString::call,
        ),
        0,
        { |_vm, res: Result| { res.unwrap() == 0 } },
        6
    );
}

#[test]
fn test_call_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov64 r0, 0x0
        mov64 r8, 0x1
        lsh64 r8, 0x20
        or64 r8, 0x30
        callx r8
        exit
        mov64 r0, 0x2A
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 42 } },
        8
    );
}

#[test]
fn test_err_callx_oob_low() {
    test_interpreter_and_jit_asm!(
        "
        mov64 r0, 0x3
        callx r0
        exit",
        [],
        (),
        0,
        {
            |_vm, res: Result| {
                matches!(res.unwrap_err(),
                    EbpfError::CallOutsideTextSegment(pc, target_pc)
                    if pc == 30 && target_pc == 0
                )
            }
        },
        2
    );
}

#[test]
fn test_err_callx_oob_high() {
    test_interpreter_and_jit_asm!(
        "
        mov64 r0, -0x1
        lsh64 r0, 0x20
        or64 r0, 0x3
        callx r0
        exit",
        [],
        (),
        0,
        {
            |_vm, res: Result| {
                matches!(res.unwrap_err(),
                    EbpfError::CallOutsideTextSegment(pc, target_pc)
                    if pc == 32 && target_pc == 0xffffffff00000000
                )
            }
        },
        4
    );
}

#[test]
fn test_err_static_jmp_lddw() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 0
        mov r1, 0
        mov r2, 0
        lddw r0, 0x1
        ja +2
        lddw r1, 0x1
        lddw r2, 0x1
        add r1, r2
        add r0, r1
        exit
        ",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x2 } },
        9
    );
    test_interpreter_and_jit_asm!(
        "
        call 3
        mov r0, r0
        mov r0, r0
        lddw r0, 0x1122334455667788
        exit
        ",
        [],
        (),
        0,
        {
            |_vm, res: Result| {
                matches!(res.unwrap_err(),
                    EbpfError::UnsupportedInstruction(pc) if pc == 33
                )
            }
        },
        2
    );
}

#[test]
fn test_err_dynamic_jmp_lddw() {
    test_interpreter_and_jit_asm!(
        "
        mov64 r8, 0x1
        lsh64 r8, 0x20
        or64 r8, 0x28
        callx r8
        lddw r0, 0x1122334455667788
        exit",
        [],
        (),
        0,
        {
            |_vm, res: Result| {
                matches!(res.unwrap_err(),
                    EbpfError::UnsupportedInstruction(pc) if pc == 34
                )
            }
        },
        5
    );
    test_interpreter_and_jit_asm!(
        "
        mov64 r1, 0x1
        lsh64 r1, 0x20
        or64 r1, 0x38
        callx r1
        mov r0, r0
        mov r0, r0
        lddw r0, 0x1122334455667788
        exit
        ",
        [],
        (),
        0,
        {
            |_vm, res: Result| {
                matches!(res.unwrap_err(),
                    EbpfError::UnsupportedInstruction(pc) if pc == 36
                )
            }
        },
        5
    );
    test_interpreter_and_jit_asm!(
        "
        lddw r1, 0x100000038
        callx r1
        mov r0, r0
        mov r0, r0
        exit
        lddw r0, 0x1122334455667788
        exit
        ",
        [],
        (),
        0,
        {
            |_vm, res: Result| {
                matches!(res.unwrap_err(),
                    EbpfError::UnsupportedInstruction(pc) if pc == 36
                )
            }
        },
        3
    );
}

#[test]
fn test_bpf_to_bpf_depth() {
    let config = Config::default();
    for i in 0..config.max_call_depth {
        test_interpreter_and_jit_elf!(
            "tests/elfs/multiple_file.so",
            config,
            [i as u8],
            (
                b"log" => syscalls::BpfSyscallString::init::<BpfSyscallContext, UserError>; syscalls::BpfSyscallString::call,
            ),
            0,
            { |_vm, res: Result| { res.unwrap() == 0 } },
            if i == 0 { 4 } else { 3 + 10 * i as u64 }
        );
    }
}

#[test]
fn test_err_bpf_to_bpf_too_deep() {
    let config = Config::default();
    test_interpreter_and_jit_elf!(
        "tests/elfs/multiple_file.so",
        config,
        [config.max_call_depth as u8],
        (
            b"log" => syscalls::BpfSyscallString::init::<BpfSyscallContext, UserError>; syscalls::BpfSyscallString::call,
        ),
        0,
        {
            |_vm, res: Result| {
                matches!(res.unwrap_err(),
                    EbpfError::CallDepthExceeded(pc, depth)
                    if pc == 55 && depth == config.max_call_depth
                )
            }
        },
        176
    );
}

#[test]
fn test_err_reg_stack_depth() {
    let config = Config::default();
    test_interpreter_and_jit_asm!(
        "
        mov64 r0, 0x1
        lsh64 r0, 0x20
        callx r0
        exit",
        [],
        (),
        0,
        {
            |_vm, res: Result| {
                matches!(res.unwrap_err(),
                    EbpfError::CallDepthExceeded(pc, depth)
                    if pc == 31 && depth == config.max_call_depth
                )
            }
        },
        60
    );
}

// CALL_IMM : Syscalls

/* TODO: syscalls::trash_registers needs asm!().
// https://github.com/rust-lang/rust/issues/72016
#[test]
fn test_call_save() {
    test_interpreter_and_jit_asm!(
        "
        mov64 r6, 0x1
        mov64 r7, 0x20
        mov64 r8, 0x300
        mov64 r9, 0x4000
        call 0
        mov64 r0, 0x0
        or64 r0, r6
        or64 r0, r7
        or64 r0, r8
        or64 r0, r9
        exit",
        [],
        (
            0 => syscalls::trash_registers,
        ),
        { |_vm, res: Result| { res.unwrap() == 0 } }
    );
}*/

#[test]
fn test_err_syscall_string() {
    test_interpreter_and_jit_asm!(
        "
        mov64 r1, 0x0
        syscall BpfSyscallString
        mov64 r0, 0x0
        exit",
        [72, 101, 108, 108, 111],
        (
            b"BpfSyscallString" => syscalls::BpfSyscallString::init::<BpfSyscallContext, UserError>; syscalls::BpfSyscallString::call,
        ),
        0,
        {
            |_vm, res: Result| {
                matches!(res.unwrap_err(),
                    EbpfError::AccessViolation(pc, access_type, vm_addr, len, name)
                    if access_type == AccessType::Load && pc == 0 && vm_addr == 0 && len == 0 && name == "unknown"
                )
            }
        },
        2
    );
}

#[test]
fn test_syscall_string() {
    test_interpreter_and_jit_asm!(
        "
        mov64 r2, 0x5
        syscall BpfSyscallString
        mov64 r0, 0x0
        exit",
        [72, 101, 108, 108, 111],
        (
            b"BpfSyscallString" => syscalls::BpfSyscallString::init::<BpfSyscallContext, UserError>; syscalls::BpfSyscallString::call,
        ),
        0,
        { |_vm, res: Result| { res.unwrap() == 0 } },
        4
    );
}

#[test]
fn test_syscall() {
    test_interpreter_and_jit_asm!(
        "
        mov64 r1, 0xAA
        mov64 r2, 0xBB
        mov64 r3, 0xCC
        mov64 r4, 0xDD
        mov64 r5, 0xEE
        syscall BpfSyscallU64
        mov64 r0, 0x0
        exit",
        [],
        (
            b"BpfSyscallU64" => syscalls::BpfSyscallU64::init::<BpfSyscallContext, UserError>; syscalls::BpfSyscallU64::call,
        ),
        0,
        { |_vm, res: Result| { res.unwrap() == 0 } },
        8
    );
}

#[test]
fn test_call_gather_bytes() {
    test_interpreter_and_jit_asm!(
        "
        mov r1, 1
        mov r2, 2
        mov r3, 3
        mov r4, 4
        mov r5, 5
        syscall BpfGatherBytes
        exit",
        [],
        (
            b"BpfGatherBytes" => syscalls::BpfGatherBytes::init::<BpfSyscallContext, UserError>; syscalls::BpfGatherBytes::call,
        ),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x0102030405 } },
        7
    );
}

#[test]
fn test_call_memfrob() {
    test_interpreter_and_jit_asm!(
        "
        mov r6, r1
        add r1, 2
        mov r2, 4
        syscall BpfMemFrob
        ldxdw r0, [r6]
        be64 r0
        exit",
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, //
        ],
        (
            b"BpfMemFrob" => syscalls::BpfMemFrob::init::<BpfSyscallContext, UserError>; syscalls::BpfMemFrob::call,
        ),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x102292e2f2c0708 } },
        7
    );
}

#[test]
fn test_syscall_with_context() {
    test_interpreter_and_jit_asm!(
        "
        mov64 r1, 0xAA
        mov64 r2, 0xBB
        mov64 r3, 0xCC
        mov64 r4, 0xDD
        mov64 r5, 0xEE
        syscall SyscallWithContext
        mov64 r0, 0x0
        exit",
        [],
        (
            b"SyscallWithContext" => syscalls::SyscallWithContext::init::< syscalls::BpfSyscallContext, UserError>; syscalls::SyscallWithContext::call
        ),
        42,
        { |vm: &EbpfVm<RequisiteVerifier, UserError, TestInstructionMeter>, res: Result| {
            let syscall_context_object = unsafe { &*(vm.get_syscall_context_object(syscalls::SyscallWithContext::call as usize).unwrap() as *const syscalls::SyscallWithContext) };
            assert_eq!(syscall_context_object.context, 84);
            res.unwrap() == 0
        }},
        8
    );
}

type UserContext = u64;
pub struct NestedVmSyscall {}
impl NestedVmSyscall {
    pub fn init<C, E>(_unused: C) -> Box<dyn SyscallObject<UserError>> {
        Box::new(Self {})
    }
}
impl SyscallObject<UserError> for NestedVmSyscall {
    fn call(
        &mut self,
        depth: u64,
        throw: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        _memory_mapping: &mut MemoryMapping,
        result: &mut Result,
    ) {
        #[allow(unused_mut)]
        if depth > 0 {
            let mut syscall_registry = SyscallRegistry::default();
            syscall_registry
                .register_syscall_by_name(
                    b"NestedVmSyscall",
                    NestedVmSyscall::init::<UserContext, UserError>,
                    NestedVmSyscall::call,
                )
                .unwrap();
            let mem = [depth as u8 - 1, throw as u8];
            let mut executable = assemble::<UserError, TestInstructionMeter>(
                "
                ldxb r2, [r1+1]
                ldxb r1, [r1]
                syscall NestedVmSyscall
                exit",
                Config::default(),
                syscall_registry,
            )
            .unwrap();
            test_interpreter_and_jit!(
                executable,
                mem,
                0,
                {
                    |_vm, res: Result| {
                        *result = res;
                        true
                    }
                },
                if throw == 0 { 4 } else { 3 }
            );
        } else {
            *result = if throw == 0 {
                Ok(42)
            } else {
                Err(EbpfError::CallDepthExceeded(33, 0))
            };
        }
    }
}

#[test]
fn test_nested_vm_syscall() {
    let config = Config::default();
    let mut nested_vm_syscall = NestedVmSyscall {};
    let mut memory_mapping = MemoryMapping::new::<UserError>(vec![], &config).unwrap();
    let mut result = Ok(0);
    nested_vm_syscall.call(1, 0, 0, 0, 0, &mut memory_mapping, &mut result);
    assert!(result.unwrap() == 42);
    let mut result = Ok(0);
    nested_vm_syscall.call(1, 1, 0, 0, 0, &mut memory_mapping, &mut result);
    assert!(matches!(result.unwrap_err(),
        EbpfError::CallDepthExceeded(pc, depth)
        if pc == 33 && depth == 0
    ));
}

// Elf

#[test]
fn test_load_elf() {
    test_interpreter_and_jit_elf!(
        "tests/elfs/noop.so",
        [],
        (
            b"log" => syscalls::BpfSyscallString::init::<BpfSyscallContext, UserError>; syscalls::BpfSyscallString::call,
            b"log_64" => syscalls::BpfSyscallU64::init::<BpfSyscallContext, UserError>; syscalls::BpfSyscallU64::call,
        ),
        0,
        { |_vm, res: Result| { res.unwrap() == 0 } },
        11
    );
}

#[test]
fn test_load_elf_empty_noro() {
    test_interpreter_and_jit_elf!(
        "tests/elfs/noro.so",
        [],
        (
            b"log_64" => syscalls::BpfSyscallU64::init::<BpfSyscallContext, UserError>; syscalls::BpfSyscallU64::call,
        ),
        0,
        { |_vm, res: Result| { res.unwrap() == 0 } },
        8
    );
}

#[test]
fn test_load_elf_empty_rodata() {
    test_interpreter_and_jit_elf!(
        "tests/elfs/empty_rodata.so",
        [],
        (
            b"log_64" => syscalls::BpfSyscallU64::init::<BpfSyscallContext, UserError>; syscalls::BpfSyscallU64::call,
        ),
        0,
        { |_vm, res: Result| { res.unwrap() == 0 } },
        8
    );
}

#[test]
fn test_load_elf_rodata() {
    // checks that the program loads the correct rodata offset with both
    // borrowed and owned rodata
    for optimize_rodata in [false, true] {
        let config = Config {
            optimize_rodata,
            ..Config::default()
        };
        test_interpreter_and_jit_elf!(
            "tests/elfs/rodata.so",
            config,
            [],
            (),
            0,
            { |_vm, res: Result| { res.unwrap() == 42 } },
            3
        );
    }
}

#[test]
fn test_load_elf_rodata_high_vaddr() {
    test_interpreter_and_jit_elf!(
        "tests/elfs/rodata_high_vaddr.so",
        [1],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 42 } },
        3
    );
}

#[test]
fn test_custom_entrypoint() {
    let mut file = File::open("tests/elfs/unresolved_syscall.so").expect("file open failed");
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();
    elf[24] = 80; // Move entrypoint to later in the text section
    let config = Config {
        enable_instruction_tracing: true,
        ..Config::default()
    };
    let mut syscall_registry = SyscallRegistry::default();
    test_interpreter_and_jit!(register, syscall_registry, b"log" => syscalls::BpfSyscallString::init::<BpfSyscallContext, UserError>; syscalls::BpfSyscallString::call);
    let mut syscall_registry = SyscallRegistry::default();
    test_interpreter_and_jit!(register, syscall_registry, b"log_64" => syscalls::BpfSyscallU64::init::<BpfSyscallContext, UserError>; syscalls::BpfSyscallU64::call);
    #[allow(unused_mut)]
    let mut executable =
        Executable::<UserError, TestInstructionMeter>::from_elf(&elf, config, syscall_registry)
            .unwrap();
    test_interpreter_and_jit!(
        executable,
        [],
        syscalls::BpfSyscallContext::default(),
        { |_vm, res: Result| { res.unwrap() == 0 } },
        2
    );
}

// Instruction Meter Limit

#[test]
fn test_tight_infinite_loop_conditional() {
    test_interpreter_and_jit_asm!(
        "
        jsge r0, r0, -1
        exit",
        [],
        (),
        0,
        {
            |_vm, res: Result| {
                matches!(res.unwrap_err(),
                    EbpfError::ExceededMaxInstructions(pc, initial_insn_count)
                    if pc == 30 && initial_insn_count == 4
                )
            }
        },
        4
    );
}

#[test]
fn test_tight_infinite_loop_unconditional() {
    test_interpreter_and_jit_asm!(
        "
        ja -1
        exit",
        [],
        (),
        0,
        {
            |_vm, res: Result| {
                matches!(res.unwrap_err(),
                    EbpfError::ExceededMaxInstructions(pc, initial_insn_count)
                    if pc == 30 && initial_insn_count == 4
                )
            }
        },
        4
    );
}

#[test]
fn test_tight_infinite_recursion() {
    test_interpreter_and_jit_asm!(
        "
        entrypoint:
        mov64 r3, 0x41414141
        call entrypoint
        exit",
        [],
        (),
        0,
        {
            |_vm, res: Result| {
                matches!(res.unwrap_err(),
                    EbpfError::ExceededMaxInstructions(pc, initial_insn_count)
                    if pc == 31 && initial_insn_count == 4
                )
            }
        },
        4
    );
}

#[test]
fn test_tight_infinite_recursion_callx() {
    test_interpreter_and_jit_asm!(
        "
        mov64 r8, 0x1
        lsh64 r8, 0x20
        or64 r8, 0x18
        mov64 r3, 0x41414141
        callx r8
        exit",
        [],
        (),
        0,
        {
            |_vm, res: Result| {
                matches!(res.unwrap_err(),
                    EbpfError::ExceededMaxInstructions(pc, initial_insn_count)
                    if pc == 34 && initial_insn_count == 7
                )
            }
        },
        7
    );
}

#[test]
fn test_instruction_count_syscall() {
    test_interpreter_and_jit_asm!(
        "
        mov64 r2, 0x5
        syscall BpfSyscallString
        mov64 r0, 0x0
        exit",
        [72, 101, 108, 108, 111],
        (
            b"BpfSyscallString" => syscalls::BpfSyscallString::init::<BpfSyscallContext, UserError>; syscalls::BpfSyscallString::call,
        ),
        0,
        { |_vm, res: Result| { res.unwrap() == 0 } },
        4
    );
}

#[test]
fn test_err_instruction_count_syscall_capped() {
    test_interpreter_and_jit_asm!(
        "
        mov64 r2, 0x5
        call 0
        mov64 r0, 0x0
        exit",
        [72, 101, 108, 108, 111],
        (
            b"BpfSyscallString" => syscalls::BpfSyscallString::init::<BpfSyscallContext, UserError>; syscalls::BpfSyscallString::call,
        ),
        0,
        {
            |_vm, res: Result| {
                matches!(res.unwrap_err(),
                    EbpfError::ExceededMaxInstructions(pc, initial_insn_count)
                    if pc == 32 && initial_insn_count == 3
                )
            }
        },
        3
    );
}

#[test]
fn test_err_instruction_count_lddw_capped() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 0
        lddw r1, 0x1
        mov r2, 0
        exit
        ",
        [],
        (),
        0,
        {
            |_vm, res: Result| {
                matches!(res.unwrap_err(),
                    EbpfError::ExceededMaxInstructions(pc, initial_insn_count)
                    if pc == 32 && initial_insn_count == 2
                )
            }
        },
        2
    );
}

#[test]
fn test_non_terminate_early() {
    test_interpreter_and_jit_asm!(
        "
        mov64 r6, 0x0
        mov64 r1, 0x0
        mov64 r2, 0x0
        mov64 r3, 0x0
        mov64 r4, 0x0
        mov64 r5, r6
        syscall Unresolved
        add64 r6, 0x1
        ja -0x8
        exit",
        [],
        (),
        0,
        {
            |_vm, res: Result| {
                matches!(res.unwrap_err(),
                    EbpfError::UnsupportedInstruction(pc)
                    if pc == 35
                )
            }
        },
        7
    );
}

#[test]
fn test_err_non_terminate_capped() {
    test_interpreter_and_jit_asm!(
        "
        mov64 r6, 0x0
        mov64 r1, 0x0
        mov64 r2, 0x0
        mov64 r3, 0x0
        mov64 r4, 0x0
        mov64 r5, r6
        syscall BpfTracePrintf
        add64 r6, 0x1
        ja -0x8
        exit",
        [],
        (
            b"BpfTracePrintf" => syscalls::BpfTracePrintf::init::<BpfSyscallContext, UserError>; syscalls::BpfTracePrintf::call,
        ),
        0,
        {
            |_vm, res: Result| {
                matches!(res.unwrap_err(),
                    EbpfError::ExceededMaxInstructions(pc, initial_insn_count)
                    if pc == 35 && initial_insn_count == 6
                )
            }
        },
        6
    );
    test_interpreter_and_jit_asm!(
        "
        mov64 r6, 0x0
        mov64 r1, 0x0
        mov64 r2, 0x0
        mov64 r3, 0x0
        mov64 r4, 0x0
        mov64 r5, r6
        syscall BpfTracePrintf
        add64 r6, 0x1
        ja -0x8
        exit",
        [],
        (
            b"BpfTracePrintf" => syscalls::BpfTracePrintf::init::<BpfSyscallContext, UserError>; syscalls::BpfTracePrintf::call,
        ),
        0,
        {
            |_vm, res: Result| {
                matches!(res.unwrap_err(),
                    EbpfError::ExceededMaxInstructions(pc, initial_insn_count)
                    if pc == 37 && initial_insn_count == 1000
                )
            }
        },
        1000
    );
}

#[test]
fn test_err_capped_before_exception() {
    test_interpreter_and_jit_asm!(
        "
        mov64 r1, 0x0
        mov64 r2, 0x0
        add64 r0, 0x0
        add64 r0, 0x0
        div64 r1, r2
        add64 r0, 0x0
        exit",
        [],
        (),
        0,
        {
            |_vm, res: Result| {
                matches!(res.unwrap_err(),
                    EbpfError::ExceededMaxInstructions(pc, initial_insn_count)
                    if pc == 31 && initial_insn_count == 2
                )
            }
        },
        2
    );
    test_interpreter_and_jit_asm!(
        "
        mov64 r1, 0x0
        mov64 r2, 0x0
        add64 r0, 0x0
        add64 r0, 0x0
        syscall Unresolved
        add64 r0, 0x0
        exit",
        [],
        (),
        0,
        {
            |_vm, res: Result| {
                matches!(res.unwrap_err(),
                    EbpfError::ExceededMaxInstructions(pc, initial_insn_count)
                    if pc == 33 && initial_insn_count == 4
                )
            }
        },
        4
    );
}

#[test]
fn test_err_exit_capped() {
    test_interpreter_and_jit_asm!(
        "
        mov64 r1, 0x1
        lsh64 r1, 0x20
        or64 r1, 0x20
        callx r1
        exit
        ",
        [],
        (),
        0,
        {
            |_vm, res: Result| {
                matches!(res.unwrap_err(),
                    EbpfError::ExceededMaxInstructions(pc, initial_insn_count) if pc == 34 && initial_insn_count == 5
                )
            }
        },
        5
    );
    test_interpreter_and_jit_asm!(
        "
        mov64 r1, 0x1
        lsh64 r1, 0x20
        or64 r1, 0x20
        callx r1
        mov r0, r0
        exit
        ",
        [],
        (),
        0,
        {
            |_vm, res: Result| {
                matches!(res.unwrap_err(),
                    EbpfError::ExceededMaxInstructions(pc, initial_insn_count) if pc == 35 && initial_insn_count == 6
                )
            }
        },
        6
    );
    test_interpreter_and_jit_asm!(
        "
        call 0
        mov r0, r0
        exit
        ",
        [],
        (),
        0,
        {
            |_vm, res: Result| {
                matches!(res.unwrap_err(),
                    EbpfError::ExceededMaxInstructions(pc, initial_insn_count) if pc == 32 && initial_insn_count == 3
                )
            }
        },
        3
    );
}

// Symbols and Relocation

#[test]
fn test_symbol_relocation() {
    test_interpreter_and_jit_asm!(
        "
        mov64 r1, r10
        sub64 r1, 0x1
        mov64 r2, 0x1
        syscall BpfSyscallString
        mov64 r0, 0x0
        exit",
        [72, 101, 108, 108, 111],
        (
            b"BpfSyscallString" => syscalls::BpfSyscallString::init::<BpfSyscallContext, UserError>; syscalls::BpfSyscallString::call
        ),
        0,
        { |_vm, res: Result| { res.unwrap() == 0 } },
        6
    );
}

#[test]
fn test_err_call_unresolved() {
    test_interpreter_and_jit_asm!(
        "
        mov r1, 1
        mov r2, 2
        mov r3, 3
        mov r4, 4
        mov r5, 5
        syscall Unresolved
        mov64 r0, 0x0
        exit",
        [],
        (),
        0,
        {
            |_vm, res: Result| matches!(res.unwrap_err(), EbpfError::UnsupportedInstruction(pc) if pc == 34)
        },
        6
    );
}

#[test]
fn test_err_unresolved_elf() {
    let mut syscall_registry = SyscallRegistry::default();
    test_interpreter_and_jit!(register, syscall_registry, b"log" => syscalls::BpfSyscallString::init::<BpfSyscallContext, UserError>; syscalls::BpfSyscallString::call);
    let mut file = File::open("tests/elfs/unresolved_syscall.so").unwrap();
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();
    let config = Config {
        reject_broken_elfs: true,
        ..Config::default()
    };
    assert!(
        matches!(Executable::<UserError, TestInstructionMeter>::from_elf(&elf, config, syscall_registry), Err(EbpfError::ElfError(ElfError::UnresolvedSymbol(symbol, pc, offset))) if symbol == "log_64" && pc == 550 && offset == 4168)
    );
}

#[test]
fn test_syscall_static() {
    test_interpreter_and_jit_elf!(
        "tests/elfs/syscall_static.so",
        [],
        (
            b"log" => syscalls::BpfSyscallString::init::<BpfSyscallContext, UserError>; syscalls::BpfSyscallString::call,
        ),
        0,
        { |_vm, res: Result| { res.unwrap() == 0 } },
        5
    );
}

#[test]
fn test_syscall_unknown_static() {
    // Check that unknown static syscalls result in UnsupportedInstruction.
    //
    // See also elf::test::test_static_syscall_disabled for the corresponding
    // check with config.syscalls_static=false.
    test_interpreter_and_jit_elf!(
        "tests/elfs/syscall_static_unknown.so",
        [],
        (
            b"log" => syscalls::BpfSyscallString::init::<BpfSyscallContext, UserError>; syscalls::BpfSyscallString::call,
        ),
        0,
        { |_vm, res: Result| { matches!(res.unwrap_err(), EbpfError::UnsupportedInstruction(29)) } },
        1
    );
}

#[test]
fn test_reloc_64_64() {
    // Tests the correctness of R_BPF_64_64 relocations. The program returns the
    // address of the entrypoint.
    //   [ 1] .text             PROGBITS        00000000000000e8 0000e8 000018 00  AX  0   0  8
    test_interpreter_and_jit_elf!(
        "tests/elfs/reloc_64_64.so",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == ebpf::MM_PROGRAM_START + 0xe8 } },
        2
    );
}

#[test]
fn test_reloc_64_64_high_vaddr() {
    // Same as test_reloc_64_64, but with .text already alinged to
    // MM_PROGRAM_START by the linker
    test_interpreter_and_jit_elf!(
        "tests/elfs/reloc_64_64_high_vaddr.so",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == ebpf::MM_PROGRAM_START } },
        2
    );
}

#[test]
fn test_reloc_64_relative() {
    // Tests the correctness of R_BPF_64_RELATIVE relocations. The program
    // returns the address of the first .rodata byte.
    //   [ 1] .text             PROGBITS        00000000000000e8 0000e8 000018 00  AX  0   0  8
    //   [ 2] .rodata           PROGBITS        0000000000000100 000100 00000b 01 AMS  0   0  1
    test_interpreter_and_jit_elf!(
        "tests/elfs/reloc_64_relative.so",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == ebpf::MM_PROGRAM_START + 0x100 } },
        2
    );
}

#[test]
fn test_reloc_64_relative_high_vaddr() {
    // Same as test_reloc_64_relative, but with .text placed already within
    // MM_PROGRAM_START by the linker
    // [ 1] .text             PROGBITS        0000000100000000 001000 000018 00  AX  0   0  8
    // [ 2] .rodata           PROGBITS        0000000100000018 001018 00000b 01 AMS  0   0  1
    test_interpreter_and_jit_elf!(
        "tests/elfs/reloc_64_relative_high_vaddr.so",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == ebpf::MM_PROGRAM_START + 0x18 } },
        2
    );
}

#[test]
fn test_reloc_64_relative_data() {
    // Tests the correctness of R_BPF_64_RELATIVE relocations in sections other
    // than .text. The program returns the address of the first .rodata byte.
    // [ 1] .text             PROGBITS        00000000000000e8 0000e8 000020 00  AX  0   0  8
    // [ 2] .rodata           PROGBITS        0000000000000108 000108 000019 01 AMS  0   0  1
    //
    // 00000000000001f8 <FILE>:
    // 63:       08 01 00 00 00 00 00 00
    test_interpreter_and_jit_elf!(
        "tests/elfs/reloc_64_relative_data.so",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == ebpf::MM_PROGRAM_START + 0x108 } },
        3
    );
}

#[test]
fn test_reloc_64_relative_data_high_vaddr() {
    // Same as test_reloc_64_relative_data, but with rodata already placed
    // within MM_PROGRAM_START by the linker
    // [ 1] .text             PROGBITS        0000000100000000 001000 000020 00  AX  0   0  8
    // [ 2] .rodata           PROGBITS        0000000100000020 001020 000019 01 AMS  0   0  1
    //
    // 0000000100000110 <FILE>:
    // 536870946:      20 00 00 00 01 00 00 00
    test_interpreter_and_jit_elf!(
        "tests/elfs/reloc_64_relative_data_high_vaddr.so",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == ebpf::MM_PROGRAM_START + 0x20 } },
        3
    );
}

#[test]
fn test_reloc_64_relative_data_pre_sbfv2() {
    // Before https://github.com/solana-labs/llvm-project/pull/35, we used to
    // generate invalid R_BPF_64_RELATIVE relocations in sections other than
    // .text.
    //
    // This test checks that the old behaviour is maintained for backwards
    // compatibility when dealing with non-sbfv2 files. See also Elf::relocate().
    //
    // The program returns the address of the first .rodata byte.
    // [ 1] .text             PROGBITS        00000000000000e8 0000e8 000020 00  AX  0   0  8
    // [ 2] .rodata           PROGBITS        0000000000000108 000108 000019 01 AMS  0   0  1
    //
    // 00000000000001f8 <FILE>:
    // 63:       00 00 00 00 08 01 00 00
    test_interpreter_and_jit_elf!(
        "tests/elfs/reloc_64_relative_data_pre_sbfv2.so",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == ebpf::MM_PROGRAM_START + 0x108 } },
        3
    );
}

// Programs

#[test]
fn test_mul_loop() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 0x7
        add r1, 0xa
        lsh r1, 0x20
        rsh r1, 0x20
        jeq r1, 0x0, +4
        mov r0, 0x7
        mul r0, 0x7
        add r1, -1
        jne r1, 0x0, -3
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x75db9c97 } },
        37
    );
}

#[test]
fn test_prime() {
    test_interpreter_and_jit_asm!(
        "
        mov r1, 67
        mov r0, 0x1
        mov r2, 0x2
        jgt r1, 0x2, +4
        ja +10
        add r2, 0x1
        mov r0, 0x1
        jge r2, r1, +7
        mov r3, r1
        div r3, r2
        mul r3, r2
        mov r4, r1
        sub r4, r3
        mov r0, 0x0
        jne r4, 0x0, -10
        exit",
        [],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x1 } },
        655
    );
}

#[test]
fn test_subnet() {
    test_interpreter_and_jit_asm!(
        "
        mov r2, 0xe
        ldxh r3, [r1+12]
        jne r3, 0x81, +2
        mov r2, 0x12
        ldxh r3, [r1+16]
        and r3, 0xffff
        jne r3, 0x8, +5
        add r1, r2
        mov r0, 0x1
        ldxw r1, [r1+16]
        and r1, 0xffffff
        jeq r1, 0x1a8c0, +1
        mov r0, 0x0
        exit",
        [
            0x00, 0x00, 0xc0, 0x9f, 0xa0, 0x97, 0x00, 0xa0, //
            0xcc, 0x3b, 0xbf, 0xfa, 0x08, 0x00, 0x45, 0x10, //
            0x00, 0x3c, 0x46, 0x3c, 0x40, 0x00, 0x40, 0x06, //
            0x73, 0x1c, 0xc0, 0xa8, 0x01, 0x02, 0xc0, 0xa8, //
            0x01, 0x01, 0x06, 0x0e, 0x00, 0x17, 0x99, 0xc5, //
            0xa0, 0xec, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, //
            0x7d, 0x78, 0xe0, 0xa3, 0x00, 0x00, 0x02, 0x04, //
            0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x00, 0x9c, //
            0x27, 0x24, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, //
            0x03, 0x00, //
        ],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x1 } },
        11
    );
}

#[test]
fn test_tcp_port80_match() {
    test_interpreter_and_jit_asm!(
        PROG_TCP_PORT_80,
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00, 0x06, //
            0x07, 0x08, 0x09, 0x0a, 0x08, 0x00, 0x45, 0x00, //
            0x00, 0x56, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, //
            0xf9, 0x4d, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, //
            0x00, 0x02, 0x27, 0x10, 0x00, 0x50, 0x00, 0x00, //
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, //
            0x20, 0x00, 0xc5, 0x18, 0x00, 0x00, 0x44, 0x44, //
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, //
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, //
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, //
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, //
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, //
            0x44, 0x44, 0x44, 0x44, //
        ],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x1 } },
        17
    );
}

#[test]
fn test_tcp_port80_nomatch() {
    test_interpreter_and_jit_asm!(
        PROG_TCP_PORT_80,
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00, 0x06, //
            0x07, 0x08, 0x09, 0x0a, 0x08, 0x00, 0x45, 0x00, //
            0x00, 0x56, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, //
            0xf9, 0x4d, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, //
            0x00, 0x02, 0x00, 0x16, 0x27, 0x10, 0x00, 0x00, //
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x51, 0x02, //
            0x20, 0x00, 0xc5, 0x18, 0x00, 0x00, 0x44, 0x44, //
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, //
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, //
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, //
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, //
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, //
            0x44, 0x44, 0x44, 0x44, //
        ],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x0 } },
        18
    );
}

#[test]
fn test_tcp_port80_nomatch_ethertype() {
    test_interpreter_and_jit_asm!(
        PROG_TCP_PORT_80,
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00, 0x06, //
            0x07, 0x08, 0x09, 0x0a, 0x08, 0x01, 0x45, 0x00, //
            0x00, 0x56, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, //
            0xf9, 0x4d, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, //
            0x00, 0x02, 0x27, 0x10, 0x00, 0x50, 0x00, 0x00, //
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, //
            0x20, 0x00, 0xc5, 0x18, 0x00, 0x00, 0x44, 0x44, //
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, //
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, //
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, //
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, //
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, //
            0x44, 0x44, 0x44, 0x44, //
        ],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x0 } },
        7
    );
}

#[test]
fn test_tcp_port80_nomatch_proto() {
    test_interpreter_and_jit_asm!(
        PROG_TCP_PORT_80,
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00, 0x06, //
            0x07, 0x08, 0x09, 0x0a, 0x08, 0x00, 0x45, 0x00, //
            0x00, 0x56, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, //
            0xf9, 0x4d, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, //
            0x00, 0x02, 0x27, 0x10, 0x00, 0x50, 0x00, 0x00, //
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, //
            0x20, 0x00, 0xc5, 0x18, 0x00, 0x00, 0x44, 0x44, //
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, //
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, //
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, //
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, //
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, //
            0x44, 0x44, 0x44, 0x44, //
        ],
        (),
        0,
        { |_vm, res: Result| { res.unwrap() == 0x0 } },
        9
    );
}

#[test]
fn test_tcp_sack_match() {
    test_interpreter_and_jit_asm!(
        TCP_SACK_ASM,
        TCP_SACK_MATCH,
        (),
        0,
        { |_vm, res: Result| res.unwrap() == 0x1 },
        79
    );
}

#[test]
fn test_tcp_sack_nomatch() {
    test_interpreter_and_jit_asm!(
        TCP_SACK_ASM,
        TCP_SACK_NOMATCH,
        (),
        0,
        { |_vm, res: Result| res.unwrap() == 0x0 },
        55
    );
}

#[inline(never)]
fn copy_ebpf_error(err: &mut EbpfError<UserError>) {
    *err = EbpfError::DivideByZero(0);
}

#[inline(never)]
fn copy_result(err: &mut Result) {
    *err = Result::Err(EbpfError::DivideByZero(0));
}

#[test]
fn test_result_discriminant_size() {
    unsafe {
        // Create a Result<u64, EbpfError<UserError>> filled with 0xaa
        let test: [u8; std::mem::size_of::<Result>()] = [0xaa; std::mem::size_of::<Result>()];
        let mut test_result =
            std::mem::transmute::<[u8; std::mem::size_of::<Result>()], Result>(test);
        // Overwrite the Result with another result
        copy_result(&mut test_result);

        // Check that all 64-bits of the discriminant were changed
        let err_kind = *(&test_result as *const _ as *const u64);
        assert_eq!(err_kind, 1u64);
    }
}

#[test]
fn test_err_discriminant_size() {
    unsafe {
        // Create a EbpfError filled with 0xaa
        let test: [u8; std::mem::size_of::<EbpfError<UserError>>()] =
            [0xaa; std::mem::size_of::<EbpfError<UserError>>()];
        let mut test_err = std::mem::transmute::<
            [u8; std::mem::size_of::<EbpfError<UserError>>()],
            EbpfError<UserError>,
        >(test);
        // Overwrite the EbpfError with another error
        copy_ebpf_error(&mut test_err);

        // Check that all 64-bits of the discriminant were changed
        let err_kind = *(&test_err as *const _ as *const u64);
        assert_eq!(err_kind, 8u64);
    }
}

// Fuzzy

#[cfg(all(not(windows), target_arch = "x86_64"))]
fn execute_generated_program(prog: &[u8]) -> bool {
    let max_instruction_count = 1024;
    let mem_size = 1024 * 1024;
    let mut bpf_functions = BTreeMap::new();
    let config = Config {
        enable_instruction_tracing: true,
        ..Config::default()
    };
    let syscall_registry = SyscallRegistry::default();
    register_bpf_function(
        &config,
        &mut bpf_functions,
        &syscall_registry,
        0,
        "entrypoint",
    )
    .unwrap();
    let executable = Executable::<UserError, TestInstructionMeter>::from_text_bytes(
        prog,
        config,
        syscall_registry,
        bpf_functions,
    );
    let executable = if let Ok(executable) = executable {
        executable
    } else {
        return false;
    };
    let verified_executable = VerifiedExecutable::<
        solana_rbpf::verifier::RequisiteVerifier,
        UserError,
        TestInstructionMeter,
    >::from_executable(executable);
    let mut verified_executable = if let Ok(verified_executable) = verified_executable {
        verified_executable
    } else {
        return false;
    };
    if verified_executable.jit_compile().is_err() {
        return false;
    }
    let (instruction_count_interpreter, tracer_interpreter, result_interpreter) = {
        let mut mem = vec![0u8; mem_size];
        let mem_region = MemoryRegion::new_writable(&mut mem, ebpf::MM_INPUT_START);
        let mut vm = EbpfVm::new(&verified_executable, &mut [], vec![mem_region]).unwrap();
        let result_interpreter = vm.execute_program_interpreted(&mut TestInstructionMeter {
            remaining: max_instruction_count,
        });
        let tracer_interpreter = vm.get_tracer().clone();
        (
            vm.get_total_instruction_count(),
            tracer_interpreter,
            result_interpreter,
        )
    };
    let mut mem = vec![0u8; mem_size];
    let mem_region = MemoryRegion::new_writable(&mut mem, ebpf::MM_INPUT_START);
    let mut vm = EbpfVm::new(&verified_executable, &mut [], vec![mem_region]).unwrap();
    let result_jit = vm.execute_program_jit(&mut TestInstructionMeter {
        remaining: max_instruction_count,
    });
    let tracer_jit = vm.get_tracer();
    if result_interpreter != result_jit
        || !solana_rbpf::vm::Tracer::compare(&tracer_interpreter, tracer_jit)
    {
        let analysis = solana_rbpf::static_analysis::Analysis::from_executable(
            verified_executable.get_executable(),
        )
        .unwrap();
        println!("result_interpreter={:?}", result_interpreter);
        println!("result_jit={:?}", result_jit);
        let stdout = std::io::stdout();
        tracer_interpreter
            .write(&mut stdout.lock(), &analysis)
            .unwrap();
        tracer_jit.write(&mut stdout.lock(), &analysis).unwrap();
        panic!();
    }
    if verified_executable
        .get_executable()
        .get_config()
        .enable_instruction_meter
    {
        let instruction_count_jit = vm.get_total_instruction_count();
        assert_eq!(instruction_count_interpreter, instruction_count_jit);
    }
    true
}

#[cfg(all(not(windows), target_arch = "x86_64"))]
#[test]
fn test_total_chaos() {
    let instruction_count = 6;
    let iteration_count = 1000000;
    let mut program = vec![0; instruction_count * ebpf::INSN_SIZE];
    program[ebpf::INSN_SIZE * (instruction_count - 1)..ebpf::INSN_SIZE * instruction_count]
        .copy_from_slice(&[ebpf::EXIT, 0, 0, 0, 0, 0, 0, 0]);
    let seed = 0xC2DB2F8F282284A0;
    let mut prng = SmallRng::seed_from_u64(seed);
    for _ in 0..iteration_count {
        prng.fill_bytes(&mut program[0..ebpf::INSN_SIZE * (instruction_count - 1)]);
        execute_generated_program(&program);
    }
    for _ in 0..iteration_count {
        prng.fill_bytes(&mut program[0..ebpf::INSN_SIZE * (instruction_count - 1)]);
        for index in (0..program.len()).step_by(ebpf::INSN_SIZE) {
            program[index + 0x1] &= 0x77;
            program[index + 0x2] &= 0x00;
            program[index + 0x3] &= 0x77;
            program[index + 0x4] &= 0x00;
            program[index + 0x5] &= 0x77;
            program[index + 0x6] &= 0x77;
            program[index + 0x7] &= 0x77;
        }
        execute_generated_program(&program);
    }
}
