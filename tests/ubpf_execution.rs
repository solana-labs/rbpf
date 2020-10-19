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

use solana_rbpf::{
    assembler::assemble,
    ebpf::{self, hash_symbol_name},
    elf::ELFError,
    error::EbpfError,
    memory_region::AccessType,
    syscalls,
    user_error::UserError,
    verifier::check,
    vm::{Config, DefaultInstructionMeter, EbpfVm, Executable, Syscall},
};
use std::{fs::File, io::Read};
use test_utils::{
    bpf_syscall_string, bpf_syscall_u64, bpf_trace_printf, ExecResult, SyscallWithContext,
    TestInstructionMeter, PROG_TCP_PORT_80, TCP_SACK_ASM, TCP_SACK_MATCH, TCP_SACK_NOMATCH,
};

macro_rules! test_interpreter_and_jit {
    ($vm:expr, $($location:expr => $syscall:expr),*) => {
        $($vm.register_syscall($location, $syscall).unwrap();)*
    };
    ( $executable:expr, $mem:tt, ($($location:expr => $syscall:expr),* $(,)?), $check:block, $expected_instruction_count:expr ) => {
        let check_closure = $check;
        let instruction_count_interpreter = {
            let mem = $mem;
            let mut vm = EbpfVm::<UserError, TestInstructionMeter>::new($executable.as_ref(), Config::default(), &mem, &[]).unwrap();
            test_interpreter_and_jit!(vm, $($location => $syscall),*);
            assert!(check_closure(vm.execute_program_interpreted(&mut TestInstructionMeter { remaining: $expected_instruction_count })));
            vm.get_total_instruction_count()
        };
        #[cfg(not(windows))]
        {
            let mem = $mem;
            let mut vm = EbpfVm::<UserError, TestInstructionMeter>::new($executable.as_ref(), Config::default(), &mem, &[]).unwrap();
            test_interpreter_and_jit!(vm, $($location => $syscall),*);
            match vm.jit_compile() {
                Err(err) => assert!(check_closure(Err(err))),
                Ok(()) => {
                    assert!(check_closure(unsafe { vm.execute_program_jit(&mut TestInstructionMeter { remaining: $expected_instruction_count }) }));
                    let instruction_count_jit = vm.get_total_instruction_count();
                    assert_eq!(instruction_count_interpreter, instruction_count_jit);
                },
            }
        }
        assert_eq!(instruction_count_interpreter, $expected_instruction_count);
    };
}

macro_rules! test_interpreter_and_jit_asm {
    ( $source:tt, $mem:tt, ($($location:expr => $syscall:expr),* $(,)?), $check:block, $expected_instruction_count:expr ) => {
        let program = assemble($source).unwrap();
        let executable = Executable::<UserError>::from_text_bytes(&program, None).unwrap();
        test_interpreter_and_jit!(executable, $mem, ($($location => $syscall),*), $check, $expected_instruction_count);
    };
}

macro_rules! test_interpreter_and_jit_elf {
    ( $source:tt, $mem:tt, ($($location:expr => $syscall:expr),* $(,)?), $check:block, $expected_instruction_count:expr ) => {
        let mut file = File::open($source).unwrap();
        let mut elf = Vec::new();
        file.read_to_end(&mut elf).unwrap();
        let executable = Executable::<UserError>::from_elf(&elf, None).unwrap();
        test_interpreter_and_jit!(executable, $mem, ($($location => $syscall),*), $check, $expected_instruction_count);
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
        { |res: ExecResult| { res.unwrap() == 0x1 } },
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
        { |res: ExecResult| { res.unwrap() == 0xffffffff } },
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
        { |res: ExecResult| { res.unwrap() == 0xffffffff } },
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
        { |res: ExecResult| { res.unwrap() == 0x1 } },
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
        { |res: ExecResult| { res.unwrap() == 0x3 } },
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
        { |res: ExecResult| { res.unwrap() == 0xfffffffe } },
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
        { |res: ExecResult| { res.unwrap() == 0xfffffffffffffffe } },
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
        { |res: ExecResult| { res.unwrap() == 0x2a } },
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
        { |res: ExecResult| { res.unwrap() == 0x2a } },
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
        { |res: ExecResult| { res.unwrap() == 600 } },
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
        { |res: ExecResult| { res.unwrap() == 0x11 } },
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
        { |res: ExecResult| { res.unwrap() == 0x11 } },
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
        { |res: ExecResult| { res.unwrap() == 0x4 } },
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
        { |res: ExecResult| { res.unwrap() == 0xffff8000 } },
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
        { |res: ExecResult| { res.unwrap() == 0xffff8000 } },
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
        { |res: ExecResult| { res.unwrap() == 0xfffffffffffffff8 } },
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
        { |res: ExecResult| { res.unwrap() == 0x10 } },
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
        { |res: ExecResult| { res.unwrap() == 0x00ffffff } },
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
        { |res: ExecResult| { res.unwrap() == 0x1 } },
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
        { |res: ExecResult| { res.unwrap() == 0x1122 } },
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
        { |res: ExecResult| { res.unwrap() == 0x1122 } },
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
        { |res: ExecResult| { res.unwrap() == 0x11223344 } },
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
        { |res: ExecResult| { res.unwrap() == 0x11223344 } },
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
        { |res: ExecResult| { res.unwrap() == 0x1122334455667788 } },
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
        { |res: ExecResult| { res.unwrap() == 0x1122 } },
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
        { |res: ExecResult| { res.unwrap() == 0x11223344 } },
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
        { |res: ExecResult| { res.unwrap() == 0x1122334455667788 } },
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
        { |res: ExecResult| { res.unwrap() == 0xc } },
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
        { |res: ExecResult| { res.unwrap() == 0xc } },
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
        { |res: ExecResult| { res.unwrap() == 0x4 } },
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
        { |res: ExecResult| { res.unwrap() == 0x100000004 } },
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
        { |res: ExecResult| { res.unwrap() == 0x100000004 } },
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
        { |res: ExecResult| { res.unwrap() == 0x3 } },
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
        { |res: ExecResult| { res.unwrap() == 0x3 } },
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
        { |res: ExecResult| { res.unwrap() == 0x3 } },
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
        { |res: ExecResult| { res.unwrap() == 0x300000000 } },
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
        { |res: ExecResult| { res.unwrap() == 0x300000000 } },
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
        { |res: ExecResult| matches!(res.unwrap_err(), EbpfError::DivideByZero(pc) if pc == 31) },
        3
    );
}

#[test]
fn test_err_div_by_zero_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 1
        mov32 r1, 0
        div32 r0, r1
        exit",
        [],
        (),
        { |res: ExecResult| matches!(res.unwrap_err(), EbpfError::DivideByZero(pc) if pc == 31) },
        3
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
        { |res: ExecResult| { res.unwrap() == 0x5 } },
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
        { |res: ExecResult| { res.unwrap() == 0x0 } },
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
        { |res: ExecResult| { res.unwrap() == 0x30ba5a04 } },
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
        { |res: ExecResult| matches!(res.unwrap_err(), EbpfError::DivideByZero(pc) if pc == 31) },
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
        { |res: ExecResult| matches!(res.unwrap_err(), EbpfError::DivideByZero(pc) if pc == 31) },
        3
    );
}

// BPF_LD : Loads

#[test]
fn test_ldabsb() {
    test_interpreter_and_jit_asm!(
        "
        ldabsb 0x3
        exit",
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, //
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, //
        ],
        (),
        { |res: ExecResult| { res.unwrap() == 0x33 } },
        2
    );
}

#[test]
fn test_ldabsh() {
    test_interpreter_and_jit_asm!(
        "
        ldabsh 0x3
        exit",
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, //
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, //
        ],
        (),
        { |res: ExecResult| { res.unwrap() == 0x4433 } },
        2
    );
}

#[test]
fn test_ldabsw() {
    test_interpreter_and_jit_asm!(
        "
        ldabsw 0x3
        exit",
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, //
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, //
        ],
        (),
        { |res: ExecResult| { res.unwrap() == 0x66554433 } },
        2
    );
}

#[test]
fn test_ldabsdw() {
    test_interpreter_and_jit_asm!(
        "
        ldabsdw 0x3
        exit",
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, //
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, //
        ],
        (),
        { |res: ExecResult| { res.unwrap() == 0xaa99887766554433 } },
        2
    );
}

#[test]
fn test_err_ldabsb_oob() {
    test_interpreter_and_jit_asm!(
        "
        ldabsb 0x33
        exit",
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, //
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, //
        ],
        (),
        {
            |res: ExecResult| {
                matches!(res.unwrap_err(),
                    EbpfError::AccessViolation(pc, access_type, _, _, _)
                    if access_type == AccessType::Load && pc == 29
                )
            }
        },
        1
    );
}

#[test]
fn test_err_ldabsb_nomem() {
    test_interpreter_and_jit_asm!(
        "
        ldabsb 0x33
        exit",
        [],
        (),
        {
            |res: ExecResult| {
                matches!(res.unwrap_err(),
                    EbpfError::AccessViolation(pc, access_type, _, _, _)
                    if access_type == AccessType::Load && pc == 29
                )
            }
        },
        1
    );
}

#[test]
fn test_ldindb() {
    test_interpreter_and_jit_asm!(
        "
        mov64 r1, 0x5
        ldindb r1, 0x3
        exit",
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, //
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, //
        ],
        (),
        { |res: ExecResult| { res.unwrap() == 0x88 } },
        3
    );
}

#[test]
fn test_ldindh() {
    test_interpreter_and_jit_asm!(
        "
        mov64 r1, 0x5
        ldindh r1, 0x3
        exit",
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, //
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, //
        ],
        (),
        { |res: ExecResult| { res.unwrap() == 0x9988 } },
        3
    );
}

#[test]
fn test_ldindw() {
    test_interpreter_and_jit_asm!(
        "
        mov64 r1, 0x4
        ldindw r1, 0x1
        exit",
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, //
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, //
        ],
        (),
        { |res: ExecResult| { res.unwrap() == 0x88776655 } },
        3
    );
}

#[test]
fn test_ldinddw() {
    test_interpreter_and_jit_asm!(
        "
        mov64 r1, 0x2
        ldinddw r1, 0x3
        exit",
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, //
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, //
        ],
        (),
        { |res: ExecResult| { res.unwrap() == 0xccbbaa9988776655 } },
        3
    );
}

#[test]
fn test_err_ldindb_oob() {
    test_interpreter_and_jit_asm!(
        "
        mov64 r1, 0x5
        ldindb r1, 0x33
        exit",
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, //
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, //
        ],
        (),
        {
            |res: ExecResult| {
                matches!(res.unwrap_err(),
                    EbpfError::AccessViolation(pc, access_type, _, _, _)
                    if access_type == AccessType::Load && pc == 30
                )
            }
        },
        2
    );
}

#[test]
fn test_err_ldindb_nomem() {
    test_interpreter_and_jit_asm!(
        "
        mov64 r1, 0x5
        ldindb r1, 0x33
        exit",
        [],
        (),
        {
            |res: ExecResult| {
                matches!(res.unwrap_err(),
                    EbpfError::AccessViolation(pc, access_type, _, _, _)
                    if access_type == AccessType::Load && pc == 30
                )
            }
        },
        2
    );
}

#[test]
fn test_ldxb() {
    test_interpreter_and_jit_asm!(
        "
        ldxb r0, [r1+2]
        exit",
        [0xaa, 0xbb, 0x11, 0xcc, 0xdd],
        (),
        { |res: ExecResult| { res.unwrap() == 0x11 } },
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
        { |res: ExecResult| { res.unwrap() == 0x2211 } },
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
        { |res: ExecResult| { res.unwrap() == 0x44332211 } },
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
        { |res: ExecResult| { res.unwrap() == 0x1234 } },
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
        { |res: ExecResult| { res.unwrap() == 0x8877665544332211 } },
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
        {
            |res: ExecResult| {
                matches!(res.unwrap_err(),
                    EbpfError::AccessViolation(pc, access_type, _, _, _)
                    if access_type == AccessType::Load && pc == 29
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
        { |res: ExecResult| { res.unwrap() == 0x9876543210 } },
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
        { |res: ExecResult| { res.unwrap() == 0x9876543210 } },
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
        { |res: ExecResult| { res.unwrap() == 0x3ff } },
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
        { |res: ExecResult| { res.unwrap() == 0x030f0f } },
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
        { |res: ExecResult| { res.unwrap() == 0x1122334455667788 } },
        2
    );
}

#[test]
fn test_lddw2() {
    test_interpreter_and_jit_asm!(
        "
        lddw r0, 0x0000000080000000
        exit",
        [],
        (),
        { |res: ExecResult| { res.unwrap() == 0x80000000 } },
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
        { |res: ExecResult| { res.unwrap() == 0x11 } },
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
        { |res: ExecResult| { res.unwrap() == 0x2211 } },
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
        { |res: ExecResult| { res.unwrap() == 0x44332211 } },
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
        { |res: ExecResult| { res.unwrap() == 0x44332211 } },
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
        { |res: ExecResult| { res.unwrap() == 0x11 } },
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
        { |res: ExecResult| { res.unwrap() == 0x2211 } },
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
        { |res: ExecResult| { res.unwrap() == 0x44332211 } },
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
        { |res: ExecResult| { res.unwrap() == 0x8877665544332211 } },
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
        { |res: ExecResult| { res.unwrap() == 0xf0f2f3f4f5f6f7f8 } },
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
        { |res: ExecResult| { res.unwrap() == 0xf1f9 } },
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
        { |res: ExecResult| { res.unwrap() == 0x2a } },
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
        { |res: ExecResult| { res.unwrap() == 0x0 } },
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
        { |res: ExecResult| { res.unwrap() == 0x0 } },
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
        { |res: ExecResult| { res.unwrap() == 0x3 } },
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
        { |res: ExecResult| { res.unwrap() == 0x1 } },
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
        { |res: ExecResult| { res.unwrap() == 0x1 } },
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
        { |res: ExecResult| { res.unwrap() == 0x1 } },
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
        { |res: ExecResult| { res.unwrap() == 0x1 } },
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
        { |res: ExecResult| { res.unwrap() == 0x1 } },
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
        { |res: ExecResult| { res.unwrap() == 0x1 } },
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
        { |res: ExecResult| { res.unwrap() == 0x1 } },
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
        { |res: ExecResult| { res.unwrap() == 0x1 } },
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
        { |res: ExecResult| { res.unwrap() == 0x1 } },
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
        { |res: ExecResult| { res.unwrap() == 0x1 } },
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
        { |res: ExecResult| { res.unwrap() == 0x1 } },
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
        { |res: ExecResult| { res.unwrap() == 0x1 } },
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
        { |res: ExecResult| { res.unwrap() == 0x1 } },
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
        { |res: ExecResult| { res.unwrap() == 0x1 } },
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
        { |res: ExecResult| { res.unwrap() == 0x1 } },
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
        { |res: ExecResult| { res.unwrap() == 0x1 } },
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
        { |res: ExecResult| { res.unwrap() == 0x1 } },
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
        { |res: ExecResult| { res.unwrap() == 0x1 } },
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
        { |res: ExecResult| { res.unwrap() == 0x1 } },
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
        { |res: ExecResult| { res.unwrap() == 0x1 } },
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
        { |res: ExecResult| { res.unwrap() == 0x1 } },
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
        { |res: ExecResult| { res.unwrap() == 0x1 } },
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
        { |res: ExecResult| { res.unwrap() == 0x1 } },
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
        { |res: ExecResult| { res.unwrap() == 0xcd } },
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
        call 1
        mov r1, 0
        ldxb r2, [r10-4]
        ldxb r3, [r10-3]
        ldxb r4, [r10-2]
        ldxb r5, [r10-1]
        call 0
        xor r0, 0x2a2a2a2a
        exit",
        [],
        (
            0 => Syscall::Function(syscalls::gather_bytes),
            1 => Syscall::Function(syscalls::memfrob),
        ),
        { |res: ExecResult| { res.unwrap() == 0x01020304 } },
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
        call 0
        mov r1, r0
        mov r0, 0x1
        lsh r1, 0x20
        rsh r1, 0x20
        jne r1, 0x0, +11
        mov r1, r10
        add r1, -8
        mov r2, r10
        add r2, -16
        call 0
        mov r1, r0
        lsh r1, 0x20
        rsh r1, 0x20
        mov r0, 0x1
        jeq r1, r6, +1
        mov r0, 0x0
        exit",
        [],
        (
            0 => Syscall::Function(syscalls::strcmp),
        ),
        { |res: ExecResult| { res.unwrap() == 0x0 } },
        28
    );
}

#[test]
fn test_err_stack_out_of_bound() {
    test_interpreter_and_jit_asm!(
        "
        stb [r10-0x4000], 0
        exit",
        [],
        (),
        {
            |res: ExecResult| {
                matches!(res.unwrap_err(),
                    EbpfError::AccessViolation(pc, access_type, _, _, _)
                    if access_type == AccessType::Store && pc == 29
                )
            }
        },
        1
    );
}

// CALL_IMM & CALL_REG : Procedure Calls

#[test]
fn test_relative_call() {
    test_interpreter_and_jit_elf!(
        "tests/elfs/relative_call.so",
        [1],
        (
            hash_symbol_name(b"log") => Syscall::Function(bpf_syscall_string),
        ),
        { |res: ExecResult| { res.unwrap() == 2 } },
        14
    );
}

#[test]
fn test_bpf_to_bpf_scratch_registers() {
    test_interpreter_and_jit_elf!(
        "tests/elfs/scratch_registers.so",
        [1],
        (
            hash_symbol_name(b"log_64") => Syscall::Function(bpf_syscall_u64),
        ),
        { |res: ExecResult| { res.unwrap() == 112 } },
        41
    );
}

#[test]
fn test_bpf_to_bpf_pass_stack_reference() {
    test_interpreter_and_jit_elf!(
        "tests/elfs/pass_stack_reference.so",
        [],
        (),
        { |res: ExecResult| res.unwrap() == 42 },
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
        call 0
        mov64 r0, 0x0
        exit",
        [],
        (
            0 => Syscall::Function(bpf_syscall_string),
        ),
        { |res: ExecResult| { res.unwrap() == 0 } },
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
        callx 0x8
        exit
        mov64 r0, 0x2A
        exit",
        [],
        (),
        { |res: ExecResult| { res.unwrap() == 42 } },
        8
    );
}

#[test]
fn test_err_oob_callx_low() {
    test_interpreter_and_jit_asm!(
        "
        mov64 r0, 0x0
        callx 0x0
        exit",
        [],
        (),
        {
            |res: ExecResult| {
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
fn test_err_oob_callx_high() {
    test_interpreter_and_jit_asm!(
        "
        mov64 r0, -0x1
        lsh64 r0, 0x20
        callx 0x0
        exit",
        [],
        (),
        {
            |res: ExecResult| {
                matches!(res.unwrap_err(),
                    EbpfError::CallOutsideTextSegment(pc, target_pc)
                    if pc == 31 && target_pc == 0xffffffff00000000
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
            [i as u8],
            (
                hash_symbol_name(b"log") => Syscall::Function(bpf_syscall_string),
            ),
            { |res: ExecResult| { res.unwrap() == 0 } },
            if i == 0 { 4 } else { 3 + 10 * i as u64 }
        );
    }
}

#[test]
fn test_err_bpf_to_bpf_too_deep() {
    let config = Config::default();
    test_interpreter_and_jit_elf!(
        "tests/elfs/multiple_file.so",
        [config.max_call_depth as u8],
        (
            hash_symbol_name(b"log") => Syscall::Function(bpf_syscall_string),
        ),
        {
            |res: ExecResult| {
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
        callx 0x0
        exit",
        [],
        (
            hash_symbol_name(b"log") => Syscall::Function(bpf_syscall_string),
        ),
        {
            |res: ExecResult| {
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
            0 => Syscall::Function(syscalls::trash_registers),
        ),
        { |res: ExecResult| { res.unwrap() == 0 } }
    );
}*/

#[test]
fn test_err_syscall_string() {
    test_interpreter_and_jit_asm!(
        "
        mov64 r1, 0x0
        call 0
        mov64 r0, 0x0
        exit",
        [72, 101, 108, 108, 111],
        (
            0 => Syscall::Function(bpf_syscall_string),
        ),
        {
            |res: ExecResult| {
                matches!(res.unwrap_err(),
                    EbpfError::AccessViolation(pc, access_type, _, _, _)
                    if access_type == AccessType::Load && pc == 0
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
        call 0
        mov64 r0, 0x0
        exit",
        [72, 101, 108, 108, 111],
        (
            0 => Syscall::Function(bpf_syscall_string),
        ),
        { |res: ExecResult| { res.unwrap() == 0 } },
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
        call 0
        mov64 r0, 0x0
        exit",
        [],
        (
            0 => Syscall::Function(bpf_syscall_u64),
        ),
        { |res: ExecResult| { res.unwrap() == 0 } },
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
        call 0
        exit",
        [],
        (
            0 => Syscall::Function(syscalls::gather_bytes),
        ),
        { |res: ExecResult| { res.unwrap() == 0x0102030405 } },
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
        call 0
        ldxdw r0, [r6]
        be64 r0
        exit",
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, //
        ],
        (
            0 => Syscall::Function(syscalls::memfrob),
        ),
        { |res: ExecResult| { res.unwrap() == 0x102292e2f2c0708 } },
        7
    );
}

#[test]
fn test_syscall_with_context() {
    let mut number = 42;
    let number_ptr = &mut number as *mut u64;
    test_interpreter_and_jit_asm!(
        "
        mov64 r1, 0xAA
        mov64 r2, 0xBB
        mov64 r3, 0xCC
        mov64 r4, 0xDD
        mov64 r5, 0xEE
        call 0
        mov64 r0, 0x0
        exit",
        [],
        (
            0 => Syscall::Object(Box::new(SyscallWithContext {
                context: &mut number,
            })),
        ),
        { |res: ExecResult| {
            unsafe {
                assert_eq!(*number_ptr, 84);
                *number_ptr = 42;
            }
            res.unwrap() == 0
        }},
        8
    );
}

// Elf

#[test]
fn test_load_elf() {
    test_interpreter_and_jit_elf!(
        "tests/elfs/noop.so",
        [],
        (
            hash_symbol_name(b"log") => Syscall::Function(bpf_syscall_string),
            hash_symbol_name(b"log_64") => Syscall::Function(bpf_syscall_u64),
        ),
        { |res: ExecResult| { res.unwrap() == 0 } },
        11
    );
}

#[test]
fn test_load_elf_empty_noro() {
    test_interpreter_and_jit_elf!(
        "tests/elfs/noro.so",
        [],
        (
            hash_symbol_name(b"log_64") => Syscall::Function(bpf_syscall_u64),
        ),
        { |res: ExecResult| { res.unwrap() == 0 } },
        8
    );
}

#[test]
fn test_load_elf_empty_rodata() {
    test_interpreter_and_jit_elf!(
        "tests/elfs/empty_rodata.so",
        [],
        (
            hash_symbol_name(b"log_64") => Syscall::Function(bpf_syscall_u64),
        ),
        { |res: ExecResult| { res.unwrap() == 0 } },
        8
    );
}

#[test]
fn test_custom_entrypoint() {
    let mut file = File::open("tests/elfs/unresolved_syscall.so").expect("file open failed");
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();
    elf[24] = 80; // Move entrypoint to later in the text section
    let executable = Executable::<UserError>::from_elf(&elf, None).unwrap();
    test_interpreter_and_jit!(
        executable,
        [],
        (
            hash_symbol_name(b"log") => Syscall::Function(bpf_syscall_string),
            hash_symbol_name(b"log_64") => Syscall::Function(bpf_syscall_u64),
        ),
        { |res: ExecResult| { res.unwrap() == 0 } },
        2
    );
}

// Instruction Meter Limit

#[test]
fn test_instruction_count_syscall() {
    test_interpreter_and_jit_asm!(
        "
        mov64 r2, 0x5
        call 0
        mov64 r0, 0x0
        exit",
        [72, 101, 108, 108, 111],
        (
            0 => Syscall::Function(bpf_syscall_string),
        ),
        { |res: ExecResult| { res.unwrap() == 0 } },
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
            0 => Syscall::Function(bpf_syscall_string),
        ),
        {
            |res: ExecResult| {
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
fn test_non_terminate_early() {
    test_interpreter_and_jit_asm!(
        "
        mov64 r6, 0x0
        mov64 r1, 0x0
        mov64 r2, 0x0
        mov64 r3, 0x0
        mov64 r4, 0x0
        mov64 r5, r6
        call 0x6
        add64 r6, 0x1
        ja -0x8
        exit",
        [],
        (),
        {
            |res: ExecResult| {
                matches!(res.unwrap_err(),
                    EbpfError::ELFError(ELFError::UnresolvedSymbol(a, b, c))
                    if a == "Unknown" && b == 35 && c == 48
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
        call 0x0
        add64 r6, 0x1
        ja -0x8
        exit",
        [],
        (
            0 => Syscall::Function(bpf_trace_printf),
        ),
        {
            |res: ExecResult| {
                matches!(res.unwrap_err(),
                    EbpfError::ExceededMaxInstructions(pc, initial_insn_count)
                    if pc == 35 && initial_insn_count == 6
                )
            }
        },
        6
    );
}

#[test]
fn test_err_non_terminating_capped() {
    test_interpreter_and_jit_asm!(
        "
        mov64 r6, 0x0
        mov64 r1, 0x0
        mov64 r2, 0x0
        mov64 r3, 0x0
        mov64 r4, 0x0
        mov64 r5, r6
        call 0x0
        add64 r6, 0x1
        ja -0x8
        exit",
        [],
        (
            0 => Syscall::Function(bpf_trace_printf),
        ),
        {
            |res: ExecResult| {
                matches!(res.unwrap_err(),
                    EbpfError::ExceededMaxInstructions(pc, initial_insn_count)
                    if pc == 37 && initial_insn_count == 1000
                )
            }
        },
        1000
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
        call 0
        mov64 r0, 0x0
        exit",
        [72, 101, 108, 108, 111],
        (
            0 => Syscall::Function(bpf_syscall_string),
        ),
        { |res: ExecResult| { res.unwrap() == 0 } },
        6
    );
}

#[test]
fn test_err_symbol_unresolved() {
    test_interpreter_and_jit_asm!(
        "
        call 0
        mov64 r0, 0x0
        exit",
        [],
        (),
        {
            |res: ExecResult| matches!(res.unwrap_err(), EbpfError::ELFError(ELFError::UnresolvedSymbol(symbol, pc, offset)) if symbol == "Unknown" && pc == 29 && offset == 0)
        },
        1
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
        call 63
        exit",
        [],
        (),
        {
            |res: ExecResult| matches!(res.unwrap_err(), EbpfError::ELFError(ELFError::UnresolvedSymbol(symbol, pc, offset)) if symbol == "Unknown" && pc == 34 && offset == 40)
        },
        6
    );
}

#[test]
fn test_err_unresolved_elf() {
    test_interpreter_and_jit_elf!(
        "tests/elfs/unresolved_syscall.so",
        [],
        (
            hash_symbol_name(b"log") => Syscall::Function(bpf_syscall_string),
        ),
        {
            |res: ExecResult| matches!(res.unwrap_err(), EbpfError::ELFError(ELFError::UnresolvedSymbol(symbol, pc, offset)) if symbol == "log_64" && pc == 550 && offset == 4168)
        },
        9
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
        { |res: ExecResult| { res.unwrap() == 0x75db9c97 } },
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
        { |res: ExecResult| { res.unwrap() == 0x1 } },
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
        { |res: ExecResult| { res.unwrap() == 0x1 } },
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
        { |res: ExecResult| { res.unwrap() == 0x1 } },
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
        { |res: ExecResult| { res.unwrap() == 0x0 } },
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
        { |res: ExecResult| { res.unwrap() == 0x0 } },
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
        { |res: ExecResult| { res.unwrap() == 0x0 } },
        9
    );
}

#[test]
fn test_tcp_sack_match() {
    test_interpreter_and_jit_asm!(
        TCP_SACK_ASM,
        TCP_SACK_MATCH,
        (),
        { |res: ExecResult| res.unwrap() == 0x1 },
        79
    );
}

#[test]
fn test_tcp_sack_nomatch() {
    test_interpreter_and_jit_asm!(
        TCP_SACK_ASM,
        TCP_SACK_NOMATCH,
        (),
        { |res: ExecResult| res.unwrap() == 0x0 },
        55
    );
}

#[test]
fn test_large_program() {
    fn write_insn(prog: &mut [u8], insn: usize, asm: &str) {
        prog[insn * ebpf::INSN_SIZE..insn * ebpf::INSN_SIZE + ebpf::INSN_SIZE]
            .copy_from_slice(&assemble(asm).unwrap());
    }

    let mut prog = vec![0; ebpf::PROG_MAX_INSNS * ebpf::INSN_SIZE];
    let mut add_insn = vec![0; ebpf::INSN_SIZE];
    write_insn(&mut add_insn, 0, "mov64 r0, 0");
    for insn in (0..(ebpf::PROG_MAX_INSNS - 1) * ebpf::INSN_SIZE).step_by(ebpf::INSN_SIZE) {
        prog[insn..insn + ebpf::INSN_SIZE].copy_from_slice(&add_insn);
    }
    write_insn(&mut prog, ebpf::PROG_MAX_INSNS - 1, "exit");

    {
        // Test jumping to pc larger then i16
        write_insn(&mut prog, ebpf::PROG_MAX_INSNS - 2, "ja 0x0");

        let executable = Executable::<UserError>::from_text_bytes(&prog, None).unwrap();
        let mut vm = EbpfVm::<UserError, DefaultInstructionMeter>::new(
            executable.as_ref(),
            Config::default(),
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(
            0,
            vm.execute_program_interpreted(&mut DefaultInstructionMeter {})
                .unwrap()
        );
    }
    // reset program
    write_insn(&mut prog, ebpf::PROG_MAX_INSNS - 2, "mov64 r0, 0");

    {
        // test program that is too large
        prog.extend_from_slice(&assemble("exit").unwrap());

        assert!(Executable::<UserError>::from_text_bytes(&prog, Some(check)).is_err());
    }
    // reset program
    prog.truncate(ebpf::PROG_MAX_INSNS * ebpf::INSN_SIZE);

    // verify program still works
    let executable = Executable::<UserError>::from_text_bytes(&prog, None).unwrap();
    test_interpreter_and_jit!(
        executable,
        [],
        (),
        { |res: ExecResult| res.unwrap() == 0x0 },
        ebpf::PROG_MAX_INSNS as u64
    );
}
