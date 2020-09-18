// Copyright 2020 Solana <alexander@solana.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

extern crate byteorder;
extern crate libc;
extern crate solana_rbpf;
extern crate thiserror;

use byteorder::{ByteOrder, LittleEndian};
use libc::c_char;
use solana_rbpf::{
    assembler::assemble,
    ebpf::{self},
    error::EbpfError,
    memory_region::{AccessType, MemoryMapping},
    syscalls,
    user_error::UserError,
    vm::{EbpfVm, SyscallFunction, SyscallObject},
};
use std::{slice::from_raw_parts, str::from_utf8};

type ExecResult = Result<u64, EbpfError<UserError>>;

macro_rules! test_vm_and_jit {
    ( $source:tt, $mem:tt, $syscalls:tt, $check:tt ) => {
        let mut program = assemble($source).unwrap();
        let syscalls: &[(u32, SyscallFunction<UserError>, Option<usize>)] = &$syscalls;
        for syscall in syscalls {
            if let Some(offset) = syscall.2 {
                LittleEndian::write_u32(&mut program[offset..offset + 4], syscall.0);
            }
        }
        let executable =
            EbpfVm::<UserError>::create_executable_from_text_bytes(&program, None).unwrap();
        let check_closure = $check;
        {
            let mem = $mem;
            let mut vm = EbpfVm::<UserError>::new(executable.as_ref(), &mem, &[]).unwrap();
            for syscall in syscalls {
                vm.register_syscall(syscall.0, syscall.1).unwrap();
            }
            assert!(check_closure(vm.execute_program()));
        }
        #[cfg(not(windows))]
        {
            let mem = $mem;
            let mut vm = EbpfVm::<UserError>::new(executable.as_ref(), &mem, &[]).unwrap();
            for syscall in syscalls {
                vm.register_syscall(syscall.0, syscall.1).unwrap();
            }
            vm.jit_compile().unwrap();
            assert!(check_closure(unsafe { vm.execute_program_jit() }));
        }
    };
}

// BPF_ALU : Arithmetic and Logic

#[test]
fn test_vm_jit_mov() {
    test_vm_and_jit!(
        "
        mov32 r1, 1
        mov32 r0, r1
        exit",
        [],
        [],
        { |res: ExecResult| { res.unwrap() == 0x1 } }
    );
}

#[test]
fn test_vm_jit_mov32_imm_large() {
    test_vm_and_jit!(
        "
        mov32 r0, -1
        exit",
        [],
        [],
        { |res: ExecResult| { res.unwrap() == 0xffffffff } }
    );
}

#[test]
fn test_vm_jit_mov_large() {
    test_vm_and_jit!(
        "
        mov32 r1, -1
        mov32 r0, r1
        exit",
        [],
        [],
        { |res: ExecResult| { res.unwrap() == 0xffffffff } }
    );
}

#[test]
fn test_vm_jit_bounce() {
    test_vm_and_jit!(
        "
        mov r0, 1
        mov r6, r0
        mov r7, r6
        mov r8, r7
        mov r9, r8
        mov r0, r9
        exit",
        [],
        [],
        { |res: ExecResult| { res.unwrap() == 0x1 } }
    );
}

#[test]
fn test_vm_jit_add() {
    test_vm_and_jit!(
        "
        mov32 r0, 0
        mov32 r1, 2
        add32 r0, 1
        add32 r0, r1
        exit",
        [],
        [],
        { |res: ExecResult| { res.unwrap() == 0x3 } }
    );
}

#[test]
fn test_vm_jit_alu_bit() {
    test_vm_and_jit!(
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
        [],
        { |res: ExecResult| { res.unwrap() == 0x11 } }
    );
}

#[test]
fn test_vm_jit_mul32_imm() {
    test_vm_and_jit!(
        "
        mov r0, 3
        mul32 r0, 4
        exit",
        [],
        [],
        { |res: ExecResult| { res.unwrap() == 0xc } }
    );
}

#[test]
fn test_vm_jit_mul32_reg() {
    test_vm_and_jit!(
        "
        mov r0, 3
        mov r1, 4
        mul32 r0, r1
        exit",
        [],
        [],
        { |res: ExecResult| { res.unwrap() == 0xc } }
    );
}

#[test]
fn test_vm_jit_mul32_reg_overflow() {
    test_vm_and_jit!(
        "
        mov r0, 0x40000001
        mov r1, 4
        mul32 r0, r1
        exit",
        [],
        [],
        { |res: ExecResult| { res.unwrap() == 0x4 } }
    );
}

#[test]
fn test_vm_jit_mul64_imm() {
    test_vm_and_jit!(
        "
        mov r0, 0x40000001
        mul r0, 4
        exit",
        [],
        [],
        { |res: ExecResult| { res.unwrap() == 0x100000004 } }
    );
}

#[test]
fn test_vm_jit_mul64_reg() {
    test_vm_and_jit!(
        "
        mov r0, 0x40000001
        mov r1, 4
        mul r0, r1
        exit",
        [],
        [],
        { |res: ExecResult| { res.unwrap() == 0x100000004 } }
    );
}

#[test]
fn test_vm_jit_div32_high_divisor() {
    test_vm_and_jit!(
        "
        mov r0, 12
        lddw r1, 0x100000004
        div32 r0, r1
        exit",
        [],
        [],
        { |res: ExecResult| { res.unwrap() == 0x3 } }
    );
}

#[test]
fn test_vm_jit_div32_imm() {
    test_vm_and_jit!(
        "
        lddw r0, 0x10000000c
        div32 r0, 4
        exit",
        [],
        [],
        { |res: ExecResult| { res.unwrap() == 0x3 } }
    );
}

#[test]
fn test_vm_jit_div32_reg() {
    test_vm_and_jit!(
        "
        lddw r0, 0x10000000c
        mov r1, 4
        div32 r0, r1
        exit",
        [],
        [],
        { |res: ExecResult| { res.unwrap() == 0x3 } }
    );
}

#[test]
fn test_vm_jit_div64_imm() {
    test_vm_and_jit!(
        "
        mov r0, 0xc
        lsh r0, 32
        div r0, 4
        exit",
        [],
        [],
        { |res: ExecResult| { res.unwrap() == 0x300000000 } }
    );
}

#[test]
fn test_vm_jit_div64_reg() {
    test_vm_and_jit!(
        "
        mov r0, 0xc
        lsh r0, 32
        mov r1, 4
        div r0, r1
        exit",
        [],
        [],
        { |res: ExecResult| { res.unwrap() == 0x300000000 } }
    );
}

#[test]
fn test_vm_jit_err_div64_by_zero_reg() {
    test_vm_and_jit!(
        "
        mov32 r0, 1
        mov32 r1, 0
        div r0, r1
        exit",
        [],
        [],
        { |res: ExecResult| matches!(res.unwrap_err(), EbpfError::DivideByZero(pc) if pc == 2) }
    );
}

#[test]
fn test_vm_jit_err_div_by_zero_reg() {
    test_vm_and_jit!(
        "
        mov32 r0, 1
        mov32 r1, 0
        div32 r0, r1
        exit",
        [],
        [],
        { |res: ExecResult| matches!(res.unwrap_err(), EbpfError::DivideByZero(pc) if pc == 2) }
    );
}

#[test]
fn test_vm_jit_mod() {
    test_vm_and_jit!(
        "
        mov32 r0, 5748
        mod32 r0, 92
        mov32 r1, 13
        mod32 r0, r1
        exit",
        [],
        [],
        { |res: ExecResult| { res.unwrap() == 0x5 } }
    );
}

#[test]
fn test_vm_jit_mod32() {
    test_vm_and_jit!(
        "
        lddw r0, 0x100000003
        mod32 r0, 3
        exit",
        [],
        [],
        { |res: ExecResult| { res.unwrap() == 0x0 } }
    );
}

#[test]
fn test_vm_jit_mod64() {
    test_vm_and_jit!(
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
        [],
        { |res: ExecResult| { res.unwrap() == 0x30ba5a04 } }
    );
}

#[test]
fn test_vm_jit_err_mod64_by_zero_reg() {
    test_vm_and_jit!(
        "
        mov32 r0, 1
        mov32 r1, 0
        mod r0, r1
        exit",
        [],
        [],
        { |res: ExecResult| matches!(res.unwrap_err(), EbpfError::DivideByZero(pc) if pc == 2) }
    );
}

#[test]
fn test_vm_jit_err_mod_by_zero_reg() {
    test_vm_and_jit!(
        "
        mov32 r0, 1
        mov32 r1, 0
        mod32 r0, r1
        exit",
        [],
        [],
        { |res: ExecResult| matches!(res.unwrap_err(), EbpfError::DivideByZero(pc) if pc == 2) }
    );
}

// BPF_LD : Loads

#[test]
fn test_vm_jit_ldabsb() {
    test_vm_and_jit!(
        "
        ldabsb 0x3
        exit",
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, //
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, //
        ],
        [],
        { |res: ExecResult| { res.unwrap() == 0x33 } }
    );
}

#[test]
fn test_vm_jit_ldabsh() {
    test_vm_and_jit!(
        "
        ldabsh 0x3
        exit",
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, //
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, //
        ],
        [],
        { |res: ExecResult| { res.unwrap() == 0x4433 } }
    );
}

#[test]
fn test_vm_jit_ldabsw() {
    test_vm_and_jit!(
        "
        ldabsw 0x3
        exit",
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, //
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, //
        ],
        [],
        { |res: ExecResult| { res.unwrap() == 0x66554433 } }
    );
}

#[test]
fn test_vm_jit_ldabsdw() {
    test_vm_and_jit!(
        "
        ldabsdw 0x3
        exit",
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, //
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, //
        ],
        [],
        { |res: ExecResult| { res.unwrap() == 0xaa99887766554433 } }
    );
}

#[test]
fn test_vm_jit_err_ldabsb_oob() {
    test_vm_and_jit!(
        "
        ldabsb 0x33
        exit",
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, //
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, //
        ],
        [],
        {
            |res: ExecResult| {
                matches!(res.unwrap_err(),
                    EbpfError::AccessViolation(pc, access_type, _, _, _)
                    if access_type == AccessType::Load && pc == 29
                )
            }
        }
    );
}

#[test]
fn test_vm_jit_err_ldabsb_nomem() {
    test_vm_and_jit!(
        "
        ldabsb 0x33
        exit",
        [],
        [],
        {
            |res: ExecResult| {
                matches!(res.unwrap_err(),
                    EbpfError::AccessViolation(pc, access_type, _, _, _)
                    if access_type == AccessType::Load && pc == 29
                )
            }
        }
    );
}

#[test]
fn test_vm_jit_ldindb() {
    test_vm_and_jit!(
        "
        mov64 r1, 0x5
        ldindb r1, 0x3
        exit",
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, //
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, //
        ],
        [],
        { |res: ExecResult| { res.unwrap() == 0x88 } }
    );
}

#[test]
fn test_vm_jit_ldindh() {
    test_vm_and_jit!(
        "
        mov64 r1, 0x5
        ldindh r1, 0x3
        exit",
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, //
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, //
        ],
        [],
        { |res: ExecResult| { res.unwrap() == 0x9988 } }
    );
}

#[test]
fn test_vm_jit_ldindw() {
    test_vm_and_jit!(
        "
        mov64 r1, 0x4
        ldindw r1, 0x1
        exit",
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, //
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, //
        ],
        [],
        { |res: ExecResult| { res.unwrap() == 0x88776655 } }
    );
}

#[test]
fn test_vm_jit_ldinddw() {
    test_vm_and_jit!(
        "
        mov64 r1, 0x2
        ldinddw r1, 0x3
        exit",
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, //
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, //
        ],
        [],
        { |res: ExecResult| { res.unwrap() == 0xccbbaa9988776655 } }
    );
}

#[test]
fn test_vm_jit_err_ldindb_oob() {
    test_vm_and_jit!(
        "
        mov64 r1, 0x5
        ldindb r1, 0x33
        exit",
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, //
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, //
        ],
        [],
        {
            |res: ExecResult| {
                matches!(res.unwrap_err(),
                    EbpfError::AccessViolation(pc, access_type, _, _, _)
                    if access_type == AccessType::Load && pc == 30
                )
            }
        }
    );
}

#[test]
fn test_vm_jit_err_ldindb_nomem() {
    test_vm_and_jit!(
        "
        mov64 r1, 0x5
        ldindb r1, 0x33
        exit",
        [],
        [],
        {
            |res: ExecResult| {
                matches!(res.unwrap_err(),
                    EbpfError::AccessViolation(pc, access_type, _, _, _)
                    if access_type == AccessType::Load && pc == 30
                )
            }
        }
    );
}

#[test]
fn test_vm_jit_ldxb() {
    test_vm_and_jit!(
        "
        ldxb r0, [r1+2]
        exit",
        [0xaa, 0xbb, 0x11, 0xcc, 0xdd],
        [],
        { |res: ExecResult| { res.unwrap() == 0x11 } }
    );
}

#[test]
fn test_vm_jit_ldxh() {
    test_vm_and_jit!(
        "
        ldxh r0, [r1+2]
        exit",
        [0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd],
        [],
        { |res: ExecResult| { res.unwrap() == 0x2211 } }
    );
}

#[test]
fn test_vm_jit_ldxw() {
    test_vm_and_jit!(
        "
        ldxw r0, [r1+2]
        exit",
        [
            0xaa, 0xbb, 0x11, 0x22, 0x33, 0x44, 0xcc, 0xdd, //
        ],
        [],
        { |res: ExecResult| { res.unwrap() == 0x44332211 } }
    );
}

#[test]
fn test_vm_jit_ldxh_same_reg() {
    test_vm_and_jit!(
        "
        mov r0, r1
        sth [r0], 0x1234
        ldxh r0, [r0]
        exit",
        [0xff, 0xff],
        [],
        { |res: ExecResult| { res.unwrap() == 0x1234 } }
    );
}

#[test]
fn test_vm_jit_lldxdw() {
    test_vm_and_jit!(
        "
        ldxdw r0, [r1+2]
        exit",
        [
            0xaa, 0xbb, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, //
            0x77, 0x88, 0xcc, 0xdd, //
        ],
        [],
        { |res: ExecResult| { res.unwrap() == 0x8877665544332211 } }
    );
}

#[test]
fn test_vm_jit_err_ldxdw_oob() {
    test_vm_and_jit!(
        "
        ldxdw r0, [r1+6]
        exit",
        [
            0xaa, 0xbb, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, //
            0x77, 0x88, 0xcc, 0xdd, //
        ],
        [],
        {
            |res: ExecResult| {
                matches!(res.unwrap_err(),
                    EbpfError::AccessViolation(pc, access_type, _, _, _)
                    if access_type == AccessType::Load && pc == 29
                )
            }
        }
    );
}

#[test]
fn test_vm_jit_lddw() {
    test_vm_and_jit!(
        "
        lddw r0, 0x1122334455667788
        exit",
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, //
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, //
        ],
        [],
        { |res: ExecResult| { res.unwrap() == 0x1122334455667788 } }
    );
}

#[test]
fn test_vm_jit_lddw2() {
    test_vm_and_jit!(
        "
        lddw r0, 0x0000000080000000
        exit",
        [],
        [],
        { |res: ExecResult| { res.unwrap() == 0x80000000 } }
    );
}

#[test]
fn test_vm_jit_stb() {
    test_vm_and_jit!(
        "
        stb [r1+2], 0x11
        ldxb r0, [r1+2]
        exit",
        [0xaa, 0xbb, 0xff, 0xcc, 0xdd],
        [],
        { |res: ExecResult| { res.unwrap() == 0x11 } }
    );
}

#[test]
fn test_vm_jit_sth() {
    test_vm_and_jit!(
        "
        sth [r1+2], 0x2211
        ldxh r0, [r1+2]
        exit",
        [
            0xaa, 0xbb, 0xff, 0xff, 0xcc, 0xdd, //
        ],
        [],
        { |res: ExecResult| { res.unwrap() == 0x2211 } }
    );
}

#[test]
fn test_vm_jit_stw() {
    test_vm_and_jit!(
        "
        stw [r1+2], 0x44332211
        ldxw r0, [r1+2]
        exit",
        [
            0xaa, 0xbb, 0xff, 0xff, 0xff, 0xff, 0xcc, 0xdd, //
        ],
        [],
        { |res: ExecResult| { res.unwrap() == 0x44332211 } }
    );
}

#[test]
fn test_vm_jit_stdw() {
    test_vm_and_jit!(
        "
        stdw [r1+2], 0x44332211
        ldxdw r0, [r1+2]
        exit",
        [
            0xaa, 0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //
            0xff, 0xff, 0xcc, 0xdd, //
        ],
        [],
        { |res: ExecResult| { res.unwrap() == 0x44332211 } }
    );
}

#[test]
fn test_vm_jit_stxb() {
    test_vm_and_jit!(
        "
        mov32 r2, 0x11
        stxb [r1+2], r2
        ldxb r0, [r1+2]
        exit",
        [
            0xaa, 0xbb, 0xff, 0xcc, 0xdd, //
        ],
        [],
        { |res: ExecResult| { res.unwrap() == 0x11 } }
    );
}

#[test]
fn test_vm_jit_stxh() {
    test_vm_and_jit!(
        "
        mov32 r2, 0x2211
        stxh [r1+2], r2
        ldxh r0, [r1+2]
        exit",
        [
            0xaa, 0xbb, 0xff, 0xff, 0xcc, 0xdd, //
        ],
        [],
        { |res: ExecResult| { res.unwrap() == 0x2211 } }
    );
}

#[test]
fn test_vm_jit_stxw() {
    test_vm_and_jit!(
        "
        mov32 r2, 0x44332211
        stxw [r1+2], r2
        ldxw r0, [r1+2]
        exit",
        [
            0xaa, 0xbb, 0xff, 0xff, 0xff, 0xff, 0xcc, 0xdd, //
        ],
        [],
        { |res: ExecResult| { res.unwrap() == 0x44332211 } }
    );
}

#[test]
fn test_vm_jit_stxdw() {
    test_vm_and_jit!(
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
        [],
        { |res: ExecResult| { res.unwrap() == 0x8877665544332211 } }
    );
}

// BPF_JMP : Branches

#[test]
fn test_vm_jit_exit() {
    test_vm_and_jit!(
        "
        mov r0, 0
        exit",
        [],
        [],
        { |res: ExecResult| { res.unwrap() == 0x0 } }
    );
}

#[test]
fn test_vm_jit_early_exit() {
    test_vm_and_jit!(
        "
        mov r0, 3
        exit
        mov r0, 4
        exit",
        [],
        [],
        { |res: ExecResult| { res.unwrap() == 0x3 } }
    );
}

#[test]
fn test_vm_jit_ja() {
    test_vm_and_jit!(
        "
        mov r0, 1
        ja +1
        mov r0, 2
        exit",
        [],
        [],
        { |res: ExecResult| { res.unwrap() == 0x1 } }
    );
}

#[test]
fn test_vm_jit_jeq_imm() {
    test_vm_and_jit!(
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
        [],
        { |res: ExecResult| { res.unwrap() == 0x1 } }
    );
}

#[test]
fn test_vm_jit_jeq_reg() {
    test_vm_and_jit!(
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
        [],
        { |res: ExecResult| { res.unwrap() == 0x1 } }
    );
}

#[test]
fn test_vm_jit_jge_imm() {
    test_vm_and_jit!(
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
        [],
        { |res: ExecResult| { res.unwrap() == 0x1 } }
    );
}

#[test]
fn test_vm_jit_jge_reg() {
    test_vm_and_jit!(
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
        [],
        { |res: ExecResult| { res.unwrap() == 0x1 } }
    );
}

#[test]
fn test_vm_jit_jle_imm() {
    test_vm_and_jit!(
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
        [],
        { |res: ExecResult| { res.unwrap() == 0x1 } }
    );
}

#[test]
fn test_vm_jit_jle_reg() {
    test_vm_and_jit!(
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
        [],
        { |res: ExecResult| { res.unwrap() == 0x1 } }
    );
}

#[test]
fn test_vm_jit_jgt_imm() {
    test_vm_and_jit!(
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
        [],
        { |res: ExecResult| { res.unwrap() == 0x1 } }
    );
}

#[test]
fn test_vm_jit_jgt_reg() {
    test_vm_and_jit!(
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
        [],
        { |res: ExecResult| { res.unwrap() == 0x1 } }
    );
}

#[test]
fn test_vm_jit_jlt_imm() {
    test_vm_and_jit!(
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
        [],
        { |res: ExecResult| { res.unwrap() == 0x1 } }
    );
}

#[test]
fn test_vm_jit_jlt_reg() {
    test_vm_and_jit!(
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
        [],
        { |res: ExecResult| { res.unwrap() == 0x1 } }
    );
}

#[test]
fn test_vm_jit_jne_imm() {
    test_vm_and_jit!(
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
        [],
        { |res: ExecResult| { res.unwrap() == 0x1 } }
    );
}

#[test]
fn test_vm_jit_jne_reg() {
    test_vm_and_jit!(
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
        [],
        { |res: ExecResult| { res.unwrap() == 0x1 } }
    );
}

#[test]
fn test_vm_jit_jset_imm() {
    test_vm_and_jit!(
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
        [],
        { |res: ExecResult| { res.unwrap() == 0x1 } }
    );
}

#[test]
fn test_vm_jit_jset_reg() {
    test_vm_and_jit!(
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
        [],
        { |res: ExecResult| { res.unwrap() == 0x1 } }
    );
}

#[test]
fn test_vm_jit_jsge_imm() {
    test_vm_and_jit!(
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
        [],
        { |res: ExecResult| { res.unwrap() == 0x1 } }
    );
}

#[test]
fn test_vm_jit_jsge_reg() {
    test_vm_and_jit!(
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
        [],
        { |res: ExecResult| { res.unwrap() == 0x1 } }
    );
}

#[test]
fn test_vm_jit_jsle_imm() {
    test_vm_and_jit!(
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
        [],
        { |res: ExecResult| { res.unwrap() == 0x1 } }
    );
}

#[test]
fn test_vm_jit_jsle_reg() {
    test_vm_and_jit!(
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
        [],
        { |res: ExecResult| { res.unwrap() == 0x1 } }
    );
}

#[test]
fn test_vm_jit_jsgt_imm() {
    test_vm_and_jit!(
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
        [],
        { |res: ExecResult| { res.unwrap() == 0x1 } }
    );
}

#[test]
fn test_vm_jit_jsgt_reg() {
    test_vm_and_jit!(
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
        [],
        { |res: ExecResult| { res.unwrap() == 0x1 } }
    );
}

#[test]
fn test_vm_jit_jslt_imm() {
    test_vm_and_jit!(
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
        [],
        { |res: ExecResult| { res.unwrap() == 0x1 } }
    );
}

#[test]
fn test_vm_jit_jslt_reg() {
    test_vm_and_jit!(
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
        [],
        { |res: ExecResult| { res.unwrap() == 0x1 } }
    );
}

// CALL_IMM : Syscalls

fn bpf_syscall_string(
    vm_addr: u64,
    len: u64,
    _arg3: u64,
    _arg4: u64,
    _arg5: u64,
    memory_mapping: &MemoryMapping,
) -> ExecResult {
    let host_addr = memory_mapping.map(AccessType::Load, vm_addr, len)?;
    let c_buf: *const c_char = host_addr as *const c_char;
    unsafe {
        for i in 0..len {
            let c = std::ptr::read(c_buf.offset(i as isize));
            if c == 0 {
                break;
            }
        }
        let message = from_utf8(from_raw_parts(host_addr as *const u8, len as usize)).unwrap();
        println!("log: {}", message);
    }
    Ok(0)
}

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

struct SyscallWithContext<'a> {
    context: &'a mut u64,
}
impl<'a> SyscallObject<UserError> for SyscallWithContext<'a> {
    fn call(
        &mut self,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
        memory_mapping: &MemoryMapping,
    ) -> ExecResult {
        println!(
            "SyscallWithContext: {:?}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:?}",
            self as *const _, arg1, arg2, arg3, arg4, arg5, memory_mapping as *const _
        );
        assert_eq!(*self.context, 42);
        *self.context = 84;
        Ok(0)
    }
}

#[test]
fn test_vm_jit_err_syscall_string() {
    test_vm_and_jit!(
        "
        mov64 r1, 0x0
        call -0x1
        mov64 r0, 0x0
        exit",
        [72, 101, 108, 108, 111],
        [(ebpf::hash_symbol_name(b"log"), bpf_syscall_string, Some(12))],
        {
            |res: ExecResult| {
                matches!(res.unwrap_err(),
                    EbpfError::AccessViolation(pc, access_type, _, _, _)
                    if access_type == AccessType::Load && pc == 0
                )
            }
        }
    );
}

#[test]
fn test_vm_jit_syscall_string() {
    test_vm_and_jit!(
        "
        mov64 r2, 0x5
        call -0x1
        mov64 r0, 0x0
        exit",
        [72, 101, 108, 108, 111],
        [(ebpf::hash_symbol_name(b"log"), bpf_syscall_string, Some(12))],
        { |res: ExecResult| { res.unwrap() == 0 } }
    );
}

#[test]
fn test_vm_jit_syscall() {
    test_vm_and_jit!(
        "
        mov64 r1, 0xAA
        mov64 r2, 0xBB
        mov64 r3, 0xCC
        mov64 r4, 0xDD
        mov64 r5, 0xEE
        call -0x1
        mov64 r0, 0x0
        exit",
        [],
        [(ebpf::hash_symbol_name(b"log"), bpf_syscall_u64, Some(44))],
        { |res: ExecResult| { res.unwrap() == 0 } }
    );
}

#[test]
fn test_vm_jit_call() {
    test_vm_and_jit!(
        "
        mov r1, 1
        mov r2, 2
        mov r3, 3
        mov r4, 4
        mov r5, 5
        call 0
        exit",
        [],
        [(0, syscalls::gather_bytes, None)],
        { |res: ExecResult| { res.unwrap() == 0x0102030405 } }
    );
}

#[test]
fn test_vm_jit_call_memfrob() {
    test_vm_and_jit!(
        "
        mov r6, r1
        add r1, 2
        mov r2, 4
        call 1
        ldxdw r0, [r6]
        be64 r0
        exit",
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, //
        ],
        [(1, syscalls::memfrob, None)],
        { |res: ExecResult| { res.unwrap() == 0x102292e2f2c0708 } }
    );
}
