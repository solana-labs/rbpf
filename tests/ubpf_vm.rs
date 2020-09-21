// Converted from the tests for uBPF <https://github.com/iovisor/ubpf>
// Copyright 2015 Big Switch Networks, Inc
// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

// The tests contained in this file are extracted from the unit tests of uBPF software. Each test
// in this file has a name in the form `test_vm_<name>`, and corresponds to the (human-readable)
// code in `ubpf/tree/master/tests/<name>`, available at
// <https://github.com/iovisor/ubpf/tree/master/tests> (hyphen had to be replaced with underscores
// as Rust will not accept them in function names). It is strongly advised to refer to the uBPF
// version to understand what these program do.
//
// Each program was assembled from the uBPF version with the assembler provided by uBPF itself, and
// available at <https://github.com/iovisor/ubpf/tree/master/ubpf>.
// The very few modifications that have been realized should be indicated.

// These are unit tests for the eBPF interpreter.

extern crate solana_rbpf;

use solana_rbpf::{
    assembler::assemble,
    syscalls,
    user_error::UserError,
    vm::{EbpfVm, Syscall},
};

// TODO: syscalls::trash_registers needs asm!().
// Try this again once asm!() is available in stable.
// #[ignore]
// #[test]
// fn test_vm_call_save() {
//     let prog = &[
//         0xb7, 0x06, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, //
//         0xb7, 0x07, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, //
//         0xb7, 0x08, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, //
//         0xb7, 0x09, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, //
//         0x85, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, //
//         0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
//         0x4f, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
//         0x4f, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
//         0x4f, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
//         0x4f, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
//         0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
//     ];
//     let mut vm = EbpfVm::<UserError>::new(Some(prog), &[], &[]).unwrap();
//     vm.register_syscall(2, syscalls::trash_registers, None);
//     assert_eq!(vm.execute_program().unwrap(), 0x4321);
// }

// uBPF limits the number of user functions at 64. We don't.
//#[test]
//fn test_vm_err_call_bad_imm() {
//}

// With the introduction of call frames there may be stack regions
// above or below the current stack, to test out of bounds we have to
// try significantly further away
#[test]
#[should_panic(expected = "AccessViolation(29, Store")]
fn test_vm_err_stack_out_of_bound() {
    let prog = assemble(
        "
        stb [r10-0x4000], 0
        exit",
    )
    .unwrap();
    let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref(), &[], &[]).unwrap();
    vm.execute_program().unwrap();
}

#[test]
fn test_vm_stack1() {
    let prog = assemble(
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
    )
    .unwrap();
    let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref(), &[], &[]).unwrap();
    assert_eq!(vm.execute_program().unwrap(), 0xcd);
}

#[test]
fn test_vm_stack2() {
    let prog = assemble(
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
    )
    .unwrap();
    let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref(), &[], &[]).unwrap();
    vm.register_syscall(0, Syscall::Function(syscalls::gather_bytes))
        .unwrap();
    vm.register_syscall(1, Syscall::Function(syscalls::memfrob))
        .unwrap();
    assert_eq!(vm.execute_program().unwrap(), 0x01020304);
}

#[test]
fn test_vm_string_stack() {
    let prog = assemble(
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
        call 0x4
        mov r1, r0
        mov r0, 0x1
        lsh r1, 0x20
        rsh r1, 0x20
        jne r1, 0x0, +11
        mov r1, r10
        add r1, -8
        mov r2, r10
        add r2, -16
        call 0x4
        mov r1, r0
        lsh r1, 0x20
        rsh r1, 0x20
        mov r0, 0x1
        jeq r1, r6, +1
        mov r0, 0x0
        exit",
    )
    .unwrap();
    let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref(), &[], &[]).unwrap();
    vm.register_syscall(4, Syscall::Function(syscalls::strcmp))
        .unwrap();
    assert_eq!(vm.execute_program().unwrap(), 0x0);
}
