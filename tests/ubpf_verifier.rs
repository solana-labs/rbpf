// Converted from the tests for uBPF <https://github.com/iovisor/ubpf>
// Copyright 2015 Big Switch Networks, Inc
// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

// The tests contained in this file are extracted from the unit tests of uBPF software. Each test
// in this file has a name in the form `test_verifier_<name>`, and corresponds to the
// (human-readable) code in `ubpf/tree/master/tests/<name>`, available at
// <https://github.com/iovisor/ubpf/tree/master/tests> (hyphen had to be replaced with underscores
// as Rust will not accept them in function names). It is strongly advised to refer to the uBPF
// version to understand what these program do.
//
// Each program was assembled from the uBPF version with the assembler provided by uBPF itself, and
// available at <https://github.com/iovisor/ubpf/tree/master/ubpf>.
// The very few modifications that have been realized should be indicated.

// These are unit tests for the eBPF “verifier”.

extern crate solana_rbpf;
extern crate thiserror;

use solana_rbpf::{
    assembler::assemble,
    ebpf,
    error::UserDefinedError,
    user_error::UserError,
    verifier::check,
    vm::{Config, DefaultInstructionMeter, EbpfVm, Executable},
};
use thiserror::Error;

/// Error definitions
#[derive(Debug, Error)]
pub enum VerifierTestError {
    #[error("{0}")]
    Rejected(String),
}
impl UserDefinedError for VerifierTestError {}

#[test]
fn test_verifier_success() {
    let executable = assemble::<VerifierTestError, DefaultInstructionMeter>(
        "
        mov32 r0, 0xBEE
        exit",
        Some(|_prog: &[u8]| Ok(())),
        Config::default(),
    )
    .unwrap();
    let _vm = EbpfVm::<VerifierTestError, DefaultInstructionMeter>::new(
        executable.as_ref(),
        &mut [],
        &[],
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "Gaggablaghblagh!")]
fn test_verifier_fail() {
    fn verifier_fail(_prog: &[u8]) -> Result<(), VerifierTestError> {
        Err(VerifierTestError::Rejected("Gaggablaghblagh!".to_string()))
    }
    let _executable = assemble::<VerifierTestError, DefaultInstructionMeter>(
        "
        mov32 r0, 0xBEE
        exit",
        Some(verifier_fail),
        Config::default(),
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "DivisionByZero(1)")]
fn test_verifier_err_div_by_zero_imm() {
    let _executable = assemble::<UserError, DefaultInstructionMeter>(
        "
        mov32 r0, 1
        div32 r0, 0
        exit",
        Some(check),
        Config::default(),
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "UnsupportedLeBeArgument(0)")]
fn test_verifier_err_endian_size() {
    let prog = &[
        0xdc, 0x01, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, //
        0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    ];
    let _ = <dyn Executable<UserError, DefaultInstructionMeter>>::from_text_bytes(
        prog,
        Some(check),
        Config::default(),
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "IncompleteLddw(0)")]
fn test_verifier_err_incomplete_lddw() {
    // Note: ubpf has test-err-incomplete-lddw2, which is the same
    let prog = &[
        0x18, 0x00, 0x00, 0x00, 0x88, 0x77, 0x66, 0x55, //
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    ];
    let _ = <dyn Executable<UserError, DefaultInstructionMeter>>::from_text_bytes(
        prog,
        Some(check),
        Config::default(),
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "InfiniteLoop(0)")]
fn test_verifier_err_infinite_loop() {
    let _executable = assemble::<UserError, DefaultInstructionMeter>(
        "
        ja -1
        exit",
        Some(check),
        Config::default(),
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "InvalidDestinationRegister(0)")]
fn test_verifier_err_invalid_reg_dst() {
    let _executable = assemble::<UserError, DefaultInstructionMeter>(
        "
        mov r11, 1
        exit",
        Some(check),
        Config::default(),
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "InvalidSourceRegister(0)")]
fn test_verifier_err_invalid_reg_src() {
    let _executable = assemble::<UserError, DefaultInstructionMeter>(
        "
        mov r0, r11
        exit",
        Some(check),
        Config::default(),
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "JumpToMiddleOfLddw(2, 0)")]
fn test_verifier_err_jmp_lddw() {
    let _executable = assemble::<UserError, DefaultInstructionMeter>(
        "
        ja +1
        lddw r0, 0x1122334455667788
        exit",
        Some(check),
        Config::default(),
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "JumpOutOfCode(3, 0)")]
fn test_verifier_err_jmp_out() {
    let _executable = assemble::<UserError, DefaultInstructionMeter>(
        "
        ja +2
        exit",
        Some(check),
        Config::default(),
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "InvalidLastInstruction")]
fn test_verifier_err_no_exit() {
    let _executable = assemble::<UserError, DefaultInstructionMeter>(
        "
        mov32 r0, 0",
        Some(check),
        Config::default(),
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "ProgramTooLarge(65537)")]
fn test_verifier_err_too_many_instructions() {
    let mut prog = (0..(65536 * ebpf::INSN_SIZE))
        .map(|x| match x % 8 {
            0 => 0xb7,
            1 => 0x01,
            _ => 0,
        })
        .collect::<Vec<u8>>();
    prog.append(&mut vec![0x95, 0, 0, 0, 0, 0, 0, 0]);

    let _ = <dyn Executable<UserError, DefaultInstructionMeter>>::from_text_bytes(
        &prog,
        Some(check),
        Config::default(),
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "UnknownOpCode(6, 0)")]
fn test_verifier_err_unknown_opcode() {
    let prog = &[
        0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    ];
    let _ = <dyn Executable<UserError, DefaultInstructionMeter>>::from_text_bytes(
        prog,
        Some(check),
        Config::default(),
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "CannotWriteR10(0)")]
fn test_verifier_err_write_r10() {
    let _executable = assemble::<UserError, DefaultInstructionMeter>(
        "
        mov r10, 1
        exit",
        Some(check),
        Config::default(),
    )
    .unwrap();
}
