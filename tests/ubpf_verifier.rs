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
    fn verifier_success(_prog: &[u8]) -> Result<(), VerifierTestError> {
        Ok(())
    }
    let prog = assemble(
        "
        mov32 r0, 0xBEE
        exit",
    )
    .unwrap();
    let executable = Executable::<VerifierTestError, DefaultInstructionMeter>::from_text_bytes(
        &prog,
        Some(verifier_success),
        Config::default(),
    )
    .unwrap();
    let _ = EbpfVm::<VerifierTestError, DefaultInstructionMeter>::new(
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
    let prog = assemble(
        "
        mov32 r0, 0xBEE
        exit",
    )
    .unwrap();
    let _ = Executable::<VerifierTestError, DefaultInstructionMeter>::from_text_bytes(
        &prog,
        Some(verifier_fail),
        Config::default(),
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "DivisionByZero(1)")]
fn test_verifier_err_div_by_zero_imm() {
    let prog = assemble(
        "
        mov32 r0, 1
        div32 r0, 0
        exit",
    )
    .unwrap();
    let _ = Executable::<UserError, DefaultInstructionMeter>::from_text_bytes(
        &prog,
        Some(check),
        Config::default(),
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "UnsupportedLEBEArgument(0)")]
fn test_verifier_err_endian_size() {
    let prog = &[
        0xdc, 0x01, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, //
        0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    ];
    let _ = Executable::<UserError, DefaultInstructionMeter>::from_text_bytes(
        prog,
        Some(check),
        Config::default(),
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "IncompleteLDDW(0)")]
fn test_verifier_err_incomplete_lddw() {
    // Note: ubpf has test-err-incomplete-lddw2, which is the same
    let prog = &[
        0x18, 0x00, 0x00, 0x00, 0x88, 0x77, 0x66, 0x55, //
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    ];
    let _ = Executable::<UserError, DefaultInstructionMeter>::from_text_bytes(
        prog,
        Some(check),
        Config::default(),
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "InfiniteLoop(0)")]
fn test_verifier_err_infinite_loop() {
    let prog = assemble(
        "
        ja -1
        exit",
    )
    .unwrap();
    let _ = Executable::<UserError, DefaultInstructionMeter>::from_text_bytes(
        &prog,
        Some(check),
        Config::default(),
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "InvalidDestinationRegister(0)")]
fn test_verifier_err_invalid_reg_dst() {
    let prog = assemble(
        "
        mov r11, 1
        exit",
    )
    .unwrap();
    let _ = Executable::<UserError, DefaultInstructionMeter>::from_text_bytes(
        &prog,
        Some(check),
        Config::default(),
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "InvalidSourceRegister(0)")]
fn test_verifier_err_invalid_reg_src() {
    let prog = assemble(
        "
        mov r0, r11
        exit",
    )
    .unwrap();
    let _ = Executable::<UserError, DefaultInstructionMeter>::from_text_bytes(
        &prog,
        Some(check),
        Config::default(),
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "JumpToMiddleOfLDDW(2, 0)")]
fn test_verifier_err_jmp_lddw() {
    let prog = assemble(
        "
        ja +1
        lddw r0, 0x1122334455667788
        exit",
    )
    .unwrap();
    let _ = Executable::<UserError, DefaultInstructionMeter>::from_text_bytes(
        &prog,
        Some(check),
        Config::default(),
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "JumpOutOfCode(3, 0)")]
fn test_verifier_err_jmp_out() {
    let prog = assemble(
        "
        ja +2
        exit",
    )
    .unwrap();
    let _ = Executable::<UserError, DefaultInstructionMeter>::from_text_bytes(
        &prog,
        Some(check),
        Config::default(),
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "InvalidLastInstruction")]
fn test_verifier_err_no_exit() {
    let prog = assemble(
        "
        mov32 r0, 0",
    )
    .unwrap();
    let _ = Executable::<UserError, DefaultInstructionMeter>::from_text_bytes(
        &prog,
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

    let _ = Executable::<UserError, DefaultInstructionMeter>::from_text_bytes(
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
    let _ = Executable::<UserError, DefaultInstructionMeter>::from_text_bytes(
        prog,
        Some(check),
        Config::default(),
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "CannotWriteR10(0)")]
fn test_verifier_err_write_r10() {
    let prog = assemble(
        "
        mov r10, 1
        exit",
    )
    .unwrap();
    let _ = Executable::<UserError, DefaultInstructionMeter>::from_text_bytes(
        &prog,
        Some(check),
        Config::default(),
    )
    .unwrap();
}
