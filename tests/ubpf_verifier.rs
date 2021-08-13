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
    error::UserDefinedError,
    user_error::UserError,
    verifier::{check, VerifierError},
    vm::{Config, EbpfVm, Executable, SyscallRegistry, TestInstructionMeter},
};
use std::collections::BTreeMap;
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
    let executable = assemble::<UserError, TestInstructionMeter>(
        "
        mov32 r0, 0xBEE
        exit",
        Some(|_prog: &[u8], _config: &Config| Ok(())),
        Config::default(),
        SyscallRegistry::default(),
    )
    .unwrap();
    let _vm = EbpfVm::<UserError, TestInstructionMeter>::new(executable.as_ref(), &mut [], &mut [])
        .unwrap();
}

#[test]
#[should_panic(expected = "NoProgram")]
fn test_verifier_fail() {
    fn verifier_fail(_prog: &[u8], _config: &Config) -> Result<(), VerifierError> {
        Err(VerifierError::NoProgram)
    }
    let _executable = assemble::<UserError, TestInstructionMeter>(
        "
        mov32 r0, 0xBEE
        exit",
        Some(verifier_fail),
        Config::default(),
        SyscallRegistry::default(),
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "DivisionByZero(30)")]
fn test_verifier_err_div_by_zero_imm() {
    let _executable = assemble::<UserError, TestInstructionMeter>(
        "
        mov32 r0, 1
        div32 r0, 0
        exit",
        Some(check),
        Config::default(),
        SyscallRegistry::default(),
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "UnsupportedLEBEArgument(29)")]
fn test_verifier_err_endian_size() {
    let prog = &[
        0xdc, 0x01, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, //
        0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    ];
    let _ = <dyn Executable<UserError, TestInstructionMeter>>::from_text_bytes(
        prog,
        Some(check),
        Config::default(),
        SyscallRegistry::default(),
        BTreeMap::default(),
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "IncompleteLDDW(29)")]
fn test_verifier_err_incomplete_lddw() {
    // Note: ubpf has test-err-incomplete-lddw2, which is the same
    let prog = &[
        0x18, 0x00, 0x00, 0x00, 0x88, 0x77, 0x66, 0x55, //
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    ];
    let _ = <dyn Executable<UserError, TestInstructionMeter>>::from_text_bytes(
        prog,
        Some(check),
        Config::default(),
        SyscallRegistry::default(),
        BTreeMap::default(),
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "InvalidDestinationRegister(29)")]
fn test_verifier_err_invalid_reg_dst() {
    let _executable = assemble::<UserError, TestInstructionMeter>(
        "
        mov r11, 1
        exit",
        Some(check),
        Config::default(),
        SyscallRegistry::default(),
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "InvalidSourceRegister(29)")]
fn test_verifier_err_invalid_reg_src() {
    let _executable = assemble::<UserError, TestInstructionMeter>(
        "
        mov r0, r11
        exit",
        Some(check),
        Config::default(),
        SyscallRegistry::default(),
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "JumpToMiddleOfLDDW(2, 29)")]
fn test_verifier_err_jmp_lddw() {
    let _executable = assemble::<UserError, TestInstructionMeter>(
        "
        ja +1
        lddw r0, 0x1122334455667788
        exit",
        Some(check),
        Config::default(),
        SyscallRegistry::default(),
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "JumpOutOfCode(3, 29)")]
fn test_verifier_err_jmp_out() {
    let _executable = assemble::<UserError, TestInstructionMeter>(
        "
        ja +2
        exit",
        Some(check),
        Config::default(),
        SyscallRegistry::default(),
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "UnknownOpCode(6, 29)")]
fn test_verifier_err_unknown_opcode() {
    let prog = &[
        0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    ];
    let _ = <dyn Executable<UserError, TestInstructionMeter>>::from_text_bytes(
        prog,
        Some(check),
        Config::default(),
        SyscallRegistry::default(),
        BTreeMap::default(),
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "CannotWriteR10(29)")]
fn test_verifier_err_write_r10() {
    let _executable = assemble::<UserError, TestInstructionMeter>(
        "
        mov r10, 1
        exit",
        Some(check),
        Config::default(),
        SyscallRegistry::default(),
    )
    .unwrap();
}

#[test]
fn test_verifier_err_all_shift_overflows() {
    let testcases = [
        // lsh32_imm
        ("lsh32 r0, 16", Ok(())),
        ("lsh32 r0, 32", Err("ShiftWithOverflow(32, 32, 29)")),
        ("lsh32 r0, 64", Err("ShiftWithOverflow(64, 32, 29)")),
        // rsh32_imm
        ("rsh32 r0, 16", Ok(())),
        ("rsh32 r0, 32", Err("ShiftWithOverflow(32, 32, 29)")),
        ("rsh32 r0, 64", Err("ShiftWithOverflow(64, 32, 29)")),
        // arsh32_imm
        ("arsh32 r0, 16", Ok(())),
        ("arsh32 r0, 32", Err("ShiftWithOverflow(32, 32, 29)")),
        ("arsh32 r0, 64", Err("ShiftWithOverflow(64, 32, 29)")),
        // lsh64_imm
        ("lsh64 r0, 32", Ok(())),
        ("lsh64 r0, 64", Err("ShiftWithOverflow(64, 64, 29)")),
        // rsh64_imm
        ("rsh64 r0, 32", Ok(())),
        ("rsh64 r0, 64", Err("ShiftWithOverflow(64, 64, 29)")),
        // arsh64_imm
        ("arsh64 r0, 32", Ok(())),
        ("arsh64 r0, 64", Err("ShiftWithOverflow(64, 64, 29)")),
    ];

    for (overflowing_instruction, expected) in testcases {
        let assembly = format!("\n{}\nexit", overflowing_instruction);
        let result = assemble::<UserError, TestInstructionMeter>(
            &assembly,
            Some(check),
            Config {
                verify_shift32_imm: true,
                ..Config::default()
            },
            SyscallRegistry::default(),
        );
        match expected {
            Ok(()) => assert!(result.is_ok()),
            Err(overflow_msg) => match result {
                Err(err) => assert_eq!(
                    err,
                    format!("Executable constructor VerifierError({})", overflow_msg),
                ),
                _ => panic!("Expected error"),
            },
        }
    }
}
