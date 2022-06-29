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
    elf::Executable,
    error::UserDefinedError,
    user_error::UserError,
    verifier::{RequisiteVerifier, Verifier, VerifierError},
    vm::{Config, EbpfVm, SyscallRegistry, TestInstructionMeter, VerifiedExecutable},
};
use std::collections::BTreeMap;
use test_utils::TautologyVerifier;
use thiserror::Error;

/// Error definitions
#[derive(Debug, Error)]
pub enum VerifierTestError {
    #[error("{0}")]
    Rejected(String),
}
impl UserDefinedError for VerifierTestError {}

struct ContradictionVerifier {}
impl Verifier for ContradictionVerifier {
    fn verify(_prog: &[u8], _config: &Config) -> std::result::Result<(), VerifierError> {
        Err(VerifierError::NoProgram)
    }
}

#[test]
fn test_verifier_success() {
    let executable = assemble::<UserError, TestInstructionMeter>(
        "
        mov32 r0, 0xBEE
        exit",
        Config::default(),
        SyscallRegistry::default(),
    )
    .unwrap();
    let verified_executable =
        VerifiedExecutable::<TautologyVerifier, UserError, TestInstructionMeter>::from_executable(
            executable,
        )
        .unwrap();
    let _vm = EbpfVm::<TautologyVerifier, UserError, TestInstructionMeter>::new(
        &verified_executable,
        &mut [],
        Vec::new(),
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "NoProgram")]
fn test_verifier_fail() {
    let executable = assemble::<UserError, TestInstructionMeter>(
        "
        mov32 r0, 0xBEE
        exit",
        Config::default(),
        SyscallRegistry::default(),
    )
    .unwrap();
    let _verified_executable = VerifiedExecutable::<
        ContradictionVerifier,
        UserError,
        TestInstructionMeter,
    >::from_executable(executable)
    .unwrap();
}

#[test]
#[should_panic(expected = "DivisionByZero(30)")]
fn test_verifier_err_div_by_zero_imm() {
    let executable = assemble::<UserError, TestInstructionMeter>(
        "
        mov32 r0, 1
        div32 r0, 0
        exit",
        Config::default(),
        SyscallRegistry::default(),
    )
    .unwrap();
    let _verified_executable =
        VerifiedExecutable::<RequisiteVerifier, UserError, TestInstructionMeter>::from_executable(
            executable,
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
    let executable = Executable::<UserError, TestInstructionMeter>::from_text_bytes(
        prog,
        Config::default(),
        SyscallRegistry::default(),
        BTreeMap::default(),
    )
    .unwrap();
    let _verified_executable =
        VerifiedExecutable::<RequisiteVerifier, UserError, TestInstructionMeter>::from_executable(
            executable,
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
    let executable = Executable::<UserError, TestInstructionMeter>::from_text_bytes(
        prog,
        Config::default(),
        SyscallRegistry::default(),
        BTreeMap::default(),
    )
    .unwrap();
    let _verified_executable =
        VerifiedExecutable::<RequisiteVerifier, UserError, TestInstructionMeter>::from_executable(
            executable,
        )
        .unwrap();
}

#[test]
fn test_verifier_err_invalid_reg_dst() {
    // r11 is disabled when dynamic_stack_frames=false, and only sub and add are
    // allowed when dynamic_stack_frames=true
    for dynamic_stack_frames in [false, true] {
        let executable = assemble::<UserError, TestInstructionMeter>(
            "
            mov r11, 1
            exit",
            Config {
                dynamic_stack_frames,
                ..Config::default()
            },
            SyscallRegistry::default(),
        )
        .unwrap();
        let result = VerifiedExecutable::<RequisiteVerifier, UserError, TestInstructionMeter>::from_executable(executable)
            .map_err(|err| format!("Executable constructor {:?}", err));

        assert_eq!(
            result.unwrap_err(),
            "Executable constructor VerifierError(InvalidDestinationRegister(29))"
        );
    }
}

#[test]
fn test_verifier_err_invalid_reg_src() {
    // r11 is disabled when dynamic_stack_frames=false, and only sub and add are
    // allowed when dynamic_stack_frames=true
    for dynamic_stack_frames in [false, true] {
        let executable = assemble::<UserError, TestInstructionMeter>(
            "
            mov r0, r11
            exit",
            Config {
                dynamic_stack_frames,
                ..Config::default()
            },
            SyscallRegistry::default(),
        )
        .unwrap();
        let result = VerifiedExecutable::<RequisiteVerifier, UserError, TestInstructionMeter>::from_executable(executable)
            .map_err(|err| format!("Executable constructor {:?}", err));

        assert_eq!(
            result.unwrap_err(),
            "Executable constructor VerifierError(InvalidSourceRegister(29))"
        );
    }
}

#[test]
fn test_verifier_resize_stack_ptr_success() {
    let executable = assemble::<UserError, TestInstructionMeter>(
        "
        sub r11, 1
        add r11, 1
        exit",
        Config {
            dynamic_stack_frames: true,
            enable_stack_frame_gaps: false,
            ..Config::default()
        },
        SyscallRegistry::default(),
    )
    .unwrap();
    let _verified_executable =
        VerifiedExecutable::<RequisiteVerifier, UserError, TestInstructionMeter>::from_executable(
            executable,
        )
        .unwrap();
}

#[test]
#[should_panic(expected = "JumpToMiddleOfLDDW(2, 29)")]
fn test_verifier_err_jmp_lddw() {
    let executable = assemble::<UserError, TestInstructionMeter>(
        "
        ja +1
        lddw r0, 0x1122334455667788
        exit",
        Config::default(),
        SyscallRegistry::default(),
    )
    .unwrap();
    let _verified_executable =
        VerifiedExecutable::<RequisiteVerifier, UserError, TestInstructionMeter>::from_executable(
            executable,
        )
        .unwrap();
}

#[test]
#[should_panic(expected = "JumpOutOfCode(3, 29)")]
fn test_verifier_err_jmp_out() {
    let executable = assemble::<UserError, TestInstructionMeter>(
        "
        ja +2
        exit",
        Config::default(),
        SyscallRegistry::default(),
    )
    .unwrap();
    let _verified_executable =
        VerifiedExecutable::<RequisiteVerifier, UserError, TestInstructionMeter>::from_executable(
            executable,
        )
        .unwrap();
}

#[test]
#[should_panic(expected = "JumpOutOfCode(18446744073709551615, 29)")]
fn test_verifier_err_jmp_out_start() {
    let executable = assemble::<UserError, TestInstructionMeter>(
        "
        ja -2
        exit",
        Config::default(),
        SyscallRegistry::default(),
    )
    .unwrap();
    let _verified_executable =
        VerifiedExecutable::<RequisiteVerifier, UserError, TestInstructionMeter>::from_executable(
            executable,
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
    let executable = Executable::<UserError, TestInstructionMeter>::from_text_bytes(
        prog,
        Config::default(),
        SyscallRegistry::default(),
        BTreeMap::default(),
    )
    .unwrap();
    let _verified_executable =
        VerifiedExecutable::<RequisiteVerifier, UserError, TestInstructionMeter>::from_executable(
            executable,
        )
        .unwrap();
}

#[test]
#[should_panic(expected = "CannotWriteR10(29)")]
fn test_verifier_err_write_r10() {
    let executable = assemble::<UserError, TestInstructionMeter>(
        "
        mov r10, 1
        exit",
        Config::default(),
        SyscallRegistry::default(),
    )
    .unwrap();
    let _verified_executable =
        VerifiedExecutable::<RequisiteVerifier, UserError, TestInstructionMeter>::from_executable(
            executable,
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
        let executable = assemble::<UserError, TestInstructionMeter>(
            &assembly,
            Config::default(),
            SyscallRegistry::default(),
        )
        .unwrap();
        let result = VerifiedExecutable::<RequisiteVerifier, UserError, TestInstructionMeter>::from_executable(executable)
            .map_err(|err| format!("Executable constructor {:?}", err));
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

#[test]
fn test_sdiv_disabled() {
    let instructions = [
        (ebpf::SDIV32_IMM, "sdiv32 r0, 2"),
        (ebpf::SDIV32_REG, "sdiv32 r0, r1"),
        (ebpf::SDIV64_IMM, "sdiv64 r0, 4"),
        (ebpf::SDIV64_REG, "sdiv64 r0, r1"),
    ];

    for (opc, instruction) in instructions {
        for enable_sdiv in [true, false] {
            let assembly = format!("\n{}\nexit", instruction);
            let executable = assemble::<UserError, TestInstructionMeter>(
                &assembly,
                Config {
                    enable_sdiv,
                    ..Config::default()
                },
                SyscallRegistry::default(),
            )
            .unwrap();
            let result = VerifiedExecutable::<RequisiteVerifier, UserError, TestInstructionMeter>::from_executable(executable)
                .map_err(|err| format!("Executable constructor {:?}", err));
            if enable_sdiv {
                assert!(result.is_ok());
            } else {
                assert_eq!(
                    result.unwrap_err(),
                    format!(
                        "Executable constructor VerifierError(UnknownOpCode({}, {}))",
                        opc,
                        ebpf::ELF_INSN_DUMP_OFFSET
                    ),
                );
            }
        }
    }
}
