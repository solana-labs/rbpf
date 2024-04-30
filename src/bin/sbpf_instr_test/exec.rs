use solana_rbpf::{
    ebpf,
    ebpf::Insn,
    elf::Executable,
    memory_region::{MemoryMapping, MemoryRegion},
    program::{BuiltinProgram, FunctionRegistry, SBPFVersion},
    verifier::{RequisiteVerifier, Verifier},
    vm::{Config, EbpfVm, TestContextObject},
};
use std::sync::Arc;

use crate::types::*;

pub fn run_input(input: &Input) -> Effects {
    let vm_config = Config::default();
    let sbpf_version = SBPFVersion::V1;
    let function_registry_usize = FunctionRegistry::default();
    let function_registry_typed = FunctionRegistry::default();

    let mut text = Vec::<u8>::with_capacity(8 * (3 + input.regs.len()));

    for (i, reg) in input.regs[..=9].iter().enumerate() {
        text.extend_from_slice(
            &Insn {
                opc: ebpf::LD_DW_IMM,
                dst: i as u8,
                imm: ((reg & u32::MAX as u64) as u32) as i64,
                ..Insn::default()
            }
            .to_array(),
        );
        text.extend_from_slice(
            &Insn {
                imm: ((reg >> 32) as u32) as i64,
                ..Insn::default()
            }
            .to_array(),
        );
    }
    text.extend_from_slice(&input.encode_instruction().to_le_bytes());
    text.extend_from_slice(
        &Insn {
            opc: ebpf::EXIT,
            ..Insn::default()
        }
        .to_array(),
    );

    let verify_fail =
        RequisiteVerifier::verify(&text, &vm_config, &sbpf_version, &function_registry_usize)
            .is_err();
    if verify_fail {
        return Effects {
            status: Status::VerifyFail,
            ..Effects::default()
        };
    }

    // Set up VM

    let loader = Arc::new(BuiltinProgram::new_loader(
        vm_config,
        function_registry_typed,
    ));

    let executable = Executable::new_from_text_bytes(
        &text,
        Arc::clone(&loader),
        sbpf_version.clone(),
        function_registry_usize,
    )
    .unwrap();

    let cus = 10000u64;
    let mut context_object = TestContextObject::new(cus);
    let mut input_data = input.input.clone();

    let regions: Vec<MemoryRegion> = vec![
        MemoryRegion::new_readonly(&[], ebpf::MM_PROGRAM_START),
        MemoryRegion::new_readonly(&[], ebpf::MM_STACK_START),
        MemoryRegion::new_readonly(&[], ebpf::MM_HEAP_START),
        MemoryRegion::new_writable(&mut input_data, ebpf::MM_INPUT_START),
    ];

    let memory_mapping = MemoryMapping::new(regions, &vm_config, &sbpf_version).unwrap();
    let stack_len = 0usize;

    let mut vm = EbpfVm::new(
        loader,
        &sbpf_version,
        &mut context_object,
        memory_mapping,
        stack_len,
    );
    vm.stack_pointer = input.regs[10]; // stack_pointer is r10

    let interpreted = true;
    let (_, result) = vm.execute_program(&executable, interpreted);
    if result.is_err() {
        return Effects {
            status: Status::Fault,
            ..Effects::default()
        };
    }

    Effects {
        status: Status::Ok,
        regs: vm.registers,
    }
}

pub fn run_fixture(fixture: &Fixture, source_file: &str) -> bool {
    let mut fail = false;
    let actual = run_input(&fixture.input);
    let expected = &fixture.effects;
    if expected.status != actual.status {
        eprintln!(
            "FAIL {}:{}: Expected status {:?}, got {:?}",
            source_file, fixture.line, fixture.effects.status, actual.status
        );
        fail = true;
    }
    fail
}
