use solana_rbpf::{
    ebpf::{self, Insn},
    elf::Executable,
    interpreter::Interpreter,
    memory_region::{MemoryMapping, MemoryRegion},
    program::{BuiltinProgram, FunctionRegistry, SBPFVersion},
    verifier::{RequisiteVerifier, Verifier},
    vm::{Config, EbpfVm, TestContextObject},
};
use std::sync::Arc;

use crate::types::*;

pub fn run_input(input: &Input) -> Effects {
    let vm_config = Config {
        enable_instruction_meter: false,
        ..Config::default()
    };
    let sbpf_version = SBPFVersion::V1;
    let function_registry_usize = FunctionRegistry::default();
    let function_registry_typed = FunctionRegistry::default();

    let mut text = Vec::<u8>::with_capacity(8 * 3);

    text.extend_from_slice(&input.encode_instruction().to_le_bytes());
    if let Some(ext) = input.encode_instruction_ext() {
        text.extend_from_slice(&ext.to_le_bytes());
    }
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
    let mut interpreter = Interpreter::new(&mut vm, &executable, input.regs);
    while interpreter.step() {}
    let post_reg = interpreter.reg;
    if vm.program_result.is_err() {
        return Effects {
            status: Status::Fault,
            ..Effects::default()
        };
    }

    Effects {
        status: Status::Ok,
        regs: post_reg,
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
    if expected.status != Status::Ok || actual.status != Status::Ok {
        return fail;
    }
    for i in 0..=9 {
        let reg_expected = expected.regs[i];
        let reg_actual = actual.regs[i];
        if reg_expected != reg_actual {
            eprintln!(
                "FAIL {}:{}: Expected r{} = {:#x}, got {:#x}",
                source_file, fixture.line, i, reg_expected, reg_actual
            );
            fail = true;
        }
    }
    fail
}
