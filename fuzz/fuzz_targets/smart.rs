#![no_main]

use std::hint::black_box;

use libfuzzer_sys::fuzz_target;

use grammar_aware::*;
use solana_rbpf::{
    ebpf,
    elf::Executable,
    insn_builder::{Arch, IntoBytes},
    memory_region::MemoryRegion,
    verifier::{RequisiteVerifier, Verifier},
    vm::{EbpfVm, FunctionRegistry, BuiltInProgram, TestContextObject, VerifiedExecutable},
};
use test_utils::TautologyVerifier;

use crate::common::ConfigTemplate;

mod common;
mod grammar_aware;

#[derive(arbitrary::Arbitrary, Debug)]
struct FuzzData {
    template: ConfigTemplate,
    prog: FuzzProgram,
    mem: Vec<u8>,
    arch: Arch,
}

fuzz_target!(|data: FuzzData| {
    let prog = make_program(&data.prog, data.arch);
    let config = data.template.into();
    let function_registry = FunctionRegistry::default();
    if RequisiteVerifier::verify(prog.into_bytes(), &config, &function_registry).is_err() {
        // verify please
        return;
    }
    let mut mem = data.mem;
    let executable = Executable::<TestContextObject>::from_text_bytes(
        prog.into_bytes(),
        std::sync::Arc::new(BuiltInProgram::new_loader(config)),
        function_registry,
    )
    .unwrap();
    let verified_executable =
        VerifiedExecutable::<TautologyVerifier, TestContextObject>::from_executable(executable)
            .unwrap();
    let mem_region = MemoryRegion::new_writable(&mut mem, ebpf::MM_INPUT_START);
    let mut context_object = TestContextObject::new(1 << 16);
    let mut interp_vm = EbpfVm::new(
        &verified_executable,
        &mut context_object,
        &mut [],
        vec![mem_region],
    )
    .unwrap();
    let (_interp_ins_count, interp_res) = interp_vm.execute_program(true);
    drop(black_box(interp_res));
});
