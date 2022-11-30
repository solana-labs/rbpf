#![no_main]

use std::hint::black_box;

use libfuzzer_sys::fuzz_target;

use solana_rbpf::{
    ebpf,
    elf::Executable,
    memory_region::MemoryRegion,
    verifier::{RequisiteVerifier, Verifier},
    vm::{EbpfVm, FunctionRegistry, SyscallRegistry, TestContextObject, VerifiedExecutable},
};
use test_utils::TautologyVerifier;

use crate::common::ConfigTemplate;

mod common;

#[derive(arbitrary::Arbitrary, Debug)]
struct DumbFuzzData {
    template: ConfigTemplate,
    prog: Vec<u8>,
    mem: Vec<u8>,
}

fuzz_target!(|data: DumbFuzzData| {
    let prog = data.prog;
    let config = data.template.into();
    let function_registry = FunctionRegistry::default();
    if RequisiteVerifier::verify(&prog, &config, &function_registry).is_err() {
        // verify please
        return;
    }
    let mut mem = data.mem;
    let executable = Executable::<TestContextObject>::from_text_bytes(
        &prog,
        config,
        std::sync::Arc::new(SyscallRegistry::default()),
        function_registry,
    )
    .unwrap();
    let verified_executable =
        VerifiedExecutable::<TautologyVerifier, TestContextObject>::from_executable(executable)
            .unwrap();
    let mem_region = MemoryRegion::new_writable(&mut mem, ebpf::MM_INPUT_START);
    let mut context_object = TestContextObject::new(29);
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
