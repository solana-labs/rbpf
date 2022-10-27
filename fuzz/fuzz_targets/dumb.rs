#![no_main]

use std::hint::black_box;

use libfuzzer_sys::fuzz_target;

use solana_rbpf::{
    ebpf,
    elf::Executable,
    memory_region::MemoryRegion,
    verifier::{RequisiteVerifier, Verifier},
    vm::{EbpfVm, SyscallRegistry, FunctionRegistry, TestInstructionMeter, VerifiedExecutable},
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
    let executable = Executable::<TestInstructionMeter>::from_text_bytes(
        &prog,
        config,
        SyscallRegistry::default(),
        function_registry,
    )
    .unwrap();
    let verified_executable =
        VerifiedExecutable::<TautologyVerifier, TestInstructionMeter>::from_executable(executable)
            .unwrap();
    let mem_region = MemoryRegion::new_writable(&mut mem, ebpf::MM_INPUT_START);
    let mut vm = EbpfVm::new(&verified_executable, &mut (), &mut [], vec![mem_region]).unwrap();

    drop(black_box(vm.execute_program_interpreted(
        &mut TestInstructionMeter { remaining: 1024 },
    )));
});
