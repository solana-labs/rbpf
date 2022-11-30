#![no_main]

use libfuzzer_sys::fuzz_target;

use semantic_aware::*;
use solana_rbpf::{
    ebpf,
    elf::Executable,
    error::EbpfError,
    insn_builder::IntoBytes,
    memory_region::MemoryRegion,
    static_analysis::Analysis,
    verifier::{RequisiteVerifier, Verifier},
    vm::{
        ContextObject, EbpfVm, FunctionRegistry, ProgramResult, SyscallRegistry, TestContextObject,
        VerifiedExecutable,
    },
};
use std::sync::Arc;
use test_utils::TautologyVerifier;

use crate::common::ConfigTemplate;

mod common;
mod semantic_aware;

#[derive(arbitrary::Arbitrary, Debug)]
struct FuzzData {
    template: ConfigTemplate,
    prog: FuzzProgram,
    mem: Vec<u8>,
}

fn dump_insns<V: Verifier, C: ContextObject>(verified_executable: &VerifiedExecutable<V, C>) {
    let analysis = Analysis::from_executable(verified_executable.get_executable()).unwrap();
    eprint!("Using the following disassembly");
    analysis.disassemble(&mut std::io::stderr().lock()).unwrap();
}

fuzz_target!(|data: FuzzData| {
    let prog = make_program(&data.prog);
    let config = data.template.into();
    let function_registry = FunctionRegistry::default();
    if RequisiteVerifier::verify(prog.into_bytes(), &config, &function_registry).is_err() {
        // verify please
        return;
    }
    let mut interp_mem = data.mem.clone();
    let mut jit_mem = data.mem;
    let executable = Executable::<TestContextObject>::from_text_bytes(
        prog.into_bytes(),
        config,
        Arc::new(SyscallRegistry::default()),
        function_registry,
    )
    .unwrap();
    let mut verified_executable =
        VerifiedExecutable::<TautologyVerifier, TestContextObject>::from_executable(executable)
            .unwrap();
    if verified_executable.jit_compile().is_ok() {
        let mut interp_syscall_object = TestContextObject::new(1 << 16);
        let interp_mem_region = MemoryRegion::new_writable(&mut interp_mem, ebpf::MM_INPUT_START);
        let mut interp_vm = EbpfVm::new(
            &verified_executable,
            &mut interp_syscall_object,
            &mut [],
            vec![interp_mem_region],
        )
        .unwrap();
        let mut jit_syscall_object = TestContextObject::new(1 << 16);
        let jit_mem_region = MemoryRegion::new_writable(&mut jit_mem, ebpf::MM_INPUT_START);
        let mut jit_vm = EbpfVm::new(
            &verified_executable,
            &mut jit_syscall_object,
            &mut [],
            vec![jit_mem_region],
        )
        .unwrap();

        let (_interp_ins_count, interp_res) = interp_vm.execute_program(true);
        let (_jit_ins_count, jit_res) = jit_vm.execute_program(false);
        if format!("{:?}", interp_res) != format!("{:?}", jit_res) {
            // spot check: there's a meaningless bug where ExceededMaxInstructions is different due to jump calculations
            if let ProgramResult::Err(EbpfError::ExceededMaxInstructions(interp_count, _)) =
                interp_res
            {
                if let ProgramResult::Err(EbpfError::ExceededMaxInstructions(jit_count, _)) =
                    jit_res
                {
                    if interp_count != jit_count {
                        return;
                    }
                }
            }
            eprintln!("{:#?}", &data.prog);
            dump_insns(&verified_executable);
            panic!("Expected {:?}, but got {:?}", interp_res, jit_res);
        }
        if interp_res.is_ok() {
            // we know jit res must be ok if interp res is by this point
            if interp_syscall_object.remaining != jit_syscall_object.remaining {
                dump_insns(&verified_executable);
                panic!(
                    "Expected {} insts remaining, but got {}",
                    interp_syscall_object.remaining, jit_syscall_object.remaining
                );
            }
            if interp_mem != jit_mem {
                dump_insns(&verified_executable);
                panic!(
                    "Expected different memory. From interpreter: {:?}\nFrom JIT: {:?}",
                    interp_mem, jit_mem
                );
            }
        }
    }
});
