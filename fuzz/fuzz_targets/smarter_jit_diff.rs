#![no_main]

use libfuzzer_sys::fuzz_target;

use semantic_aware::*;
use solana_rbpf::{
    ebpf,
    elf::Executable,
    insn_builder::IntoBytes,
    memory_region::MemoryRegion,
    program::{BuiltinProgram, FunctionRegistry, SBPFVersion},
    static_analysis::Analysis,
    verifier::{RequisiteVerifier, Verifier},
    vm::{ContextObject, TestContextObject},
};
use test_utils::create_vm;

use crate::common::ConfigTemplate;

mod common;
mod semantic_aware;

#[derive(arbitrary::Arbitrary, Debug)]
struct FuzzData {
    template: ConfigTemplate,
    prog: FuzzProgram,
    mem: Vec<u8>,
}

fn dump_insns<C: ContextObject>(executable: &Executable<C>) {
    let analysis = Analysis::from_executable(executable).unwrap();
    eprint!("Using the following disassembly");
    analysis.disassemble(&mut std::io::stderr().lock()).unwrap();
}

fuzz_target!(|data: FuzzData| {
    let prog = make_program(&data.prog);
    let config = data.template.into();
    let function_registry = FunctionRegistry::default();
    if RequisiteVerifier::verify(
        prog.into_bytes(),
        &config,
        &SBPFVersion::V2,
        &function_registry,
    )
    .is_err()
    {
        // verify please
        return;
    }
    let mut interp_mem = data.mem.clone();
    let mut jit_mem = data.mem;
    let mut executable = Executable::<TestContextObject>::from_text_bytes(
        prog.into_bytes(),
        std::sync::Arc::new(BuiltinProgram::new_loader(
            config,
            FunctionRegistry::default(),
        )),
        SBPFVersion::V2,
        function_registry,
    )
    .unwrap();
    if executable.jit_compile().is_ok() {
        let mut interp_context_object = TestContextObject::new(1 << 16);
        let interp_mem_region = MemoryRegion::new_writable(&mut interp_mem, ebpf::MM_INPUT_START);
        create_vm!(
            interp_vm,
            &executable,
            &mut interp_context_object,
            interp_stack,
            interp_heap,
            vec![interp_mem_region],
            None
        );

        let mut jit_context_object = TestContextObject::new(1 << 16);
        let jit_mem_region = MemoryRegion::new_writable(&mut jit_mem, ebpf::MM_INPUT_START);
        create_vm!(
            jit_vm,
            &executable,
            &mut jit_context_object,
            jit_stack,
            jit_heap,
            vec![jit_mem_region],
            None
        );

        let (_interp_ins_count, interp_res) = interp_vm.execute_program(&executable, true);
        let (_jit_ins_count, jit_res) = jit_vm.execute_program(&executable, false);
        let interp_res_str = format!("{:?}", interp_res);
        let jit_res_str = format!("{:?}", jit_res);
        if interp_res_str != jit_res_str {
            // spot check: there's a meaningless bug where ExceededMaxInstructions is different due to jump calculations
            if interp_res_str.contains("ExceededMaxInstructions")
                && jit_res_str.contains("ExceededMaxInstructions")
            {
                return;
            }
            eprintln!("{:#?}", &data.prog);
            dump_insns(&executable);
            panic!("Expected {}, but got {}", interp_res_str, jit_res_str);
        }
        if interp_res.is_ok() {
            // we know jit res must be ok if interp res is by this point
            if interp_context_object.remaining != jit_context_object.remaining {
                dump_insns(&executable);
                panic!(
                    "Expected {} insts remaining, but got {}",
                    interp_context_object.remaining, jit_context_object.remaining
                );
            }
            if interp_mem != jit_mem {
                dump_insns(&executable);
                panic!(
                    "Expected different memory. From interpreter: {:?}\nFrom JIT: {:?}",
                    interp_mem, jit_mem
                );
            }
        }
    }
});
