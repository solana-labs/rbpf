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
        EbpfVm, InstructionMeter, ProgramResult, SyscallRegistry, TestInstructionMeter,
        VerifiedExecutable, FunctionRegistry,
    },
};
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

fn dump_insns<V: Verifier, I: InstructionMeter>(verified_executable: &VerifiedExecutable<V, I>) {
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
    let executable = Executable::<TestInstructionMeter>::from_text_bytes(
        prog.into_bytes(),
        config,
        SyscallRegistry::default(),
        function_registry,
    )
    .unwrap();
    let mut verified_executable =
        VerifiedExecutable::<TautologyVerifier, TestInstructionMeter>::from_executable(executable)
            .unwrap();
    if verified_executable.jit_compile().is_ok() {
        let interp_mem_region = MemoryRegion::new_writable(&mut interp_mem, ebpf::MM_INPUT_START);
        let mut interp_vm =
            EbpfVm::new(&verified_executable, &mut (), &mut [], vec![interp_mem_region]).unwrap();
        let jit_mem_region = MemoryRegion::new_writable(&mut jit_mem, ebpf::MM_INPUT_START);
        let mut jit_vm = EbpfVm::new(&verified_executable, &mut (), &mut [], vec![jit_mem_region]).unwrap();

        let mut interp_meter = TestInstructionMeter { remaining: 1 << 16 };
        let interp_res = interp_vm.execute_program_interpreted(&mut interp_meter);
        let mut jit_meter = TestInstructionMeter { remaining: 1 << 16 };
        let jit_res = jit_vm.execute_program_jit(&mut jit_meter);
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
            if interp_meter.remaining != jit_meter.remaining {
                dump_insns(&verified_executable);
                panic!(
                    "Expected {} insts remaining, but got {}",
                    interp_meter.remaining, jit_meter.remaining
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
