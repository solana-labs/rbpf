#![no_main]

use std::collections::BTreeMap;

use libfuzzer_sys::fuzz_target;

use semantic_aware::*;
use solana_rbpf::{
    ebpf,
    elf::{register_bpf_function, Executable},
    error::{EbpfError, UserDefinedError},
    insn_builder::IntoBytes,
    memory_region::MemoryRegion,
    static_analysis::Analysis,
    user_error::UserError,
    verifier::check,
    vm::{EbpfVm, InstructionMeter, SyscallRegistry, TestInstructionMeter},
};

use crate::common::ConfigTemplate;

mod common;
mod semantic_aware;

#[derive(arbitrary::Arbitrary, Debug)]
struct FuzzData {
    template: ConfigTemplate,
    prog: FuzzProgram,
    mem: Vec<u8>,
}

fn dump_insns<E: UserDefinedError, I: InstructionMeter>(executable: &Executable<E, I>) {
    let analysis = Analysis::from_executable(executable).unwrap();
    eprint!("Using the following disassembly");
    analysis.disassemble(&mut std::io::stderr().lock()).unwrap();
}

fuzz_target!(|data: FuzzData| {
    let prog = make_program(&data.prog);
    let config = data.template.into();
    if check(prog.into_bytes(), &config).is_err() {
        // verify please
        return;
    }
    let mut interp_mem = data.mem.clone();
    let mut jit_mem = data.mem;
    let registry = SyscallRegistry::default();
    let mut bpf_functions = BTreeMap::new();
    register_bpf_function(&config, &mut bpf_functions, &registry, 0, "entrypoint").unwrap();
    let mut executable = Executable::<UserError, TestInstructionMeter>::from_text_bytes(
        prog.into_bytes(),
        None,
        config,
        SyscallRegistry::default(),
        bpf_functions,
    )
    .unwrap();
    if Executable::jit_compile(&mut executable).is_ok() {
        let interp_mem_region = MemoryRegion::new_writable(&mut interp_mem, ebpf::MM_INPUT_START);
        let mut interp_vm =
            EbpfVm::<UserError, TestInstructionMeter>::new(&executable, &mut [], vec![interp_mem_region])
                .unwrap();
        let jit_mem_region = MemoryRegion::new_writable(&mut jit_mem, ebpf::MM_INPUT_START);
        let mut jit_vm =
            EbpfVm::<UserError, TestInstructionMeter>::new(&executable, &mut [], vec![jit_mem_region])
                .unwrap();

        let mut interp_meter = TestInstructionMeter { remaining: 1 << 16 };
        let interp_res = interp_vm.execute_program_interpreted(&mut interp_meter);
        let mut jit_meter = TestInstructionMeter { remaining: 1 << 16 };
        let jit_res = jit_vm.execute_program_jit(&mut jit_meter);
        if interp_res != jit_res {
            // spot check: there's a meaningless bug where ExceededMaxInstructions is different due to jump calculations
            if let Err(EbpfError::<UserError>::ExceededMaxInstructions(interp_count, _)) =
                interp_res
            {
                if let Err(EbpfError::<UserError>::ExceededMaxInstructions(jit_count, _)) = jit_res
                {
                    if interp_count != jit_count {
                        return;
                    }
                }
            }
            eprintln!("{:#?}", &data.prog);
            dump_insns(&executable);
            panic!("Expected {:?}, but got {:?}", interp_res, jit_res);
        }
        if interp_res.is_ok() {
            // we know jit res must be ok if interp res is by this point
            if interp_meter.remaining != jit_meter.remaining {
                dump_insns(&executable);
                panic!(
                    "Expected {} insts remaining, but got {}",
                    interp_meter.remaining, jit_meter.remaining
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
