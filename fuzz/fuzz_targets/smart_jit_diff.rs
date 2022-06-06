#![no_main]

use std::collections::BTreeMap;

use libfuzzer_sys::fuzz_target;

use grammar_aware::*;
use solana_rbpf::{
    ebpf,
    elf::{register_bpf_function, Executable},
    insn_builder::{Arch, Instruction, IntoBytes},
    memory_region::MemoryRegion,
    user_error::UserError,
    verifier::{RequisiteVerifier, Verifier},
    vm::{EbpfVm, SyscallRegistry, TestInstructionMeter, VerifiedExecutable},
};
use test_utils::TautologyVerifier;

use crate::common::ConfigTemplate;

mod common;
mod grammar_aware;

#[derive(arbitrary::Arbitrary, Debug)]
struct FuzzData {
    template: ConfigTemplate,
    exit_dst: u8,
    exit_src: u8,
    exit_off: i16,
    exit_imm: i64,
    prog: FuzzProgram,
    mem: Vec<u8>,
}

fuzz_target!(|data: FuzzData| {
    let mut prog = make_program(&data.prog, Arch::X64);
    prog.exit()
        .set_dst(data.exit_dst)
        .set_src(data.exit_src)
        .set_off(data.exit_off)
        .set_imm(data.exit_imm)
        .push();
    let config = data.template.into();
    if RequisiteVerifier::verify(prog.into_bytes(), &config).is_err() {
        // verify please
        return;
    }
    let mut interp_mem = data.mem.clone();
    let mut jit_mem = data.mem;
    let registry = SyscallRegistry::default();
    let mut bpf_functions = BTreeMap::new();
    register_bpf_function(&config, &mut bpf_functions, &registry, 0, "entrypoint").unwrap();
    let executable = Executable::<UserError, TestInstructionMeter>::from_text_bytes(
        prog.into_bytes(),
        config,
        SyscallRegistry::default(),
        bpf_functions,
    )
    .unwrap();
    let mut verified_executable =
        VerifiedExecutable::<TautologyVerifier, UserError, TestInstructionMeter>::from_executable(
            executable,
        )
        .unwrap();
    if verified_executable.jit_compile().is_ok() {
        let interp_mem_region = MemoryRegion::new_writable(&mut interp_mem, ebpf::MM_INPUT_START);
        let mut interp_vm =
            EbpfVm::new(&verified_executable, &mut [], vec![interp_mem_region]).unwrap();
        let jit_mem_region = MemoryRegion::new_writable(&mut jit_mem, ebpf::MM_INPUT_START);
        let mut jit_vm = EbpfVm::new(&verified_executable, &mut [], vec![jit_mem_region]).unwrap();

        let mut interp_meter = TestInstructionMeter { remaining: 1 << 16 };
        let interp_res = interp_vm.execute_program_interpreted(&mut interp_meter);
        let mut jit_meter = TestInstructionMeter { remaining: 1 << 16 };
        let jit_res = jit_vm.execute_program_jit(&mut jit_meter);
        if interp_res != jit_res {
            panic!("Expected {:?}, but got {:?}", interp_res, jit_res);
        }
        if interp_res.is_ok() {
            // we know jit res must be ok if interp res is by this point
            if interp_meter.remaining != jit_meter.remaining {
                panic!(
                    "Expected {} insts remaining, but got {}",
                    interp_meter.remaining, jit_meter.remaining
                );
            }
            if interp_mem != jit_mem {
                panic!(
                    "Expected different memory. From interpreter: {:?}\nFrom JIT: {:?}",
                    interp_mem, jit_mem
                );
            }
        }
    }
});
