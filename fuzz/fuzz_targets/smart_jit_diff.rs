#![no_main]

use libfuzzer_sys::fuzz_target;

use grammar_aware::*;
use solana_rbpf::{
    ebpf,
    elf::Executable,
    insn_builder::{Arch, Instruction, IntoBytes},
    memory_region::MemoryRegion,
    verifier::{RequisiteVerifier, Verifier},
    vm::{EbpfVm, FunctionRegistry, SyscallRegistry, TestContextObject, VerifiedExecutable},
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
        SyscallRegistry::default(),
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
            panic!("Expected {:?}, but got {:?}", interp_res, jit_res);
        }
        if interp_res.is_ok() {
            // we know jit res must be ok if interp res is by this point
            if interp_syscall_object.remaining != jit_syscall_object.remaining {
                panic!(
                    "Expected {} insts remaining, but got {}",
                    interp_syscall_object.remaining, jit_syscall_object.remaining
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
