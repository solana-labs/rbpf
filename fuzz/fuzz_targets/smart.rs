#![feature(bench_black_box)]
#![no_main]

mod grammar_aware;

use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

use std::hint::black_box;

use solana_rbpf::{elf::{Executable, register_bpf_function}, insn_builder::{Arch, IntoBytes}, verifier::check, vm::{Config, EbpfVm, TestInstructionMeter, SyscallRegistry}, user_error::UserError};

use grammar_aware::*;

#[derive(arbitrary::Arbitrary, Debug)]
struct FuzzData {
    prog: FuzzProgram,
    mem: Vec<u8>,
    arch: Arch,
}

fuzz_target!(|data: FuzzData| {
    let prog = make_program(&data.prog, data.arch);
    let config = Config::default();
    if check(prog.into_bytes(), &config).is_err() { // verify please
        return;
    }
    let mut mem = data.mem;
    let registry = SyscallRegistry::default();
    let mut bpf_functions = BTreeMap::new();
    register_bpf_function(&config, &mut bpf_functions, &registry, 0, "entrypoint").unwrap();
    let executable = Executable::<UserError, TestInstructionMeter>::from_text_bytes(prog.into_bytes(), None, config, SyscallRegistry::default(), bpf_functions).unwrap();
    let mut vm = EbpfVm::<UserError, TestInstructionMeter>::new(&executable, &mut [], &mut mem).unwrap();

    drop(black_box(vm.execute_program_interpreted(&mut TestInstructionMeter { remaining: 1 << 16 })));
});
