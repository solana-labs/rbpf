#![feature(bench_black_box)]

#![no_main]
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

use std::hint::black_box;

use solana_rbpf::{elf::{Executable, register_bpf_function}, verifier::check, vm::{Config, EbpfVm, TestInstructionMeter, SyscallRegistry}, user_error::UserError};

#[derive(arbitrary::Arbitrary, Debug)]
struct DumbFuzzData {
    prog: Vec<u8>,
    mem: Vec<u8>,
}

fuzz_target!(|data: DumbFuzzData| {
    let prog = data.prog;
    let config = Config::default();
    if check(&prog, &config).is_err() { // verify please
        return;
    }
    let mut mem = data.mem;
    let registry = SyscallRegistry::default();
    let mut bpf_functions = BTreeMap::new();
    register_bpf_function(&config, &mut bpf_functions, &registry, 0, "entrypoint").unwrap();
    let executable = Executable::<UserError, TestInstructionMeter>::from_text_bytes(&prog, None, Config::default(), SyscallRegistry::default(), bpf_functions).unwrap();
    let mut vm = EbpfVm::<UserError, TestInstructionMeter>::new(&executable, &mut [], &mut mem).unwrap();

    drop(black_box(vm.execute_program_interpreted(&mut TestInstructionMeter { remaining: 1024 })));
});
