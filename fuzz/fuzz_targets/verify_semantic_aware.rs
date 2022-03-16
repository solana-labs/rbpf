#![no_main]

mod semantic_aware;

use solana_rbpf::vm::Config;
use solana_rbpf::verifier::check;
use solana_rbpf::insn_builder::IntoBytes;

use libfuzzer_sys::fuzz_target;

use semantic_aware::*;

#[derive(arbitrary::Arbitrary, Debug)]
struct FuzzData {
    prog: FuzzProgram,
}

fuzz_target!(|data: FuzzData| {
    let prog = make_program(&data.prog);
    let config = Config::default();
    check(prog.into_bytes(), &config).unwrap();
});
