#![no_main]

use libfuzzer_sys::fuzz_target;

use semantic_aware::*;
use solana_rbpf::insn_builder::IntoBytes;
use solana_rbpf::verifier::{RequisiteVerifier, Verifier};

use crate::common::ConfigTemplate;

mod common;
mod semantic_aware;

#[derive(arbitrary::Arbitrary, Debug)]
struct FuzzData {
    template: ConfigTemplate,
    prog: FuzzProgram,
}

fuzz_target!(|data: FuzzData| {
    let prog = make_program(&data.prog);
    let config = data.template.into();
    RequisiteVerifier::verify(prog.into_bytes(), &config).unwrap();
});
