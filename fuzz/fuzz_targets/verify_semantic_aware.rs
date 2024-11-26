#![no_main]

use libfuzzer_sys::fuzz_target;

use semantic_aware::*;
use solana_rbpf::{
    insn_builder::IntoBytes,
    program::{BuiltinFunction, FunctionRegistry, SBPFVersion},
    verifier::{RequisiteVerifier, Verifier},
    vm::TestContextObject,
};

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
    let function_registry = FunctionRegistry::default();
    let syscall_registry = FunctionRegistry::<BuiltinFunction<TestContextObject>>::default();

    RequisiteVerifier::verify(
        prog.into_bytes(),
        &config,
        SBPFVersion::V3,
        &function_registry,
        &syscall_registry,
    )
    .unwrap();
});
