use std::mem::size_of;

use arbitrary::{Arbitrary, Unstructured};

use solana_rbpf::vm::Config;

#[derive(Debug)]
pub struct ConfigTemplate {
    max_call_depth: usize,
    instruction_meter_checkpoint_distance: usize,
    noop_instruction_rate: u32,
    enable_stack_frame_gaps: bool,
    enable_symbol_and_section_labels: bool,
    sanitize_user_provided_values: bool,
    optimize_rodata: bool,
}

impl<'a> Arbitrary<'a> for ConfigTemplate {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let bools = u16::arbitrary(u)?;
        Ok(ConfigTemplate {
            max_call_depth: usize::from(u8::arbitrary(u)?) + 1, // larger is unreasonable + must be non-zero
            instruction_meter_checkpoint_distance: usize::from(u16::arbitrary(u)?), // larger is unreasonable
            noop_instruction_rate: u32::from(u16::arbitrary(u)?),
            enable_stack_frame_gaps: bools & (1 << 0) != 0,
            enable_symbol_and_section_labels: bools & (1 << 1) != 0,
            sanitize_user_provided_values: bools & (1 << 3) != 0,
            optimize_rodata: bools & (1 << 9) != 0,
        })
    }

    fn size_hint(_: usize) -> (usize, Option<usize>) {
        (
            size_of::<u8>() + size_of::<u16>() + size_of::<f64>() + size_of::<u16>(),
            None,
        )
    }
}

impl From<ConfigTemplate> for Config {
    fn from(template: ConfigTemplate) -> Self {
        match template {
            ConfigTemplate {
                max_call_depth,
                instruction_meter_checkpoint_distance,
                noop_instruction_rate,
                enable_stack_frame_gaps,
                enable_symbol_and_section_labels,
                sanitize_user_provided_values,
                optimize_rodata,
            } => Config {
                max_call_depth,
                enable_stack_frame_gaps,
                instruction_meter_checkpoint_distance,
                enable_symbol_and_section_labels,
                noop_instruction_rate,
                sanitize_user_provided_values,
                optimize_rodata,
                ..Default::default()
            },
        }
    }
}
