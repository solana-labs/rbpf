//! Static Byte Code Analysis

use crate::{
    disassembler::{to_insn_vec, HlInsn},
    ebpf,
    error::UserDefinedError,
    vm::Executable,
    vm::InstructionMeter,
};
use std::collections::BTreeMap;

/// Type of a control flow graph node
#[derive(PartialEq)]
pub enum LabelKind {
    /// From the prologue to the epilogue
    Function,
    /// From one jump source or destination to the next
    BasicBlock,
}

/// A node of the control flow graph
pub struct Label {
    /// Human readable name (for disassembler)
    pub name: String,
    /// Length in insturction slots
    pub length: usize,
    /// Type
    pub kind: LabelKind,
    /// PCs of instructions which can jump here
    pub sources: Vec<usize>,
}

macro_rules! resolve_label {
    ($labels:expr, $target_pc:expr) => {
        if let Some(label) = $labels.get(&$target_pc) {
            label.name.clone()
        } else {
            format!("{} # unresolved symbol", $target_pc)
        }
    };
}

/// Result of the executable analysis
pub struct AnalysisResult {
    /// Plain list of instructions as they occur in the executable
    pub instructions: Vec<HlInsn>,
    /// Nodes of the control flow graph
    pub destinations: BTreeMap<usize, Label>,
    /// Edges of the control flow graph
    pub sources: BTreeMap<usize, Vec<usize>>,
}

impl AnalysisResult {
    /// Analyze an executable statically
    pub fn from_executable<E: UserDefinedError, I: InstructionMeter>(
        executable: &dyn Executable<E, I>,
    ) -> Self {
        let (_program_vm_addr, program) = executable.get_text_bytes().unwrap();
        let mut result = Self {
            instructions: to_insn_vec(program),
            destinations: BTreeMap::new(),
            sources: BTreeMap::new(),
        };
        let (syscalls, bpf_functions) = executable.get_symbols();
        for (pc, bpf_function) in bpf_functions {
            result.destinations.insert(
                pc,
                Label {
                    name: bpf_function.0, // demangle(&bpf_function.0).to_string(),
                    length: 0,            // bpf_function.1,
                    kind: LabelKind::Function,
                    sources: Vec::new(),
                },
            );
        }
        let entrypoint_pc = executable.get_entrypoint_instruction_offset().unwrap();
        result.destinations.entry(entrypoint_pc).or_insert(Label {
            name: "entrypoint".to_string(),
            length: 0,
            kind: LabelKind::Function,
            sources: Vec::new(),
        });
        for insn in result.instructions.iter() {
            match insn.opc {
                ebpf::CALL_IMM => {
                    if let Some(target_pc) = executable.lookup_bpf_function(insn.imm as u32) {
                        // result.sources.insert(insn.ptr, vec![*target_pc]);
                        if !result.destinations.contains_key(target_pc) {
                            result.destinations.insert(
                                *target_pc,
                                Label {
                                    name: format!("function_{}", target_pc),
                                    length: 0,
                                    kind: LabelKind::Function,
                                    sources: Vec::new(),
                                },
                            );
                        }
                    }
                }
                ebpf::CALL_REG | ebpf::EXIT => {
                    result.sources.insert(insn.ptr, vec![]);
                }
                _ => {}
            }
        }
        for insn in result.instructions.iter() {
            let target_pc = (insn.ptr as isize + insn.off as isize + 1) as usize;
            match insn.opc {
                ebpf::JA => {
                    result.sources.insert(insn.ptr, vec![target_pc]);
                }
                ebpf::JEQ_IMM
                | ebpf::JGT_IMM
                | ebpf::JGE_IMM
                | ebpf::JLT_IMM
                | ebpf::JLE_IMM
                | ebpf::JSET_IMM
                | ebpf::JNE_IMM
                | ebpf::JSGT_IMM
                | ebpf::JSGE_IMM
                | ebpf::JSLT_IMM
                | ebpf::JSLE_IMM
                | ebpf::JEQ_REG
                | ebpf::JGT_REG
                | ebpf::JGE_REG
                | ebpf::JLT_REG
                | ebpf::JLE_REG
                | ebpf::JSET_REG
                | ebpf::JNE_REG
                | ebpf::JSGT_REG
                | ebpf::JSGE_REG
                | ebpf::JSLT_REG
                | ebpf::JSLE_REG => {
                    result
                        .sources
                        .insert(insn.ptr, vec![insn.ptr + 1, target_pc]);
                    result.destinations.insert(
                        insn.ptr + 1,
                        Label {
                            name: format!("lbb_{}", insn.ptr + 1),
                            length: 0,
                            kind: LabelKind::BasicBlock,
                            sources: Vec::new(),
                        },
                    );
                }
                _ => continue,
            }
            result.destinations.entry(target_pc).or_insert(Label {
                name: format!("lbb_{}", target_pc),
                length: 0,
                kind: LabelKind::BasicBlock,
                sources: Vec::new(),
            });
        }
        for (source, destinations) in &result.sources {
            for destination in destinations {
                result
                    .destinations
                    .get_mut(destination)
                    .unwrap()
                    .sources
                    .push(*source);
            }
        }
        let mut destination_iter = result.destinations.iter_mut().peekable();
        let mut source_iter = result.sources.iter().peekable();
        while let Some((begin, label)) = destination_iter.next() {
            match result
                .instructions
                .binary_search_by(|insn| insn.ptr.cmp(begin))
            {
                Ok(_) => {}
                Err(_index) => {
                    println!("WARNING: Invalid symbol {:?}, pc={}", label.name, begin);
                    label.length = 0;
                    continue;
                }
            }
            if label.length > 0 {
                continue;
            }
            while let Some(next_source) = source_iter.peek() {
                if *next_source.0 < *begin {
                    source_iter.next();
                } else {
                    break;
                }
            }
            let end = if let Some(next_destination) = destination_iter.peek() {
                if let Some(next_source) = source_iter.peek() {
                    let next_source = *next_source.0 + 1;
                    if next_source < *next_destination.0 {
                        source_iter.next();
                        next_source
                    } else {
                        *next_destination.0
                    }
                } else {
                    *next_destination.0
                }
            } else if let Some(next_source) = source_iter.next() {
                *next_source.0 + 1
            } else {
                result.instructions.last().unwrap().ptr
            };
            label.length = end - begin;
        }
        for insn in result.instructions.iter_mut() {
            match insn.opc {
                ebpf::CALL_IMM => {
                    insn.desc = if let Some(syscall_name) = syscalls.get(&(insn.imm as u32)) {
                        format!("syscall {}", syscall_name)
                    } else if let Some(target_pc) = executable.lookup_bpf_function(insn.imm as u32)
                    {
                        format!("call {}", resolve_label!(result.destinations, target_pc))
                    } else {
                        format!("call {:x} # unresolved relocation", insn.imm)
                    };
                }
                ebpf::JA => {
                    let target_pc = (insn.ptr as isize + insn.off as isize + 1) as usize;
                    insn.desc = format!(
                        "{} {}",
                        insn.name,
                        resolve_label!(result.destinations, target_pc)
                    );
                }
                ebpf::JEQ_IMM
                | ebpf::JGT_IMM
                | ebpf::JGE_IMM
                | ebpf::JLT_IMM
                | ebpf::JLE_IMM
                | ebpf::JSET_IMM
                | ebpf::JNE_IMM
                | ebpf::JSGT_IMM
                | ebpf::JSGE_IMM
                | ebpf::JSLT_IMM
                | ebpf::JSLE_IMM => {
                    let target_pc = (insn.ptr as isize + insn.off as isize + 1) as usize;
                    insn.desc = format!(
                        "{} r{}, {:#x}, {}",
                        insn.name,
                        insn.dst,
                        insn.imm,
                        resolve_label!(result.destinations, target_pc)
                    );
                }
                ebpf::JEQ_REG
                | ebpf::JGT_REG
                | ebpf::JGE_REG
                | ebpf::JLT_REG
                | ebpf::JLE_REG
                | ebpf::JSET_REG
                | ebpf::JNE_REG
                | ebpf::JSGT_REG
                | ebpf::JSGE_REG
                | ebpf::JSLT_REG
                | ebpf::JSLE_REG => {
                    let target_pc = (insn.ptr as isize + insn.off as isize + 1) as usize;
                    insn.desc = format!(
                        "{} r{}, r{}, {}",
                        insn.name,
                        insn.dst,
                        insn.src,
                        resolve_label!(result.destinations, target_pc)
                    );
                }
                _ => {}
            }
        }
        result
    }
}
