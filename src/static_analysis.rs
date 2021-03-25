//! Static Byte Code Analysis

use crate::{
    disassembler::{to_insn_vec, HlInsn},
    ebpf,
    error::UserDefinedError,
    vm::Executable,
    vm::InstructionMeter,
};
use std::collections::{BTreeMap, HashMap};

/// A node of the control flow graph
pub struct CfgNode {
    /// Length in instruction slots
    pub length: usize,
    /// Is at least one of the sources a call instruction
    pub is_function_entry: bool,
    /// PCs of instructions which can jump here
    pub sources: Vec<usize>,
}

/// Result of the executable analysis
pub struct Analysis {
    /// Plain list of instructions as they occur in the executable
    pub instructions: Vec<HlInsn>,
    /// Syscalls of the executable (available if debug symbols are not stripped)
    pub syscalls: HashMap<u32, String>,
    /// BPF functions of the executable (available if debug symbols are not stripped)
    pub bpf_functions: HashMap<usize, (String, usize)>,
    /// Nodes of the control flow graph
    pub cfg_nodes: BTreeMap<usize, CfgNode>,
    /// Edges of the control flow graph (source, destinations)
    pub cfg_edges: BTreeMap<usize, Vec<usize>>,
}

impl Analysis {
    /// Analyze an executable statically
    pub fn from_executable<E: UserDefinedError, I: InstructionMeter>(
        executable: &dyn Executable<E, I>,
    ) -> Self {
        let mut result = {
            let (_program_vm_addr, program) = executable.get_text_bytes().unwrap();
            let (syscalls, bpf_functions) = executable.get_symbols();
            Self {
                instructions: to_insn_vec(program),
                syscalls,
                bpf_functions,
                cfg_nodes: BTreeMap::new(),
                cfg_edges: BTreeMap::new(),
            }
        };
        for pc in result.bpf_functions.keys() {
            result.cfg_nodes.insert(
                *pc,
                CfgNode {
                    length: 0,
                    is_function_entry: true,
                    sources: Vec::new(),
                },
            );
        }
        let entrypoint_pc = executable.get_entrypoint_instruction_offset().unwrap();
        result.cfg_nodes.entry(entrypoint_pc).or_insert(CfgNode {
            length: 0,
            is_function_entry: true,
            sources: Vec::new(),
        });
        for insn in result.instructions.iter() {
            match insn.opc {
                ebpf::CALL_IMM => {
                    if let Some(target_pc) = executable.lookup_bpf_function(insn.imm as u32) {
                        result.cfg_edges.insert(insn.ptr, vec![*target_pc]);
                        if !result.cfg_nodes.contains_key(target_pc) {
                            result.cfg_nodes.insert(
                                *target_pc,
                                CfgNode {
                                    length: 0,
                                    is_function_entry: true,
                                    sources: Vec::new(),
                                },
                            );
                        }
                    }
                }
                ebpf::CALL_REG | ebpf::EXIT => {
                    result.cfg_edges.insert(insn.ptr, Vec::new());
                }
                _ => {}
            }
        }
        for insn in result.instructions.iter() {
            let target_pc = (insn.ptr as isize + insn.off as isize + 1) as usize;
            match insn.opc {
                ebpf::JA => {
                    result.cfg_edges.insert(insn.ptr, vec![target_pc]);
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
                        .cfg_edges
                        .insert(insn.ptr, vec![insn.ptr + 1, target_pc]);
                    result.cfg_nodes.insert(
                        insn.ptr + 1,
                        CfgNode {
                            length: 0,
                            is_function_entry: false,
                            sources: Vec::new(),
                        },
                    );
                }
                _ => continue,
            }
            result.cfg_nodes.entry(target_pc).or_insert(CfgNode {
                length: 0,
                is_function_entry: false,
                sources: Vec::new(),
            });
        }
        for (source, destinations) in &result.cfg_edges {
            for destination in destinations {
                result
                    .cfg_nodes
                    .get_mut(destination)
                    .unwrap()
                    .sources
                    .push(*source);
            }
        }
        let mut destination_iter = result.cfg_nodes.iter_mut().peekable();
        let mut source_iter = result.cfg_edges.iter().peekable();
        while let Some((begin, cfg_node)) = destination_iter.next() {
            match result
                .instructions
                .binary_search_by(|insn| insn.ptr.cmp(begin))
            {
                Ok(_) => {}
                Err(_index) => continue,
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
            cfg_node.length = end - begin;
        }
        result
    }
}
