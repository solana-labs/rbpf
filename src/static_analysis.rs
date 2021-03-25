//! Static Byte Code Analysis

use crate::{
    disassembler::{to_insn_vec, HlInsn},
    ebpf,
    error::UserDefinedError,
    vm::Executable,
    vm::InstructionMeter,
};
use std::collections::{BTreeMap, HashMap};

/// A node of the control-flow graph
#[derive(Default)]
pub struct CfgNode {
    /// Is at least one of the sources a "call" instruction
    pub is_function_entry: bool,
    /// Basic blocks which can jump to the start of this basic block
    pub sources: Vec<usize>,
    /// Basic blocks which the end of this basic block can jump to
    pub destinations: Vec<usize>,
}

/// Result of the executable analysis
pub struct Analysis {
    /// Plain list of instructions as they occur in the executable
    pub instructions: Vec<HlInsn>,
    /// Syscalls of the executable (available if debug symbols are not stripped)
    pub syscalls: HashMap<u32, String>,
    /// BPF functions of the executable (available if debug symbols are not stripped)
    pub bpf_functions: HashMap<usize, (String, usize)>,
    /// Nodes of the control-flow graph
    pub cfg_nodes: BTreeMap<usize, CfgNode>,
}

impl Analysis {
    /// Analyze an executable statically
    pub fn from_executable<E: UserDefinedError, I: InstructionMeter>(
        executable: &dyn Executable<E, I>,
    ) -> Self {
        let (_program_vm_addr, program) = executable.get_text_bytes().unwrap();
        let (syscalls, bpf_functions) = executable.get_symbols();
        let mut result = Self {
            instructions: to_insn_vec(program),
            syscalls,
            bpf_functions,
            cfg_nodes: BTreeMap::new(),
        };
        result.split_into_basic_blocks(executable);
        result
    }

    fn split_into_basic_blocks<E: UserDefinedError, I: InstructionMeter>(
        &mut self,
        executable: &dyn Executable<E, I>,
    ) {
        fn insert_basic_block(
            cfg_nodes: &mut BTreeMap<usize, CfgNode>,
            pc: usize,
            is_function_entry: bool,
        ) {
            if let Some(cfg_node) = cfg_nodes.get_mut(&pc) {
                cfg_node.is_function_entry = cfg_node.is_function_entry || is_function_entry;
            } else {
                cfg_nodes.insert(
                    pc,
                    CfgNode {
                        is_function_entry,
                        ..CfgNode::default()
                    },
                );
            }
        }
        let mut cfg_edges = BTreeMap::new();
        for pc in self.bpf_functions.keys() {
            insert_basic_block(&mut self.cfg_nodes, *pc, true);
        }
        let entrypoint_pc = executable.get_entrypoint_instruction_offset().unwrap();
        insert_basic_block(&mut self.cfg_nodes, entrypoint_pc, true);
        for insn in self.instructions.iter() {
            let target_pc = (insn.ptr as isize + insn.off as isize + 1) as usize;
            match insn.opc {
                ebpf::CALL_IMM => {
                    if let Some(syscall_name) = self.syscalls.get(&(insn.imm as u32)) {
                        cfg_edges.insert(
                            insn.ptr,
                            if syscall_name == "abort" {
                                vec![]
                            } else {
                                vec![insn.ptr + 1]
                            },
                        );
                        insert_basic_block(&mut self.cfg_nodes, insn.ptr + 1, false);
                    } else if let Some(target_pc) = executable.lookup_bpf_function(insn.imm as u32)
                    {
                        cfg_edges.insert(insn.ptr, vec![*target_pc]);
                        insert_basic_block(&mut self.cfg_nodes, insn.ptr + 1, false);
                        insert_basic_block(&mut self.cfg_nodes, *target_pc, true);
                    }
                }
                ebpf::CALL_REG => {
                    cfg_edges.insert(insn.ptr, vec![]); // Abnormal CFG edge
                    insert_basic_block(&mut self.cfg_nodes, insn.ptr + 1, false);
                }
                ebpf::EXIT => {
                    cfg_edges.insert(insn.ptr, vec![]);
                    insert_basic_block(&mut self.cfg_nodes, insn.ptr + 1, false);
                }
                ebpf::JA => {
                    cfg_edges.insert(insn.ptr, vec![target_pc]);
                    insert_basic_block(&mut self.cfg_nodes, insn.ptr + 1, false);
                    insert_basic_block(&mut self.cfg_nodes, target_pc, false);
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
                    cfg_edges.insert(insn.ptr, vec![insn.ptr + 1, target_pc]);
                    insert_basic_block(&mut self.cfg_nodes, insn.ptr + 1, false);
                    insert_basic_block(&mut self.cfg_nodes, target_pc, false);
                }
                _ => {}
            }
        }
        {
            let mut cfg_nodes = BTreeMap::new();
            std::mem::swap(&mut self.cfg_nodes, &mut cfg_nodes);
            let mut cfg_nodes = cfg_nodes
                .into_iter()
                .filter(|(cfg_node_start, _cfg_node)| {
                    match self
                        .instructions
                        .binary_search_by(|insn| insn.ptr.cmp(&cfg_node_start))
                    {
                        Ok(_) => true,
                        Err(_index) => false,
                    }
                })
                .collect();
            std::mem::swap(&mut self.cfg_nodes, &mut cfg_nodes);
        }
        let mut cfg_node_iter = self.cfg_nodes.iter_mut().peekable();
        let mut cfg_edge_iter = cfg_edges.iter_mut().peekable();
        while let Some((cfg_node_start, cfg_node)) = cfg_node_iter.next() {
            while let Some(next_cfg_edge) = cfg_edge_iter.peek() {
                if *next_cfg_edge.0 < *cfg_node_start {
                    println!(
                        "WARN: Skipped edge {} before block {}",
                        *next_cfg_edge.0, *cfg_node_start
                    );
                    cfg_edge_iter.next();
                } else {
                    break;
                }
            }
            if let Some(next_cfg_edge) = cfg_edge_iter.peek() {
                let terminal_edge = if let Some(next_cfg_node) = cfg_node_iter.peek() {
                    *next_cfg_edge.0 < *next_cfg_node.0
                } else {
                    true
                };
                if terminal_edge {
                    cfg_node.destinations = next_cfg_edge.1.clone();
                    cfg_edge_iter.next();
                    continue;
                }
            }
            if let Some(next_cfg_node) = cfg_node_iter.peek() {
                if !next_cfg_node.1.is_function_entry {
                    cfg_node.destinations.push(*next_cfg_node.0);
                }
            }
        }
        let cfg_edges = self
            .cfg_nodes
            .iter()
            .map(|(source, cfg_node)| (*source, cfg_node.destinations.clone()))
            .collect::<Vec<(usize, Vec<usize>)>>();
        for (source, destinations) in cfg_edges {
            for destination in &destinations {
                self.cfg_nodes
                    .get_mut(&destination)
                    .unwrap()
                    .sources
                    .push(source);
            }
        }
    }
}
