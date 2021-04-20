//! Static Byte Code Analysis

use crate::{
    disassembler::{to_insn_vec, HlInsn},
    ebpf,
    error::UserDefinedError,
    vm::Executable,
    vm::InstructionMeter,
};
use std::collections::BTreeMap;

/// A node of the control-flow graph
#[derive(Default)]
pub struct CfgNode {
    /// Basic blocks which can jump to the start of this basic block
    pub sources: Vec<usize>,
    /// Basic blocks which the end of this basic block can jump to
    pub destinations: Vec<usize>,
    /// Range of the instructions belonging to this basic block
    pub instructions: std::ops::Range<usize>,
}

/// Result of the executable analysis
pub struct Analysis {
    /// Plain list of instructions as they occur in the executable
    pub instructions: Vec<HlInsn>,
    /// Syscalls used by the executable (available if debug symbols are not stripped)
    pub syscalls: BTreeMap<u32, String>,
    /// Functions in the executable (available if debug symbols are not stripped)
    pub functions: BTreeMap<usize, (String, usize)>,
    /// Nodes of the control-flow graph
    pub cfg_nodes: BTreeMap<usize, CfgNode>,
    /// CfgNode where the execution starts
    pub entrypoint: usize,
}

impl Analysis {
    /// Analyze an executable statically
    pub fn from_executable<E: UserDefinedError, I: InstructionMeter>(
        executable: &dyn Executable<E, I>,
    ) -> Self {
        let (_program_vm_addr, program) = executable.get_text_bytes().unwrap();
        let (syscalls, functions) = executable.get_symbols();
        let mut result = Self {
            instructions: to_insn_vec(program),
            syscalls,
            functions,
            cfg_nodes: BTreeMap::new(),
            entrypoint: executable.get_entrypoint_instruction_offset().unwrap(),
        };
        result.split_into_basic_blocks(executable, false);
        result
    }

    fn link_cfg_edges(&mut self, cfg_edges: Vec<(usize, Vec<usize>)>, both_directions: bool) {
        for (source, destinations) in cfg_edges {
            if both_directions {
                self.cfg_nodes.get_mut(&source).unwrap().destinations = destinations.clone();
            }
            for destination in &destinations {
                self.cfg_nodes
                    .get_mut(&destination)
                    .unwrap()
                    .sources
                    .push(source);
            }
        }
    }

    fn split_into_basic_blocks<E: UserDefinedError, I: InstructionMeter>(
        &mut self,
        executable: &dyn Executable<E, I>,
        flatten_call_graph: bool,
    ) {
        {
            self.functions
                .entry(self.entrypoint)
                .or_insert(("entrypoint".to_string(), 0));
            for pc in self.functions.keys() {
                self.cfg_nodes.entry(*pc).or_insert_with(CfgNode::default);
            }
        }
        let mut cfg_edges = BTreeMap::new();
        for insn in self.instructions.iter() {
            let target_pc = (insn.ptr as isize + insn.off as isize + 1) as usize;
            match insn.opc {
                ebpf::CALL_IMM => {
                    if let Some(syscall_name) = self.syscalls.get(&(insn.imm as u32)) {
                        if syscall_name == "abort" {
                            cfg_edges.insert(insn.ptr, (insn.opc, Vec::new()));
                            self.cfg_nodes
                                .entry(insn.ptr + 1)
                                .or_insert_with(CfgNode::default);
                        }
                    } else if let Some(target_pc) = executable.lookup_bpf_function(insn.imm as u32)
                    {
                        self.functions
                            .entry(*target_pc)
                            .or_insert((format!("function_{}", *target_pc), 0));
                        if flatten_call_graph {
                            cfg_edges.insert(insn.ptr, (insn.opc, vec![*target_pc]));
                            self.cfg_nodes
                                .entry(insn.ptr + 1)
                                .or_insert_with(CfgNode::default);
                        }
                        self.cfg_nodes
                            .entry(*target_pc)
                            .or_insert_with(CfgNode::default);
                    }
                }
                ebpf::CALL_REG => {
                    cfg_edges.insert(insn.ptr, (insn.opc, vec![insn.ptr + 1])); // Abnormal CFG edge
                    self.cfg_nodes
                        .entry(insn.ptr + 1)
                        .or_insert_with(CfgNode::default);
                }
                ebpf::EXIT => {
                    cfg_edges.insert(insn.ptr, (insn.opc, Vec::new()));
                    self.cfg_nodes
                        .entry(insn.ptr + 1)
                        .or_insert_with(CfgNode::default);
                }
                ebpf::JA => {
                    cfg_edges.insert(insn.ptr, (insn.opc, vec![target_pc]));
                    self.cfg_nodes
                        .entry(insn.ptr + 1)
                        .or_insert_with(CfgNode::default);
                    self.cfg_nodes
                        .entry(target_pc)
                        .or_insert_with(CfgNode::default);
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
                    cfg_edges.insert(insn.ptr, (insn.opc, vec![insn.ptr + 1, target_pc]));
                    self.cfg_nodes
                        .entry(insn.ptr + 1)
                        .or_insert_with(CfgNode::default);
                    self.cfg_nodes
                        .entry(target_pc)
                        .or_insert_with(CfgNode::default);
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
        {
            let mut instruction_index = 0;
            let mut cfg_node_iter = self.cfg_nodes.iter_mut().peekable();
            let mut cfg_edge_iter = cfg_edges.iter_mut().peekable();
            while let Some((cfg_node_start, cfg_node)) = cfg_node_iter.next() {
                let cfg_node_end = if let Some(next_cfg_node) = cfg_node_iter.peek() {
                    *next_cfg_node.0 - 1
                } else {
                    self.instructions.last().unwrap().ptr
                };
                cfg_node.instructions.start = instruction_index;
                while instruction_index < self.instructions.len() {
                    if self.instructions[instruction_index].ptr <= cfg_node_end {
                        instruction_index += 1;
                        cfg_node.instructions.end = instruction_index;
                    } else {
                        break;
                    }
                }
                if let Some(next_cfg_edge) = cfg_edge_iter.peek() {
                    if *next_cfg_edge.0 <= cfg_node_end {
                        cfg_node.destinations = next_cfg_edge.1 .1.clone();
                        cfg_edge_iter.next();
                        continue;
                    }
                }
                if let Some(next_cfg_node) = cfg_node_iter.peek() {
                    if !self.functions.contains_key(cfg_node_start) {
                        cfg_node.destinations.push(*next_cfg_node.0);
                    }
                }
            }
        }
        self.link_cfg_edges(
            self.cfg_nodes
                .iter()
                .map(|(source, cfg_node)| (*source, cfg_node.destinations.clone()))
                .collect::<Vec<(usize, Vec<usize>)>>(),
            false,
        );
        if flatten_call_graph {
            let mut destinations = Vec::new();
            let mut cfg_edges = Vec::new();
            for (source, cfg_node) in self.cfg_nodes.iter() {
                if self.functions.contains_key(source) {
                    destinations = cfg_node
                        .sources
                        .iter()
                        .map(|destination| {
                            self.instructions
                                [self.cfg_nodes.get(destination).unwrap().instructions.end]
                                .ptr
                        })
                        .collect();
                }
                if cfg_node.destinations.is_empty()
                    && self.instructions[cfg_node.instructions.end - 1].opc == ebpf::EXIT
                {
                    cfg_edges.push((*source, destinations.clone()));
                }
            }
            self.link_cfg_edges(cfg_edges, true);
        }
    }
}
