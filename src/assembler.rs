#![allow(clippy::integer_arithmetic)]
// Copyright 2017 Rich Lane <lanerl@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! This module translates eBPF assembly language to binary.

use self::InstructionType::{
    AluBinary, AluUnary, CallImm, CallReg, Endian, JumpConditional, JumpUnconditional, LoadAbs,
    LoadImm, LoadInd, LoadReg, NoOperand, StoreImm, StoreReg, Syscall,
};
use crate::{
    asm_parser::{
        parse,
        Operand::{Integer, Label, Memory, Register},
        Statement,
    },
    ebpf::{self, Insn},
    elf::{register_bpf_function, Executable},
    error::UserDefinedError,
    vm::{Config, InstructionMeter, SyscallRegistry},
};
use std::collections::{BTreeMap, HashMap};

#[derive(Clone, Copy, Debug, PartialEq)]
enum InstructionType {
    AluBinary,
    AluUnary,
    LoadImm,
    LoadAbs,
    LoadInd,
    LoadReg,
    StoreImm,
    StoreReg,
    JumpUnconditional,
    JumpConditional,
    Syscall,
    CallImm,
    CallReg,
    Endian(i64),
    NoOperand,
}

fn make_instruction_map() -> HashMap<String, (InstructionType, u8)> {
    let mut result = HashMap::new();

    let alu_binary_ops = [
        ("add", ebpf::BPF_ADD),
        ("sub", ebpf::BPF_SUB),
        ("mul", ebpf::BPF_MUL),
        ("div", ebpf::BPF_DIV),
        ("or", ebpf::BPF_OR),
        ("and", ebpf::BPF_AND),
        ("lsh", ebpf::BPF_LSH),
        ("rsh", ebpf::BPF_RSH),
        ("mod", ebpf::BPF_MOD),
        ("xor", ebpf::BPF_XOR),
        ("mov", ebpf::BPF_MOV),
        ("arsh", ebpf::BPF_ARSH),
    ];

    let mem_sizes = [
        ("w", ebpf::BPF_W),
        ("h", ebpf::BPF_H),
        ("b", ebpf::BPF_B),
        ("dw", ebpf::BPF_DW),
    ];

    let jump_conditions = [
        ("jeq", ebpf::BPF_JEQ),
        ("jgt", ebpf::BPF_JGT),
        ("jge", ebpf::BPF_JGE),
        ("jlt", ebpf::BPF_JLT),
        ("jle", ebpf::BPF_JLE),
        ("jset", ebpf::BPF_JSET),
        ("jne", ebpf::BPF_JNE),
        ("jsgt", ebpf::BPF_JSGT),
        ("jsge", ebpf::BPF_JSGE),
        ("jslt", ebpf::BPF_JSLT),
        ("jsle", ebpf::BPF_JSLE),
    ];

    {
        let mut entry = |name: &str, inst_type: InstructionType, opc: u8| {
            result.insert(name.to_string(), (inst_type, opc))
        };

        // Miscellaneous.
        entry("exit", NoOperand, ebpf::EXIT);
        entry("ja", JumpUnconditional, ebpf::JA);
        entry("syscall", Syscall, ebpf::CALL_IMM);
        entry("call", CallImm, ebpf::CALL_IMM);
        entry("callx", CallReg, ebpf::CALL_REG);
        entry("lddw", LoadImm, ebpf::LD_DW_IMM);

        // AluUnary.
        entry("neg", AluUnary, ebpf::NEG64);
        entry("neg32", AluUnary, ebpf::NEG32);
        entry("neg64", AluUnary, ebpf::NEG64);

        // AluBinary.
        for &(name, opc) in &alu_binary_ops {
            entry(name, AluBinary, ebpf::BPF_ALU64 | opc);
            entry(&format!("{}32", name), AluBinary, ebpf::BPF_ALU | opc);
            entry(&format!("{}64", name), AluBinary, ebpf::BPF_ALU64 | opc);
        }

        entry("sdiv", AluBinary, ebpf::BPF_ALU64 | ebpf::BPF_SDIV);
        entry("sdiv64", AluBinary, ebpf::BPF_ALU64 | ebpf::BPF_SDIV);
        entry("sdiv32", AluBinary, ebpf::BPF_ALU | ebpf::BPF_SDIV);

        // LoadAbs, LoadInd, LoadReg, StoreImm, and StoreReg.
        for &(suffix, size) in &mem_sizes {
            entry(
                &format!("ldabs{}", suffix),
                LoadAbs,
                ebpf::BPF_ABS | ebpf::BPF_LD | size,
            );
            entry(
                &format!("ldind{}", suffix),
                LoadInd,
                ebpf::BPF_IND | ebpf::BPF_LD | size,
            );
            entry(
                &format!("ldx{}", suffix),
                LoadReg,
                ebpf::BPF_MEM | ebpf::BPF_LDX | size,
            );
            entry(
                &format!("st{}", suffix),
                StoreImm,
                ebpf::BPF_MEM | ebpf::BPF_ST | size,
            );
            entry(
                &format!("stx{}", suffix),
                StoreReg,
                ebpf::BPF_MEM | ebpf::BPF_STX | size,
            );
        }

        // JumpConditional.
        for &(name, condition) in &jump_conditions {
            entry(name, JumpConditional, ebpf::BPF_JMP | condition);
        }

        // Endian.
        for &size in &[16, 32, 64] {
            entry(&format!("be{}", size), Endian(size), ebpf::BE);
            entry(&format!("le{}", size), Endian(size), ebpf::LE);
        }
    }

    result
}

fn insn(opc: u8, dst: i64, src: i64, off: i64, imm: i64) -> Result<Insn, String> {
    if !(0..16).contains(&dst) {
        return Err(format!("Invalid destination register {}", dst));
    }
    if dst < 0 || src >= 16 {
        return Err(format!("Invalid source register {}", src));
    }
    if off < i16::MIN as i64 || off > i16::MAX as i64 {
        return Err(format!("Invalid offset {}", off));
    }
    if imm < i32::MIN as i64 || imm > i32::MAX as i64 {
        return Err(format!("Invalid immediate {}", imm));
    }
    Ok(Insn {
        ptr: 0,
        opc,
        dst: dst as u8,
        src: src as u8,
        off: off as i16,
        imm,
    })
}

/// Parse assembly source and translate to binary.
///
/// # Examples
///
/// ```
/// use solana_rbpf::{assembler::assemble, user_error::UserError, vm::{Config, TestInstructionMeter, SyscallRegistry}};
/// let executable = assemble::<UserError, TestInstructionMeter>(
///    "add64 r1, 0x605
///     mov64 r2, 0x32
///     mov64 r1, r0
///     be16 r0
///     neg64 r2
///     exit",
///     Config::default(),
///     SyscallRegistry::default(),
/// ).unwrap();
/// let program = executable.get_text_bytes().1;
/// println!("{:?}", program);
/// # assert_eq!(program,
/// #            &[0x07, 0x01, 0x00, 0x00, 0x05, 0x06, 0x00, 0x00,
/// #              0xb7, 0x02, 0x00, 0x00, 0x32, 0x00, 0x00, 0x00,
/// #              0xbf, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/// #              0xdc, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
/// #              0x87, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/// #              0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
/// ```
///
/// This will produce the following output:
///
/// ```test
/// [0x07, 0x01, 0x00, 0x00, 0x05, 0x06, 0x00, 0x00,
///  0xb7, 0x02, 0x00, 0x00, 0x32, 0x00, 0x00, 0x00,
///  0xbf, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///  0xdc, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
///  0x87, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///  0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
/// ```
pub fn assemble<E: UserDefinedError, I: 'static + InstructionMeter>(
    src: &str,
    config: Config,
    syscall_registry: SyscallRegistry,
) -> Result<Executable<E, I>, String> {
    fn resolve_label(
        insn_ptr: usize,
        labels: &HashMap<&str, usize>,
        label: &str,
    ) -> Result<i64, String> {
        labels
            .get(label)
            .map(|target_pc| *target_pc as i64 - insn_ptr as i64 - 1)
            .ok_or_else(|| format!("Label not found {}", label))
    }

    fn resolve_call(
        config: &Config,
        bpf_functions: &mut BTreeMap<u32, (usize, String)>,
        syscall_registry: &SyscallRegistry,
        labels: &HashMap<&str, usize>,
        label: &str,
        target_pc: Option<usize>,
    ) -> Result<i64, String> {
        let target_pc = if let Some(target_pc) = target_pc {
            target_pc
        } else {
            *labels
                .get(label)
                .ok_or_else(|| format!("Label not found {}", label))?
        };
        let hash = register_bpf_function(config, bpf_functions, syscall_registry, target_pc, label)
            .map_err(|_| format!("Label hash collision {}", label))?;
        Ok(hash as i32 as i64)
    }

    let statements = parse(src)?;
    let instruction_map = make_instruction_map();
    let mut insn_ptr = 0;
    let mut labels = HashMap::new();
    labels.insert("entrypoint", 0);
    for statement in statements.iter() {
        match statement {
            Statement::Label { name } => {
                labels.insert(name.as_str(), insn_ptr);
            }
            Statement::Instruction { name, .. } => {
                insn_ptr += if name == "lddw" { 2 } else { 1 };
            }
        }
    }
    insn_ptr = 0;
    let mut bpf_functions = BTreeMap::new();
    resolve_call(
        &config,
        &mut bpf_functions,
        &syscall_registry,
        &labels,
        "entrypoint",
        None,
    )?;
    let mut instructions: Vec<Insn> = Vec::new();
    for statement in statements.iter() {
        if let Statement::Instruction { name, operands } = statement {
            let name = name.as_str();
            match instruction_map.get(name) {
                Some(&(inst_type, opc)) => {
                    let mut insn = match (inst_type, operands.as_slice()) {
                        (AluBinary, [Register(dst), Register(src)]) => {
                            insn(opc | ebpf::BPF_X, *dst, *src, 0, 0)
                        }
                        (AluBinary, [Register(dst), Integer(imm)]) => {
                            insn(opc | ebpf::BPF_K, *dst, 0, 0, *imm)
                        }
                        (AluUnary, [Register(dst)]) => insn(opc, *dst, 0, 0, 0),
                        (LoadAbs, [Integer(imm)]) => insn(opc, 0, 0, 0, *imm),
                        (LoadInd, [Register(src), Integer(imm)]) => insn(opc, 0, *src, 0, *imm),
                        (LoadReg, [Register(dst), Memory(src, off)])
                        | (StoreReg, [Memory(dst, off), Register(src)]) => {
                            insn(opc, *dst, *src, *off, 0)
                        }
                        (StoreImm, [Memory(dst, off), Integer(imm)]) => {
                            insn(opc, *dst, 0, *off, *imm)
                        }
                        (NoOperand, []) => insn(opc, 0, 0, 0, 0),
                        (JumpUnconditional, [Integer(off)]) => insn(opc, 0, 0, *off, 0),
                        (JumpConditional, [Register(dst), Register(src), Integer(off)]) => {
                            insn(opc | ebpf::BPF_X, *dst, *src, *off, 0)
                        }
                        (JumpConditional, [Register(dst), Integer(imm), Integer(off)]) => {
                            insn(opc | ebpf::BPF_K, *dst, 0, *off, *imm)
                        }
                        (JumpUnconditional, [Label(label)]) => {
                            insn(opc, 0, 0, resolve_label(insn_ptr, &labels, label)?, 0)
                        }
                        (CallImm, [Integer(imm)]) => {
                            let target_pc = (*imm + insn_ptr as i64 + 1) as usize;
                            let label = format!("function_{}", target_pc);
                            let hash = resolve_call(
                                &config,
                                &mut bpf_functions,
                                &syscall_registry,
                                &labels,
                                &label,
                                Some(target_pc),
                            )?;
                            insn(opc, 0, 1, 0, hash as i32 as i64)
                        }
                        (CallReg, [Register(dst)]) => insn(opc, 0, 0, 0, *dst),
                        (JumpConditional, [Register(dst), Register(src), Label(label)]) => insn(
                            opc | ebpf::BPF_X,
                            *dst,
                            *src,
                            resolve_label(insn_ptr, &labels, label)?,
                            0,
                        ),
                        (JumpConditional, [Register(dst), Integer(imm), Label(label)]) => insn(
                            opc | ebpf::BPF_K,
                            *dst,
                            0,
                            resolve_label(insn_ptr, &labels, label)?,
                            *imm,
                        ),
                        (Syscall, [Label(label)]) => insn(
                            opc,
                            0,
                            0,
                            0,
                            ebpf::hash_symbol_name(label.as_bytes()) as i32 as i64,
                        ),
                        (CallImm, [Label(label)]) => {
                            let hash = resolve_call(
                                &config,
                                &mut bpf_functions,
                                &syscall_registry,
                                &labels,
                                label,
                                None,
                            )?;
                            insn(opc, 0, 1, 0, hash as i32 as i64)
                        }
                        (Endian(size), [Register(dst)]) => insn(opc, *dst, 0, 0, size),
                        (LoadImm, [Register(dst), Integer(imm)]) => {
                            insn(opc, *dst, 0, 0, (*imm << 32) >> 32)
                        }
                        _ => Err(format!("Unexpected operands: {:?}", operands)),
                    }?;
                    insn.ptr = insn_ptr;
                    instructions.push(insn);
                    insn_ptr += 1;
                    if let LoadImm = inst_type {
                        if let Integer(imm) = operands[1] {
                            instructions.push(Insn {
                                ptr: insn_ptr,
                                imm: (imm >> 32) as i64,
                                ..Insn::default()
                            });
                            insn_ptr += 1;
                        }
                    }
                }
                None => return Err(format!("Invalid instruction {:?}", name)),
            }
        }
    }
    let program = instructions
        .iter()
        .flat_map(|insn| insn.to_vec())
        .collect::<Vec<_>>();
    Executable::<E, I>::from_text_bytes(&program, config, syscall_registry, bpf_functions)
        .map_err(|err| format!("Executable constructor {:?}", err))
}
