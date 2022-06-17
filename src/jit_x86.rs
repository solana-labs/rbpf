// Derived from uBPF <https://github.com/iovisor/ubpf>
// Copyright 2015 Big Switch Networks, Inc
//      (uBPF: JIT algorithm, originally in C)
// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//      (Translation to Rust, MetaBuff addition)
// Copyright 2020 Solana Maintainers <maintainers@solana.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![allow(clippy::integer_arithmetic)]
#![allow(clippy::deprecated_cfg_attr)]
#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unreachable_code)]

use std::{
    mem,
    pin::Pin, ptr,
};
use rand::{Rng};

use crate::{
    elf::Executable,
    vm::{InstructionMeter, Tracer, SYSCALL_CONTEXT_OBJECTS_OFFSET},
    ebpf::{self, INSN_SIZE, FIRST_SCRATCH_REG, SCRATCH_REGS, FRAME_PTR_REG, MM_STACK_START, STACK_PTR_REG, Insn},
    error::{UserDefinedError, EbpfError},
    memory_region::{AccessType, MemoryMapping, MemoryRegion},
    user_error::UserError,
    x86::*,
    jit::*
};

pub struct JitCompilerX86 {
    core: JitCompilerCore
}

impl JitCompilerImpl for JitCompilerX86 {
    fn get_max_empty_machine_code_length() -> usize {
        4096
    }
    fn get_max_machine_code_per_instruction() -> usize {
        110
    }
    fn get_core(&mut self) -> &mut JitCompilerCore {
        &mut self.core
    }
    fn get_result(self) -> JitProgramSections {
        self.core.result
    }
    fn new<E: UserDefinedError>(jit: JitCompilerCore) -> Result<Self, EbpfError<E>> {
        Ok(Self {
            core: jit
        })
    }
    fn handle_insn<E: UserDefinedError, I: InstructionMeter>(jit: &mut JitCompilerCore, mut insn: Insn, executable: &Pin<Box<Executable<E, I>>>, program: &[u8]) -> Result<(), EbpfError<E>> {
        if jit.config.enable_instruction_tracing {
            emit_ins(jit, X86Instruction::load_immediate(OperandSize::S64, R11, jit.pc as i64));
            emit_ins(jit, X86Instruction::call_immediate(jit.relative_to_anchor(ANCHOR_TRACE, 5)));
            emit_ins(jit, X86Instruction::load_immediate(OperandSize::S64, R11, 0));
        }
        let dst = if insn.dst == STACK_PTR_REG as u8 { u8::MAX } else { REGISTER_MAP[insn.dst as usize] };
        let src = REGISTER_MAP[insn.src as usize];
        let target_pc = (jit.pc as isize + insn.off as isize + 1) as usize;
        match insn.opc {
            _ if insn.dst == STACK_PTR_REG as u8 && jit.config.dynamic_stack_frames => {
                let stack_ptr_access = X86IndirectAccess::Offset(slot_on_environment_stack(jit, EnvironmentStackSlotX86::BpfStackPtr));
                match insn.opc {
                    ebpf::SUB64_IMM => emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x81, 5, RBP, insn.imm, Some(stack_ptr_access))),
                    ebpf::ADD64_IMM => emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x81, 0, RBP, insn.imm, Some(stack_ptr_access))),
                    _ => {
                        #[cfg(debug_assertions)]
                        unreachable!("unexpected insn on r11")
                    }
                }
            }

            ebpf::LD_DW_IMM  => {
                Self::emit_validate_and_profile_instruction_count(jit, true, Some(jit.pc + 2));
                jit.pc += 1;
                jit.result.pc_section[jit.pc] = jit.anchors[ANCHOR_CALL_UNSUPPORTED_INSTRUCTION] as usize;
                ebpf::augment_lddw_unchecked(program, &mut insn);
                if should_sanitize_constant(jit, insn.imm) {
                    emit_sanitized_load_immediate(jit, OperandSize::S64, dst, insn.imm);
                } else {
                    emit_ins(jit, X86Instruction::load_immediate(OperandSize::S64, dst, insn.imm));
                }
            },

            // BPF_LDX class
            ebpf::LD_B_REG   => {
                emit_address_translation(jit, R11, Value::RegisterPlusConstant64(src, insn.off as i64, true), 1, AccessType::Load);
                emit_ins(jit, X86Instruction::load(OperandSize::S8, R11, dst, X86IndirectAccess::Offset(0)));
            },
            ebpf::LD_H_REG   => {
                emit_address_translation(jit, R11, Value::RegisterPlusConstant64(src, insn.off as i64, true), 2, AccessType::Load);
                emit_ins(jit, X86Instruction::load(OperandSize::S16, R11, dst, X86IndirectAccess::Offset(0)));
            },
            ebpf::LD_W_REG   => {
                emit_address_translation(jit, R11, Value::RegisterPlusConstant64(src, insn.off as i64, true), 4, AccessType::Load);
                emit_ins(jit, X86Instruction::load(OperandSize::S32, R11, dst, X86IndirectAccess::Offset(0)));
            },
            ebpf::LD_DW_REG  => {
                emit_address_translation(jit, R11, Value::RegisterPlusConstant64(src, insn.off as i64, true), 8, AccessType::Load);
                emit_ins(jit, X86Instruction::load(OperandSize::S64, R11, dst, X86IndirectAccess::Offset(0)));
            },

            // BPF_ST class
            ebpf::ST_B_IMM   => {
                emit_address_translation(jit, R11, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 1, AccessType::Store);
                emit_ins(jit, X86Instruction::store_immediate(OperandSize::S8, R11, X86IndirectAccess::Offset(0), insn.imm as i64));
            },
            ebpf::ST_H_IMM   => {
                emit_address_translation(jit, R11, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 2, AccessType::Store);
                emit_ins(jit, X86Instruction::store_immediate(OperandSize::S16, R11, X86IndirectAccess::Offset(0), insn.imm as i64));
            },
            ebpf::ST_W_IMM   => {
                emit_address_translation(jit, R11, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 4, AccessType::Store);
                emit_ins(jit, X86Instruction::store_immediate(OperandSize::S32, R11, X86IndirectAccess::Offset(0), insn.imm as i64));
            },
            ebpf::ST_DW_IMM  => {
                emit_address_translation(jit, R11, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 8, AccessType::Store);
                emit_ins(jit, X86Instruction::store_immediate(OperandSize::S64, R11, X86IndirectAccess::Offset(0), insn.imm as i64));
            },

            // BPF_STX class
            ebpf::ST_B_REG  => {
                emit_address_translation(jit, R11, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 1, AccessType::Store);
                emit_ins(jit, X86Instruction::store(OperandSize::S8, src, R11, X86IndirectAccess::Offset(0)));
            },
            ebpf::ST_H_REG  => {
                emit_address_translation(jit, R11, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 2, AccessType::Store);
                emit_ins(jit, X86Instruction::store(OperandSize::S16, src, R11, X86IndirectAccess::Offset(0)));
            },
            ebpf::ST_W_REG  => {
                emit_address_translation(jit, R11, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 4, AccessType::Store);
                emit_ins(jit, X86Instruction::store(OperandSize::S32, src, R11, X86IndirectAccess::Offset(0)));
            },
            ebpf::ST_DW_REG  => {
                emit_address_translation(jit, R11, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 8, AccessType::Store);
                emit_ins(jit, X86Instruction::store(OperandSize::S64, src, R11, X86IndirectAccess::Offset(0)));
            },

            // BPF_ALU class
            ebpf::ADD32_IMM  => {
                emit_sanitized_alu(jit, OperandSize::S32, 0x01, 0, dst, insn.imm);
                emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x63, dst, dst, 0, None)); // sign extend i32 to i64
            },
            ebpf::ADD32_REG  => {
                emit_ins(jit, X86Instruction::alu(OperandSize::S32, 0x01, src, dst, 0, None));
                emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x63, dst, dst, 0, None)); // sign extend i32 to i64
            },
            ebpf::SUB32_IMM  => {
                emit_sanitized_alu(jit, OperandSize::S32, 0x29, 5, dst, insn.imm);
                emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x63, dst, dst, 0, None)); // sign extend i32 to i64
            },
            ebpf::SUB32_REG  => {
                emit_ins(jit, X86Instruction::alu(OperandSize::S32, 0x29, src, dst, 0, None));
                emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x63, dst, dst, 0, None)); // sign extend i32 to i64
            },
            ebpf::MUL32_IMM | ebpf::DIV32_IMM | ebpf::SDIV32_IMM | ebpf::MOD32_IMM  =>
                emit_muldivmod(jit, insn.opc, dst, dst, Some(insn.imm)),
            ebpf::MUL32_REG | ebpf::DIV32_REG | ebpf::SDIV32_REG | ebpf::MOD32_REG  =>
                emit_muldivmod(jit, insn.opc, src, dst, None),
            ebpf::OR32_IMM   => emit_sanitized_alu(jit, OperandSize::S32, 0x09, 1, dst, insn.imm),
            ebpf::OR32_REG   => emit_ins(jit, X86Instruction::alu(OperandSize::S32, 0x09, src, dst, 0, None)),
            ebpf::AND32_IMM  => emit_sanitized_alu(jit, OperandSize::S32, 0x21, 4, dst, insn.imm),
            ebpf::AND32_REG  => emit_ins(jit, X86Instruction::alu(OperandSize::S32, 0x21, src, dst, 0, None)),
            ebpf::LSH32_IMM  => emit_shift(jit, OperandSize::S32, 4, R11, dst, Some(insn.imm)),
            ebpf::LSH32_REG  => emit_shift(jit, OperandSize::S32, 4, src, dst, None),
            ebpf::RSH32_IMM  => emit_shift(jit, OperandSize::S32, 5, R11, dst, Some(insn.imm)),
            ebpf::RSH32_REG  => emit_shift(jit, OperandSize::S32, 5, src, dst, None),
            ebpf::NEG32      => emit_ins(jit, X86Instruction::alu(OperandSize::S32, 0xf7, 3, dst, 0, None)),
            ebpf::XOR32_IMM  => emit_sanitized_alu(jit, OperandSize::S32, 0x31, 6, dst, insn.imm),
            ebpf::XOR32_REG  => emit_ins(jit, X86Instruction::alu(OperandSize::S32, 0x31, src, dst, 0, None)),
            ebpf::MOV32_IMM  => {
                if should_sanitize_constant(jit, insn.imm) {
                    emit_sanitized_load_immediate(jit, OperandSize::S32, dst, insn.imm);
                } else {
                    emit_ins(jit, X86Instruction::load_immediate(OperandSize::S32, dst, insn.imm));
                }
            }
            ebpf::MOV32_REG  => emit_ins(jit, X86Instruction::mov(OperandSize::S32, src, dst)),
            ebpf::ARSH32_IMM => emit_shift(jit, OperandSize::S32, 7, R11, dst, Some(insn.imm)),
            ebpf::ARSH32_REG => emit_shift(jit, OperandSize::S32, 7, src, dst, None),
            ebpf::LE         => {
                match insn.imm {
                    16 => {
                        emit_ins(jit, X86Instruction::alu(OperandSize::S32, 0x81, 4, dst, 0xffff, None)); // Mask to 16 bit
                    }
                    32 => {
                        emit_ins(jit, X86Instruction::alu(OperandSize::S32, 0x81, 4, dst, -1, None)); // Mask to 32 bit
                    }
                    64 => {}
                    _ => {
                        return Err(EbpfError::InvalidInstruction(jit.pc + ebpf::ELF_INSN_DUMP_OFFSET));
                    }
                }
            },
            ebpf::BE         => {
                match insn.imm {
                    16 => {
                        emit_ins(jit, X86Instruction::bswap(OperandSize::S16, dst));
                        emit_ins(jit, X86Instruction::alu(OperandSize::S32, 0x81, 4, dst, 0xffff, None)); // Mask to 16 bit
                    }
                    32 => emit_ins(jit, X86Instruction::bswap(OperandSize::S32, dst)),
                    64 => emit_ins(jit, X86Instruction::bswap(OperandSize::S64, dst)),
                    _ => {
                        return Err(EbpfError::InvalidInstruction(jit.pc + ebpf::ELF_INSN_DUMP_OFFSET));
                    }
                }
            },

            // BPF_ALU64 class
            ebpf::ADD64_IMM  => emit_sanitized_alu(jit, OperandSize::S64, 0x01, 0, dst, insn.imm),
            ebpf::ADD64_REG  => emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x01, src, dst, 0, None)),
            ebpf::SUB64_IMM  => emit_sanitized_alu(jit, OperandSize::S64, 0x29, 5, dst, insn.imm),
            ebpf::SUB64_REG  => emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x29, src, dst, 0, None)),
            ebpf::MUL64_IMM | ebpf::DIV64_IMM | ebpf::SDIV64_IMM | ebpf::MOD64_IMM  =>
                emit_muldivmod(jit, insn.opc, dst, dst, Some(insn.imm)),
            ebpf::MUL64_REG | ebpf::DIV64_REG | ebpf::SDIV64_REG | ebpf::MOD64_REG  =>
                emit_muldivmod(jit, insn.opc, src, dst, None),
            ebpf::OR64_IMM   => emit_sanitized_alu(jit, OperandSize::S64, 0x09, 1, dst, insn.imm),
            ebpf::OR64_REG   => emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x09, src, dst, 0, None)),
            ebpf::AND64_IMM  => emit_sanitized_alu(jit, OperandSize::S64, 0x21, 4, dst, insn.imm),
            ebpf::AND64_REG  => emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x21, src, dst, 0, None)),
            ebpf::LSH64_IMM  => emit_shift(jit, OperandSize::S64, 4, R11, dst, Some(insn.imm)),
            ebpf::LSH64_REG  => emit_shift(jit, OperandSize::S64, 4, src, dst, None),
            ebpf::RSH64_IMM  => emit_shift(jit, OperandSize::S64, 5, R11, dst, Some(insn.imm)),
            ebpf::RSH64_REG  => emit_shift(jit, OperandSize::S64, 5, src, dst, None),
            ebpf::NEG64      => emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0xf7, 3, dst, 0, None)),
            ebpf::XOR64_IMM  => emit_sanitized_alu(jit, OperandSize::S64, 0x31, 6, dst, insn.imm),
            ebpf::XOR64_REG  => emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x31, src, dst, 0, None)),
            ebpf::MOV64_IMM  => {
                if should_sanitize_constant(jit, insn.imm) {
                    emit_sanitized_load_immediate(jit, OperandSize::S64, dst, insn.imm);
                } else {
                    emit_ins(jit, X86Instruction::load_immediate(OperandSize::S64, dst, insn.imm));
                }
            }
            ebpf::MOV64_REG  => emit_ins(jit, X86Instruction::mov(OperandSize::S64, src, dst)),
            ebpf::ARSH64_IMM => emit_shift(jit, OperandSize::S64, 7, R11, dst, Some(insn.imm)),
            ebpf::ARSH64_REG => emit_shift(jit, OperandSize::S64, 7, src, dst, None),

            // BPF_JMP class
            ebpf::JA         => {
                Self::emit_validate_and_profile_instruction_count(jit, false, Some(target_pc));
                emit_ins(jit, X86Instruction::load_immediate(OperandSize::S64, R11, target_pc as i64));
                let jump_offset = jit.relative_to_target_pc(target_pc, 5, FixupType::JumpImm as u8);
                emit_ins(jit, X86Instruction::jump_immediate(jump_offset));
            },
            ebpf::JEQ_IMM    => emit_conditional_branch_imm(jit, 0x84, false, insn.imm, dst, target_pc),
            ebpf::JEQ_REG    => emit_conditional_branch_reg(jit, 0x84, false, src, dst, target_pc),
            ebpf::JGT_IMM    => emit_conditional_branch_imm(jit, 0x87, false, insn.imm, dst, target_pc),
            ebpf::JGT_REG    => emit_conditional_branch_reg(jit, 0x87, false, src, dst, target_pc),
            ebpf::JGE_IMM    => emit_conditional_branch_imm(jit, 0x83, false, insn.imm, dst, target_pc),
            ebpf::JGE_REG    => emit_conditional_branch_reg(jit, 0x83, false, src, dst, target_pc),
            ebpf::JLT_IMM    => emit_conditional_branch_imm(jit, 0x82, false, insn.imm, dst, target_pc),
            ebpf::JLT_REG    => emit_conditional_branch_reg(jit, 0x82, false, src, dst, target_pc),
            ebpf::JLE_IMM    => emit_conditional_branch_imm(jit, 0x86, false, insn.imm, dst, target_pc),
            ebpf::JLE_REG    => emit_conditional_branch_reg(jit, 0x86, false, src, dst, target_pc),
            ebpf::JSET_IMM   => emit_conditional_branch_imm(jit, 0x85, true, insn.imm, dst, target_pc),
            ebpf::JSET_REG   => emit_conditional_branch_reg(jit, 0x85, true, src, dst, target_pc),
            ebpf::JNE_IMM    => emit_conditional_branch_imm(jit, 0x85, false, insn.imm, dst, target_pc),
            ebpf::JNE_REG    => emit_conditional_branch_reg(jit, 0x85, false, src, dst, target_pc),
            ebpf::JSGT_IMM   => emit_conditional_branch_imm(jit, 0x8f, false, insn.imm, dst, target_pc),
            ebpf::JSGT_REG   => emit_conditional_branch_reg(jit, 0x8f, false, src, dst, target_pc),
            ebpf::JSGE_IMM   => emit_conditional_branch_imm(jit, 0x8d, false, insn.imm, dst, target_pc),
            ebpf::JSGE_REG   => emit_conditional_branch_reg(jit, 0x8d, false, src, dst, target_pc),
            ebpf::JSLT_IMM   => emit_conditional_branch_imm(jit, 0x8c, false, insn.imm, dst, target_pc),
            ebpf::JSLT_REG   => emit_conditional_branch_reg(jit, 0x8c, false, src, dst, target_pc),
            ebpf::JSLE_IMM   => emit_conditional_branch_imm(jit, 0x8e, false, insn.imm, dst, target_pc),
            ebpf::JSLE_REG   => emit_conditional_branch_reg(jit, 0x8e, false, src, dst, target_pc),
            ebpf::CALL_IMM   => {
                // For JIT, syscalls MUST be registered at compile time. They can be
                // updated later, but not created after compiling (we need the address of the
                // syscall function in the JIT-compiled program).

                let mut resolved = false;
                let (syscalls, calls) = if jit.config.static_syscalls {
                    (insn.src == 0, insn.src != 0)
                } else {
                    (true, true)
                };

                if syscalls {
                    if let Some(syscall) = executable.get_syscall_registry().lookup_syscall(insn.imm as u32) {
                        if jit.config.enable_instruction_meter {
                            Self::emit_validate_and_profile_instruction_count(jit, true, Some(0));
                        }
                        emit_ins(jit, X86Instruction::load_immediate(OperandSize::S64, R11, syscall.function as *const u8 as i64));
                        emit_ins(jit, X86Instruction::load(OperandSize::S64, R10, RAX, X86IndirectAccess::Offset((SYSCALL_CONTEXT_OBJECTS_OFFSET + syscall.context_object_slot) as i32 * 8 + jit.program_argument_key)));
                        emit_ins(jit, X86Instruction::call_immediate(jit.relative_to_anchor(ANCHOR_SYSCALL, 5)));
                        if jit.config.enable_instruction_meter {
                            emit_undo_profile_instruction_count(jit, 0);
                        }
                        // Throw error if the result indicates one
                        // NOTE: If we do not throw this error now, we might cause a memory leak (ie.
                        // the error and any of its fields will not be free'd)
                        emit_ins(jit, X86Instruction::cmp_immediate(OperandSize::S64, R11, 0, Some(X86IndirectAccess::Offset(0))));
                        emit_ins(jit, X86Instruction::load_immediate(OperandSize::S64, R11, jit.pc as i64));
                        emit_ins(jit, X86Instruction::conditional_jump_immediate(0x85, jit.relative_to_anchor(ANCHOR_RUST_EXCEPTION, 6)));

                        resolved = true;
                    }
                }

                if calls {
                    if let Some(target_pc) = executable.lookup_bpf_function(insn.imm as u32) {
                        emit_bpf_call(jit, Value::Constant64(target_pc as i64, false));
                        resolved = true;
                    }
                }

                if !resolved {
                    emit_ins(jit, X86Instruction::load_immediate(OperandSize::S64, R11, jit.pc as i64));
                    emit_ins(jit, X86Instruction::jump_immediate(jit.relative_to_anchor(ANCHOR_CALL_UNSUPPORTED_INSTRUCTION, 5)));
                }
            },
            ebpf::CALL_REG  => {
                emit_bpf_call(jit, Value::Register(REGISTER_MAP[insn.imm as usize]));
            },
            ebpf::EXIT      => {
                let call_depth_access = X86IndirectAccess::Offset(slot_on_environment_stack(jit, EnvironmentStackSlotX86::CallDepth));
                emit_ins(jit, X86Instruction::load(OperandSize::S64, RBP, REGISTER_MAP[FRAME_PTR_REG], call_depth_access));

                // If CallDepth == 0, we've reached the exit instruction of the entry point
                emit_ins(jit, X86Instruction::cmp_immediate(OperandSize::S32, REGISTER_MAP[FRAME_PTR_REG], 0, None));
                if jit.config.enable_instruction_meter {
                    emit_ins(jit, X86Instruction::load_immediate(OperandSize::S64, R11, jit.pc as i64));
                }
                // we're done
                emit_ins(jit, X86Instruction::conditional_jump_immediate(0x84, jit.relative_to_anchor(ANCHOR_EXIT, 6)));

                // else decrement and update CallDepth
                emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x81, 5, REGISTER_MAP[FRAME_PTR_REG], 1, None));
                emit_ins(jit, X86Instruction::store(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], RBP, call_depth_access));

                // and return
                Self::emit_validate_and_profile_instruction_count(jit, false, Some(0));
                emit_ins(jit, X86Instruction::return_near());
            },

            _               => return Err(EbpfError::UnsupportedInstruction(jit.pc + ebpf::ELF_INSN_DUMP_OFFSET)),
            }
        Ok(())
    }

    // When we call into the JIT-ed code, the code emitted here is the first thing to run.
    //
    // ARGUMENT_REGISTERS[0] - &ProgramResult<E>
    // ARGUMENT_REGISTERS[1] (alias: REGISTER_MAP[1]) - input start address
    // ARGUMENT_REGISTERS[2] - *JITProgramArgument
    // ARGUMENT_REGISTERS[3] - &InstructionMeter
    fn generate_prologue<E: UserDefinedError, I: InstructionMeter>(jit: &mut JitCompilerCore, executable: &Pin<Box<Executable<E, I>>>) {
        // Place the environment on the stack according to EnvironmentStackSlotX86

        // Save registers
        for reg in CALLEE_SAVED_REGISTERS.iter() {
            emit_ins(jit, X86Instruction::push(*reg, None));
        }

        // Initialize CallDepth to 0
        emit_ins(jit, X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], 0));
        emit_ins(jit, X86Instruction::push(REGISTER_MAP[FRAME_PTR_REG], None));

        // Initialize the BPF frame and stack pointers (BpfFramePtr and BpfStackPtr)
        if jit.config.dynamic_stack_frames {
            // The stack is fully descending from MM_STACK_START + stack_size to MM_STACK_START
            emit_ins(jit, X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], MM_STACK_START as i64 + jit.config.stack_size() as i64));
            // Push BpfFramePtr
            emit_ins(jit, X86Instruction::push(REGISTER_MAP[FRAME_PTR_REG], None));
            // Push BpfStackPtr
            emit_ins(jit, X86Instruction::push(REGISTER_MAP[FRAME_PTR_REG], None));
        } else {
            // The frames are ascending from MM_STACK_START to MM_STACK_START + stack_size. The stack within the frames is descending.
            emit_ins(jit, X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], MM_STACK_START as i64 + jit.config.stack_frame_size as i64));
            // Push BpfFramePtr
            emit_ins(jit, X86Instruction::push(REGISTER_MAP[FRAME_PTR_REG], None));
            // When using static frames BpfStackPtr is not used
            emit_ins(jit, X86Instruction::load_immediate(OperandSize::S64, RBP, 0));
            emit_ins(jit, X86Instruction::push(RBP, None));
        }

        // Save pointer to optional typed return value
        emit_ins(jit, X86Instruction::push(ARGUMENT_REGISTERS[0], None));

        // Save initial value of instruction_meter.get_remaining()
        emit_rust_call(jit, Value::Constant64(I::get_remaining as *const u8 as i64, false), &[
            Argument { index: 0, value: Value::Register(ARGUMENT_REGISTERS[3]) },
        ], Some(ARGUMENT_REGISTERS[0]), false);
        emit_ins(jit, X86Instruction::push(ARGUMENT_REGISTERS[0], None));

        // Save instruction meter
        emit_ins(jit, X86Instruction::push(ARGUMENT_REGISTERS[3], None));

        // Initialize stop watch
        emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x31, R11, R11, 0, None)); // R11 ^= R11;
        emit_ins(jit, X86Instruction::push(R11, None));
        emit_ins(jit, X86Instruction::push(R11, None));

        // Initialize frame pointer
        emit_ins(jit, X86Instruction::mov(OperandSize::S64, RSP, RBP));
        emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x81, 0, RBP, 8 * (EnvironmentStackSlotX86::SlotCount as i64 - 1 + jit.environment_stack_key as i64), None));

        // Save JitProgramArgument
        emit_ins(jit, X86Instruction::lea(OperandSize::S64, ARGUMENT_REGISTERS[2], R10, Some(X86IndirectAccess::Offset(-jit.program_argument_key))));

        // Zero BPF registers
        for reg in REGISTER_MAP.iter() {
            if *reg != REGISTER_MAP[1] && *reg != REGISTER_MAP[FRAME_PTR_REG] {
                emit_ins(jit, X86Instruction::load_immediate(OperandSize::S64, *reg, 0));
            }
        }

        // Jump to entry point
        let entry = executable.get_entrypoint_instruction_offset().unwrap_or(0);
        if jit.config.enable_instruction_meter {
            Self::emit_profile_instruction_count(jit, Some(entry + 1));
        }
        emit_ins(jit, X86Instruction::load_immediate(OperandSize::S64, R11, entry as i64));
        let jump_offset = jit.relative_to_target_pc(entry, 5, FixupType::JumpImm as u8);
        emit_ins(jit, X86Instruction::jump_immediate(jump_offset));
    }

    fn emit_overrun<E: UserDefinedError>(jit: &mut JitCompilerCore) {
        Self::emit_validate_and_profile_instruction_count(jit, true, Some(jit.pc + 2));
        emit_ins(jit, X86Instruction::load_immediate(OperandSize::S64, R11, jit.pc as i64));
        emit_set_exception_kind::<E>(jit, EbpfError::ExecutionOverrun(0));
        emit_ins(jit, X86Instruction::jump_immediate(jit.relative_to_anchor(ANCHOR_EXCEPTION_AT, 5)));
    }

    fn generate_subroutines<E: UserDefinedError, I: InstructionMeter>(jit: &mut JitCompilerCore) {
        // Epilogue
        jit.set_anchor(ANCHOR_EPILOGUE);
        // Print stop watch value
        fn stopwatch_result(numerator: u64, denominator: u64) {
            println!("Stop watch: {} / {} = {}", numerator, denominator, if denominator == 0 { 0.0 } else { numerator as f64 / denominator as f64 });
        }
        if jit.stopwatch_is_active {
            emit_rust_call(jit, Value::Constant64(stopwatch_result as *const u8 as i64, false), &[
                Argument { index: 1, value: Value::RegisterIndirect(RBP, slot_on_environment_stack(jit, EnvironmentStackSlotX86::StopwatchDenominator), false) },
                Argument { index: 0, value: Value::RegisterIndirect(RBP, slot_on_environment_stack(jit, EnvironmentStackSlotX86::StopwatchNumerator), false) },
            ], None, false);
        }
        // Store instruction_meter in RAX
        emit_ins(jit, X86Instruction::mov(OperandSize::S64, ARGUMENT_REGISTERS[0], RAX));
        // Restore stack pointer in case the BPF stack was used
        emit_ins(jit, X86Instruction::lea(OperandSize::S64, RBP, RSP, Some(X86IndirectAccess::Offset(slot_on_environment_stack(jit, EnvironmentStackSlotX86::LastSavedRegister)))));
        // Restore registers
        for reg in CALLEE_SAVED_REGISTERS.iter().rev() {
            emit_ins(jit, X86Instruction::pop(*reg));
        }
        emit_ins(jit, X86Instruction::return_near());

        // Routine for instruction tracing
        if jit.config.enable_instruction_tracing {
            jit.set_anchor(ANCHOR_TRACE);
            // Save registers on stack
            emit_ins(jit, X86Instruction::push(R11, None));
            for reg in REGISTER_MAP.iter().rev() {
                emit_ins(jit, X86Instruction::push(*reg, None));
            }
            emit_ins(jit, X86Instruction::mov(OperandSize::S64, RSP, REGISTER_MAP[0]));
            emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x81, 0, RSP, - 8 * 3, None)); // RSP -= 8 * 3;
            emit_rust_call(jit, Value::Constant64(Tracer::trace as *const u8 as i64, false), &[
                Argument { index: 1, value: Value::Register(REGISTER_MAP[0]) }, // registers
                Argument { index: 0, value: Value::RegisterIndirect(R10, mem::size_of::<MemoryMapping>() as i32 + jit.program_argument_key, false) }, // jit.tracer
            ], None, false);
            // Pop stack and return
            emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x81, 0, RSP, 8 * 3, None)); // RSP += 8 * 3;
            emit_ins(jit, X86Instruction::pop(REGISTER_MAP[0]));
            emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x81, 0, RSP, 8 * (REGISTER_MAP.len() - 1) as i64, None)); // RSP += 8 * (REGISTER_MAP.len() - 1);
            emit_ins(jit, X86Instruction::pop(R11));
            emit_ins(jit, X86Instruction::return_near());
        }

        // Handler for syscall exceptions
        jit.set_anchor(ANCHOR_RUST_EXCEPTION);
        emit_profile_instruction_count_finalize(jit, false);
        emit_ins(jit, X86Instruction::jump_immediate(jit.relative_to_anchor(ANCHOR_EPILOGUE, 5)));

        // Handler for EbpfError::ExceededMaxInstructions
        jit.set_anchor(ANCHOR_CALL_EXCEEDED_MAX_INSTRUCTIONS);
        emit_set_exception_kind::<E>(jit, EbpfError::ExceededMaxInstructions(0, 0));
        emit_ins(jit, X86Instruction::mov(OperandSize::S64, ARGUMENT_REGISTERS[0], R11)); // R11 = instruction_meter;
        emit_profile_instruction_count_finalize(jit, true);
        emit_ins(jit, X86Instruction::jump_immediate(jit.relative_to_anchor(ANCHOR_EPILOGUE, 5)));

        // Handler for exceptions which report their pc
        jit.set_anchor(ANCHOR_EXCEPTION_AT);
        // Validate that we did not reach the instruction meter limit before the exception occured
        if jit.config.enable_instruction_meter {
            Self::emit_validate_instruction_count(jit, false, None);
        }
        emit_profile_instruction_count_finalize(jit, true);
        emit_ins(jit, X86Instruction::jump_immediate(jit.relative_to_anchor(ANCHOR_EPILOGUE, 5)));

        // Handler for EbpfError::CallDepthExceeded
        jit.set_anchor(ANCHOR_CALL_DEPTH_EXCEEDED);
        emit_set_exception_kind::<E>(jit, EbpfError::CallDepthExceeded(0, 0));
        emit_ins(jit, X86Instruction::store_immediate(OperandSize::S64, R10, X86IndirectAccess::Offset(24), jit.config.max_call_depth as i64)); // depth = jit.config.max_call_depth;
        emit_ins(jit, X86Instruction::jump_immediate(jit.relative_to_anchor(ANCHOR_EXCEPTION_AT, 5)));

        // Handler for EbpfError::CallOutsideTextSegment
        jit.set_anchor(ANCHOR_CALL_OUTSIDE_TEXT_SEGMENT);
        emit_set_exception_kind::<E>(jit, EbpfError::CallOutsideTextSegment(0, 0));
        emit_ins(jit, X86Instruction::store(OperandSize::S64, REGISTER_MAP[0], R10, X86IndirectAccess::Offset(24))); // target_address = RAX;
        emit_ins(jit, X86Instruction::jump_immediate(jit.relative_to_anchor(ANCHOR_EXCEPTION_AT, 5)));

        // Handler for EbpfError::DivideByZero
        jit.set_anchor(ANCHOR_DIV_BY_ZERO);
        emit_set_exception_kind::<E>(jit, EbpfError::DivideByZero(0));
        emit_ins(jit, X86Instruction::jump_immediate(jit.relative_to_anchor(ANCHOR_EXCEPTION_AT, 5)));

        // Handler for EbpfError::DivideOverflow
        jit.set_anchor(ANCHOR_DIV_OVERFLOW);
        emit_set_exception_kind::<E>(jit, EbpfError::DivideOverflow(0));
        emit_ins(jit, X86Instruction::jump_immediate(jit.relative_to_anchor(ANCHOR_EXCEPTION_AT, 5)));

        // Handler for EbpfError::UnsupportedInstruction
        jit.set_anchor(ANCHOR_CALLX_UNSUPPORTED_INSTRUCTION);
        // Load BPF target pc from stack (which was saved in ANCHOR_BPF_CALL_REG)
        emit_ins(jit, X86Instruction::load(OperandSize::S64, RSP, R11, X86IndirectAccess::OffsetIndexShift(-16, RSP, 0))); // R11 = RSP[-16];
        // emit_ins(jit, X86Instruction::jump_immediate(jit.relative_to_anchor(ANCHOR_CALL_UNSUPPORTED_INSTRUCTION, 5))); // Fall-through

        // Handler for EbpfError::UnsupportedInstruction
        jit.set_anchor(ANCHOR_CALL_UNSUPPORTED_INSTRUCTION);
        if jit.config.enable_instruction_tracing {
            emit_ins(jit, X86Instruction::call_immediate(jit.relative_to_anchor(ANCHOR_TRACE, 5)));
        }
        emit_set_exception_kind::<E>(jit, EbpfError::UnsupportedInstruction(0));
        emit_ins(jit, X86Instruction::jump_immediate(jit.relative_to_anchor(ANCHOR_EXCEPTION_AT, 5)));

        // Quit gracefully
        jit.set_anchor(ANCHOR_EXIT);
        Self::emit_validate_instruction_count(jit, false, None);
        emit_profile_instruction_count_finalize(jit, false);
        emit_ins(jit, X86Instruction::load(OperandSize::S64, RBP, R10, X86IndirectAccess::Offset(slot_on_environment_stack(jit, EnvironmentStackSlotX86::OptRetValPtr))));
        emit_ins(jit, X86Instruction::store(OperandSize::S64, REGISTER_MAP[0], R10, X86IndirectAccess::Offset(8))); // result.return_value = R0;
        emit_ins(jit, X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[0], 0));
        emit_ins(jit, X86Instruction::store(OperandSize::S64, REGISTER_MAP[0], R10, X86IndirectAccess::Offset(0)));  // result.is_error = false;
        emit_ins(jit, X86Instruction::jump_immediate(jit.relative_to_anchor(ANCHOR_EPILOGUE, 5)));

        // Routine for syscall
        jit.set_anchor(ANCHOR_SYSCALL);
        emit_ins(jit, X86Instruction::push(R11, None)); // Padding for stack alignment
        if jit.config.enable_instruction_meter {
            // RDI = *PrevInsnMeter - RDI;
            emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x2B, ARGUMENT_REGISTERS[0], RBP, 0, Some(X86IndirectAccess::Offset(slot_on_environment_stack(jit, EnvironmentStackSlotX86::PrevInsnMeter))))); // RDI -= *PrevInsnMeter;
            emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0xf7, 3, ARGUMENT_REGISTERS[0], 0, None)); // RDI = -RDI;
            emit_rust_call(jit, Value::Constant64(I::consume as *const u8 as i64, false), &[
                Argument { index: 1, value: Value::Register(ARGUMENT_REGISTERS[0]) },
                Argument { index: 0, value: Value::RegisterIndirect(RBP, slot_on_environment_stack(jit, EnvironmentStackSlotX86::InsnMeterPtr), false) },
            ], None, false);
        }
        emit_rust_call(jit, Value::Register(R11), &[
            Argument { index: 7, value: Value::RegisterIndirect(RBP, slot_on_environment_stack(jit, EnvironmentStackSlotX86::OptRetValPtr), false) },
            Argument { index: 6, value: Value::RegisterPlusConstant32(R10, jit.program_argument_key, false) }, // jit_program_argument.memory_mapping
            Argument { index: 5, value: Value::Register(ARGUMENT_REGISTERS[5]) },
            Argument { index: 4, value: Value::Register(ARGUMENT_REGISTERS[4]) },
            Argument { index: 3, value: Value::Register(ARGUMENT_REGISTERS[3]) },
            Argument { index: 2, value: Value::Register(ARGUMENT_REGISTERS[2]) },
            Argument { index: 1, value: Value::Register(ARGUMENT_REGISTERS[1]) },
            Argument { index: 0, value: Value::Register(RAX) }, // "&mut jit" in the "call" method of the SyscallObject
        ], None, false);
        if jit.config.enable_instruction_meter {
            emit_rust_call(jit, Value::Constant64(I::get_remaining as *const u8 as i64, false), &[
                Argument { index: 0, value: Value::RegisterIndirect(RBP, slot_on_environment_stack(jit, EnvironmentStackSlotX86::InsnMeterPtr), false) },
            ], Some(ARGUMENT_REGISTERS[0]), false);
            emit_ins(jit, X86Instruction::store(OperandSize::S64, ARGUMENT_REGISTERS[0], RBP, X86IndirectAccess::Offset(slot_on_environment_stack(jit, EnvironmentStackSlotX86::PrevInsnMeter))));
        }
        emit_ins(jit, X86Instruction::pop(R11));
        // Store Ok value in result register
        emit_ins(jit, X86Instruction::load(OperandSize::S64, RBP, R11, X86IndirectAccess::Offset(slot_on_environment_stack(jit, EnvironmentStackSlotX86::OptRetValPtr))));
        emit_ins(jit, X86Instruction::load(OperandSize::S64, R11, REGISTER_MAP[0], X86IndirectAccess::Offset(8)));
        emit_ins(jit, X86Instruction::return_near());

        // Routine for prologue of emit_bpf_call()
        jit.set_anchor(ANCHOR_BPF_CALL_PROLOGUE);
        emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x81, 5, RSP, 8 * (SCRATCH_REGS + 1) as i64, None)); // alloca
        emit_ins(jit, X86Instruction::store(OperandSize::S64, R11, RSP, X86IndirectAccess::OffsetIndexShift(0, RSP, 0))); // Save original R11
        emit_ins(jit, X86Instruction::load(OperandSize::S64, RSP, R11, X86IndirectAccess::OffsetIndexShift(8 * (SCRATCH_REGS + 1) as i32, RSP, 0))); // Load return address
        for (i, reg) in REGISTER_MAP.iter().skip(FIRST_SCRATCH_REG).take(SCRATCH_REGS).enumerate() {
            emit_ins(jit, X86Instruction::store(OperandSize::S64, *reg, RSP, X86IndirectAccess::OffsetIndexShift(8 * (SCRATCH_REGS - i + 1) as i32, RSP, 0))); // Push SCRATCH_REG
        }
        // Push the caller's frame pointer. The code to restore it is emitted at the end of emit_bpf_call().
        emit_ins(jit, X86Instruction::store(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], RSP, X86IndirectAccess::OffsetIndexShift(8, RSP, 0)));
        emit_ins(jit, X86Instruction::xchg(OperandSize::S64, R11, RSP, Some(X86IndirectAccess::OffsetIndexShift(0, RSP, 0)))); // Push return address and restore original R11

        // Increase CallDepth
        let call_depth_access = X86IndirectAccess::Offset(slot_on_environment_stack(jit, EnvironmentStackSlotX86::CallDepth));
        emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x81, 0, RBP, 1, Some(call_depth_access)));
        emit_ins(jit, X86Instruction::load(OperandSize::S64, RBP, REGISTER_MAP[FRAME_PTR_REG], call_depth_access));
        // If CallDepth == jit.config.max_call_depth, stop and return CallDepthExceeded
        emit_ins(jit, X86Instruction::cmp_immediate(OperandSize::S32, REGISTER_MAP[FRAME_PTR_REG], jit.config.max_call_depth as i64, None));
        emit_ins(jit, X86Instruction::conditional_jump_immediate(0x83, jit.relative_to_anchor(ANCHOR_CALL_DEPTH_EXCEEDED, 6)));

        // Setup the frame pointer for the new frame. What we do depends on whether we're using dynamic or fixed frames.
        let frame_ptr_access = X86IndirectAccess::Offset(slot_on_environment_stack(jit, EnvironmentStackSlotX86::BpfFramePtr));
        if jit.config.dynamic_stack_frames {
            // When dynamic frames are on, the next frame starts at the end of the current frame
            let stack_ptr_access = X86IndirectAccess::Offset(slot_on_environment_stack(jit, EnvironmentStackSlotX86::BpfStackPtr));
            emit_ins(jit, X86Instruction::load(OperandSize::S64, RBP, REGISTER_MAP[FRAME_PTR_REG], stack_ptr_access));
            emit_ins(jit, X86Instruction::store(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], RBP, frame_ptr_access));
        } else {
            // With fixed frames we start the new frame at the next fixed offset
            let stack_frame_size = jit.config.stack_frame_size as i64 * if jit.config.enable_stack_frame_gaps { 2 } else { 1 };
            emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x81, 0, RBP, stack_frame_size, Some(frame_ptr_access))); // frame_ptr += stack_frame_size;
            emit_ins(jit, X86Instruction::load(OperandSize::S64, RBP, REGISTER_MAP[FRAME_PTR_REG], frame_ptr_access)); // Load BpfFramePtr
        }
        emit_ins(jit, X86Instruction::return_near());

        // Routine for emit_bpf_call(Value::Register())
        jit.set_anchor(ANCHOR_BPF_CALL_REG);
        // Force alignment of RAX
        emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x81, 4, REGISTER_MAP[0], !(INSN_SIZE as i64 - 1), None)); // RAX &= !(INSN_SIZE - 1);
        // Upper bound check
        // if(RAX >= jit.program_vm_addr + number_of_instructions * INSN_SIZE) throw CALL_OUTSIDE_TEXT_SEGMENT;
        let number_of_instructions = jit.result.pc_section.len() - 1;
        emit_ins(jit, X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], jit.program_vm_addr as i64 + (number_of_instructions * INSN_SIZE) as i64));
        emit_ins(jit, X86Instruction::cmp(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], REGISTER_MAP[0], None));
        emit_ins(jit, X86Instruction::conditional_jump_immediate(0x83, jit.relative_to_anchor(ANCHOR_CALL_OUTSIDE_TEXT_SEGMENT, 6)));
        // Lower bound check
        // if(RAX < jit.program_vm_addr) throw CALL_OUTSIDE_TEXT_SEGMENT;
        emit_ins(jit, X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], jit.program_vm_addr as i64));
        emit_ins(jit, X86Instruction::cmp(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], REGISTER_MAP[0], None));
        emit_ins(jit, X86Instruction::conditional_jump_immediate(0x82, jit.relative_to_anchor(ANCHOR_CALL_OUTSIDE_TEXT_SEGMENT, 6)));
        // Calculate offset relative to instruction_addresses
        emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x29, REGISTER_MAP[FRAME_PTR_REG], REGISTER_MAP[0], 0, None)); // RAX -= jit.program_vm_addr;
        // Calculate the target_pc (dst / INSN_SIZE) to update the instruction_meter
        let shift_amount = INSN_SIZE.trailing_zeros();
        debug_assert_eq!(INSN_SIZE, 1 << shift_amount);
        emit_ins(jit, X86Instruction::mov(OperandSize::S64, REGISTER_MAP[0], R11));
        emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0xc1, 5, R11, shift_amount as i64, None));
        // Save BPF target pc for potential ANCHOR_CALLX_UNSUPPORTED_INSTRUCTION
        emit_ins(jit, X86Instruction::store(OperandSize::S64, R11, RSP, X86IndirectAccess::OffsetIndexShift(-8, RSP, 0))); // RSP[-8] = R11;
        // Load host target_address from jit.result.pc_section
        debug_assert_eq!(INSN_SIZE, 8); // Because the instruction size is also the slot size we do not need to shift the offset
        emit_ins(jit, X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], jit.result.pc_section.as_ptr() as i64));
        emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x01, REGISTER_MAP[FRAME_PTR_REG], REGISTER_MAP[0], 0, None)); // RAX += jit.result.pc_section;
        emit_ins(jit, X86Instruction::load(OperandSize::S64, REGISTER_MAP[0], REGISTER_MAP[0], X86IndirectAccess::Offset(0))); // RAX = jit.result.pc_section[RAX / 8];
        // Load the frame pointer again since we've clobbered REGISTER_MAP[FRAME_PTR_REG]
        emit_ins(jit, X86Instruction::load(OperandSize::S64, RBP, REGISTER_MAP[FRAME_PTR_REG], X86IndirectAccess::Offset(slot_on_environment_stack(jit, EnvironmentStackSlotX86::BpfFramePtr))));
        emit_ins(jit, X86Instruction::return_near());

        // Translates a host pc back to a BPF pc by linear search of the pc_section table
        jit.set_anchor(ANCHOR_TRANSLATE_PC);
        emit_ins(jit, X86Instruction::push(REGISTER_MAP[0], None)); // Save REGISTER_MAP[0]
        emit_ins(jit, X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[0], jit.result.pc_section.as_ptr() as i64 - 8)); // Loop index and pointer to look up
        jit.set_anchor(ANCHOR_TRANSLATE_PC_LOOP); // Loop label
        emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x81, 0, REGISTER_MAP[0], 8, None)); // Increase index
        emit_ins(jit, X86Instruction::cmp(OperandSize::S64, R11, REGISTER_MAP[0], Some(X86IndirectAccess::Offset(8)))); // Look up and compare against value at next index
        emit_ins(jit, X86Instruction::conditional_jump_immediate(0x86, jit.relative_to_anchor(ANCHOR_TRANSLATE_PC_LOOP, 6))); // Continue while *REGISTER_MAP[0] <= R11
        emit_ins(jit, X86Instruction::mov(OperandSize::S64, REGISTER_MAP[0], R11)); // R11 = REGISTER_MAP[0];
        emit_ins(jit, X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[0], jit.result.pc_section.as_ptr() as i64)); // REGISTER_MAP[0] = jit.result.pc_section;
        emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x29, REGISTER_MAP[0], R11, 0, None)); // R11 -= REGISTER_MAP[0];
        emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0xc1, 5, R11, 3, None)); // R11 >>= 3;
        emit_ins(jit, X86Instruction::pop(REGISTER_MAP[0])); // Restore REGISTER_MAP[0]
        emit_ins(jit, X86Instruction::return_near());

        // Translates a vm memory address to a host memory address
        for (access_type, len) in &[
            (AccessType::Load, 1i32),
            (AccessType::Load, 2i32),
            (AccessType::Load, 4i32),
            (AccessType::Load, 8i32),
            (AccessType::Store, 1i32),
            (AccessType::Store, 2i32),
            (AccessType::Store, 4i32),
            (AccessType::Store, 8i32),
        ] {
            let target_offset = len.trailing_zeros() as usize + 4 * (*access_type as usize);
            let stack_offset = if !jit.config.dynamic_stack_frames && jit.config.enable_stack_frame_gaps {
                24
            } else {
                16
            };

            jit.set_anchor(ANCHOR_MEMORY_ACCESS_VIOLATION + target_offset);
            emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x31, R11, R11, 0, None)); // R11 = 0;
            emit_ins(jit, X86Instruction::load(OperandSize::S64, RSP, R11, X86IndirectAccess::OffsetIndexShift(stack_offset, R11, 0)));
            emit_rust_call(jit, Value::Constant64(MemoryMapping::generate_access_violation::<UserError> as *const u8 as i64, false), &[
                Argument { index: 3, value: Value::Register(R11) }, // Specify first as the src register could be overwritten by other arguments
                Argument { index: 4, value: Value::Constant64(*len as i64, false) },
                Argument { index: 2, value: Value::Constant64(*access_type as i64, false) },
                Argument { index: 1, value: Value::RegisterPlusConstant32(R10, jit.program_argument_key, false) }, // jit_program_argument.memory_mapping
                Argument { index: 0, value: Value::RegisterIndirect(RBP, slot_on_environment_stack(jit, EnvironmentStackSlotX86::OptRetValPtr), false) }, // Pointer to optional typed return value
            ], None, true);
            emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x81, 0, RSP, stack_offset as i64 + 8, None)); // Drop R11, RAX, RCX, RDX from stack
            emit_ins(jit, X86Instruction::pop(R11)); // Put callers PC in R11
            emit_ins(jit, X86Instruction::call_immediate(jit.relative_to_anchor(ANCHOR_TRANSLATE_PC, 5)));
            emit_ins(jit, X86Instruction::jump_immediate(jit.relative_to_anchor(ANCHOR_EXCEPTION_AT, 5)));

            jit.set_anchor(ANCHOR_TRANSLATE_MEMORY_ADDRESS + target_offset);
            emit_ins(jit, X86Instruction::push(R11, None));
            emit_ins(jit, X86Instruction::push(RAX, None));
            emit_ins(jit, X86Instruction::push(RCX, None));
            if !jit.config.dynamic_stack_frames && jit.config.enable_stack_frame_gaps {
                emit_ins(jit, X86Instruction::push(RDX, None));
            }
            emit_ins(jit, X86Instruction::mov(OperandSize::S64, R11, RAX)); // RAX = vm_addr;
            emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0xc1, 5, RAX, ebpf::VIRTUAL_ADDRESS_BITS as i64, None)); // RAX >>= ebpf::VIRTUAL_ADDRESS_BITS;
            emit_ins(jit, X86Instruction::cmp(OperandSize::S64, RAX, R10, Some(X86IndirectAccess::Offset(jit.program_argument_key + 8)))); // region_index >= jit_program_argument.memory_mapping.regions.len()
            emit_ins(jit, X86Instruction::conditional_jump_immediate(0x86, jit.relative_to_anchor(ANCHOR_MEMORY_ACCESS_VIOLATION + target_offset, 6)));
            debug_assert_eq!(1 << 5, mem::size_of::<MemoryRegion>());
            emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0xc1, 4, RAX, 5, None)); // RAX *= mem::size_of::<MemoryRegion>();
            emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x03, RAX, R10, 0, Some(X86IndirectAccess::Offset(jit.program_argument_key)))); // region = &jit_program_argument.memory_mapping.regions[region_index];
            if *access_type == AccessType::Store {
                emit_ins(jit, X86Instruction::cmp_immediate(OperandSize::S8, RAX, 0, Some(X86IndirectAccess::Offset(MemoryRegion::IS_WRITABLE_OFFSET)))); // region.is_writable == 0
                emit_ins(jit, X86Instruction::conditional_jump_immediate(0x84, jit.relative_to_anchor(ANCHOR_MEMORY_ACCESS_VIOLATION + target_offset, 6)));
            }
            emit_ins(jit, X86Instruction::load(OperandSize::S64, RAX, RCX, X86IndirectAccess::Offset(MemoryRegion::VM_ADDR_OFFSET))); // RCX = region.vm_addr
            emit_ins(jit, X86Instruction::cmp(OperandSize::S64, RCX, R11, None)); // vm_addr < region.vm_addr
            emit_ins(jit, X86Instruction::conditional_jump_immediate(0x82, jit.relative_to_anchor(ANCHOR_MEMORY_ACCESS_VIOLATION + target_offset, 6)));
            emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x29, RCX, R11, 0, None)); // vm_addr -= region.vm_addr
            if !jit.config.dynamic_stack_frames && jit.config.enable_stack_frame_gaps {
                emit_ins(jit, X86Instruction::load(OperandSize::S8, RAX, RCX, X86IndirectAccess::Offset(MemoryRegion::VM_GAP_SHIFT_OFFSET))); // RCX = region.vm_gap_shift;
                emit_ins(jit, X86Instruction::mov(OperandSize::S64, R11, RDX)); // RDX = R11;
                emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0xd3, 5, RDX, 0, None)); // RDX = R11 >> region.vm_gap_shift;
                emit_ins(jit, X86Instruction::test_immediate(OperandSize::S64, RDX, 1, None)); // (RDX & 1) != 0
                emit_ins(jit, X86Instruction::conditional_jump_immediate(0x85, jit.relative_to_anchor(ANCHOR_MEMORY_ACCESS_VIOLATION + target_offset, 6)));
                emit_ins(jit, X86Instruction::load_immediate(OperandSize::S64, RDX, -1)); // RDX = -1;
                emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0xd3, 4, RDX, 0, None)); // gap_mask = -1 << region.vm_gap_shift;
                emit_ins(jit, X86Instruction::mov(OperandSize::S64, RDX, RCX)); // RCX = RDX;
                emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0xf7, 2, RCX, 0, None)); // inverse_gap_mask = !gap_mask;
                emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x21, R11, RCX, 0, None)); // below_gap = R11 & inverse_gap_mask;
                emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x21, RDX, R11, 0, None)); // above_gap = R11 & gap_mask;
                emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0xc1, 5, R11, 1, None)); // above_gap >>= 1;
                emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x09, RCX, R11, 0, None)); // gapped_offset = above_gap | below_gap;
            }
            emit_ins(jit, X86Instruction::lea(OperandSize::S64, R11, RCX, Some(X86IndirectAccess::Offset(*len)))); // RCX = R11 + len;
            emit_ins(jit, X86Instruction::cmp(OperandSize::S64, RCX, RAX, Some(X86IndirectAccess::Offset(MemoryRegion::LEN_OFFSET)))); // region.len < R11 + len
            emit_ins(jit, X86Instruction::conditional_jump_immediate(0x82, jit.relative_to_anchor(ANCHOR_MEMORY_ACCESS_VIOLATION + target_offset, 6)));
            emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x03, R11, RAX, 0, Some(X86IndirectAccess::Offset(MemoryRegion::HOST_ADDR_OFFSET)))); // R11 += region.host_addr;
            if !jit.config.dynamic_stack_frames && jit.config.enable_stack_frame_gaps {
                emit_ins(jit, X86Instruction::pop(RDX));
            }
            emit_ins(jit, X86Instruction::pop(RCX));
            emit_ins(jit, X86Instruction::pop(RAX));
            emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x81, 0, RSP, 8, None));
            emit_ins(jit, X86Instruction::return_near());
        }
    }

    #[inline]
    fn emit_validate_instruction_count(jit: &mut JitCompilerCore, exclusive: bool, pc: Option<usize>) {
        if let Some(pc) = pc {
            jit.last_instruction_meter_validation_pc = pc;
            emit_ins(jit, X86Instruction::cmp_immediate(OperandSize::S64, ARGUMENT_REGISTERS[0], pc as i64 + 1, None));
        } else {
            emit_ins(jit, X86Instruction::cmp(OperandSize::S64, R11, ARGUMENT_REGISTERS[0], None));
        }
        emit_ins(jit, X86Instruction::conditional_jump_immediate(if exclusive { 0x82 } else { 0x86 }, jit.relative_to_anchor(ANCHOR_CALL_EXCEEDED_MAX_INSTRUCTIONS, 6)));
    }

    #[inline]
    fn emit_profile_instruction_count(jit: &mut JitCompilerCore, target_pc: Option<usize>) {
        match target_pc {
            Some(target_pc) => {
                emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x81, 0, ARGUMENT_REGISTERS[0], target_pc as i64 - jit.pc as i64 - 1, None)); // instruction_meter += target_pc - (jit.pc + 1);
            },
            None => {
                emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x81, 5, ARGUMENT_REGISTERS[0], jit.pc as i64 + 1, None)); // instruction_meter -= jit.pc + 1;
                emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x01, R11, ARGUMENT_REGISTERS[0], jit.pc as i64, None)); // instruction_meter += target_pc;
            },
        }
    }

    fn fixup_text_jumps(jit: &mut JitCompilerCore) {
        // Relocate forward jumps
        for jump in &jit.text_section_jumps {
            debug_assert!(jump.fixup_type == FixupType::JumpImm as u8);
            let destination = jit.result.pc_section[jump.target_pc] as *const u8;
            let offset_value =
                unsafe { destination.offset_from(jump.location) } as i32 // Relative jump
                - mem::size_of::<i32>() as i32; // Jump from end of instruction
            unsafe { ptr::write_unaligned(jump.location as *mut i32, offset_value); }
        }
    }
}

const REGISTER_MAP: [u8; 11] = [
    CALLER_SAVED_REGISTERS[0],
    ARGUMENT_REGISTERS[1],
    ARGUMENT_REGISTERS[2],
    ARGUMENT_REGISTERS[3],
    ARGUMENT_REGISTERS[4],
    ARGUMENT_REGISTERS[5],
    CALLEE_SAVED_REGISTERS[2],
    CALLEE_SAVED_REGISTERS[3],
    CALLEE_SAVED_REGISTERS[4],
    CALLEE_SAVED_REGISTERS[5],
    CALLEE_SAVED_REGISTERS[1],
];

// Special registers:
//     ARGUMENT_REGISTERS[0]  RDI  BPF program counter limit (used by instruction meter)
// CALLER_SAVED_REGISTERS[8]  R11  Scratch register
// CALLER_SAVED_REGISTERS[7]  R10  Constant pointer to JitProgramArgument (also scratch register for exception handling)
// CALLEE_SAVED_REGISTERS[0]  RBP  Constant pointer to initial RSP - 8

#[inline]
fn emit_sanitized_load_immediate(jit: &mut JitCompilerCore, size: OperandSize, destination: u8, value: i64) {
    match size {
        OperandSize::S32 => {
            let key: i32 = jit.diversification_rng.gen();
            emit_ins(jit, X86Instruction::load_immediate(size, destination, (value as i32).wrapping_sub(key) as i64));
            emit_ins(jit, X86Instruction::alu(size, 0x81, 0, destination, key as i64, None));
        },
        OperandSize::S64 if destination == R11 => {
            let key: i64 = jit.diversification_rng.gen();
            let lower_key = key as i32 as i64;
            let upper_key = (key >> 32) as i32 as i64;
            emit_ins(jit, X86Instruction::load_immediate(size, destination, value.wrapping_sub(lower_key).rotate_right(32).wrapping_sub(upper_key)));
            emit_ins(jit, X86Instruction::alu(size, 0x81, 0, destination, upper_key, None)); // wrapping_add(upper_key)
            emit_ins(jit, X86Instruction::alu(size, 0xc1, 1, destination, 32, None)); // rotate_right(32)
            emit_ins(jit, X86Instruction::alu(size, 0x81, 0, destination, lower_key, None)); // wrapping_add(lower_key)
        },
        OperandSize::S64 if value >= i32::MIN as i64 && value <= i32::MAX as i64 => {
            let key = jit.diversification_rng.gen::<i32>() as i64;
            emit_ins(jit, X86Instruction::load_immediate(size, destination, value.wrapping_sub(key)));
            emit_ins(jit, X86Instruction::alu(size, 0x81, 0, destination, key, None));
        },
        OperandSize::S64 => {
            let key: i64 = jit.diversification_rng.gen();
            emit_ins(jit, X86Instruction::load_immediate(size, destination, value.wrapping_sub(key)));
            emit_ins(jit, X86Instruction::load_immediate(size, R11, key));
            emit_ins(jit, X86Instruction::alu(size, 0x01, R11, destination, 0, None));
        },
        _ => {
            #[cfg(debug_assertions)]
            unreachable!();
        }
    }
}

#[inline]
fn should_sanitize_constant(jit: &JitCompilerCore, value: i64) -> bool {
    if !jit.config.sanitize_user_provided_values {
        return false;
    }

    match value as u64 {
        0xFFFF
        | 0xFFFFFF
        | 0xFFFFFFFF
        | 0xFFFFFFFFFF
        | 0xFFFFFFFFFFFF
        | 0xFFFFFFFFFFFFFF
        | 0xFFFFFFFFFFFFFFFF => false,
        v if v <= 0xFF => false,
        v if !v <= 0xFF => false,
        _ => true
    }
}

#[inline]
fn emit_sanitized_alu(jit: &mut JitCompilerCore, size: OperandSize, opcode: u8, opcode_extension: u8, destination: u8, immediate: i64) {
    if should_sanitize_constant(jit, immediate) {
        emit_sanitized_load_immediate(jit, size, R11, immediate);
        emit_ins(jit, X86Instruction::alu(size, opcode, R11, destination, immediate, None));
    } else {
        emit_ins(jit, X86Instruction::alu(size, 0x81, opcode_extension, destination, immediate, None));
    }
}

#[inline]
fn emit_undo_profile_instruction_count(jit: &mut JitCompilerCore, target_pc: usize) {
    if jit.config.enable_instruction_meter {
        emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x81, 0, ARGUMENT_REGISTERS[0], jit.pc as i64 + 1 - target_pc as i64, None)); // instruction_meter += (jit.pc + 1) - target_pc;
    }
}


#[inline]
fn emit_profile_instruction_count_finalize(jit: &mut JitCompilerCore, store_pc_in_exception: bool) {
    if jit.config.enable_instruction_meter || store_pc_in_exception {
        emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x81, 0, R11, 1, None)); // R11 += 1;
    }
    if jit.config.enable_instruction_meter {
        emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x29, R11, ARGUMENT_REGISTERS[0], 0, None)); // instruction_meter -= pc + 1;
    }
    if store_pc_in_exception {
        emit_ins(jit, X86Instruction::load(OperandSize::S64, RBP, R10, X86IndirectAccess::Offset(slot_on_environment_stack(jit, EnvironmentStackSlotX86::OptRetValPtr))));
        emit_ins(jit, X86Instruction::store_immediate(OperandSize::S64, R10, X86IndirectAccess::Offset(0), 1)); // is_err = true;
        emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x81, 0, R11, ebpf::ELF_INSN_DUMP_OFFSET as i64 - 1, None));
        emit_ins(jit, X86Instruction::store(OperandSize::S64, R11, R10, X86IndirectAccess::Offset(16))); // pc = jit.pc + ebpf::ELF_INSN_DUMP_OFFSET;
    }
}


#[inline]
fn emit_conditional_branch_reg(jit: &mut JitCompilerCore, op: u8, bitwise: bool, first_operand: u8, second_operand: u8, target_pc: usize) {
    JitCompilerX86::emit_validate_and_profile_instruction_count(jit, false, Some(target_pc));
    if bitwise { // Logical
        emit_ins(jit, X86Instruction::test(OperandSize::S64, first_operand, second_operand, None));
    } else { // Arithmetic
        emit_ins(jit, X86Instruction::cmp(OperandSize::S64, first_operand, second_operand, None));
    }
    emit_ins(jit, X86Instruction::load_immediate(OperandSize::S64, R11, target_pc as i64));
    let jump_offset = jit.relative_to_target_pc(target_pc, 6, FixupType::JumpImm as u8);
    emit_ins(jit, X86Instruction::conditional_jump_immediate(op, jump_offset));
    emit_undo_profile_instruction_count(jit, target_pc);
}

#[inline]
fn emit_conditional_branch_imm(jit: &mut JitCompilerCore, op: u8, bitwise: bool, immediate: i64, second_operand: u8, target_pc: usize) {
    JitCompilerX86::emit_validate_and_profile_instruction_count(jit, false, Some(target_pc));
    if should_sanitize_constant(jit, immediate) {
        emit_sanitized_load_immediate(jit, OperandSize::S64, R11, immediate);
        if bitwise { // Logical
            emit_ins(jit, X86Instruction::test(OperandSize::S64, R11, second_operand, None));
        } else { // Arithmetic
            emit_ins(jit, X86Instruction::cmp(OperandSize::S64, R11, second_operand, None));
        }
    } else if bitwise { // Logical
        emit_ins(jit, X86Instruction::test_immediate(OperandSize::S64, second_operand, immediate, None));
    } else { // Arithmetic
        emit_ins(jit, X86Instruction::cmp_immediate(OperandSize::S64, second_operand, immediate, None));
    }
    emit_ins(jit, X86Instruction::load_immediate(OperandSize::S64, R11, target_pc as i64));
    let jump_offset = jit.relative_to_target_pc(target_pc, 6, FixupType::JumpImm as u8);
    emit_ins(jit, X86Instruction::conditional_jump_immediate(op, jump_offset));
    emit_undo_profile_instruction_count(jit, target_pc);
}

enum Value {
    Register(u8),
    RegisterIndirect(u8, i32, bool),
    RegisterPlusConstant32(u8, i32, bool),
    RegisterPlusConstant64(u8, i64, bool),
    Constant64(i64, bool),
}

#[inline]
fn emit_bpf_call(jit: &mut JitCompilerCore, dst: Value) {
    // Store PC in case the bounds check fails
    emit_ins(jit, X86Instruction::load_immediate(OperandSize::S64, R11, jit.pc as i64));

    emit_ins(jit, X86Instruction::call_immediate(jit.relative_to_anchor(ANCHOR_BPF_CALL_PROLOGUE, 5)));

    match dst {
        Value::Register(reg) => {
            // Move vm target_address into RAX
            emit_ins(jit, X86Instruction::push(REGISTER_MAP[0], None));
            if reg != REGISTER_MAP[0] {
                emit_ins(jit, X86Instruction::mov(OperandSize::S64, reg, REGISTER_MAP[0]));
            }

            emit_ins(jit, X86Instruction::call_immediate(jit.relative_to_anchor(ANCHOR_BPF_CALL_REG, 5)));

            JitCompilerX86::emit_validate_and_profile_instruction_count(jit, false, None);
            emit_ins(jit, X86Instruction::mov(OperandSize::S64, REGISTER_MAP[0], R11)); // Save target_pc
            emit_ins(jit, X86Instruction::pop(REGISTER_MAP[0])); // Restore RAX
            emit_ins(jit, X86Instruction::call_reg(R11, None)); // callq *%r11
        },
        Value::Constant64(target_pc, user_provided) => {
            debug_assert!(!user_provided);
            JitCompilerX86::emit_validate_and_profile_instruction_count(jit, false, Some(target_pc as usize));
            emit_ins(jit, X86Instruction::load_immediate(OperandSize::S64, R11, target_pc as i64));
            let jump_offset = jit.relative_to_target_pc(target_pc as usize, 5, FixupType::JumpImm as u8);
            emit_ins(jit, X86Instruction::call_immediate(jump_offset));
        },
        _ => {
            #[cfg(debug_assertions)]
            unreachable!();
        }
    }

    emit_undo_profile_instruction_count(jit, 0);

    // Restore the previous frame pointer
    emit_ins(jit, X86Instruction::pop(REGISTER_MAP[FRAME_PTR_REG]));
    let frame_ptr_access = X86IndirectAccess::Offset(slot_on_environment_stack(jit, EnvironmentStackSlotX86::BpfFramePtr));
    emit_ins(jit, X86Instruction::store(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], RBP, frame_ptr_access));
    for reg in REGISTER_MAP.iter().skip(FIRST_SCRATCH_REG).take(SCRATCH_REGS).rev() {
        emit_ins(jit, X86Instruction::pop(*reg));
    }
}

struct Argument {
    index: usize,
    value: Value,
}

// Restores: all registers
fn emit_rust_call(jit: &mut JitCompilerCore, dst: Value, arguments: &[Argument], result_reg: Option<u8>, check_exception: bool) {
    let mut saved_registers = CALLER_SAVED_REGISTERS.to_vec();
    if let Some(reg) = result_reg {
        let dst = saved_registers.iter().position(|x| *x == reg);
        debug_assert!(dst.is_some());
        if let Some(dst) = dst {
            saved_registers.remove(dst);
        }
    }

    // Save registers on stack
    for reg in saved_registers.iter() {
        emit_ins(jit, X86Instruction::push(*reg, None));
    }

    // Pass arguments
    let mut stack_arguments = 0;
    for argument in arguments {
        let is_stack_argument = argument.index >= ARGUMENT_REGISTERS.len();
        let dst = if is_stack_argument {
            stack_arguments += 1;
            R11
        } else {
            ARGUMENT_REGISTERS[argument.index]
        };
        match argument.value {
            Value::Register(reg) => {
                if is_stack_argument {
                    emit_ins(jit, X86Instruction::push(reg, None));
                } else if reg != dst {
                    emit_ins(jit, X86Instruction::mov(OperandSize::S64, reg, dst));
                }
            },
            Value::RegisterIndirect(reg, offset, user_provided) => {
                debug_assert!(!user_provided);
                if is_stack_argument {
                    emit_ins(jit, X86Instruction::push(reg, Some(X86IndirectAccess::Offset(offset))));
                } else {
                    emit_ins(jit, X86Instruction::load(OperandSize::S64, reg, dst, X86IndirectAccess::Offset(offset)));
                }
            },
            Value::RegisterPlusConstant32(reg, offset, user_provided) => {
                debug_assert!(!user_provided);
                if is_stack_argument {
                    emit_ins(jit, X86Instruction::push(reg, None));
                    emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x81, 0, RSP, offset as i64, Some(X86IndirectAccess::OffsetIndexShift(0, RSP, 0))));
                } else {
                    emit_ins(jit, X86Instruction::lea(OperandSize::S64, reg, dst, Some(X86IndirectAccess::Offset(offset))));
                }
            },
            Value::RegisterPlusConstant64(reg, offset, user_provided) => {
                debug_assert!(!user_provided);
                if is_stack_argument {
                    emit_ins(jit, X86Instruction::push(reg, None));
                    emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x81, 0, RSP, offset, Some(X86IndirectAccess::OffsetIndexShift(0, RSP, 0))));
                } else {
                    emit_ins(jit, X86Instruction::load_immediate(OperandSize::S64, dst, offset));
                    emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x01, reg, dst, 0, None));
                }
            },
            Value::Constant64(value, user_provided) => {
                debug_assert!(!user_provided && !is_stack_argument);
                emit_ins(jit, X86Instruction::load_immediate(OperandSize::S64, dst, value));
            },
        }
    }

    match dst {
        Value::Register(reg) => {
            emit_ins(jit, X86Instruction::call_reg(reg, None));
        },
        Value::Constant64(value, user_provided) => {
            debug_assert!(!user_provided);
            emit_ins(jit, X86Instruction::load_immediate(OperandSize::S64, RAX, value));
            emit_ins(jit, X86Instruction::call_reg(RAX, None));
        },
        _ => {
            #[cfg(debug_assertions)]
            unreachable!();
        }
    }

    // Save returned value in result register
    if let Some(reg) = result_reg {
        emit_ins(jit, X86Instruction::mov(OperandSize::S64, RAX, reg));
    }

    // Restore registers from stack
    emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x81, 0, RSP, stack_arguments * 8, None));
    for reg in saved_registers.iter().rev() {
        emit_ins(jit, X86Instruction::pop(*reg));
    }

    if check_exception {
        // Test if result indicates that an error occured
        emit_ins(jit, X86Instruction::load(OperandSize::S64, RBP, R11, X86IndirectAccess::Offset(slot_on_environment_stack(jit, EnvironmentStackSlotX86::OptRetValPtr))));
        emit_ins(jit, X86Instruction::cmp_immediate(OperandSize::S64, R11, 0, Some(X86IndirectAccess::Offset(0))));
    }
}


#[inline]
fn emit_address_translation(jit: &mut JitCompilerCore, host_addr: u8, vm_addr: Value, len: u64, access_type: AccessType) {
    match vm_addr {
        Value::RegisterPlusConstant64(reg, constant, user_provided) => {
            if user_provided && should_sanitize_constant(jit, constant) {
                emit_sanitized_load_immediate(jit, OperandSize::S64, R11, constant);
            } else {
                emit_ins(jit, X86Instruction::load_immediate(OperandSize::S64, R11, constant));
            }
            emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x01, reg, R11, 0, None));
        },
        Value::Constant64(constant, user_provided) => {
            if user_provided && should_sanitize_constant(jit, constant) {
                emit_sanitized_load_immediate(jit, OperandSize::S64, R11, constant);
            } else {
                emit_ins(jit, X86Instruction::load_immediate(OperandSize::S64, R11, constant));
            }
        },
        _ => {
            #[cfg(debug_assertions)]
            unreachable!();
        },
    }
    let anchor = ANCHOR_TRANSLATE_MEMORY_ADDRESS + len.trailing_zeros() as usize + 4 * (access_type as usize);
    emit_ins(jit, X86Instruction::call_immediate(jit.relative_to_anchor(anchor, 5)));
    emit_ins(jit, X86Instruction::mov(OperandSize::S64, R11, host_addr));
}

fn emit_shift(jit: &mut JitCompilerCore, size: OperandSize, opcode_extension: u8, source: u8, destination: u8, immediate: Option<i64>) {
    if let Some(immediate) = immediate {
        if should_sanitize_constant(jit, immediate) {
            emit_sanitized_load_immediate(jit, OperandSize::S32, source, immediate);
        } else {
            emit_ins(jit, X86Instruction::alu(size, 0xc1, opcode_extension, destination, immediate, None));
            return;
        }
    }
    if let OperandSize::S32 = size {
        emit_ins(jit, X86Instruction::alu(OperandSize::S32, 0x81, 4, destination, -1, None)); // Mask to 32 bit
    }
    if source == RCX {
        if destination == RCX {
            emit_ins(jit, X86Instruction::alu(size, 0xd3, opcode_extension, destination, 0, None));
        } else {
            emit_ins(jit, X86Instruction::push(RCX, None));
            emit_ins(jit, X86Instruction::alu(size, 0xd3, opcode_extension, destination, 0, None));
            emit_ins(jit, X86Instruction::pop(RCX));
        }
    } else if destination == RCX {
        if source != R11 {
            emit_ins(jit, X86Instruction::push(source, None));
        }
        emit_ins(jit, X86Instruction::xchg(OperandSize::S64, source, RCX, None));
        emit_ins(jit, X86Instruction::alu(size, 0xd3, opcode_extension, source, 0, None));
        emit_ins(jit, X86Instruction::mov(OperandSize::S64, source, RCX));
        if source != R11 {
            emit_ins(jit, X86Instruction::pop(source));
        }
    } else {
        emit_ins(jit, X86Instruction::push(RCX, None));
        emit_ins(jit, X86Instruction::mov(OperandSize::S64, source, RCX));
        emit_ins(jit, X86Instruction::alu(size, 0xd3, opcode_extension, destination, 0, None));
        emit_ins(jit, X86Instruction::pop(RCX));
    }
}

fn emit_muldivmod(jit: &mut JitCompilerCore, opc: u8, src: u8, dst: u8, imm: Option<i64>) {
    let mul = (opc & ebpf::BPF_ALU_OP_MASK) == (ebpf::MUL32_IMM & ebpf::BPF_ALU_OP_MASK);
    let div = (opc & ebpf::BPF_ALU_OP_MASK) == (ebpf::DIV32_IMM & ebpf::BPF_ALU_OP_MASK);
    let sdiv = (opc & ebpf::BPF_ALU_OP_MASK) == (ebpf::SDIV32_IMM & ebpf::BPF_ALU_OP_MASK);
    let modrm = (opc & ebpf::BPF_ALU_OP_MASK) == (ebpf::MOD32_IMM & ebpf::BPF_ALU_OP_MASK);
    let size = if (opc & ebpf::BPF_CLS_MASK) == ebpf::BPF_ALU64 { OperandSize::S64 } else { OperandSize::S32 };

    if !mul && imm.is_none() {
        // Save pc
        emit_ins(jit, X86Instruction::load_immediate(OperandSize::S64, R11, jit.pc as i64));
        emit_ins(jit, X86Instruction::test(size, src, src, None)); // src == 0
        emit_ins(jit, X86Instruction::conditional_jump_immediate(0x84, jit.relative_to_anchor(ANCHOR_DIV_BY_ZERO, 6)));
    }

    // sdiv overflows with MIN / -1. If we have an immediate and it's not -1, we
    // don't need any checks.
    if sdiv && imm.unwrap_or(-1) == -1 {
        emit_ins(jit, X86Instruction::load_immediate(size, R11, if let OperandSize::S64 = size { i64::MIN } else { i32::MIN as i64 }));
        emit_ins(jit, X86Instruction::cmp(size, dst, R11, None)); // dst == MIN

        if imm.is_none() {
            // The exception case is: dst == MIN && src == -1
            // Via De Morgan's law becomes: !(dst != MIN || src != -1)
            // Also, we know that src != 0 in here, so we can use it to set R11 to something not zero
            emit_ins(jit, X86Instruction::load_immediate(size, R11, 0)); // No XOR here because we need to keep the status flags
            emit_ins(jit, X86Instruction::cmov(size, 0x45, src, R11)); // if dst != MIN { r11 = src; }
            emit_ins(jit, X86Instruction::cmp_immediate(size, src, -1, None)); // src == -1
            emit_ins(jit, X86Instruction::cmov(size, 0x45, src, R11)); // if src != -1 { r11 = src; }
            emit_ins(jit, X86Instruction::test(size, R11, R11, None)); // r11 == 0
        }

        // MIN / -1, raise EbpfError::DivideOverflow(pc)
        emit_ins(jit, X86Instruction::load_immediate(OperandSize::S64, R11, jit.pc as i64));
        emit_ins(jit, X86Instruction::conditional_jump_immediate(0x84, jit.relative_to_anchor(ANCHOR_DIV_OVERFLOW, 6)));
    }

    if dst != RAX {
        emit_ins(jit, X86Instruction::push(RAX, None));
    }
    if dst != RDX {
        emit_ins(jit, X86Instruction::push(RDX, None));
    }

    if let Some(imm) = imm {
        if should_sanitize_constant(jit, imm) {
            emit_sanitized_load_immediate(jit, OperandSize::S64, R11, imm);
        } else {
            emit_ins(jit, X86Instruction::load_immediate(OperandSize::S64, R11, imm));
        }
    } else {
        emit_ins(jit, X86Instruction::mov(OperandSize::S64, src, R11));
    }

    if dst != RAX {
        emit_ins(jit, X86Instruction::mov(OperandSize::S64, dst, RAX));
    }

    if div || modrm {
        emit_ins(jit, X86Instruction::alu(size, 0x31, RDX, RDX, 0, None)); // RDX = 0
    } else if sdiv {
        emit_ins(jit, X86Instruction::dividend_sign_extension(size)); // (RAX, RDX) = RAX as i128
    }

    emit_ins(jit, X86Instruction::alu(size, 0xf7, if mul { 4 } else if sdiv { 7 } else { 6 }, R11, 0, None));

    if dst != RDX {
        if modrm {
            emit_ins(jit, X86Instruction::mov(OperandSize::S64, RDX, dst));
        }
        emit_ins(jit, X86Instruction::pop(RDX));
    }
    if dst != RAX {
        if !modrm {
            emit_ins(jit, X86Instruction::mov(OperandSize::S64, RAX, dst));
        }
        emit_ins(jit, X86Instruction::pop(RAX));
    }

    if let OperandSize::S32 = size {
        if mul || sdiv {
            emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x63, dst, dst, 0, None)); // sign extend i32 to i64
        }
    }
}


#[inline]
fn emit_set_exception_kind<E: UserDefinedError>(jit: &mut JitCompilerCore, err: EbpfError<E>) {
    let err = Result::<u64, EbpfError<E>>::Err(err);
    let err_kind = unsafe { *(&err as *const _ as *const u64).offset(1) };
    emit_ins(jit, X86Instruction::load(OperandSize::S64, RBP, R10, X86IndirectAccess::Offset(slot_on_environment_stack(jit, EnvironmentStackSlotX86::OptRetValPtr))));
    emit_ins(jit, X86Instruction::store_immediate(OperandSize::S64, R10, X86IndirectAccess::Offset(8), err_kind as i64));
}

#[allow(dead_code)]
#[inline]
fn emit_stopwatch(jit: &mut JitCompilerCore, begin: bool) {
    jit.stopwatch_is_active = true;
    emit_ins(jit, X86Instruction::push(RDX, None));
    emit_ins(jit, X86Instruction::push(RAX, None));
    emit_ins(jit, X86Instruction::fence(FenceType::Load)); // lfence
    emit_ins(jit, X86Instruction::cycle_count()); // rdtsc
    emit_ins(jit, X86Instruction::fence(FenceType::Load)); // lfence
    emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0xc1, 4, RDX, 32, None)); // RDX <<= 32;
    emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x09, RDX, RAX, 0, None)); // RAX |= RDX;
    if begin {
        emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x29, RAX, RBP, 0, Some(X86IndirectAccess::Offset(slot_on_environment_stack(jit, EnvironmentStackSlotX86::StopwatchNumerator))))); // *numerator -= RAX;
    } else {
        emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x01, RAX, RBP, 0, Some(X86IndirectAccess::Offset(slot_on_environment_stack(jit, EnvironmentStackSlotX86::StopwatchNumerator))))); // *numerator += RAX;
        emit_ins(jit, X86Instruction::alu(OperandSize::S64, 0x81, 0, RBP, 1, Some(X86IndirectAccess::Offset(slot_on_environment_stack(jit, EnvironmentStackSlotX86::StopwatchDenominator))))); // *denominator += 1;
    }
    emit_ins(jit, X86Instruction::pop(RAX));
    emit_ins(jit, X86Instruction::pop(RDX));
}

// This function helps the optimizer to inline the machinecode emission while avoiding stack allocations
#[inline(always)]
pub fn emit_ins(jit: &mut JitCompilerCore, instruction: X86Instruction) {
    instruction.emit(jit);
    if jit.next_noop_insertion == 0 {
        jit.next_noop_insertion = jit.diversification_rng.gen_range(0..jit.config.noop_instruction_rate * 2);
        // X86Instruction::noop().emit(jit)?;
        emit::<u8>(jit, 0x90);
    } else {
        jit.next_noop_insertion -= 1;
    }
}

enum FixupType {
    JumpImm = 0
}

#[derive(PartialEq, Eq, Copy, Clone)]
#[repr(C)]
pub enum EnvironmentStackSlotX86 {
    /// The 6 CALLEE_SAVED_REGISTERS
    LastSavedRegister = 5,
    /// The current call depth.
    ///
    /// Incremented on calls and decremented on exits. It's used to enforce
    /// config.max_call_depth and to know when to terminate execution.
    CallDepth = 6,
    /// BPF frame pointer (REGISTER_MAP[FRAME_PTR_REG]).
    BpfFramePtr = 7,
    /// The BPF stack pointer (r11). Only used when config.dynamic_stack_frames=true.
    ///
    /// The stack pointer isn't exposed as an actual register. Only sub and add
    /// instructions (typically generated by the LLVM backend) are allowed to
    /// access it. Its value is only stored in this slot and therefore the
    /// register is not tracked in REGISTER_MAP.
    BpfStackPtr = 8,
    /// Constant pointer to optional typed return value
    OptRetValPtr = 9,
    /// Last return value of instruction_meter.get_remaining()
    PrevInsnMeter = 10,
    /// Constant pointer to instruction_meter
    InsnMeterPtr = 11,
    /// CPU cycles accumulated by the stop watch
    StopwatchNumerator = 12,
    /// Number of times the stop watch was used
    StopwatchDenominator = 13,
    /// Bumper for size_of
    SlotCount = 14,
}

pub fn slot_on_environment_stack(jit: &JitCompilerCore, slot: EnvironmentStackSlotX86) -> i32 {
    -8 * (slot as i32 + jit.environment_stack_key)
}
