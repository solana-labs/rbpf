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
    arm64::*,
    jit::*
};

pub struct JitCompilerARM64 {
    core: JitCompilerCore
}

impl JitCompilerImpl for JitCompilerARM64 {
    fn get_max_empty_machine_code_length() -> usize {
        8192
    }
    fn get_max_machine_code_per_instruction() -> usize {
        153
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
            emit_load_immediate64(jit, ARM_SCRATCH[0], jit.pc as u64);
            emit_call_anchor(jit, ANCHOR_TRACE);
            emit_load_immediate64(jit, ARM_SCRATCH[0], 0);
        }
        let dst = if insn.dst == STACK_PTR_REG as u8 { u8::MAX } else { REGISTER_MAP[insn.dst as usize] };
        let src = REGISTER_MAP[insn.src as usize];
        let target_pc = (jit.pc as isize + insn.off as isize + 1) as usize;
        match insn.opc {
                _ if insn.dst == STACK_PTR_REG as u8 && jit.config.dynamic_stack_frames => {
                    emit_load_env(jit, EnvironmentStackSlotARM64::BpfStackPtr, ARM_SCRATCH[0]);
                    emit_load_immediate64(jit, ARM_SCRATCH[1], insn.imm as u64);
                    match insn.opc {
                        ebpf::SUB64_IMM => emit_ins(jit, ARM64Instruction::sub(OperandSize::S64, ARM_SCRATCH[0], ARM_SCRATCH[1], ARM_SCRATCH[0])),
                        ebpf::ADD64_IMM => emit_ins(jit, ARM64Instruction::add(OperandSize::S64, ARM_SCRATCH[0], ARM_SCRATCH[1], ARM_SCRATCH[0])),
                        _ => {
                            #[cfg(debug_assertions)]
                            unreachable!("unexpected insn on r11")
                        }
                    }
                    emit_store_env(jit, ARM_SCRATCH[0], EnvironmentStackSlotARM64::BpfStackPtr, ARM_SCRATCH[1]);
                }

                ebpf::LD_DW_IMM  => {
                    Self::emit_validate_and_profile_instruction_count(jit, true, Some(jit.pc + 2));
                    jit.pc += 1;
                    jit.result.pc_section[jit.pc] = jit.anchors[ANCHOR_CALL_UNSUPPORTED_INSTRUCTION] as usize;
                    ebpf::augment_lddw_unchecked(program, &mut insn);
                    emit_load_immediate64(jit, dst, insn.imm as u64);
                },

                // BPF_LDX class
                ebpf::LD_B_REG   => {
                    emit_address_translation(jit, ARM_SCRATCH[0], Value::RegisterPlusConstant64(src, insn.off as u64, true), 1, AccessType::Load);
                    emit_ins(jit, ARM64Instruction::load(OperandSize::S8, ARM_SCRATCH[0], ARM64MemoryOperand::Offset(0), dst));
                },
                ebpf::LD_H_REG   => {
                    emit_address_translation(jit, ARM_SCRATCH[0], Value::RegisterPlusConstant64(src, insn.off as u64, true), 2, AccessType::Load);
                    emit_ins(jit, ARM64Instruction::load(OperandSize::S16, ARM_SCRATCH[0], ARM64MemoryOperand::Offset(0), dst));
                },
                ebpf::LD_W_REG   => {
                    emit_address_translation(jit, ARM_SCRATCH[0], Value::RegisterPlusConstant64(src, insn.off as u64, true), 4, AccessType::Load);
                    emit_ins(jit, ARM64Instruction::load(OperandSize::S32, ARM_SCRATCH[0], ARM64MemoryOperand::Offset(0), dst));
                },
                ebpf::LD_DW_REG  => {
                    emit_address_translation(jit, ARM_SCRATCH[0], Value::RegisterPlusConstant64(src, insn.off as u64, true), 8, AccessType::Load);
                    emit_ins(jit, ARM64Instruction::load(OperandSize::S64, ARM_SCRATCH[0], ARM64MemoryOperand::Offset(0), dst));
                },

                // BPF_ST class
                ebpf::ST_B_IMM   => {
                    emit_address_translation(jit, ARM_SCRATCH[0], Value::RegisterPlusConstant64(dst, insn.off as u64, true), 1, AccessType::Store);
                    emit_load_immediate64(jit, ARM_SCRATCH[1], insn.imm as u64);
                    emit_ins(jit, ARM64Instruction::store(OperandSize::S8, ARM_SCRATCH[1], ARM_SCRATCH[0], ARM64MemoryOperand::Offset(0)));
                },
                ebpf::ST_H_IMM   => {
                    emit_address_translation(jit, ARM_SCRATCH[0], Value::RegisterPlusConstant64(dst, insn.off as u64, true), 2, AccessType::Store);
                    emit_load_immediate64(jit, ARM_SCRATCH[1], insn.imm as u64);
                    emit_ins(jit, ARM64Instruction::store(OperandSize::S16, ARM_SCRATCH[1], ARM_SCRATCH[0], ARM64MemoryOperand::Offset(0)));
                },
                ebpf::ST_W_IMM   => {
                    emit_address_translation(jit, ARM_SCRATCH[0], Value::RegisterPlusConstant64(dst, insn.off as u64, true), 4, AccessType::Store);
                    emit_load_immediate64(jit, ARM_SCRATCH[1], insn.imm as u64);
                    emit_ins(jit, ARM64Instruction::store(OperandSize::S32, ARM_SCRATCH[1], ARM_SCRATCH[0], ARM64MemoryOperand::Offset(0)));
                },
                ebpf::ST_DW_IMM  => {
                    emit_address_translation(jit, ARM_SCRATCH[0], Value::RegisterPlusConstant64(dst, insn.off as u64, true), 8, AccessType::Store);
                    emit_load_immediate64(jit, ARM_SCRATCH[1], insn.imm as u64);
                    emit_ins(jit, ARM64Instruction::store(OperandSize::S64, ARM_SCRATCH[1], ARM_SCRATCH[0], ARM64MemoryOperand::Offset(0)));
                },

                // BPF_STX class
                ebpf::ST_B_REG  => {
                    emit_address_translation(jit, ARM_SCRATCH[0], Value::RegisterPlusConstant64(dst, insn.off as u64, true), 1, AccessType::Store);
                    emit_ins(jit, ARM64Instruction::store(OperandSize::S8, src, ARM_SCRATCH[0], ARM64MemoryOperand::Offset(0)));
                },
                ebpf::ST_H_REG  => {
                    emit_address_translation(jit, ARM_SCRATCH[0], Value::RegisterPlusConstant64(dst, insn.off as u64, true), 2, AccessType::Store);
                    emit_ins(jit, ARM64Instruction::store(OperandSize::S16, src, ARM_SCRATCH[0], ARM64MemoryOperand::Offset(0)));
                },
                ebpf::ST_W_REG  => {
                    emit_address_translation(jit, ARM_SCRATCH[0], Value::RegisterPlusConstant64(dst, insn.off as u64, true), 4, AccessType::Store);
                    emit_ins(jit, ARM64Instruction::store(OperandSize::S32, src, ARM_SCRATCH[0], ARM64MemoryOperand::Offset(0)));
                },
                ebpf::ST_DW_REG  => {
                    emit_address_translation(jit, ARM_SCRATCH[0], Value::RegisterPlusConstant64(dst, insn.off as u64, true), 8, AccessType::Store);
                    emit_ins(jit, ARM64Instruction::store(OperandSize::S64, src, ARM_SCRATCH[0], ARM64MemoryOperand::Offset(0)));
                },

                // BPF_ALU class
                ebpf::ADD32_IMM  => {
                    emit_load_immediate64(jit, ARM_SCRATCH[0], insn.imm as u64);
                    emit_ins(jit, ARM64Instruction::add(OperandSize::S32, dst, ARM_SCRATCH[0], dst));
                    emit_ins(jit, ARM64Instruction::sign_extend_to_i64(OperandSize::S32, dst, dst));
                },
                ebpf::ADD32_REG  => {
                    emit_ins(jit, ARM64Instruction::add(OperandSize::S32, dst, src, dst));
                    emit_ins(jit, ARM64Instruction::sign_extend_to_i64(OperandSize::S32, dst, dst));
                },
                ebpf::SUB32_IMM  => {
                    emit_load_immediate64(jit, ARM_SCRATCH[0], insn.imm as u64);
                    emit_ins(jit, ARM64Instruction::sub(OperandSize::S32, dst, ARM_SCRATCH[0], dst));
                    emit_ins(jit, ARM64Instruction::sign_extend_to_i64(OperandSize::S32, dst, dst));
                },
                ebpf::SUB32_REG  => {
                    emit_ins(jit, ARM64Instruction::sub(OperandSize::S32, dst, src, dst));
                    emit_ins(jit, ARM64Instruction::sign_extend_to_i64(OperandSize::S32, dst, dst));
                },
                ebpf::MUL32_IMM | ebpf::DIV32_IMM | ebpf::SDIV32_IMM | ebpf::MOD32_IMM  =>
                    emit_muldivmod(jit, insn.opc, dst, dst, Some(insn.imm)),
                ebpf::MUL32_REG | ebpf::DIV32_REG | ebpf::SDIV32_REG | ebpf::MOD32_REG  =>
                    emit_muldivmod(jit, insn.opc, src, dst, None),
                ebpf::OR32_IMM   => {
                    emit_load_immediate64(jit, ARM_SCRATCH[0], insn.imm as u64);
                    emit_ins(jit, ARM64Instruction::orr(OperandSize::S32, ARM_SCRATCH[0], dst));
                },
                ebpf::OR32_REG   => {
                    emit_ins(jit, ARM64Instruction::orr(OperandSize::S32, src, dst));
                },
                ebpf::AND32_IMM   => {
                    emit_load_immediate64(jit, ARM_SCRATCH[0], insn.imm as u64);
                    emit_ins(jit, ARM64Instruction::and(OperandSize::S32, ARM_SCRATCH[0], dst, dst));
                },
                ebpf::AND32_REG   => {
                    emit_ins(jit, ARM64Instruction::and(OperandSize::S32, src, dst, dst));
                },
                ebpf::LSH32_IMM   => {
                    emit_load_immediate64(jit, ARM_SCRATCH[0], insn.imm as u64);
                    emit_ins(jit, ARM64Instruction::lsl_reg(OperandSize::S32, dst, ARM_SCRATCH[0], dst));
                },
                ebpf::LSH32_REG   => {
                    emit_ins(jit, ARM64Instruction::lsl_reg(OperandSize::S32, dst, src, dst));
                },
                ebpf::RSH32_IMM   => {
                    emit_load_immediate64(jit, ARM_SCRATCH[0], insn.imm as u64);
                    emit_ins(jit, ARM64Instruction::lsr_reg(OperandSize::S32, dst, ARM_SCRATCH[0], dst));
                },
                ebpf::RSH32_REG   => {
                    emit_ins(jit, ARM64Instruction::lsr_reg(OperandSize::S32, dst, src, dst));
                },
                ebpf::NEG32      => emit_ins(jit, ARM64Instruction::sub(OperandSize::S32, SP_XZR, dst, dst)),
                ebpf::XOR32_IMM   => {
                    emit_load_immediate64(jit, ARM_SCRATCH[0], insn.imm as u64);
                    emit_ins(jit, ARM64Instruction::eor(OperandSize::S32, ARM_SCRATCH[0], dst));
                },
                ebpf::XOR32_REG   => {
                    emit_ins(jit, ARM64Instruction::eor(OperandSize::S32, src, dst));
                },
                ebpf::MOV32_IMM  => { emit_load_immediate64(jit, dst, (insn.imm as u32) as u64); }
                ebpf::MOV32_REG  => emit_ins(jit, ARM64Instruction::mov(OperandSize::S32, src, dst)),
                ebpf::ARSH32_IMM   => {
                    emit_load_immediate64(jit, ARM_SCRATCH[0], insn.imm as u64);
                    emit_ins(jit, ARM64Instruction::asr_reg(OperandSize::S32, dst, ARM_SCRATCH[0], dst));
                },
                ebpf::ARSH32_REG   => {
                    emit_ins(jit, ARM64Instruction::asr_reg(OperandSize::S32, dst, src, dst));
                },
                ebpf::LE         => {
                    match insn.imm {
                        16 => {
                            emit_ins(jit, ARM64Instruction::zero_extend_to_u64(OperandSize::S16, dst, dst));
                        },
                        32 => {
                            emit_ins(jit, ARM64Instruction::zero_extend_to_u64(OperandSize::S32, dst, dst));
                        },
                        64 => {}
                        _ => {
                            return Err(EbpfError::InvalidInstruction(jit.pc + ebpf::ELF_INSN_DUMP_OFFSET));
                        }
                    }
                },
                ebpf::BE         => {
                    match insn.imm {
                        16 => {
                            emit_ins(jit, ARM64Instruction::rev(OperandSize::S16, dst, dst));
                            emit_ins(jit, ARM64Instruction::zero_extend_to_u64(OperandSize::S16, dst, dst));
                        },
                        32 => emit_ins(jit, ARM64Instruction::rev(OperandSize::S32, dst, dst)),
                        64 => emit_ins(jit, ARM64Instruction::rev(OperandSize::S64, dst, dst)),
                        _ => {
                            return Err(EbpfError::InvalidInstruction(jit.pc + ebpf::ELF_INSN_DUMP_OFFSET));
                        }
                    }
                },

                // BPF_ALU64 class
                ebpf::ADD64_IMM  => {
                    emit_load_immediate64(jit, ARM_SCRATCH[0], insn.imm as u64);
                    emit_ins(jit, ARM64Instruction::add(OperandSize::S64, dst, ARM_SCRATCH[0], dst));
                },
                ebpf::ADD64_REG  => {
                    emit_ins(jit, ARM64Instruction::add(OperandSize::S64, dst, src, dst));
                },
                ebpf::SUB64_IMM  => {
                    emit_load_immediate64(jit, ARM_SCRATCH[0], insn.imm as u64);
                    emit_ins(jit, ARM64Instruction::sub(OperandSize::S64, dst, ARM_SCRATCH[0], dst));
                },
                ebpf::SUB64_REG  => {
                    emit_ins(jit, ARM64Instruction::sub(OperandSize::S64, dst, src, dst));
                },
                ebpf::MUL64_IMM | ebpf::DIV64_IMM | ebpf::SDIV64_IMM | ebpf::MOD64_IMM  =>
                    emit_muldivmod(jit, insn.opc, dst, dst, Some(insn.imm)),
                ebpf::MUL64_REG | ebpf::DIV64_REG | ebpf::SDIV64_REG | ebpf::MOD64_REG  =>
                    emit_muldivmod(jit, insn.opc, src, dst, None),
                ebpf::OR64_IMM   => {
                    emit_load_immediate64(jit, ARM_SCRATCH[0], insn.imm as u64);
                    emit_ins(jit, ARM64Instruction::orr(OperandSize::S64, ARM_SCRATCH[0], dst));
                },
                ebpf::OR64_REG   => {
                    emit_ins(jit, ARM64Instruction::orr(OperandSize::S64, src, dst));
                },
                ebpf::AND64_IMM   => {
                    emit_load_immediate64(jit, ARM_SCRATCH[0], insn.imm as u64);
                    emit_ins(jit, ARM64Instruction::and(OperandSize::S64, ARM_SCRATCH[0], dst, dst));
                },
                ebpf::AND64_REG   => {
                    emit_ins(jit, ARM64Instruction::and(OperandSize::S64, src, dst, dst));
                },
                ebpf::LSH64_IMM   => {
                    emit_load_immediate64(jit, ARM_SCRATCH[0], insn.imm as u64);
                    emit_ins(jit, ARM64Instruction::lsl_reg(OperandSize::S64, dst, ARM_SCRATCH[0], dst));
                },
                ebpf::LSH64_REG   => {
                    emit_ins(jit, ARM64Instruction::lsl_reg(OperandSize::S64, dst, src, dst));
                },
                ebpf::RSH64_IMM   => {
                    emit_load_immediate64(jit, ARM_SCRATCH[0], insn.imm as u64);
                    emit_ins(jit, ARM64Instruction::lsr_reg(OperandSize::S64, dst, ARM_SCRATCH[0], dst));
                },
                ebpf::RSH64_REG   => {
                    emit_ins(jit, ARM64Instruction::lsr_reg(OperandSize::S64, dst, src, dst));
                },
                ebpf::NEG64      => emit_ins(jit, ARM64Instruction::sub(OperandSize::S64, SP_XZR, dst, dst)),
                ebpf::XOR64_IMM   => {
                    emit_load_immediate64(jit, ARM_SCRATCH[0], insn.imm as u64);
                    emit_ins(jit, ARM64Instruction::eor(OperandSize::S64, ARM_SCRATCH[0], dst));
                },
                ebpf::XOR64_REG   => {
                    emit_ins(jit, ARM64Instruction::eor(OperandSize::S64, src, dst));
                },
                ebpf::MOV64_IMM  => { emit_load_immediate64(jit, dst, insn.imm as u64); }
                ebpf::MOV64_REG  => emit_ins(jit, ARM64Instruction::mov(OperandSize::S64, src, dst)),
                ebpf::ARSH64_IMM   => {
                    emit_load_immediate64(jit, ARM_SCRATCH[0], insn.imm as u64);
                    emit_ins(jit, ARM64Instruction::asr_reg(OperandSize::S64, dst, ARM_SCRATCH[0], dst));
                },
                ebpf::ARSH64_REG   => {
                    emit_ins(jit, ARM64Instruction::asr_reg(OperandSize::S64, dst, src, dst));
                },

                // BPF_JMP class
                ebpf::JA         => {
                    Self::emit_validate_and_profile_instruction_count(jit, false, Some(target_pc));
                    // emit_load_immediate64(jit, ARM_SCRATCH[0], target_pc as u64);
                    emit_load_immediate64(jit, CUR_JIT_PC, target_pc as u64);
                    let jmp_off = jit.relative_to_target_pc_arm64(target_pc, FixupType::JUMP as u8);
                    emit_jmp(jit, jmp_off);
                },
                ebpf::JEQ_IMM    => {
                    emit_load_immediate64(jit, ARM_SCRATCH[0], insn.imm as u64);
                    emit_conditional_branch_reg(jit, Condition::EQ, false, ARM_SCRATCH[0], dst, target_pc)
                }
                ebpf::JEQ_REG    => emit_conditional_branch_reg(jit, Condition::EQ, false, src, dst, target_pc),
                ebpf::JGT_IMM    => {
                    emit_load_immediate64(jit, ARM_SCRATCH[0], insn.imm as u64);
                    emit_conditional_branch_reg(jit, Condition::HI, false, ARM_SCRATCH[0], dst, target_pc)
                }
                ebpf::JGT_REG    => emit_conditional_branch_reg(jit, Condition::HI, false, src, dst, target_pc),
                ebpf::JGE_IMM    => {
                    emit_load_immediate64(jit, ARM_SCRATCH[0], insn.imm as u64);
                    emit_conditional_branch_reg(jit, Condition::HS, false, ARM_SCRATCH[0], dst, target_pc)
                }
                ebpf::JGE_REG    => emit_conditional_branch_reg(jit, Condition::HS, false, src, dst, target_pc),
                ebpf::JLT_IMM    => {
                    emit_load_immediate64(jit, ARM_SCRATCH[0], insn.imm as u64);
                    emit_conditional_branch_reg(jit, Condition::LO, false, ARM_SCRATCH[0], dst, target_pc)
                }
                ebpf::JLT_REG    => emit_conditional_branch_reg(jit, Condition::LO, false, src, dst, target_pc),
                ebpf::JLE_IMM    => {
                    emit_load_immediate64(jit, ARM_SCRATCH[0], insn.imm as u64);
                    emit_conditional_branch_reg(jit, Condition::LS, false, ARM_SCRATCH[0], dst, target_pc)
                }
                ebpf::JLE_REG    => emit_conditional_branch_reg(jit, Condition::LS, false, src, dst, target_pc),
                ebpf::JSET_IMM    => {
                    emit_load_immediate64(jit, ARM_SCRATCH[0], insn.imm as u64);
                    emit_conditional_branch_reg(jit, Condition::NE, true, ARM_SCRATCH[0], dst, target_pc)
                }
                ebpf::JSET_REG    => emit_conditional_branch_reg(jit, Condition::NE, true, src, dst, target_pc),
                ebpf::JNE_IMM    => {
                    emit_load_immediate64(jit, ARM_SCRATCH[0], insn.imm as u64);
                    emit_conditional_branch_reg(jit, Condition::NE, false, ARM_SCRATCH[0], dst, target_pc)
                }
                ebpf::JNE_REG    => emit_conditional_branch_reg(jit, Condition::NE, false, src, dst, target_pc),
                ebpf::JSGT_IMM    => {
                    emit_load_immediate64(jit, ARM_SCRATCH[0], insn.imm as u64);
                    emit_conditional_branch_reg(jit, Condition::GT, false, ARM_SCRATCH[0], dst, target_pc)
                }
                ebpf::JSGT_REG    => emit_conditional_branch_reg(jit, Condition::GT, false, src, dst, target_pc),
                ebpf::JSGE_IMM    => {
                    emit_load_immediate64(jit, ARM_SCRATCH[0], insn.imm as u64);
                    emit_conditional_branch_reg(jit, Condition::GE, false, ARM_SCRATCH[0], dst, target_pc)
                }
                ebpf::JSGE_REG    => emit_conditional_branch_reg(jit, Condition::GE, false, src, dst, target_pc),
                ebpf::JSLT_IMM    => {
                    emit_load_immediate64(jit, ARM_SCRATCH[0], insn.imm as u64);
                    emit_conditional_branch_reg(jit, Condition::LT, false, ARM_SCRATCH[0], dst, target_pc)
                }
                ebpf::JSLT_REG    => emit_conditional_branch_reg(jit, Condition::LT, false, src, dst, target_pc),
                ebpf::JSLE_IMM    => {
                    emit_load_immediate64(jit, ARM_SCRATCH[0], insn.imm as u64);
                    emit_conditional_branch_reg(jit, Condition::LE, false, ARM_SCRATCH[0], dst, target_pc)
                }
                ebpf::JSLE_REG    => emit_conditional_branch_reg(jit, Condition::LE, false, src, dst, target_pc),
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
                            emit_load_immediate64(jit, ARM_SCRATCH[0], syscall.function as *const u8 as u64);

                            emit_load_immediate64(jit, ARM_SCRATCH[1], (( SYSCALL_CONTEXT_OBJECTS_OFFSET + syscall.context_object_slot) as i32 * 8 + jit.program_argument_key ) as u64);
                            emit_ins(jit, ARM64Instruction::load(OperandSize::S64, JIT_PROGRAM_ARGUMENT, ARM64MemoryOperand::OffsetIndexShift(ARM_SCRATCH[1], false), ARM_SCRATCH[1]));

                            emit_call_anchor(jit, ANCHOR_SYSCALL);
                            if jit.config.enable_instruction_meter {
                                emit_undo_profile_instruction_count(jit, 0);
                            }
                            // Throw error if the result indicates one
                            emit_ins(jit, ARM64Instruction::load(OperandSize::S64, ARM_SCRATCH[0], ARM64MemoryOperand::Offset(0), ARM_SCRATCH[0]));
                            emit_ins(jit, ARM64Instruction::cmp_imm(OperandSize::S64, ARM_SCRATCH[0], 0));
                            emit_load_immediate64(jit, ARM_SCRATCH[0], jit.pc as u64);
                            emit_bcond(jit, Condition::NE, jit.relative_to_anchor(ANCHOR_RUST_EXCEPTION, 0));

                            resolved = true;
                        }
                    }

                    if calls {
                        if let Some(target_pc) = executable.lookup_bpf_function(insn.imm as u32) {
                            emit_bpf_call(jit, Value::Constant64(target_pc as u64, false));
                            resolved = true;
                        }
                    }

                    if !resolved {
                        emit_load_immediate64(jit, CUR_JIT_PC, jit.pc as u64);
                        emit_jmp(jit, jit.relative_to_anchor(ANCHOR_CALL_UNSUPPORTED_INSTRUCTION, 0));
                    }
                },
                ebpf::CALL_REG  => {
                    emit_bpf_call(jit, Value::Register(REGISTER_MAP[insn.imm as usize]));
                },
                ebpf::EXIT      => {
                    emit_load_env(jit, EnvironmentStackSlotARM64::CallDepth, REGISTER_MAP[FRAME_PTR_REG]);

                    // If CallDepth == 0, we've reached the exit instruction of the entry point
                    emit_ins(jit, ARM64Instruction::cmp_imm(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], 0));
                    if jit.config.enable_instruction_meter {
                        emit_load_immediate64(jit, CUR_JIT_PC, jit.pc as u64);
                    }
                    // we're done
                    emit_bcond(jit, Condition::EQ, jit.relative_to_anchor(ANCHOR_EXIT, 0));

                    // else decrement and update CallDepth
                    emit_ins(jit, ARM64Instruction::sub_imm(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], 1, REGISTER_MAP[FRAME_PTR_REG]));
                    emit_store_env(jit, REGISTER_MAP[FRAME_PTR_REG], EnvironmentStackSlotARM64::CallDepth, ARM_SCRATCH[0]);

                    // and return
                    Self::emit_validate_and_profile_instruction_count(jit, false, Some(0));
                    emit_ins(jit, ARM64Instruction::ret());
                },

                _               => return Err(EbpfError::UnsupportedInstruction(jit.pc + ebpf::ELF_INSN_DUMP_OFFSET)),
            }
        Ok(())
    }
    fn generate_subroutines<E: UserDefinedError, I: InstructionMeter>(jit: &mut JitCompilerCore) {
        // Epilogue
        jit.set_anchor(ANCHOR_EPILOGUE);

        // Print stop watch value
        fn stopwatch_result(numerator: u64, denominator: u64) {
            println!("Stop watch: {} / {} = {}", numerator, denominator, if denominator == 0 { 0.0 } else { numerator as f64 / denominator as f64 });
        }
        if jit.stopwatch_is_active {
            emit_rust_call(jit, Value::Constant64(stopwatch_result as *const u8 as u64, false), &[
                Argument { index: 1, value: Value::EnvironmentStackSlotARM64(EnvironmentStackSlotARM64::StopwatchDenominator) },
                Argument { index: 0, value: Value::EnvironmentStackSlotARM64(EnvironmentStackSlotARM64::StopwatchNumerator) },
            ], None, false);
        }

        // Restore stack pointer in case the BPF stack was used
        emit_load_immediate64(jit, ARM_SCRATCH[0], slot_on_environment_stack(jit, EnvironmentStackSlotARM64::LastSavedRegister) as u64);

        emit_ins(jit, ARM64Instruction::add(OperandSize::S64, ARM_SCRATCH[0], ENV_REG, ARM_SCRATCH[0]));
        emit_ins(jit, ARM64Instruction::add_imm(OperandSize::S64, ARM_SCRATCH[0], 0, SP_XZR)); // have to use add_imm to write to SP

        // Restore registers
        for (lowest_slot, reg) in CALLEE_SAVED_REGISTERS.iter().rev().enumerate() {
            emit_ins(jit, ARM64Instruction::load(OperandSize::S64, SP_XZR, ARM64MemoryOperand::Offset(8 * lowest_slot as i16), *reg));
        }
        debug_assert!(CALLEE_SAVED_REGISTERS.len() % 2 == 0);
        emit_ins(jit, ARM64Instruction::add_imm(OperandSize::S64, SP_XZR, CALLEE_SAVED_REGISTERS.len() as u16 * 8, SP_XZR));

        emit_ins(jit, ARM64Instruction::ret());

        // Routine for instruction tracing
        if jit.config.enable_instruction_tracing {
            jit.set_anchor(ANCHOR_TRACE);
            //emit_ins(jit, ARM64Instruction::push64(ARM_SCRATCH[1]));
            debug_assert!(REGISTER_MAP.len() % 2 == 1);
            emit_ins(jit, ARM64Instruction::sub_imm(OperandSize::S64, SP_XZR, 8 * ( REGISTER_MAP.len() as u16 + 1 ), SP_XZR));
            for (i, reg) in REGISTER_MAP.iter().enumerate() {
                emit_ins(jit, ARM64Instruction::store(OperandSize::S64, *reg, SP_XZR, ARM64MemoryOperand::Offset((i * 8) as i16)));
            }
            emit_ins(jit, ARM64Instruction::store(OperandSize::S64, ARM_SCRATCH[0], SP_XZR, ARM64MemoryOperand::Offset(REGISTER_MAP.len() as i16 * 8)));
            emit_ins(jit, ARM64Instruction::add_imm(OperandSize::S64, SP_XZR, 0, REGISTER_MAP[0])); // must use add_imm because mov uses XZR instead of SP
            emit_ins(jit, ARM64Instruction::sub_imm(OperandSize::S64, SP_XZR, 8 * 4, SP_XZR));
            emit_load_immediate64(jit, ARM_SCRATCH[1], (mem::size_of::<MemoryMapping>() as i32 + jit.program_argument_key) as u64);
            emit_rust_call(jit, Value::Constant64(Tracer::trace as *const u8 as u64, false), &[
                Argument { index: 1, value: Value::Register(REGISTER_MAP[0]) }, // registers
                Argument { index: 0, value: Value::RegisterIndirect(JIT_PROGRAM_ARGUMENT, ARM64MemoryOperand::OffsetIndexShift(ARM_SCRATCH[1], false), false) }, // jit.tracer
            ], None, false);
            // Pop stack and return
            emit_ins(jit, ARM64Instruction::add_imm(OperandSize::S64, SP_XZR, 8 * 4, SP_XZR));
            emit_ins(jit, ARM64Instruction::load(OperandSize::S64, SP_XZR, ARM64MemoryOperand::Offset(0), REGISTER_MAP[0]));
            emit_ins(jit, ARM64Instruction::add_imm(OperandSize::S64, SP_XZR, (8 * (REGISTER_MAP.len() + 1)) as u16, SP_XZR)); // RSP += 8 * (REGISTER_MAP.len() + 1);

            //emit_ins(jit, ARM64Instruction::pop64(ARM_SCRATCH[1]));
            emit_ins(jit, ARM64Instruction::load(OperandSize::S64, SP_XZR, ARM64MemoryOperand::Offset(-8), ARM_SCRATCH[0]));
            emit_ins(jit, ARM64Instruction::ret());
        }

        // Handler for EbpfError::ExceededMaxInstructions
        jit.set_anchor(ANCHOR_CALL_EXCEEDED_MAX_INSTRUCTIONS);
        emit_set_exception_kind::<E>(jit, EbpfError::ExceededMaxInstructions(0, 0));
        emit_ins(jit, ARM64Instruction::mov(OperandSize::S64, BPF_PROGRAM_COUNTER, ARM_SCRATCH[0])); // R11 = instruction_meter;
        emit_profile_instruction_count_finalize(jit, true);
        emit_jmp(jit, jit.relative_to_anchor(ANCHOR_EPILOGUE, 0));

        // Handler for exceptions which report their pc
        jit.set_anchor(ANCHOR_EXCEPTION_AT);
        // Validate that we did not reach the instruction meter limit before the exception occured
        emit_ins(jit, ARM64Instruction::mov(OperandSize::S64, CUR_JIT_PC, ARM_SCRATCH[0]));
        if jit.config.enable_instruction_meter {
            Self::emit_validate_instruction_count(jit, false, None);
        }
        emit_ins(jit, ARM64Instruction::mov(OperandSize::S64, CUR_JIT_PC, ARM_SCRATCH[0]));
        emit_profile_instruction_count_finalize(jit, true);
        emit_jmp(jit, jit.relative_to_anchor(ANCHOR_EPILOGUE, 0));


        // Handler for EbpfError::CallDepthExceeded
        jit.set_anchor(ANCHOR_CALL_DEPTH_EXCEEDED);
        emit_set_exception_kind::<E>(jit, EbpfError::CallDepthExceeded(0, 0));
        emit_load_immediate64(jit, ARM_SCRATCH[1], jit.config.max_call_depth as u64);
        emit_ins(jit, ARM64Instruction::store(OperandSize::S64, ARM_SCRATCH[1], JIT_PROGRAM_ARGUMENT, ARM64MemoryOperand::Offset(24))); // depth = jit.config.max_call_depth;
        emit_jmp(jit, jit.relative_to_anchor(ANCHOR_EXCEPTION_AT, 0));

        // Handler for EbpfError::CallOutsideTextSegment
        jit.set_anchor(ANCHOR_CALL_OUTSIDE_TEXT_SEGMENT);
        emit_set_exception_kind::<E>(jit, EbpfError::CallOutsideTextSegment(0, 0));
        emit_ins(jit, ARM64Instruction::store(OperandSize::S64, REGISTER_MAP[0], JIT_PROGRAM_ARGUMENT, ARM64MemoryOperand::Offset(24))); // target_address = RAX;
        emit_jmp(jit, jit.relative_to_anchor(ANCHOR_EXCEPTION_AT, 0));

        // Handler for EbpfError::DivideByZero
        jit.set_anchor(ANCHOR_DIV_BY_ZERO);
        emit_set_exception_kind::<E>(jit, EbpfError::DivideByZero(0));
        emit_jmp(jit, jit.relative_to_anchor(ANCHOR_EXCEPTION_AT, 0));

        // Handler for EbpfError::DivideOverflow
        jit.set_anchor(ANCHOR_DIV_OVERFLOW);
        emit_set_exception_kind::<E>(jit, EbpfError::DivideOverflow(0));
        emit_jmp(jit, jit.relative_to_anchor(ANCHOR_EXCEPTION_AT, 0));

        // Handler for EbpfError::UnsupportedInstruction
        jit.set_anchor(ANCHOR_CALLX_UNSUPPORTED_INSTRUCTION);
        // Load BPF target pc from stack (which was saved in ANCHOR_BPF_CALL_REG)
        emit_ins(jit, ARM64Instruction::load(OperandSize::S64, SP_XZR, ARM64MemoryOperand::Offset(-24), CUR_JIT_PC)); // R11 = RSP[-16];
        // Self::emit_jmp(jit, ANCHOR_CALL_UNSUPPORTED_INSTRUCTION); // Fall-through

        // Handler for EbpfError::UnsupportedInstruction
        jit.set_anchor(ANCHOR_CALL_UNSUPPORTED_INSTRUCTION);
        if jit.config.enable_instruction_tracing {
            emit_ins(jit, ARM64Instruction::mov(OperandSize::S64, CUR_JIT_PC, ARM_SCRATCH[0]));
            emit_call_anchor(jit, ANCHOR_TRACE);
        }
        emit_set_exception_kind::<E>(jit, EbpfError::UnsupportedInstruction(0));
        emit_jmp(jit, jit.relative_to_anchor(ANCHOR_EXCEPTION_AT, 0));

        // Quit gracefully
        jit.set_anchor(ANCHOR_EXIT);
        emit_ins(jit, ARM64Instruction::mov(OperandSize::S64, CUR_JIT_PC, ARM_SCRATCH[0]));
        Self::emit_validate_instruction_count(jit, false, None);
        emit_profile_instruction_count_finalize(jit, false);

        emit_load_immediate64(jit, ARM_SCRATCH[0], slot_on_environment_stack(jit, EnvironmentStackSlotARM64::OptRetValPtr) as u64);

        emit_ins(jit, ARM64Instruction::load(OperandSize::S64, ENV_REG, ARM64MemoryOperand::OffsetIndexShift(ARM_SCRATCH[0], false), JIT_PROGRAM_ARGUMENT));
        emit_ins(jit, ARM64Instruction::store(OperandSize::S64, REGISTER_MAP[0], JIT_PROGRAM_ARGUMENT, ARM64MemoryOperand::Offset(8))); // result.return_value = R0;
        emit_ins(jit, ARM64Instruction::store(OperandSize::S64, SP_XZR, JIT_PROGRAM_ARGUMENT, ARM64MemoryOperand::Offset(0)));  // result.is_error = false;
        emit_jmp(jit, jit.relative_to_anchor(ANCHOR_EPILOGUE, 0));


        // Handler for syscall exceptions
        jit.set_anchor(ANCHOR_RUST_EXCEPTION);
        emit_profile_instruction_count_finalize(jit, false);
        emit_jmp(jit, jit.relative_to_anchor(ANCHOR_EPILOGUE, 0));


        // Routine for syscall
        jit.set_anchor(ANCHOR_SYSCALL);
        emit_ins(jit, ARM64Instruction::push64(ARM_SCRATCH[0])); // Padding for stack alignment
        if jit.config.enable_instruction_meter {
            // RDI = *PrevInsnMeter - RDI;
            emit_load_env(jit, EnvironmentStackSlotARM64::PrevInsnMeter, ARM_SCRATCH[2]);
            emit_ins(jit, ARM64Instruction::sub(OperandSize::S64, ARM_SCRATCH[2], BPF_PROGRAM_COUNTER, BPF_PROGRAM_COUNTER));
            emit_rust_call(jit, Value::Constant64(I::consume as *const u8 as u64, false), &[
                Argument { index: 1, value: Value::Register(BPF_PROGRAM_COUNTER) },
                Argument { index: 0, value: Value::EnvironmentStackSlotARM64(EnvironmentStackSlotARM64::InsnMeterPtr) },
            ], None, false);
        }
        // emit_load_env(jit, EnvironmentStackSlotARM64::OptRetValPtr, XR);
        emit_rust_call(jit, Value::Register(ARM_SCRATCH[0]), &[
            Argument { index: 7, value: Value::EnvironmentStackSlotARM64(EnvironmentStackSlotARM64::OptRetValPtr) },
            Argument { index: 6, value: Value::RegisterPlusConstant64(JIT_PROGRAM_ARGUMENT, jit.program_argument_key as u64, false) }, // jit_program_argument.memory_mapping
            Argument { index: 5, value: Value::Register(ARGUMENT_REGISTERS[5]) },
            Argument { index: 4, value: Value::Register(ARGUMENT_REGISTERS[4]) },
            Argument { index: 3, value: Value::Register(ARGUMENT_REGISTERS[3]) },
            Argument { index: 2, value: Value::Register(ARGUMENT_REGISTERS[2]) },
            Argument { index: 1, value: Value::Register(ARGUMENT_REGISTERS[1]) },
            Argument { index: 0, value: Value::Register(ARM_SCRATCH[1]) }, // "&mut jit" in the "call" method of the SyscallObject
        ], None, false);
        if jit.config.enable_instruction_meter {
            emit_rust_call(jit, Value::Constant64(I::get_remaining as *const u8 as u64, false), &[
                Argument { index: 0, value: Value::EnvironmentStackSlotARM64(EnvironmentStackSlotARM64::InsnMeterPtr) },
            ], Some(BPF_PROGRAM_COUNTER), false);
            emit_store_env(jit, BPF_PROGRAM_COUNTER, EnvironmentStackSlotARM64::PrevInsnMeter, ARM_SCRATCH[0]);
        }
        emit_ins(jit, ARM64Instruction::pop64(ARM_SCRATCH[0]));
        // Store Ok value in result register
        emit_load_env(jit, EnvironmentStackSlotARM64::OptRetValPtr, ARM_SCRATCH[0]);
        emit_ins(jit, ARM64Instruction::load(OperandSize::S64, ARM_SCRATCH[0], ARM64MemoryOperand::Offset(8), REGISTER_MAP[0]));
        emit_ins(jit, ARM64Instruction::ret());
        // Routine for prologue of emit_bpf_call()
        // ARM_SCRATCH[0] holds current BPF pc
        jit.set_anchor(ANCHOR_BPF_CALL_PROLOGUE);
        emit_ins(jit, ARM64Instruction::sub_imm(OperandSize::S64, SP_XZR, 8 * (SCRATCH_REGS + 2) as u16, SP_XZR)); // alloca
        emit_ins(jit, ARM64Instruction::store(OperandSize::S64, LR, SP_XZR, ARM64MemoryOperand::Offset(0)));
        //emit_ins(jit, ARM64Instruction::store(OperandSize::S64, ARM_SCRATCH[0], SP_XZR, ARM64MemoryOperand::Offset(0)));
        //emit_ins(jit, ARM64Instruction::load(OperandSize::S64, SP_XZR, ARM64MemoryOperand::Offset(8 * (SCRATCH_REGS + 1) as i16), ARM_SCRATCH[0])); // load return address
        // The original x86 implementation trashes the old return address location (lol), and then
        // moves rsp accordingly.
        for (i, reg) in REGISTER_MAP.iter().skip(FIRST_SCRATCH_REG).take(SCRATCH_REGS).enumerate() {
            emit_ins(jit, ARM64Instruction::store(OperandSize::S64, *reg, SP_XZR, ARM64MemoryOperand::Offset(8 * (SCRATCH_REGS - i + 1) as i16))); // Push SCRATCH_REG
        }
        // Push the caller's frame pointer. The code to restore it is emitted at the end of emit_bpf_call().
        emit_ins(jit, ARM64Instruction::store(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], SP_XZR, ARM64MemoryOperand::Offset(8)));
        //X86Instruction::xchg(OperandSize::S64, ARM_SCRATCH[0], RSP, Some(X86IndirectAccess::OffsetIndexShift(0, RSP, 0))).emit(jit); // Push return address and restore original ARM_SCRATCH[0]

        // Increase CallDepth
        emit_load_env(jit, EnvironmentStackSlotARM64::CallDepth, ARM_SCRATCH[0]);
        emit_ins(jit, ARM64Instruction::add_imm(OperandSize::S64, ARM_SCRATCH[0], 1, ARM_SCRATCH[0]));
        emit_store_env(jit, ARM_SCRATCH[0], EnvironmentStackSlotARM64::CallDepth, ARM_SCRATCH[1]);
        emit_load_immediate64(jit, ARM_SCRATCH[1], jit.config.max_call_depth as u64);
        emit_ins(jit, ARM64Instruction::cmp(OperandSize::S64, ARM_SCRATCH[1], ARM_SCRATCH[0]));
        // If CallDepth >= jit.config.max_call_depth, stop and return CallDepthExceeded
        emit_bcond(jit, Condition::HS, jit.relative_to_anchor(ANCHOR_CALL_DEPTH_EXCEEDED, 0));

        // Setup the frame pointer for the new frame. What we do depends on whether we're using dynamic or fixed frames.
        if jit.config.dynamic_stack_frames {
            // When dynamic frames are on, the next frame starts at the end of the current frame
            emit_load_env(jit, EnvironmentStackSlotARM64::BpfStackPtr, REGISTER_MAP[FRAME_PTR_REG]);
            emit_store_env(jit, REGISTER_MAP[FRAME_PTR_REG], EnvironmentStackSlotARM64::BpfFramePtr, ARM_SCRATCH[0]);
        } else {
            // With fixed frames we start the new frame at the next fixed offset
            let stack_frame_size = jit.config.stack_frame_size as i64 * if jit.config.enable_stack_frame_gaps { 2 } else { 1 };
            emit_load_env(jit, EnvironmentStackSlotARM64::BpfFramePtr, REGISTER_MAP[FRAME_PTR_REG]);
            emit_load_immediate64(jit, ARM_SCRATCH[1], stack_frame_size as u64);
            emit_ins(jit, ARM64Instruction::add(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], ARM_SCRATCH[1], REGISTER_MAP[FRAME_PTR_REG]));
            emit_store_env(jit, REGISTER_MAP[FRAME_PTR_REG], EnvironmentStackSlotARM64::BpfFramePtr, ARM_SCRATCH[0]);
        }
        emit_ins(jit, ARM64Instruction::ret());

        // Routine for emit_bpf_call(Value::Register())
        // REGISTER_MAP[0] holds target BPF pc
        jit.set_anchor(ANCHOR_BPF_CALL_REG);
        // Force alignment of RAX
        emit_load_immediate64(jit, ARM_SCRATCH[0], !(INSN_SIZE as i64 -1) as u64);
        emit_ins(jit, ARM64Instruction::and(OperandSize::S64, REGISTER_MAP[0], ARM_SCRATCH[0], REGISTER_MAP[0])); // RAX &= !(INSN_SIZE - 1);
        // Upper bound check
        // if(RAX >= jit.program_vm_addr + number_of_instructions * INSN_SIZE) throw CALL_OUTSIDE_TEXT_SEGMENT;
        let number_of_instructions = jit.result.pc_section.len() - 1;
        emit_load_immediate64(jit, ARM_SCRATCH[1], jit.program_vm_addr as u64 + (number_of_instructions * INSN_SIZE) as u64);
        emit_ins(jit, ARM64Instruction::cmp(OperandSize::S64, ARM_SCRATCH[1], REGISTER_MAP[0]));
        emit_bcond(jit, Condition::HS, jit.relative_to_anchor(ANCHOR_CALL_OUTSIDE_TEXT_SEGMENT, 0));
        // Lower bound check
        // if(RAX < jit.program_vm_addr) throw CALL_OUTSIDE_TEXT_SEGMENT;
        emit_load_immediate64(jit, ARM_SCRATCH[1], jit.program_vm_addr as u64);
        emit_ins(jit, ARM64Instruction::cmp(OperandSize::S64, ARM_SCRATCH[1], REGISTER_MAP[0]));
        emit_bcond(jit, Condition::LO, jit.relative_to_anchor(ANCHOR_CALL_OUTSIDE_TEXT_SEGMENT, 0));
        // Calculate offset relative to instruction_addresses
        emit_ins(jit, ARM64Instruction::sub(OperandSize::S64, REGISTER_MAP[0], ARM_SCRATCH[1], REGISTER_MAP[0]));
        // Calculate the target_pc (dst / INSN_SIZE) to update the instruction_meter
        let shift_amount = INSN_SIZE.trailing_zeros();
        debug_assert_eq!(INSN_SIZE, 1 << shift_amount);
        emit_ins(jit, ARM64Instruction::mov(OperandSize::S64, REGISTER_MAP[0], ARM_SCRATCH[0]));
        emit_ins(jit, ARM64Instruction::lsr_imm(ARM_SCRATCH[0], shift_amount as u8, ARM_SCRATCH[0]));
        // Save BPF target pc for potential ANCHOR_CALLX_UNSUPPORTED_INSTRUCTION
        emit_ins(jit, ARM64Instruction::store(OperandSize::S64, ARM_SCRATCH[0], SP_XZR, ARM64MemoryOperand::Offset(-8))); // RSP[-8] = ARM_SCRATCH[0];
        // Load host target_address from jit.result.pc_section
        debug_assert_eq!(INSN_SIZE, 8); // Because the instruction size is also the slot size we do not need to shift the offset
        emit_load_immediate64(jit, ARM_SCRATCH[1], jit.result.pc_section.as_ptr() as u64);
        emit_ins(jit, ARM64Instruction::add(OperandSize::S64, REGISTER_MAP[0], ARM_SCRATCH[1], REGISTER_MAP[0]));
        emit_ins(jit, ARM64Instruction::load(OperandSize::S64, REGISTER_MAP[0], ARM64MemoryOperand::Offset(0), REGISTER_MAP[0])); // RAX = jit.result.pc_section[RAX / 8];
        emit_ins(jit, ARM64Instruction::ret());

        // Translates a host pc back to a BPF pc by linear search of the pc_section table
        jit.set_anchor(ANCHOR_TRANSLATE_PC);
        emit_load_immediate64(jit, ARM_SCRATCH[1], jit.result.pc_section.as_ptr() as u64 - 8); // Loop index and pointer to look up
        jit.set_anchor(ANCHOR_TRANSLATE_PC_LOOP); // Loop label
        emit_ins(jit, ARM64Instruction::add_imm(OperandSize::S64, ARM_SCRATCH[1], 8, ARM_SCRATCH[1])); // Increase index
        emit_ins(jit, ARM64Instruction::load(OperandSize::S64, ARM_SCRATCH[1], ARM64MemoryOperand::Offset(8), ARM_SCRATCH[2]));
        emit_ins(jit, ARM64Instruction::cmp(OperandSize::S64, ARM_SCRATCH[0], ARM_SCRATCH[2])); // Look up and compare against value at next index
        emit_bcond(jit, Condition::LS, jit.relative_to_anchor(ANCHOR_TRANSLATE_PC_LOOP, 0)); // Continue while *ARM_SCRATCH[1] <= ARM_SCRATCH[0]
        emit_ins(jit, ARM64Instruction::mov(OperandSize::S64, ARM_SCRATCH[1], CUR_JIT_PC)); // CUR_JIT_PC = ARM_SCRATCH[1];
        emit_load_immediate64(jit, ARM_SCRATCH[1], jit.result.pc_section.as_ptr() as u64); // ARM_SCRATCH[1] = jit.result.pc_section
        emit_ins(jit, ARM64Instruction::sub(OperandSize::S64, CUR_JIT_PC, ARM_SCRATCH[1], CUR_JIT_PC));
        emit_ins(jit, ARM64Instruction::lsr_imm(CUR_JIT_PC, 3, CUR_JIT_PC)); // CUR_JIT_PC >>= 3; divide by 8 to get the instruction index
        emit_ins(jit, ARM64Instruction::ret());

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
                16
            } else {
                0
            };

            jit.set_anchor(ANCHOR_MEMORY_ACCESS_VIOLATION + target_offset);
            emit_ins(jit, ARM64Instruction::load(OperandSize::S64, SP_XZR, ARM64MemoryOperand::Offset(stack_offset), ARM_SCRATCH[0]));

            // This is relying on the return value optimization
            emit_load_env(jit, EnvironmentStackSlotARM64::OptRetValPtr, XR);
            emit_rust_call(jit, Value::Constant64(MemoryMapping::generate_access_violation::<UserError> as *const u8 as u64, false), &[
                Argument { index: 2, value: Value::Register(ARM_SCRATCH[0]) }, // Specify first as the src register could be overwritten by other arguments
                Argument { index: 3, value: Value::Constant64(*len as u64, false) },
                Argument { index: 1, value: Value::Constant64(*access_type as u64, false) },
                Argument { index: 0, value: Value::RegisterPlusConstant64(JIT_PROGRAM_ARGUMENT, jit.program_argument_key as u64, false) }, // jit_program_argument.memory_mapping
            ], None, true);
            emit_ins(jit, ARM64Instruction::add_imm(OperandSize::S64, SP_XZR, stack_offset as u16 + 16, SP_XZR));
            emit_ins(jit, ARM64Instruction::mov(OperandSize::S64, LR, ARM_SCRATCH[0])); // Put callers PC in ARM_SCRATCH[0]
            emit_call_anchor(jit, ANCHOR_TRANSLATE_PC);
            emit_jmp(jit, jit.relative_to_anchor(ANCHOR_EXCEPTION_AT, 0));



            jit.set_anchor(ANCHOR_TRANSLATE_MEMORY_ADDRESS + target_offset);
            emit_ins(jit, ARM64Instruction::push64(ARM_SCRATCH[0]));
            if !jit.config.dynamic_stack_frames && jit.config.enable_stack_frame_gaps {
                emit_ins(jit, ARM64Instruction::push64(ARM_SCRATCH[1]));
            }
            emit_ins(jit, ARM64Instruction::mov(OperandSize::S64, ARM_SCRATCH[0], ARM_SCRATCH[1])); // ARM_SCRATCH[1] = vm_addr;
            emit_ins(jit, ARM64Instruction::lsr_imm(ARM_SCRATCH[1], ebpf::VIRTUAL_ADDRESS_BITS as u8, ARM_SCRATCH[1]));// ARM_SCRATCH[1] >>= ebpf::VIRTUAL_ADDRESS_BITS;

            emit_load_immediate64(jit, ARM_SCRATCH[2], (jit.program_argument_key + 8) as u64);
            emit_ins(jit, ARM64Instruction::load(OperandSize::S64, JIT_PROGRAM_ARGUMENT, ARM64MemoryOperand::OffsetIndexShift(ARM_SCRATCH[2], false), ARM_SCRATCH[2]));
            emit_ins(jit, ARM64Instruction::cmp(OperandSize::S64, ARM_SCRATCH[1], ARM_SCRATCH[2])); // region_index >= jit_program_argument.memory_mapping.regions.len()
            emit_bcond(jit, Condition::LS, jit.relative_to_anchor(ANCHOR_MEMORY_ACCESS_VIOLATION + target_offset, 0));
            debug_assert_eq!(1 << 5, mem::size_of::<MemoryRegion>());
            emit_ins(jit, ARM64Instruction::lsl_imm(ARM_SCRATCH[1], 5, ARM_SCRATCH[1]));// ARM_SCRATCH[1] *= mem::size_of::<MemoryRegion>();

            emit_load_immediate64(jit, ARM_SCRATCH[2], (jit.program_argument_key) as u64);
            emit_ins(jit, ARM64Instruction::load(OperandSize::S64, JIT_PROGRAM_ARGUMENT, ARM64MemoryOperand::OffsetIndexShift(ARM_SCRATCH[2], false), ARM_SCRATCH[2]));
            emit_ins(jit, ARM64Instruction::add(OperandSize::S64, ARM_SCRATCH[1], ARM_SCRATCH[2], ARM_SCRATCH[1]));
            if *access_type == AccessType::Store {
                emit_ins(jit, ARM64Instruction::load(OperandSize::S8, ARM_SCRATCH[1], ARM64MemoryOperand::Offset(MemoryRegion::IS_WRITABLE_OFFSET as i16), ARM_SCRATCH[2]));
                emit_ins(jit, ARM64Instruction::cmp(OperandSize::S8, ARM_SCRATCH[2], SP_XZR));
                emit_bcond(jit, Condition::EQ, jit.relative_to_anchor(ANCHOR_MEMORY_ACCESS_VIOLATION + target_offset, 0));
            }
            emit_ins(jit, ARM64Instruction::load(OperandSize::S64, ARM_SCRATCH[1], ARM64MemoryOperand::Offset(MemoryRegion::VM_ADDR_OFFSET as i16), ARM_SCRATCH[2])); // ARM_SCRATCH[2] = region.vm_addr
            emit_ins(jit, ARM64Instruction::cmp(OperandSize::S64, ARM_SCRATCH[2], ARM_SCRATCH[0])); // vm_addr < region.vm_addr
            emit_bcond(jit, Condition::LO, jit.relative_to_anchor(ANCHOR_MEMORY_ACCESS_VIOLATION + target_offset, 0));
            emit_ins(jit, ARM64Instruction::sub(OperandSize::S64, ARM_SCRATCH[0], ARM_SCRATCH[2], ARM_SCRATCH[0]));
            if !jit.config.dynamic_stack_frames && jit.config.enable_stack_frame_gaps {
                emit_ins(jit, ARM64Instruction::load(OperandSize::S8, ARM_SCRATCH[1], ARM64MemoryOperand::Offset(MemoryRegion::VM_GAP_SHIFT_OFFSET as i16), ARM_SCRATCH[2])); // ARM_SCRATCH[2] = region.vm_gap_shift;
                emit_ins(jit, ARM64Instruction::lsr_reg(OperandSize::S64, ARM_SCRATCH[0], ARM_SCRATCH[2], ARM_SCRATCH[3])); // ARM_SCRATCH[3] = ARM_SCRATCH[0] >> region.vm_gap_shift;
                emit_ins(jit, ARM64Instruction::tst_imm(ARM_SCRATCH[3], ARM64BitwiseImm::ONE)); // (ARM_SCRATCH[3] & 1) != 0
                emit_bcond(jit, Condition::NE, jit.relative_to_anchor(ANCHOR_MEMORY_ACCESS_VIOLATION + target_offset, 0));
                emit_ins(jit, ARM64Instruction::movn(ARM_SCRATCH[3], 0, 0)); // ARM_SCRATCH[3] = -1;

                emit_ins(jit, ARM64Instruction::lsl_reg(OperandSize::S64, ARM_SCRATCH[3], ARM_SCRATCH[2], ARM_SCRATCH[3])); // gap_mask = -1 << region.vm_gap_shift;

                emit_ins(jit, ARM64Instruction::mvn(OperandSize::S64, ARM_SCRATCH[3], ARM_SCRATCH[2])); // inverse_gap_mask = !gap_mask;
                emit_ins(jit, ARM64Instruction::and(OperandSize::S64, ARM_SCRATCH[0], ARM_SCRATCH[2], ARM_SCRATCH[2])); // below_gap = ARM_SCRATCH[0] & inverse_gap
                emit_ins(jit, ARM64Instruction::and(OperandSize::S64, ARM_SCRATCH[3], ARM_SCRATCH[0], ARM_SCRATCH[0])); // above_gap = ARM_SCRATCH[0] & gap_mask;
                emit_ins(jit, ARM64Instruction::lsr_imm(ARM_SCRATCH[0], 1, ARM_SCRATCH[0]));
                emit_ins(jit, ARM64Instruction::orr(OperandSize::S64, ARM_SCRATCH[2], ARM_SCRATCH[0])); // gapped_offset = above_gap | below_gap;
            }
            emit_ins(jit, ARM64Instruction::add_imm(OperandSize::S64, ARM_SCRATCH[0], *len as u16, ARM_SCRATCH[2]));
            emit_ins(jit, ARM64Instruction::load(OperandSize::S64, ARM_SCRATCH[1], ARM64MemoryOperand::Offset(MemoryRegion::LEN_OFFSET as i16), ARM_SCRATCH[3]));
            emit_ins(jit, ARM64Instruction::cmp(OperandSize::S64, ARM_SCRATCH[2], ARM_SCRATCH[3])); // region.len < ARM_SCRATCH[0] + len
            emit_bcond(jit, Condition::LO, jit.relative_to_anchor(ANCHOR_MEMORY_ACCESS_VIOLATION + target_offset, 0));
            emit_ins(jit, ARM64Instruction::load(OperandSize::S64, ARM_SCRATCH[1], ARM64MemoryOperand::Offset(MemoryRegion::HOST_ADDR_OFFSET as i16), ARM_SCRATCH[3]));

            emit_ins(jit, ARM64Instruction::add(OperandSize::S64, ARM_SCRATCH[0], ARM_SCRATCH[3], ARM_SCRATCH[0]));
            emit_ins(jit, ARM64Instruction::add_imm(OperandSize::S64, SP_XZR, 16 + stack_offset as u16, SP_XZR));
            emit_ins(jit, ARM64Instruction::ret());
        }
    }

    fn generate_prologue<E: UserDefinedError, I: InstructionMeter>(jit: &mut JitCompilerCore, executable: &Pin<Box<Executable<E, I>>>) {
        debug_assert!(EnvironmentStackSlotARM64::SlotCount as u16 % 2 == 0);
        emit_ins(jit, ARM64Instruction::sub_imm(OperandSize::S64, SP_XZR, 8 * EnvironmentStackSlotARM64::SlotCount as u16, SP_XZR));
        let mut last_slot = EnvironmentStackSlotARM64::SlotCount as i16 - 1;

        debug_assert!(CALLEE_SAVED_REGISTERS.len() == EnvironmentStackSlotARM64::LastSavedRegister as usize + 1);
        // Save registers
        for reg in CALLEE_SAVED_REGISTERS.iter() {
            emit_ins(jit, ARM64Instruction::store(OperandSize::S64, *reg, SP_XZR, ARM64MemoryOperand::Offset(8 * last_slot)));
            last_slot -= 1;
        }

        // Initialize CallDepth to 0
        emit_load_immediate64(jit, REGISTER_MAP[FRAME_PTR_REG], 0);
        emit_ins(jit, ARM64Instruction::store(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], SP_XZR, ARM64MemoryOperand::Offset(8 * last_slot)));
        last_slot -= 1;

        // Initialize the BPF frame and stack pointers (BpfFramePtr and BpfStackPtr)
        if jit.config.dynamic_stack_frames {
            // The stack is fully descending from MM_STACK_START + stack_size to MM_STACK_START
            emit_load_immediate64(jit, REGISTER_MAP[FRAME_PTR_REG], MM_STACK_START as u64 + jit.config.stack_size() as u64);
            // Push BpfFramePtr
            emit_ins(jit, ARM64Instruction::store(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], SP_XZR, ARM64MemoryOperand::Offset(8 * last_slot)));
            last_slot -= 1;
            // Push BpfStackPtr
            emit_ins(jit, ARM64Instruction::store(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], SP_XZR, ARM64MemoryOperand::Offset(8 * last_slot)));
            last_slot -= 1;
        } else {
            // The frames are ascending from MM_STACK_START to MM_STACK_START + stack_size. The stack within the frames is descending.
            emit_load_immediate64(jit, REGISTER_MAP[FRAME_PTR_REG], MM_STACK_START as u64 + jit.config.stack_frame_size as u64);
            // Push BpfFramePtr
            emit_ins(jit, ARM64Instruction::store(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], SP_XZR, ARM64MemoryOperand::Offset(8 * last_slot)));
            last_slot -= 1;
            // When using static frames BpfStackPtr is not used
            emit_load_immediate64(jit, ENV_REG, 0);
            emit_ins(jit, ARM64Instruction::store(OperandSize::S64, ENV_REG, SP_XZR, ARM64MemoryOperand::Offset(8 * last_slot)));
            last_slot -= 1;
        }

        // Save pointer to optional typed return value
        emit_ins(jit, ARM64Instruction::store(OperandSize::S64, ARGUMENT_REGISTERS[0], SP_XZR, ARM64MemoryOperand::Offset(8 * last_slot)));
        last_slot -= 1;

        // Save initial value of instruction_meter.get_remaining()
        emit_rust_call(jit, Value::Constant64(I::get_remaining as *const u8 as u64, false), &[
            Argument { index: 0, value: Value::Register(ARGUMENT_REGISTERS[3]) },
        ], Some(ARGUMENT_REGISTERS[0]), false);

        emit_ins(jit, ARM64Instruction::store(OperandSize::S64, ARGUMENT_REGISTERS[0], SP_XZR, ARM64MemoryOperand::Offset(8 * last_slot)));
        last_slot -= 1;

        // Save instruction meter
        emit_ins(jit, ARM64Instruction::store(OperandSize::S64, ARGUMENT_REGISTERS[3], SP_XZR, ARM64MemoryOperand::Offset(8 * last_slot)));
        last_slot -= 1;

        // Initialize stop watch
        emit_ins(jit, ARM64Instruction::eor(OperandSize::S64, ARM_SCRATCH[0], ARM_SCRATCH[0]));
        emit_ins(jit, ARM64Instruction::store(OperandSize::S64, ARM_SCRATCH[0], SP_XZR, ARM64MemoryOperand::Offset(8 * last_slot)));
        last_slot -= 1;

        emit_ins(jit, ARM64Instruction::store(OperandSize::S64, ARM_SCRATCH[0], SP_XZR, ARM64MemoryOperand::Offset(8 * last_slot)));
        debug_assert!(last_slot == 0);

        // Initialize frame pointer
        // NOTE: ORR is the default used for MOV. ORR uses XZR. Here we use ADD (imm) instead, which uses
        // SP
        emit_ins(jit, ARM64Instruction::add_imm(OperandSize::S64, SP_XZR, 0, ENV_REG));
        emit_load_immediate64(jit, ARM_SCRATCH[0], (8 * (EnvironmentStackSlotARM64::SlotCount as i64 - 1 + jit.environment_stack_key as i64)) as u64);
        emit_ins(jit, ARM64Instruction::add(OperandSize::S64, ENV_REG, ARM_SCRATCH[0], ENV_REG)); // ENV_REG += ARM_SCRATCH[0]

        // Save JitProgramArgument
        emit_load_immediate64(jit, ARM_SCRATCH[0], (-jit.program_argument_key) as u64);
        emit_ins(jit, ARM64Instruction::add(OperandSize::S64, ARM_SCRATCH[0], ARGUMENT_REGISTERS[2], JIT_PROGRAM_ARGUMENT));

        // Zero BPF registers
        for reg in REGISTER_MAP.iter() {
            if *reg != REGISTER_MAP[1] && *reg != REGISTER_MAP[FRAME_PTR_REG] {
                emit_load_immediate64(jit, *reg, 0);
            }
        }

        // Jump to entry point
        let entry = executable.get_entrypoint_instruction_offset().unwrap_or(0);
        if jit.config.enable_instruction_meter {
            Self::emit_profile_instruction_count(jit, Some(entry + 1));
        }
        emit_load_immediate64(jit, ARM_SCRATCH[0], entry as u64);
        let jump_offset = jit.relative_to_target_pc_arm64(entry, FixupType::JUMP as u8);
        emit_jmp(jit, jump_offset);
    }

    #[inline]
    fn emit_validate_instruction_count(jit: &mut JitCompilerCore, exclusive: bool, pc: Option<usize>) {
        if let Some(pc) = pc {
            jit.last_instruction_meter_validation_pc = pc;
            emit_load_immediate64(jit, ARM_SCRATCH[1], pc as u64 + 1);
            emit_ins(jit, ARM64Instruction::cmp(OperandSize::S64, ARM_SCRATCH[1], BPF_PROGRAM_COUNTER));
        } else {
            emit_ins(jit, ARM64Instruction::cmp(OperandSize::S64, ARM_SCRATCH[0], BPF_PROGRAM_COUNTER));
        }
        emit_bcond(jit, if exclusive { Condition::LO } else { Condition::LS }, jit.relative_to_anchor(ANCHOR_CALL_EXCEEDED_MAX_INSTRUCTIONS, 0));
    }

    #[inline]
    fn emit_profile_instruction_count(jit: &mut JitCompilerCore, target_pc: Option<usize>) {
        match target_pc {
            Some(target_pc) => {
                emit_load_immediate64(jit, ARM_SCRATCH[0], (target_pc as i64 - jit.pc as i64 - 1) as u64);
                emit_ins(jit, ARM64Instruction::add(OperandSize::S64, ARM_SCRATCH[0], BPF_PROGRAM_COUNTER, BPF_PROGRAM_COUNTER));
            },
            None => {
                emit_load_immediate64(jit, ARM_SCRATCH[1], jit.pc as u64 + 1);
                emit_ins(jit, ARM64Instruction::sub(OperandSize::S64, BPF_PROGRAM_COUNTER, ARM_SCRATCH[1], BPF_PROGRAM_COUNTER)); // instruction_meter -= jit.pc + 1;

                emit_ins(jit, ARM64Instruction::add(OperandSize::S64, BPF_PROGRAM_COUNTER, ARM_SCRATCH[0], BPF_PROGRAM_COUNTER)); // instruction_meter += target_pc;
            },
        }
    }
    #[inline]
    fn emit_overrun<E: UserDefinedError>(jit: &mut JitCompilerCore) {
        emit_set_exception_kind::<E>(jit, EbpfError::ExecutionOverrun(0));
        emit_load_immediate64(jit, CUR_JIT_PC, jit.pc as u64);
        emit_jmp(jit, jit.relative_to_anchor(ANCHOR_EXCEPTION_AT, 0));
    }

    fn fixup_text_jumps(jit: &mut JitCompilerCore) {
        for jump in &jit.text_section_jumps {
            let destination = jit.result.pc_section[jump.target_pc] as *const u8;
            let offset_value =
                ( unsafe { destination.offset_from(jump.location) } as i32 ) / 4; // Relative jump
            let mut inst = unsafe { ptr::read_unaligned(jump.location as *const u32) };
            match jump.fixup_type {
                x if x == FixupType::IMM26 as u8 => {
                    assert!((-(1 << 25)..(1 << 25)).contains(&offset_value));
                    // b or bl with an imm26
                    inst |= (offset_value as u32) & ((1u32 << 26) - 1);
                },
                x if x == FixupType::IMM19 as u8 => {
                    assert!((-(1 << 18)..(1 << 18)).contains(&offset_value));
                    // b.cond with a imm19
                    inst |= ((offset_value as u32) & ((1u32 << 19) - 1)) << 5;
                },
                _ => unreachable!()
            }
            unsafe {
                ptr::write_unaligned(
                    jump.location as *mut u32,
                    inst,
                );
            }
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
    ARGUMENT_REGISTERS[6],
    ARGUMENT_REGISTERS[7],
    CALLEE_SAVED_REGISTERS[4],
    CALLEE_SAVED_REGISTERS[5],
    CALLEE_SAVED_REGISTERS[1],
];

const ARM_SCRATCH: [u8; 4] = [
    CALLER_SAVED_REGISTERS[1],
    CALLER_SAVED_REGISTERS[2],
    CALLER_SAVED_REGISTERS[3],
    CALLER_SAVED_REGISTERS[4]
];

// Special registers:
//   X0  BPF program counter limit (used by instruction meter)
//   X10, X11, X12 Scratch register
//   X13 Constant pointer to JitProgramArgument (also scratch register for exception handling)
//   X19 Constant pointer to inital RSP - 8
const ENV_REG: u8 = CALLEE_SAVED_REGISTERS[0];
const JIT_PROGRAM_ARGUMENT: u8 = CALLER_SAVED_REGISTERS[5];
const BPF_PROGRAM_COUNTER: u8 = ARGUMENT_REGISTERS[0];
const CUR_JIT_PC: u8 = CALLER_SAVED_REGISTERS[6];

#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
enum FixupType {
    IMM26 = 1, // for B, BL
    IMM19 = 2 // for B.cond
}
impl FixupType {
    pub const CALL: FixupType = FixupType::IMM26;
    pub const JUMP: FixupType = FixupType::IMM26;
    pub const COND_JUMP: FixupType = FixupType::IMM19;
}

struct Argument {
    index: usize,
    value: Value,
}

enum Value {
    Register(u8),
    RegisterIndirect(u8, ARM64MemoryOperand, bool),
    EnvironmentStackSlotARM64(EnvironmentStackSlotARM64),
    RegisterPlusConstant64(u8, u64, bool),
    Constant64(u64, bool),
}

impl Argument {
    fn is_stack_argument(&self) -> bool {
        debug_assert!(self.index < ARGUMENT_REGISTERS.len());
        self.index >= ARGUMENT_REGISTERS.len()
    }

    fn get_argument_register(&self) -> u8 {
        ARGUMENT_REGISTERS[self.index]
    }

    fn emit_pass(&self, jit: &mut JitCompilerCore) {
        let is_stack_argument = self.is_stack_argument();
        let dst = if is_stack_argument {
            ARM_SCRATCH[0]
        } else {
            self.get_argument_register()
        };
        match self.value {
            Value::Register(reg) => {
                if is_stack_argument {
                    emit_ins(jit, ARM64Instruction::push64(reg));
                } else if reg != dst {
                    emit_ins(jit, ARM64Instruction::mov(OperandSize::S64, reg, dst));
                }
            },
            Value::RegisterIndirect(reg, mem_op, user_provided) => {
                debug_assert!(!user_provided);
                emit_ins(jit, ARM64Instruction::load(OperandSize::S64, reg, mem_op, dst));
                if is_stack_argument {
                    emit_ins(jit, ARM64Instruction::push64(dst));
                }
            },
            Value::EnvironmentStackSlotARM64(slot) => {
                emit_load_immediate64(jit, ARM_SCRATCH[0], slot_on_environment_stack(jit, slot) as u64);
                emit_ins(jit, ARM64Instruction::load(OperandSize::S64, ENV_REG, ARM64MemoryOperand::OffsetIndexShift(ARM_SCRATCH[0], false), dst));
                if is_stack_argument {
                    emit_ins(jit, ARM64Instruction::push64(dst));
                }
            },
            Value::RegisterPlusConstant64(reg, offset, user_provided) => {
                debug_assert!(!user_provided);
                emit_load_immediate64(jit, dst, offset);
                emit_ins(jit, ARM64Instruction::add(OperandSize::S64, dst, reg, dst));
                if is_stack_argument {
                    emit_ins(jit, ARM64Instruction::push64(dst));
                }
            },
            Value::Constant64(value, user_provided) => {
                debug_assert!(!user_provided && !is_stack_argument);
                emit_load_immediate64(jit, dst, value);
            },
        }
    }
}

#[inline]
fn emit_bpf_call(jit: &mut JitCompilerCore, dst: Value) {
    // Store PC in case the bounds check fails
    emit_load_immediate64(jit, CUR_JIT_PC, jit.pc as u64);
    emit_ins(jit, ARM64Instruction::push64(LR));
    emit_call_nosavelr(jit, jit.relative_to_anchor(ANCHOR_BPF_CALL_PROLOGUE, 0));
    emit_ins(jit, ARM64Instruction::load(OperandSize::S64, SP_XZR, ARM64MemoryOperand::Offset(8 * ( SCRATCH_REGS+2 ) as i16), LR));

    match dst {
        Value::Register(reg) => {
            // Move vm target_address into RAX
            emit_ins(jit, ARM64Instruction::push64(REGISTER_MAP[0]));
            if reg != REGISTER_MAP[0] {
                emit_ins(jit, ARM64Instruction::mov(OperandSize::S64, reg, REGISTER_MAP[0]));
            }
            emit_call_anchor(jit, ANCHOR_BPF_CALL_REG);

            JitCompilerARM64::emit_validate_and_profile_instruction_count(jit, false, None);
            emit_ins(jit, ARM64Instruction::mov(OperandSize::S64, REGISTER_MAP[0], ARM_SCRATCH[0])); // Save jump target vaddar
            emit_ins(jit, ARM64Instruction::pop64(REGISTER_MAP[0])); // Restore RAX
            emit_ins(jit, ARM64Instruction::push64(LR));
            emit_ins(jit, ARM64Instruction::blr(ARM_SCRATCH[0])); // the actual call
            emit_ins(jit, ARM64Instruction::pop64(LR));
        },
        Value::Constant64(target_pc, user_provided) => {
            debug_assert!(!user_provided);
            JitCompilerARM64::emit_validate_and_profile_instruction_count(jit, false, Some(target_pc as usize));
            emit_load_immediate64(jit, CUR_JIT_PC, target_pc as u64);
            emit_call_targetpc(jit, target_pc as usize);
        },
        _ => {
            #[cfg(debug_assertions)]
            unreachable!();
        }
    }

    emit_undo_profile_instruction_count(jit, 0);

    // Restore the previous frame pointer
    emit_ins(jit, ARM64Instruction::load(OperandSize::S64, SP_XZR, ARM64MemoryOperand::Offset(8), REGISTER_MAP[FRAME_PTR_REG]));
    emit_store_env(jit, REGISTER_MAP[FRAME_PTR_REG], EnvironmentStackSlotARM64::BpfFramePtr, ARM_SCRATCH[0]);
    for (i, reg) in REGISTER_MAP.iter().skip(FIRST_SCRATCH_REG).take(SCRATCH_REGS).rev().enumerate() {
        emit_ins(jit, ARM64Instruction::load(OperandSize::S64, SP_XZR, ARM64MemoryOperand::Offset(16 + (i as i16 * 8)), *reg));
    }
    emit_ins(jit, ARM64Instruction::add_imm(OperandSize::S64, SP_XZR, 8 * (SCRATCH_REGS as u16 + 2) + 16, SP_XZR)); // consume everything that was pushed in the prologue, and consume the saved LR slot
}


#[inline]
fn emit_load_immediate64(jit: &mut JitCompilerCore, reg: u8, mut imm: u64) {
    emit_ins(jit, ARM64Instruction::mov(OperandSize::S64, SP_XZR, reg));

    let mut shift: u8 = 0;
    while imm != 0 {
        emit_ins(jit, ARM64Instruction::movk(reg, shift, imm as u16));
        imm >>= 16;
        shift += 1;
    }
}

#[inline]
fn emit_rust_call(jit: &mut JitCompilerCore, dst: Value, arguments: &[Argument], result_reg: Option<u8>, check_exception: bool) {
    let mut saved_registers = CALLER_SAVED_REGISTERS.to_vec();
    saved_registers.extend(ARGUMENT_REGISTERS);
    if let Some(reg) = result_reg {
        let dst = saved_registers.iter().position(|x| *x == reg);
        debug_assert!(dst.is_some());
        if let Some(dst) = dst {
            saved_registers.remove(dst);
        }
    }

    // Save registers on stack
    for reg in saved_registers.iter() {
        emit_ins(jit, ARM64Instruction::push64(*reg));
    }

    if matches!(dst, Value::Register(x) if x == ARM_SCRATCH[0]) {
        emit_ins(jit, ARM64Instruction::push64(ARM_SCRATCH[0]));
    }
    // Pass arguments
    let mut stack_arguments = 0;
    for argument in arguments {
        if argument.is_stack_argument() {
            stack_arguments += 1;
        }
        argument.emit_pass(jit);
    }

    if matches!(dst, Value::Register(x) if x == ARM_SCRATCH[0]) {
        emit_ins(jit, ARM64Instruction::pop64(ARM_SCRATCH[0]));
    }

    emit_ins(jit, ARM64Instruction::push64(LR));
    match dst {
        Value::Register(reg) => {
            emit_ins(jit, ARM64Instruction::blr(reg));
        },
        Value::Constant64(value, user_provided) => {
            debug_assert!(!user_provided);
            emit_load_immediate64(jit, ARM_SCRATCH[0], value as u64);
            emit_ins(jit, ARM64Instruction::blr(ARM_SCRATCH[0]));
        },
        _ => {
            #[cfg(debug_assertions)]
            unreachable!();
        }
    }
    emit_ins(jit, ARM64Instruction::pop64(LR));

    // Save returned value in result register
    if let Some(reg) = result_reg {
        emit_ins(jit, ARM64Instruction::mov(OperandSize::S64, X0, reg));
    }

    // Restore registers from stack
    emit_ins(jit, ARM64Instruction::add_imm(OperandSize::S64, SP_XZR, stack_arguments as u16 * 16, SP_XZR));
    for reg in saved_registers.iter().rev() {
        emit_ins(jit, ARM64Instruction::pop64(*reg));
    }

    if check_exception {
        // Test if result indicates that an error occured
        emit_load_immediate64(jit, ARM_SCRATCH[0], slot_on_environment_stack(jit, EnvironmentStackSlotARM64::OptRetValPtr) as u64);
        emit_ins(jit, ARM64Instruction::load(OperandSize::S64, ENV_REG, ARM64MemoryOperand::OffsetIndexShift(ARM_SCRATCH[0], false), ARM_SCRATCH[0]));
        emit_ins(jit, ARM64Instruction::load(OperandSize::S64, ARM_SCRATCH[0], ARM64MemoryOperand::Offset(0), ARM_SCRATCH[0]));
        emit_ins(jit, ARM64Instruction::cmp(OperandSize::S64, ARM_SCRATCH[0], SP_XZR));
    }
}

#[inline]
fn emit_profile_instruction_count_finalize(jit: &mut JitCompilerCore, store_pc_in_exception: bool) {
    if jit.config.enable_instruction_meter || store_pc_in_exception {
        emit_ins(jit, ARM64Instruction::add_imm(OperandSize::S64, ARM_SCRATCH[0], 1, ARM_SCRATCH[0]));
    }
    if jit.config.enable_instruction_meter {
        emit_ins(jit, ARM64Instruction::sub(OperandSize::S64, BPF_PROGRAM_COUNTER, ARM_SCRATCH[0], BPF_PROGRAM_COUNTER));
    }
    if store_pc_in_exception {
        emit_load_env(jit, EnvironmentStackSlotARM64::OptRetValPtr, JIT_PROGRAM_ARGUMENT);
        emit_load_immediate64(jit, ARM_SCRATCH[1], 1);
        emit_ins(jit, ARM64Instruction::store(OperandSize::S64, ARM_SCRATCH[1], JIT_PROGRAM_ARGUMENT, ARM64MemoryOperand::Offset(0))); // is_err = true;

        emit_load_immediate64(jit, ARM_SCRATCH[1], ebpf::ELF_INSN_DUMP_OFFSET as u64 - 1);
        emit_ins(jit, ARM64Instruction::add(OperandSize::S64, ARM_SCRATCH[0], ARM_SCRATCH[1], ARM_SCRATCH[0]));
        emit_ins(jit, ARM64Instruction::store(OperandSize::S64, ARM_SCRATCH[0], JIT_PROGRAM_ARGUMENT, ARM64MemoryOperand::Offset(16))); // pc = jit.pc + ebpf::ELF_INSN_DUMP_OFFSET;
    }
}

fn emit_undo_profile_instruction_count(jit: &mut JitCompilerCore, target_pc: usize) {
    if jit.config.enable_instruction_meter {
        emit_load_immediate64(jit, ARM_SCRATCH[3], (jit.pc as i64 + 1 - target_pc as i64) as u64);
        emit_ins(jit, ARM64Instruction::add(OperandSize::S64, BPF_PROGRAM_COUNTER, ARM_SCRATCH[3], BPF_PROGRAM_COUNTER));  // instruction_meter += (jit.pc + 1) - target_pc;
    }
}

#[inline]
fn emit_load_env(jit: &mut JitCompilerCore, env: EnvironmentStackSlotARM64, dst: u8) {
        emit_load_immediate64(jit, dst, slot_on_environment_stack(jit, env) as u64);
        emit_ins(jit, ARM64Instruction::load(OperandSize::S64, ENV_REG, ARM64MemoryOperand::OffsetIndexShift(dst, false), dst));
}

#[inline]
fn emit_store_env(jit: &mut JitCompilerCore, src: u8, env: EnvironmentStackSlotARM64, scratch: u8) {
        emit_load_immediate64(jit, scratch, slot_on_environment_stack(jit, env) as u64);
        emit_ins(jit, ARM64Instruction::store(OperandSize::S64, src, ENV_REG, ARM64MemoryOperand::OffsetIndexShift(scratch, false)));
}

#[inline]
fn emit_call_nosavelr(jit: &mut JitCompilerCore, target_pc: i32) {
    emit_ins(jit, ARM64Instruction::bl(target_pc / 4));
}
#[inline]
fn emit_call_anchor(jit: &mut JitCompilerCore, anchor: usize) {
    emit_ins(jit, ARM64Instruction::push64(LR));

    let jump_off = jit.relative_to_anchor(anchor, 0);
    emit_ins(jit, ARM64Instruction::bl(jump_off / 4));

    emit_ins(jit, ARM64Instruction::pop64(LR));
}
#[inline]
fn emit_call_targetpc(jit: &mut JitCompilerCore, target_pc: usize) {
    emit_ins(jit, ARM64Instruction::push64(LR));

    let jump_off = jit.relative_to_target_pc_arm64(target_pc, FixupType::CALL as u8);
    emit_ins(jit, ARM64Instruction::bl(jump_off / 4));

    emit_ins(jit, ARM64Instruction::pop64(LR));
}

#[inline]
fn emit_bcond(jit: &mut JitCompilerCore, cond: Condition, target_pc: i32) {
    emit_ins(jit, ARM64Instruction::b_cond(cond, target_pc / 4));
}

#[inline]
fn emit_jmp(jit: &mut JitCompilerCore, target_pc: i32) {
    emit_ins(jit, ARM64Instruction::b(target_pc / 4));
}


#[inline]
fn emit_conditional_branch_reg(jit: &mut JitCompilerCore, cond: Condition, bitwise: bool, first_operand: u8, second_operand: u8, target_pc: usize) {
    if first_operand == ARM_SCRATCH[0] {
        emit_ins(jit, ARM64Instruction::push64(ARM_SCRATCH[0]));
    }
    JitCompilerARM64::emit_validate_and_profile_instruction_count(jit, false, Some(target_pc));
    if first_operand == ARM_SCRATCH[0] {
        emit_ins(jit, ARM64Instruction::pop64(ARM_SCRATCH[0]));
    }
    if bitwise { // Logical
        emit_ins(jit, ARM64Instruction::tst(OperandSize::S64, first_operand, second_operand));
    } else { // Arithmetic
        emit_ins(jit, ARM64Instruction::cmp(OperandSize::S64, first_operand, second_operand));
    }
    emit_load_immediate64(jit, CUR_JIT_PC, target_pc as u64);
    let jump_off = jit.relative_to_target_pc_arm64(target_pc, FixupType::COND_JUMP as u8);
    emit_bcond(jit, cond, jump_off);
    emit_undo_profile_instruction_count(jit, target_pc);
}

#[inline]
fn emit_set_exception_kind<E: UserDefinedError>(jit: &mut JitCompilerCore, err: EbpfError<E>) {
    let err = Result::<u64, EbpfError<E>>::Err(err);
    let err_kind = unsafe { *(&err as *const _ as *const u64).offset(1) };
    emit_load_env(jit, EnvironmentStackSlotARM64::OptRetValPtr, JIT_PROGRAM_ARGUMENT);
    emit_load_immediate64(jit, ARM_SCRATCH[0], err_kind as u64);
    emit_ins(jit, ARM64Instruction::store(OperandSize::S64, ARM_SCRATCH[0], JIT_PROGRAM_ARGUMENT, ARM64MemoryOperand::Offset(8)));
}

#[inline]
fn emit_address_translation(jit: &mut JitCompilerCore, host_addr: u8, vm_addr: Value, len: u64, access_type: AccessType) {
    match vm_addr {
        Value::RegisterPlusConstant64(reg, constant, _user_provided) => {
            emit_load_immediate64(jit, ARM_SCRATCH[0], constant);
            emit_ins(jit, ARM64Instruction::add(OperandSize::S64, ARM_SCRATCH[0], reg, ARM_SCRATCH[0]));
        },
        Value::Constant64(constant, _user_provided) => {
            emit_load_immediate64(jit, ARM_SCRATCH[0], constant);
        },
        _ => {
            #[cfg(debug_assertions)]
            unreachable!();
        },
    }
    emit_call_anchor(jit, ANCHOR_TRANSLATE_MEMORY_ADDRESS + len.trailing_zeros() as usize + 4 * (access_type as usize));
    ARM64Instruction::mov(OperandSize::S64, ARM_SCRATCH[0], host_addr).emit(jit)
}

fn emit_muldivmod(jit: &mut JitCompilerCore, opc: u8, src: u8, dst: u8, imm: Option<i64>) {
    let mul = (opc & ebpf::BPF_ALU_OP_MASK) == (ebpf::MUL32_IMM & ebpf::BPF_ALU_OP_MASK);
    let div = (opc & ebpf::BPF_ALU_OP_MASK) == (ebpf::DIV32_IMM & ebpf::BPF_ALU_OP_MASK);
    let sdiv = (opc & ebpf::BPF_ALU_OP_MASK) == (ebpf::SDIV32_IMM & ebpf::BPF_ALU_OP_MASK);
    let modrm = (opc & ebpf::BPF_ALU_OP_MASK) == (ebpf::MOD32_IMM & ebpf::BPF_ALU_OP_MASK);
    let size = if (opc & ebpf::BPF_CLS_MASK) == ebpf::BPF_ALU64 { OperandSize::S64 } else { OperandSize::S32 };


    if (div || sdiv || modrm) && imm.is_none() {
        // Save pc
        emit_load_immediate64(jit, CUR_JIT_PC, jit.pc as u64);
        emit_ins(jit, ARM64Instruction::tst(size, src, src)); // src == 0
        emit_bcond(jit, Condition::EQ, jit.relative_to_anchor(ANCHOR_DIV_BY_ZERO, 0));
    }

    // sdiv overflows with MIN / -1. If we have an immediate and it's not -1, we
    // don't need any checks.
    if sdiv && imm.unwrap_or(-1) == -1 {
        emit_load_immediate64(jit, ARM_SCRATCH[1], 0);
        emit_load_immediate64(jit, ARM_SCRATCH[0], if let OperandSize::S64 = size { i64::MIN as u64 } else { i32::MIN as u64 });
        emit_ins(jit, ARM64Instruction::sub(size, dst, ARM_SCRATCH[0], ARM_SCRATCH[0]));
        if imm.is_none() {
            // if src != -1, we can skip checking dst
            emit_ins(jit, ARM64Instruction::movn(ARM_SCRATCH[1], 0, 0)); // ARM_SCRATCH[0] = -1;
            emit_ins(jit, ARM64Instruction::sub(size, src, ARM_SCRATCH[1], ARM_SCRATCH[1]));
        }

        // MIN / -1, raise EbpfError::DivideOverflow(pc)
        emit_load_immediate64(jit, CUR_JIT_PC, jit.pc as u64);
        emit_ins(jit, ARM64Instruction::orr(size, ARM_SCRATCH[0], ARM_SCRATCH[1]));
        emit_ins(jit, ARM64Instruction::tst(size, ARM_SCRATCH[1], ARM_SCRATCH[1]));
        emit_bcond(jit, Condition::EQ, jit.relative_to_anchor(ANCHOR_DIV_OVERFLOW, 0)); // zero flag means dst == MIN and SRC == -1
    }

    if let Some(imm) = imm {
        emit_load_immediate64(jit, ARM_SCRATCH[0], imm as u64);
    } else {
        emit_ins(jit, ARM64Instruction::mov(OperandSize::S64, src, ARM_SCRATCH[0]));
    }

    if div {
        emit_ins(jit, ARM64Instruction::udiv(size, dst, ARM_SCRATCH[0], dst));
    } else if sdiv {
        emit_ins(jit, ARM64Instruction::sdiv(size, dst, ARM_SCRATCH[0], dst));
    } else if mul {
        emit_ins(jit, ARM64Instruction::madd(size, dst, ARM_SCRATCH[0], SP_XZR, dst));
    } else {
        emit_ins(jit, ARM64Instruction::udiv(size, dst, ARM_SCRATCH[0], ARM_SCRATCH[1]));
        emit_ins(jit, ARM64Instruction::msub(size, ARM_SCRATCH[1], ARM_SCRATCH[0], dst, dst));
    }

    if size == OperandSize::S32 && (mul || sdiv)  {
        emit_ins(jit, ARM64Instruction::sign_extend_to_i64(OperandSize::S32, dst, dst));
    }
}

// This function helps the optimizer to inline the machinecode emission while avoiding stack allocations
#[inline(always)]
pub fn emit_ins(jit: &mut JitCompilerCore, instruction: ARM64Instruction) {
    instruction.emit(jit);
    if jit.next_noop_insertion == 0 {
        jit.next_noop_insertion = jit.diversification_rng.gen_range(0..jit.config.noop_instruction_rate * 2);
        // X86Instruction::noop().emit(jit)?;
        emit::<u32>(jit, 0xaa0003e0);
    } else {
        jit.next_noop_insertion -= 1;
    }
}

/// Indices of slots inside the struct at inital SP
#[derive(PartialEq, Eq, Copy, Clone)]
#[repr(C)]
pub enum EnvironmentStackSlotARM64 {
    /// The 12 CALLEE_SAVED_REGISTERS
    LastSavedRegister = 11,
    /// The current call depth.
    ///
    /// Incremented on calls and decremented on exits. It's used to enforce
    /// config.max_call_depth and to know when to terminate execution.
    CallDepth = 12,
    /// BPF frame pointer (REGISTER_MAP[FRAME_PTR_REG]).
    BpfFramePtr = 13,
    /// The BPF stack pointer (r11). Only used when config.dynamic_stack_frames=true.
    ///
    /// The stack pointer isn't exposed as an actual register. Only sub and add
    /// instructions (typically generated by the LLVM backend) are allowed to
    /// access it. Its value is only stored in this slot and therefore the
    /// register is not tracked in REGISTER_MAP.
    BpfStackPtr = 14,
    /// Constant pointer to optional typed return value
    OptRetValPtr = 15,
    /// Last return value of instruction_meter.get_remaining()
    PrevInsnMeter = 16,
    /// Constant pointer to instruction_meter
    InsnMeterPtr = 17,
    /// CPU cycles accumulated by the stop watch
    StopwatchNumerator = 18,
    /// Number of times the stop watch was used
    StopwatchDenominator = 19,
    /// Bumper for size_of
    SlotCount = 20,
}

pub fn slot_on_environment_stack(jit: &JitCompilerCore, slot: EnvironmentStackSlotARM64) -> i32 {
    -8 * (slot as i32 + jit.environment_stack_key)
}

