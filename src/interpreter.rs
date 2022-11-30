#![allow(clippy::integer_arithmetic)]
// Derived from uBPF <https://github.com/iovisor/ubpf>
// Copyright 2015 Big Switch Networks, Inc
//      (uBPF: VM architecture, parts of the interpreter, originally in C)
// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//      (Translation to Rust, MetaBuff/multiple classes addition, hashmaps for syscalls)
// Copyright 2020 Solana Maintainers <maintainers@solana.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Interpreter for eBPF programs.

use crate::{
    ebpf,
    ebpf::STACK_PTR_REG,
    error::EbpfError,
    memory_region::AccessType,
    verifier::Verifier,
    vm::{Config, ContextObject, EbpfVm, ProgramResult},
};

/// Translates a vm_addr into a host_addr and sets the pc in the error if one occurs
#[cfg_attr(feature = "debugger", macro_export)]
macro_rules! translate_memory_access {
    ($self:ident, $vm_addr:ident, $access_type:expr, $pc:ident, $T:ty) => {
        match $self.vm.env.memory_mapping.map(
            $access_type,
            $vm_addr,
            std::mem::size_of::<$T>() as u64,
        ) {
            ProgramResult::Ok(host_addr) => host_addr as *mut $T,
            ProgramResult::Err(EbpfError::AccessViolation(
                _pc,
                access_type,
                vm_addr,
                len,
                regions,
            )) => {
                return Err(EbpfError::AccessViolation(
                    $pc + ebpf::ELF_INSN_DUMP_OFFSET,
                    access_type,
                    vm_addr,
                    len,
                    regions,
                ));
            }
            ProgramResult::Err(EbpfError::StackAccessViolation(
                _pc,
                access_type,
                vm_addr,
                len,
                stack_frame,
            )) => {
                return Err(EbpfError::StackAccessViolation(
                    $pc + ebpf::ELF_INSN_DUMP_OFFSET,
                    access_type,
                    vm_addr,
                    len,
                    stack_frame,
                ));
            }
            _ => unreachable!(),
        }
    };
}

/// State of the interpreter during a debugging session
#[cfg(feature = "debugger")]
pub enum DebugState {
    /// Single step the interpreter
    Step,
    /// Continue execution till the end or till a breakpoint is hit
    Continue,
}

/// State of an interpreter
pub struct Interpreter<'a, 'b, V: Verifier, C: ContextObject> {
    pub(crate) vm: &'a mut EbpfVm<'b, V, C>,
    pub(crate) program: &'a [u8],
    pub(crate) program_vm_addr: u64,
    pub(crate) due_insn_count: u64,

    /// General purpose self.registers
    pub reg: [u64; 11],
    /// Program counter / instruction pointer
    pub pc: usize,

    #[cfg(feature = "debugger")]
    pub(crate) debug_state: DebugState,
    #[cfg(feature = "debugger")]
    pub(crate) breakpoints: Vec<u64>,
}

impl<'a, 'b, V: Verifier, C: ContextObject> Interpreter<'a, 'b, V, C> {
    /// Creates a new interpreter state
    pub fn new(
        vm: &'a mut EbpfVm<'b, V, C>,
        registers: [u64; 11],
        target_pc: usize,
    ) -> Result<Self, EbpfError> {
        let executable = vm.verified_executable.get_executable();
        let (program_vm_addr, program) = executable.get_text_bytes();
        Ok(Self {
            vm,
            program,
            program_vm_addr,
            due_insn_count: 0,
            reg: registers,
            pc: target_pc,
            #[cfg(feature = "debugger")]
            debug_state: DebugState::Continue,
            #[cfg(feature = "debugger")]
            breakpoints: Vec::new(),
        })
    }

    fn check_pc(&self, current_pc: usize, target_pc: usize) -> Result<usize, EbpfError> {
        let offset =
            target_pc
                .checked_mul(ebpf::INSN_SIZE)
                .ok_or(EbpfError::CallOutsideTextSegment(
                    current_pc + ebpf::ELF_INSN_DUMP_OFFSET,
                    self.program_vm_addr + (target_pc * ebpf::INSN_SIZE) as u64,
                ))?;
        let _ = self.program.get(offset..offset + ebpf::INSN_SIZE).ok_or(
            EbpfError::CallOutsideTextSegment(
                current_pc + ebpf::ELF_INSN_DUMP_OFFSET,
                self.program_vm_addr + (target_pc * ebpf::INSN_SIZE) as u64,
            ),
        )?;
        Ok(target_pc)
    }

    /// Translate between the virtual machines' pc value and the pc value used by the debugger
    #[cfg(feature = "debugger")]
    pub fn get_dbg_pc(&self) -> u64 {
        ((self.pc * ebpf::INSN_SIZE) as u64)
            + self
                .vm
                .verified_executable
                .get_executable()
                .get_text_section_offset()
    }

    fn push_frame(&mut self, config: &Config) -> Result<(), EbpfError> {
        let frame = &mut self.vm.env.call_frames[self.vm.env.call_depth as usize];
        frame.caller_saved_registers.copy_from_slice(
            &self.reg[ebpf::FIRST_SCRATCH_REG..ebpf::FIRST_SCRATCH_REG + ebpf::SCRATCH_REGS],
        );
        frame.frame_pointer = self.reg[ebpf::FRAME_PTR_REG];
        frame.target_pc = self.pc;

        self.vm.env.call_depth += 1;
        if self.vm.env.call_depth as usize == config.max_call_depth {
            return Err(EbpfError::CallDepthExceeded(
                self.pc + ebpf::ELF_INSN_DUMP_OFFSET - 1,
                config.max_call_depth,
            ));
        }

        if config.dynamic_stack_frames {
            // When dynamic frames are on, the next frame starts at the end of the current frame
            self.vm.env.frame_pointer = self.vm.env.stack_pointer;
        } else {
            // With fixed frames we start the new frame at the next fixed offset
            let stack_frame_size =
                config.stack_frame_size * if config.enable_stack_frame_gaps { 2 } else { 1 };
            self.vm.env.frame_pointer = self
                .vm
                .env
                .frame_pointer
                .overflowing_add(stack_frame_size as u64)
                .0;
        }
        self.reg[ebpf::FRAME_PTR_REG] = self.vm.env.frame_pointer;

        Ok(())
    }

    /// Advances the interpreter state by one instruction
    #[rustfmt::skip]
    pub fn step(&mut self) -> Result<Option<u64>, EbpfError> {
        let executable = self.vm.verified_executable.get_executable();
        let config = &executable.get_config();

        let mut instruction_width = 1;
        self.due_insn_count += 1;
        let pc = self.pc;
        self.pc += instruction_width;
        if self.pc * ebpf::INSN_SIZE > self.program.len() {
            return Err(EbpfError::ExecutionOverrun(
                pc + ebpf::ELF_INSN_DUMP_OFFSET,
            ));
        }
        let mut insn = ebpf::get_insn_unchecked(self.program, pc);
        let dst = insn.dst as usize;
        let src = insn.src as usize;

        if config.enable_instruction_tracing {
            let mut state = [0u64; 12];
            state[0..11].copy_from_slice(&self.reg);
            state[11] = pc as u64;
            self.vm.env.context_object_pointer.trace(state);
        }

        match insn.opc {
            _ if dst == STACK_PTR_REG && config.dynamic_stack_frames => {
                // Let the stack overflow. For legitimate programs, this is a nearly
                // impossible condition to hit since programs are metered and we already
                // enforce a maximum call depth. For programs that intentionally mess
                // around with the stack pointer, MemoryRegion::map will return
                // InvalidVirtualAddress(stack_ptr) once an invalid stack address is
                // accessed.
                match insn.opc {
                    ebpf::SUB64_IMM => { self.vm.env.stack_pointer = self.vm.env.stack_pointer.overflowing_add(-insn.imm as u64).0; }
                    ebpf::ADD64_IMM => { self.vm.env.stack_pointer = self.vm.env.stack_pointer.overflowing_add(insn.imm as u64).0; }
                    _ => {
                        #[cfg(debug_assertions)]
                        unreachable!("unexpected insn on r11")
                    }
                }
            }

            ebpf::LD_DW_IMM  => {
                ebpf::augment_lddw_unchecked(self.program, &mut insn);
                instruction_width = 2;
                self.pc += 1;
                self.reg[dst] = insn.imm as u64;
            },

            // BPF_LDX class
            ebpf::LD_B_REG   => {
                let vm_addr = (self.reg[src] as i64).wrapping_add(insn.off as i64) as u64;
                let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Load, pc, u8);
                self.reg[dst] = unsafe { *host_ptr as u64 };
            },
            ebpf::LD_H_REG   => {
                let vm_addr = (self.reg[src] as i64).wrapping_add(insn.off as i64) as u64;
                let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Load, pc, u16);
                self.reg[dst] = unsafe { *host_ptr as u64 };
            },
            ebpf::LD_W_REG   => {
                let vm_addr = (self.reg[src] as i64).wrapping_add(insn.off as i64) as u64;
                let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Load, pc, u32);
                self.reg[dst] = unsafe { *host_ptr as u64 };
            },
            ebpf::LD_DW_REG  => {
                let vm_addr = (self.reg[src] as i64).wrapping_add(insn.off as i64) as u64;
                let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Load, pc, u64);
                self.reg[dst] = unsafe { *host_ptr };
            },

            // BPF_ST class
            ebpf::ST_B_IMM   => {
                let vm_addr = (self.reg[dst] as i64).wrapping_add( insn.off as i64) as u64;
                let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Store, pc, u8);
                unsafe { *host_ptr = insn.imm as u8 };
            },
            ebpf::ST_H_IMM   => {
                let vm_addr = (self.reg[dst] as i64).wrapping_add(insn.off as i64) as u64;
                let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Store, pc, u16);
                unsafe { *host_ptr = insn.imm as u16 };
            },
            ebpf::ST_W_IMM   => {
                let vm_addr = (self.reg[dst] as i64).wrapping_add(insn.off as i64) as u64;
                let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Store, pc, u32);
                unsafe { *host_ptr = insn.imm as u32 };
            },
            ebpf::ST_DW_IMM  => {
                let vm_addr = (self.reg[dst] as i64).wrapping_add(insn.off as i64) as u64;
                let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Store, pc, u64);
                unsafe { *host_ptr = insn.imm as u64 };
            },

            // BPF_STX class
            ebpf::ST_B_REG   => {
                let vm_addr = (self.reg[dst] as i64).wrapping_add(insn.off as i64) as u64;
                let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Store, pc, u8);
                unsafe { *host_ptr = self.reg[src] as u8 };
            },
            ebpf::ST_H_REG   => {
                let vm_addr = (self.reg[dst] as i64).wrapping_add(insn.off as i64) as u64;
                let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Store, pc, u16);
                unsafe { *host_ptr = self.reg[src] as u16 };
            },
            ebpf::ST_W_REG   => {
                let vm_addr = (self.reg[dst] as i64).wrapping_add(insn.off as i64) as u64;
                let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Store, pc, u32);
                unsafe { *host_ptr = self.reg[src] as u32 };
            },
            ebpf::ST_DW_REG  => {
                let vm_addr = (self.reg[dst] as i64).wrapping_add(insn.off as i64) as u64;
                let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Store, pc, u64);
                unsafe { *host_ptr = self.reg[src] };
            },

            // BPF_ALU class
            ebpf::ADD32_IMM  => self.reg[dst] = (self.reg[dst] as i32).wrapping_add(insn.imm as i32)      as u64,
            ebpf::ADD32_REG  => self.reg[dst] = (self.reg[dst] as i32).wrapping_add(self.reg[src] as i32) as u64,
            ebpf::SUB32_IMM  => self.reg[dst] = (self.reg[dst] as i32).wrapping_sub(insn.imm as i32)      as u64,
            ebpf::SUB32_REG  => self.reg[dst] = (self.reg[dst] as i32).wrapping_sub(self.reg[src] as i32) as u64,
            ebpf::MUL32_IMM  => self.reg[dst] = (self.reg[dst] as i32).wrapping_mul(insn.imm as i32)      as u64,
            ebpf::MUL32_REG  => self.reg[dst] = (self.reg[dst] as i32).wrapping_mul(self.reg[src] as i32) as u64,
            ebpf::DIV32_IMM  => self.reg[dst] = (self.reg[dst] as u32             / insn.imm as u32)      as u64,
            ebpf::DIV32_REG  => {
                if self.reg[src] as u32 == 0 {
                    return Err(EbpfError::DivideByZero(pc + ebpf::ELF_INSN_DUMP_OFFSET));
                }
                                self.reg[dst] = (self.reg[dst] as u32             / self.reg[src] as u32) as u64;
            },
            ebpf::SDIV32_IMM  => {
                if self.reg[dst] as i32 == i32::MIN && insn.imm == -1 {
                    return Err(EbpfError::DivideOverflow(pc + ebpf::ELF_INSN_DUMP_OFFSET));
                }
                                self.reg[dst] = (self.reg[dst] as i32             / insn.imm as i32)      as u64;
            }
            ebpf::SDIV32_REG  => {
                if self.reg[src] as i32 == 0 {
                    return Err(EbpfError::DivideByZero(pc + ebpf::ELF_INSN_DUMP_OFFSET));
                }
                if self.reg[dst] as i32 == i32::MIN && self.reg[src] as i32 == -1 {
                    return Err(EbpfError::DivideOverflow(pc + ebpf::ELF_INSN_DUMP_OFFSET));
                }
                                self.reg[dst] = (self.reg[dst] as i32             / self.reg[src] as i32) as u64;
            },
            ebpf::OR32_IMM   => self.reg[dst] = (self.reg[dst] as u32             | insn.imm as u32)      as u64,
            ebpf::OR32_REG   => self.reg[dst] = (self.reg[dst] as u32             | self.reg[src] as u32) as u64,
            ebpf::AND32_IMM  => self.reg[dst] = (self.reg[dst] as u32             & insn.imm as u32)      as u64,
            ebpf::AND32_REG  => self.reg[dst] = (self.reg[dst] as u32             & self.reg[src] as u32) as u64,
            ebpf::LSH32_IMM  => self.reg[dst] = (self.reg[dst] as u32).wrapping_shl(insn.imm as u32)      as u64,
            ebpf::LSH32_REG  => self.reg[dst] = (self.reg[dst] as u32).wrapping_shl(self.reg[src] as u32) as u64,
            ebpf::RSH32_IMM  => self.reg[dst] = (self.reg[dst] as u32).wrapping_shr(insn.imm as u32)      as u64,
            ebpf::RSH32_REG  => self.reg[dst] = (self.reg[dst] as u32).wrapping_shr(self.reg[src] as u32) as u64,
            ebpf::NEG32      => self.reg[dst] = (self.reg[dst] as i32).wrapping_neg()                     as u64 & (u32::MAX as u64),
            ebpf::MOD32_IMM  => self.reg[dst] = (self.reg[dst] as u32             % insn.imm as u32)      as u64,
            ebpf::MOD32_REG  => {
                if self.reg[src] as u32 == 0 {
                    return Err(EbpfError::DivideByZero(pc + ebpf::ELF_INSN_DUMP_OFFSET));
                }
                                self.reg[dst] = (self.reg[dst] as u32             % self.reg[src] as u32) as u64;
            },
            ebpf::XOR32_IMM  => self.reg[dst] = (self.reg[dst] as u32             ^ insn.imm as u32)      as u64,
            ebpf::XOR32_REG  => self.reg[dst] = (self.reg[dst] as u32             ^ self.reg[src] as u32) as u64,
            ebpf::MOV32_IMM  => self.reg[dst] = insn.imm as u32 as u64,
            ebpf::MOV32_REG  => self.reg[dst] = (self.reg[src] as u32) as u64,
            ebpf::ARSH32_IMM => self.reg[dst] = (self.reg[dst] as i32).wrapping_shr(insn.imm as u32)      as u64 & (u32::MAX as u64),
            ebpf::ARSH32_REG => self.reg[dst] = (self.reg[dst] as i32).wrapping_shr(self.reg[src] as u32) as u64 & (u32::MAX as u64),
            ebpf::LE         => {
                self.reg[dst] = match insn.imm {
                    16 => (self.reg[dst] as u16).to_le() as u64,
                    32 => (self.reg[dst] as u32).to_le() as u64,
                    64 =>  self.reg[dst].to_le(),
                    _  => {
                        return Err(EbpfError::InvalidInstruction(pc + ebpf::ELF_INSN_DUMP_OFFSET));
                    }
                };
            },
            ebpf::BE         => {
                self.reg[dst] = match insn.imm {
                    16 => (self.reg[dst] as u16).to_be() as u64,
                    32 => (self.reg[dst] as u32).to_be() as u64,
                    64 =>  self.reg[dst].to_be(),
                    _  => {
                        return Err(EbpfError::InvalidInstruction(pc + ebpf::ELF_INSN_DUMP_OFFSET));
                    }
                };
            },

            // BPF_ALU64 class
            ebpf::ADD64_IMM  => self.reg[dst] =  self.reg[dst].wrapping_add(insn.imm as u64),
            ebpf::ADD64_REG  => self.reg[dst] =  self.reg[dst].wrapping_add(self.reg[src]),
            ebpf::SUB64_IMM  => self.reg[dst] =  self.reg[dst].wrapping_sub(insn.imm as u64),
            ebpf::SUB64_REG  => self.reg[dst] =  self.reg[dst].wrapping_sub(self.reg[src]),
            ebpf::MUL64_IMM  => self.reg[dst] =  self.reg[dst].wrapping_mul(insn.imm as u64),
            ebpf::MUL64_REG  => self.reg[dst] =  self.reg[dst].wrapping_mul(self.reg[src]),
            ebpf::DIV64_IMM  => self.reg[dst] /= insn.imm as u64,
            ebpf::DIV64_REG  => {
                if self.reg[src] == 0 {
                    return Err(EbpfError::DivideByZero(pc + ebpf::ELF_INSN_DUMP_OFFSET));
                }
                                self.reg[dst] /= self.reg[src];
            },
            ebpf::SDIV64_IMM => {
                if self.reg[dst] as i64 == i64::MIN && insn.imm == -1 {
                    return Err(EbpfError::DivideOverflow(pc + ebpf::ELF_INSN_DUMP_OFFSET));
                }
                                self.reg[dst] = (self.reg[dst] as i64 / insn.imm)                          as u64
            }
            ebpf::SDIV64_REG => {
                if self.reg[src] == 0 {
                    return Err(EbpfError::DivideByZero(pc + ebpf::ELF_INSN_DUMP_OFFSET));
                }
                if self.reg[dst] as i64 == i64::MIN && self.reg[src] as i64 == -1 {
                    return Err(EbpfError::DivideOverflow(pc + ebpf::ELF_INSN_DUMP_OFFSET));
                }
                                self.reg[dst] = (self.reg[dst] as i64 / self.reg[src] as i64)             as u64;
            },
            ebpf::OR64_IMM   => self.reg[dst] |= insn.imm as u64,
            ebpf::OR64_REG   => self.reg[dst] |= self.reg[src],
            ebpf::AND64_IMM  => self.reg[dst] &= insn.imm as u64,
            ebpf::AND64_REG  => self.reg[dst] &= self.reg[src],
            ebpf::LSH64_IMM  => self.reg[dst] =  self.reg[dst].wrapping_shl(insn.imm as u32),
            ebpf::LSH64_REG  => self.reg[dst] =  self.reg[dst].wrapping_shl(self.reg[src] as u32),
            ebpf::RSH64_IMM  => self.reg[dst] =  self.reg[dst].wrapping_shr(insn.imm as u32),
            ebpf::RSH64_REG  => self.reg[dst] =  self.reg[dst].wrapping_shr(self.reg[src] as u32),
            ebpf::NEG64      => self.reg[dst] = (self.reg[dst] as i64).wrapping_neg() as u64,
            ebpf::MOD64_IMM  => self.reg[dst] %= insn.imm as u64,
            ebpf::MOD64_REG  => {
                if self.reg[src] == 0 {
                    return Err(EbpfError::DivideByZero(pc + ebpf::ELF_INSN_DUMP_OFFSET));
                }
                                self.reg[dst] %= self.reg[src];
            },
            ebpf::XOR64_IMM  => self.reg[dst] ^= insn.imm as u64,
            ebpf::XOR64_REG  => self.reg[dst] ^= self.reg[src],
            ebpf::MOV64_IMM  => self.reg[dst] =  insn.imm as u64,
            ebpf::MOV64_REG  => self.reg[dst] =  self.reg[src],
            ebpf::ARSH64_IMM => self.reg[dst] = (self.reg[dst] as i64).wrapping_shr(insn.imm as u32)      as u64,
            ebpf::ARSH64_REG => self.reg[dst] = (self.reg[dst] as i64).wrapping_shr(self.reg[src] as u32) as u64,

            // BPF_JMP class
            ebpf::JA         =>                                                   { self.pc = (self.pc as isize + insn.off as isize) as usize; },
            ebpf::JEQ_IMM    => if  self.reg[dst] == insn.imm as u64              { self.pc = (self.pc as isize + insn.off as isize) as usize; },
            ebpf::JEQ_REG    => if  self.reg[dst] == self.reg[src]                { self.pc = (self.pc as isize + insn.off as isize) as usize; },
            ebpf::JGT_IMM    => if  self.reg[dst] >  insn.imm as u64              { self.pc = (self.pc as isize + insn.off as isize) as usize; },
            ebpf::JGT_REG    => if  self.reg[dst] >  self.reg[src]                { self.pc = (self.pc as isize + insn.off as isize) as usize; },
            ebpf::JGE_IMM    => if  self.reg[dst] >= insn.imm as u64              { self.pc = (self.pc as isize + insn.off as isize) as usize; },
            ebpf::JGE_REG    => if  self.reg[dst] >= self.reg[src]                { self.pc = (self.pc as isize + insn.off as isize) as usize; },
            ebpf::JLT_IMM    => if  self.reg[dst] <  insn.imm as u64              { self.pc = (self.pc as isize + insn.off as isize) as usize; },
            ebpf::JLT_REG    => if  self.reg[dst] <  self.reg[src]                { self.pc = (self.pc as isize + insn.off as isize) as usize; },
            ebpf::JLE_IMM    => if  self.reg[dst] <= insn.imm as u64              { self.pc = (self.pc as isize + insn.off as isize) as usize; },
            ebpf::JLE_REG    => if  self.reg[dst] <= self.reg[src]                { self.pc = (self.pc as isize + insn.off as isize) as usize; },
            ebpf::JSET_IMM   => if  self.reg[dst] &  insn.imm as u64 != 0         { self.pc = (self.pc as isize + insn.off as isize) as usize; },
            ebpf::JSET_REG   => if  self.reg[dst] &  self.reg[src] != 0           { self.pc = (self.pc as isize + insn.off as isize) as usize; },
            ebpf::JNE_IMM    => if  self.reg[dst] != insn.imm as u64              { self.pc = (self.pc as isize + insn.off as isize) as usize; },
            ebpf::JNE_REG    => if  self.reg[dst] != self.reg[src]                { self.pc = (self.pc as isize + insn.off as isize) as usize; },
            ebpf::JSGT_IMM   => if (self.reg[dst] as i64) >  insn.imm             { self.pc = (self.pc as isize + insn.off as isize) as usize; },
            ebpf::JSGT_REG   => if (self.reg[dst] as i64) >  self.reg[src] as i64 { self.pc = (self.pc as isize + insn.off as isize) as usize; },
            ebpf::JSGE_IMM   => if (self.reg[dst] as i64) >= insn.imm             { self.pc = (self.pc as isize + insn.off as isize) as usize; },
            ebpf::JSGE_REG   => if (self.reg[dst] as i64) >= self.reg[src] as i64 { self.pc = (self.pc as isize + insn.off as isize) as usize; },
            ebpf::JSLT_IMM   => if (self.reg[dst] as i64) <  insn.imm             { self.pc = (self.pc as isize + insn.off as isize) as usize; },
            ebpf::JSLT_REG   => if (self.reg[dst] as i64) <  self.reg[src] as i64 { self.pc = (self.pc as isize + insn.off as isize) as usize; },
            ebpf::JSLE_IMM   => if (self.reg[dst] as i64) <= insn.imm             { self.pc = (self.pc as isize + insn.off as isize) as usize; },
            ebpf::JSLE_REG   => if (self.reg[dst] as i64) <= self.reg[src] as i64 { self.pc = (self.pc as isize + insn.off as isize) as usize; },

            ebpf::CALL_REG   => {
                let target_address = self.reg[insn.imm as usize];
                self.push_frame(config)?;
                if target_address < self.program_vm_addr {
                    return Err(EbpfError::CallOutsideTextSegment(pc + ebpf::ELF_INSN_DUMP_OFFSET, target_address / ebpf::INSN_SIZE as u64 * ebpf::INSN_SIZE as u64));
                }
                let target_pc = (target_address - self.program_vm_addr) as usize / ebpf::INSN_SIZE;
                self.pc = self.check_pc(pc, target_pc)?;
                if config.static_syscalls && executable.lookup_bpf_function(target_pc as u32).is_none() {
                    self.due_insn_count += 1;
                    return Err(EbpfError::UnsupportedInstruction(target_pc + ebpf::ELF_INSN_DUMP_OFFSET));
                }
            },

            // Do not delegate the check to the verifier, since self.registered functions can be
            // changed after the program has been verified.
            ebpf::CALL_IMM   => {
                let mut resolved = false;
                let (syscalls, calls) = if config.static_syscalls {
                    (insn.src == 0, insn.src != 0)
                } else {
                    (true, true)
                };

                if syscalls {
                    if let Some(syscall) = executable.get_syscall_registry().lookup_syscall(insn.imm as u32) {
                        resolved = true;

                        if config.enable_instruction_meter {
                            self.vm.env.context_object_pointer.consume(self.due_insn_count);
                        }
                        self.due_insn_count = 0;
                        let mut result = ProgramResult::Ok(0);
                        syscall(
                            self.vm.env.context_object_pointer,
                            self.reg[1],
                            self.reg[2],
                            self.reg[3],
                            self.reg[4],
                            self.reg[5],
                            &mut self.vm.env.memory_mapping,
                            &mut result,
                        );
                        self.reg[0] = match result {
                            ProgramResult::Ok(value) => value,
                            ProgramResult::Err(err) => return Err(err),
                        };
                        if config.enable_instruction_meter {
                            self.vm.env.previous_instruction_meter = self.vm.env.context_object_pointer.get_remaining();
                        }
                    }
                }

                if calls && !resolved {
                    if let Some(target_pc) = executable.lookup_bpf_function(insn.imm as u32) {
                        resolved = true;

                        // make BPF to BPF call
                        self.push_frame(config)?;
                        self.pc = self.check_pc(pc, target_pc)?;
                    }
                }

                if !resolved {
                    return Err(EbpfError::UnsupportedInstruction(pc + ebpf::ELF_INSN_DUMP_OFFSET));
                }
            }

            ebpf::EXIT       => {
                if self.vm.env.call_depth == 0 {
                    return Ok(Some(self.reg[0]));
                }
                // Return from BPF to BPF call
                self.vm.env.call_depth -= 1;
                let frame = &self.vm.env.call_frames[self.vm.env.call_depth as usize];
                self.pc = self.check_pc(pc, frame.target_pc)?;
                self.reg[ebpf::FRAME_PTR_REG] = frame.frame_pointer;
                self.vm.env.frame_pointer = self.reg[ebpf::FRAME_PTR_REG];
                self.reg[ebpf::FIRST_SCRATCH_REG
                    ..ebpf::FIRST_SCRATCH_REG + ebpf::SCRATCH_REGS]
                    .copy_from_slice(&frame.caller_saved_registers);
            }
            _ => return Err(EbpfError::UnsupportedInstruction(pc + ebpf::ELF_INSN_DUMP_OFFSET)),
        }

        if config.enable_instruction_meter && self.due_insn_count >= self.vm.env.previous_instruction_meter {
            // Use `pc + instruction_width` instead of `self.pc` here because jumps and calls don't continue at the end of this instruction
            return Err(EbpfError::ExceededMaxInstructions(pc + instruction_width + ebpf::ELF_INSN_DUMP_OFFSET, 0));
        }

        Ok(None)
    }
}
