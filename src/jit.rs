#![allow(clippy::arithmetic_side_effects)]
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

use rand::{rngs::SmallRng, Rng, SeedableRng};
use std::{fmt::Debug, mem, ptr};

use crate::{
    ebpf::{self, FIRST_SCRATCH_REG, FRAME_PTR_REG, INSN_SIZE, SCRATCH_REGS, STACK_PTR_REG},
    elf::Executable,
    error::EbpfError,
    memory_management::{
        allocate_pages, free_pages, get_system_page_size, protect_pages, round_to_page_size,
    },
    memory_region::{AccessType, MemoryMapping},
    verifier::Verifier,
    vm::{Config, ContextObject, EbpfVm, ProgramResult},
    x86::*,
};

/// Shift the RUNTIME_ENVIRONMENT_KEY by this many bits to the LSB
///
/// 3 bits for 8 Byte alignment, and 1 bit to have encoding space for the RuntimeEnvironment.
const PROGRAM_ENVIRONMENT_KEY_SHIFT: u32 = 4;
const MAX_EMPTY_PROGRAM_MACHINE_CODE_LENGTH: usize = 4096;
const MAX_MACHINE_CODE_LENGTH_PER_INSTRUCTION: usize = 110;
const MACHINE_CODE_PER_INSTRUCTION_METER_CHECKPOINT: usize = 13;

static RUNTIME_ENVIRONMENT_KEY: std::sync::OnceLock<i32> = std::sync::OnceLock::<i32>::new();

pub struct JitProgram {
    /// OS page size in bytes and the alignment of the sections
    page_size: usize,
    /// A `*const u8` pointer into the text_section for each BPF instruction
    pc_section: &'static mut [usize],
    /// The x86 machinecode
    text_section: &'static mut [u8],
}

impl JitProgram {
    fn new(pc: usize, code_size: usize) -> Result<Self, EbpfError> {
        let page_size = get_system_page_size();
        let pc_loc_table_size = round_to_page_size(pc * 8, page_size);
        let over_allocated_code_size = round_to_page_size(code_size, page_size);
        unsafe {
            let raw = allocate_pages(pc_loc_table_size + over_allocated_code_size)?;
            Ok(Self {
                page_size,
                pc_section: std::slice::from_raw_parts_mut(raw as *mut usize, pc),
                text_section: std::slice::from_raw_parts_mut(
                    raw.add(pc_loc_table_size),
                    over_allocated_code_size,
                ),
            })
        }
    }

    fn seal(&mut self, text_section_usage: usize) -> Result<(), EbpfError> {
        if self.page_size == 0 {
            return Ok(());
        }
        let raw = self.pc_section.as_ptr() as *mut u8;
        let pc_loc_table_size = round_to_page_size(self.pc_section.len() * 8, self.page_size);
        let over_allocated_code_size = round_to_page_size(self.text_section.len(), self.page_size);
        let code_size = round_to_page_size(text_section_usage, self.page_size);
        unsafe {
            // Fill with debugger traps
            std::ptr::write_bytes(
                raw.add(pc_loc_table_size).add(text_section_usage),
                0xcc,
                code_size - text_section_usage,
            );
            if over_allocated_code_size > code_size {
                free_pages(
                    raw.add(pc_loc_table_size).add(code_size),
                    over_allocated_code_size - code_size,
                )?;
            }
            self.text_section =
                std::slice::from_raw_parts_mut(raw.add(pc_loc_table_size), text_section_usage);
            protect_pages(
                self.pc_section.as_mut_ptr() as *mut u8,
                pc_loc_table_size,
                false,
            )?;
            protect_pages(self.text_section.as_mut_ptr(), code_size, true)?;
        }
        Ok(())
    }

    pub fn invoke<C: ContextObject>(
        &self,
        _config: &Config,
        vm: &mut EbpfVm<C>,
        registers: [u64; 12],
    ) -> i64 {
        unsafe {
            let mut instruction_meter =
                (vm.previous_instruction_meter as i64).wrapping_add(registers[11] as i64);
            std::arch::asm!(
                // RBP and RBX must be saved and restored manually in the current version of rustc and llvm.
                "push rbx",
                "push rbp",
                "mov [{host_stack_pointer}], rsp",
                "add QWORD PTR [{host_stack_pointer}], -8", // We will push RIP in "call r10" later
                "mov rbp, {rbp}",
                "mov rbx, {rbx}",
                "mov rax, [r11 + 0x00]",
                "mov rsi, [r11 + 0x08]",
                "mov rdx, [r11 + 0x10]",
                "mov rcx, [r11 + 0x18]",
                "mov r8,  [r11 + 0x20]",
                "mov r9,  [r11 + 0x28]",
                "mov r12, [r11 + 0x30]",
                "mov r13, [r11 + 0x38]",
                "mov r14, [r11 + 0x40]",
                "mov r15, [r11 + 0x48]",
                "mov r11, [r11 + 0x58]",
                "call r10",
                "pop rbp",
                "pop rbx",
                host_stack_pointer = in(reg) &mut vm.host_stack_pointer,
                rbp = in(reg) (vm as *mut _ as *mut u64).offset(*RUNTIME_ENVIRONMENT_KEY.get().unwrap() as isize),
                rbx = in(reg) registers[ebpf::FRAME_PTR_REG],
                inlateout("rdi") instruction_meter,
                inlateout("r10") self.pc_section[registers[11] as usize] => _,
                inlateout("r11") &registers => _,
                lateout("rax") _, lateout("rsi") _, lateout("rdx") _, lateout("rcx") _, lateout("r8") _,
                lateout("r9") _, lateout("r12") _, lateout("r13") _, lateout("r14") _, lateout("r15") _,
                // lateout("rbp") _, lateout("rbx") _,
            );
            instruction_meter
        }
    }

    pub fn machine_code_length(&self) -> usize {
        self.text_section.len()
    }

    pub fn mem_size(&self) -> usize {
        let pc_loc_table_size = round_to_page_size(self.pc_section.len() * 8, self.page_size);
        let code_size = round_to_page_size(self.text_section.len(), self.page_size);
        pc_loc_table_size + code_size
    }
}

impl Drop for JitProgram {
    fn drop(&mut self) {
        let pc_loc_table_size = round_to_page_size(self.pc_section.len() * 8, self.page_size);
        let code_size = round_to_page_size(self.text_section.len(), self.page_size);
        if pc_loc_table_size + code_size > 0 {
            unsafe {
                let _ = free_pages(
                    self.pc_section.as_ptr() as *mut u8,
                    pc_loc_table_size + code_size,
                );
            }
        }
    }
}

impl Debug for JitProgram {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.write_fmt(format_args!("JitProgram {:?}", self as *const _))
    }
}

impl PartialEq for JitProgram {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self as *const _, other as *const _)
    }
}

// Used to define subroutines and then call them
// See JitCompiler::set_anchor() and JitCompiler::relative_to_anchor()
const ANCHOR_TRACE: usize = 0;
const ANCHOR_CALL_EXCEEDED_MAX_INSTRUCTIONS: usize = 1;
const ANCHOR_EPILOGUE: usize = 2;
const ANCHOR_ALLOCATE_EXCEPTION: usize = 3;
const ANCHOR_THROW_EXCEPTION_UNCHECKED: usize = 4;
const ANCHOR_EXIT: usize = 5;
const ANCHOR_THROW_EXCEPTION: usize = 6;
const ANCHOR_ACCESS_VIOLATION: usize = 7;
const ANCHOR_CALL_DEPTH_EXCEEDED: usize = 8;
const ANCHOR_CALL_OUTSIDE_TEXT_SEGMENT: usize = 9;
const ANCHOR_DIV_BY_ZERO: usize = 10;
const ANCHOR_DIV_OVERFLOW: usize = 11;
const ANCHOR_CALL_UNSUPPORTED_INSTRUCTION: usize = 12;
const ANCHOR_EXTERNAL_FUNCTION_CALL: usize = 13;
const ANCHOR_ANCHOR_INTERNAL_FUNCTION_CALL_PROLOGUE: usize = 14;
const ANCHOR_ANCHOR_INTERNAL_FUNCTION_CALL_REG: usize = 15;
const ANCHOR_TRANSLATE_MEMORY_ADDRESS: usize = 23;
const ANCHOR_COUNT: usize = 32; // Update me when adding or removing anchors

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
// CALLER_SAVED_REGISTERS[7]  R10  Unused for the most part, scratch register for exception handling
// CALLEE_SAVED_REGISTERS[0]  RBP  Constant pointer to initial RSP - 8

#[derive(Copy, Clone, Debug)]
pub enum OperandSize {
    S0 = 0,
    S8 = 8,
    S16 = 16,
    S32 = 32,
    S64 = 64,
}

enum Value {
    Register(u8),
    RegisterIndirect(u8, i32, bool),
    RegisterPlusConstant32(u8, i32, bool),
    RegisterPlusConstant64(u8, i64, bool),
    Constant64(i64, bool),
}

struct Argument {
    index: usize,
    value: Value,
}

#[derive(Debug)]
struct Jump {
    location: *const u8,
    target_pc: usize,
}

/// Indices of slots inside RuntimeEnvironment
enum RuntimeEnvironmentSlot {
    HostStackPointer = 0,
    CallDepth = 1,
    StackPointer = 2,
    ContextObjectPointer = 3,
    PreviousInstructionMeter = 4,
    StopwatchNumerator = 5,
    StopwatchDenominator = 6,
    ProgramResult = 7,
    MemoryMapping = 10,
}

/* Explaination of the Instruction Meter

    The instruction meter serves two purposes: First, measure how many BPF instructions are
    executed (profiling) and second, limit this number by stopping the program with an exception
    once a given threshold is reached (validation). One approach would be to increment and
    validate the instruction meter before each instruction. However, this would heavily impact
    performance. Thus, we only profile and validate the instruction meter at branches.

    For this, we implicitly sum up all the instructions between two branches.
    It is easy to know the end of such a slice of instructions, but how do we know where it
    started? There could be multiple ways to jump onto a path which all lead to the same final
    branch. This is, where the integral technique comes in. The program is basically a sequence
    of instructions with the x-axis being the program counter (short "pc"). The cost function is
    a constant function which returns one for every point on the x axis. Now, the instruction
    meter needs to calculate the definite integral of the cost function between the start and the
    end of the current slice of instructions. For that we need the indefinite integral of the cost
    function. Fortunately, the derivative of the pc is the cost function (it increases by one for
    every instruction), thus the pc is an antiderivative of the the cost function and a valid
    indefinite integral. So, to calculate an definite integral of the cost function, we just need
    to subtract the start pc from the end pc of the slice. This difference can then be subtracted
    from the remaining instruction counter until it goes below zero at which point it reaches
    the instruction meter limit. Ok, but how do we know the start of the slice at the end?

    The trick is: We do not need to know. As subtraction and addition are associative operations,
    we can reorder them, even beyond the current branch. Thus, we can simply account for the
    amount the start will subtract at the next branch by already adding that to the remaining
    instruction counter at the current branch. So, every branch just subtracts its current pc
    (the end of the slice) and adds the target pc (the start of the next slice) to the remaining
    instruction counter. This way, no branch needs to know the pc of the last branch explicitly.
    Another way to think about this trick is as follows: The remaining instruction counter now
    measures what the maximum pc is, that we can reach with the remaining budget after the last
    branch.

    One problem are conditional branches. There are basically two ways to handle them: Either,
    only do the profiling if the branch is taken, which requires two jumps (one for the profiling
    and one to get to the target pc). Or, always profile it as if the jump to the target pc was
    taken, but then behind the conditional branch, undo the profiling (as it was not taken). We
    use the second method and the undo profiling is the same as the normal profiling, just with
    reversed plus and minus signs.

    Another special case to keep in mind are return instructions. They would require us to know
    the return address (target pc), but in the JIT we already converted that to be a host address.
    Of course, one could also save the BPF return address on the stack, but an even simpler
    solution exists: Just count as if you were jumping to an specific target pc before the exit,
    and then after returning use the undo profiling. The trick is, that the undo profiling now
    has the current pc which is the BPF return address. The virtual target pc we count towards
    and undo again can be anything, so we just set it to zero.
*/

pub struct JitCompiler<'a, V: Verifier, C: ContextObject> {
    result: JitProgram,
    text_section_jumps: Vec<Jump>,
    anchors: [*const u8; ANCHOR_COUNT],
    offset_in_text_section: usize,
    executable: &'a Executable<V, C>,
    program: &'a [u8],
    program_vm_addr: u64,
    config: &'a Config,
    pc: usize,
    last_instruction_meter_validation_pc: usize,
    next_noop_insertion: u32,
    runtime_environment_key: i32,
    diversification_rng: SmallRng,
    stopwatch_is_active: bool,
}

#[rustfmt::skip]
impl<'a, V: Verifier, C: ContextObject> JitCompiler<'a, V, C> {
    /// Constructs a new compiler and allocates memory for the compilation output
    pub fn new(executable: &'a Executable<V, C>) -> Result<Self, EbpfError> {
        let config = executable.get_config();
        let (program_vm_addr, program) = executable.get_text_bytes();

        // Scan through program to find actual number of instructions
        let mut pc = 0;
        if executable.get_sbpf_version().disable_lddw() {
            pc = program.len() / ebpf::INSN_SIZE;
        } else {
            while (pc + 1) * ebpf::INSN_SIZE <= program.len() {
                let insn = ebpf::get_insn_unchecked(program, pc);
                pc += match insn.opc {
                    ebpf::LD_DW_IMM => 2,
                    _ => 1,
                };
            }
        }

        let mut code_length_estimate = MAX_EMPTY_PROGRAM_MACHINE_CODE_LENGTH + MAX_MACHINE_CODE_LENGTH_PER_INSTRUCTION * pc;
        if config.noop_instruction_rate != 0 {
            code_length_estimate += code_length_estimate / config.noop_instruction_rate as usize;
        }
        if config.instruction_meter_checkpoint_distance != 0 {
            code_length_estimate += pc / config.instruction_meter_checkpoint_distance * MACHINE_CODE_PER_INSTRUCTION_METER_CHECKPOINT;
        }

        let runtime_environment_key = *RUNTIME_ENVIRONMENT_KEY.get_or_init(|| {
            if config.encrypt_runtime_environment {
                rand::thread_rng().gen::<i32>() >> PROGRAM_ENVIRONMENT_KEY_SHIFT
            } else {
                0
            }
        });
        let mut diversification_rng = SmallRng::from_rng(rand::thread_rng()).map_err(|_| EbpfError::JitNotCompiled)?;
        
        Ok(Self {
            result: JitProgram::new(pc, code_length_estimate)?,
            text_section_jumps: vec![],
            anchors: [std::ptr::null(); ANCHOR_COUNT],
            offset_in_text_section: 0,
            executable,
            program_vm_addr,
            program,
            config,
            pc: 0,
            last_instruction_meter_validation_pc: 0,
            next_noop_insertion: if config.noop_instruction_rate == 0 { u32::MAX } else { diversification_rng.gen_range(0..config.noop_instruction_rate * 2) },
            runtime_environment_key,
            diversification_rng,
            stopwatch_is_active: false,
        })
    }

    /// Compiles the given executable, consuming the compiler
    pub fn compile(mut self) -> Result<JitProgram, EbpfError> {
        let text_section_base = self.result.text_section.as_ptr();

        self.emit_subroutines();

        while self.pc * ebpf::INSN_SIZE < self.program.len() {
            if self.offset_in_text_section + MAX_MACHINE_CODE_LENGTH_PER_INSTRUCTION > self.result.text_section.len() {
                return Err(EbpfError::ExhaustedTextSegment(self.pc));
            }
            let mut insn = ebpf::get_insn_unchecked(self.program, self.pc);
            self.result.pc_section[self.pc] = unsafe { text_section_base.add(self.offset_in_text_section) } as usize;

            // Regular instruction meter checkpoints to prevent long linear runs from exceeding their budget
            if self.last_instruction_meter_validation_pc + self.config.instruction_meter_checkpoint_distance <= self.pc {
                self.emit_validate_instruction_count(true, Some(self.pc));
            }

            if self.config.enable_instruction_tracing {
                self.emit_ins(X86Instruction::load_immediate(OperandSize::S64, R11, self.pc as i64));
                self.emit_ins(X86Instruction::call_immediate(self.relative_to_anchor(ANCHOR_TRACE, 5)));
                self.emit_ins(X86Instruction::load_immediate(OperandSize::S64, R11, 0));
            }

            let dst = if insn.dst == STACK_PTR_REG as u8 { u8::MAX } else { REGISTER_MAP[insn.dst as usize] };
            let src = REGISTER_MAP[insn.src as usize];
            let target_pc = (self.pc as isize + insn.off as isize + 1) as usize;

            match insn.opc {
                ebpf::ADD64_IMM if insn.dst == STACK_PTR_REG as u8 && self.executable.get_sbpf_version().dynamic_stack_frames() => {
                    let stack_ptr_access = X86IndirectAccess::Offset(self.slot_on_environment_stack(RuntimeEnvironmentSlot::StackPointer));
                    self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x81, 0, RBP, insn.imm, Some(stack_ptr_access)));
                }

                ebpf::LD_UW_IMM => {
                    self.emit_sanitized_alu(OperandSize::S64, 0x09, 1, dst, (insn.imm as u64).wrapping_shl(32) as i64);
                }
                ebpf::LD_DW_IMM  => {
                    self.emit_validate_and_profile_instruction_count(true, Some(self.pc + 2));
                    self.pc += 1;
                    self.result.pc_section[self.pc] = self.anchors[ANCHOR_CALL_UNSUPPORTED_INSTRUCTION] as usize;
                    ebpf::augment_lddw_unchecked(self.program, &mut insn);
                    if self.should_sanitize_constant(insn.imm) {
                        self.emit_sanitized_load_immediate(OperandSize::S64, dst, insn.imm);
                    } else {
                        self.emit_ins(X86Instruction::load_immediate(OperandSize::S64, dst, insn.imm));
                    }
                },

                // BPF_LDX class
                ebpf::LD_B_REG   => {
                    self.emit_address_translation(Some(dst), Value::RegisterPlusConstant64(src, insn.off as i64, true), 1, None);
                },
                ebpf::LD_H_REG   => {
                    self.emit_address_translation(Some(dst), Value::RegisterPlusConstant64(src, insn.off as i64, true), 2, None);
                },
                ebpf::LD_W_REG   => {
                    self.emit_address_translation(Some(dst), Value::RegisterPlusConstant64(src, insn.off as i64, true), 4, None);
                },
                ebpf::LD_DW_REG  => {
                    self.emit_address_translation(Some(dst), Value::RegisterPlusConstant64(src, insn.off as i64, true), 8, None);
                },

                // BPF_ST class
                ebpf::ST_B_IMM   => {
                    self.emit_address_translation(None, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 1, Some(Value::Constant64(insn.imm, true)));
                },
                ebpf::ST_H_IMM   => {
                    self.emit_address_translation(None, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 2, Some(Value::Constant64(insn.imm, true)));
                },
                ebpf::ST_W_IMM   => {
                    self.emit_address_translation(None, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 4, Some(Value::Constant64(insn.imm, true)));
                },
                ebpf::ST_DW_IMM  => {
                    self.emit_address_translation(None, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 8, Some(Value::Constant64(insn.imm, true)));
                },

                // BPF_STX class
                ebpf::ST_B_REG  => {
                    self.emit_address_translation(None, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 1, Some(Value::Register(src)));
                },
                ebpf::ST_H_REG  => {
                    self.emit_address_translation(None, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 2, Some(Value::Register(src)));
                },
                ebpf::ST_W_REG  => {
                    self.emit_address_translation(None, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 4, Some(Value::Register(src)));
                },
                ebpf::ST_DW_REG  => {
                    self.emit_address_translation(None, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 8, Some(Value::Register(src)));
                },

                // BPF_ALU class
                ebpf::ADD32_IMM  => {
                    self.emit_sanitized_alu(OperandSize::S32, 0x01, 0, dst, insn.imm);
                    self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x63, dst, dst, 0, None)); // sign extend i32 to i64
                },
                ebpf::ADD32_REG  => {
                    self.emit_ins(X86Instruction::alu(OperandSize::S32, 0x01, src, dst, 0, None));
                    self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x63, dst, dst, 0, None)); // sign extend i32 to i64
                },
                ebpf::SUB32_IMM  => {
                    if self.executable.get_sbpf_version().swap_sub_reg_imm_operands() {
                        self.emit_ins(X86Instruction::alu(OperandSize::S32, 0xf7, 3, dst, 0, None));
                        if insn.imm != 0 {
                            self.emit_sanitized_alu(OperandSize::S32, 0x01, 0, dst, insn.imm);
                        }
                    } else {
                        self.emit_sanitized_alu(OperandSize::S32, 0x29, 5, dst, insn.imm);
                    }
                    self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x63, dst, dst, 0, None)); // sign extend i32 to i64
                },
                ebpf::SUB32_REG  => {
                    self.emit_ins(X86Instruction::alu(OperandSize::S32, 0x29, src, dst, 0, None));
                    self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x63, dst, dst, 0, None)); // sign extend i32 to i64
                },
                ebpf::MUL32_IMM | ebpf::DIV32_IMM | ebpf::SDIV32_IMM | ebpf::MOD32_IMM  =>
                    self.emit_muldivmod(insn.opc, dst, dst, Some(insn.imm)),
                ebpf::MUL32_REG | ebpf::DIV32_REG | ebpf::SDIV32_REG | ebpf::MOD32_REG  =>
                    self.emit_muldivmod(insn.opc, src, dst, None),
                ebpf::OR32_IMM   => self.emit_sanitized_alu(OperandSize::S32, 0x09, 1, dst, insn.imm),
                ebpf::OR32_REG   => self.emit_ins(X86Instruction::alu(OperandSize::S32, 0x09, src, dst, 0, None)),
                ebpf::AND32_IMM  => self.emit_sanitized_alu(OperandSize::S32, 0x21, 4, dst, insn.imm),
                ebpf::AND32_REG  => self.emit_ins(X86Instruction::alu(OperandSize::S32, 0x21, src, dst, 0, None)),
                ebpf::LSH32_IMM  => self.emit_shift(OperandSize::S32, 4, R11, dst, Some(insn.imm)),
                ebpf::LSH32_REG  => self.emit_shift(OperandSize::S32, 4, src, dst, None),
                ebpf::RSH32_IMM  => self.emit_shift(OperandSize::S32, 5, R11, dst, Some(insn.imm)),
                ebpf::RSH32_REG  => self.emit_shift(OperandSize::S32, 5, src, dst, None),
                ebpf::NEG32     if self.executable.get_sbpf_version().enable_neg() => self.emit_ins(X86Instruction::alu(OperandSize::S32, 0xf7, 3, dst, 0, None)),
                ebpf::XOR32_IMM  => self.emit_sanitized_alu(OperandSize::S32, 0x31, 6, dst, insn.imm),
                ebpf::XOR32_REG  => self.emit_ins(X86Instruction::alu(OperandSize::S32, 0x31, src, dst, 0, None)),
                ebpf::MOV32_IMM  => {
                    if self.should_sanitize_constant(insn.imm) {
                        self.emit_sanitized_load_immediate(OperandSize::S32, dst, insn.imm);
                    } else {
                        self.emit_ins(X86Instruction::load_immediate(OperandSize::S32, dst, insn.imm));
                    }
                }
                ebpf::MOV32_REG  => self.emit_ins(X86Instruction::mov(OperandSize::S32, src, dst)),
                ebpf::ARSH32_IMM => self.emit_shift(OperandSize::S32, 7, R11, dst, Some(insn.imm)),
                ebpf::ARSH32_REG => self.emit_shift(OperandSize::S32, 7, src, dst, None),
                ebpf::LE         => {
                    match insn.imm {
                        16 => {
                            self.emit_ins(X86Instruction::alu(OperandSize::S32, 0x81, 4, dst, 0xffff, None)); // Mask to 16 bit
                        }
                        32 => {
                            self.emit_ins(X86Instruction::alu(OperandSize::S32, 0x81, 4, dst, -1, None)); // Mask to 32 bit
                        }
                        64 => {}
                        _ => {
                            return Err(EbpfError::InvalidInstruction(self.pc + ebpf::ELF_INSN_DUMP_OFFSET));
                        }
                    }
                },
                ebpf::BE         => {
                    match insn.imm {
                        16 => {
                            self.emit_ins(X86Instruction::bswap(OperandSize::S16, dst));
                            self.emit_ins(X86Instruction::alu(OperandSize::S32, 0x81, 4, dst, 0xffff, None)); // Mask to 16 bit
                        }
                        32 => self.emit_ins(X86Instruction::bswap(OperandSize::S32, dst)),
                        64 => self.emit_ins(X86Instruction::bswap(OperandSize::S64, dst)),
                        _ => {
                            return Err(EbpfError::InvalidInstruction(self.pc + ebpf::ELF_INSN_DUMP_OFFSET));
                        }
                    }
                },

                // BPF_ALU64 class
                ebpf::ADD64_IMM  => self.emit_sanitized_alu(OperandSize::S64, 0x01, 0, dst, insn.imm),
                ebpf::ADD64_REG  => self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x01, src, dst, 0, None)),
                ebpf::SUB64_IMM  => {
                    if self.executable.get_sbpf_version().swap_sub_reg_imm_operands() {
                        self.emit_ins(X86Instruction::alu(OperandSize::S64, 0xf7, 3, dst, 0, None));
                        if insn.imm != 0 {
                            self.emit_sanitized_alu(OperandSize::S64, 0x01, 0, dst, insn.imm);
                        }
                    } else {
                        self.emit_sanitized_alu(OperandSize::S64, 0x29, 5, dst, insn.imm);
                    }
                }
                ebpf::SUB64_REG  => self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x29, src, dst, 0, None)),
                ebpf::MUL64_IMM | ebpf::DIV64_IMM | ebpf::SDIV64_IMM | ebpf::MOD64_IMM  =>
                    self.emit_muldivmod(insn.opc, dst, dst, Some(insn.imm)),
                ebpf::MUL64_REG | ebpf::DIV64_REG | ebpf::SDIV64_REG | ebpf::MOD64_REG  =>
                    self.emit_muldivmod(insn.opc, src, dst, None),
                ebpf::OR64_IMM   => self.emit_sanitized_alu(OperandSize::S64, 0x09, 1, dst, insn.imm),
                ebpf::OR64_REG   => self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x09, src, dst, 0, None)),
                ebpf::AND64_IMM  => self.emit_sanitized_alu(OperandSize::S64, 0x21, 4, dst, insn.imm),
                ebpf::AND64_REG  => self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x21, src, dst, 0, None)),
                ebpf::LSH64_IMM  => self.emit_shift(OperandSize::S64, 4, R11, dst, Some(insn.imm)),
                ebpf::LSH64_REG  => self.emit_shift(OperandSize::S64, 4, src, dst, None),
                ebpf::RSH64_IMM  => self.emit_shift(OperandSize::S64, 5, R11, dst, Some(insn.imm)),
                ebpf::RSH64_REG  => self.emit_shift(OperandSize::S64, 5, src, dst, None),
                ebpf::NEG64     if self.executable.get_sbpf_version().enable_neg() => self.emit_ins(X86Instruction::alu(OperandSize::S64, 0xf7, 3, dst, 0, None)),
                ebpf::XOR64_IMM  => self.emit_sanitized_alu(OperandSize::S64, 0x31, 6, dst, insn.imm),
                ebpf::XOR64_REG  => self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x31, src, dst, 0, None)),
                ebpf::MOV64_IMM  => {
                    if self.should_sanitize_constant(insn.imm) {
                        self.emit_sanitized_load_immediate(OperandSize::S64, dst, insn.imm);
                    } else {
                        self.emit_ins(X86Instruction::load_immediate(OperandSize::S64, dst, insn.imm));
                    }
                }
                ebpf::MOV64_REG  => self.emit_ins(X86Instruction::mov(OperandSize::S64, src, dst)),
                ebpf::ARSH64_IMM => self.emit_shift(OperandSize::S64, 7, R11, dst, Some(insn.imm)),
                ebpf::ARSH64_REG => self.emit_shift(OperandSize::S64, 7, src, dst, None),

                // BPF_JMP class
                ebpf::JA         => {
                    self.emit_validate_and_profile_instruction_count(false, Some(target_pc));
                    self.emit_ins(X86Instruction::load_immediate(OperandSize::S64, R11, target_pc as i64));
                    let jump_offset = self.relative_to_target_pc(target_pc, 5);
                    self.emit_ins(X86Instruction::jump_immediate(jump_offset));
                },
                ebpf::JEQ_IMM    => self.emit_conditional_branch_imm(0x84, false, insn.imm, dst, target_pc),
                ebpf::JEQ_REG    => self.emit_conditional_branch_reg(0x84, false, src, dst, target_pc),
                ebpf::JGT_IMM    => self.emit_conditional_branch_imm(0x87, false, insn.imm, dst, target_pc),
                ebpf::JGT_REG    => self.emit_conditional_branch_reg(0x87, false, src, dst, target_pc),
                ebpf::JGE_IMM    => self.emit_conditional_branch_imm(0x83, false, insn.imm, dst, target_pc),
                ebpf::JGE_REG    => self.emit_conditional_branch_reg(0x83, false, src, dst, target_pc),
                ebpf::JLT_IMM    => self.emit_conditional_branch_imm(0x82, false, insn.imm, dst, target_pc),
                ebpf::JLT_REG    => self.emit_conditional_branch_reg(0x82, false, src, dst, target_pc),
                ebpf::JLE_IMM    => self.emit_conditional_branch_imm(0x86, false, insn.imm, dst, target_pc),
                ebpf::JLE_REG    => self.emit_conditional_branch_reg(0x86, false, src, dst, target_pc),
                ebpf::JSET_IMM   => self.emit_conditional_branch_imm(0x85, true, insn.imm, dst, target_pc),
                ebpf::JSET_REG   => self.emit_conditional_branch_reg(0x85, true, src, dst, target_pc),
                ebpf::JNE_IMM    => self.emit_conditional_branch_imm(0x85, false, insn.imm, dst, target_pc),
                ebpf::JNE_REG    => self.emit_conditional_branch_reg(0x85, false, src, dst, target_pc),
                ebpf::JSGT_IMM   => self.emit_conditional_branch_imm(0x8f, false, insn.imm, dst, target_pc),
                ebpf::JSGT_REG   => self.emit_conditional_branch_reg(0x8f, false, src, dst, target_pc),
                ebpf::JSGE_IMM   => self.emit_conditional_branch_imm(0x8d, false, insn.imm, dst, target_pc),
                ebpf::JSGE_REG   => self.emit_conditional_branch_reg(0x8d, false, src, dst, target_pc),
                ebpf::JSLT_IMM   => self.emit_conditional_branch_imm(0x8c, false, insn.imm, dst, target_pc),
                ebpf::JSLT_REG   => self.emit_conditional_branch_reg(0x8c, false, src, dst, target_pc),
                ebpf::JSLE_IMM   => self.emit_conditional_branch_imm(0x8e, false, insn.imm, dst, target_pc),
                ebpf::JSLE_REG   => self.emit_conditional_branch_reg(0x8e, false, src, dst, target_pc),
                ebpf::CALL_IMM   => {
                    // For JIT, external functions MUST be registered at compile time.

                    let mut resolved = false;
                    let (external, internal) = if self.executable.get_sbpf_version().static_syscalls() {
                        (insn.src == 0, insn.src != 0)
                    } else {
                        (true, true)
                    };

                    if external {
                        if let Some((_function_name, function)) = self.executable.get_loader().get_function_registry().lookup_by_key(insn.imm as u32) {
                            self.emit_validate_and_profile_instruction_count(true, Some(0));
                            self.emit_ins(X86Instruction::load_immediate(OperandSize::S64, R11, function as usize as i64));
                            self.emit_ins(X86Instruction::call_immediate(self.relative_to_anchor(ANCHOR_EXTERNAL_FUNCTION_CALL, 5)));
                            self.emit_undo_profile_instruction_count(0);
                            resolved = true;
                        }
                    }

                    if internal {
                        if let Some((_function_name, target_pc)) = self.executable.get_function_registry().lookup_by_key(insn.imm as u32) {
                            self.emit_internal_call(Value::Constant64(target_pc as i64, false));
                            resolved = true;
                        }
                    }

                    if !resolved {
                        self.emit_ins(X86Instruction::load_immediate(OperandSize::S64, R11, self.pc as i64));
                        self.emit_ins(X86Instruction::jump_immediate(self.relative_to_anchor(ANCHOR_CALL_UNSUPPORTED_INSTRUCTION, 5)));
                    }
                },
                ebpf::CALL_REG  => {
                    let target_pc = if self.executable.get_sbpf_version().callx_uses_src_reg() {
                        src
                    } else {
                        REGISTER_MAP[insn.imm as usize]
                    };
                    self.emit_internal_call(Value::Register(target_pc));
                },
                ebpf::EXIT      => {
                    let call_depth_access = X86IndirectAccess::Offset(self.slot_on_environment_stack(RuntimeEnvironmentSlot::CallDepth));
                    self.emit_ins(X86Instruction::load(OperandSize::S64, RBP, REGISTER_MAP[FRAME_PTR_REG], call_depth_access));

                    // If CallDepth == 0, we've reached the exit instruction of the entry point
                    self.emit_ins(X86Instruction::cmp_immediate(OperandSize::S32, REGISTER_MAP[FRAME_PTR_REG], 0, None));
                    if self.config.enable_instruction_meter {
                        self.emit_ins(X86Instruction::load_immediate(OperandSize::S64, R11, self.pc as i64));
                    }
                    // we're done
                    self.emit_ins(X86Instruction::conditional_jump_immediate(0x84, self.relative_to_anchor(ANCHOR_EXIT, 6)));

                    // else decrement and update CallDepth
                    self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x81, 5, REGISTER_MAP[FRAME_PTR_REG], 1, None));
                    self.emit_ins(X86Instruction::store(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], RBP, call_depth_access));

                    if !self.executable.get_sbpf_version().dynamic_stack_frames() {
                        let stack_pointer_access = X86IndirectAccess::Offset(self.slot_on_environment_stack(RuntimeEnvironmentSlot::StackPointer));
                        let stack_frame_size = self.config.stack_frame_size as i64 * if self.config.enable_stack_frame_gaps { 2 } else { 1 };
                        self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x81, 5, RBP, stack_frame_size, Some(stack_pointer_access))); // env.stack_pointer -= stack_frame_size;
                    }

                    // and return
                    self.emit_validate_and_profile_instruction_count(false, Some(0));
                    self.emit_ins(X86Instruction::return_near());
                },

                _               => return Err(EbpfError::UnsupportedInstruction(self.pc + ebpf::ELF_INSN_DUMP_OFFSET)),
            }

            self.pc += 1;
        }

        // Bumper in case there was no final exit
        if self.offset_in_text_section + MAX_MACHINE_CODE_LENGTH_PER_INSTRUCTION > self.result.text_section.len() {
            return Err(EbpfError::ExhaustedTextSegment(self.pc));
        }        
        self.emit_validate_and_profile_instruction_count(true, Some(self.pc + 2));
        self.emit_ins(X86Instruction::load_immediate(OperandSize::S64, R11, self.pc as i64));
        self.emit_set_exception_kind(EbpfError::ExecutionOverrun(0));
        self.emit_ins(X86Instruction::jump_immediate(self.relative_to_anchor(ANCHOR_THROW_EXCEPTION, 5)));

        self.resolve_jumps();
        self.result.seal(self.offset_in_text_section)?;
        Ok(self.result)
    }

    #[inline]
    fn should_sanitize_constant(&self, value: i64) -> bool {
        if !self.config.sanitize_user_provided_values {
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
    fn slot_on_environment_stack(&self, slot: RuntimeEnvironmentSlot) -> i32 {
        8 * (slot as i32 - self.runtime_environment_key)
    }

    #[inline]
    pub(crate) fn emit<T>(&mut self, data: T) {
        unsafe {
            let ptr = self.result.text_section.as_ptr().add(self.offset_in_text_section);
            #[allow(clippy::cast_ptr_alignment)]
            ptr::write_unaligned(ptr as *mut T, data as T);
        }
        self.offset_in_text_section += mem::size_of::<T>();
    }

    #[inline]
    pub(crate) fn emit_variable_length(&mut self, size: OperandSize, data: u64) {
        match size {
            OperandSize::S0 => {},
            OperandSize::S8 => self.emit::<u8>(data as u8),
            OperandSize::S16 => self.emit::<u16>(data as u16),
            OperandSize::S32 => self.emit::<u32>(data as u32),
            OperandSize::S64 => self.emit::<u64>(data),
        }
    }

    // This function helps the optimizer to inline the machinecode emission while avoiding stack allocations
    #[inline(always)]
    pub fn emit_ins(&mut self, instruction: X86Instruction) {
        instruction.emit(self);
        if self.next_noop_insertion == 0 {
            self.next_noop_insertion = self.diversification_rng.gen_range(0..self.config.noop_instruction_rate * 2);
            // X86Instruction::noop().emit(self)?;
            self.emit::<u8>(0x90);
        } else {
            self.next_noop_insertion -= 1;
        }
    }

    #[inline]
    fn emit_sanitized_load_immediate(&mut self, size: OperandSize, destination: u8, value: i64) {
        match size {
            OperandSize::S32 => {
                let key: i32 = self.diversification_rng.gen();
                self.emit_ins(X86Instruction::load_immediate(size, destination, (value as i32).wrapping_sub(key) as i64));
                self.emit_ins(X86Instruction::alu(size, 0x81, 0, destination, key as i64, None));
            },
            OperandSize::S64 if destination == R11 => {
                let key: i64 = self.diversification_rng.gen();
                let lower_key = key as i32 as i64;
                let upper_key = (key >> 32) as i32 as i64;
                self.emit_ins(X86Instruction::load_immediate(size, destination, value.wrapping_sub(lower_key).rotate_right(32).wrapping_sub(upper_key)));
                self.emit_ins(X86Instruction::alu(size, 0x81, 0, destination, upper_key, None)); // wrapping_add(upper_key)
                self.emit_ins(X86Instruction::alu(size, 0xc1, 1, destination, 32, None)); // rotate_right(32)
                self.emit_ins(X86Instruction::alu(size, 0x81, 0, destination, lower_key, None)); // wrapping_add(lower_key)
            },
            OperandSize::S64 if value >= i32::MIN as i64 && value <= i32::MAX as i64 => {
                let key = self.diversification_rng.gen::<i32>() as i64;
                self.emit_ins(X86Instruction::load_immediate(size, destination, value.wrapping_sub(key)));
                self.emit_ins(X86Instruction::alu(size, 0x81, 0, destination, key, None));
            },
            OperandSize::S64 => {
                let key: i64 = self.diversification_rng.gen();
                self.emit_ins(X86Instruction::load_immediate(size, destination, value.wrapping_sub(key)));
                self.emit_ins(X86Instruction::load_immediate(size, R11, key));
                self.emit_ins(X86Instruction::alu(size, 0x01, R11, destination, 0, None));
            },
            _ => {
                #[cfg(debug_assertions)]
                unreachable!();
            }
        }
    }

    #[inline]
    fn emit_sanitized_alu(&mut self, size: OperandSize, opcode: u8, opcode_extension: u8, destination: u8, immediate: i64) {
        if self.should_sanitize_constant(immediate) {
            self.emit_sanitized_load_immediate(size, R11, immediate);
            self.emit_ins(X86Instruction::alu(size, opcode, R11, destination, immediate, None));
        } else {
            self.emit_ins(X86Instruction::alu(size, 0x81, opcode_extension, destination, immediate, None));
        }
    }

    #[allow(dead_code)]
    #[inline]
    fn emit_stopwatch(&mut self, begin: bool) {
        self.stopwatch_is_active = true;
        self.emit_ins(X86Instruction::push(RDX, None));
        self.emit_ins(X86Instruction::push(RAX, None));
        self.emit_ins(X86Instruction::fence(FenceType::Load)); // lfence
        self.emit_ins(X86Instruction::cycle_count()); // rdtsc
        self.emit_ins(X86Instruction::fence(FenceType::Load)); // lfence
        self.emit_ins(X86Instruction::alu(OperandSize::S64, 0xc1, 4, RDX, 32, None)); // RDX <<= 32;
        self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x09, RDX, RAX, 0, None)); // RAX |= RDX;
        if begin {
            self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x29, RAX, RBP, 0, Some(X86IndirectAccess::Offset(self.slot_on_environment_stack(RuntimeEnvironmentSlot::StopwatchNumerator))))); // *numerator -= RAX;
        } else {
            self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x01, RAX, RBP, 0, Some(X86IndirectAccess::Offset(self.slot_on_environment_stack(RuntimeEnvironmentSlot::StopwatchNumerator))))); // *numerator += RAX;
            self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x81, 0, RBP, 1, Some(X86IndirectAccess::Offset(self.slot_on_environment_stack(RuntimeEnvironmentSlot::StopwatchDenominator))))); // *denominator += 1;
        }
        self.emit_ins(X86Instruction::pop(RAX));
        self.emit_ins(X86Instruction::pop(RDX));
    }

    #[inline]
    fn emit_validate_instruction_count(&mut self, exclusive: bool, pc: Option<usize>) {
        if !self.config.enable_instruction_meter {
            return;
        }
        // Update `MACHINE_CODE_PER_INSTRUCTION_METER_CHECKPOINT` if you change the code generation here
        if let Some(pc) = pc {
            self.last_instruction_meter_validation_pc = pc;
            self.emit_ins(X86Instruction::cmp_immediate(OperandSize::S64, ARGUMENT_REGISTERS[0], pc as i64 + 1, None));
        } else {
            self.emit_ins(X86Instruction::cmp(OperandSize::S64, R11, ARGUMENT_REGISTERS[0], None));
        }
        self.emit_ins(X86Instruction::conditional_jump_immediate(if exclusive { 0x82 } else { 0x86 }, self.relative_to_anchor(ANCHOR_CALL_EXCEEDED_MAX_INSTRUCTIONS, 6)));
    }

    #[inline]
    fn emit_profile_instruction_count(&mut self, target_pc: Option<usize>) {
        match target_pc {
            Some(target_pc) => {
                self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x81, 0, ARGUMENT_REGISTERS[0], target_pc as i64 - self.pc as i64 - 1, None)); // instruction_meter += target_pc - (self.pc + 1);
            },
            None => {
                self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x81, 5, ARGUMENT_REGISTERS[0], self.pc as i64 + 1, None)); // instruction_meter -= self.pc + 1;
                self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x01, R11, ARGUMENT_REGISTERS[0], self.pc as i64, None)); // instruction_meter += target_pc;
            },
        }
    }

    #[inline]
    fn emit_validate_and_profile_instruction_count(&mut self, exclusive: bool, target_pc: Option<usize>) {
        if self.config.enable_instruction_meter {
            self.emit_validate_instruction_count(exclusive, Some(self.pc));
            self.emit_profile_instruction_count(target_pc);
        }
    }

    #[inline]
    fn emit_undo_profile_instruction_count(&mut self, target_pc: usize) {
        if self.config.enable_instruction_meter {
            self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x81, 0, ARGUMENT_REGISTERS[0], self.pc as i64 + 1 - target_pc as i64, None)); // instruction_meter += (self.pc + 1) - target_pc;
        }
    }

    fn emit_rust_call(&mut self, dst: Value, arguments: &[Argument], result_reg: Option<u8>) {
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
            self.emit_ins(X86Instruction::push(*reg, None));
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
                        self.emit_ins(X86Instruction::push(reg, None));
                    } else if reg != dst {
                        self.emit_ins(X86Instruction::mov(OperandSize::S64, reg, dst));
                    }
                },
                Value::RegisterIndirect(reg, offset, user_provided) => {
                    debug_assert!(!user_provided);
                    if is_stack_argument {
                        self.emit_ins(X86Instruction::push(reg, Some(X86IndirectAccess::Offset(offset))));
                    } else {
                        self.emit_ins(X86Instruction::load(OperandSize::S64, reg, dst, X86IndirectAccess::Offset(offset)));
                    }
                },
                Value::RegisterPlusConstant32(reg, offset, user_provided) => {
                    debug_assert!(!user_provided);
                    if is_stack_argument {
                        self.emit_ins(X86Instruction::push(reg, None));
                        self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x81, 0, RSP, offset as i64, Some(X86IndirectAccess::OffsetIndexShift(0, RSP, 0))));
                    } else {
                        self.emit_ins(X86Instruction::lea(OperandSize::S64, reg, dst, Some(X86IndirectAccess::Offset(offset))));
                    }
                },
                Value::RegisterPlusConstant64(reg, offset, user_provided) => {
                    debug_assert!(!user_provided);
                    if is_stack_argument {
                        self.emit_ins(X86Instruction::push(reg, None));
                        self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x81, 0, RSP, offset, Some(X86IndirectAccess::OffsetIndexShift(0, RSP, 0))));
                    } else {
                        self.emit_ins(X86Instruction::load_immediate(OperandSize::S64, dst, offset));
                        self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x01, reg, dst, 0, None));
                    }
                },
                Value::Constant64(value, user_provided) => {
                    debug_assert!(!user_provided && !is_stack_argument);
                    self.emit_ins(X86Instruction::load_immediate(OperandSize::S64, dst, value));
                },
            }
        }
    
        match dst {
            Value::Register(reg) => {
                self.emit_ins(X86Instruction::call_reg(reg, None));
            },
            Value::Constant64(value, user_provided) => {
                debug_assert!(!user_provided);
                self.emit_ins(X86Instruction::load_immediate(OperandSize::S64, RAX, value));
                self.emit_ins(X86Instruction::call_reg(RAX, None));
            },
            _ => {
                #[cfg(debug_assertions)]
                unreachable!();
            }
        }
    
        // Save returned value in result register
        if let Some(reg) = result_reg {
            self.emit_ins(X86Instruction::mov(OperandSize::S64, RAX, reg));
        }
    
        // Restore registers from stack
        self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x81, 0, RSP, stack_arguments * 8, None));
        for reg in saved_registers.iter().rev() {
            self.emit_ins(X86Instruction::pop(*reg));
        }
    }

    #[inline]
    fn emit_internal_call(&mut self, dst: Value) {
        // Store PC in case the bounds check fails
        self.emit_ins(X86Instruction::load_immediate(OperandSize::S64, R11, self.pc as i64));

        self.emit_ins(X86Instruction::call_immediate(self.relative_to_anchor(ANCHOR_ANCHOR_INTERNAL_FUNCTION_CALL_PROLOGUE, 5)));

        match dst {
            Value::Register(reg) => {
                // Move vm target_address into RAX
                self.emit_ins(X86Instruction::push(REGISTER_MAP[0], None));
                if reg != REGISTER_MAP[0] {
                    self.emit_ins(X86Instruction::mov(OperandSize::S64, reg, REGISTER_MAP[0]));
                }

                self.emit_ins(X86Instruction::call_immediate(self.relative_to_anchor(ANCHOR_ANCHOR_INTERNAL_FUNCTION_CALL_REG, 5)));

                self.emit_validate_and_profile_instruction_count(false, None);
                self.emit_ins(X86Instruction::mov(OperandSize::S64, REGISTER_MAP[0], R10));
                self.emit_ins(X86Instruction::pop(REGISTER_MAP[0])); // Restore RAX
                self.emit_ins(X86Instruction::call_reg(R10, None)); // callq *%r10
            },
            Value::Constant64(target_pc, user_provided) => {
                debug_assert!(!user_provided);
                self.emit_validate_and_profile_instruction_count(false, Some(target_pc as usize));
                self.emit_ins(X86Instruction::load_immediate(OperandSize::S64, R11, target_pc));
                let jump_offset = self.relative_to_target_pc(target_pc as usize, 5);
                self.emit_ins(X86Instruction::call_immediate(jump_offset));
            },
            _ => {
                #[cfg(debug_assertions)]
                unreachable!();
            }
        }

        self.emit_undo_profile_instruction_count(0);

        // Restore the previous frame pointer
        self.emit_ins(X86Instruction::pop(REGISTER_MAP[FRAME_PTR_REG]));
        for reg in REGISTER_MAP.iter().skip(FIRST_SCRATCH_REG).take(SCRATCH_REGS).rev() {
            self.emit_ins(X86Instruction::pop(*reg));
        }
    }

    #[inline]
    fn emit_address_translation(&mut self, dst: Option<u8>, vm_addr: Value, len: u64, value: Option<Value>) {
        debug_assert_ne!(dst.is_some(), value.is_some());

        match vm_addr {
            Value::RegisterPlusConstant64(reg, constant, user_provided) => {
                if user_provided && self.should_sanitize_constant(constant) {
                    self.emit_sanitized_load_immediate(OperandSize::S64, R11, constant);
                } else {
                    self.emit_ins(X86Instruction::load_immediate(OperandSize::S64, R11, constant));
                }
                self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x01, reg, R11, 0, None));
            },
            Value::Constant64(constant, user_provided) => {
                if user_provided && self.should_sanitize_constant(constant) {
                    self.emit_sanitized_load_immediate(OperandSize::S64, R11, constant);
                } else {
                    self.emit_ins(X86Instruction::load_immediate(OperandSize::S64, R11, constant));
                }
            },
            _ => {
                #[cfg(debug_assertions)]
                unreachable!();
            },
        }

        match value {
            Some(Value::Register(reg)) => {
                self.emit_ins(X86Instruction::mov(OperandSize::S64, reg, R10));
            }
            Some(Value::Constant64(constant, user_provided)) => {
                if user_provided && self.should_sanitize_constant(constant) {
                    self.emit_sanitized_load_immediate(OperandSize::S64, R10, constant);
                } else {
                    self.emit_ins(X86Instruction::load_immediate(OperandSize::S64, R10, constant));
                }
            }
            _ => {}
        }

        if self.config.enable_address_translation {
            let access_type = if value.is_none() { AccessType::Load } else { AccessType::Store };
            let anchor = ANCHOR_TRANSLATE_MEMORY_ADDRESS + len.trailing_zeros() as usize + 4 * (access_type as usize);
            self.emit_ins(X86Instruction::push_immediate(OperandSize::S64, self.pc as i32));
            self.emit_ins(X86Instruction::call_immediate(self.relative_to_anchor(anchor, 5)));
            if let Some(dst) = dst {
                self.emit_ins(X86Instruction::mov(OperandSize::S64, R11, dst));
            }
        } else if let Some(dst) = dst {
            match len {
                1 => self.emit_ins(X86Instruction::load(OperandSize::S8, R11, dst, X86IndirectAccess::Offset(0))),
                2 => self.emit_ins(X86Instruction::load(OperandSize::S16, R11, dst, X86IndirectAccess::Offset(0))),
                4 => self.emit_ins(X86Instruction::load(OperandSize::S32, R11, dst, X86IndirectAccess::Offset(0))),
                8 => self.emit_ins(X86Instruction::load(OperandSize::S64, R11, dst, X86IndirectAccess::Offset(0))),
                _ => unreachable!(),
            }
        } else {
            match len {
                1 => self.emit_ins(X86Instruction::store(OperandSize::S8, R10, R11, X86IndirectAccess::Offset(0))),
                2 => self.emit_ins(X86Instruction::store(OperandSize::S16, R10, R11, X86IndirectAccess::Offset(0))),
                4 => self.emit_ins(X86Instruction::store(OperandSize::S32, R10, R11, X86IndirectAccess::Offset(0))),
                8 => self.emit_ins(X86Instruction::store(OperandSize::S64, R10, R11, X86IndirectAccess::Offset(0))),
                _ => unreachable!(),
            }
        }
    }

    #[inline]
    fn emit_conditional_branch_reg(&mut self, op: u8, bitwise: bool, first_operand: u8, second_operand: u8, target_pc: usize) {
        self.emit_validate_and_profile_instruction_count(false, Some(target_pc));
        if bitwise { // Logical
            self.emit_ins(X86Instruction::test(OperandSize::S64, first_operand, second_operand, None));
        } else { // Arithmetic
            self.emit_ins(X86Instruction::cmp(OperandSize::S64, first_operand, second_operand, None));
        }
        self.emit_ins(X86Instruction::load_immediate(OperandSize::S64, R11, target_pc as i64));
        let jump_offset = self.relative_to_target_pc(target_pc, 6);
        self.emit_ins(X86Instruction::conditional_jump_immediate(op, jump_offset));
        self.emit_undo_profile_instruction_count(target_pc);
    }

    #[inline]
    fn emit_conditional_branch_imm(&mut self, op: u8, bitwise: bool, immediate: i64, second_operand: u8, target_pc: usize) {
        self.emit_validate_and_profile_instruction_count(false, Some(target_pc));
        if self.should_sanitize_constant(immediate) {
            self.emit_sanitized_load_immediate(OperandSize::S64, R11, immediate);
            if bitwise { // Logical
                self.emit_ins(X86Instruction::test(OperandSize::S64, R11, second_operand, None));
            } else { // Arithmetic
                self.emit_ins(X86Instruction::cmp(OperandSize::S64, R11, second_operand, None));
            }
        } else if bitwise { // Logical
            self.emit_ins(X86Instruction::test_immediate(OperandSize::S64, second_operand, immediate, None));
        } else { // Arithmetic
            self.emit_ins(X86Instruction::cmp_immediate(OperandSize::S64, second_operand, immediate, None));
        }
        self.emit_ins(X86Instruction::load_immediate(OperandSize::S64, R11, target_pc as i64));
        let jump_offset = self.relative_to_target_pc(target_pc, 6);
        self.emit_ins(X86Instruction::conditional_jump_immediate(op, jump_offset));
        self.emit_undo_profile_instruction_count(target_pc);
    }

    fn emit_shift(&mut self, size: OperandSize, opcode_extension: u8, source: u8, destination: u8, immediate: Option<i64>) {
        if let Some(immediate) = immediate {
            if self.should_sanitize_constant(immediate) {
                self.emit_sanitized_load_immediate(OperandSize::S32, source, immediate);
            } else {
                self.emit_ins(X86Instruction::alu(size, 0xc1, opcode_extension, destination, immediate, None));
                return;
            }
        }
        if let OperandSize::S32 = size {
            self.emit_ins(X86Instruction::alu(OperandSize::S32, 0x81, 4, destination, -1, None)); // Mask to 32 bit
        }
        if source == RCX {
            if destination == RCX {
                self.emit_ins(X86Instruction::alu(size, 0xd3, opcode_extension, destination, 0, None));
            } else {
                self.emit_ins(X86Instruction::push(RCX, None));
                self.emit_ins(X86Instruction::alu(size, 0xd3, opcode_extension, destination, 0, None));
                self.emit_ins(X86Instruction::pop(RCX));
            }
        } else if destination == RCX {
            if source != R11 {
                self.emit_ins(X86Instruction::push(source, None));
            }
            self.emit_ins(X86Instruction::xchg(OperandSize::S64, source, RCX, None));
            self.emit_ins(X86Instruction::alu(size, 0xd3, opcode_extension, source, 0, None));
            self.emit_ins(X86Instruction::mov(OperandSize::S64, source, RCX));
            if source != R11 {
                self.emit_ins(X86Instruction::pop(source));
            }
        } else {
            self.emit_ins(X86Instruction::push(RCX, None));
            self.emit_ins(X86Instruction::mov(OperandSize::S64, source, RCX));
            self.emit_ins(X86Instruction::alu(size, 0xd3, opcode_extension, destination, 0, None));
            self.emit_ins(X86Instruction::pop(RCX));
        }
    }

    fn emit_muldivmod(&mut self, opc: u8, src: u8, dst: u8, imm: Option<i64>) {
        let mul = (opc & ebpf::BPF_ALU_OP_MASK) == (ebpf::MUL32_IMM & ebpf::BPF_ALU_OP_MASK);
        let div = (opc & ebpf::BPF_ALU_OP_MASK) == (ebpf::DIV32_IMM & ebpf::BPF_ALU_OP_MASK);
        let sdiv = (opc & ebpf::BPF_ALU_OP_MASK) == (ebpf::SDIV32_IMM & ebpf::BPF_ALU_OP_MASK);
        let modrm = (opc & ebpf::BPF_ALU_OP_MASK) == (ebpf::MOD32_IMM & ebpf::BPF_ALU_OP_MASK);
        let size = if (opc & ebpf::BPF_CLS_MASK) == ebpf::BPF_ALU64 { OperandSize::S64 } else { OperandSize::S32 };
    
        if !mul && imm.is_none() {
            // Save pc
            self.emit_ins(X86Instruction::load_immediate(OperandSize::S64, R11, self.pc as i64));
            self.emit_ins(X86Instruction::test(size, src, src, None)); // src == 0
            self.emit_ins(X86Instruction::conditional_jump_immediate(0x84, self.relative_to_anchor(ANCHOR_DIV_BY_ZERO, 6)));
        }
    
        // sdiv overflows with MIN / -1. If we have an immediate and it's not -1, we
        // don't need any checks.
        if sdiv && imm.unwrap_or(-1) == -1 {
            self.emit_ins(X86Instruction::load_immediate(size, R11, if let OperandSize::S64 = size { i64::MIN } else { i32::MIN as i64 }));
            self.emit_ins(X86Instruction::cmp(size, dst, R11, None)); // dst == MIN
    
            if imm.is_none() {
                // The exception case is: dst == MIN && src == -1
                // Via De Morgan's law becomes: !(dst != MIN || src != -1)
                // Also, we know that src != 0 in here, so we can use it to set R11 to something not zero
                self.emit_ins(X86Instruction::load_immediate(size, R11, 0)); // No XOR here because we need to keep the status flags
                self.emit_ins(X86Instruction::cmov(size, 0x45, src, R11)); // if dst != MIN { r11 = src; }
                self.emit_ins(X86Instruction::cmp_immediate(size, src, -1, None)); // src == -1
                self.emit_ins(X86Instruction::cmov(size, 0x45, src, R11)); // if src != -1 { r11 = src; }
                self.emit_ins(X86Instruction::test(size, R11, R11, None)); // r11 == 0
            }
            
            // MIN / -1, raise EbpfError::DivideOverflow(pc)
            self.emit_ins(X86Instruction::load_immediate(OperandSize::S64, R11, self.pc as i64));
            self.emit_ins(X86Instruction::conditional_jump_immediate(0x84, self.relative_to_anchor(ANCHOR_DIV_OVERFLOW, 6)));
        }
    
        if dst != RAX {
            self.emit_ins(X86Instruction::push(RAX, None));
        }
        if dst != RDX {
            self.emit_ins(X86Instruction::push(RDX, None));
        }
    
        if let Some(imm) = imm {
            if self.should_sanitize_constant(imm) {
                self.emit_sanitized_load_immediate(OperandSize::S64, R11, imm);
            } else {
                self.emit_ins(X86Instruction::load_immediate(OperandSize::S64, R11, imm));
            }
        } else {
            self.emit_ins(X86Instruction::mov(OperandSize::S64, src, R11));
        }
    
        if dst != RAX {
            self.emit_ins(X86Instruction::mov(OperandSize::S64, dst, RAX));
        }
    
        if div || modrm {
            self.emit_ins(X86Instruction::alu(size, 0x31, RDX, RDX, 0, None)); // RDX = 0
        } else if sdiv {
            self.emit_ins(X86Instruction::dividend_sign_extension(size)); // (RAX, RDX) = RAX as i128
        }
    
        self.emit_ins(X86Instruction::alu(size, 0xf7, if mul { 4 } else if sdiv { 7 } else { 6 }, R11, 0, None));
    
        if dst != RDX {
            if modrm {
                self.emit_ins(X86Instruction::mov(OperandSize::S64, RDX, dst));
            }
            self.emit_ins(X86Instruction::pop(RDX));
        }
        if dst != RAX {
            if !modrm {
                self.emit_ins(X86Instruction::mov(OperandSize::S64, RAX, dst));
            }
            self.emit_ins(X86Instruction::pop(RAX));
        }
    
        if let OperandSize::S32 = size {
            if mul || sdiv {
                self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x63, dst, dst, 0, None)); // sign extend i32 to i64
            }
        }
    }

    fn emit_set_exception_kind(&mut self, err: EbpfError) {
        self.emit_ins(X86Instruction::call_immediate(self.relative_to_anchor(ANCHOR_ALLOCATE_EXCEPTION, 5)));
        let err_kind = unsafe { *(&err as *const _ as *const u64) };
        self.emit_ins(X86Instruction::store_immediate(OperandSize::S64, R10, X86IndirectAccess::Offset(0), err_kind as i64)); // err.kind = err_kind;
    }

    fn emit_result_is_err(&mut self, destination: u8) {
        let ok = ProgramResult::Ok(0);
        let err_kind = unsafe { *(&ok as *const _ as *const u64).add(1) };
        self.emit_ins(X86Instruction::lea(OperandSize::S64, RBP, destination, Some(X86IndirectAccess::Offset(self.slot_on_environment_stack(RuntimeEnvironmentSlot::ProgramResult)))));
        self.emit_ins(X86Instruction::cmp_immediate(OperandSize::S64, destination, err_kind as i64, Some(X86IndirectAccess::Offset(0))));
    }

    fn emit_subroutines(&mut self) {
        // Routine for instruction tracing
        if self.config.enable_instruction_tracing {
            self.set_anchor(ANCHOR_TRACE);
            // Save registers on stack
            self.emit_ins(X86Instruction::push(R11, None));
            for reg in REGISTER_MAP.iter().rev() {
                self.emit_ins(X86Instruction::push(*reg, None));
            }
            self.emit_ins(X86Instruction::mov(OperandSize::S64, RSP, REGISTER_MAP[0]));
            self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x81, 0, RSP, - 8 * 3, None)); // RSP -= 8 * 3;
            self.emit_rust_call(Value::Constant64(C::trace as *const u8 as i64, false), &[
                Argument { index: 1, value: Value::Register(REGISTER_MAP[0]) }, // registers
                Argument { index: 0, value: Value::RegisterIndirect(RBP, self.slot_on_environment_stack(RuntimeEnvironmentSlot::ContextObjectPointer), false) },
            ], None);
            // Pop stack and return
            self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x81, 0, RSP, 8 * 3, None)); // RSP += 8 * 3;
            self.emit_ins(X86Instruction::pop(REGISTER_MAP[0]));
            self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x81, 0, RSP, 8 * (REGISTER_MAP.len() - 1) as i64, None)); // RSP += 8 * (REGISTER_MAP.len() - 1);
            self.emit_ins(X86Instruction::pop(R11));
            self.emit_ins(X86Instruction::return_near());
        }

        // Epilogue
        self.set_anchor(ANCHOR_EPILOGUE);
        if self.config.enable_instruction_meter {
            self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x81, 5, ARGUMENT_REGISTERS[0], 1, None)); // instruction_meter -= 1;
            self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x29, R11, ARGUMENT_REGISTERS[0], 0, None)); // instruction_meter -= pc;
        }
        // Print stop watch value
        fn stopwatch_result(numerator: u64, denominator: u64) {
            println!("Stop watch: {} / {} = {}", numerator, denominator, if denominator == 0 { 0.0 } else { numerator as f64 / denominator as f64 });
        }
        if self.stopwatch_is_active {
            self.emit_rust_call(Value::Constant64(stopwatch_result as *const u8 as i64, false), &[
                Argument { index: 1, value: Value::RegisterIndirect(RBP, self.slot_on_environment_stack(RuntimeEnvironmentSlot::StopwatchDenominator), false) },
                Argument { index: 0, value: Value::RegisterIndirect(RBP, self.slot_on_environment_stack(RuntimeEnvironmentSlot::StopwatchNumerator), false) },
            ], None);
        }
        // Restore stack pointer in case we did not exit gracefully
        self.emit_ins(X86Instruction::load(OperandSize::S64, RBP, RSP, X86IndirectAccess::Offset(self.slot_on_environment_stack(RuntimeEnvironmentSlot::HostStackPointer))));
        self.emit_ins(X86Instruction::return_near());

        // Routine for allocating errors
        self.set_anchor(ANCHOR_ALLOCATE_EXCEPTION);
        unsafe fn allocate_error(result: &mut ProgramResult) -> *mut EbpfError {
            let err_ptr = std::alloc::alloc(std::alloc::Layout::new::<EbpfError>()) as *mut EbpfError;
            *result = ProgramResult::Err(Box::from_raw(err_ptr));
            err_ptr
        }
        self.emit_ins(X86Instruction::lea(OperandSize::S64, RBP, R10, Some(X86IndirectAccess::Offset(self.slot_on_environment_stack(RuntimeEnvironmentSlot::ProgramResult)))));
        self.emit_rust_call(Value::Constant64(allocate_error as usize as i64, false), &[
            Argument { index: 0, value: Value::Register(R10) },
        ], Some(R10));
        self.emit_ins(X86Instruction::return_near());

        // Handler for EbpfError::ExceededMaxInstructions
        self.set_anchor(ANCHOR_CALL_EXCEEDED_MAX_INSTRUCTIONS);
        self.emit_set_exception_kind(EbpfError::ExceededMaxInstructions(0));
        self.emit_ins(X86Instruction::mov(OperandSize::S64, ARGUMENT_REGISTERS[0], R11)); // R11 = instruction_meter;
        // Fall through

        // Epilogue for errors
        self.set_anchor(ANCHOR_THROW_EXCEPTION_UNCHECKED);
        self.emit_ins(X86Instruction::store(OperandSize::S64, R11, R10, X86IndirectAccess::Offset(std::mem::size_of::<u64>() as i32))); // result.pc = self.pc;
        self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x81, 0, R10, ebpf::ELF_INSN_DUMP_OFFSET as i64, Some(X86IndirectAccess::Offset(std::mem::size_of::<u64>() as i32)))); // result.pc += ebpf::ELF_INSN_DUMP_OFFSET;
        self.emit_ins(X86Instruction::jump_immediate(self.relative_to_anchor(ANCHOR_EPILOGUE, 5)));

        // Quit gracefully
        self.set_anchor(ANCHOR_EXIT);
        self.emit_validate_instruction_count(false, None);
        self.emit_ins(X86Instruction::lea(OperandSize::S64, RBP, R10, Some(X86IndirectAccess::Offset(self.slot_on_environment_stack(RuntimeEnvironmentSlot::ProgramResult)))));
        self.emit_ins(X86Instruction::store(OperandSize::S64, REGISTER_MAP[0], R10, X86IndirectAccess::Offset(8))); // result.return_value = R0;
        self.emit_ins(X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[0], 0));
        self.emit_ins(X86Instruction::jump_immediate(self.relative_to_anchor(ANCHOR_EPILOGUE, 5)));

        // Handler for exceptions which report their pc
        self.set_anchor(ANCHOR_THROW_EXCEPTION);
        // Validate that we did not reach the instruction meter limit before the exception occured
        self.emit_validate_instruction_count(false, None);
        self.emit_ins(X86Instruction::jump_immediate(self.relative_to_anchor(ANCHOR_THROW_EXCEPTION_UNCHECKED, 5)));

        // Handler for EbpfError::AccessViolation
        self.set_anchor(ANCHOR_ACCESS_VIOLATION);
        self.emit_ins(X86Instruction::load(OperandSize::S64, RBP, R10, X86IndirectAccess::Offset(self.slot_on_environment_stack(RuntimeEnvironmentSlot::ProgramResult) + std::mem::size_of::<u64>() as i32))); // err = *env.result.err;
        self.emit_ins(X86Instruction::jump_immediate(self.relative_to_anchor(ANCHOR_THROW_EXCEPTION, 5)));

        // Handler for EbpfError::CallDepthExceeded
        self.set_anchor(ANCHOR_CALL_DEPTH_EXCEEDED);
        self.emit_set_exception_kind(EbpfError::CallDepthExceeded(0, 0));
        self.emit_ins(X86Instruction::store_immediate(OperandSize::S64, R10, X86IndirectAccess::Offset((std::mem::size_of::<u64>() * 2) as i32), self.config.max_call_depth as i64)); // depth = jit.config.max_call_depth;
        self.emit_ins(X86Instruction::jump_immediate(self.relative_to_anchor(ANCHOR_THROW_EXCEPTION, 5)));

        // Handler for EbpfError::CallOutsideTextSegment
        self.set_anchor(ANCHOR_CALL_OUTSIDE_TEXT_SEGMENT);
        self.emit_set_exception_kind(EbpfError::CallOutsideTextSegment(0, 0));
        self.emit_ins(X86Instruction::store(OperandSize::S64, REGISTER_MAP[0], R10, X86IndirectAccess::Offset((std::mem::size_of::<u64>() * 2) as i32))); // target_address = RAX;
        self.emit_ins(X86Instruction::jump_immediate(self.relative_to_anchor(ANCHOR_THROW_EXCEPTION, 5)));

        // Handler for EbpfError::DivideByZero
        self.set_anchor(ANCHOR_DIV_BY_ZERO);
        self.emit_set_exception_kind(EbpfError::DivideByZero(0));
        self.emit_ins(X86Instruction::jump_immediate(self.relative_to_anchor(ANCHOR_THROW_EXCEPTION, 5)));

        // Handler for EbpfError::DivideOverflow
        self.set_anchor(ANCHOR_DIV_OVERFLOW);
        self.emit_set_exception_kind(EbpfError::DivideOverflow(0));
        self.emit_ins(X86Instruction::jump_immediate(self.relative_to_anchor(ANCHOR_THROW_EXCEPTION, 5)));

        // Handler for EbpfError::UnsupportedInstruction
        self.set_anchor(ANCHOR_CALL_UNSUPPORTED_INSTRUCTION);
        if self.config.enable_instruction_tracing {
            self.emit_ins(X86Instruction::call_immediate(self.relative_to_anchor(ANCHOR_TRACE, 5)));
        }
        self.emit_set_exception_kind(EbpfError::UnsupportedInstruction(0));
        self.emit_ins(X86Instruction::jump_immediate(self.relative_to_anchor(ANCHOR_THROW_EXCEPTION, 5)));

        // Routine for external functions
        self.set_anchor(ANCHOR_EXTERNAL_FUNCTION_CALL);
        self.emit_ins(X86Instruction::push_immediate(OperandSize::S64, -1)); // Used as PC value in error case, acts as stack padding otherwise
        if self.config.enable_instruction_meter {
            // RDI = *PreviousInstructionMeter - RDI;
            self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x2B, ARGUMENT_REGISTERS[0], RBP, 0, Some(X86IndirectAccess::Offset(self.slot_on_environment_stack(RuntimeEnvironmentSlot::PreviousInstructionMeter))))); // RDI -= *PreviousInstructionMeter;
            self.emit_ins(X86Instruction::alu(OperandSize::S64, 0xf7, 3, ARGUMENT_REGISTERS[0], 0, None)); // RDI = -RDI;
            self.emit_rust_call(Value::Constant64(C::consume as *const u8 as i64, false), &[
                Argument { index: 1, value: Value::Register(ARGUMENT_REGISTERS[0]) },
                Argument { index: 0, value: Value::RegisterIndirect(RBP, self.slot_on_environment_stack(RuntimeEnvironmentSlot::ContextObjectPointer), false) },
            ], None);
        }
        self.emit_rust_call(Value::Register(R11), &[
            Argument { index: 7, value: Value::RegisterPlusConstant32(RBP, self.slot_on_environment_stack(RuntimeEnvironmentSlot::ProgramResult), false) },
            Argument { index: 6, value: Value::RegisterPlusConstant32(RBP, self.slot_on_environment_stack(RuntimeEnvironmentSlot::MemoryMapping), false) },
            Argument { index: 5, value: Value::Register(ARGUMENT_REGISTERS[5]) },
            Argument { index: 4, value: Value::Register(ARGUMENT_REGISTERS[4]) },
            Argument { index: 3, value: Value::Register(ARGUMENT_REGISTERS[3]) },
            Argument { index: 2, value: Value::Register(ARGUMENT_REGISTERS[2]) },
            Argument { index: 1, value: Value::Register(ARGUMENT_REGISTERS[1]) },
            Argument { index: 0, value: Value::RegisterIndirect(RBP, self.slot_on_environment_stack(RuntimeEnvironmentSlot::ContextObjectPointer), false) },
        ], None);
        if self.config.enable_instruction_meter {
            self.emit_rust_call(Value::Constant64(C::get_remaining as *const u8 as i64, false), &[
                Argument { index: 0, value: Value::RegisterIndirect(RBP, self.slot_on_environment_stack(RuntimeEnvironmentSlot::ContextObjectPointer), false) },
            ], Some(ARGUMENT_REGISTERS[0]));
            self.emit_ins(X86Instruction::store(OperandSize::S64, ARGUMENT_REGISTERS[0], RBP, X86IndirectAccess::Offset(self.slot_on_environment_stack(RuntimeEnvironmentSlot::PreviousInstructionMeter)))); // *PreviousInstructionMeter = RDI;
        }

        // Test if result indicates that an error occured
        self.emit_result_is_err(R11);
        self.emit_ins(X86Instruction::pop(R11));
        self.emit_ins(X86Instruction::conditional_jump_immediate(0x85, self.relative_to_anchor(ANCHOR_EPILOGUE, 6)));
        // Store Ok value in result register
        self.emit_ins(X86Instruction::lea(OperandSize::S64, RBP, R11, Some(X86IndirectAccess::Offset(self.slot_on_environment_stack(RuntimeEnvironmentSlot::ProgramResult)))));
        self.emit_ins(X86Instruction::load(OperandSize::S64, R11, REGISTER_MAP[0], X86IndirectAccess::Offset(8)));
        self.emit_ins(X86Instruction::return_near());

        // Routine for prologue of emit_internal_call()
        self.set_anchor(ANCHOR_ANCHOR_INTERNAL_FUNCTION_CALL_PROLOGUE);
        self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x81, 5, RSP, 8 * (SCRATCH_REGS + 1) as i64, None)); // alloca
        self.emit_ins(X86Instruction::store(OperandSize::S64, R11, RSP, X86IndirectAccess::OffsetIndexShift(0, RSP, 0))); // Save original R11
        self.emit_ins(X86Instruction::load(OperandSize::S64, RSP, R11, X86IndirectAccess::OffsetIndexShift(8 * (SCRATCH_REGS + 1) as i32, RSP, 0))); // Load return address
        for (i, reg) in REGISTER_MAP.iter().skip(FIRST_SCRATCH_REG).take(SCRATCH_REGS).enumerate() {
            self.emit_ins(X86Instruction::store(OperandSize::S64, *reg, RSP, X86IndirectAccess::OffsetIndexShift(8 * (SCRATCH_REGS - i + 1) as i32, RSP, 0))); // Push SCRATCH_REG
        }
        // Push the caller's frame pointer. The code to restore it is emitted at the end of emit_internal_call().
        self.emit_ins(X86Instruction::store(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], RSP, X86IndirectAccess::OffsetIndexShift(8, RSP, 0)));
        self.emit_ins(X86Instruction::xchg(OperandSize::S64, R11, RSP, Some(X86IndirectAccess::OffsetIndexShift(0, RSP, 0)))); // Push return address and restore original R11

        // Increase CallDepth
        let call_depth_access = X86IndirectAccess::Offset(self.slot_on_environment_stack(RuntimeEnvironmentSlot::CallDepth));
        self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x81, 0, RBP, 1, Some(call_depth_access)));
        self.emit_ins(X86Instruction::load(OperandSize::S64, RBP, REGISTER_MAP[FRAME_PTR_REG], call_depth_access));
        // If CallDepth == self.config.max_call_depth, stop and return CallDepthExceeded
        self.emit_ins(X86Instruction::cmp_immediate(OperandSize::S32, REGISTER_MAP[FRAME_PTR_REG], self.config.max_call_depth as i64, None));
        self.emit_ins(X86Instruction::conditional_jump_immediate(0x83, self.relative_to_anchor(ANCHOR_CALL_DEPTH_EXCEEDED, 6)));

        // Setup the frame pointer for the new frame. What we do depends on whether we're using dynamic or fixed frames.
        let stack_pointer_access = X86IndirectAccess::Offset(self.slot_on_environment_stack(RuntimeEnvironmentSlot::StackPointer));
        if !self.executable.get_sbpf_version().dynamic_stack_frames() {
            // With fixed frames we start the new frame at the next fixed offset
            let stack_frame_size = self.config.stack_frame_size as i64 * if self.config.enable_stack_frame_gaps { 2 } else { 1 };
            self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x81, 0, RBP, stack_frame_size, Some(stack_pointer_access))); // env.stack_pointer += stack_frame_size;
        }
        self.emit_ins(X86Instruction::load(OperandSize::S64, RBP, REGISTER_MAP[FRAME_PTR_REG], stack_pointer_access)); // reg[ebpf::FRAME_PTR_REG] = env.stack_pointer;
        self.emit_ins(X86Instruction::return_near());

        // Routine for emit_internal_call(Value::Register())
        self.set_anchor(ANCHOR_ANCHOR_INTERNAL_FUNCTION_CALL_REG);
        // Force alignment of RAX
        self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x81, 4, REGISTER_MAP[0], !(INSN_SIZE as i64 - 1), None)); // RAX &= !(INSN_SIZE - 1);
        // Upper bound check
        // if(RAX >= self.program_vm_addr + number_of_instructions * INSN_SIZE) throw CALL_OUTSIDE_TEXT_SEGMENT;
        let number_of_instructions = self.result.pc_section.len();
        self.emit_ins(X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], self.program_vm_addr as i64 + (number_of_instructions * INSN_SIZE) as i64));
        self.emit_ins(X86Instruction::cmp(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], REGISTER_MAP[0], None));
        self.emit_ins(X86Instruction::conditional_jump_immediate(0x83, self.relative_to_anchor(ANCHOR_CALL_OUTSIDE_TEXT_SEGMENT, 6)));
        // Lower bound check
        // if(RAX < self.program_vm_addr) throw CALL_OUTSIDE_TEXT_SEGMENT;
        self.emit_ins(X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], self.program_vm_addr as i64));
        self.emit_ins(X86Instruction::cmp(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], REGISTER_MAP[0], None));
        self.emit_ins(X86Instruction::conditional_jump_immediate(0x82, self.relative_to_anchor(ANCHOR_CALL_OUTSIDE_TEXT_SEGMENT, 6)));
        // Calculate offset relative to instruction_addresses
        self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x29, REGISTER_MAP[FRAME_PTR_REG], REGISTER_MAP[0], 0, None)); // RAX -= self.program_vm_addr;
        // Calculate the target_pc (dst / INSN_SIZE) to update the instruction_meter
        // and as target pc for potential ANCHOR_CALL_UNSUPPORTED_INSTRUCTION
        let shift_amount = INSN_SIZE.trailing_zeros();
        debug_assert_eq!(INSN_SIZE, 1 << shift_amount);
        self.emit_ins(X86Instruction::mov(OperandSize::S64, REGISTER_MAP[0], R11));
        self.emit_ins(X86Instruction::alu(OperandSize::S64, 0xc1, 5, R11, shift_amount as i64, None));
        // Load host target_address from self.result.pc_section
        debug_assert_eq!(INSN_SIZE, 8); // Because the instruction size is also the slot size we do not need to shift the offset
        self.emit_ins(X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], self.result.pc_section.as_ptr() as i64));
        self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x01, REGISTER_MAP[FRAME_PTR_REG], REGISTER_MAP[0], 0, None)); // RAX += self.result.pc_section;
        self.emit_ins(X86Instruction::load(OperandSize::S64, REGISTER_MAP[0], REGISTER_MAP[0], X86IndirectAccess::Offset(0))); // RAX = self.result.pc_section[RAX / 8];
        // Load the frame pointer again since we've clobbered REGISTER_MAP[FRAME_PTR_REG]
        self.emit_ins(X86Instruction::load(OperandSize::S64, RBP, REGISTER_MAP[FRAME_PTR_REG], X86IndirectAccess::Offset(self.slot_on_environment_stack(RuntimeEnvironmentSlot::StackPointer))));
        self.emit_ins(X86Instruction::return_near());

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
            self.set_anchor(ANCHOR_TRANSLATE_MEMORY_ADDRESS + target_offset);
            // call MemoryMapping::(load|store) storing the result in RuntimeEnvironmentSlot::ProgramResult
            if *access_type == AccessType::Load {
                let load = match len {
                    1 => MemoryMapping::load::<u8> as *const u8 as i64,
                    2 => MemoryMapping::load::<u16> as *const u8 as i64,
                    4 => MemoryMapping::load::<u32> as *const u8 as i64,
                    8 => MemoryMapping::load::<u64> as *const u8 as i64,
                    _ => unreachable!()
                };
                self.emit_rust_call(Value::Constant64(load, false), &[
                    Argument { index: 2, value: Value::Register(R11) }, // Specify first as the src register could be overwritten by other arguments
                    Argument { index: 3, value: Value::Constant64(0, false) }, // self.pc is set later
                    Argument { index: 1, value: Value::RegisterPlusConstant32(RBP, self.slot_on_environment_stack(RuntimeEnvironmentSlot::MemoryMapping), false) },
                    Argument { index: 0, value: Value::RegisterPlusConstant32(RBP, self.slot_on_environment_stack(RuntimeEnvironmentSlot::ProgramResult), false) },
                ], None);
            } else {
                let store = match len {
                    1 => MemoryMapping::store::<u8> as *const u8 as i64,
                    2 => MemoryMapping::store::<u16> as *const u8 as i64,
                    4 => MemoryMapping::store::<u32> as *const u8 as i64,
                    8 => MemoryMapping::store::<u64> as *const u8 as i64,
                    _ => unreachable!()
                };
                self.emit_rust_call(Value::Constant64(store, false), &[
                    Argument { index: 3, value: Value::Register(R11) }, // Specify first as the src register could be overwritten by other arguments
                    Argument { index: 2, value: Value::Register(R10) },
                    Argument { index: 4, value: Value::Constant64(0, false) }, // self.pc is set later
                    Argument { index: 1, value: Value::RegisterPlusConstant32(RBP, self.slot_on_environment_stack(RuntimeEnvironmentSlot::MemoryMapping), false) },
                    Argument { index: 0, value: Value::RegisterPlusConstant32(RBP, self.slot_on_environment_stack(RuntimeEnvironmentSlot::ProgramResult), false) },
                ], None);
            }

            // Throw error if the result indicates one
            self.emit_result_is_err(R11);
            self.emit_ins(X86Instruction::pop(R11)); // R11 = self.pc
            self.emit_ins(X86Instruction::xchg(OperandSize::S64, R11, RSP, Some(X86IndirectAccess::OffsetIndexShift(0, RSP, 0)))); // Swap return address and self.pc
            self.emit_ins(X86Instruction::lea(OperandSize::S64, RBP, R10, Some(X86IndirectAccess::Offset(self.slot_on_environment_stack(RuntimeEnvironmentSlot::ProgramResult)))));
            self.emit_ins(X86Instruction::conditional_jump_immediate(0x85, self.relative_to_anchor(ANCHOR_ACCESS_VIOLATION, 6)));

            // unwrap() the result into R11
            self.emit_ins(X86Instruction::load(OperandSize::S64, R10, R11, X86IndirectAccess::Offset(8)));

            self.emit_ins(X86Instruction::return_near());
        }
    }

    fn set_anchor(&mut self, anchor: usize) {
        self.anchors[anchor] = unsafe { self.result.text_section.as_ptr().add(self.offset_in_text_section) };
    }

    // instruction_length = 5 (Unconditional jump / call)
    // instruction_length = 6 (Conditional jump)
    #[inline]
    fn relative_to_anchor(&self, anchor: usize, instruction_length: usize) -> i32 {
        let instruction_end = unsafe { self.result.text_section.as_ptr().add(self.offset_in_text_section).add(instruction_length) };
        let destination = self.anchors[anchor];
        debug_assert!(!destination.is_null());
        (unsafe { destination.offset_from(instruction_end) } as i32) // Relative jump
    }

    #[inline]
    fn relative_to_target_pc(&mut self, target_pc: usize, instruction_length: usize) -> i32 {
        let instruction_end = unsafe { self.result.text_section.as_ptr().add(self.offset_in_text_section).add(instruction_length) };
        let destination = if self.result.pc_section[target_pc] != 0 {
            // Backward jump
            self.result.pc_section[target_pc] as *const u8
        } else {
            // Forward jump, needs relocation
            self.text_section_jumps.push(Jump { location: unsafe { instruction_end.sub(4) }, target_pc });
            return 0;
        };
        debug_assert!(!destination.is_null());
        (unsafe { destination.offset_from(instruction_end) } as i32) // Relative jump
    }

    fn resolve_jumps(&mut self) {
        // Relocate forward jumps
        for jump in &self.text_section_jumps {
            let destination = self.result.pc_section[jump.target_pc] as *const u8;
            let offset_value = 
                unsafe { destination.offset_from(jump.location) } as i32 // Relative jump
                - mem::size_of::<i32>() as i32; // Jump from end of instruction
            unsafe { ptr::write_unaligned(jump.location as *mut i32, offset_value); }
        }
        // There is no `VerifierError::JumpToMiddleOfLDDW` for `call imm` so patch it here
        let call_unsupported_instruction = self.anchors[ANCHOR_CALL_UNSUPPORTED_INSTRUCTION] as usize;
        if self.executable.get_sbpf_version().static_syscalls() {
            let mut prev_pc = 0;
            for current_pc in self.executable.get_function_registry().keys() {
                if current_pc as usize >= self.result.pc_section.len() {
                    break;
                }
                for pc in prev_pc..current_pc as usize {
                    self.result.pc_section[pc] = call_unsupported_instruction;
                }
                prev_pc = current_pc as usize + 1;
            }
            for pc in prev_pc..self.result.pc_section.len() {
                self.result.pc_section[pc] = call_unsupported_instruction;
            }
        }
    }
}

#[cfg(all(test, target_arch = "x86_64", not(target_os = "windows")))]
mod tests {
    use super::*;
    use crate::{
        elf::{FunctionRegistry, SBPFVersion},
        syscalls,
        verifier::TautologyVerifier,
        vm::{BuiltinFunction, BuiltinProgram, TestContextObject},
    };
    use byteorder::{ByteOrder, LittleEndian};
    use std::sync::Arc;

    #[test]
    fn test_runtime_environment_slots() {
        let executable = create_mockup_executable(&[]);
        let mut context_object = TestContextObject::new(0);
        let env = EbpfVm::new(
            executable.get_config(),
            executable.get_sbpf_version(),
            &mut context_object,
            MemoryMapping::new_identity(),
            0,
        );

        macro_rules! check_slot {
            ($env:expr, $entry:ident, $slot:ident) => {
                assert_eq!(
                    unsafe {
                        (&$env.$entry as *const _ as *const u64)
                            .offset_from(&$env as *const _ as *const u64) as usize
                    },
                    RuntimeEnvironmentSlot::$slot as usize,
                );
            };
        }

        check_slot!(env, host_stack_pointer, HostStackPointer);
        check_slot!(env, call_depth, CallDepth);
        check_slot!(env, stack_pointer, StackPointer);
        check_slot!(env, context_object_pointer, ContextObjectPointer);
        check_slot!(env, previous_instruction_meter, PreviousInstructionMeter);
        check_slot!(env, stopwatch_numerator, StopwatchNumerator);
        check_slot!(env, stopwatch_denominator, StopwatchDenominator);
        check_slot!(env, program_result, ProgramResult);
        check_slot!(env, memory_mapping, MemoryMapping);
    }

    fn create_mockup_executable(
        program: &[u8],
    ) -> Executable<TautologyVerifier, TestContextObject> {
        let mut function_registry =
            FunctionRegistry::<BuiltinFunction<TestContextObject>>::default();
        function_registry
            .register_function_hashed(*b"gather_bytes", syscalls::bpf_gather_bytes)
            .unwrap();
        let loader = BuiltinProgram::new_loader(
            Config {
                noop_instruction_rate: 0,
                ..Config::default()
            },
            function_registry,
        );
        let mut function_registry = FunctionRegistry::default();
        function_registry
            .register_function(8, *b"function_foo", 8)
            .unwrap();
        Executable::<TautologyVerifier, TestContextObject>::from_text_bytes(
            program,
            Arc::new(loader),
            SBPFVersion::V2,
            function_registry,
        )
        .unwrap()
    }

    #[test]
    fn test_code_length_estimate() {
        const INSTRUCTION_COUNT: usize = 256;
        let mut prog = [0; ebpf::INSN_SIZE * INSTRUCTION_COUNT];

        let empty_program_machine_code_length = {
            prog[0] = ebpf::EXIT;
            let mut executable = create_mockup_executable(&prog[0..ebpf::INSN_SIZE]);
            Executable::<TautologyVerifier, TestContextObject>::jit_compile(&mut executable)
                .unwrap();
            executable
                .get_compiled_program()
                .unwrap()
                .machine_code_length()
        };
        assert!(empty_program_machine_code_length <= MAX_EMPTY_PROGRAM_MACHINE_CODE_LENGTH);

        for mut opcode in 0x00..=0xFF {
            let immediate = match opcode {
                0x85 | 0x8D => 8,
                0x86 => {
                    // Put external function calls on a separate loop iteration
                    opcode = 0x85;
                    0x91020CDD
                }
                0xD4 | 0xDC => 16,
                _ => 0xFFFFFFFF,
            };
            for pc in 0..INSTRUCTION_COUNT {
                prog[pc * ebpf::INSN_SIZE] = opcode;
                prog[pc * ebpf::INSN_SIZE + 1] = 0x88;
                prog[pc * ebpf::INSN_SIZE + 2] = 0xFF;
                prog[pc * ebpf::INSN_SIZE + 3] = 0xFF;
                LittleEndian::write_u32(&mut prog[pc * ebpf::INSN_SIZE + 4..], immediate);
            }
            let mut executable = create_mockup_executable(&prog);
            let result =
                Executable::<TautologyVerifier, TestContextObject>::jit_compile(&mut executable);
            if result.is_err() {
                assert!(matches!(
                    result.unwrap_err(),
                    EbpfError::UnsupportedInstruction(_)
                ));
                continue;
            }
            let machine_code_length = executable
                .get_compiled_program()
                .unwrap()
                .machine_code_length()
                - empty_program_machine_code_length;
            let instruction_count = if opcode == 0x18 {
                // LDDW takes two slots
                INSTRUCTION_COUNT / 2
            } else {
                INSTRUCTION_COUNT
            };
            let machine_code_length_per_instruction =
                (machine_code_length as f64 / instruction_count as f64 + 0.5) as usize;
            assert!(machine_code_length_per_instruction <= MAX_MACHINE_CODE_LENGTH_PER_INSTRUCTION);
            /*println!("opcode={:02X} machine_code_length_per_instruction={}", opcode, machine_code_length_per_instruction);
            let analysis = crate::static_analysis::Analysis::from_executable(&executable).unwrap();
            {
                let stdout = std::io::stdout();
                analysis.disassemble(&mut stdout.lock()).unwrap();
            }*/
        }
    }
}
