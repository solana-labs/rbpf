#![allow(clippy::integer_arithmetic)]
// Derived from uBPF <https://github.com/iovisor/ubpf>
// Copyright 2015 Big Switch Networks, Inc
//      (uBPF: JIT algorithm, originally in C)
// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//      (Translation to Rust, MetaBuff addition)
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![allow(clippy::deprecated_cfg_attr)]
#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unreachable_code)]

extern crate libc;

use std::{
    collections::HashMap,
    fmt::{Debug, Error as FormatterError, Formatter},
    mem,
    ops::{Index, IndexMut},
    pin::Pin, ptr,
};
use rand::{rngs::SmallRng, Rng, SeedableRng};

use crate::{
    elf::Executable,
    vm::{Config, ProgramResult, InstructionMeter, Tracer, SYSCALL_CONTEXT_OBJECTS_OFFSET},
    ebpf::{self, INSN_SIZE, FIRST_SCRATCH_REG, SCRATCH_REGS, FRAME_PTR_REG, MM_STACK_START, STACK_PTR_REG},
    error::{UserDefinedError, EbpfError},
    memory_region::{AccessType, MemoryMapping, MemoryRegion},
    user_error::UserError,
    x86::*,
};

const MAX_EMPTY_PROGRAM_MACHINE_CODE_LENGTH: usize = 4096;
const MAX_MACHINE_CODE_LENGTH_PER_INSTRUCTION: usize = 110;

/// Argument for executing a eBPF JIT-compiled program
pub struct JitProgramArgument<'a> {
    /// The MemoryMapping to be used to run the compiled code
    pub memory_mapping: MemoryMapping<'a>,
    /// Pointers to the context objects of syscalls
    pub syscall_context_objects: [*const u8; 0],
}

struct JitProgramSections {
    page_size: usize,
    pc_section: &'static mut [u64],
    text_section: &'static mut [u8],
}

#[cfg(not(target_os = "windows"))]
macro_rules! libc_error_guard {
    (succeeded?, mmap, $addr:expr, $($arg:expr),*) => {{
        *$addr = libc::mmap(*$addr, $($arg),*);
        *$addr != libc::MAP_FAILED
    }};
    (succeeded?, $function:ident, $($arg:expr),*) => {
        libc::$function($($arg),*) == 0
    };
    ($function:ident, $($arg:expr),*) => {{
        const RETRY_COUNT: usize = 3;
        for i in 0..RETRY_COUNT {
            if libc_error_guard!(succeeded?, $function, $($arg),*) {
                break;
            } else if i + 1 == RETRY_COUNT {
                let args = vec![$(format!("{:?}", $arg)),*];
                #[cfg(any(target_os = "freebsd", target_os = "ios", target_os = "macos"))]
                let errno = *libc::__error();
                #[cfg(target_os = "linux")]
                let errno = *libc::__errno_location();
                return Err(EbpfError::LibcInvocationFailed(stringify!($function), args, errno));
            }
        }
    }};
}

fn round_to_page_size(value: usize, page_size: usize) -> usize {
    (value + page_size - 1) / page_size * page_size
}

#[allow(unused_variables)]
impl JitProgramSections {
    fn new<E: UserDefinedError>(pc: usize, code_size: usize) -> Result<Self, EbpfError<E>> {
        #[cfg(target_os = "windows")]
        {
            Ok(Self {
                page_size: 0,
                pc_section: &mut [],
                text_section: &mut [],
            })
        }
        #[cfg(not(target_os = "windows"))]
        unsafe {
            let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
            let pc_loc_table_size = round_to_page_size(pc * 8, page_size);
            let over_allocated_code_size = round_to_page_size(code_size, page_size);
            let mut raw: *mut libc::c_void = std::ptr::null_mut();
            libc_error_guard!(mmap, &mut raw, pc_loc_table_size + over_allocated_code_size, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_ANONYMOUS | libc::MAP_PRIVATE, 0, 0);
            Ok(Self {
                page_size,
                pc_section: std::slice::from_raw_parts_mut(raw as *mut u64, pc),
                text_section: std::slice::from_raw_parts_mut(raw.add(pc_loc_table_size) as *mut u8, over_allocated_code_size),
            })
        }
    }

    fn seal<E: UserDefinedError>(&mut self, text_section_usage: usize) -> Result<(), EbpfError<E>> {
        if self.page_size > 0 {
            let raw = self.pc_section.as_ptr() as *mut u8;
            let pc_loc_table_size = round_to_page_size(self.pc_section.len() * 8, self.page_size);
            let over_allocated_code_size = round_to_page_size(self.text_section.len(), self.page_size);
            let code_size = round_to_page_size(text_section_usage, self.page_size);
            #[cfg(not(target_os = "windows"))]
            unsafe {
                if over_allocated_code_size > code_size {
                    libc_error_guard!(munmap, raw.add(pc_loc_table_size).add(code_size) as *mut _, over_allocated_code_size - code_size);
                }
                std::ptr::write_bytes(raw.add(pc_loc_table_size).add(text_section_usage), 0xcc, code_size - text_section_usage); // Fill with debugger traps
                self.text_section = std::slice::from_raw_parts_mut(raw.add(pc_loc_table_size), text_section_usage);
                libc_error_guard!(mprotect, self.pc_section.as_mut_ptr() as *mut _, pc_loc_table_size, libc::PROT_READ);
                libc_error_guard!(mprotect, self.text_section.as_mut_ptr() as *mut _, code_size, libc::PROT_EXEC | libc::PROT_READ);
            }
        }
        Ok(())
    }

    pub fn mem_size(&self) -> usize {
        let pc_loc_table_size = round_to_page_size(self.pc_section.len() * 8, self.page_size);
        let code_size = round_to_page_size(self.text_section.len(), self.page_size);
        pc_loc_table_size + code_size
    }
}

impl Drop for JitProgramSections {
    fn drop(&mut self) {
        let pc_loc_table_size = round_to_page_size(self.pc_section.len() * 8, self.page_size);
        let code_size = round_to_page_size(self.text_section.len(), self.page_size);
        if pc_loc_table_size + code_size > 0 {
            #[cfg(not(target_os = "windows"))]
            unsafe {
                libc::munmap(self.pc_section.as_ptr() as *mut _, pc_loc_table_size + code_size);
            }
        }
    }
}

/// eBPF JIT-compiled program
pub struct JitProgram<E: UserDefinedError, I: InstructionMeter> {
    /// Holds and manages the protected memory
    sections: JitProgramSections,
    /// Call this with JitProgramArgument to execute the compiled code
    pub main: unsafe fn(&ProgramResult<E>, u64, &JitProgramArgument, &mut I) -> i64,
}

impl<E: UserDefinedError, I: InstructionMeter> Debug for JitProgram<E, I> {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.write_fmt(format_args!("JitProgram {:?}", &self.main as *const _))
    }
}

impl<E: UserDefinedError, I: InstructionMeter> PartialEq for JitProgram<E, I> {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self.main as *const u8, other.main as *const u8)
    }
}

impl<E: UserDefinedError, I: InstructionMeter> JitProgram<E, I> {
    pub fn new(executable: &Pin<Box<Executable<E, I>>>) -> Result<Self, EbpfError<E>> {
        let program = executable.get_text_bytes().1;
        let mut jit = JitCompiler::new::<E>(program, executable.get_config())?;
        jit.compile::<E, I>(executable)?;
        let main = unsafe { mem::transmute(jit.result.text_section.as_ptr()) };
        Ok(Self {
            sections: jit.result,
            main,
        })
    }

    pub fn mem_size(&self) -> usize {
        mem::size_of::<Self>() +
        self.sections.mem_size()
    }

    pub fn machine_code_length(&self) -> usize {
        self.sections.text_section.len()
    }
}

// Special values for target_pc in struct Jump
const TARGET_PC_LOCAL_ANCHOR: usize = std::usize::MAX - 100;
const TARGET_PC_DIV_OVERFLOW: usize = std::usize::MAX - 33;
const TARGET_PC_TRACE: usize = std::usize::MAX - 32;
const TARGET_PC_SYSCALL: usize = std::usize::MAX - 31;
const TARGET_PC_BPF_CALL_PROLOGUE: usize = std::usize::MAX - 30;
const TARGET_PC_BPF_CALL_REG: usize = std::usize::MAX - 29;
const TARGET_PC_TRANSLATE_PC: usize = std::usize::MAX - 28;
const TARGET_PC_TRANSLATE_PC_LOOP: usize = std::usize::MAX - 27;
const TARGET_PC_TRANSLATE_MEMORY_ADDRESS: usize = std::usize::MAX - 26;
const TARGET_PC_MEMORY_ACCESS_VIOLATION: usize = std::usize::MAX - 18;
const TARGET_PC_CALL_EXCEEDED_MAX_INSTRUCTIONS: usize = std::usize::MAX - 10;
const TARGET_PC_CALL_DEPTH_EXCEEDED: usize = std::usize::MAX - 9;
const TARGET_PC_CALL_OUTSIDE_TEXT_SEGMENT: usize = std::usize::MAX - 8;
const TARGET_PC_CALLX_UNSUPPORTED_INSTRUCTION: usize = std::usize::MAX - 7;
const TARGET_PC_CALL_UNSUPPORTED_INSTRUCTION: usize = std::usize::MAX - 6;
const TARGET_PC_DIV_BY_ZERO: usize = std::usize::MAX - 5;
const TARGET_PC_EXCEPTION_AT: usize = std::usize::MAX - 4;
const TARGET_PC_RUST_EXCEPTION: usize = std::usize::MAX - 3;
const TARGET_PC_EXIT: usize = std::usize::MAX - 2;
const TARGET_PC_EPILOGUE: usize = std::usize::MAX - 1;

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
// CALLEE_SAVED_REGISTERS[0]  RBP  Constant pointer to inital RSP - 8

#[inline]
pub fn emit<T, E: UserDefinedError>(jit: &mut JitCompiler, data: T) -> Result<(), EbpfError<E>> {
    let size = mem::size_of::<T>() as usize;
    if jit.offset_in_text_section + size > jit.result.text_section.len() {
        return Err(EbpfError::ExhausedTextSegment(jit.pc));
    }
    unsafe {
        #[allow(clippy::cast_ptr_alignment)]
        let ptr = jit.result.text_section.as_ptr().add(jit.offset_in_text_section) as *mut T;
        *ptr = data as T;
    }
    jit.offset_in_text_section += size;
    Ok(())
}

pub fn emit_variable_length<E: UserDefinedError>(jit: &mut JitCompiler, size: OperandSize, data: u64) -> Result<(), EbpfError<E>> {
    match size {
        OperandSize::S0 => Ok(()),
        OperandSize::S8 => emit::<u8, E>(jit, data as u8),
        OperandSize::S16 => emit::<u16, E>(jit, data as u16),
        OperandSize::S32 => emit::<u32, E>(jit, data as u32),
        OperandSize::S64 => emit::<u64, E>(jit, data),
    }
}

#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub enum OperandSize {
    S0  = 0,
    S8  = 8,
    S16 = 16,
    S32 = 32,
    S64 = 64,
}

#[inline]
fn emit_sanitized_load_immediate<E: UserDefinedError>(jit: &mut JitCompiler, size: OperandSize, destination: u8, value: i64) -> Result<(), EbpfError<E>> {
    match size {
        OperandSize::S32 => {
            let key: i32 = jit.diversification_rng.gen();
            X86Instruction::load_immediate(size, destination, (value as i32).wrapping_sub(key) as i64).emit(jit)?;
            emit_alu(jit, size, 0x81, 0, destination, key as i64, None)
        },
        OperandSize::S64 if destination == R11 => {
            let key: i64 = jit.diversification_rng.gen();
            let lower_key = key as i32 as i64;
            let upper_key = (key >> 32) as i32 as i64;
            X86Instruction::load_immediate(size, destination, value.wrapping_sub(lower_key).rotate_right(32).wrapping_sub(upper_key)).emit(jit)?;
            emit_alu(jit, size, 0x81, 0, destination, upper_key, None)?; // wrapping_add(upper_key)
            emit_alu(jit, size, 0xc1, 1, destination, 32, None)?; // rotate_right(32)
            emit_alu(jit, size, 0x81, 0, destination, lower_key, None) // wrapping_add(lower_key)
        },
        OperandSize::S64 if value >= std::i32::MIN as i64 && value <= std::i32::MAX as i64 => {
            let key = jit.diversification_rng.gen::<i32>() as i64;
            X86Instruction::load_immediate(size, destination, value.wrapping_sub(key)).emit(jit)?;
            emit_alu(jit, size, 0x81, 0, destination, key, None)
        },
        OperandSize::S64 => {
            let key: i64 = jit.diversification_rng.gen();
            X86Instruction::load_immediate(size, destination, value.wrapping_sub(key)).emit(jit)?;
            X86Instruction::load_immediate(size, R11, key).emit(jit)?;
            emit_alu(jit, size, 0x01, R11, destination, 0, None)
        },
        _ => {
            #[cfg(debug_assertions)]
            unreachable!();
            Ok(())
        }
    }
}

#[inline]
fn emit_alu<E: UserDefinedError>(jit: &mut JitCompiler, size: OperandSize, opcode: u8, source: u8, destination: u8, immediate: i64, indirect: Option<X86IndirectAccess>) -> Result<(), EbpfError<E>> {
    X86Instruction {
        size,
        opcode,
        first_operand: source,
        second_operand: destination,
        immediate_size: match opcode {
            0xc1 => OperandSize::S8,
            0x81 => OperandSize::S32,
            0xf7 if source == 0 => OperandSize::S32,
            _ => OperandSize::S0,
        },
        immediate,
        indirect,
        ..X86Instruction::default()
    }.emit(jit)
}

#[inline]
fn should_sanitize_constant(jit: &JitCompiler, value: i64) -> bool {
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
fn emit_sanitized_alu<E: UserDefinedError>(jit: &mut JitCompiler, size: OperandSize, opcode: u8, opcode_extension: u8, destination: u8, immediate: i64) -> Result<(), EbpfError<E>> {
    if should_sanitize_constant(jit, immediate) {
        emit_sanitized_load_immediate(jit, size, R11, immediate)?;
        emit_alu(jit, size, opcode, R11, destination, immediate, None)
    } else {
        emit_alu(jit, size, 0x81, opcode_extension, destination, immediate, None)
    }
}

#[inline]
fn emit_jump_offset<E: UserDefinedError>(jit: &mut JitCompiler, target_pc: usize) -> Result<(), EbpfError<E>> {
    jit.text_section_jumps.push(Jump { location: jit.offset_in_text_section, target_pc });
    emit::<u32, E>(jit, 0)
}

#[inline]
fn emit_jcc<E: UserDefinedError>(jit: &mut JitCompiler, code: u8, target_pc: usize) -> Result<(), EbpfError<E>> {
    emit::<u8, E>(jit, 0x0f)?;
    emit::<u8, E>(jit, code)?;
    emit_jump_offset(jit, target_pc)
}

#[inline]
fn emit_jmp<E: UserDefinedError>(jit: &mut JitCompiler, target_pc: usize) -> Result<(), EbpfError<E>> {
    emit::<u8, E>(jit, 0xe9)?;
    emit_jump_offset(jit, target_pc)
}

#[inline]
fn emit_call<E: UserDefinedError>(jit: &mut JitCompiler, target_pc: usize) -> Result<(), EbpfError<E>> {
    emit::<u8, E>(jit, 0xe8)?;
    emit_jump_offset(jit, target_pc)
}

#[inline]
fn set_anchor(jit: &mut JitCompiler, target: usize) {
    jit.handler_anchors.insert(target, jit.offset_in_text_section);
}

/// Indices of slots inside the struct at inital RSP
#[repr(C)]
enum EnvironmentStackSlot {
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

fn slot_on_environment_stack(jit: &JitCompiler, slot: EnvironmentStackSlot) -> i32 {
    -8 * (slot as i32 + jit.environment_stack_key)
}

#[allow(dead_code)]
#[inline]
fn emit_stopwatch<E: UserDefinedError>(jit: &mut JitCompiler, begin: bool) -> Result<(), EbpfError<E>> {
    jit.stopwatch_is_active = true;
    X86Instruction::push(RDX, None).emit(jit)?;
    X86Instruction::push(RAX, None).emit(jit)?;
    X86Instruction::fence(FenceType::Load).emit(jit)?; // lfence
    X86Instruction::cycle_count().emit(jit)?; // rdtsc
    X86Instruction::fence(FenceType::Load).emit(jit)?; // lfence
    emit_alu(jit, OperandSize::S64, 0xc1, 4, RDX, 32, None)?; // RDX <<= 32;
    emit_alu(jit, OperandSize::S64, 0x09, RDX, RAX, 0, None)?; // RAX |= RDX;
    if begin {
        emit_alu(jit, OperandSize::S64, 0x29, RAX, RBP, 0, Some(X86IndirectAccess::Offset(slot_on_environment_stack(jit, EnvironmentStackSlot::StopwatchNumerator))))?; // *numerator -= RAX;
    } else {
        emit_alu(jit, OperandSize::S64, 0x01, RAX, RBP, 0, Some(X86IndirectAccess::Offset(slot_on_environment_stack(jit, EnvironmentStackSlot::StopwatchNumerator))))?; // *numerator += RAX;
        emit_alu(jit, OperandSize::S64, 0x81, 0, RBP, 1, Some(X86IndirectAccess::Offset(slot_on_environment_stack(jit, EnvironmentStackSlot::StopwatchDenominator))))?; // *denominator += 1;
    }
    X86Instruction::pop(RAX).emit(jit)?;
    X86Instruction::pop(RDX).emit(jit)
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

#[inline]
fn emit_validate_instruction_count<E: UserDefinedError>(jit: &mut JitCompiler, exclusive: bool, pc: Option<usize>) -> Result<(), EbpfError<E>> {
    if let Some(pc) = pc {
        jit.last_instruction_meter_validation_pc = pc;
        X86Instruction::cmp_immediate(OperandSize::S64, ARGUMENT_REGISTERS[0], pc as i64 + 1, None).emit(jit)?;
    } else {
        X86Instruction::cmp(OperandSize::S64, R11, ARGUMENT_REGISTERS[0], None).emit(jit)?;
    }
    emit_jcc(jit, if exclusive { 0x82 } else { 0x86 }, TARGET_PC_CALL_EXCEEDED_MAX_INSTRUCTIONS)
}

#[inline]
fn emit_profile_instruction_count<E: UserDefinedError>(jit: &mut JitCompiler, target_pc: Option<usize>) -> Result<(), EbpfError<E>> {
    match target_pc {
        Some(target_pc) => {
            emit_alu(jit, OperandSize::S64, 0x81, 0, ARGUMENT_REGISTERS[0], target_pc as i64 - jit.pc as i64 - 1, None)?; // instruction_meter += target_pc - (jit.pc + 1);
        },
        None => {
            emit_alu(jit, OperandSize::S64, 0x81, 5, ARGUMENT_REGISTERS[0], jit.pc as i64 + 1, None)?; // instruction_meter -= jit.pc + 1;
            emit_alu(jit, OperandSize::S64, 0x01, R11, ARGUMENT_REGISTERS[0], jit.pc as i64, None)?; // instruction_meter += target_pc;
        },
    }
    Ok(())
}

#[inline]
fn emit_validate_and_profile_instruction_count<E: UserDefinedError>(jit: &mut JitCompiler, exclusive: bool, target_pc: Option<usize>) -> Result<(), EbpfError<E>> {
    if jit.config.enable_instruction_meter {
        emit_validate_instruction_count(jit, exclusive, Some(jit.pc))?;
        emit_profile_instruction_count(jit, target_pc)?;
    }
    Ok(())
}

#[inline]
fn emit_undo_profile_instruction_count<E: UserDefinedError>(jit: &mut JitCompiler, target_pc: usize) -> Result<(), EbpfError<E>> {
    if jit.config.enable_instruction_meter {
        emit_alu(jit, OperandSize::S64, 0x81, 0, ARGUMENT_REGISTERS[0], jit.pc as i64 + 1 - target_pc as i64, None)?; // instruction_meter += (jit.pc + 1) - target_pc;
    }
    Ok(())
}

#[inline]
fn emit_profile_instruction_count_finalize<E: UserDefinedError>(jit: &mut JitCompiler, store_pc_in_exception: bool) -> Result<(), EbpfError<E>> {
    if jit.config.enable_instruction_meter || store_pc_in_exception {
        emit_alu(jit, OperandSize::S64, 0x81, 0, R11, 1, None)?; // R11 += 1;
    }
    if jit.config.enable_instruction_meter {
        emit_alu(jit, OperandSize::S64, 0x29, R11, ARGUMENT_REGISTERS[0], 0, None)?; // instruction_meter -= pc + 1;
    }
    if store_pc_in_exception {
        X86Instruction::load(OperandSize::S64, RBP, R10, X86IndirectAccess::Offset(slot_on_environment_stack(jit, EnvironmentStackSlot::OptRetValPtr))).emit(jit)?;
        X86Instruction::store_immediate(OperandSize::S64, R10, X86IndirectAccess::Offset(0), 1).emit(jit)?; // is_err = true;
        emit_alu(jit, OperandSize::S64, 0x81, 0, R11, ebpf::ELF_INSN_DUMP_OFFSET as i64 - 1, None)?;
        X86Instruction::store(OperandSize::S64, R11, R10, X86IndirectAccess::Offset(16)).emit(jit)?; // pc = jit.pc + ebpf::ELF_INSN_DUMP_OFFSET;
    }
    Ok(())
}

#[inline]
fn emit_conditional_branch_reg<E: UserDefinedError>(jit: &mut JitCompiler, op: u8, bitwise: bool, first_operand: u8, second_operand: u8, target_pc: usize) -> Result<(), EbpfError<E>> {
    emit_validate_and_profile_instruction_count(jit, false, Some(target_pc))?;
    if bitwise { // Logical
        X86Instruction::test(OperandSize::S64, first_operand, second_operand, None).emit(jit)?;
    } else { // Arithmetic
        X86Instruction::cmp(OperandSize::S64, first_operand, second_operand, None).emit(jit)?;
    }
    X86Instruction::load_immediate(OperandSize::S64, R11, target_pc as i64).emit(jit)?;
    emit_jcc(jit, op, target_pc)?;
    emit_undo_profile_instruction_count(jit, target_pc)
}

#[inline]
fn emit_conditional_branch_imm<E: UserDefinedError>(jit: &mut JitCompiler, op: u8, bitwise: bool, immediate: i64, second_operand: u8, target_pc: usize) -> Result<(), EbpfError<E>> {
    emit_validate_and_profile_instruction_count(jit, false, Some(target_pc))?;
    if should_sanitize_constant(jit, immediate) {
        emit_sanitized_load_immediate(jit, OperandSize::S64, R11, immediate)?;
        if bitwise { // Logical
            X86Instruction::test(OperandSize::S64, R11, second_operand, None).emit(jit)?;
        } else { // Arithmetic
            X86Instruction::cmp(OperandSize::S64, R11, second_operand, None).emit(jit)?;
        }
    } else if bitwise { // Logical
        X86Instruction::test_immediate(OperandSize::S64, second_operand, immediate, None).emit(jit)?;
    } else { // Arithmetic
        X86Instruction::cmp_immediate(OperandSize::S64, second_operand, immediate, None).emit(jit)?;
    }
    X86Instruction::load_immediate(OperandSize::S64, R11, target_pc as i64).emit(jit)?;
    emit_jcc(jit, op, target_pc)?;
    emit_undo_profile_instruction_count(jit, target_pc)
}

enum Value {
    Register(u8),
    RegisterIndirect(u8, i32, bool),
    RegisterPlusConstant32(u8, i32, bool),
    RegisterPlusConstant64(u8, i64, bool),
    Constant64(i64, bool),
}

#[inline]
fn emit_bpf_call<E: UserDefinedError>(jit: &mut JitCompiler, dst: Value) -> Result<(), EbpfError<E>> {
    // Store PC in case the bounds check fails
    X86Instruction::load_immediate(OperandSize::S64, R11, jit.pc as i64).emit(jit)?;

    emit_call(jit, TARGET_PC_BPF_CALL_PROLOGUE)?;

    match dst {
        Value::Register(reg) => {
            // Move vm target_address into RAX
            X86Instruction::push(REGISTER_MAP[0], None).emit(jit)?;
            if reg != REGISTER_MAP[0] {
                X86Instruction::mov(OperandSize::S64, reg, REGISTER_MAP[0]).emit(jit)?;
            }

            emit_call(jit, TARGET_PC_BPF_CALL_REG)?;

            emit_validate_and_profile_instruction_count(jit, false, None)?;
            X86Instruction::mov(OperandSize::S64, REGISTER_MAP[0], R11).emit(jit)?; // Save target_pc
            X86Instruction::pop(REGISTER_MAP[0]).emit(jit)?; // Restore RAX
            X86Instruction::call_reg(R11, None).emit(jit)?; // callq *%r11
        },
        Value::Constant64(target_pc, user_provided) => {
            debug_assert!(!user_provided);
            emit_validate_and_profile_instruction_count(jit, false, Some(target_pc as usize))?;
            X86Instruction::load_immediate(OperandSize::S64, R11, target_pc as i64).emit(jit)?;
            emit_call(jit, target_pc as usize)?;
        },
        _ => {
            #[cfg(debug_assertions)]
            unreachable!();
        }
    }

    emit_undo_profile_instruction_count(jit, 0)?;

    // Restore the previous frame pointer
    X86Instruction::pop(REGISTER_MAP[FRAME_PTR_REG]).emit(jit)?;
    let frame_ptr_access = X86IndirectAccess::Offset(slot_on_environment_stack(jit, EnvironmentStackSlot::BpfFramePtr));
    X86Instruction::store(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], RBP, frame_ptr_access).emit(jit)?;
    for reg in REGISTER_MAP.iter().skip(FIRST_SCRATCH_REG).take(SCRATCH_REGS).rev() {
        X86Instruction::pop(*reg).emit(jit)?;
    }
    Ok(())
}

struct Argument {
    index: usize,
    value: Value,
}

impl Argument {
    fn is_stack_argument(&self) -> bool {
        self.index >= ARGUMENT_REGISTERS.len()
    }

    fn get_argument_register(&self) -> u8 {
        ARGUMENT_REGISTERS[self.index]
    }

    fn emit_pass<E: UserDefinedError>(&self, jit: &mut JitCompiler) -> Result<(), EbpfError<E>> {
        let is_stack_argument = self.is_stack_argument();
        let dst = if is_stack_argument {
            R11
        } else {
            self.get_argument_register()
        };
        match self.value {
            Value::Register(reg) => {
                if is_stack_argument {
                    X86Instruction::push(reg, None).emit(jit)?;
                } else if reg != dst {
                    X86Instruction::mov(OperandSize::S64, reg, dst).emit(jit)?;
                }
            },
            Value::RegisterIndirect(reg, offset, user_provided) => {
                debug_assert!(!user_provided);
                if is_stack_argument {
                    X86Instruction::push(reg, Some(X86IndirectAccess::Offset(offset))).emit(jit)?;
                } else {
                    X86Instruction::load(OperandSize::S64, reg, dst, X86IndirectAccess::Offset(offset)).emit(jit)?;
                }
            },
            Value::RegisterPlusConstant32(reg, offset, user_provided) => {
                debug_assert!(!user_provided);
                if is_stack_argument {
                    X86Instruction::push(reg, None).emit(jit)?;
                    emit_alu(jit, OperandSize::S64, 0x81, 0, RSP, offset as i64, Some(X86IndirectAccess::OffsetIndexShift(0, RSP, 0)))?;
                } else {
                    X86Instruction::lea(OperandSize::S64, reg, dst, Some(X86IndirectAccess::Offset(offset))).emit(jit)?;
                }
            },
            Value::RegisterPlusConstant64(reg, offset, user_provided) => {
                debug_assert!(!user_provided);
                if is_stack_argument {
                    X86Instruction::push(reg, None).emit(jit)?;
                    emit_alu(jit, OperandSize::S64, 0x81, 0, RSP, offset, Some(X86IndirectAccess::OffsetIndexShift(0, RSP, 0)))?;
                } else {
                    X86Instruction::load_immediate(OperandSize::S64, dst, offset).emit(jit)?;
                    emit_alu(jit, OperandSize::S64, 0x01, reg, dst, 0, None)?;
                }
            },
            Value::Constant64(value, user_provided) => {
                debug_assert!(!user_provided && !is_stack_argument);
                X86Instruction::load_immediate(OperandSize::S64, dst, value).emit(jit)?;
            },
        }
        Ok(())
    }
}

#[inline]
fn emit_rust_call<E: UserDefinedError>(jit: &mut JitCompiler, dst: Value, arguments: &[Argument], result_reg: Option<u8>, check_exception: bool) -> Result<(), EbpfError<E>> {
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
        X86Instruction::push(*reg, None).emit(jit)?;
    }

    // Pass arguments
    let mut stack_arguments = 0;
    for argument in arguments {
        if argument.is_stack_argument() {
            stack_arguments += 1;
        }
        argument.emit_pass(jit)?;
    }

    match dst {
        Value::Register(reg) => {
            X86Instruction::call_reg(reg, None).emit(jit)?;
        },
        Value::Constant64(value, user_provided) => {
            debug_assert!(!user_provided);
            X86Instruction::load_immediate(OperandSize::S64, RAX, value).emit(jit)?;
            X86Instruction::call_reg(RAX, None).emit(jit)?;
        },
        _ => {
            #[cfg(debug_assertions)]
            unreachable!();
        }
    }

    // Save returned value in result register
    if let Some(reg) = result_reg {
        X86Instruction::mov(OperandSize::S64, RAX, reg).emit(jit)?;
    }

    // Restore registers from stack
    emit_alu(jit, OperandSize::S64, 0x81, 0, RSP, stack_arguments * 8, None)?;
    for reg in saved_registers.iter().rev() {
        X86Instruction::pop(*reg).emit(jit)?;
    }

    if check_exception {
        // Test if result indicates that an error occured
        X86Instruction::load(OperandSize::S64, RBP, R11, X86IndirectAccess::Offset(slot_on_environment_stack(jit, EnvironmentStackSlot::OptRetValPtr))).emit(jit)?;
        X86Instruction::cmp_immediate(OperandSize::S64, R11, 0, Some(X86IndirectAccess::Offset(0))).emit(jit)?;
    }
    Ok(())
}

#[inline]
fn emit_address_translation<E: UserDefinedError>(jit: &mut JitCompiler, host_addr: u8, vm_addr: Value, len: u64, access_type: AccessType) -> Result<(), EbpfError<E>> {
    match vm_addr {
        Value::RegisterPlusConstant64(reg, constant, user_provided) => {
            if user_provided && should_sanitize_constant(jit, constant) {
                emit_sanitized_load_immediate(jit, OperandSize::S64, R11, constant)?;
            } else {
                X86Instruction::load_immediate(OperandSize::S64, R11, constant).emit(jit)?;
            }
            emit_alu(jit, OperandSize::S64, 0x01, reg, R11, 0, None)?;
        },
        Value::Constant64(constant, user_provided) => {
            if user_provided && should_sanitize_constant(jit, constant) {
                emit_sanitized_load_immediate(jit, OperandSize::S64, R11, constant)?;
            } else {
                X86Instruction::load_immediate(OperandSize::S64, R11, constant).emit(jit)?;
            }
        },
        _ => {
            #[cfg(debug_assertions)]
            unreachable!();
        },
    }
    emit_call(jit, TARGET_PC_TRANSLATE_MEMORY_ADDRESS + len.trailing_zeros() as usize + 4 * (access_type as usize))?;
    X86Instruction::mov(OperandSize::S64, R11, host_addr).emit(jit)
}

fn emit_shift<E: UserDefinedError>(jit: &mut JitCompiler, size: OperandSize, opcode_extension: u8, source: u8, destination: u8, immediate: Option<i64>) -> Result<(), EbpfError<E>> {
    if let Some(immediate) = immediate {
        if should_sanitize_constant(jit, immediate) {
            emit_sanitized_load_immediate(jit, OperandSize::S32, source, immediate)?;
        } else {
            return emit_alu(jit, size, 0xc1, opcode_extension, destination, immediate, None);
        }
    }
    if size == OperandSize::S32 {
        emit_alu(jit, OperandSize::S32, 0x81, 4, destination, -1, None)?; // Mask to 32 bit
    }
    if source == RCX {
        if destination == RCX {
            emit_alu(jit, size, 0xd3, opcode_extension, destination, 0, None)
        } else {
            X86Instruction::push(RCX, None).emit(jit)?;
            emit_alu(jit, size, 0xd3, opcode_extension, destination, 0, None)?;
            X86Instruction::pop(RCX).emit(jit)
        }
    } else if destination == RCX {
        if source != R11 {
            X86Instruction::push(source, None).emit(jit)?;
        }
        X86Instruction::xchg(OperandSize::S64, source, RCX, None).emit(jit)?;
        emit_alu(jit, size, 0xd3, opcode_extension, source, 0, None)?;
        X86Instruction::mov(OperandSize::S64, source, RCX).emit(jit)?;
        if source != R11 {
            X86Instruction::pop(source).emit(jit)?;
        }
        Ok(())
    } else {
        X86Instruction::push(RCX, None).emit(jit)?;
        X86Instruction::mov(OperandSize::S64, source, RCX).emit(jit)?;
        emit_alu(jit, size, 0xd3, opcode_extension, destination, 0, None)?;
        X86Instruction::pop(RCX).emit(jit)
    }
}

fn emit_muldivmod<E: UserDefinedError>(jit: &mut JitCompiler, opc: u8, src: u8, dst: u8, imm: Option<i64>) -> Result<(), EbpfError<E>> {
    let mul = (opc & ebpf::BPF_ALU_OP_MASK) == (ebpf::MUL32_IMM & ebpf::BPF_ALU_OP_MASK);
    let div = (opc & ebpf::BPF_ALU_OP_MASK) == (ebpf::DIV32_IMM & ebpf::BPF_ALU_OP_MASK);
    let sdiv = (opc & ebpf::BPF_ALU_OP_MASK) == (ebpf::SDIV32_IMM & ebpf::BPF_ALU_OP_MASK);
    let modrm = (opc & ebpf::BPF_ALU_OP_MASK) == (ebpf::MOD32_IMM & ebpf::BPF_ALU_OP_MASK);
    let size = if (opc & ebpf::BPF_CLS_MASK) == ebpf::BPF_ALU64 { OperandSize::S64 } else { OperandSize::S32 };

    // subtracting offset_in_text_section from TARGET_PC_LOCAL_ANCHOR gives us a
    // unique local anchor
    let sdiv_anchor =  if sdiv { TARGET_PC_LOCAL_ANCHOR - jit.offset_in_text_section } else { 0 };

    if (div || sdiv || modrm) && imm.is_none() {
        // Save pc
        X86Instruction::load_immediate(OperandSize::S64, R11, jit.pc as i64).emit(jit)?;
        X86Instruction::test(size, src, src, None).emit(jit)?; // src == 0
        emit_jcc(jit, 0x84, TARGET_PC_DIV_BY_ZERO)?;

    }

    // sdiv overflows with MIN / -1. If we have an immediate and it's not -1, we
    // don't need any checks.
    if sdiv && imm.unwrap_or(-1) == -1 {
        if imm.is_none() {
            // if src != -1, we can skip checking dst
            X86Instruction::cmp_immediate(size, src, -1, None).emit(jit)?;
            emit_jcc(jit, 0x85, sdiv_anchor)?;
        }

        // if dst != MIN, we're not going to overflow
        X86Instruction::load_immediate(size, R11, if size == OperandSize::S64 { i64::MIN } else { i32::MIN as i64 }).emit(jit)?;
        X86Instruction::cmp(size, dst, R11, None).emit(jit)?;
        emit_jcc(jit, 0x85, sdiv_anchor)?;

        // MIN / -1, raise EbpfError::DivideOverflow(pc)
        X86Instruction::load_immediate(OperandSize::S64, R11, jit.pc as i64).emit(jit)?;
        emit_jmp(jit, TARGET_PC_DIV_OVERFLOW)?;
    }

    if sdiv {
        set_anchor(jit, sdiv_anchor);
    }

    if dst != RAX {
        X86Instruction::push(RAX, None).emit(jit)?;
    }
    if dst != RDX {
        X86Instruction::push(RDX, None).emit(jit)?;
    }

    if let Some(imm) = imm {
        if should_sanitize_constant(jit, imm) {
            emit_sanitized_load_immediate(jit, OperandSize::S64, R11, imm)?;
        } else {
            X86Instruction::load_immediate(OperandSize::S64, R11, imm).emit(jit)?;
        }
    } else {
        X86Instruction::mov(OperandSize::S64, src, R11).emit(jit)?;
    }

    if dst != RAX {
        X86Instruction::mov(OperandSize::S64, dst, RAX).emit(jit)?;
    }

    if div || modrm {
        // xor %edx,%edx
        emit_alu(jit, size, 0x31, RDX, RDX, 0, None)?;
    } else if sdiv {
        // cdq or cqo depending on operand size
        X86Instruction {
            size,
            opcode: 0x99,
            modrm: false,
            ..X86Instruction::default()
        }.emit(jit)?;
    }

    emit_alu(jit, size, 0xf7, if mul { 4 } else if sdiv { 7 } else { 6 }, R11, 0, None)?;

    if dst != RDX {
        if modrm {
            X86Instruction::mov(OperandSize::S64, RDX, dst).emit(jit)?;
        }
        X86Instruction::pop(RDX).emit(jit)?;
    }
    if dst != RAX {
        if div || sdiv || mul {
            X86Instruction::mov(OperandSize::S64, RAX, dst).emit(jit)?;
        }
        X86Instruction::pop(RAX).emit(jit)?;
    }

    if size == OperandSize::S32 && opc & ebpf::BPF_ALU_OP_MASK == ebpf::BPF_MUL {
        X86Instruction::sign_extend_i32_to_i64(dst, dst).emit(jit)?;
    }
    Ok(())
}

#[inline]
fn emit_set_exception_kind<E: UserDefinedError>(jit: &mut JitCompiler, err: EbpfError<E>) -> Result<(), EbpfError<E>> {
    let err = Result::<u64, EbpfError<E>>::Err(err);
    let err_kind = unsafe { *(&err as *const _ as *const u64).offset(1) };
    X86Instruction::load(OperandSize::S64, RBP, R10, X86IndirectAccess::Offset(slot_on_environment_stack(jit, EnvironmentStackSlot::OptRetValPtr))).emit(jit)?;
    X86Instruction::store_immediate(OperandSize::S64, R10, X86IndirectAccess::Offset(8), err_kind as i64).emit(jit)
}

#[derive(Debug)]
struct Jump {
    location: usize,
    target_pc: usize,
}
impl Jump {
    fn get_target_offset(&self, jit: &JitCompiler) -> u64 {
        match jit.handler_anchors.get(&self.target_pc) {
            Some(target) => *target as u64,
            None         => jit.result.pc_section[self.target_pc]
        }
    }
}

pub struct JitCompiler {
    result: JitProgramSections,
    pc_section_jumps: Vec<Jump>,
    text_section_jumps: Vec<Jump>,
    offset_in_text_section: usize,
    pc: usize,
    last_instruction_meter_validation_pc: usize,
    program_vm_addr: u64,
    handler_anchors: HashMap<usize, usize>,
    config: Config,
    diversification_rng: SmallRng,
    stopwatch_is_active: bool,
    environment_stack_key: i32,
    program_argument_key: i32,
}

impl Index<usize> for JitCompiler {
    type Output = u8;

    fn index(&self, _index: usize) -> &u8 {
        &self.result.text_section[_index]
    }
}

impl IndexMut<usize> for JitCompiler {
    fn index_mut(&mut self, _index: usize) -> &mut u8 {
        &mut self.result.text_section[_index]
    }
}

impl std::fmt::Debug for JitCompiler {
    fn fmt(&self, fmt: &mut Formatter) -> Result<(), FormatterError> {
        fmt.write_str("JIT text_section: [")?;
        for i in self.result.text_section as &[u8] {
            fmt.write_fmt(format_args!(" {:#04x},", i))?;
        };
        fmt.write_str(" ] | ")?;
        fmt.debug_struct("JIT state")
            .field("memory", &self.result.pc_section.as_ptr())
            .field("pc", &self.pc)
            .field("offset_in_text_section", &self.offset_in_text_section)
            .field("pc_section", &self.result.pc_section)
            .field("handler_anchors", &self.handler_anchors)
            .field("pc_section_jumps", &self.pc_section_jumps)
            .field("text_section_jumps", &self.text_section_jumps)
            .finish()
    }
}

impl JitCompiler {
    // Arguments are unused on windows
    fn new<E: UserDefinedError>(program: &[u8], config: &Config) -> Result<Self, EbpfError<E>> {
        #[cfg(target_os = "windows")]
        {
            let _ = program;
            let _ = config;
            panic!("JIT not supported on windows");
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = program;
            let _ = config;
            panic!("JIT is only supported on x86_64");
        }

        // Scan through program to find actual number of instructions
        let mut pc = 0;
        while (pc + 1) * ebpf::INSN_SIZE <= program.len() {
            let insn = ebpf::get_insn_unchecked(program, pc);
            pc += match insn.opc {
                ebpf::LD_DW_IMM => 2,
                _ => 1,
            };
        }

        let mut code_length_estimate = MAX_EMPTY_PROGRAM_MACHINE_CODE_LENGTH + MAX_MACHINE_CODE_LENGTH_PER_INSTRUCTION * pc;
        code_length_estimate += (code_length_estimate as f64 * config.noop_instruction_ratio) as usize;
        let mut diversification_rng = SmallRng::from_rng(rand::thread_rng()).unwrap();
        let (environment_stack_key, program_argument_key) =
            if config.encrypt_environment_registers {
                (
                    diversification_rng.gen::<i32>() / 16, // -3 bits for 8 Byte alignment, and -1 bit to have encoding space for EnvironmentStackSlot::SlotCount
                    diversification_rng.gen::<i32>() / 2, // -1 bit to have encoding space for (SYSCALL_CONTEXT_OBJECTS_OFFSET + syscall.context_object_slot) * 8
                )
            } else { (0, 0) };

        Ok(Self {
            result: JitProgramSections::new(pc + 1, code_length_estimate)?,
            pc_section_jumps: vec![],
            text_section_jumps: vec![],
            offset_in_text_section: 0,
            pc: 0,
            last_instruction_meter_validation_pc: 0,
            program_vm_addr: 0,
            handler_anchors: HashMap::new(),
            config: *config,
            diversification_rng,
            stopwatch_is_active: false,
            environment_stack_key,
            program_argument_key,
        })
    }

    fn compile<E: UserDefinedError, I: InstructionMeter>(&mut self,
            executable: &Pin<Box<Executable<E, I>>>) -> Result<(), EbpfError<E>> {
        let (program_vm_addr, program) = executable.get_text_bytes();
        self.program_vm_addr = program_vm_addr;

        self.generate_prologue::<E, I>()?;

        // Jump to entry point
        let entry = executable.get_entrypoint_instruction_offset().unwrap_or(0);
        if self.config.enable_instruction_meter {
            emit_profile_instruction_count(self, Some(entry + 1))?;
        }
        X86Instruction::load_immediate(OperandSize::S64, R11, entry as i64).emit(self)?;
        emit_jmp(self, entry)?;

        // Have these in front so that the linear search of TARGET_PC_TRANSLATE_PC does not terminate early
        self.generate_helper_routines::<E, I>()?;
        self.generate_exception_handlers::<E>()?;

        while self.pc * ebpf::INSN_SIZE < program.len() {
            let mut insn = ebpf::get_insn_unchecked(program, self.pc);

            self.result.pc_section[self.pc] = self.offset_in_text_section as u64;

            // Regular instruction meter checkpoints to prevent long linear runs from exceeding their budget
            if self.last_instruction_meter_validation_pc + self.config.instruction_meter_checkpoint_distance <= self.pc {
                emit_validate_instruction_count(self, true, Some(self.pc))?;
            }

            if self.config.enable_instruction_tracing {
                X86Instruction::load_immediate(OperandSize::S64, R11, self.pc as i64).emit(self)?;
                emit_call(self, TARGET_PC_TRACE)?;
                X86Instruction::load_immediate(OperandSize::S64, R11, 0).emit(self)?;
            }

            let dst = if insn.dst == STACK_PTR_REG as u8 { u8::MAX } else { REGISTER_MAP[insn.dst as usize] };
            let src = REGISTER_MAP[insn.src as usize];
            let target_pc = (self.pc as isize + insn.off as isize + 1) as usize;

            match insn.opc {
                _ if insn.dst == STACK_PTR_REG as u8 && self.config.dynamic_stack_frames => {
                    let stack_ptr_access = X86IndirectAccess::Offset(slot_on_environment_stack(self, EnvironmentStackSlot::BpfStackPtr));
                    match insn.opc {
                        ebpf::SUB64_IMM => emit_alu(self, OperandSize::S64, 0x81, 5, RBP, insn.imm, Some(stack_ptr_access))?,
                        ebpf::ADD64_IMM => emit_alu(self, OperandSize::S64, 0x81, 0, RBP, insn.imm, Some(stack_ptr_access))?,
                        _ => {
                            #[cfg(debug_assertions)]
                            unreachable!("unexpected insn on r11")
                        }
                    }
                }
                // BPF_LD class
                ebpf::LD_ABS_B   => {
                    emit_address_translation(self, R11, Value::Constant64(ebpf::MM_INPUT_START.wrapping_add(insn.imm as u32 as u64) as i64, true), 1, AccessType::Load)?;
                    X86Instruction::load(OperandSize::S8, R11, RAX, X86IndirectAccess::Offset(0)).emit(self)?;
                },
                ebpf::LD_ABS_H   => {
                    emit_address_translation(self, R11, Value::Constant64(ebpf::MM_INPUT_START.wrapping_add(insn.imm as u32 as u64) as i64, true), 2, AccessType::Load)?;
                    X86Instruction::load(OperandSize::S16, R11, RAX, X86IndirectAccess::Offset(0)).emit(self)?;
                },
                ebpf::LD_ABS_W   => {
                    emit_address_translation(self, R11, Value::Constant64(ebpf::MM_INPUT_START.wrapping_add(insn.imm as u32 as u64) as i64, true), 4, AccessType::Load)?;
                    X86Instruction::load(OperandSize::S32, R11, RAX, X86IndirectAccess::Offset(0)).emit(self)?;
                },
                ebpf::LD_ABS_DW  => {
                    emit_address_translation(self, R11, Value::Constant64(ebpf::MM_INPUT_START.wrapping_add(insn.imm as u32 as u64) as i64, true), 8, AccessType::Load)?;
                    X86Instruction::load(OperandSize::S64, R11, RAX, X86IndirectAccess::Offset(0)).emit(self)?;
                },
                ebpf::LD_IND_B   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(src, ebpf::MM_INPUT_START.wrapping_add(insn.imm as u32 as u64) as i64, true), 1, AccessType::Load)?;
                    X86Instruction::load(OperandSize::S8, R11, RAX, X86IndirectAccess::Offset(0)).emit(self)?;
                },
                ebpf::LD_IND_H   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(src, ebpf::MM_INPUT_START.wrapping_add(insn.imm as u32 as u64) as i64, true), 2, AccessType::Load)?;
                    X86Instruction::load(OperandSize::S16, R11, RAX, X86IndirectAccess::Offset(0)).emit(self)?;
                },
                ebpf::LD_IND_W   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(src, ebpf::MM_INPUT_START.wrapping_add(insn.imm as u32 as u64) as i64, true), 4, AccessType::Load)?;
                    X86Instruction::load(OperandSize::S32, R11, RAX, X86IndirectAccess::Offset(0)).emit(self)?;
                },
                ebpf::LD_IND_DW  => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(src, ebpf::MM_INPUT_START.wrapping_add(insn.imm as u32 as u64) as i64, true), 8, AccessType::Load)?;
                    X86Instruction::load(OperandSize::S64, R11, RAX, X86IndirectAccess::Offset(0)).emit(self)?;
                },

                ebpf::LD_DW_IMM  => {
                    emit_validate_and_profile_instruction_count(self, true, Some(self.pc + 2))?;
                    self.pc += 1;
                    self.pc_section_jumps.push(Jump { location: self.pc, target_pc: TARGET_PC_CALL_UNSUPPORTED_INSTRUCTION });
                    ebpf::augment_lddw_unchecked(program, &mut insn);
                    if should_sanitize_constant(self, insn.imm) {
                        emit_sanitized_load_immediate(self, OperandSize::S64, dst, insn.imm)?;
                    } else {
                        X86Instruction::load_immediate(OperandSize::S64, dst, insn.imm).emit(self)?;
                    }
                },

                // BPF_LDX class
                ebpf::LD_B_REG   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(src, insn.off as i64, true), 1, AccessType::Load)?;
                    X86Instruction::load(OperandSize::S8, R11, dst, X86IndirectAccess::Offset(0)).emit(self)?;
                },
                ebpf::LD_H_REG   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(src, insn.off as i64, true), 2, AccessType::Load)?;
                    X86Instruction::load(OperandSize::S16, R11, dst, X86IndirectAccess::Offset(0)).emit(self)?;
                },
                ebpf::LD_W_REG   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(src, insn.off as i64, true), 4, AccessType::Load)?;
                    X86Instruction::load(OperandSize::S32, R11, dst, X86IndirectAccess::Offset(0)).emit(self)?;
                },
                ebpf::LD_DW_REG  => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(src, insn.off as i64, true), 8, AccessType::Load)?;
                    X86Instruction::load(OperandSize::S64, R11, dst, X86IndirectAccess::Offset(0)).emit(self)?;
                },

                // BPF_ST class
                ebpf::ST_B_IMM   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 1, AccessType::Store)?;
                    X86Instruction::store_immediate(OperandSize::S8, R11, X86IndirectAccess::Offset(0), insn.imm as i64).emit(self)?;
                },
                ebpf::ST_H_IMM   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 2, AccessType::Store)?;
                    X86Instruction::store_immediate(OperandSize::S16, R11, X86IndirectAccess::Offset(0), insn.imm as i64).emit(self)?;
                },
                ebpf::ST_W_IMM   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 4, AccessType::Store)?;
                    X86Instruction::store_immediate(OperandSize::S32, R11, X86IndirectAccess::Offset(0), insn.imm as i64).emit(self)?;
                },
                ebpf::ST_DW_IMM  => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 8, AccessType::Store)?;
                    X86Instruction::store_immediate(OperandSize::S64, R11, X86IndirectAccess::Offset(0), insn.imm as i64).emit(self)?;
                },

                // BPF_STX class
                ebpf::ST_B_REG  => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 1, AccessType::Store)?;
                    X86Instruction::store(OperandSize::S8, src, R11, X86IndirectAccess::Offset(0)).emit(self)?;
                },
                ebpf::ST_H_REG  => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 2, AccessType::Store)?;
                    X86Instruction::store(OperandSize::S16, src, R11, X86IndirectAccess::Offset(0)).emit(self)?;
                },
                ebpf::ST_W_REG  => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 4, AccessType::Store)?;
                    X86Instruction::store(OperandSize::S32, src, R11, X86IndirectAccess::Offset(0)).emit(self)?;
                },
                ebpf::ST_DW_REG  => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 8, AccessType::Store)?;
                    X86Instruction::store(OperandSize::S64, src, R11, X86IndirectAccess::Offset(0)).emit(self)?;
                },

                // BPF_ALU class
                ebpf::ADD32_IMM  => {
                    emit_sanitized_alu(self, OperandSize::S32, 0x01, 0, dst, insn.imm)?;
                    X86Instruction::sign_extend_i32_to_i64(dst, dst).emit(self)?;
                },
                ebpf::ADD32_REG  => {
                    emit_alu(self, OperandSize::S32, 0x01, src, dst, 0, None)?;
                    X86Instruction::sign_extend_i32_to_i64(dst, dst).emit(self)?;
                },
                ebpf::SUB32_IMM  => {
                    emit_sanitized_alu(self, OperandSize::S32, 0x29, 5, dst, insn.imm)?;
                    X86Instruction::sign_extend_i32_to_i64(dst, dst).emit(self)?;
                },
                ebpf::SUB32_REG  => {
                    emit_alu(self, OperandSize::S32, 0x29, src, dst, 0, None)?;
                    X86Instruction::sign_extend_i32_to_i64(dst, dst).emit(self)?;
                },
                ebpf::MUL32_IMM | ebpf::DIV32_IMM | ebpf::SDIV32_IMM | ebpf::MOD32_IMM  =>
                    emit_muldivmod(self, insn.opc, dst, dst, Some(insn.imm))?,
                ebpf::MUL32_REG | ebpf::DIV32_REG | ebpf::SDIV32_REG | ebpf::MOD32_REG  =>
                    emit_muldivmod(self, insn.opc, src, dst, None)?,
                ebpf::OR32_IMM   => emit_sanitized_alu(self, OperandSize::S32, 0x09, 1, dst, insn.imm)?,
                ebpf::OR32_REG   => emit_alu(self, OperandSize::S32, 0x09, src, dst, 0, None)?,
                ebpf::AND32_IMM  => emit_sanitized_alu(self, OperandSize::S32, 0x21, 4, dst, insn.imm)?,
                ebpf::AND32_REG  => emit_alu(self, OperandSize::S32, 0x21, src, dst, 0, None)?,
                ebpf::LSH32_IMM  => emit_shift(self, OperandSize::S32, 4, R11, dst, Some(insn.imm))?,
                ebpf::LSH32_REG  => emit_shift(self, OperandSize::S32, 4, src, dst, None)?,
                ebpf::RSH32_IMM  => emit_shift(self, OperandSize::S32, 5, R11, dst, Some(insn.imm))?,
                ebpf::RSH32_REG  => emit_shift(self, OperandSize::S32, 5, src, dst, None)?,
                ebpf::NEG32      => emit_alu(self, OperandSize::S32, 0xf7, 3, dst, 0, None)?,
                ebpf::XOR32_IMM  => emit_sanitized_alu(self, OperandSize::S32, 0x31, 6, dst, insn.imm)?,
                ebpf::XOR32_REG  => emit_alu(self, OperandSize::S32, 0x31, src, dst, 0, None)?,
                ebpf::MOV32_IMM  => {
                    if should_sanitize_constant(self, insn.imm) {
                        emit_sanitized_load_immediate(self, OperandSize::S32, dst, insn.imm)?;
                    } else {
                        X86Instruction::load_immediate(OperandSize::S32, dst, insn.imm).emit(self)?;
                    }
                }
                ebpf::MOV32_REG  => X86Instruction::mov(OperandSize::S32, src, dst).emit(self)?,
                ebpf::ARSH32_IMM => emit_shift(self, OperandSize::S32, 7, R11, dst, Some(insn.imm))?,
                ebpf::ARSH32_REG => emit_shift(self, OperandSize::S32, 7, src, dst, None)?,
                ebpf::LE         => {
                    match insn.imm {
                        16 => {
                            emit_alu(self, OperandSize::S32, 0x81, 4, dst, 0xffff, None)?; // Mask to 16 bit
                        }
                        32 => {
                            emit_alu(self, OperandSize::S32, 0x81, 4, dst, -1, None)?; // Mask to 32 bit
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
                            X86Instruction::bswap(OperandSize::S16, dst).emit(self)?;
                            emit_alu(self, OperandSize::S32, 0x81, 4, dst, 0xffff, None)?; // Mask to 16 bit
                        }
                        32 => X86Instruction::bswap(OperandSize::S32, dst).emit(self)?,
                        64 => X86Instruction::bswap(OperandSize::S64, dst).emit(self)?,
                        _ => {
                            return Err(EbpfError::InvalidInstruction(self.pc + ebpf::ELF_INSN_DUMP_OFFSET));
                        }
                    }
                },

                // BPF_ALU64 class
                ebpf::ADD64_IMM  => emit_sanitized_alu(self, OperandSize::S64, 0x01, 0, dst, insn.imm)?,
                ebpf::ADD64_REG  => emit_alu(self, OperandSize::S64, 0x01, src, dst, 0, None)?,
                ebpf::SUB64_IMM  => emit_sanitized_alu(self, OperandSize::S64, 0x29, 5, dst, insn.imm)?,
                ebpf::SUB64_REG  => emit_alu(self, OperandSize::S64, 0x29, src, dst, 0, None)?,
                ebpf::MUL64_IMM | ebpf::DIV64_IMM | ebpf::SDIV64_IMM | ebpf::MOD64_IMM  =>
                    emit_muldivmod(self, insn.opc, dst, dst, Some(insn.imm))?,
                ebpf::MUL64_REG | ebpf::DIV64_REG | ebpf::SDIV64_REG | ebpf::MOD64_REG  =>
                    emit_muldivmod(self, insn.opc, src, dst, None)?,
                ebpf::OR64_IMM   => emit_sanitized_alu(self, OperandSize::S64, 0x09, 1, dst, insn.imm)?,
                ebpf::OR64_REG   => emit_alu(self, OperandSize::S64, 0x09, src, dst, 0, None)?,
                ebpf::AND64_IMM  => emit_sanitized_alu(self, OperandSize::S64, 0x21, 4, dst, insn.imm)?,
                ebpf::AND64_REG  => emit_alu(self, OperandSize::S64, 0x21, src, dst, 0, None)?,
                ebpf::LSH64_IMM  => emit_shift(self, OperandSize::S64, 4, R11, dst, Some(insn.imm))?,
                ebpf::LSH64_REG  => emit_shift(self, OperandSize::S64, 4, src, dst, None)?,
                ebpf::RSH64_IMM  => emit_shift(self, OperandSize::S64, 5, R11, dst, Some(insn.imm))?,
                ebpf::RSH64_REG  => emit_shift(self, OperandSize::S64, 5, src, dst, None)?,
                ebpf::NEG64      => emit_alu(self, OperandSize::S64, 0xf7, 3, dst, 0, None)?,
                ebpf::XOR64_IMM  => emit_sanitized_alu(self, OperandSize::S64, 0x31, 6, dst, insn.imm)?,
                ebpf::XOR64_REG  => emit_alu(self, OperandSize::S64, 0x31, src, dst, 0, None)?,
                ebpf::MOV64_IMM  => {
                    if should_sanitize_constant(self, insn.imm) {
                        emit_sanitized_load_immediate(self, OperandSize::S64, dst, insn.imm)?;
                    } else {
                        X86Instruction::load_immediate(OperandSize::S64, dst, insn.imm).emit(self)?;
                    }
                }
                ebpf::MOV64_REG  => X86Instruction::mov(OperandSize::S64, src, dst).emit(self)?,
                ebpf::ARSH64_IMM => emit_shift(self, OperandSize::S64, 7, R11, dst, Some(insn.imm))?,
                ebpf::ARSH64_REG => emit_shift(self, OperandSize::S64, 7, src, dst, None)?,

                // BPF_JMP class
                ebpf::JA         => {
                    emit_validate_and_profile_instruction_count(self, false, Some(target_pc))?;
                    X86Instruction::load_immediate(OperandSize::S64, R11, target_pc as i64).emit(self)?;
                    emit_jmp(self, target_pc)?;
                },
                ebpf::JEQ_IMM    => emit_conditional_branch_imm(self, 0x84, false, insn.imm, dst, target_pc)?,
                ebpf::JEQ_REG    => emit_conditional_branch_reg(self, 0x84, false, src, dst, target_pc)?,
                ebpf::JGT_IMM    => emit_conditional_branch_imm(self, 0x87, false, insn.imm, dst, target_pc)?,
                ebpf::JGT_REG    => emit_conditional_branch_reg(self, 0x87, false, src, dst, target_pc)?,
                ebpf::JGE_IMM    => emit_conditional_branch_imm(self, 0x83, false, insn.imm, dst, target_pc)?,
                ebpf::JGE_REG    => emit_conditional_branch_reg(self, 0x83, false, src, dst, target_pc)?,
                ebpf::JLT_IMM    => emit_conditional_branch_imm(self, 0x82, false, insn.imm, dst, target_pc)?,
                ebpf::JLT_REG    => emit_conditional_branch_reg(self, 0x82, false, src, dst, target_pc)?,
                ebpf::JLE_IMM    => emit_conditional_branch_imm(self, 0x86, false, insn.imm, dst, target_pc)?,
                ebpf::JLE_REG    => emit_conditional_branch_reg(self, 0x86, false, src, dst, target_pc)?,
                ebpf::JSET_IMM   => emit_conditional_branch_imm(self, 0x85, true, insn.imm, dst, target_pc)?,
                ebpf::JSET_REG   => emit_conditional_branch_reg(self, 0x85, true, src, dst, target_pc)?,
                ebpf::JNE_IMM    => emit_conditional_branch_imm(self, 0x85, false, insn.imm, dst, target_pc)?,
                ebpf::JNE_REG    => emit_conditional_branch_reg(self, 0x85, false, src, dst, target_pc)?,
                ebpf::JSGT_IMM   => emit_conditional_branch_imm(self, 0x8f, false, insn.imm, dst, target_pc)?,
                ebpf::JSGT_REG   => emit_conditional_branch_reg(self, 0x8f, false, src, dst, target_pc)?,
                ebpf::JSGE_IMM   => emit_conditional_branch_imm(self, 0x8d, false, insn.imm, dst, target_pc)?,
                ebpf::JSGE_REG   => emit_conditional_branch_reg(self, 0x8d, false, src, dst, target_pc)?,
                ebpf::JSLT_IMM   => emit_conditional_branch_imm(self, 0x8c, false, insn.imm, dst, target_pc)?,
                ebpf::JSLT_REG   => emit_conditional_branch_reg(self, 0x8c, false, src, dst, target_pc)?,
                ebpf::JSLE_IMM   => emit_conditional_branch_imm(self, 0x8e, false, insn.imm, dst, target_pc)?,
                ebpf::JSLE_REG   => emit_conditional_branch_reg(self, 0x8e, false, src, dst, target_pc)?,
                ebpf::CALL_IMM   => {
                    // For JIT, syscalls MUST be registered at compile time. They can be
                    // updated later, but not created after compiling (we need the address of the
                    // syscall function in the JIT-compiled program).

                    let mut resolved = false;
                    let (syscalls, calls) = if self.config.static_syscalls {
                        (insn.src == 0, insn.src != 0)
                    } else {
                        (true, true)
                    };

                    if syscalls {
                        if let Some(syscall) = executable.get_syscall_registry().lookup_syscall(insn.imm as u32) {
                            if self.config.enable_instruction_meter {
                                emit_validate_and_profile_instruction_count(self, true, Some(0))?;
                            }
                            X86Instruction::load_immediate(OperandSize::S64, R11, syscall.function as *const u8 as i64).emit(self)?;
                            X86Instruction::load(OperandSize::S64, R10, RAX, X86IndirectAccess::Offset((SYSCALL_CONTEXT_OBJECTS_OFFSET + syscall.context_object_slot) as i32 * 8 + self.program_argument_key)).emit(self)?;
                            emit_call(self, TARGET_PC_SYSCALL)?;
                            if self.config.enable_instruction_meter {
                                emit_undo_profile_instruction_count(self, 0)?;
                            }
                            // Throw error if the result indicates one
                            X86Instruction::cmp_immediate(OperandSize::S64, R11, 0, Some(X86IndirectAccess::Offset(0))).emit(self)?;
                            X86Instruction::load_immediate(OperandSize::S64, R11, self.pc as i64).emit(self)?;
                            emit_jcc(self, 0x85, TARGET_PC_RUST_EXCEPTION)?;

                            resolved = true;
                        }
                    }

                    if calls {
                        if let Some(target_pc) = executable.lookup_bpf_function(insn.imm as u32) {
                            emit_bpf_call(self, Value::Constant64(target_pc as i64, false))?;
                            resolved = true;
                        }
                    }

                    if !resolved {
                        if self.config.disable_unresolved_symbols_at_runtime {
                            X86Instruction::load_immediate(OperandSize::S64, R11, self.pc as i64).emit(self)?;
                            emit_jmp(self, TARGET_PC_CALL_UNSUPPORTED_INSTRUCTION)?;
                        } else {
                            emit_validate_instruction_count(self, true, Some(self.pc))?;
                            // executable.report_unresolved_symbol(self.pc)?;
                            // Workaround for unresolved symbols in ELF: Report error at runtime instead of compiletime
                            emit_rust_call(self, Value::Constant64(Executable::<E, I>::report_unresolved_symbol as *const u8 as i64, false), &[
                                Argument { index: 2, value: Value::Constant64(self.pc as i64, false) },
                                Argument { index: 1, value: Value::Constant64(&*executable.as_ref() as *const _ as i64, false) },
                                Argument { index: 0, value: Value::RegisterIndirect(RBP, slot_on_environment_stack(self, EnvironmentStackSlot::OptRetValPtr), false) },
                            ], None, true)?;
                            X86Instruction::load_immediate(OperandSize::S64, R11, self.pc as i64).emit(self)?;
                            emit_jmp(self, TARGET_PC_RUST_EXCEPTION)?;
                        }
                    }
                },
                ebpf::CALL_REG  => {
                    emit_bpf_call(self, Value::Register(REGISTER_MAP[insn.imm as usize]))?;
                },
                ebpf::EXIT      => {
                    let call_depth_access = X86IndirectAccess::Offset(slot_on_environment_stack(self, EnvironmentStackSlot::CallDepth));
                    X86Instruction::load(OperandSize::S64, RBP, REGISTER_MAP[FRAME_PTR_REG], call_depth_access).emit(self)?;

                    // If CallDepth == 0, we've reached the exit instruction of the entry point
                    X86Instruction::cmp_immediate(OperandSize::S32, REGISTER_MAP[FRAME_PTR_REG], 0, None).emit(self)?;
                    if self.config.enable_instruction_meter {
                        X86Instruction::load_immediate(OperandSize::S64, R11, self.pc as i64).emit(self)?;
                    }
                    // we're done
                    emit_jcc(self, 0x84, TARGET_PC_EXIT)?;

                    // else decrement and update CallDepth
                    emit_alu(self, OperandSize::S64, 0x81, 5, REGISTER_MAP[FRAME_PTR_REG], 1, None)?;
                    X86Instruction::store(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], RBP, call_depth_access).emit(self)?;

                    // and return
                    emit_validate_and_profile_instruction_count(self, false, Some(0))?;
                    X86Instruction::return_near().emit(self)?;
                },

                _               => return Err(EbpfError::UnsupportedInstruction(self.pc + ebpf::ELF_INSN_DUMP_OFFSET)),
            }

            self.pc += 1;
        }
        self.result.pc_section[self.pc] = self.offset_in_text_section as u64; // Bumper so that the linear search of TARGET_PC_TRANSLATE_PC can not run off

        // Bumper in case there was no final exit
        emit_validate_and_profile_instruction_count(self, true, Some(self.pc + 2))?;
        X86Instruction::load_immediate(OperandSize::S64, R11, self.pc as i64).emit(self)?;
        emit_set_exception_kind::<E>(self, EbpfError::ExecutionOverrun(0))?;
        emit_jmp(self, TARGET_PC_EXCEPTION_AT)?;

        self.generate_epilogue::<E>()?;
        self.resolve_jumps();
        self.result.seal(self.offset_in_text_section)?;

        // Delete secrets
        self.environment_stack_key = 0;
        self.program_argument_key = 0;

        Ok(())
    }

    fn generate_helper_routines<E: UserDefinedError, I: InstructionMeter>(&mut self) -> Result<(), EbpfError<E>> {
        // Routine for instruction tracing
        if self.config.enable_instruction_tracing {
            set_anchor(self, TARGET_PC_TRACE);
            // Save registers on stack
            X86Instruction::push(R11, None).emit(self)?;
            for reg in REGISTER_MAP.iter().rev() {
                X86Instruction::push(*reg, None).emit(self)?;
            }
            X86Instruction::mov(OperandSize::S64, RSP, REGISTER_MAP[0]).emit(self)?;
            emit_alu(self, OperandSize::S64, 0x81, 0, RSP, - 8 * 3, None)?; // RSP -= 8 * 3;
            emit_rust_call(self, Value::Constant64(Tracer::trace as *const u8 as i64, false), &[
                Argument { index: 1, value: Value::Register(REGISTER_MAP[0]) }, // registers
                Argument { index: 0, value: Value::RegisterIndirect(R10, mem::size_of::<MemoryMapping>() as i32 + self.program_argument_key, false) }, // jit.tracer
            ], None, false)?;
            // Pop stack and return
            emit_alu(self, OperandSize::S64, 0x81, 0, RSP, 8 * 3, None)?; // RSP += 8 * 3;
            X86Instruction::pop(REGISTER_MAP[0]).emit(self)?;
            emit_alu(self, OperandSize::S64, 0x81, 0, RSP, 8 * (REGISTER_MAP.len() - 1) as i64, None)?; // RSP += 8 * (REGISTER_MAP.len() - 1);
            X86Instruction::pop(R11).emit(self)?;
            X86Instruction::return_near().emit(self)?;
        }

        // Routine for syscall
        set_anchor(self, TARGET_PC_SYSCALL);
        X86Instruction::push(R11, None).emit(self)?; // Padding for stack alignment
        if self.config.enable_instruction_meter {
            // RDI = *PrevInsnMeter - RDI;
            emit_alu(self, OperandSize::S64, 0x2B, ARGUMENT_REGISTERS[0], RBP, 0, Some(X86IndirectAccess::Offset(slot_on_environment_stack(self, EnvironmentStackSlot::PrevInsnMeter))))?; // RDI -= *PrevInsnMeter;
            emit_alu(self, OperandSize::S64, 0xf7, 3, ARGUMENT_REGISTERS[0], 0, None)?; // RDI = -RDI;
            emit_rust_call(self, Value::Constant64(I::consume as *const u8 as i64, false), &[
                Argument { index: 1, value: Value::Register(ARGUMENT_REGISTERS[0]) },
                Argument { index: 0, value: Value::RegisterIndirect(RBP, slot_on_environment_stack(self, EnvironmentStackSlot::InsnMeterPtr), false) },
            ], None, false)?;
        }
        emit_rust_call(self, Value::Register(R11), &[
            Argument { index: 7, value: Value::RegisterIndirect(RBP, slot_on_environment_stack(self, EnvironmentStackSlot::OptRetValPtr), false) },
            Argument { index: 6, value: Value::RegisterPlusConstant32(R10, self.program_argument_key, false) }, // jit_program_argument.memory_mapping
            Argument { index: 5, value: Value::Register(ARGUMENT_REGISTERS[5]) },
            Argument { index: 4, value: Value::Register(ARGUMENT_REGISTERS[4]) },
            Argument { index: 3, value: Value::Register(ARGUMENT_REGISTERS[3]) },
            Argument { index: 2, value: Value::Register(ARGUMENT_REGISTERS[2]) },
            Argument { index: 1, value: Value::Register(ARGUMENT_REGISTERS[1]) },
            Argument { index: 0, value: Value::Register(RAX) }, // "&mut self" in the "call" method of the SyscallObject
        ], None, false)?;
        if self.config.enable_instruction_meter {
            emit_rust_call(self, Value::Constant64(I::get_remaining as *const u8 as i64, false), &[
                Argument { index: 0, value: Value::RegisterIndirect(RBP, slot_on_environment_stack(self, EnvironmentStackSlot::InsnMeterPtr), false) },
            ], Some(ARGUMENT_REGISTERS[0]), false)?;
            X86Instruction::store(OperandSize::S64, ARGUMENT_REGISTERS[0], RBP, X86IndirectAccess::Offset(slot_on_environment_stack(self, EnvironmentStackSlot::PrevInsnMeter))).emit(self)?;
        }
        X86Instruction::pop(R11).emit(self)?;
        // Store Ok value in result register
        X86Instruction::load(OperandSize::S64, RBP, R11, X86IndirectAccess::Offset(slot_on_environment_stack(self, EnvironmentStackSlot::OptRetValPtr))).emit(self)?;
        X86Instruction::load(OperandSize::S64, R11, REGISTER_MAP[0], X86IndirectAccess::Offset(8)).emit(self)?;
        X86Instruction::return_near().emit(self)?;

        // Routine for prologue of emit_bpf_call()
        set_anchor(self, TARGET_PC_BPF_CALL_PROLOGUE);
        emit_alu(self, OperandSize::S64, 0x81, 5, RSP, 8 * (SCRATCH_REGS + 1) as i64, None)?; // alloca
        X86Instruction::store(OperandSize::S64, R11, RSP, X86IndirectAccess::OffsetIndexShift(0, RSP, 0)).emit(self)?; // Save original R11
        X86Instruction::load(OperandSize::S64, RSP, R11, X86IndirectAccess::OffsetIndexShift(8 * (SCRATCH_REGS + 1) as i32, RSP, 0)).emit(self)?; // Load return address
        for (i, reg) in REGISTER_MAP.iter().skip(FIRST_SCRATCH_REG).take(SCRATCH_REGS).enumerate() {
            X86Instruction::store(OperandSize::S64, *reg, RSP, X86IndirectAccess::OffsetIndexShift(8 * (SCRATCH_REGS - i + 1) as i32, RSP, 0)).emit(self)?; // Push SCRATCH_REG
        }
        // Push the caller's frame pointer. The code to restore it is emitted at the end of emit_bpf_call().
        X86Instruction::store(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], RSP, X86IndirectAccess::OffsetIndexShift(8, RSP, 0)).emit(self)?;
        X86Instruction::xchg(OperandSize::S64, R11, RSP, Some(X86IndirectAccess::OffsetIndexShift(0, RSP, 0))).emit(self)?; // Push return address and restore original R11

        // Increase CallDepth
        let call_depth_access = X86IndirectAccess::Offset(slot_on_environment_stack(self, EnvironmentStackSlot::CallDepth));
        emit_alu(self, OperandSize::S64, 0x81, 0, RBP, 1, Some(call_depth_access))?;
        X86Instruction::load(OperandSize::S64, RBP, REGISTER_MAP[FRAME_PTR_REG], call_depth_access).emit(self)?;
        // If CallDepth == self.config.max_call_depth, stop and return CallDepthExceeded
        X86Instruction::cmp_immediate(OperandSize::S32, REGISTER_MAP[FRAME_PTR_REG], self.config.max_call_depth as i64, None).emit(self)?;
        emit_jcc(self, 0x83, TARGET_PC_CALL_DEPTH_EXCEEDED)?;

        // Setup the frame pointer for the new frame. What we do depends on whether we're using dynamic or fixed frames.
        let frame_ptr_access = X86IndirectAccess::Offset(slot_on_environment_stack(self, EnvironmentStackSlot::BpfFramePtr));
        if self.config.dynamic_stack_frames {
            // When dynamic frames are on, the next frame starts at the end of the current frame
            let stack_ptr_access = X86IndirectAccess::Offset(slot_on_environment_stack(self, EnvironmentStackSlot::BpfStackPtr));
            X86Instruction::load(OperandSize::S64, RBP, REGISTER_MAP[FRAME_PTR_REG], stack_ptr_access).emit(self)?;
            X86Instruction::store(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], RBP, frame_ptr_access).emit(self)?;
        } else {
            // With fixed frames we start the new frame at the next fixed offset
            let stack_frame_size = self.config.stack_frame_size as i64 * if self.config.enable_stack_frame_gaps { 2 } else { 1 };
            emit_alu(self, OperandSize::S64, 0x81, 0, RBP, stack_frame_size, Some(frame_ptr_access))?; // frame_ptr += stack_frame_size;
            X86Instruction::load(OperandSize::S64, RBP, REGISTER_MAP[FRAME_PTR_REG], frame_ptr_access).emit(self)?; // Load BpfFramePtr
        }
        X86Instruction::return_near().emit(self)?;

        // Routine for emit_bpf_call(Value::Register())
        set_anchor(self, TARGET_PC_BPF_CALL_REG);
        // Force alignment of RAX
        emit_alu(self, OperandSize::S64, 0x81, 4, REGISTER_MAP[0], !(INSN_SIZE as i64 - 1), None)?; // RAX &= !(INSN_SIZE - 1);
        // Upper bound check
        // if(RAX >= self.program_vm_addr + number_of_instructions * INSN_SIZE) throw CALL_OUTSIDE_TEXT_SEGMENT;
        let number_of_instructions = self.result.pc_section.len() - 1;
        X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], self.program_vm_addr as i64 + (number_of_instructions * INSN_SIZE) as i64).emit(self)?;
        X86Instruction::cmp(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], REGISTER_MAP[0], None).emit(self)?;
        emit_jcc(self, 0x83, TARGET_PC_CALL_OUTSIDE_TEXT_SEGMENT)?;
        // Lower bound check
        // if(RAX < self.program_vm_addr) throw CALL_OUTSIDE_TEXT_SEGMENT;
        X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], self.program_vm_addr as i64).emit(self)?;
        X86Instruction::cmp(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], REGISTER_MAP[0], None).emit(self)?;
        emit_jcc(self, 0x82, TARGET_PC_CALL_OUTSIDE_TEXT_SEGMENT)?;
        // Calculate offset relative to instruction_addresses
        emit_alu(self, OperandSize::S64, 0x29, REGISTER_MAP[FRAME_PTR_REG], REGISTER_MAP[0], 0, None)?; // RAX -= self.program_vm_addr;
        // Calculate the target_pc (dst / INSN_SIZE) to update the instruction_meter
        let shift_amount = INSN_SIZE.trailing_zeros();
        debug_assert_eq!(INSN_SIZE, 1 << shift_amount);
        X86Instruction::mov(OperandSize::S64, REGISTER_MAP[0], R11).emit(self)?;
        emit_alu(self, OperandSize::S64, 0xc1, 5, R11, shift_amount as i64, None)?;
        // Save BPF target pc for potential TARGET_PC_CALLX_UNSUPPORTED_INSTRUCTION
        X86Instruction::store(OperandSize::S64, R11, RSP, X86IndirectAccess::OffsetIndexShift(-8, RSP, 0)).emit(self)?; // RSP[-8] = R11;
        // Load host target_address from self.result.pc_section
        debug_assert_eq!(INSN_SIZE, 8); // Because the instruction size is also the slot size we do not need to shift the offset
        X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], self.result.pc_section.as_ptr() as i64).emit(self)?;
        emit_alu(self, OperandSize::S64, 0x01, REGISTER_MAP[FRAME_PTR_REG], REGISTER_MAP[0], 0, None)?; // RAX += self.result.pc_section;
        X86Instruction::load(OperandSize::S64, REGISTER_MAP[0], REGISTER_MAP[0], X86IndirectAccess::Offset(0)).emit(self)?; // RAX = self.result.pc_section[RAX / 8];
        // Load the frame pointer again since we've clobbered REGISTER_MAP[FRAME_PTR_REG]
        X86Instruction::load(OperandSize::S64, RBP, REGISTER_MAP[FRAME_PTR_REG], X86IndirectAccess::Offset(slot_on_environment_stack(self, EnvironmentStackSlot::BpfFramePtr))).emit(self)?;
        X86Instruction::return_near().emit(self)?;

        // Translates a host pc back to a BPF pc by linear search of the pc_section table
        set_anchor(self, TARGET_PC_TRANSLATE_PC);
        X86Instruction::push(REGISTER_MAP[0], None).emit(self)?; // Save REGISTER_MAP[0]
        X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[0], self.result.pc_section.as_ptr() as i64 - 8).emit(self)?; // Loop index and pointer to look up
        set_anchor(self, TARGET_PC_TRANSLATE_PC_LOOP); // Loop label
        emit_alu(self, OperandSize::S64, 0x81, 0, REGISTER_MAP[0], 8, None)?; // Increase index
        X86Instruction::cmp(OperandSize::S64, R11, REGISTER_MAP[0], Some(X86IndirectAccess::Offset(8))).emit(self)?; // Look up and compare against value at next index
        emit_jcc(self, 0x86, TARGET_PC_TRANSLATE_PC_LOOP)?; // Continue while *REGISTER_MAP[0] <= R11
        X86Instruction::mov(OperandSize::S64, REGISTER_MAP[0], R11).emit(self)?; // R11 = REGISTER_MAP[0];
        X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[0], self.result.pc_section.as_ptr() as i64).emit(self)?; // REGISTER_MAP[0] = self.result.pc_section;
        emit_alu(self, OperandSize::S64, 0x29, REGISTER_MAP[0], R11, 0, None)?; // R11 -= REGISTER_MAP[0];
        emit_alu(self, OperandSize::S64, 0xc1, 5, R11, 3, None)?; // R11 >>= 3;
        X86Instruction::pop(REGISTER_MAP[0]).emit(self)?; // Restore REGISTER_MAP[0]
        X86Instruction::return_near().emit(self)?;

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

            set_anchor(self, TARGET_PC_TRANSLATE_MEMORY_ADDRESS + target_offset);
            X86Instruction::push(R11, None).emit(self)?;
            X86Instruction::push(RAX, None).emit(self)?;
            X86Instruction::push(RCX, None).emit(self)?;
            let stack_offset = if !self.config.dynamic_stack_frames && self.config.enable_stack_frame_gaps {
                X86Instruction::push(RDX, None).emit(self)?;
                24
            } else {
                16
            };
            X86Instruction::mov(OperandSize::S64, R11, RAX).emit(self)?; // RAX = vm_addr;
            emit_alu(self, OperandSize::S64, 0xc1, 5, RAX, ebpf::VIRTUAL_ADDRESS_BITS as i64, None)?; // RAX >>= ebpf::VIRTUAL_ADDRESS_BITS;
            X86Instruction::cmp(OperandSize::S64, RAX, R10, Some(X86IndirectAccess::Offset(self.program_argument_key + 8))).emit(self)?; // region_index >= jit_program_argument.memory_mapping.regions.len()
            emit_jcc(self, 0x86, TARGET_PC_MEMORY_ACCESS_VIOLATION + target_offset)?;
            debug_assert_eq!(1 << 5, mem::size_of::<MemoryRegion>());
            emit_alu(self, OperandSize::S64, 0xc1, 4, RAX, 5, None)?; // RAX *= mem::size_of::<MemoryRegion>();
            emit_alu(self, OperandSize::S64, 0x03, RAX, R10, 0, Some(X86IndirectAccess::Offset(self.program_argument_key)))?; // region = &jit_program_argument.memory_mapping.regions[region_index];
            if *access_type == AccessType::Store {
                X86Instruction::cmp_immediate(OperandSize::S8, RAX, 0, Some(X86IndirectAccess::Offset(MemoryRegion::IS_WRITABLE_OFFSET))).emit(self)?; // region.is_writable == 0
                emit_jcc(self, 0x84, TARGET_PC_MEMORY_ACCESS_VIOLATION + target_offset)?;
            }
            X86Instruction::load(OperandSize::S64, RAX, RCX, X86IndirectAccess::Offset(MemoryRegion::VM_ADDR_OFFSET)).emit(self)?; // RCX = region.vm_addr
            X86Instruction::cmp(OperandSize::S64, RCX, R11, None).emit(self)?; // vm_addr < region.vm_addr
            emit_jcc(self, 0x82, TARGET_PC_MEMORY_ACCESS_VIOLATION + target_offset)?;
            emit_alu(self, OperandSize::S64, 0x29, RCX, R11, 0, None)?; // vm_addr -= region.vm_addr
            if !self.config.dynamic_stack_frames && self.config.enable_stack_frame_gaps {
                X86Instruction::load(OperandSize::S8, RAX, RCX, X86IndirectAccess::Offset(MemoryRegion::VM_GAP_SHIFT_OFFSET)).emit(self)?; // RCX = region.vm_gap_shift;
                X86Instruction::mov(OperandSize::S64, R11, RDX).emit(self)?; // RDX = R11;
                emit_alu(self, OperandSize::S64, 0xd3, 5, RDX, 0, None)?; // RDX = R11 >> region.vm_gap_shift;
                X86Instruction::test_immediate(OperandSize::S64, RDX, 1, None).emit(self)?; // (RDX & 1) != 0
                emit_jcc(self, 0x85, TARGET_PC_MEMORY_ACCESS_VIOLATION + target_offset)?;
                X86Instruction::load_immediate(OperandSize::S64, RDX, -1).emit(self)?; // RDX = -1;
                emit_alu(self, OperandSize::S64, 0xd3, 4, RDX, 0, None)?; // gap_mask = -1 << region.vm_gap_shift;
                X86Instruction::mov(OperandSize::S64, RDX, RCX).emit(self)?; // RCX = RDX;
                emit_alu(self, OperandSize::S64, 0xf7, 2, RCX, 0, None)?; // inverse_gap_mask = !gap_mask;
                emit_alu(self, OperandSize::S64, 0x21, R11, RCX, 0, None)?; // below_gap = R11 & inverse_gap_mask;
                emit_alu(self, OperandSize::S64, 0x21, RDX, R11, 0, None)?; // above_gap = R11 & gap_mask;
                emit_alu(self, OperandSize::S64, 0xc1, 5, R11, 1, None)?; // above_gap >>= 1;
                emit_alu(self, OperandSize::S64, 0x09, RCX, R11, 0, None)?; // gapped_offset = above_gap | below_gap;
            }
            X86Instruction::lea(OperandSize::S64, R11, RCX, Some(X86IndirectAccess::Offset(*len))).emit(self)?; // RCX = R11 + len;
            X86Instruction::cmp(OperandSize::S64, RCX, RAX, Some(X86IndirectAccess::Offset(MemoryRegion::LEN_OFFSET))).emit(self)?; // region.len < R11 + len
            emit_jcc(self, 0x82, TARGET_PC_MEMORY_ACCESS_VIOLATION + target_offset)?;
            emit_alu(self, OperandSize::S64, 0x03, R11, RAX, 0, Some(X86IndirectAccess::Offset(MemoryRegion::HOST_ADDR_OFFSET)))?; // R11 += region.host_addr;
            if !self.config.dynamic_stack_frames && self.config.enable_stack_frame_gaps {
                X86Instruction::pop(RDX).emit(self)?;
            }
            X86Instruction::pop(RCX).emit(self)?;
            X86Instruction::pop(RAX).emit(self)?;
            emit_alu(self, OperandSize::S64, 0x81, 0, RSP, 8, None)?;
            X86Instruction::return_near().emit(self)?;

            set_anchor(self, TARGET_PC_MEMORY_ACCESS_VIOLATION + target_offset);
            emit_alu(self, OperandSize::S64, 0x31, R11, R11, 0, None)?; // R11 = 0;
            X86Instruction::load(OperandSize::S64, RSP, R11, X86IndirectAccess::OffsetIndexShift(stack_offset, R11, 0)).emit(self)?;
            emit_rust_call(self, Value::Constant64(MemoryMapping::generate_access_violation::<UserError> as *const u8 as i64, false), &[
                Argument { index: 3, value: Value::Register(R11) }, // Specify first as the src register could be overwritten by other arguments
                Argument { index: 4, value: Value::Constant64(*len as i64, false) },
                Argument { index: 2, value: Value::Constant64(*access_type as i64, false) },
                Argument { index: 1, value: Value::RegisterPlusConstant32(R10, self.program_argument_key, false) }, // jit_program_argument.memory_mapping
                Argument { index: 0, value: Value::RegisterIndirect(RBP, slot_on_environment_stack(self, EnvironmentStackSlot::OptRetValPtr), false) }, // Pointer to optional typed return value
            ], None, true)?;
            emit_alu(self, OperandSize::S64, 0x81, 0, RSP, stack_offset as i64 + 8, None)?; // Drop R11, RAX, RCX, RDX from stack
            X86Instruction::pop(R11).emit(self)?; // Put callers PC in R11
            emit_call(self, TARGET_PC_TRANSLATE_PC)?;
            emit_jmp(self, TARGET_PC_EXCEPTION_AT)?;
        }
        Ok(())
    }

    fn generate_exception_handlers<E: UserDefinedError>(&mut self) -> Result<(), EbpfError<E>> {
        // Handler for EbpfError::ExceededMaxInstructions
        set_anchor(self, TARGET_PC_CALL_EXCEEDED_MAX_INSTRUCTIONS);
        emit_set_exception_kind::<E>(self, EbpfError::ExceededMaxInstructions(0, 0))?;
        X86Instruction::mov(OperandSize::S64, ARGUMENT_REGISTERS[0], R11).emit(self)?; // R11 = instruction_meter;
        emit_profile_instruction_count_finalize(self, true)?;
        emit_jmp(self, TARGET_PC_EPILOGUE)?;

        // Handler for EbpfError::CallDepthExceeded
        set_anchor(self, TARGET_PC_CALL_DEPTH_EXCEEDED);
        emit_set_exception_kind::<E>(self, EbpfError::CallDepthExceeded(0, 0))?;
        X86Instruction::store_immediate(OperandSize::S64, R10, X86IndirectAccess::Offset(24), self.config.max_call_depth as i64).emit(self)?; // depth = jit.config.max_call_depth;
        emit_jmp(self, TARGET_PC_EXCEPTION_AT)?;

        // Handler for EbpfError::CallOutsideTextSegment
        set_anchor(self, TARGET_PC_CALL_OUTSIDE_TEXT_SEGMENT);
        emit_set_exception_kind::<E>(self, EbpfError::CallOutsideTextSegment(0, 0))?;
        X86Instruction::store(OperandSize::S64, REGISTER_MAP[0], R10, X86IndirectAccess::Offset(24)).emit(self)?; // target_address = RAX;
        emit_jmp(self, TARGET_PC_EXCEPTION_AT)?;

        // Handler for EbpfError::DivideByZero
        set_anchor(self, TARGET_PC_DIV_BY_ZERO);
        emit_set_exception_kind::<E>(self, EbpfError::DivideByZero(0))?;
        emit_jmp(self, TARGET_PC_EXCEPTION_AT)?;

        // Handler for EbpfError::DivideOverflow
        set_anchor(self, TARGET_PC_DIV_OVERFLOW);
        emit_set_exception_kind::<E>(self, EbpfError::DivideOverflow(0))?;
        emit_jmp(self, TARGET_PC_EXCEPTION_AT)?;

        // Handler for EbpfError::UnsupportedInstruction
        set_anchor(self, TARGET_PC_CALLX_UNSUPPORTED_INSTRUCTION);
        // Load BPF target pc from stack (which was saved in TARGET_PC_BPF_CALL_REG)
        X86Instruction::load(OperandSize::S64, RSP, R11, X86IndirectAccess::OffsetIndexShift(-16, RSP, 0)).emit(self)?; // R11 = RSP[-16];
        // emit_jmp(self, TARGET_PC_CALL_UNSUPPORTED_INSTRUCTION)?; // Fall-through

        // Handler for EbpfError::UnsupportedInstruction
        set_anchor(self, TARGET_PC_CALL_UNSUPPORTED_INSTRUCTION);
        if self.config.enable_instruction_tracing {
            emit_call(self, TARGET_PC_TRACE)?;
        }
        emit_set_exception_kind::<E>(self, EbpfError::UnsupportedInstruction(0))?;
        // emit_jmp(self, TARGET_PC_EXCEPTION_AT)?; // Fall-through

        // Handler for exceptions which report their pc
        set_anchor(self, TARGET_PC_EXCEPTION_AT);
        // Validate that we did not reach the instruction meter limit before the exception occured
        if self.config.enable_instruction_meter {
            emit_validate_instruction_count(self, false, None)?;
        }
        emit_profile_instruction_count_finalize(self, true)?;
        emit_jmp(self, TARGET_PC_EPILOGUE)?;

        // Handler for syscall exceptions
        set_anchor(self, TARGET_PC_RUST_EXCEPTION);
        emit_profile_instruction_count_finalize(self, false)?;
        emit_jmp(self, TARGET_PC_EPILOGUE)
    }

    fn generate_prologue<E: UserDefinedError, I: InstructionMeter>(&mut self) -> Result<(), EbpfError<E>> {
        // Place the environment on the stack according to EnvironmentStackSlot

        // Save registers
        for reg in CALLEE_SAVED_REGISTERS.iter() {
            X86Instruction::push(*reg, None).emit(self)?;
        }

        // Initialize CallDepth to 0
        X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], 0).emit(self)?;
        X86Instruction::push(REGISTER_MAP[FRAME_PTR_REG], None).emit(self)?;

        // Initialize the BPF frame and stack pointers (BpfFramePtr and BpfStackPtr)
        if self.config.dynamic_stack_frames {
            // The stack is fully descending from MM_STACK_START + stack_size to MM_STACK_START
            X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], MM_STACK_START as i64 + self.config.stack_size() as i64).emit(self)?;
            // Push BpfFramePtr
            X86Instruction::push(REGISTER_MAP[FRAME_PTR_REG], None).emit(self)?;
            // Push BpfStackPtr
            X86Instruction::push(REGISTER_MAP[FRAME_PTR_REG], None).emit(self)?;
        } else {
            // The frames are ascending from MM_STACK_START to MM_STACK_START + stack_size. The stack within the frames is descending.
            X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], MM_STACK_START as i64 + self.config.stack_frame_size as i64).emit(self)?;
            // Push BpfFramePtr
            X86Instruction::push(REGISTER_MAP[FRAME_PTR_REG], None).emit(self)?;
            // When using static frames BpfStackPtr is not used
            X86Instruction::load_immediate(OperandSize::S64, RBP, 0).emit(self)?;
            X86Instruction::push(RBP, None).emit(self)?;
        }

        // Save pointer to optional typed return value
        X86Instruction::push(ARGUMENT_REGISTERS[0], None).emit(self)?;

        // Save initial value of instruction_meter.get_remaining()
        emit_rust_call(self, Value::Constant64(I::get_remaining as *const u8 as i64, false), &[
            Argument { index: 0, value: Value::Register(ARGUMENT_REGISTERS[3]) },
        ], Some(ARGUMENT_REGISTERS[0]), false)?;
        X86Instruction::push(ARGUMENT_REGISTERS[0], None).emit(self)?;

        // Save instruction meter
        X86Instruction::push(ARGUMENT_REGISTERS[3], None).emit(self)?;

        // Initialize stop watch
        emit_alu(self, OperandSize::S64, 0x31, R11, R11, 0, None)?; // R11 ^= R11;
        X86Instruction::push(R11, None).emit(self)?;
        X86Instruction::push(R11, None).emit(self)?;

        // Initialize frame pointer
        X86Instruction::mov(OperandSize::S64, RSP, RBP).emit(self)?;
        emit_alu(self, OperandSize::S64, 0x81, 0, RBP, 8 * (EnvironmentStackSlot::SlotCount as i64 - 1 + self.environment_stack_key as i64), None)?;

        // Save JitProgramArgument
        X86Instruction::lea(OperandSize::S64, ARGUMENT_REGISTERS[2], R10, Some(X86IndirectAccess::Offset(-self.program_argument_key))).emit(self)?;

        // Zero BPF registers
        for reg in REGISTER_MAP.iter() {
            if *reg != REGISTER_MAP[1] && *reg != REGISTER_MAP[FRAME_PTR_REG] {
                X86Instruction::load_immediate(OperandSize::S64, *reg, 0).emit(self)?;
            }
        }

        Ok(())
    }

    fn generate_epilogue<E: UserDefinedError>(&mut self) -> Result<(), EbpfError<E>> {
        // Quit gracefully
        set_anchor(self, TARGET_PC_EXIT);
        emit_validate_instruction_count(self, false, None)?;
        emit_profile_instruction_count_finalize(self, false)?;

        X86Instruction::load(OperandSize::S64, RBP, R10, X86IndirectAccess::Offset(slot_on_environment_stack(self, EnvironmentStackSlot::OptRetValPtr))).emit(self)?;
        X86Instruction::store(OperandSize::S64, REGISTER_MAP[0], R10, X86IndirectAccess::Offset(8)).emit(self)?; // result.return_value = R0;
        X86Instruction::load_immediate(OperandSize::S64, REGISTER_MAP[0], 0).emit(self)?;
        X86Instruction::store(OperandSize::S64, REGISTER_MAP[0], R10, X86IndirectAccess::Offset(0)).emit(self)?;  // result.is_error = false;

        // Epilogue
        set_anchor(self, TARGET_PC_EPILOGUE);

        // Print stop watch value
        fn stopwatch_result(numerator: u64, denominator: u64) {
            println!("Stop watch: {} / {} = {}", numerator, denominator, if denominator == 0 { 0.0 } else { numerator as f64 / denominator as f64 });
        }
        if self.stopwatch_is_active {
            emit_rust_call(self, Value::Constant64(stopwatch_result as *const u8 as i64, false), &[
                Argument { index: 1, value: Value::RegisterIndirect(RBP, slot_on_environment_stack(self, EnvironmentStackSlot::StopwatchDenominator), false) },
                Argument { index: 0, value: Value::RegisterIndirect(RBP, slot_on_environment_stack(self, EnvironmentStackSlot::StopwatchNumerator), false) },
            ], None, false)?;
        }

        // Store instruction_meter in RAX
        X86Instruction::mov(OperandSize::S64, ARGUMENT_REGISTERS[0], RAX).emit(self)?;

        // Restore stack pointer in case the BPF stack was used
        X86Instruction::lea(OperandSize::S64, RBP, RSP, Some(X86IndirectAccess::Offset(slot_on_environment_stack(self, EnvironmentStackSlot::LastSavedRegister)))).emit(self)?;

        // Restore registers
        for reg in CALLEE_SAVED_REGISTERS.iter().rev() {
            X86Instruction::pop(*reg).emit(self)?;
        }

        X86Instruction::return_near().emit(self)
    }

    pub fn emit_random_noop<E: UserDefinedError>(&mut self) -> Result<(), EbpfError<E>> {
        if self.config.noop_instruction_ratio != 0.0 && self.diversification_rng.gen_bool(self.config.noop_instruction_ratio) {
            // X86Instruction::noop().emit(self)
            emit::<u8, E>(self, 0x90)
        } else {
            Ok(())
        }
    }

    fn resolve_jumps(&mut self) {
        for jump in &self.pc_section_jumps {
            self.result.pc_section[jump.location] = jump.get_target_offset(self);
        }
        for jump in &self.text_section_jumps {
            let offset_value = jump.get_target_offset(self) as i32
                - jump.location as i32 // Relative jump
                - mem::size_of::<i32>() as i32; // Jump from end of instruction
            unsafe {
                ptr::write_unaligned(
                    self.result.text_section.as_ptr().add(jump.location) as *mut i32,
                    offset_value,
                );
            }
        }
        let call_unsupported_instruction = self.handler_anchors.get(&TARGET_PC_CALL_UNSUPPORTED_INSTRUCTION).unwrap();
        let callx_unsupported_instruction = self.handler_anchors.get(&TARGET_PC_CALLX_UNSUPPORTED_INSTRUCTION).unwrap();
        for offset in self.result.pc_section.iter_mut() {
            if *offset == *call_unsupported_instruction as u64 {
                // Turns compiletime exception handlers to runtime ones (as they need to turn the host PC back into a BPF PC)
                *offset = *callx_unsupported_instruction as u64;
            }
            *offset = unsafe { (self.result.text_section.as_ptr() as *const u8).add(*offset as usize) } as u64;
        }
    }
}

#[cfg(all(test, target_arch = "x86_64", not(target_os = "windows")))]
mod tests {
    use super::*;
    use crate::{syscalls, vm::{SyscallRegistry, SyscallObject, TestInstructionMeter}, elf::register_bpf_function};
    use std::collections::BTreeMap;
    use byteorder::{LittleEndian, ByteOrder};

    fn create_mockup_executable(program: &[u8]) -> Pin<Box<Executable::<UserError, TestInstructionMeter>>> {
        let config = Config {
            noop_instruction_ratio: 0.0,
            ..Config::default()
        };
        let mut syscall_registry = SyscallRegistry::default();
        syscall_registry
            .register_syscall_by_hash(
                0xFFFFFFFF,
                syscalls::BpfGatherBytes::init::<syscalls::BpfSyscallContext, UserError>,
                syscalls::BpfGatherBytes::call,
            )
            .unwrap();
        let mut bpf_functions = BTreeMap::new();
        register_bpf_function(
            &config,
            &mut bpf_functions,
            &syscall_registry,
            0,
            "entrypoint",
        )
        .unwrap();
        bpf_functions.insert(0xFFFFFFFF, (8, "foo".to_string()));
        Executable::<UserError, TestInstructionMeter>::from_text_bytes(
            program,
            None,
            config,
            syscall_registry,
            bpf_functions,
        )
        .unwrap()
    }
    
    #[test]
    fn test_code_length_estimate() {
        const INSTRUCTION_COUNT: usize = 256;
        let mut prog = [0; ebpf::INSN_SIZE * INSTRUCTION_COUNT];
    
        let empty_program_machine_code_length = {
            prog[0] = ebpf::EXIT;
            let mut executable = create_mockup_executable(&[]);
            Executable::<UserError, TestInstructionMeter>::jit_compile(&mut executable).unwrap();
            executable.get_compiled_program().unwrap().machine_code_length()
        };
        assert!(empty_program_machine_code_length <= MAX_EMPTY_PROGRAM_MACHINE_CODE_LENGTH);
    
        for opcode in 0..255 {
            for pc in 0..INSTRUCTION_COUNT {
                prog[pc * ebpf::INSN_SIZE] = opcode;
                prog[pc * ebpf::INSN_SIZE + 1] = 0x88;
                prog[pc * ebpf::INSN_SIZE + 2] = 0xFF;
                prog[pc * ebpf::INSN_SIZE + 3] = 0xFF;
                LittleEndian::write_u32(&mut prog[pc * ebpf::INSN_SIZE + 4..], match opcode {
                    0x8D => 8,
                    0xD4 | 0xDC => 16,
                    _ => 0xFFFFFFFF,
                });
            }
            let mut executable = create_mockup_executable(&prog);
            let result = Executable::<UserError, TestInstructionMeter>::jit_compile(&mut executable);
            if result.is_err() {
                assert!(matches!(result.unwrap_err(), EbpfError::UnsupportedInstruction(_)));
                continue;
            }
            let machine_code_length = executable.get_compiled_program().unwrap().machine_code_length() - empty_program_machine_code_length;
            let instruction_count = if opcode == 0x18 { INSTRUCTION_COUNT / 2 } else { INSTRUCTION_COUNT };
            let machine_code_length_per_instruction = (machine_code_length as f64 / instruction_count as f64 + 0.5) as usize;
            assert!(machine_code_length_per_instruction <= MAX_MACHINE_CODE_LENGTH_PER_INSTRUCTION);
        }
    }
}
