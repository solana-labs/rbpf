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

use std::fmt::Debug;
use std::mem;
use std::collections::HashMap;
use std::fmt::Formatter;
use std::fmt::Error as FormatterError;
use std::ops::{Index, IndexMut};

use crate::{
    vm::{Config, Executable, ProgramResult, InstructionMeter, Tracer, DynTraitFatPointer, SYSCALL_CONTEXT_OBJECTS_OFFSET},
    ebpf::{self, INSN_SIZE, FIRST_SCRATCH_REG, SCRATCH_REGS, STACK_REG, MM_STACK_START},
    error::{UserDefinedError, EbpfError},
    memory_region::{AccessType, MemoryMapping},
    user_error::UserError,
};

/// Argument for executing a eBPF JIT-compiled program
pub struct JitProgramArgument<'a> {
    /// The MemoryMapping to be used to run the compiled code
    pub memory_mapping: MemoryMapping<'a>,
    /// Pointers to the context objects of syscalls
    pub syscall_context_objects: [*const u8; 0],
}

/// eBPF JIT-compiled program
pub struct JitProgram<E: UserDefinedError, I: InstructionMeter> {
    /// Call this with JitProgramArgument to execute the compiled code
    pub main: unsafe fn(&ProgramResult<E>, u64, &JitProgramArgument, &mut I) -> i64,
}

impl<E: UserDefinedError, I: InstructionMeter> Debug for JitProgram<E, I> {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.write_fmt(format_args!("JitProgram {:?}", &self.main as *const _))
    }
}

impl<E: UserDefinedError, I: InstructionMeter> PartialEq for JitProgram<E, I> {
    fn eq(&self, other: &JitProgram<E, I>) -> bool {
        std::ptr::eq(self.main as *const u8, other.main as *const u8)
    }
}

// Special values for target_pc in struct Jump
const TARGET_OFFSET: usize = ebpf::PROG_MAX_INSNS;
const TARGET_PC_TRACE: usize = TARGET_OFFSET + 1;
const TARGET_PC_TRANSLATE_PC: usize = TARGET_OFFSET + 2;
const TARGET_PC_TRANSLATE_PC_LOOP: usize = TARGET_OFFSET + 3;
const TARGET_PC_CALL_EXCEEDED_MAX_INSTRUCTIONS: usize = TARGET_OFFSET + 4;
const TARGET_PC_CALL_DEPTH_EXCEEDED: usize = TARGET_OFFSET + 5;
const TARGET_PC_CALL_OUTSIDE_TEXT_SEGMENT: usize = TARGET_OFFSET + 6;
const TARGET_PC_DIV_BY_ZERO: usize = TARGET_OFFSET + 7;
const TARGET_PC_UNSUPPORTED_INSTRUCTION: usize = TARGET_OFFSET + 8;
const TARGET_PC_EXCEPTION_AT: usize = TARGET_OFFSET + 9;
const TARGET_PC_SYSCALL_EXCEPTION: usize = TARGET_OFFSET + 10;
const TARGET_PC_EXIT: usize = TARGET_OFFSET + 11;
const TARGET_PC_EPILOGUE: usize = TARGET_OFFSET + 12;

#[derive(Copy, Clone)]
enum OperandSize {
    S8  = 8,
    S16 = 16,
    S32 = 32,
    S64 = 64,
}

// Registers
const RAX: u8 = 0;
const RCX: u8 = 1;
const RDX: u8 = 2;
const RBX: u8 = 3;
const RSP: u8 = 4;
const RBP: u8 = 5;
const RSI: u8 = 6;
const RDI: u8 = 7;
const R8:  u8 = 8;
const R9:  u8 = 9;
const R10: u8 = 10;
const R11: u8 = 11;
const R12: u8 = 12;
const R13: u8 = 13;
const R14: u8 = 14;
const R15: u8 = 15;

// System V AMD64 ABI
// Works on: Linux, macOS, BSD and Solaris but not on Windows
const ARGUMENT_REGISTERS: [u8; 6] = [
    RDI, RSI, RDX, RCX, R8, R9
];
const CALLER_SAVED_REGISTERS: [u8; 9] = [
    RAX, RCX, RDX, RSI, RDI, R8, R9, R10, R11
];
const CALLEE_SAVED_REGISTERS: [u8; 6] = [
    RBP, RBX, R12, R13, R14, R15
];

// Special registers:
// RDI Instruction meter (BPF pc limit)
// RBP Stores a constant pointer to original RSP-8
// R10 Stores a constant pointer to JitProgramArgument
// R11 Scratch register for offsetting

const REGISTER_MAP: [u8; 11] = [
    RAX, // 0  return value
    ARGUMENT_REGISTERS[1], // 1
    ARGUMENT_REGISTERS[2], // 2
    ARGUMENT_REGISTERS[3], // 3
    ARGUMENT_REGISTERS[4], // 4
    ARGUMENT_REGISTERS[5], // 5
    CALLEE_SAVED_REGISTERS[2], // 6
    CALLEE_SAVED_REGISTERS[3], // 7
    CALLEE_SAVED_REGISTERS[4], // 8
    CALLEE_SAVED_REGISTERS[5], // 9
    RBX, // 10 stack pointer
];

macro_rules! emit_bytes {
    ( $jit:ident, $data:tt, $t:ty ) => {{
        let size = mem::size_of::<$t>() as usize;
        assert!($jit.offset + size <= $jit.contents.len());
        unsafe {
            #[allow(clippy::cast_ptr_alignment)]
            let ptr = $jit.contents.as_ptr().add($jit.offset) as *mut $t;
            *ptr = $data as $t;
        }
        $jit.offset += size;
    }}
}

#[inline]
fn emit1(jit: &mut JitCompiler, data: u8) {
    emit_bytes!(jit, data, u8);
}

#[inline]
fn emit2(jit: &mut JitCompiler, data: u16) {
    emit_bytes!(jit, data, u16);
}

#[inline]
fn emit4(jit: &mut JitCompiler, data: u32) {
    emit_bytes!(jit, data, u32);
}

#[inline]
fn emit8(jit: &mut JitCompiler, data: u64) {
    emit_bytes!(jit, data, u64);
}

#[allow(dead_code)]
#[inline]
fn emit_debugger_trap(jit: &mut JitCompiler) {
    emit1(jit, 0xcc);
}

#[inline]
fn emit_modrm(jit: &mut JitCompiler, modrm: u8, r: u8, m: u8) {
    assert_eq!((modrm | 0xc0), 0xc0);
    emit1(jit, (modrm & 0xc0) | ((r & 0b111) << 3) | (m & 0b111));
}

#[inline]
fn emit_modrm_reg2reg(jit: &mut JitCompiler, r: u8, m: u8) {
    emit_modrm(jit, 0xc0, r, m);
}

#[inline]
fn emit_sib(jit: &mut JitCompiler, scale: u8, index: u8, base: u8) {
    assert_eq!((scale | 0xc0), 0xc0);
    emit1(jit, (scale & 0xc0) | ((index & 0b111) << 3) | (base & 0b111));
}

#[inline]
fn emit_modrm_and_displacement(jit: &mut JitCompiler, r: u8, m: u8, d: i32) {
    if d == 0 && (m & 0b111) != RBP {
        emit_modrm(jit, 0x00, r, m);
        if (m & 0b111) == RSP {
            emit_sib(jit, 0, m, m);
        }
    } else if d >= -128 && d <= 127 {
        emit_modrm(jit, 0x40, r, m);
        if (m & 0b111) == RSP {
            emit_sib(jit, 0, m, m);
        }
        emit1(jit, d as u8);
    } else {
        emit_modrm(jit, 0x80, r, m);
        if (m & 0b111) == RSP {
            emit_sib(jit, 0, m, m);
        }
        emit4(jit, d as u32);
    }
}

#[inline]
fn emit_rex(jit: &mut JitCompiler, w: u8, r: u8, x: u8, b: u8) {
    assert_eq!((w | 1), 1);
    assert_eq!((r | 1), 1);
    assert_eq!((x | 1), 1);
    assert_eq!((b | 1), 1);
    emit1(jit, 0x40 | (w << 3) | (r << 2) | (x << 1) | b);
}

// Emits a REX prefix with the top bit of src and dst.
// Skipped if no bits would be set.
#[inline]
fn emit_basic_rex(jit: &mut JitCompiler, w: u8, src: u8, dst: u8) {
    let is_masked = | val, mask | if val & mask == 0 { 0 } else { 1 };
    let src_masked = is_masked(src, 0b1000);
    let dst_masked = is_masked(dst, 0b1000);
    if w != 0 || src_masked != 0 || dst_masked != 0 {
        emit_rex(jit, w, src_masked, 0, dst_masked);
    }
}

#[inline]
fn emit_push(jit: &mut JitCompiler, r: u8) {
    emit_basic_rex(jit, 0, 0, r);
    emit1(jit, 0x50 | (r & 0b111));
}

#[inline]
fn emit_pop(jit: &mut JitCompiler, r: u8) {
    emit_basic_rex(jit, 0, 0, r);
    emit1(jit, 0x58 | (r & 0b111));
}

#[derive(PartialEq, Copy, Clone)]
enum OperationWidth {
    Bit32 = 0,
    Bit64 = 1,
}

// REX prefix and ModRM byte
// We use the MR encoding when there is a choice
// 'src' is often used as an opcode extension
#[inline]
fn emit_alu(jit: &mut JitCompiler, width: OperationWidth, op: u8, src: u8, dst: u8, imm: i32, displacement: Option<i32>) {
    emit_basic_rex(jit, width as u8, src, dst);
    emit1(jit, op);
    match displacement {
        Some(d) => {
            emit_modrm_and_displacement(jit, src, dst, d);
        },
        None => {
            emit_modrm_reg2reg(jit, src, dst);
        }
    }
    match op {
        0xc1 => emit1(jit, imm as u8),
        0x81 | 0xc7 => emit4(jit, imm as u32),
        0xf7 if src == 0 => emit4(jit, imm as u32),
        _ => {}
    }
}

// Register to register mov
#[inline]
fn emit_mov(jit: &mut JitCompiler, width: OperationWidth, src: u8, dst: u8) {
    emit_alu(jit, width, 0x89, src, dst, 0, None);
}

// Sign extend register i32 to register i64
#[inline]
fn sign_extend_i32_to_i64(jit: &mut JitCompiler, src: u8, dst: u8) {
    emit_alu(jit, OperationWidth::Bit64, 0x63, src, dst, 0, None);
}

// Register to register exchange / swap
#[inline]
fn emit_xchg(jit: &mut JitCompiler, src: u8, dst: u8) {
    emit_alu(jit, OperationWidth::Bit64, 0x87, src, dst, 0, None);
}

#[inline]
fn emit_cmp_imm32(jit: &mut JitCompiler, dst: u8, imm: i32, displacement: Option<i32>) {
    emit_alu(jit, OperationWidth::Bit64, 0x81, 7, dst, imm, displacement);
}

#[inline]
fn emit_cmp(jit: &mut JitCompiler, src: u8, dst: u8, displacement: Option<i32>) {
    emit_alu(jit, OperationWidth::Bit64, 0x39, src, dst, 0, displacement);
}

#[inline]
fn emit_jump_offset(jit: &mut JitCompiler, target_pc: usize) {
    jit.jumps.push(Jump { in_content: true, location: jit.offset, target_pc });
    emit4(jit, 0);
}

#[inline]
fn emit_jcc(jit: &mut JitCompiler, code: u8, target_pc: usize) {
    emit1(jit, 0x0f);
    emit1(jit, code);
    emit_jump_offset(jit, target_pc);
}

#[inline]
fn emit_jmp(jit: &mut JitCompiler, target_pc: usize) {
    emit1(jit, 0xe9);
    emit_jump_offset(jit, target_pc);
}

#[inline]
fn emit_call(jit: &mut JitCompiler, target_pc: usize) {
    emit1(jit, 0xe8);
    emit_jump_offset(jit, target_pc);
}

#[inline]
fn set_anchor(jit: &mut JitCompiler, target: usize) {
    jit.special_targets.insert(target, jit.offset);
}

// Load [src + offset] into dst
#[inline]
fn emit_load(jit: &mut JitCompiler, size: OperandSize, src: u8, dst: u8, offset: i32) {
    let data = match size {
        OperandSize::S64 => 1,
        _ => 0
    };
    emit_basic_rex(jit, data, dst, src);

    match size {
        OperandSize::S8 => {
            // movzx
            emit1(jit, 0x0f);
            emit1(jit, 0xb6);
        },
        OperandSize::S16 => {
            // movzx
            emit1(jit, 0x0f);
            emit1(jit, 0xb7);
        },
        OperandSize::S32 | OperandSize::S64 => {
            // mov
            emit1(jit, 0x8b);
        }
    }

    emit_modrm_and_displacement(jit, dst, src, offset);
}

// Load sign-extended immediate into register
#[inline]
fn emit_load_imm(jit: &mut JitCompiler, dst: u8, imm: i64) {
    if imm >= std::i32::MIN as i64 && imm <= std::i32::MAX as i64 {
        emit_alu(jit, OperationWidth::Bit64, 0xc7, 0, dst, imm as i32, None);
    } else {
        // movabs $imm,dst
        emit_basic_rex(jit, 1, 0, dst);
        emit1(jit, 0xb8 | (dst & 0b111));
        emit8(jit, imm as u64);
    }
}

// Load effective address (64 bit)
#[allow(dead_code)]
#[inline]
fn emit_leaq(jit: &mut JitCompiler, src: u8, dst: u8, offset: i32) {
    emit_basic_rex(jit, 1, dst, src);
    // leaq src + offset, dst
    emit1(jit, 0x8d);
    emit_modrm_and_displacement(jit, dst, src, offset);
}

// Store register src to [dst + offset]
#[inline]
fn emit_store(jit: &mut JitCompiler, size: OperandSize, src: u8, dst: u8, offset: i32) {
    if let OperandSize::S16 = size {
        emit1(jit, 0x66) // 16-bit override
    };
    let (is_s8, is_u64, rexw) = match size {
        OperandSize::S8  => (true, false, 0),
        OperandSize::S64 => (false, true, 1),
        _                => (false, false, 0),
    };
    if is_u64 || (src & 0b1000) != 0 || (dst & 0b1000) != 0 || is_s8 {
        let is_masked = | val, mask | {
            match val & mask {
                0 => 0,
                _ => 1
            }
        };
        emit_rex(jit, rexw, is_masked(src, 8), 0, is_masked(dst, 8));
    }
    match size {
        OperandSize::S8 => emit1(jit, 0x88),
        _               => emit1(jit, 0x89),
    };
    emit_modrm_and_displacement(jit, src, dst, offset);
}

// Store immediate to [dst + offset]
#[inline]
fn emit_store_imm32(jit: &mut JitCompiler, size: OperandSize, dst: u8, offset: i32, imm: i32) {
    if let OperandSize::S16 = size {
        emit1(jit, 0x66) // 16-bit override
    };
    match size {
        OperandSize::S64 => emit_basic_rex(jit, 1, 0, dst),
        _                => emit_basic_rex(jit, 0, 0, dst),
    };
    match size {
        OperandSize::S8 => emit1(jit, 0xc6),
        _               => emit1(jit, 0xc7),
    };
    emit_modrm_and_displacement(jit, 0, dst, offset);
    match size {
        OperandSize::S8  => emit1(jit, imm as u8),
        OperandSize::S16 => emit2(jit, imm as u16),
        _                => emit4(jit, imm as u32),
    };
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
fn emit_profile_instruction_count(jit: &mut JitCompiler, target_pc: Option<usize>) {
    if jit.config.enable_instruction_meter {
        match target_pc {
            Some(target_pc) => {
                emit_alu(jit, OperationWidth::Bit64, 0x81, 0, ARGUMENT_REGISTERS[0], target_pc as i32 - jit.pc as i32 - 1, None); // instruction_meter += target_pc - (jit.pc + 1);
            },
            None => { // If no constant target_pc is given, it is expected to be on the stack instead
                emit_pop(jit, R11);
                emit_alu(jit, OperationWidth::Bit64, 0x81, 5, ARGUMENT_REGISTERS[0], jit.pc as i32 + 1, None); // instruction_meter -= jit.pc + 1;
                emit_alu(jit, OperationWidth::Bit64, 0x01, R11, ARGUMENT_REGISTERS[0], jit.pc as i32, None); // instruction_meter += target_pc;
            },
        }
    }
}

#[inline]
fn emit_validate_and_profile_instruction_count(jit: &mut JitCompiler, exclusive: bool, target_pc: Option<usize>) {
    if jit.config.enable_instruction_meter {
        emit_cmp_imm32(jit, ARGUMENT_REGISTERS[0], jit.pc as i32 + 1, None);
        emit_jcc(jit, if exclusive { 0x82 } else { 0x86 }, TARGET_PC_CALL_EXCEEDED_MAX_INSTRUCTIONS);
        emit_profile_instruction_count(jit, target_pc);
    }
}

#[inline]
fn emit_undo_profile_instruction_count(jit: &mut JitCompiler, target_pc: usize) {
    if jit.config.enable_instruction_meter {
        emit_alu(jit, OperationWidth::Bit64, 0x81, 0, ARGUMENT_REGISTERS[0], jit.pc as i32 + 1 - target_pc as i32, None); // instruction_meter += (jit.pc + 1) - target_pc;
    }
}

#[inline]
fn emit_profile_instruction_count_of_exception(jit: &mut JitCompiler) {
    emit_alu(jit, OperationWidth::Bit64, 0x81, 0, R11, 1, None);
    if jit.config.enable_instruction_meter {
        emit_alu(jit, OperationWidth::Bit64, 0x29, R11, ARGUMENT_REGISTERS[0], 0, None); // instruction_meter -= pc + 1;
    }
}

#[inline]
fn emit_conditional_branch_reg(jit: &mut JitCompiler, op: u8, src: u8, dst: u8, target_pc: usize) {
    emit_validate_and_profile_instruction_count(jit, false, Some(target_pc));
    emit_cmp(jit, src, dst, None);
    emit_jcc(jit, op, target_pc);
    emit_undo_profile_instruction_count(jit, target_pc);
}

#[inline]
fn emit_conditional_branch_imm(jit: &mut JitCompiler, op: u8, imm: i32, dst: u8, target_pc: usize) {
    emit_validate_and_profile_instruction_count(jit, false, Some(target_pc));
    emit_cmp_imm32(jit, dst, imm, None);
    emit_jcc(jit, op, target_pc);
    emit_undo_profile_instruction_count(jit, target_pc);
}

enum Value {
    Register(u8),
    RegisterIndirect(u8, i32),
    RegisterPlusConstant64(u8, i64),
    Constant64(i64),
}

#[inline]
fn emit_bpf_call(jit: &mut JitCompiler, dst: Value, number_of_instructions: usize) {
    for reg in REGISTER_MAP.iter().skip(FIRST_SCRATCH_REG).take(SCRATCH_REGS) {
        emit_push(jit, *reg);
    }
    emit_push(jit, REGISTER_MAP[STACK_REG]);

    match dst {
        Value::Register(reg) => {
            // Move vm target_address into RAX
            emit_push(jit, REGISTER_MAP[0]);
            if reg != REGISTER_MAP[0] {
                emit_mov(jit, OperationWidth::Bit64, reg, REGISTER_MAP[0]);
            }
            // Force alignment of RAX
            emit_alu(jit, OperationWidth::Bit64, 0x81, 4, REGISTER_MAP[0], !(INSN_SIZE as i32 - 1), None); // RAX &= !(INSN_SIZE - 1);
            // Store PC in case the bounds check fails
            emit_load_imm(jit, R11, jit.pc as i64);
            // Upper bound check
            // if(RAX >= jit.program_vm_addr + number_of_instructions * INSN_SIZE) throw CALL_OUTSIDE_TEXT_SEGMENT;
            emit_load_imm(jit, REGISTER_MAP[STACK_REG], jit.program_vm_addr as i64 + (number_of_instructions * INSN_SIZE) as i64);
            emit_cmp(jit, REGISTER_MAP[STACK_REG], REGISTER_MAP[0], None);
            emit_jcc(jit, 0x83, TARGET_PC_CALL_OUTSIDE_TEXT_SEGMENT);
            // Lower bound check
            // if(RAX < jit.program_vm_addr) throw CALL_OUTSIDE_TEXT_SEGMENT;
            emit_load_imm(jit, REGISTER_MAP[STACK_REG], jit.program_vm_addr as i64);
            emit_cmp(jit, REGISTER_MAP[STACK_REG], REGISTER_MAP[0], None);
            emit_jcc(jit, 0x82, TARGET_PC_CALL_OUTSIDE_TEXT_SEGMENT);
            // Calculate offset relative to instruction_addresses
            emit_alu(jit, OperationWidth::Bit64, 0x29, REGISTER_MAP[STACK_REG], REGISTER_MAP[0], 0, None); // RAX -= jit.program_vm_addr;
            if jit.config.enable_instruction_meter {
                // Calculate the target_pc to update the instruction_meter
                let shift_amount = INSN_SIZE.trailing_zeros();
                assert_eq!(INSN_SIZE, 1<<shift_amount);
                emit_mov(jit, OperationWidth::Bit64, REGISTER_MAP[0], REGISTER_MAP[STACK_REG]);
                emit_alu(jit, OperationWidth::Bit64, 0xc1, 5, REGISTER_MAP[STACK_REG], shift_amount as i32, None);
                emit_push(jit, REGISTER_MAP[STACK_REG]);
            }
            // Load host target_address from JitProgramArgument.instruction_addresses
            assert_eq!(INSN_SIZE, 8); // Because the instruction size is also the slot size we do not need to shift the offset
            emit_mov(jit, OperationWidth::Bit64, REGISTER_MAP[0], REGISTER_MAP[STACK_REG]);
            emit_load_imm(jit, REGISTER_MAP[STACK_REG], jit.pc_locs.as_ptr() as i64);
            emit_alu(jit, OperationWidth::Bit64, 0x01, REGISTER_MAP[STACK_REG], REGISTER_MAP[0], 0, None); // RAX += jit.pc_locs;
            emit_load(jit, OperandSize::S64, REGISTER_MAP[0], REGISTER_MAP[0], 0); // RAX = jit.pc_locs[RAX / 8];
        },
        Value::Constant64(_target_pc) => {},
        _ => panic!()
    }

    emit_load(jit, OperandSize::S64, RBP, REGISTER_MAP[STACK_REG], -8 * CALLEE_SAVED_REGISTERS.len() as i32); // load stack_ptr
    emit_alu(jit, OperationWidth::Bit64, 0x81, 4, REGISTER_MAP[STACK_REG], !(jit.config.stack_frame_size as i32 * 2 - 1), None); // stack_ptr &= !(jit.config.stack_frame_size * 2 - 1);
    emit_alu(jit, OperationWidth::Bit64, 0x81, 0, REGISTER_MAP[STACK_REG], jit.config.stack_frame_size as i32 * 3, None); // stack_ptr += jit.config.stack_frame_size * 3;
    emit_store(jit, OperandSize::S64, REGISTER_MAP[STACK_REG], RBP, -8 * CALLEE_SAVED_REGISTERS.len() as i32); // store stack_ptr

    // if(stack_ptr >= MM_STACK_START + jit.config.max_call_depth * jit.config.stack_frame_size * 2) throw EbpfError::CallDepthExeeded;
    emit_load_imm(jit, R11, MM_STACK_START as i64 + (jit.config.max_call_depth * jit.config.stack_frame_size * 2) as i64);
    emit_cmp(jit, R11, REGISTER_MAP[STACK_REG], None);
    // Store PC in case the bounds check fails
    emit_load_imm(jit, R11, jit.pc as i64);
    emit_jcc(jit, 0x83, TARGET_PC_CALL_DEPTH_EXCEEDED);

    match dst {
        Value::Register(_reg) => {
            emit_validate_and_profile_instruction_count(jit, true, None);

            emit_mov(jit, OperationWidth::Bit64, REGISTER_MAP[0], R11);
            emit_pop(jit, REGISTER_MAP[0]);

            // callq *%r11
            emit1(jit, 0x41);
            emit1(jit, 0xff);
            emit1(jit, 0xd3);
        },
        Value::Constant64(target_pc) => {
            emit_validate_and_profile_instruction_count(jit, true, Some(target_pc as usize));
            emit_call(jit, target_pc as usize);
        },
        _ => panic!()
    }
    emit_undo_profile_instruction_count(jit, 0);

    emit_pop(jit, REGISTER_MAP[STACK_REG]);
    for reg in REGISTER_MAP.iter().skip(FIRST_SCRATCH_REG).take(SCRATCH_REGS).rev() {
        emit_pop(jit, *reg);
    }
}

struct Argument {
    index: usize,
    value: Value,
}

#[inline]
fn emit_rust_call(jit: &mut JitCompiler, function: *const u8, arguments: &[Argument], return_reg: Option<u8>, check_exception: bool) {
    let mut saved_registers = CALLER_SAVED_REGISTERS.to_vec();
    if let Some(reg) = return_reg {
        let dst = saved_registers.iter().position(|x| *x == reg).unwrap();
        saved_registers.remove(dst);
    }

    // Pass arguments via stack
    for argument in arguments {
        if argument.index < ARGUMENT_REGISTERS.len() {
            continue;
        }
        match argument.value {
            Value::Register(reg) => {
                let src = saved_registers.iter().position(|x| *x == reg).unwrap();
                saved_registers.remove(src);
                let dst = saved_registers.len() - (argument.index - ARGUMENT_REGISTERS.len());
                saved_registers.insert(dst, reg);
            },
            Value::RegisterIndirect(reg, offset) => {
                emit_load(jit, OperandSize::S64, reg, R11, offset);
            },
            _ => panic!()
        }
    }

    // Save registers on stack
    for reg in saved_registers.iter() {
        emit_push(jit, *reg);
    }

    // Pass arguments via registers
    for argument in arguments {
        if argument.index >= ARGUMENT_REGISTERS.len() {
            continue;
        }
        let dst = ARGUMENT_REGISTERS[argument.index];
        match argument.value {
            Value::Register(reg) => {
                if reg != dst {
                    emit_mov(jit, OperationWidth::Bit64, reg, dst);
                }
            },
            Value::RegisterIndirect(reg, offset) => {
                emit_load(jit, OperandSize::S64, reg, dst, offset);
            },
            Value::RegisterPlusConstant64(reg, offset) => {
                emit_load_imm(jit, R11, offset);
                emit_alu(jit, OperationWidth::Bit64, 0x01, reg, R11, 0, None);
                emit_mov(jit, OperationWidth::Bit64, R11, dst);
            },
            Value::Constant64(value) => {
                emit_load_imm(jit, dst, value);
            },
        }
    }

    // TODO use direct call when possible
    emit_load_imm(jit, RAX, function as i64);
    // callq *%rax
    emit1(jit, 0xff);
    emit1(jit, 0xd0);

    if let Some(reg) = return_reg {
        emit_mov(jit, OperationWidth::Bit64, RAX, reg);
    }

    // Restore registers from stack
    for reg in saved_registers.iter().rev() {
        emit_pop(jit, *reg);
    }

    if check_exception {
        // Test if result indicates that an error occured
        emit_load(jit, OperandSize::S64, RBP, R11, -8 * (CALLEE_SAVED_REGISTERS.len() + 1) as i32);
        emit_cmp_imm32(jit, R11, 0, Some(0));
    }
}

#[inline]
fn emit_address_translation(jit: &mut JitCompiler, host_addr: u8, vm_addr: Value, len: u64, access_type: AccessType) {
    emit_rust_call(jit, MemoryMapping::map::<UserError> as *const u8, &[
        Argument { index: 3, value: vm_addr }, // Specify first as the src register could be overwritten by other arguments
        Argument { index: 0, value: Value::RegisterIndirect(RBP, -8 * (CALLEE_SAVED_REGISTERS.len() + 1) as i32) }, // Pointer to optional typed return value
        Argument { index: 1, value: Value::Register(R10) }, // JitProgramArgument::memory_mapping
        Argument { index: 2, value: Value::Constant64(access_type as i64) },
        Argument { index: 4, value: Value::Constant64(len as i64) },
    ], None, true);

    // Throw error if the result indicates one
    emit_load_imm(jit, R11, jit.pc as i64);
    emit_jcc(jit, 0x85, TARGET_PC_EXCEPTION_AT);

    // Store Ok value in result register
    emit_load(jit, OperandSize::S64, RBP, R11, -8 * (CALLEE_SAVED_REGISTERS.len() + 1) as i32);
    emit_load(jit, OperandSize::S64, R11, host_addr, 8);
}

fn emit_shift(jit: &mut JitCompiler, width: OperationWidth, opc: u8, src: u8, dst: u8) {
    if width == OperationWidth::Bit32 {
        emit_alu(jit, OperationWidth::Bit32, 0x81, 4, dst, -1, None); // Mask to 32 bit
    }
    if src == RCX {
        if dst == RCX {
            emit_alu(jit, width, 0xd3, opc, dst, 0, None);
        } else {
            emit_mov(jit, OperationWidth::Bit64, RCX, R11);
            emit_alu(jit, width, 0xd3, opc, dst, 0, None);
            emit_mov(jit, OperationWidth::Bit64, R11, RCX);
        }
    } else if dst == RCX {
        emit_mov(jit, OperationWidth::Bit64, src, R11);
        emit_xchg(jit, src, RCX);
        emit_alu(jit, width, 0xd3, opc, src, 0, None);
        emit_mov(jit, OperationWidth::Bit64, src, RCX);
        emit_mov(jit, OperationWidth::Bit64, R11, src);
    } else {
        emit_mov(jit, OperationWidth::Bit64, RCX, R11);
        emit_mov(jit, OperationWidth::Bit64, src, RCX);
        emit_alu(jit, width, 0xd3, opc, dst, 0, None);
        emit_mov(jit, OperationWidth::Bit64, R11, RCX);
    }
}

fn emit_muldivmod(jit: &mut JitCompiler, opc: u8, src: u8, dst: u8, imm: Option<i32>) {
    let mul = (opc & ebpf::BPF_ALU_OP_MASK) == (ebpf::MUL32_IMM & ebpf::BPF_ALU_OP_MASK);
    let div = (opc & ebpf::BPF_ALU_OP_MASK) == (ebpf::DIV32_IMM & ebpf::BPF_ALU_OP_MASK);
    let modrm = (opc & ebpf::BPF_ALU_OP_MASK) == (ebpf::MOD32_IMM & ebpf::BPF_ALU_OP_MASK);
    let width = if (opc & ebpf::BPF_CLS_MASK) == ebpf::BPF_ALU64 { OperationWidth::Bit64 } else { OperationWidth::Bit32 };

    if (div || modrm) && imm.is_none() {
        // Save pc
        emit_load_imm(jit, R11, jit.pc as i64);

        // test src,src
        emit_alu(jit, width, 0x85, src, src, 0, None);

        // Jump if src is zero
        emit_jcc(jit, 0x84, TARGET_PC_DIV_BY_ZERO);
    }

    if dst != RAX {
        emit_push(jit, RAX);
    }
    if dst != RDX {
        emit_push(jit, RDX);
    }

    if let Some(imm) = imm {
        emit_load_imm(jit, R11, imm as i64);
    } else {
        emit_mov(jit, OperationWidth::Bit64, src, R11);
    }

    if dst != RAX {
        emit_mov(jit, OperationWidth::Bit64, dst, RAX);
    }

    if div || modrm {
        // xor %edx,%edx
        emit_alu(jit, width, 0x31, RDX, RDX, 0, None);
    }

    emit_alu(jit, width, 0xf7, if mul { 4 } else { 6 }, R11, 0, None);

    if dst != RDX {
        if modrm {
            emit_mov(jit, OperationWidth::Bit64, RDX, dst);
        }
        emit_pop(jit, RDX);
    }
    if dst != RAX {
        if div || mul {
            emit_mov(jit, OperationWidth::Bit64, RAX, dst);
        }
        emit_pop(jit, RAX);
    }

    if width == OperationWidth::Bit32 && opc & ebpf::BPF_ALU_OP_MASK == ebpf::BPF_MUL {
        sign_extend_i32_to_i64(jit, dst, dst);
    }
}

#[inline]
fn set_exception_kind<E: UserDefinedError>(jit: &mut JitCompiler, err: EbpfError<E>) {
    let err = Result::<u64, EbpfError<E>>::Err(err);
    let err_kind = unsafe { *(&err as *const _ as *const u64).offset(1) };
    emit_load(jit, OperandSize::S64, RBP, R10, -8 * (CALLEE_SAVED_REGISTERS.len() + 1) as i32);
    emit_store_imm32(jit, OperandSize::S64, R10, 8, err_kind as i32);
}

const PAGE_SIZE: usize = 4096;
fn round_to_page_size(value: usize) -> usize {
    (value + PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE
}

#[derive(Debug)]
struct Jump {
    in_content: bool,
    location: usize,
    target_pc: usize,
}

struct JitCompiler<'a> {
    pc_locs: &'a mut [u64],
    contents: &'a mut [u8],
    offset: usize,
    pc: usize,
    program_vm_addr: u64,
    special_targets: HashMap<usize, usize>,
    jumps: Vec<Jump>,
    config: Config,
}

impl<'a> JitCompiler<'a> {
    // Arguments are unused on windows
    fn new(_program: &[u8], _config: &Config) -> JitCompiler<'a> {
        #[cfg(windows)]
        {
            panic!("JIT not supported on windows");
        }
        let pc_locs: &mut[u64];
        let contents: &mut[u8];

        #[cfg(not(windows))] // Without this block windows will fail ungracefully, hence the panic above
        unsafe {
            // Scan through program to find actual number of instructions
            let mut pc = 0;
            while pc * ebpf::INSN_SIZE < _program.len() {
                let insn = ebpf::get_insn(_program, pc);
                pc += match insn.opc {
                    ebpf::LD_DW_IMM => 2,
                    _ => 1,
                };
            }

            let pc_loc_table_size = round_to_page_size((pc + 1) * 8);
            let code_size = round_to_page_size(pc * 256 + 512);

            let mut raw: *mut libc::c_void = std::mem::MaybeUninit::uninit().assume_init();
            libc::posix_memalign(&mut raw, PAGE_SIZE, pc_loc_table_size + code_size);

            std::ptr::write_bytes(raw, 0x00, pc_loc_table_size);
            pc_locs = std::slice::from_raw_parts_mut(raw as *mut u64, pc + 1);

            std::ptr::write_bytes(raw.add(pc_loc_table_size), 0xcc, code_size); // Populate with debugger traps
            contents = std::slice::from_raw_parts_mut(raw.add(pc_loc_table_size) as *mut u8, code_size);
        }

        JitCompiler {
            pc_locs,
            contents,
            offset: 0,
            pc: 0,
            program_vm_addr: 0,
            special_targets: HashMap::new(),
            jumps: vec![],
            config: *_config,
        }
    }

    fn compile<E: UserDefinedError, I: InstructionMeter>(&mut self,
                   executable: &'a dyn Executable<E, I>) -> Result<(), EbpfError<E>> {
        let (program_vm_addr, program) = executable.get_text_bytes()?;
        self.program_vm_addr = program_vm_addr;

        self.generate_prologue::<I>();

        // Jump to custom entry point (if any)
        let entry = executable.get_entrypoint_instruction_offset().unwrap();
        if entry != 0 {
            emit_profile_instruction_count(self, Some(entry + 1));
            emit_jmp(self, entry);
        }

        while self.pc * ebpf::INSN_SIZE < program.len() {
            let insn = ebpf::get_insn(program, self.pc);

            self.pc_locs[self.pc] = self.offset as u64;

            if self.config.enable_instruction_tracing {
                emit_load_imm(self, R11, self.pc as i64);
                emit_call(self, TARGET_PC_TRACE);
            }

            let dst = REGISTER_MAP[insn.dst as usize];
            let src = REGISTER_MAP[insn.src as usize];
            let target_pc = (self.pc as isize + insn.off as isize + 1) as usize;

            match insn.opc {

                // BPF_LD class
                ebpf::LD_ABS_B   => {
                    emit_address_translation(self, R11, Value::Constant64(ebpf::MM_INPUT_START.wrapping_add(insn.imm as u32 as u64) as i64), 1, AccessType::Load);
                    emit_load(self, OperandSize::S8, R11, RAX, 0);
                },
                ebpf::LD_ABS_H   => {
                    emit_address_translation(self, R11, Value::Constant64(ebpf::MM_INPUT_START.wrapping_add(insn.imm as u32 as u64) as i64), 2, AccessType::Load);
                    emit_load(self, OperandSize::S16, R11, RAX, 0);
                },
                ebpf::LD_ABS_W   => {
                    emit_address_translation(self, R11, Value::Constant64(ebpf::MM_INPUT_START.wrapping_add(insn.imm as u32 as u64) as i64), 4, AccessType::Load);
                    emit_load(self, OperandSize::S32, R11, RAX, 0);
                },
                ebpf::LD_ABS_DW  => {
                    emit_address_translation(self, R11, Value::Constant64(ebpf::MM_INPUT_START.wrapping_add(insn.imm as u32 as u64) as i64), 8, AccessType::Load);
                    emit_load(self, OperandSize::S64, R11, RAX, 0);
                },
                ebpf::LD_IND_B   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(src, ebpf::MM_INPUT_START.wrapping_add(insn.imm as u32 as u64) as i64), 1, AccessType::Load);
                    emit_load(self, OperandSize::S8, R11, RAX, 0);
                },
                ebpf::LD_IND_H   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(src, ebpf::MM_INPUT_START.wrapping_add(insn.imm as u32 as u64) as i64), 2, AccessType::Load);
                    emit_load(self, OperandSize::S16, R11, RAX, 0);
                },
                ebpf::LD_IND_W   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(src, ebpf::MM_INPUT_START.wrapping_add(insn.imm as u32 as u64) as i64), 4, AccessType::Load);
                    emit_load(self, OperandSize::S32, R11, RAX, 0);
                },
                ebpf::LD_IND_DW  => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(src, ebpf::MM_INPUT_START.wrapping_add(insn.imm as u32 as u64) as i64), 8, AccessType::Load);
                    emit_load(self, OperandSize::S64, R11, RAX, 0);
                },

                ebpf::LD_DW_IMM  => {
                    emit_validate_and_profile_instruction_count(self, true, Some(self.pc + 2));
                    self.pc += 1;
                    self.jumps.push(Jump { in_content: false, location: self.pc, target_pc: TARGET_PC_UNSUPPORTED_INSTRUCTION });
                    let second_part = ebpf::get_insn(program, self.pc).imm as u64;
                    let imm = (insn.imm as u32) as u64 | second_part.wrapping_shl(32);
                    emit_load_imm(self, dst, imm as i64);
                },

                // BPF_LDX class
                ebpf::LD_B_REG   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(src, insn.off as i64), 1, AccessType::Load);
                    emit_load(self, OperandSize::S8, R11, dst, 0);
                },
                ebpf::LD_H_REG   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(src, insn.off as i64), 2, AccessType::Load);
                    emit_load(self, OperandSize::S16, R11, dst, 0);
                },
                ebpf::LD_W_REG   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(src, insn.off as i64), 4, AccessType::Load);
                    emit_load(self, OperandSize::S32, R11, dst, 0);
                },
                ebpf::LD_DW_REG  => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(src, insn.off as i64), 8, AccessType::Load);
                    emit_load(self, OperandSize::S64, R11, dst, 0);
                },

                // BPF_ST class
                ebpf::ST_B_IMM   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(dst, insn.off as i64), 1, AccessType::Store);
                    emit_store_imm32(self, OperandSize::S8, R11, 0, insn.imm);
                },
                ebpf::ST_H_IMM   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(dst, insn.off as i64), 2, AccessType::Store);
                    emit_store_imm32(self, OperandSize::S16, R11, 0, insn.imm);
                },
                ebpf::ST_W_IMM   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(dst, insn.off as i64), 4, AccessType::Store);
                    emit_store_imm32(self, OperandSize::S32, R11, 0, insn.imm);
                },
                ebpf::ST_DW_IMM  => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(dst, insn.off as i64), 8, AccessType::Store);
                    emit_store_imm32(self, OperandSize::S64, R11, 0, insn.imm);
                },

                // BPF_STX class
                ebpf::ST_B_REG  => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(dst, insn.off as i64), 1, AccessType::Store);
                    emit_store(self, OperandSize::S8, src, R11, 0);
                },
                ebpf::ST_H_REG  => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(dst, insn.off as i64), 2, AccessType::Store);
                    emit_store(self, OperandSize::S16, src, R11, 0);
                },
                ebpf::ST_W_REG  => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(dst, insn.off as i64), 4, AccessType::Store);
                    emit_store(self, OperandSize::S32, src, R11, 0);
                },
                ebpf::ST_DW_REG  => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant64(dst, insn.off as i64), 8, AccessType::Store);
                    emit_store(self, OperandSize::S64, src, R11, 0);
                },

                // BPF_ALU class
                ebpf::ADD32_IMM  => {
                    emit_alu(self, OperationWidth::Bit32, 0x81, 0, dst, insn.imm, None);
                    sign_extend_i32_to_i64(self, dst, dst);
                },
                ebpf::ADD32_REG  => {
                    emit_alu(self, OperationWidth::Bit32, 0x01, src, dst, 0, None);
                    sign_extend_i32_to_i64(self, dst, dst);
                },
                ebpf::SUB32_IMM  => {
                    emit_alu(self, OperationWidth::Bit32, 0x81, 5, dst, insn.imm, None);
                    sign_extend_i32_to_i64(self, dst, dst);
                },
                ebpf::SUB32_REG  => {
                    emit_alu(self, OperationWidth::Bit32, 0x29, src, dst, 0, None);
                    sign_extend_i32_to_i64(self, dst, dst);
                },
                ebpf::MUL32_IMM | ebpf::DIV32_IMM | ebpf::MOD32_IMM  =>
                    emit_muldivmod(self, insn.opc, dst, dst, Some(insn.imm)),
                ebpf::MUL32_REG | ebpf::DIV32_REG | ebpf::MOD32_REG  =>
                    emit_muldivmod(self, insn.opc, src, dst, None),
                ebpf::OR32_IMM   => emit_alu(self, OperationWidth::Bit32, 0x81, 1, dst, insn.imm, None),
                ebpf::OR32_REG   => emit_alu(self, OperationWidth::Bit32, 0x09, src, dst, 0, None),
                ebpf::AND32_IMM  => emit_alu(self, OperationWidth::Bit32, 0x81, 4, dst, insn.imm, None),
                ebpf::AND32_REG  => emit_alu(self, OperationWidth::Bit32, 0x21, src, dst, 0, None),
                ebpf::LSH32_IMM  => emit_alu(self, OperationWidth::Bit32, 0xc1, 4, dst, insn.imm, None),
                ebpf::LSH32_REG  => emit_shift(self, OperationWidth::Bit32, 4, src, dst),
                ebpf::RSH32_IMM  => emit_alu(self, OperationWidth::Bit32, 0xc1, 5, dst, insn.imm, None),
                ebpf::RSH32_REG  => emit_shift(self, OperationWidth::Bit32, 5, src, dst),
                ebpf::NEG32      => emit_alu(self, OperationWidth::Bit32, 0xf7, 3, dst, 0, None),
                ebpf::XOR32_IMM  => emit_alu(self, OperationWidth::Bit32, 0x81, 6, dst, insn.imm, None),
                ebpf::XOR32_REG  => emit_alu(self, OperationWidth::Bit32, 0x31, src, dst, 0, None),
                ebpf::MOV32_IMM  => emit_alu(self, OperationWidth::Bit32, 0xc7, 0, dst, insn.imm, None),
                ebpf::MOV32_REG  => emit_mov(self, OperationWidth::Bit32, src, dst),
                ebpf::ARSH32_IMM => emit_alu(self, OperationWidth::Bit32, 0xc1, 7, dst, insn.imm, None),
                ebpf::ARSH32_REG => emit_shift(self, OperationWidth::Bit32, 7, src, dst),
                ebpf::LE         => {
                    match insn.imm {
                        16 => {
                            emit_alu(self, OperationWidth::Bit32, 0x81, 4, dst, 0xffff, None); // Mask to 16 bit
                        }
                        32 => {
                            emit_alu(self, OperationWidth::Bit32, 0x81, 4, dst, -1, None); // Mask to 32 bit
                        }
                        64 => {}
                        _ => unreachable!()
                    }
                },
                ebpf::BE         => {
                    match insn.imm {
                        16 => {
                            // rol
                            emit1(self, 0x66); // 16-bit override
                            emit_alu(self, OperationWidth::Bit32, 0xc1, 0, dst, 8, None);
                            emit_alu(self, OperationWidth::Bit32, 0x81, 4, dst, 0xffff, None); // Mask to 16 bit
                        }
                        32 | 64 => {
                            // bswap
                            let bit = match insn.imm { 64 => 1, _ => 0 };
                            emit_basic_rex(self, bit, 0, dst);
                            emit1(self, 0x0f);
                            emit1(self, 0xc8 | (dst & 0b111));
                        }
                        _ => unreachable!()
                    }
                },

                // BPF_ALU64 class
                ebpf::ADD64_IMM  => emit_alu(self, OperationWidth::Bit64, 0x81, 0, dst, insn.imm, None),
                ebpf::ADD64_REG  => emit_alu(self, OperationWidth::Bit64, 0x01, src, dst, 0, None),
                ebpf::SUB64_IMM  => emit_alu(self, OperationWidth::Bit64, 0x81, 5, dst, insn.imm, None),
                ebpf::SUB64_REG  => emit_alu(self, OperationWidth::Bit64, 0x29, src, dst, 0, None),
                ebpf::MUL64_IMM | ebpf::DIV64_IMM | ebpf::MOD64_IMM  =>
                    emit_muldivmod(self, insn.opc, dst, dst, Some(insn.imm)),
                ebpf::MUL64_REG | ebpf::DIV64_REG | ebpf::MOD64_REG  =>
                    emit_muldivmod(self, insn.opc, src, dst, None),
                ebpf::OR64_IMM   => emit_alu(self, OperationWidth::Bit64, 0x81, 1, dst, insn.imm, None),
                ebpf::OR64_REG   => emit_alu(self, OperationWidth::Bit64, 0x09, src, dst, 0, None),
                ebpf::AND64_IMM  => emit_alu(self, OperationWidth::Bit64, 0x81, 4, dst, insn.imm, None),
                ebpf::AND64_REG  => emit_alu(self, OperationWidth::Bit64, 0x21, src, dst, 0, None),
                ebpf::LSH64_IMM  => emit_alu(self, OperationWidth::Bit64, 0xc1, 4, dst, insn.imm, None),
                ebpf::LSH64_REG  => emit_shift(self, OperationWidth::Bit64, 4, src, dst),
                ebpf::RSH64_IMM  => emit_alu(self, OperationWidth::Bit64, 0xc1, 5, dst, insn.imm, None),
                ebpf::RSH64_REG  => emit_shift(self, OperationWidth::Bit64, 5, src, dst),
                ebpf::NEG64      => emit_alu(self, OperationWidth::Bit64, 0xf7, 3, dst, 0, None),
                ebpf::XOR64_IMM  => emit_alu(self, OperationWidth::Bit64, 0x81, 6, dst, insn.imm, None),
                ebpf::XOR64_REG  => emit_alu(self, OperationWidth::Bit64, 0x31, src, dst, 0, None),
                ebpf::MOV64_IMM  => emit_load_imm(self, dst, insn.imm as i64),
                ebpf::MOV64_REG  => emit_mov(self, OperationWidth::Bit64, src, dst),
                ebpf::ARSH64_IMM => emit_alu(self, OperationWidth::Bit64, 0xc1, 7, dst, insn.imm, None),
                ebpf::ARSH64_REG => emit_shift(self, OperationWidth::Bit64, 7, src, dst),

                // BPF_JMP class
                ebpf::JA         => {
                    emit_validate_and_profile_instruction_count(self, false, Some(target_pc));
                    emit_jmp(self, target_pc);
                },
                ebpf::JEQ_IMM    => emit_conditional_branch_imm(self, 0x84, insn.imm, dst, target_pc),
                ebpf::JEQ_REG    => emit_conditional_branch_reg(self, 0x84, src, dst, target_pc),
                ebpf::JGT_IMM    => emit_conditional_branch_imm(self, 0x87, insn.imm, dst, target_pc),
                ebpf::JGT_REG    => emit_conditional_branch_reg(self, 0x87, src, dst, target_pc),
                ebpf::JGE_IMM    => emit_conditional_branch_imm(self, 0x83, insn.imm, dst, target_pc),
                ebpf::JGE_REG    => emit_conditional_branch_reg(self, 0x83, src, dst, target_pc),
                ebpf::JLT_IMM    => emit_conditional_branch_imm(self, 0x82, insn.imm, dst, target_pc),
                ebpf::JLT_REG    => emit_conditional_branch_reg(self, 0x82, src, dst, target_pc),
                ebpf::JLE_IMM    => emit_conditional_branch_imm(self, 0x86, insn.imm, dst, target_pc),
                ebpf::JLE_REG    => emit_conditional_branch_reg(self, 0x86, src, dst, target_pc),
                ebpf::JSET_IMM   => {
                    emit_validate_and_profile_instruction_count(self, false, Some(target_pc));
                    emit_alu(self, OperationWidth::Bit64, 0xf7, 0, dst, insn.imm, None);
                    emit_jcc(self, 0x85, target_pc);
                    emit_undo_profile_instruction_count(self, target_pc);
                },
                ebpf::JSET_REG   => {
                    emit_validate_and_profile_instruction_count(self, false, Some(target_pc));
                    emit_alu(self, OperationWidth::Bit64, 0x85, src, dst, 0, None);
                    emit_jcc(self, 0x85, target_pc);
                    emit_undo_profile_instruction_count(self, target_pc);
                },
                ebpf::JNE_IMM    => emit_conditional_branch_imm(self, 0x85, insn.imm, dst, target_pc),
                ebpf::JNE_REG    => emit_conditional_branch_reg(self, 0x85, src, dst, target_pc),
                ebpf::JSGT_IMM   => emit_conditional_branch_imm(self, 0x8f, insn.imm, dst, target_pc),
                ebpf::JSGT_REG   => emit_conditional_branch_reg(self, 0x8f, src, dst, target_pc),
                ebpf::JSGE_IMM   => emit_conditional_branch_imm(self, 0x8d, insn.imm, dst, target_pc),
                ebpf::JSGE_REG   => emit_conditional_branch_reg(self, 0x8d, src, dst, target_pc),
                ebpf::JSLT_IMM   => emit_conditional_branch_imm(self, 0x8c, insn.imm, dst, target_pc),
                ebpf::JSLT_REG   => emit_conditional_branch_reg(self, 0x8c, src, dst, target_pc),
                ebpf::JSLE_IMM   => emit_conditional_branch_imm(self, 0x8e, insn.imm, dst, target_pc),
                ebpf::JSLE_REG   => emit_conditional_branch_reg(self, 0x8e, src, dst, target_pc),
                ebpf::CALL_IMM   => {
                    // For JIT, syscalls MUST be registered at compile time. They can be
                    // updated later, but not created after compiling (we need the address of the
                    // syscall function in the JIT-compiled program).
                    if let Some(syscall) = executable.get_syscall_registry().lookup_syscall(insn.imm as u32) {
                        if self.config.enable_instruction_meter {
                            emit_validate_and_profile_instruction_count(self, true, Some(0));
                            emit_load(self, OperandSize::S64, RBP, R11, -8 * (CALLEE_SAVED_REGISTERS.len() + 2) as i32);
                            emit_alu(self, OperationWidth::Bit64, 0x29, ARGUMENT_REGISTERS[0], R11, 0, None);
                            emit_mov(self, OperationWidth::Bit64, R11, ARGUMENT_REGISTERS[0]);
                            emit_load(self, OperandSize::S64, RBP, R11, -8 * (CALLEE_SAVED_REGISTERS.len() + 3) as i32);
                            emit_rust_call(self, I::consume as *const u8, &[
                                Argument { index: 1, value: Value::Register(ARGUMENT_REGISTERS[0]) },
                                Argument { index: 0, value: Value::Register(R11) },
                            ], None, false);
                        }

                        emit_load(self, OperandSize::S64, R10, RAX, (SYSCALL_CONTEXT_OBJECTS_OFFSET + syscall.context_object_slot) as i32 * 8);
                        emit_rust_call(self, syscall.function as *const u8, &[
                            Argument { index: 0, value: Value::Register(RAX) }, // "&mut self" in the "call" method of the SyscallObject
                            Argument { index: 1, value: Value::Register(ARGUMENT_REGISTERS[1]) },
                            Argument { index: 2, value: Value::Register(ARGUMENT_REGISTERS[2]) },
                            Argument { index: 3, value: Value::Register(ARGUMENT_REGISTERS[3]) },
                            Argument { index: 4, value: Value::Register(ARGUMENT_REGISTERS[4]) },
                            Argument { index: 5, value: Value::Register(ARGUMENT_REGISTERS[5]) },
                            Argument { index: 6, value: Value::Register(R10) }, // JitProgramArgument::memory_mapping
                            Argument { index: 7, value: Value::RegisterIndirect(RBP, -8 * (CALLEE_SAVED_REGISTERS.len() + 1) as i32) }, // Pointer to optional typed return value
                        ], None, true);

                        // Throw error if the result indicates one
                        emit_load_imm(self, R11, self.pc as i64);
                        emit_jcc(self, 0x85, TARGET_PC_SYSCALL_EXCEPTION);

                        // Store Ok value in result register
                        emit_load(self, OperandSize::S64, RBP, R11, -8 * (CALLEE_SAVED_REGISTERS.len() + 1) as i32);
                        emit_load(self, OperandSize::S64, R11, REGISTER_MAP[0], 8);

                        if self.config.enable_instruction_meter {
                            emit_load(self, OperandSize::S64, RBP, R11, -8 * (CALLEE_SAVED_REGISTERS.len() + 3) as i32);
                            emit_rust_call(self, I::get_remaining as *const u8, &[
                                Argument { index: 0, value: Value::Register(R11) },
                            ], Some(ARGUMENT_REGISTERS[0]), false);
                            emit_store(self, OperandSize::S64, ARGUMENT_REGISTERS[0], RBP, -8 * (CALLEE_SAVED_REGISTERS.len() + 2) as i32);
                            emit_undo_profile_instruction_count(self, 0);
                        }
                    } else {
                        match executable.lookup_bpf_call(insn.imm as u32) {
                            Some(target_pc) => {
                                emit_bpf_call(self, Value::Constant64(*target_pc as i64), self.pc_locs.len() - 1);
                            },
                            None => {
                                // executable.report_unresolved_symbol(self.pc)?;
                                // Workaround for unresolved symbols in ELF: Report error at runtime instead of compiletime
                                let fat_ptr: DynTraitFatPointer = unsafe { std::mem::transmute(executable) };
                                emit_rust_call(self, fat_ptr.vtable.methods[9], &[
                                    Argument { index: 0, value: Value::RegisterIndirect(RBP, -8 * (CALLEE_SAVED_REGISTERS.len() + 1) as i32) }, // Pointer to optional typed return value
                                    Argument { index: 1, value: Value::Constant64(fat_ptr.data as i64) },
                                    Argument { index: 2, value: Value::Constant64(self.pc as i64) },
                                ], None, true);
                                emit_load_imm(self, R11, self.pc as i64);
                                emit_jmp(self, TARGET_PC_SYSCALL_EXCEPTION);
                            },
                        }
                    }
                },
                ebpf::CALL_REG  => {
                    emit_bpf_call(self, Value::Register(REGISTER_MAP[insn.imm as usize]), self.pc_locs.len() - 1);
                },
                ebpf::EXIT      => {
                    emit_validate_and_profile_instruction_count(self, true, Some(0));

                    emit_load(self, OperandSize::S64, RBP, REGISTER_MAP[STACK_REG], -8 * CALLEE_SAVED_REGISTERS.len() as i32); // load stack_ptr
                    emit_alu(self, OperationWidth::Bit64, 0x81, 4, REGISTER_MAP[STACK_REG], !(self.config.stack_frame_size as i32 * 2 - 1), None); // stack_ptr &= !(jit.config.stack_frame_size * 2 - 1);
                    emit_alu(self, OperationWidth::Bit64, 0x81, 5, REGISTER_MAP[STACK_REG], self.config.stack_frame_size as i32 * 2, None); // stack_ptr -= jit.config.stack_frame_size * 2;
                    emit_store(self, OperandSize::S64, REGISTER_MAP[STACK_REG], RBP, -8 * CALLEE_SAVED_REGISTERS.len() as i32); // store stack_ptr

                    // if(stack_ptr < MM_STACK_START) goto exit;
                    emit_mov(self, OperationWidth::Bit64, REGISTER_MAP[0], R11);
                    emit_load_imm(self, REGISTER_MAP[0], MM_STACK_START as i64);
                    emit_cmp(self, REGISTER_MAP[0], REGISTER_MAP[STACK_REG], None);
                    emit_mov(self, OperationWidth::Bit64, R11, REGISTER_MAP[0]);
                    emit_jcc(self, 0x82, TARGET_PC_EXIT);

                    // else return;
                    emit1(self, 0xc3); // ret near
                },

                _               => return Err(EbpfError::UnsupportedInstruction(self.pc + ebpf::ELF_INSN_DUMP_OFFSET)),
            }

            self.pc += 1;
        }
        self.pc_locs[self.pc] = self.offset as u64; // Bumper so that the linear search of TARGET_PC_TRANSLATE_PC can not run off

        // Bumper in case there was no final exit
        emit_validate_and_profile_instruction_count(self, true, Some(self.pc + 2));
        emit_load_imm(self, R11, self.pc as i64);
        set_exception_kind::<E>(self, EbpfError::ExecutionOverrun(0));
        emit_jmp(self, TARGET_PC_EXCEPTION_AT);

        self.generate_helper_routines();
        self.generate_exception_handlers::<E>();
        self.generate_epilogue();
        self.resolve_jumps();
        self.truncate_and_set_permissions();

        Ok(())
    }

    fn generate_helper_routines(&mut self) {
        // Routine for instruction tracing
        if self.config.enable_instruction_tracing {
            set_anchor(self, TARGET_PC_TRACE);
            // Save registers on stack
            emit_push(self, R11);
            for reg in REGISTER_MAP.iter().rev() {
                emit_push(self, *reg);
            }
            emit_mov(self, OperationWidth::Bit64, RSP, REGISTER_MAP[0]);
            emit_alu(self, OperationWidth::Bit64, 0x81, 0, RSP, - 8 * 3, None); // RSP -= 8 * 3;
            emit_rust_call(self, Tracer::trace as *const u8, &[
                Argument { index: 0, value: Value::RegisterIndirect(R10, std::mem::size_of::<MemoryMapping>() as i32) }, // jit.tracer
                Argument { index: 1, value: Value::Register(REGISTER_MAP[0]) }, // registers
            ], None, false);
            // Pop stack and return
            emit_alu(self, OperationWidth::Bit64, 0x81, 0, RSP, 8 * 3, None); // RSP += 8 * 3;
            emit_pop(self, REGISTER_MAP[0]);
            emit_alu(self, OperationWidth::Bit64, 0x81, 0, RSP, 8 * (REGISTER_MAP.len() - 1) as i32, None); // RSP += 8 * (REGISTER_MAP.len() - 1);
            emit_pop(self, R11);
            emit1(self, 0xc3); // ret near
        }

        // Translates a host pc back to a BPF pc by linear search of the pc_locs table
        set_anchor(self, TARGET_PC_TRANSLATE_PC);
        emit_push(self, REGISTER_MAP[0]); // Save REGISTER_MAP[0]
        emit_load_imm(self, REGISTER_MAP[0], self.pc_locs.as_ptr() as i64 - 8); // Loop index and pointer to look up
        set_anchor(self, TARGET_PC_TRANSLATE_PC_LOOP); // Loop label
        emit_alu(self, OperationWidth::Bit64, 0x81, 0, REGISTER_MAP[0], 8, None); // Increase index
        emit_cmp(self, R11, REGISTER_MAP[0], Some(0)); // Look up and compare against value at index
        emit_jcc(self, 0x82, TARGET_PC_TRANSLATE_PC_LOOP); // Continue while *REGISTER_MAP[0] < R11
        emit_mov(self, OperationWidth::Bit64, REGISTER_MAP[0], R11); // R11 = REGISTER_MAP[0];
        emit_load_imm(self, REGISTER_MAP[0], self.pc_locs.as_ptr() as i64); // REGISTER_MAP[0] = self.pc_locs;
        emit_alu(self, OperationWidth::Bit64, 0x29, REGISTER_MAP[0], R11, 0, None); // R11 -= REGISTER_MAP[0];
        emit_alu(self, OperationWidth::Bit64, 0xc1, 5, R11, 3, None); // R11 >>= 3;
        emit_pop(self, REGISTER_MAP[0]); // Restore REGISTER_MAP[0]
        emit1(self, 0xc3); // ret near
    }

    fn generate_exception_handlers<E: UserDefinedError>(&mut self) {
        // Handler for EbpfError::ExceededMaxInstructions
        set_anchor(self, TARGET_PC_CALL_EXCEEDED_MAX_INSTRUCTIONS);
        emit_mov(self, OperationWidth::Bit64, ARGUMENT_REGISTERS[0], R11);
        set_exception_kind::<E>(self, EbpfError::ExceededMaxInstructions(0, 0));
        emit_jmp(self, TARGET_PC_EXCEPTION_AT);

        // Handler for EbpfError::CallDepthExceeded
        set_anchor(self, TARGET_PC_CALL_DEPTH_EXCEEDED);
        set_exception_kind::<E>(self, EbpfError::CallDepthExceeded(0, 0));
        emit_store_imm32(self, OperandSize::S64, R10, 24, self.config.max_call_depth as i32); // depth = jit.config.max_call_depth;
        emit_jmp(self, TARGET_PC_EXCEPTION_AT);

        // Handler for EbpfError::CallOutsideTextSegment
        set_anchor(self, TARGET_PC_CALL_OUTSIDE_TEXT_SEGMENT);
        set_exception_kind::<E>(self, EbpfError::CallOutsideTextSegment(0, 0));
        emit_store(self, OperandSize::S64, REGISTER_MAP[0], R10, 24); // target_address = RAX;
        emit_jmp(self, TARGET_PC_EXCEPTION_AT);

        // Handler for EbpfError::DivideByZero
        set_anchor(self, TARGET_PC_DIV_BY_ZERO);
        set_exception_kind::<E>(self, EbpfError::DivideByZero(0));
        emit_jmp(self, TARGET_PC_EXCEPTION_AT);

        // Handler for EbpfError::UnsupportedInstruction
        set_anchor(self, TARGET_PC_UNSUPPORTED_INSTRUCTION);
        emit_call(self, TARGET_PC_TRANSLATE_PC);
        if self.config.enable_instruction_tracing {
            emit_call(self, TARGET_PC_TRACE);
        }
        set_exception_kind::<E>(self, EbpfError::UnsupportedInstruction(0));
        // emit_jmp(self, TARGET_PC_EXCEPTION_AT); // Fall-through

        // Handler for exceptions which report their pc
        set_anchor(self, TARGET_PC_EXCEPTION_AT);
        emit_profile_instruction_count_of_exception(self);
        emit_load(self, OperandSize::S64, RBP, R10, -8 * (CALLEE_SAVED_REGISTERS.len() + 1) as i32);
        emit_store_imm32(self, OperandSize::S64, R10, 0, 1); // is_err = true;
        emit_alu(self, OperationWidth::Bit64, 0x81, 0, R11, ebpf::ELF_INSN_DUMP_OFFSET as i32 - 1, None);
        emit_store(self, OperandSize::S64, R11, R10, 16); // pc = self.pc + ebpf::ELF_INSN_DUMP_OFFSET;
        emit_jmp(self, TARGET_PC_EPILOGUE);

        // Handler for syscall exceptions
        set_anchor(self, TARGET_PC_SYSCALL_EXCEPTION);
        emit_profile_instruction_count_of_exception(self);
        emit_jmp(self, TARGET_PC_EPILOGUE);
    }

    fn generate_prologue<I: InstructionMeter>(&mut self) {
        // Save registers
        for reg in CALLEE_SAVED_REGISTERS.iter() {
            emit_push(self, *reg);
            if *reg == RBP {
                emit_mov(self, OperationWidth::Bit64, RSP, RBP);
            }
        }

        // Save JitProgramArgument
        emit_mov(self, OperationWidth::Bit64, ARGUMENT_REGISTERS[2], R10);

        // Initialize and save BPF stack pointer
        emit_load_imm(self, REGISTER_MAP[STACK_REG], MM_STACK_START as i64 + self.config.stack_frame_size as i64);
        emit_push(self, REGISTER_MAP[STACK_REG]);

        // Save pointer to optional typed return value
        emit_push(self, ARGUMENT_REGISTERS[0]);

        // Save initial instruction meter
        emit_rust_call(self, I::get_remaining as *const u8, &[
            Argument { index: 0, value: Value::Register(ARGUMENT_REGISTERS[3]) },
        ], Some(ARGUMENT_REGISTERS[0]), false);
        emit_push(self, ARGUMENT_REGISTERS[0]);
        emit_push(self, ARGUMENT_REGISTERS[3]);

        // Initialize other registers
        for reg in REGISTER_MAP.iter() {
            if *reg != REGISTER_MAP[1] && *reg != REGISTER_MAP[STACK_REG] {
                emit_load_imm(self, *reg, 0);
            }
        }
    }

    fn generate_epilogue(&mut self) {
        // Quit gracefully
        set_anchor(self, TARGET_PC_EXIT);
        emit_load(self, OperandSize::S64, RBP, R10, -8 * (CALLEE_SAVED_REGISTERS.len() + 1) as i32);
        emit_store(self, OperandSize::S64, REGISTER_MAP[0], R10, 8); // result.return_value = R0;
        emit_load_imm(self, REGISTER_MAP[0], 0);
        emit_store(self, OperandSize::S64, REGISTER_MAP[0], R10, 0);  // result.is_error = false;

        // Epilogue
        set_anchor(self, TARGET_PC_EPILOGUE);

        // Store instruction_meter in RAX
        emit_mov(self, OperationWidth::Bit64, ARGUMENT_REGISTERS[0], RAX);

        // Restore stack pointer in case the BPF stack was used
        emit_mov(self, OperationWidth::Bit64, RBP, R11);
        emit_alu(self, OperationWidth::Bit64, 0x81, 5, R11, 8 * (CALLEE_SAVED_REGISTERS.len()-1) as i32, None);
        emit_mov(self, OperationWidth::Bit64, R11, RSP); // RSP = RBP - 8 * (CALLEE_SAVED_REGISTERS.len() - 1);

        // Restore registers
        for reg in CALLEE_SAVED_REGISTERS.iter().rev() {
            emit_pop(self, *reg);
        }

        emit1(self, 0xc3); // ret near
    }

    fn resolve_jumps(&mut self) {
        for jump in &self.jumps {
            let target_pc = match self.special_targets.get(&jump.target_pc) {
                Some(target) => *target,
                None         => self.pc_locs[jump.target_pc as usize] as usize
            };
            if jump.in_content {
                let offset_value = target_pc as i32
                    - jump.location as i32 // Relative jump
                    - std::mem::size_of::<i32>() as i32; // Jump from end of instruction
                unsafe {
                    libc::memcpy(
                        self.contents.as_ptr().add(jump.location) as *mut libc::c_void,
                        &offset_value as *const i32 as *const libc::c_void,
                        std::mem::size_of::<i32>(),
                    );
                }
            } else {
                self.pc_locs[jump.location] = target_pc as u64;
            }
        }
        for offset in self.pc_locs.iter_mut() {
            *offset = unsafe { (self.contents.as_ptr() as *const u8).add(*offset as usize) } as u64;
        }
    }

    fn truncate_and_set_permissions(&mut self) {
        let _code_size = round_to_page_size(self.offset);
        #[cfg(not(windows))]
        unsafe {
            libc::mprotect(self.pc_locs.as_mut_ptr() as *mut _, self.pc_locs.len(), libc::PROT_READ);
            self.contents = std::slice::from_raw_parts_mut(self.contents.as_mut_ptr() as *mut _, _code_size);
            libc::mprotect(self.contents.as_mut_ptr() as *mut _, self.contents.len(), libc::PROT_EXEC | libc::PROT_READ);
        }
    }
} // struct JitCompiler

impl<'a> Index<usize> for JitCompiler<'a> {
    type Output = u8;

    fn index(&self, _index: usize) -> &u8 {
        &self.contents[_index]
    }
}

impl<'a> IndexMut<usize> for JitCompiler<'a> {
    fn index_mut(&mut self, _index: usize) -> &mut u8 {
        &mut self.contents[_index]
    }
}

impl<'a> std::fmt::Debug for JitCompiler<'a> {
    fn fmt(&self, fmt: &mut Formatter) -> Result<(), FormatterError> {
        fmt.write_str("JIT contents: [")?;
        for i in self.contents as &[u8] {
            fmt.write_fmt(format_args!(" {:#04x},", i))?;
        };
        fmt.write_str(" ] | ")?;
        fmt.debug_struct("JIT state")
            .field("pc", &self.pc)
            .field("offset", &self.offset)
            .field("pc_locs", &self.pc_locs)
            .field("special_targets", &self.special_targets)
            .field("jumps", &self.jumps)
            .finish()
    }
}

pub fn compile<E: UserDefinedError, I: InstructionMeter>(executable: &dyn Executable<E, I>)
    -> Result<JitProgram<E, I>, EbpfError<E>> {

    let program = executable.get_text_bytes()?.1;
    let mut jit = JitCompiler::new(program, executable.get_config());
    jit.compile::<E, I>(executable)?;

    Ok(JitProgram {
        main: unsafe { mem::transmute(jit.contents.as_ptr()) },
    })
}
