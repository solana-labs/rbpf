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

use std;
use std::mem;
use std::collections::HashMap;
use std::fmt::Formatter;
use std::fmt::Error as FormatterError;
use std::ops::{Index, IndexMut};

use crate::{
    vm::{Executable, Syscall, ProgramResult},
    call_frames::{CALL_FRAME_SIZE, MAX_CALL_DEPTH},
    ebpf::{self, INSN_SIZE, FIRST_SCRATCH_REG, SCRATCH_REGS, STACK_REG, MM_STACK_START, MM_PROGRAM_START},
    error::{UserDefinedError, EbpfError},
    memory_region::{AccessType, MemoryMapping},
    user_error::UserError,
};

/// Argument for executing a eBPF JIT-compiled program
pub struct JitProgramArgument {
    /// The MemoryMapping to be used to run the compiled code
    pub memory_mapping: MemoryMapping,
    /// The initial value of the instruction meter
    pub remaining_instructions: u64,
    /// Pointers to the instructions of the compiled code
    pub instruction_addresses: [*const u8; 0],
}

/// eBPF JIT-compiled program
pub struct JitProgram<E: UserDefinedError> {
    /// Call this with JitProgramArgument to execute the compiled code
    pub main: unsafe fn(&ProgramResult<E>, u64, &JitProgramArgument) -> u64,
    /// Pointers to the instructions of the compiled code
    pub instruction_addresses: Vec<*const u8>,
}

/// A virtual method table for SyscallObject
struct SyscallObjectVtable {
    /// Drops the dyn trait object
    pub drop: fn(*const u8),
    /// Size of the dyn trait object in bytes
    pub size: usize,
    /// Alignment of the dyn trait object in bytes
    pub align: usize,
    /// The call method of the SyscallObject
    pub call: *const u8,
}

// Could be replaced by https://doc.rust-lang.org/std/raw/struct.TraitObject.html
/// A dyn trait fat pointer for SyscallObject
struct SyscallTraitObject {
    /// Pointer to the actual object
    pub data: *const u8,
    /// Pointer to the virtual method table
    pub vtable: *const SyscallObjectVtable,
}

// Special values for target_pc in struct Jump
const TARGET_OFFSET: usize = ebpf::PROG_MAX_INSNS;
const TARGET_PC_EXIT: usize = TARGET_OFFSET + 1;
const TARGET_PC_EPILOGUE: usize = TARGET_OFFSET + 2;
const TARGET_PC_CALL_EXCEEDED_MAX_INSTRUCTIONS: usize = TARGET_OFFSET + 3;
const TARGET_PC_CALL_DEPTH_EXCEEDED: usize = TARGET_OFFSET + 4;
const TARGET_PC_CALL_OUTSIDE_TEXT_SEGMENT: usize = TARGET_OFFSET + 5;
const TARGET_PC_DIV_BY_ZERO: usize = TARGET_OFFSET + 6;
const TARGET_PC_EXCEPTION_AT: usize = TARGET_OFFSET + 7;
const TARGET_PC_SYSCALL_EXCEPTION: usize = TARGET_OFFSET + 8;

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
// RDI Pointer to optional typed return value
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

// Return the x86 register for the given eBPF register
fn map_register(r: u8) -> u8 {
    assert!(r < REGISTER_MAP.len() as u8);
    REGISTER_MAP[(r % REGISTER_MAP.len() as u8) as usize]
}

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
fn emit_mov(jit: &mut JitCompiler, src: u8, dst: u8) {
    emit_alu(jit, OperationWidth::Bit64, 0x89, src, dst, 0, None);
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
    let jump = Jump { offset_loc: jit.offset, target_pc };
    jit.jumps.push(jump);
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
    if jit.enable_instruction_meter {
        match target_pc {
            Some(target_pc) => {
                emit_alu(jit, OperationWidth::Bit64, 0x81, 0, RBP, target_pc as i32 - jit.pc as i32 - 1, Some(-8 * (CALLEE_SAVED_REGISTERS.len() + 1) as i32)); // instruction_meter += target_pc - (jit.pc + 1);
            },
            None => { // If no constant target_pc is given, it is expected to be on the stack instead
                emit_pop(jit, R11);
                emit_alu(jit, OperationWidth::Bit64, 0x81, 5, RBP, jit.pc as i32 + 1, Some(-8 * (CALLEE_SAVED_REGISTERS.len() + 1) as i32)); // instruction_meter -= jit.pc + 1;
                emit_alu(jit, OperationWidth::Bit64, 0x01, R11, RBP, jit.pc as i32, Some(-8 * (CALLEE_SAVED_REGISTERS.len() + 1) as i32)); // instruction_meter += target_pc;
            },
        }
    }
}

#[inline]
fn emit_validate_and_profile_instruction_count(jit: &mut JitCompiler, target_pc: Option<usize>) {
    if jit.enable_instruction_meter {
        emit_load(jit, OperandSize::S64, RBP, R11, -8 * (CALLEE_SAVED_REGISTERS.len() + 1) as i32);
        emit_cmp_imm32(jit, R11, jit.pc as i32 + 1, None);
        emit_jcc(jit, 0x82, TARGET_PC_CALL_EXCEEDED_MAX_INSTRUCTIONS);
        emit_profile_instruction_count(jit, target_pc);
    }
}

#[inline]
fn emit_undo_profile_instruction_count(jit: &mut JitCompiler, target_pc: usize) {
    if jit.enable_instruction_meter {
        emit_alu(jit, OperationWidth::Bit64, 0x81, 0, RBP, jit.pc as i32 + 1 - target_pc as i32, Some(-8 * (CALLEE_SAVED_REGISTERS.len() + 1) as i32)); // instruction_meter += (jit.pc + 1) - target_pc;
    }
}

#[inline]
fn emit_profile_instruction_count_of_exception(jit: &mut JitCompiler) {
    emit_alu(jit, OperationWidth::Bit64, 0x81, 0, R11, 1, None);
    if jit.enable_instruction_meter {
        emit_alu(jit, OperationWidth::Bit64, 0x29, R11, RBP, 0, Some(-8 * (CALLEE_SAVED_REGISTERS.len() + 1) as i32)); // instruction_meter -= pc + 1;
    }
}

#[inline]
fn emit_conditional_branch_reg(jit: &mut JitCompiler, op: u8, src: u8, dst: u8, target_pc: usize) {
    emit_validate_and_profile_instruction_count(jit, Some(target_pc));
    emit_cmp(jit, src, dst, None);
    emit_jcc(jit, op, target_pc);
    emit_undo_profile_instruction_count(jit, target_pc);
}

#[inline]
fn emit_conditional_branch_imm(jit: &mut JitCompiler, op: u8, imm: i32, dst: u8, target_pc: usize) {
    emit_validate_and_profile_instruction_count(jit, Some(target_pc));
    emit_cmp_imm32(jit, dst, imm, None);
    emit_jcc(jit, op, target_pc);
    emit_undo_profile_instruction_count(jit, target_pc);
}

enum Value {
    Register(u8),
    RegisterPlusConstant(u8, i64),
    Constant(i64)
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
            emit_mov(jit, reg, REGISTER_MAP[0]);
            // Force alignment of RAX
            emit_alu(jit, OperationWidth::Bit64, 0x81, 4, REGISTER_MAP[0], !(INSN_SIZE as i32 - 1), None); // RAX &= !(INSN_SIZE - 1, None);
            // Store PC in case the bounds check fails
            emit_load_imm(jit, R11, jit.pc as i64);
            // Upper bound check
            // if(RAX >= MM_PROGRAM_START + number_of_instructions * INSN_SIZE) throw CALL_OUTSIDE_TEXT_SEGMENT;
            emit_load_imm(jit, REGISTER_MAP[STACK_REG], MM_PROGRAM_START as i64 + (number_of_instructions * INSN_SIZE) as i64);
            emit_cmp(jit, REGISTER_MAP[STACK_REG], REGISTER_MAP[0], None);
            emit_jcc(jit, 0x83, TARGET_PC_CALL_OUTSIDE_TEXT_SEGMENT);
            // Lower bound check
            // if(RAX < MM_PROGRAM_START) throw CALL_OUTSIDE_TEXT_SEGMENT;
            emit_load_imm(jit, REGISTER_MAP[STACK_REG], MM_PROGRAM_START as i64);
            emit_cmp(jit, REGISTER_MAP[STACK_REG], REGISTER_MAP[0], None);
            emit_jcc(jit, 0x82, TARGET_PC_CALL_OUTSIDE_TEXT_SEGMENT);
            // Calculate offset relative to instruction_addresses
            emit_alu(jit, OperationWidth::Bit64, 0x29, REGISTER_MAP[STACK_REG], REGISTER_MAP[0], 0, None); // RAX -= MM_PROGRAM_START;
            if jit.enable_instruction_meter {
                // Calculate the target_pc to update the instruction_meter
                let shift_amount = INSN_SIZE.trailing_zeros();
                assert_eq!(INSN_SIZE, 1<<shift_amount);
                emit_mov(jit, REGISTER_MAP[0], REGISTER_MAP[STACK_REG]);
                emit_alu(jit, OperationWidth::Bit64, 0xc1, 5, REGISTER_MAP[STACK_REG], shift_amount as i32, None);
                emit_push(jit, REGISTER_MAP[STACK_REG]);
            }
            // Load host target_address from JitProgramArgument.instruction_addresses
            assert_eq!(INSN_SIZE, 8); // Because the instruction size is also the slot size we do not need to shift the offset
            emit_mov(jit, REGISTER_MAP[0], REGISTER_MAP[STACK_REG]);
            emit_mov(jit, R10, REGISTER_MAP[STACK_REG]);
            emit_alu(jit, OperationWidth::Bit64, 0x01, REGISTER_MAP[STACK_REG], REGISTER_MAP[0], 0, None); // RAX += &JitProgramArgument as *const _;
            emit_load(jit, OperandSize::S64, REGISTER_MAP[0], REGISTER_MAP[0], std::mem::size_of::<JitProgramArgument>() as i32); // RAX = JitProgramArgument.instruction_addresses[RAX / 8];
        },
        Value::Constant(_target_pc) => {},
        _ => panic!()
    }

    emit_load(jit, OperandSize::S64, RBP, REGISTER_MAP[STACK_REG], -8 * CALLEE_SAVED_REGISTERS.len() as i32); // load stack_ptr
    emit_alu(jit, OperationWidth::Bit64, 0x81, 4, REGISTER_MAP[STACK_REG], !(CALL_FRAME_SIZE as i32 * 2 - 1), None); // stack_ptr &= !(CALL_FRAME_SIZE * 2 - 1, None);
    emit_alu(jit, OperationWidth::Bit64, 0x81, 0, REGISTER_MAP[STACK_REG], CALL_FRAME_SIZE as i32 * 3, None); // stack_ptr += CALL_FRAME_SIZE * 3;
    emit_store(jit, OperandSize::S64, REGISTER_MAP[STACK_REG], RBP, -8 * CALLEE_SAVED_REGISTERS.len() as i32); // store stack_ptr

    // if(stack_ptr >= MM_STACK_START + MAX_CALL_DEPTH * CALL_FRAME_SIZE * 2) throw EbpfError::CallDepthExeeded;
    emit_load_imm(jit, R11, MM_STACK_START as i64 + (MAX_CALL_DEPTH * CALL_FRAME_SIZE * 2) as i64);
    emit_cmp(jit, R11, REGISTER_MAP[STACK_REG], None);
    // Store PC in case the bounds check fails
    emit_load_imm(jit, R11, jit.pc as i64);
    emit_jcc(jit, 0x83, TARGET_PC_CALL_DEPTH_EXCEEDED);

    match dst {
        Value::Register(_reg) => {
            emit_validate_and_profile_instruction_count(jit, None);
            // callq *%rax
            emit1(jit, 0xff);
            emit1(jit, 0xd0);
        },
        Value::Constant(target_pc) => {
            emit_validate_and_profile_instruction_count(jit, Some(target_pc as usize));
            emit1(jit, 0xe8);
            emit_jump_offset(jit, target_pc as usize);
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
fn emit_rust_call(jit: &mut JitCompiler, function: *const u8, arguments: &[Argument]) {
    let mut saved_registers = CALLER_SAVED_REGISTERS.to_vec();

    // Pass arguments via stack
    for argument in arguments {
        if argument.index < ARGUMENT_REGISTERS.len() {
            continue;
        }
        match argument.value {
            Value::Register(reg) => {
                let src = saved_registers.iter().position(|x| *x == reg).unwrap();
                saved_registers.remove(src);
                let dst = saved_registers.len()-(argument.index-ARGUMENT_REGISTERS.len());
                saved_registers.insert(dst, reg);
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
                    emit_mov(jit, reg, dst);
                }
            },
            Value::RegisterPlusConstant(reg, offset) => {
                emit_load_imm(jit, R11, offset);
                emit_alu(jit, OperationWidth::Bit64, 0x01, reg, R11, 0, None);
                emit_mov(jit, R11, dst);
            },
            Value::Constant(value) => {
                emit_load_imm(jit, dst, value);
            },
        }
    }

    // TODO use direct call when possible
    emit_load_imm(jit, RAX, function as i64);
    // callq *%rax
    emit1(jit, 0xff);
    emit1(jit, 0xd0);

    // Restore registers from stack
    for reg in saved_registers.iter().rev() {
        emit_pop(jit, *reg);
    }

    // Test if result indicates that an error occured
    emit_cmp_imm32(jit, RDI, 0, Some(0));
}

#[inline]
fn emit_address_translation(jit: &mut JitCompiler, host_addr: u8, vm_addr: Value, len: u64, access_type: AccessType) {
    emit_rust_call(jit, MemoryMapping::map::<UserError> as *const u8, &[
        Argument { index: 3, value: vm_addr }, // Specify first as the src register could be overwritten by other arguments
        Argument { index: 1, value: Value::Register(R10) }, // JitProgramArgument::memory_mapping
        Argument { index: 2, value: Value::Constant(access_type as i64) },
        Argument { index: 4, value: Value::Constant(len as i64) },
    ]);

    // Throw error if the result indicates one
    emit_load_imm(jit, R11, jit.pc as i64);
    emit_jcc(jit, 0x85, TARGET_PC_EXCEPTION_AT);

    // Store Ok value in result register
    emit_load(jit, OperandSize::S64, RDI, host_addr, 8);
}

fn muldivmod(jit: &mut JitCompiler, opc: u8, src: u8, dst: u8, imm: i32) {
    let mul = (opc & ebpf::BPF_ALU_OP_MASK) == (ebpf::MUL32_IMM & ebpf::BPF_ALU_OP_MASK);
    let div = (opc & ebpf::BPF_ALU_OP_MASK) == (ebpf::DIV32_IMM & ebpf::BPF_ALU_OP_MASK);
    let modrm = (opc & ebpf::BPF_ALU_OP_MASK) == (ebpf::MOD32_IMM & ebpf::BPF_ALU_OP_MASK);
    let is64 = (opc & ebpf::BPF_CLS_MASK) == ebpf::BPF_ALU64;

    if div || modrm {
        // Save pc
        emit_load_imm(jit, R11, jit.pc as i64);

        // test src,src
        if is64 {
            emit_alu(jit, OperationWidth::Bit64, 0x85, src, src, 0, None);
        } else {
            emit_alu(jit, OperationWidth::Bit32, 0x85, src, src, 0, None);
        }

        // Jump if src is zero
        emit_jcc(jit, 0x84, TARGET_PC_DIV_BY_ZERO);
    }

    if dst != RAX {
        emit_push(jit, RAX);
    }
    if dst != RDX {
        emit_push(jit, RDX);
    }
    emit_mov(jit, RCX, R11);

    if imm != 0 {
        emit_load_imm(jit, RCX, imm as i64);
    } else {
        emit_mov(jit, src, RCX);
    }

    if dst != RAX {
        emit_mov(jit, dst, RAX);
    }

    if div || modrm {
        // xor %edx,%edx
        emit_alu(jit, OperationWidth::Bit32, 0x31, RDX, RDX, 0, None);
    }

    if is64 {
        emit_rex(jit, 1, 0, 0, 0);
    }

    // mul %ecx or div %ecx
    emit_alu(jit, OperationWidth::Bit32, 0xf7, if mul { 4 } else { 6 }, RCX, 0, None);

    emit_mov(jit, R11, RCX);
    if dst != RDX {
        if modrm {
            emit_mov(jit, RDX, dst);
        }
        emit_pop(jit, RDX);
    }
    if dst != RAX {
        if div || mul {
            emit_mov(jit, RAX, dst);
        }
        emit_pop(jit, RAX);
    }
}

#[inline]
fn set_exception_kind<E: UserDefinedError>(jit: &mut JitCompiler, err: EbpfError<E>) {
    let err = Result::<u64, EbpfError<E>>::Err(err);
    let err_kind = unsafe { *(&err as *const _ as *const u64).offset(1) };
    emit_store_imm32(jit, OperandSize::S64, RDI, 8, err_kind as i32);
}

#[derive(Debug)]
struct Jump {
    offset_loc: usize,
    target_pc: usize,
}

struct JitCompiler<'a> {
    contents: &'a mut [u8],
    offset: usize,
    pc: usize,
    pc_locs: Vec<usize>,
    special_targets: HashMap<usize, usize>,
    jumps: Vec<Jump>,
    enable_instruction_meter: bool,
}

impl<'a> JitCompiler<'a> {
    // num_pages is unused on windows
    fn new(_num_pages: usize, _enable_instruction_meter: bool) -> JitCompiler<'a> {
        #[cfg(windows)]
        {
            panic!("JIT not supported on windows");
        }
        let contents: &mut[u8];
        #[cfg(not(windows))] // Without this block windows will fail ungracefully, hence the panic above
        unsafe {
            const PAGE_SIZE: usize = 4096;
            let size = _num_pages * PAGE_SIZE;
            let mut raw: *mut libc::c_void = std::mem::MaybeUninit::uninit().assume_init();
            libc::posix_memalign(&mut raw, PAGE_SIZE, size);
            libc::mprotect(raw, size, libc::PROT_EXEC | libc::PROT_READ | libc::PROT_WRITE);
            std::ptr::write_bytes(raw, 0xcc, size); // Populate with debugger traps
            contents = std::slice::from_raw_parts_mut(raw as *mut u8, _num_pages * PAGE_SIZE);
        }

        JitCompiler {
            contents,
            offset: 0,
            pc: 0,
            pc_locs: vec![],
            jumps: vec![],
            special_targets: HashMap::new(),
            enable_instruction_meter: _enable_instruction_meter,
        }
    }

    fn compile<E: UserDefinedError>(&mut self, prog: &[u8],
                   executable: &'a dyn Executable<E>,
                   syscalls: &HashMap<u32,  Syscall<'a, E>>) -> Result<(), EbpfError<E>> {
        // Save registers
        for reg in CALLEE_SAVED_REGISTERS.iter() {
            emit_push(self, *reg);
            if *reg == RBP {
                emit_mov(self, RSP, RBP);
            }
        }

        // Save JitProgramArgument
        emit_mov(self, ARGUMENT_REGISTERS[2], R10);

        // Initialize and save BPF stack pointer
        emit_load_imm(self, REGISTER_MAP[STACK_REG], MM_STACK_START as i64 + CALL_FRAME_SIZE as i64);
        emit_push(self, REGISTER_MAP[STACK_REG]);

        // Initialize instruction meter
        emit_load(self, OperandSize::S64, R10, ARGUMENT_REGISTERS[3], std::mem::size_of::<MemoryMapping>() as i32);
        emit_push(self, ARGUMENT_REGISTERS[3]);

        // Initialize other registers
        for reg in REGISTER_MAP.iter() {
            if *reg != REGISTER_MAP[1] && *reg != REGISTER_MAP[STACK_REG] {
                emit_load_imm(self, *reg, 0);
            }
        }

        let entry = executable.get_entrypoint_instruction_offset().unwrap();
        if entry != 0 {
            emit_profile_instruction_count(self, Some(entry + 1));
            emit_jmp(self, entry);
        }

        self.pc_locs = vec![0; prog.len() / ebpf::INSN_SIZE + 1];

        while self.pc * ebpf::INSN_SIZE < prog.len() {
            let insn = ebpf::get_insn(prog, self.pc);

            self.pc_locs[self.pc] = self.offset;

            let dst = map_register(insn.dst);
            let src = map_register(insn.src);
            let target_pc = (self.pc as isize + insn.off as isize + 1) as usize;

            match insn.opc {

                // BPF_LD class
                ebpf::LD_ABS_B   => {
                    emit_address_translation(self, R11, Value::Constant(insn.imm as i64 + ebpf::MM_INPUT_START as i64), 1, AccessType::Load);
                    emit_load(self, OperandSize::S8, R11, RAX, 0);
                },
                ebpf::LD_ABS_H   => {
                    emit_address_translation(self, R11, Value::Constant(insn.imm as i64 + ebpf::MM_INPUT_START as i64), 2, AccessType::Load);
                    emit_load(self, OperandSize::S16, R11, RAX, 0);
                },
                ebpf::LD_ABS_W   => {
                    emit_address_translation(self, R11, Value::Constant(insn.imm as i64 + ebpf::MM_INPUT_START as i64), 4, AccessType::Load);
                    emit_load(self, OperandSize::S32, R11, RAX, 0);
                },
                ebpf::LD_ABS_DW  => {
                    emit_address_translation(self, R11, Value::Constant(insn.imm as i64 + ebpf::MM_INPUT_START as i64), 8, AccessType::Load);
                    emit_load(self, OperandSize::S64, R11, RAX, 0);
                },
                ebpf::LD_IND_B   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant(src, insn.imm as i64 + ebpf::MM_INPUT_START as i64), 1, AccessType::Load);
                    emit_load(self, OperandSize::S8, R11, RAX, 0);
                },
                ebpf::LD_IND_H   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant(src, insn.imm as i64 + ebpf::MM_INPUT_START as i64), 2, AccessType::Load);
                    emit_load(self, OperandSize::S16, R11, RAX, 0);
                },
                ebpf::LD_IND_W   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant(src, insn.imm as i64 + ebpf::MM_INPUT_START as i64), 4, AccessType::Load);
                    emit_load(self, OperandSize::S32, R11, RAX, 0);
                },
                ebpf::LD_IND_DW  => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant(src, insn.imm as i64 + ebpf::MM_INPUT_START as i64), 8, AccessType::Load);
                    emit_load(self, OperandSize::S64, R11, RAX, 0);
                },

                ebpf::LD_DW_IMM  => {
                    emit_validate_and_profile_instruction_count(self, Some(self.pc + 2));
                    self.pc += 1;
                    let second_part = ebpf::get_insn(prog, self.pc).imm as u64;
                    let imm = (insn.imm as u32) as u64 | second_part.wrapping_shl(32);
                    emit_load_imm(self, dst, imm as i64);
                },

                // BPF_LDX class
                ebpf::LD_B_REG   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant(src, insn.off as i64), 1, AccessType::Load);
                    emit_load(self, OperandSize::S8, R11, dst, 0);
                },
                ebpf::LD_H_REG   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant(src, insn.off as i64), 2, AccessType::Load);
                    emit_load(self, OperandSize::S16, R11, dst, 0);
                },
                ebpf::LD_W_REG   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant(src, insn.off as i64), 4, AccessType::Load);
                    emit_load(self, OperandSize::S32, R11, dst, 0);
                },
                ebpf::LD_DW_REG  => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant(src, insn.off as i64), 8, AccessType::Load);
                    emit_load(self, OperandSize::S64, R11, dst, 0);
                },

                // BPF_ST class
                ebpf::ST_B_IMM   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant(dst, insn.off as i64), 1, AccessType::Store);
                    emit_store_imm32(self, OperandSize::S8, R11, 0, insn.imm);
                },
                ebpf::ST_H_IMM   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant(dst, insn.off as i64), 2, AccessType::Store);
                    emit_store_imm32(self, OperandSize::S16, R11, 0, insn.imm);
                },
                ebpf::ST_W_IMM   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant(dst, insn.off as i64), 4, AccessType::Store);
                    emit_store_imm32(self, OperandSize::S32, R11, 0, insn.imm);
                },
                ebpf::ST_DW_IMM  => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant(dst, insn.off as i64), 8, AccessType::Store);
                    emit_store_imm32(self, OperandSize::S64, R11, 0, insn.imm);
                },

                // BPF_STX class
                ebpf::ST_B_REG  => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant(dst, insn.off as i64), 1, AccessType::Store);
                    emit_store(self, OperandSize::S8, src, R11, 0);
                },
                ebpf::ST_H_REG  => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant(dst, insn.off as i64), 2, AccessType::Store);
                    emit_store(self, OperandSize::S16, src, R11, 0);
                },
                ebpf::ST_W_REG  => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant(dst, insn.off as i64), 4, AccessType::Store);
                    emit_store(self, OperandSize::S32, src, R11, 0);
                },
                ebpf::ST_DW_REG  => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant(dst, insn.off as i64), 8, AccessType::Store);
                    emit_store(self, OperandSize::S64, src, R11, 0);
                },

                // BPF_ALU class
                ebpf::ADD32_IMM  => emit_alu(self, OperationWidth::Bit32, 0x81, 0, dst, insn.imm, None),
                ebpf::ADD32_REG  => emit_alu(self, OperationWidth::Bit32, 0x01, src, dst, 0, None),
                ebpf::SUB32_IMM  => emit_alu(self, OperationWidth::Bit32, 0x81, 5, dst, insn.imm, None),
                ebpf::SUB32_REG  => emit_alu(self, OperationWidth::Bit32, 0x29, src, dst, 0, None),
                ebpf::MUL32_IMM | ebpf::MUL32_REG |
                    ebpf::DIV32_IMM | ebpf::DIV32_REG |
                    ebpf::MOD32_IMM | ebpf::MOD32_REG =>
                    muldivmod(self, insn.opc, src, dst, insn.imm),
                ebpf::OR32_IMM   => emit_alu(self, OperationWidth::Bit32, 0x81, 1, dst, insn.imm, None),
                ebpf::OR32_REG   => emit_alu(self, OperationWidth::Bit32, 0x09, src, dst, 0, None),
                ebpf::AND32_IMM  => emit_alu(self, OperationWidth::Bit32, 0x81, 4, dst, insn.imm, None),
                ebpf::AND32_REG  => emit_alu(self, OperationWidth::Bit32, 0x21, src, dst, 0, None),
                ebpf::LSH32_IMM  => emit_alu(self, OperationWidth::Bit32, 0xc1, 4, dst, insn.imm, None),
                ebpf::LSH32_REG  => {
                    emit_xchg(self, src, RCX);
                    emit_alu(self, OperationWidth::Bit64, 0x81, 4, RCX, 31, None); // Mask shift amount
                    emit_alu(self, OperationWidth::Bit32, 0xd3, 4, dst, 0, None);
                    emit_xchg(self, RCX, src);
                },
                ebpf::RSH32_IMM  => emit_alu(self, OperationWidth::Bit32, 0xc1, 5, dst, insn.imm, None),
                ebpf::RSH32_REG  => {
                    emit_xchg(self, src, RCX);
                    emit_alu(self, OperationWidth::Bit64, 0x81, 4, RCX, 31, None); // Mask shift amount
                    emit_alu(self, OperationWidth::Bit32, 0xd3, 5, dst, 0, None);
                    emit_xchg(self, RCX, src);
                },
                ebpf::NEG32      => emit_alu(self, OperationWidth::Bit32, 0xf7, 3, dst, 0, None),
                ebpf::XOR32_IMM  => emit_alu(self, OperationWidth::Bit32, 0x81, 6, dst, insn.imm, None),
                ebpf::XOR32_REG  => emit_alu(self, OperationWidth::Bit32, 0x31, src, dst, 0, None),
                ebpf::MOV32_IMM  => emit_alu(self, OperationWidth::Bit32, 0xc7, 0, dst, insn.imm, None),
                ebpf::MOV32_REG  => emit_mov(self, src, dst),
                ebpf::ARSH32_IMM => emit_alu(self, OperationWidth::Bit32, 0xc1, 7, dst, insn.imm, None),
                ebpf::ARSH32_REG => {
                    emit_xchg(self, src, RCX);
                    emit_alu(self, OperationWidth::Bit64, 0x81, 4, RCX, 31, None); // Mask shift amount
                    emit_alu(self, OperationWidth::Bit32, 0xd3, 7, dst, 0, None);
                    emit_xchg(self, RCX, src);
                },
                ebpf::LE         => {}, // No-op
                ebpf::BE         => {
                    match insn.imm {
                        16 => {
                            // rol
                            emit1(self, 0x66); // 16-bit override
                            emit_alu(self, OperationWidth::Bit32, 0xc1, 0, dst, 8, None);
                            // and
                            emit_alu(self, OperationWidth::Bit32, 0x81, 4, dst, 0xffff, None);
                        }
                        32 | 64 => {
                            // bswap
                            let bit = match insn.imm { 64 => 1, _ => 0 };
                            emit_basic_rex(self, bit, 0, dst);
                            emit1(self, 0x0f);
                            emit1(self, 0xc8 | (dst & 0b111));
                        }
                        _ => unreachable!() // Should have been caught by verifier
                    }
                },

                // BPF_ALU64 class
                ebpf::ADD64_IMM  => emit_alu(self, OperationWidth::Bit64, 0x81, 0, dst, insn.imm, None),
                ebpf::ADD64_REG  => emit_alu(self, OperationWidth::Bit64, 0x01, src, dst, 0, None),
                ebpf::SUB64_IMM  => emit_alu(self, OperationWidth::Bit64, 0x81, 5, dst, insn.imm, None),
                ebpf::SUB64_REG  => emit_alu(self, OperationWidth::Bit64, 0x29, src, dst, 0, None),
                ebpf::MUL64_IMM | ebpf::MUL64_REG |
                    ebpf::DIV64_IMM | ebpf::DIV64_REG |
                    ebpf::MOD64_IMM | ebpf::MOD64_REG  =>
                    muldivmod(self, insn.opc, src, dst, insn.imm),
                ebpf::OR64_IMM   => emit_alu(self, OperationWidth::Bit64, 0x81, 1, dst, insn.imm, None),
                ebpf::OR64_REG   => emit_alu(self, OperationWidth::Bit64, 0x09, src, dst, 0, None),
                ebpf::AND64_IMM  => emit_alu(self, OperationWidth::Bit64, 0x81, 4, dst, insn.imm, None),
                ebpf::AND64_REG  => emit_alu(self, OperationWidth::Bit64, 0x21, src, dst, 0, None),
                ebpf::LSH64_IMM  => emit_alu(self, OperationWidth::Bit64, 0xc1, 4, dst, insn.imm, None),
                ebpf::LSH64_REG  => {
                    emit_xchg(self, src, RCX);
                    emit_alu(self, OperationWidth::Bit64, 0x81, 4, RCX, 63, None); // Mask shift amount
                    emit_alu(self, OperationWidth::Bit64, 0xd3, 4, dst, 0, None);
                    emit_xchg(self, RCX, src);
                },
                ebpf::RSH64_IMM  => emit_alu(self, OperationWidth::Bit64, 0xc1, 5, dst, insn.imm, None),
                ebpf::RSH64_REG  => {
                    emit_xchg(self, src, RCX);
                    emit_alu(self, OperationWidth::Bit64, 0x81, 4, RCX, 63, None); // Mask shift amount
                    emit_alu(self, OperationWidth::Bit64, 0xd3, 5, dst, 0, None);
                    emit_xchg(self, RCX, src);
                },
                ebpf::NEG64      => emit_alu(self, OperationWidth::Bit64, 0xf7, 3, dst, 0, None),
                ebpf::XOR64_IMM  => emit_alu(self, OperationWidth::Bit64, 0x81, 6, dst, insn.imm, None),
                ebpf::XOR64_REG  => emit_alu(self, OperationWidth::Bit64, 0x31, src, dst, 0, None),
                ebpf::MOV64_IMM  => emit_load_imm(self, dst, insn.imm as i64),
                ebpf::MOV64_REG  => emit_mov(self, src, dst),
                ebpf::ARSH64_IMM => emit_alu(self, OperationWidth::Bit64, 0xc1, 7, dst, insn.imm, None),
                ebpf::ARSH64_REG => {
                    emit_xchg(self, src, RCX);
                    emit_alu(self, OperationWidth::Bit64, 0x81, 4, RCX, 63, None); // Mask shift amount
                    emit_alu(self, OperationWidth::Bit64, 0xd3, 7, dst, 0, None);
                    emit_xchg(self, RCX, src);
                },

                // BPF_JMP class
                ebpf::JA         => {
                    emit_validate_and_profile_instruction_count(self, Some(target_pc));
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
                    emit_validate_and_profile_instruction_count(self, Some(target_pc));
                    emit_alu(self, OperationWidth::Bit64, 0xf7, 0, dst, insn.imm, None);
                    emit_jcc(self, 0x85, target_pc);
                    emit_undo_profile_instruction_count(self, target_pc);
                },
                ebpf::JSET_REG   => {
                    emit_validate_and_profile_instruction_count(self, Some(target_pc));
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
                    if let Some(syscall) = syscalls.get(&(insn.imm as u32)) {
                        match syscall {
                            Syscall::Function(func) => {
                                emit_rust_call(self, *func as *const u8, &[
                                    Argument { index: 1, value: Value::Register(ARGUMENT_REGISTERS[1]) },
                                    Argument { index: 2, value: Value::Register(ARGUMENT_REGISTERS[2]) },
                                    Argument { index: 3, value: Value::Register(ARGUMENT_REGISTERS[3]) },
                                    Argument { index: 4, value: Value::Register(ARGUMENT_REGISTERS[4]) },
                                    Argument { index: 5, value: Value::Register(ARGUMENT_REGISTERS[5]) },
                                    Argument { index: 6, value: Value::Register(R10) }, // JitProgramArgument::memory_mapping
                                ]);
                            },
                            Syscall::Object(boxed) => {
                                let fat_ptr_ptr = unsafe { std::mem::transmute::<_, *const *const SyscallTraitObject>(&boxed) };
                                let fat_ptr = unsafe { std::mem::transmute::<_, *const SyscallTraitObject>(*fat_ptr_ptr) };
                                let vtable = unsafe { std::mem::transmute::<_, &SyscallObjectVtable>(&*(*fat_ptr).vtable) };
                                // We need to displace the arguments by one in upward direction to make room for "&mut self".
                                // Therefore, we Specify register arguments in reverse order, so that the move instructions do not overwrite each other.
                                // This only affects the order of the move instructions, not the arguments.
                                emit_rust_call(self, vtable.call, &[
                                    Argument { index: 5, value: Value::Register(ARGUMENT_REGISTERS[4]) },
                                    Argument { index: 4, value: Value::Register(ARGUMENT_REGISTERS[3]) },
                                    Argument { index: 3, value: Value::Register(ARGUMENT_REGISTERS[2]) },
                                    Argument { index: 2, value: Value::Register(ARGUMENT_REGISTERS[1]) },
                                    Argument { index: 1, value: Value::Constant(unsafe { (*fat_ptr).data } as i64) }, // "&mut self" in the "call" method of the SyscallObject
                                    Argument { index: 6, value: Value::Register(ARGUMENT_REGISTERS[5]) },
                                    Argument { index: 7, value: Value::Register(R10) }, // JitProgramArgument::memory_mapping
                                ]);
                            },
                        }

                        // Throw error if the result indicates one
                        emit_load_imm(self, R11, self.pc as i64);
                        emit_jcc(self, 0x85, TARGET_PC_SYSCALL_EXCEPTION);

                        // Store Ok value in result register
                        emit_load(self, OperandSize::S64, RDI, REGISTER_MAP[0], 8);
                    } else {
                        match executable.lookup_bpf_call(insn.imm as u32) {
                            Some(target_pc) => {
                                emit_bpf_call(self, Value::Constant(*target_pc as i64), prog.len() / ebpf::INSN_SIZE);
                            },
                            None => executable.report_unresolved_symbol(self.pc)?,
                        }
                    }
                },
                ebpf::CALL_REG  => {
                    emit_bpf_call(self, Value::Register(REGISTER_MAP[insn.imm as usize]), prog.len() / ebpf::INSN_SIZE);
                },
                ebpf::EXIT      => {
                    emit_validate_and_profile_instruction_count(self, Some(0));

                    emit_load(self, OperandSize::S64, RBP, REGISTER_MAP[STACK_REG], -8 * CALLEE_SAVED_REGISTERS.len() as i32); // load stack_ptr
                    emit_alu(self, OperationWidth::Bit64, 0x81, 4, REGISTER_MAP[STACK_REG], !(CALL_FRAME_SIZE as i32 * 2 - 1), None); // stack_ptr &= !(CALL_FRAME_SIZE * 2 - 1, None);
                    emit_alu(self, OperationWidth::Bit64, 0x81, 5, REGISTER_MAP[STACK_REG], CALL_FRAME_SIZE as i32 * 2, None); // stack_ptr -= CALL_FRAME_SIZE * 2;
                    emit_store(self, OperandSize::S64, REGISTER_MAP[STACK_REG], RBP, -8 * CALLEE_SAVED_REGISTERS.len() as i32); // store stack_ptr

                    // if(stack_ptr < MM_STACK_START) goto exit;
                    emit_mov(self, REGISTER_MAP[0], R11);
                    emit_load_imm(self, REGISTER_MAP[0], MM_STACK_START as i64);
                    emit_cmp(self, REGISTER_MAP[0], REGISTER_MAP[STACK_REG], None);
                    emit_mov(self, R11, REGISTER_MAP[0]);
                    emit_jcc(self, 0x82, TARGET_PC_EXIT);

                    // else return;
                    emit1(self, 0xc3); // ret near
                },

                _               => return Err(EbpfError::UnsupportedInstruction(self.pc)),
            }

            self.pc += 1;
        }

        // Handler for EbpfError::ExceededMaxInstructions
        set_anchor(self, TARGET_PC_CALL_EXCEEDED_MAX_INSTRUCTIONS);
        set_exception_kind::<E>(self, EbpfError::ExceededMaxInstructions(0, 0));
        emit_load(self, OperandSize::S64, R10, REGISTER_MAP[0], std::mem::size_of::<MemoryMapping>() as i32);
        emit_store(self, OperandSize::S64, REGISTER_MAP[0], RDI, 24); // total_insn_count = initial_instruction_meter;
        emit_jmp(self, TARGET_PC_EXCEPTION_AT);

        // Handler for EbpfError::CallDepthExceeded
        set_anchor(self, TARGET_PC_CALL_DEPTH_EXCEEDED);
        set_exception_kind::<E>(self, EbpfError::CallDepthExceeded(0, 0));
        emit_store_imm32(self, OperandSize::S64, RDI, 24, MAX_CALL_DEPTH as i32); // depth = MAX_CALL_DEPTH;
        emit_jmp(self, TARGET_PC_EXCEPTION_AT);

        // Handler for EbpfError::CallOutsideTextSegment
        set_anchor(self, TARGET_PC_CALL_OUTSIDE_TEXT_SEGMENT);
        set_exception_kind::<E>(self, EbpfError::CallOutsideTextSegment(0, 0));
        emit_store(self, OperandSize::S64, REGISTER_MAP[0], RDI, 24); // target_address = RAX;
        emit_jmp(self, TARGET_PC_EXCEPTION_AT);

        // Handler for EbpfError::DivideByZero
        set_anchor(self, TARGET_PC_DIV_BY_ZERO);
        set_exception_kind::<E>(self, EbpfError::DivideByZero(0));
        // emit_jmp(self, TARGET_PC_EXCEPTION_AT); // Fall-through

        // Handler for exceptions which report their PC
        set_anchor(self, TARGET_PC_EXCEPTION_AT);
        emit_profile_instruction_count_of_exception(self);
        emit_store_imm32(self, OperandSize::S64, RDI, 0, 1); // is_err = true;
        emit_alu(self, OperationWidth::Bit64, 0x81, 0, R11, ebpf::ELF_INSN_DUMP_OFFSET as i32 - 1, None);
        emit_store(self, OperandSize::S64, R11, RDI, 16); // pc = self.pc + ebpf::ELF_INSN_DUMP_OFFSET;
        emit_jmp(self, TARGET_PC_EPILOGUE);

        // Handler for syscall exceptions
        set_anchor(self, TARGET_PC_SYSCALL_EXCEPTION);
        emit_profile_instruction_count_of_exception(self);
        emit_jmp(self, TARGET_PC_EPILOGUE);

        // Quit gracefully
        set_anchor(self, TARGET_PC_EXIT);
        emit_store(self, OperandSize::S64, REGISTER_MAP[0], RDI, 8); // result.return_value = R0;
        emit_load_imm(self, REGISTER_MAP[0], 0);
        emit_store(self, OperandSize::S64, REGISTER_MAP[0], RDI, 0);  // result.is_error = false;

        // Epilogue
        set_anchor(self, TARGET_PC_EPILOGUE);

        // Store instruction_meter in RAX
        emit_load(self, OperandSize::S64, RBP, RAX, -8 * (CALLEE_SAVED_REGISTERS.len() + 1) as i32);

        // Restore stack pointer in case the BPF stack was used
        emit_mov(self, RBP, R11);
        emit_alu(self, OperationWidth::Bit64, 0x81, 5, R11, 8 * (CALLEE_SAVED_REGISTERS.len()-1) as i32, None);
        emit_mov(self, R11, RSP); // RSP = RBP - 8 * (CALLEE_SAVED_REGISTERS.len() - 1);

        // Restore registers
        for reg in CALLEE_SAVED_REGISTERS.iter().rev() {
            emit_pop(self, *reg);
        }

        emit1(self, 0xc3); // ret

        Ok(())
    }

    fn resolve_jumps(&mut self) {
        for jump in &self.jumps {
            let target_loc = match self.special_targets.get(&jump.target_pc) {
                Some(target) => *target,
                None         => self.pc_locs[jump.target_pc as usize]
            };

            // Assumes jump offset is at end of instruction
            unsafe {
                let offset_loc = jump.offset_loc as i32 + std::mem::size_of::<i32>() as i32;
                let rel = &(target_loc as i32 - offset_loc) as *const i32;

                let offset_ptr = self.contents.as_ptr().add(jump.offset_loc);

                libc::memcpy(offset_ptr as *mut libc::c_void, rel as *const libc::c_void,
                             std::mem::size_of::<i32>());
            }
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

// In the end, this is the only thing we export
pub fn compile<'a, E: UserDefinedError>(prog: &'a [u8],
    executable: &'a dyn Executable<E>,
    syscalls: &HashMap<u32, Syscall<'a, E>>,
    enable_instruction_meter: bool)
    -> Result<JitProgram<E>, EbpfError<E>> {

    // TODO: check how long the page must be to be sure to support an eBPF program of maximum
    // possible length
    let mut jit = JitCompiler::new(128, enable_instruction_meter);
    jit.compile(prog, executable, syscalls)?;
    jit.resolve_jumps();

    Ok(JitProgram {
        main: unsafe { mem::transmute(jit.contents.as_ptr()) },
        instruction_addresses: jit.pc_locs.iter().map(|offset| unsafe { jit.contents.as_ptr().add(*offset) }).collect(),
    })
}
