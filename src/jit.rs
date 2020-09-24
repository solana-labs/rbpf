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
    vm::{Executable, Syscall},
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
    /// Pointers to the instructions of the compiled code
    pub instruction_addresses: [*const u8; 1],
}

/// eBPF JIT-compiled program
pub struct JitProgram<E: UserDefinedError> {
    /// Call this with JitProgramArgument to execute the compiled code
    pub main: unsafe fn(u64, &JitProgramArgument) -> Result<u64, EbpfError<E>>,
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
const TARGET_OFFSET: isize = ebpf::PROG_MAX_INSNS as isize;
const TARGET_PC_EXIT: isize = TARGET_OFFSET + 1;
const TARGET_PC_EPILOGUE: isize = TARGET_OFFSET + 2;
const TARGET_PC_CALL_DEPTH_EXCEEDED: isize = TARGET_OFFSET + 3;
const TARGET_PC_CALL_OUTSIDE_TEXT_SEGMENT: isize = TARGET_OFFSET + 4;
const TARGET_PC_DIV_BY_ZERO: isize = TARGET_OFFSET + 5;
const TARGET_PC_EXCEPTION_AT: isize = TARGET_OFFSET + 6;

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
fn emit1(jit: &mut JitMemory, data: u8) {
    emit_bytes!(jit, data, u8);
}

#[inline]
fn emit2(jit: &mut JitMemory, data: u16) {
    emit_bytes!(jit, data, u16);
}

#[inline]
fn emit4(jit: &mut JitMemory, data: u32) {
    emit_bytes!(jit, data, u32);
}

#[inline]
fn emit8(jit: &mut JitMemory, data: u64) {
    emit_bytes!(jit, data, u64);
}

#[allow(dead_code)]
#[inline]
fn emit_debugger_trap(jit: &mut JitMemory) {
    emit1(jit, 0xcc);
}

#[inline]
fn emit_jump_offset(jit: &mut JitMemory, target_pc: isize) {
    let jump = Jump { offset_loc: jit.offset, target_pc };
    jit.jumps.push(jump);
    emit4(jit, 0);
}

#[inline]
fn emit_modrm(jit: &mut JitMemory, modrm: u8, r: u8, m: u8) {
    assert_eq!((modrm | 0xc0), 0xc0);
    emit1(jit, (modrm & 0xc0) | ((r & 0b111) << 3) | (m & 0b111));
}

#[inline]
fn emit_modrm_reg2reg(jit: &mut JitMemory, r: u8, m: u8) {
    emit_modrm(jit, 0xc0, r, m);
}

#[inline]
fn emit_modrm_and_displacement(jit: &mut JitMemory, r: u8, m: u8, d: i32) {
    if d == 0 && (m & 0b111) != RBP {
        emit_modrm(jit, 0x00, r, m);
    } else if d >= -128 && d <= 127 {
        emit_modrm(jit, 0x40, r, m);
        emit1(jit, d as u8);
    } else {
        emit_modrm(jit, 0x80, r, m);
        emit4(jit, d as u32);
    }
}

#[inline]
fn emit_rex(jit: &mut JitMemory, w: u8, r: u8, x: u8, b: u8) {
    assert_eq!((w | 1), 1);
    assert_eq!((r | 1), 1);
    assert_eq!((x | 1), 1);
    assert_eq!((b | 1), 1);
    emit1(jit, 0x40 | (w << 3) | (r << 2) | (x << 1) | b);
}

// Emits a REX prefix with the top bit of src and dst.
// Skipped if no bits would be set.
#[inline]
fn emit_basic_rex(jit: &mut JitMemory, w: u8, src: u8, dst: u8) {
    if w != 0 || (src & 0b1000) != 0 || (dst & 0b1000) != 0 {
        let is_masked = | val, mask | { match val & mask {
            0 => 0,
            _ => 1
        }};
        emit_rex(jit, w, is_masked(src, 8), 0, is_masked(dst, 8));
    }
}

#[inline]
fn emit_push(jit: &mut JitMemory, r: u8) {
    emit_basic_rex(jit, 0, 0, r);
    emit1(jit, 0x50 | (r & 0b111));
}

#[inline]
fn emit_pop(jit: &mut JitMemory, r: u8) {
    emit_basic_rex(jit, 0, 0, r);
    emit1(jit, 0x58 | (r & 0b111));
}

// REX prefix and ModRM byte
// We use the MR encoding when there is a choice
// 'src' is often used as an opcode extension
#[inline]
fn emit_alu32(jit: &mut JitMemory, op: u8, src: u8, dst: u8) {
    emit_basic_rex(jit, 0, src, dst);
    emit1(jit, op);
    emit_modrm_reg2reg(jit, src, dst);
}

// REX prefix, ModRM byte, and 32-bit immediate
#[inline]
fn emit_alu32_imm32(jit: &mut JitMemory, op: u8, src: u8, dst: u8, imm: i32) {
    emit_alu32(jit, op, src, dst);
    emit4(jit, imm as u32);
}

// REX prefix, ModRM byte, and 8-bit immediate
#[inline]
fn emit_alu32_imm8(jit: &mut JitMemory, op: u8, src: u8, dst: u8, imm: i8) {
    emit_alu32(jit, op, src, dst);
    emit1(jit, imm as u8);
}

// REX.W prefix and ModRM byte
// We use the MR encoding when there is a choice
// 'src' is often used as an opcode extension
#[inline]
fn emit_alu64(jit: &mut JitMemory, op: u8, src: u8, dst: u8) {
    emit_basic_rex(jit, 1, src, dst);
    emit1(jit, op);
    emit_modrm_reg2reg(jit, src, dst);
}

// REX.W prefix, ModRM byte, and 32-bit immediate
#[inline]
fn emit_alu64_imm32(jit: &mut JitMemory, op: u8, src: u8, dst: u8, imm: i32) {
    emit_alu64(jit, op, src, dst);
    emit4(jit, imm as u32);
}

// REX.W prefix, ModRM byte, and 8-bit immediate
#[inline]
fn emit_alu64_imm8(jit: &mut JitMemory, op: u8, src: u8, dst: u8, imm: i8) {
    emit_alu64(jit, op, src, dst);
    emit1(jit, imm as u8);
}

// Register to register mov
#[inline]
fn emit_mov(jit: &mut JitMemory, src: u8, dst: u8) {
    emit_alu64(jit, 0x89, src, dst);
}

// Register to register exchange / swap
#[allow(dead_code)]
#[inline]
fn emit_xchg(jit: &mut JitMemory, src: u8, dst: u8) {
    emit_alu64(jit, 0x87, src, dst);
}

#[inline]
fn emit_cmp_imm32(jit: &mut JitMemory, dst: u8, imm: i32) {
    emit_alu64_imm32(jit, 0x81, 7, dst, imm);
}

#[inline]
fn emit_cmp(jit: &mut JitMemory, src: u8, dst: u8) {
    emit_alu64(jit, 0x39, src, dst);
}

#[inline]
fn emit_jcc(jit: &mut JitMemory, code: u8, target_pc: isize) {
    emit1(jit, 0x0f);
    emit1(jit, code);
    emit_jump_offset(jit, target_pc);
}

#[inline]
fn emit_jmp(jit: &mut JitMemory, target_pc: isize) {
    emit1(jit, 0xe9);
    emit_jump_offset(jit, target_pc);
}

#[inline]
fn set_anchor(jit: &mut JitMemory, target: isize) {
    jit.special_targets.insert(target, jit.offset);
}

// Load [src + offset] into dst
#[inline]
fn emit_load(jit: &mut JitMemory, size: OperandSize, src: u8, dst: u8, offset: i32) {
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
fn emit_load_imm(jit: &mut JitMemory, dst: u8, imm: i64) {
    if imm >= std::i32::MIN as i64 && imm <= std::i32::MAX as i64 {
        emit_alu64_imm32(jit, 0xc7, 0, dst, imm as i32);
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
fn emit_leaq(jit: &mut JitMemory, src: u8, dst: u8, offset: i32) {
    emit_basic_rex(jit, 1, dst, src);
    // leaq src + offset, dst
    emit1(jit, 0x8d);
    emit_modrm_and_displacement(jit, dst, src, offset);
}

// Store register src to [dst + offset]
#[inline]
fn emit_store(jit: &mut JitMemory, size: OperandSize, src: u8, dst: u8, offset: i32) {
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
fn emit_store_imm32(jit: &mut JitMemory, size: OperandSize, dst: u8, offset: i32, imm: i32) {
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

enum Value {
    Register(u8),
    RegisterPlusConstant(u8, i64),
    Constant(i64)
}

struct Argument {
    index: usize,
    value: Value,
}

#[inline]
fn emit_bpf_call(jit: &mut JitMemory, dst: Value, number_of_instructions: usize, pc: usize) {
    for reg in REGISTER_MAP.iter().skip(FIRST_SCRATCH_REG).take(SCRATCH_REGS) {
        emit_push(jit, *reg);
    }
    emit_push(jit, REGISTER_MAP[STACK_REG]);

    match dst {
        Value::Register(reg) => {
            // Move vm target_address into RAX
            emit_mov(jit, reg, REGISTER_MAP[0]);
            // Force alignment of RAX
            emit_alu64_imm32(jit, 0x81, 4, REGISTER_MAP[0], !(INSN_SIZE as i32 - 1)); // RAX &= !(INSN_SIZE - 1);
            // Store PC in case the bounds check fails
            emit_load_imm(jit, R11, pc as i64 + ebpf::ELF_INSN_DUMP_OFFSET as i64);
            // Upper bound check
            // if(RAX >= MM_PROGRAM_START + number_of_instructions * INSN_SIZE) throw CALL_OUTSIDE_TEXT_SEGMENT;
            emit_load_imm(jit, REGISTER_MAP[STACK_REG], MM_PROGRAM_START as i64 + (number_of_instructions * INSN_SIZE) as i64);
            emit_cmp(jit, REGISTER_MAP[STACK_REG], REGISTER_MAP[0]);
            emit_jcc(jit, 0x83, TARGET_PC_CALL_OUTSIDE_TEXT_SEGMENT);
            // Lower bound check
            // if(RAX < MM_PROGRAM_START) throw CALL_OUTSIDE_TEXT_SEGMENT;
            emit_load_imm(jit, REGISTER_MAP[STACK_REG], MM_PROGRAM_START as i64);
            emit_cmp(jit, REGISTER_MAP[STACK_REG], REGISTER_MAP[0]);
            emit_jcc(jit, 0x82, TARGET_PC_CALL_OUTSIDE_TEXT_SEGMENT);
            // Calculate offset relative to instruction_addresses
            emit_alu64(jit, 0x29, REGISTER_MAP[STACK_REG], REGISTER_MAP[0]); // RAX -= MM_PROGRAM_START;
            // Load host target_address from JitProgramArgument.instruction_addresses
            emit_mov(jit, R10, REGISTER_MAP[STACK_REG]);
            emit_alu64(jit, 0x01, REGISTER_MAP[STACK_REG], REGISTER_MAP[0]); // RAX += &JitProgramArgument as *const _;
            emit_load(jit, OperandSize::S64, REGISTER_MAP[0], REGISTER_MAP[0], std::mem::size_of::<MemoryMapping>() as i32); // RAX = JitProgramArgument.instruction_addresses[RAX / 8];
        },
        Value::Constant(_target_pc) => {},
        _ => panic!()
    }

    emit_load(jit, OperandSize::S64, RBP, REGISTER_MAP[STACK_REG], -8 * CALLEE_SAVED_REGISTERS.len() as i32); // load stack_ptr
    emit_alu64_imm32(jit, 0x81, 4, REGISTER_MAP[STACK_REG], !(CALL_FRAME_SIZE as i32 * 2 - 1)); // stack_ptr &= !(CALL_FRAME_SIZE * 2 - 1);
    emit_alu64_imm32(jit, 0x81, 0, REGISTER_MAP[STACK_REG], CALL_FRAME_SIZE as i32 * 3); // stack_ptr += CALL_FRAME_SIZE * 3;
    emit_store(jit, OperandSize::S64, REGISTER_MAP[STACK_REG], RBP, -8 * CALLEE_SAVED_REGISTERS.len() as i32); // store stack_ptr

    // if(stack_ptr >= MM_STACK_START + MAX_CALL_DEPTH * CALL_FRAME_SIZE * 2) throw EbpfError::CallDepthExeeded;
    emit_mov(jit, REGISTER_MAP[0], R11);
    emit_load_imm(jit, REGISTER_MAP[0], MM_STACK_START as i64 + (MAX_CALL_DEPTH * CALL_FRAME_SIZE * 2) as i64);
    emit_cmp(jit, REGISTER_MAP[0], REGISTER_MAP[STACK_REG]);
    emit_mov(jit, R11, REGISTER_MAP[0]);
    // Store PC in case the bounds check fails
    emit_load_imm(jit, R11, pc as i64 + ebpf::ELF_INSN_DUMP_OFFSET as i64);
    emit_jcc(jit, 0x83, TARGET_PC_CALL_DEPTH_EXCEEDED);

    match dst {
        Value::Register(_reg) => {
            // callq *%rax
            emit1(jit, 0xff);
            emit1(jit, 0xd0);
        },
        Value::Constant(target_pc) => {
            emit1(jit, 0xe8);
            emit_jump_offset(jit, target_pc as isize);
        },
        _ => panic!()
    }

    emit_pop(jit, REGISTER_MAP[STACK_REG]);
    for reg in REGISTER_MAP.iter().skip(FIRST_SCRATCH_REG).take(SCRATCH_REGS).rev() {
        emit_pop(jit, *reg);
    }
}

#[inline]
fn emit_rust_call(jit: &mut JitMemory, function: *const u8, arguments: &[Argument]) {
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
                emit_alu64(jit, 0x01, reg, R11);
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
    emit_load(jit, OperandSize::S64, RDI, R11, 0);
    emit_alu64(jit, 0x85, R11, R11);
}

#[inline]
fn emit_address_translation(jit: &mut JitMemory, host_addr: u8, vm_addr: Value, len: u64, access_type: AccessType, pc: usize) {
    emit_rust_call(jit, MemoryMapping::map::<UserError> as *const u8, &[
        Argument { index: 3, value: vm_addr }, // Specify first as the src register could be overwritten by other arguments
        Argument { index: 1, value: Value::Register(R10) }, // JitProgramArgument::memory_mapping
        Argument { index: 2, value: Value::Constant(access_type as i64) },
        Argument { index: 4, value: Value::Constant(len as i64) },
    ]);

    // Throw error if the result indicates one
    emit_load_imm(jit, R11, pc as i64 + ebpf::ELF_INSN_DUMP_OFFSET as i64);
    emit_jcc(jit, 0x85, TARGET_PC_EXCEPTION_AT);

    // Store Ok value in result register
    emit_load(jit, OperandSize::S64, RDI, host_addr, 8);
}

fn muldivmod(jit: &mut JitMemory, pc: u16, opc: u8, src: u8, dst: u8, imm: i32) {
    let mul = (opc & ebpf::BPF_ALU_OP_MASK) == (ebpf::MUL32_IMM & ebpf::BPF_ALU_OP_MASK);
    let div = (opc & ebpf::BPF_ALU_OP_MASK) == (ebpf::DIV32_IMM & ebpf::BPF_ALU_OP_MASK);
    let modrm = (opc & ebpf::BPF_ALU_OP_MASK) == (ebpf::MOD32_IMM & ebpf::BPF_ALU_OP_MASK);
    let is64 = (opc & ebpf::BPF_CLS_MASK) == ebpf::BPF_ALU64;

    if div || modrm {
        // Save pc
        emit_load_imm(jit, R11, pc as i64 + ebpf::ELF_INSN_DUMP_OFFSET as i64);

        // test src,src
        if is64 {
            emit_alu64(jit, 0x85, src, src);
        } else {
            emit_alu32(jit, 0x85, src, src);
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
        emit_alu32(jit, 0x31, RDX, RDX);
    }

    if is64 {
        emit_rex(jit, 1, 0, 0, 0);
    }

    // mul %ecx or div %ecx
    emit_alu32(jit, 0xf7, if mul { 4 } else { 6 }, RCX);

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

#[derive(Debug)]
struct Jump {
    offset_loc: usize,
    target_pc:  isize,
}

struct JitMemory<'a> {
    contents:        &'a mut [u8],
    offset:          usize,
    pc_locs:         Vec<usize>,
    special_targets: HashMap<isize, usize>,
    jumps:           Vec<Jump>,
}

impl<'a> JitMemory<'a> {
    fn new(_num_pages: usize) -> JitMemory<'a> {
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
            std::ptr::write_bytes(raw, 0xc3, size);  // for now, prepopulate with 'RET' calls
            contents = std::slice::from_raw_parts_mut(raw as *mut u8, _num_pages * PAGE_SIZE);
        }

        JitMemory {
            contents,
            offset:          0,
            pc_locs:         vec![],
            jumps:           vec![],
            special_targets: HashMap::new(),
        }
    }

    fn jit_compile<E: UserDefinedError>(&mut self, prog: &[u8],
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

        // Padding on the stack to reach 16 byte alignment
        emit_load_imm(self, R11, 0);
        emit_push(self, R11);

        // Initialize other registers
        for reg in REGISTER_MAP.iter() {
            if *reg != REGISTER_MAP[1] && *reg != REGISTER_MAP[STACK_REG] {
                emit_load_imm(self, *reg, 0);
            }
        }

        let entry = executable.get_entrypoint_instruction_offset().unwrap();
        if entry != 0 {
            emit_jmp(self, entry as isize);
        }

        self.pc_locs = vec![0; prog.len() / ebpf::INSN_SIZE + 1];

        let mut insn_ptr:usize = 0;
        while insn_ptr * ebpf::INSN_SIZE < prog.len() {
            let insn = ebpf::get_insn(prog, insn_ptr);

            self.pc_locs[insn_ptr] = self.offset;

            let dst = map_register(insn.dst);
            let src = map_register(insn.src);
            let target_pc = insn_ptr as isize + insn.off as isize + 1;

            match insn.opc {

                // BPF_LD class
                ebpf::LD_ABS_B   => {
                    emit_address_translation(self, R11, Value::Constant(insn.imm as i64 + ebpf::MM_INPUT_START as i64), 1, AccessType::Load, insn_ptr);
                    emit_load(self, OperandSize::S8, R11, RAX, 0);
                },
                ebpf::LD_ABS_H   => {
                    emit_address_translation(self, R11, Value::Constant(insn.imm as i64 + ebpf::MM_INPUT_START as i64), 2, AccessType::Load, insn_ptr);
                    emit_load(self, OperandSize::S16, R11, RAX, 0);
                },
                ebpf::LD_ABS_W   => {
                    emit_address_translation(self, R11, Value::Constant(insn.imm as i64 + ebpf::MM_INPUT_START as i64), 4, AccessType::Load, insn_ptr);
                    emit_load(self, OperandSize::S32, R11, RAX, 0);
                },
                ebpf::LD_ABS_DW  => {
                    emit_address_translation(self, R11, Value::Constant(insn.imm as i64 + ebpf::MM_INPUT_START as i64), 8, AccessType::Load, insn_ptr);
                    emit_load(self, OperandSize::S64, R11, RAX, 0);
                },
                ebpf::LD_IND_B   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant(src, insn.imm as i64 + ebpf::MM_INPUT_START as i64), 1, AccessType::Load, insn_ptr);
                    emit_load(self, OperandSize::S8, R11, RAX, 0);
                },
                ebpf::LD_IND_H   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant(src, insn.imm as i64 + ebpf::MM_INPUT_START as i64), 2, AccessType::Load, insn_ptr);
                    emit_load(self, OperandSize::S16, R11, RAX, 0);
                },
                ebpf::LD_IND_W   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant(src, insn.imm as i64 + ebpf::MM_INPUT_START as i64), 4, AccessType::Load, insn_ptr);
                    emit_load(self, OperandSize::S32, R11, RAX, 0);
                },
                ebpf::LD_IND_DW  => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant(src, insn.imm as i64 + ebpf::MM_INPUT_START as i64), 8, AccessType::Load, insn_ptr);
                    emit_load(self, OperandSize::S64, R11, RAX, 0);
                },

                ebpf::LD_DW_IMM  => {
                    insn_ptr += 1;
                    let second_part = ebpf::get_insn(prog, insn_ptr).imm as u64;
                    let imm = (insn.imm as u32) as u64 | second_part.wrapping_shl(32);
                    emit_load_imm(self, dst, imm as i64);
                },

                // BPF_LDX class
                ebpf::LD_B_REG   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant(src, insn.off as i64), 1, AccessType::Load, insn_ptr);
                    emit_load(self, OperandSize::S8, R11, dst, 0);
                },
                ebpf::LD_H_REG   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant(src, insn.off as i64), 2, AccessType::Load, insn_ptr);
                    emit_load(self, OperandSize::S16, R11, dst, 0);
                },
                ebpf::LD_W_REG   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant(src, insn.off as i64), 4, AccessType::Load, insn_ptr);
                    emit_load(self, OperandSize::S32, R11, dst, 0);
                },
                ebpf::LD_DW_REG  => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant(src, insn.off as i64), 8, AccessType::Load, insn_ptr);
                    emit_load(self, OperandSize::S64, R11, dst, 0);
                },

                // BPF_ST class
                ebpf::ST_B_IMM   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant(dst, insn.off as i64), 1, AccessType::Store, insn_ptr);
                    emit_store_imm32(self, OperandSize::S8, R11, 0, insn.imm);
                },
                ebpf::ST_H_IMM   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant(dst, insn.off as i64), 2, AccessType::Store, insn_ptr);
                    emit_store_imm32(self, OperandSize::S16, R11, 0, insn.imm);
                },
                ebpf::ST_W_IMM   => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant(dst, insn.off as i64), 4, AccessType::Store, insn_ptr);
                    emit_store_imm32(self, OperandSize::S32, R11, 0, insn.imm);
                },
                ebpf::ST_DW_IMM  => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant(dst, insn.off as i64), 8, AccessType::Store, insn_ptr);
                    emit_store_imm32(self, OperandSize::S64, R11, 0, insn.imm);
                },

                // BPF_STX class
                ebpf::ST_B_REG  => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant(dst, insn.off as i64), 1, AccessType::Store, insn_ptr);
                    emit_store(self, OperandSize::S8, src, R11, 0);
                },
                ebpf::ST_H_REG  => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant(dst, insn.off as i64), 2, AccessType::Store, insn_ptr);
                    emit_store(self, OperandSize::S16, src, R11, 0);
                },
                ebpf::ST_W_REG  => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant(dst, insn.off as i64), 4, AccessType::Store, insn_ptr);
                    emit_store(self, OperandSize::S32, src, R11, 0);
                },
                ebpf::ST_DW_REG  => {
                    emit_address_translation(self, R11, Value::RegisterPlusConstant(dst, insn.off as i64), 8, AccessType::Store, insn_ptr);
                    emit_store(self, OperandSize::S64, src, R11, 0);
                },
                ebpf::ST_W_XADD  => unimplemented!(),
                ebpf::ST_DW_XADD => unimplemented!(),

                // BPF_ALU class
                ebpf::ADD32_IMM  => emit_alu32_imm32(self, 0x81, 0, dst, insn.imm),
                ebpf::ADD32_REG  => emit_alu32(self, 0x01, src, dst),
                ebpf::SUB32_IMM  => emit_alu32_imm32(self, 0x81, 5, dst, insn.imm),
                ebpf::SUB32_REG  => emit_alu32(self, 0x29, src, dst),
                ebpf::MUL32_IMM | ebpf::MUL32_REG |
                    ebpf::DIV32_IMM | ebpf::DIV32_REG |
                    ebpf::MOD32_IMM | ebpf::MOD32_REG =>
                    muldivmod(self, insn_ptr as u16, insn.opc, src, dst, insn.imm),
                ebpf::OR32_IMM   => emit_alu32_imm32(self, 0x81, 1, dst, insn.imm),
                ebpf::OR32_REG   => emit_alu32(self, 0x09, src, dst),
                ebpf::AND32_IMM  => emit_alu32_imm32(self, 0x81, 4, dst, insn.imm),
                ebpf::AND32_REG  => emit_alu32(self, 0x21, src, dst),
                ebpf::LSH32_IMM  => emit_alu32_imm8(self, 0xc1, 4, dst, insn.imm as i8),
                ebpf::LSH32_REG  => {
                    emit_mov(self, RCX, R11);
                    emit_mov(self, src, RCX);
                    emit_alu64_imm32(self, 0x81, 4, RCX, 31); // Mask shift amount
                    emit_alu32(self, 0xd3, 4, dst);
                    emit_mov(self, R11, RCX);
                },
                ebpf::RSH32_IMM  => emit_alu32_imm8(self, 0xc1, 5, dst, insn.imm as i8),
                ebpf::RSH32_REG  => {
                    emit_mov(self, RCX, R11);
                    emit_mov(self, src, RCX);
                    emit_alu64_imm32(self, 0x81, 4, RCX, 31); // Mask shift amount
                    emit_alu32(self, 0xd3, 5, dst);
                    emit_mov(self, R11, RCX);
                },
                ebpf::NEG32      => emit_alu32(self, 0xf7, 3, dst),
                ebpf::XOR32_IMM  => emit_alu32_imm32(self, 0x81, 6, dst, insn.imm),
                ebpf::XOR32_REG  => emit_alu32(self, 0x31, src, dst),
                ebpf::MOV32_IMM  => emit_alu32_imm32(self, 0xc7, 0, dst, insn.imm),
                ebpf::MOV32_REG  => emit_mov(self, src, dst),
                ebpf::ARSH32_IMM => emit_alu32_imm8(self, 0xc1, 7, dst, insn.imm as i8),
                ebpf::ARSH32_REG => {
                    emit_mov(self, RCX, R11);
                    emit_mov(self, src, RCX);
                    emit_alu64_imm32(self, 0x81, 4, RCX, 31); // Mask shift amount
                    emit_alu32(self, 0xd3, 7, dst);
                    emit_mov(self, R11, RCX);
                },
                ebpf::LE         => {}, // No-op
                ebpf::BE         => {
                    match insn.imm {
                        16 => {
                            // rol
                            emit1(self, 0x66); // 16-bit override
                            emit_alu32_imm8(self, 0xc1, 0, dst, 8);
                            // and
                            emit_alu32_imm32(self, 0x81, 4, dst, 0xffff);
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
                ebpf::ADD64_IMM  => emit_alu64_imm32(self, 0x81, 0, dst, insn.imm),
                ebpf::ADD64_REG  => emit_alu64(self, 0x01, src, dst),
                ebpf::SUB64_IMM  => emit_alu64_imm32(self, 0x81, 5, dst, insn.imm),
                ebpf::SUB64_REG  => emit_alu64(self, 0x29, src, dst),
                ebpf::MUL64_IMM | ebpf::MUL64_REG |
                    ebpf::DIV64_IMM | ebpf::DIV64_REG |
                    ebpf::MOD64_IMM | ebpf::MOD64_REG  =>
                    muldivmod(self, insn_ptr as u16, insn.opc, src, dst, insn.imm),
                ebpf::OR64_IMM   => emit_alu64_imm32(self, 0x81, 1, dst, insn.imm),
                ebpf::OR64_REG   => emit_alu64(self, 0x09, src, dst),
                ebpf::AND64_IMM  => emit_alu64_imm32(self, 0x81, 4, dst, insn.imm),
                ebpf::AND64_REG  => emit_alu64(self, 0x21, src, dst),
                ebpf::LSH64_IMM  => emit_alu64_imm8(self, 0xc1, 4, dst, insn.imm as i8),
                ebpf::LSH64_REG  => {
                    emit_mov(self, RCX, R11);
                    emit_mov(self, src, RCX);
                    emit_alu64_imm32(self, 0x81, 4, RCX, 63); // Mask shift amount
                    emit_alu64(self, 0xd3, 4, dst);
                    emit_mov(self, R11, RCX);
                },
                ebpf::RSH64_IMM  => emit_alu64_imm8(self, 0xc1, 5, dst, insn.imm as i8),
                ebpf::RSH64_REG  => {
                    emit_mov(self, RCX, R11);
                    emit_mov(self, src, RCX);
                    emit_alu64_imm32(self, 0x81, 4, RCX, 63); // Mask shift amount
                    emit_alu64(self, 0xd3, 5, dst);
                    emit_mov(self, R11, RCX);
                },
                ebpf::NEG64      => emit_alu64(self, 0xf7, 3, dst),
                ebpf::XOR64_IMM  => emit_alu64_imm32(self, 0x81, 6, dst, insn.imm),
                ebpf::XOR64_REG  => emit_alu64(self, 0x31, src, dst),
                ebpf::MOV64_IMM  => emit_load_imm(self, dst, insn.imm as i64),
                ebpf::MOV64_REG  => emit_mov(self, src, dst),
                ebpf::ARSH64_IMM => emit_alu64_imm8(self, 0xc1, 7, dst, insn.imm as i8),
                ebpf::ARSH64_REG => {
                    emit_mov(self, RCX, R11);
                    emit_mov(self, src, RCX);
                    emit_alu64_imm32(self, 0x81, 4, RCX, 63); // Mask shift amount
                    emit_alu64(self, 0xd3, 7, dst);
                    emit_mov(self, R11, RCX);
                },

                // BPF_JMP class
                ebpf::JA         => emit_jmp(self, target_pc),
                ebpf::JEQ_IMM    => {
                    emit_cmp_imm32(self, dst, insn.imm);
                    emit_jcc(self, 0x84, target_pc);
                },
                ebpf::JEQ_REG    => {
                    emit_cmp(self, src, dst);
                    emit_jcc(self, 0x84, target_pc);
                },
                ebpf::JGT_IMM    => {
                    emit_cmp_imm32(self, dst, insn.imm);
                    emit_jcc(self, 0x87, target_pc);
                },
                ebpf::JGT_REG    => {
                    emit_cmp(self, src, dst);
                    emit_jcc(self, 0x87, target_pc);
                },
                ebpf::JGE_IMM    => {
                    emit_cmp_imm32(self, dst, insn.imm);
                    emit_jcc(self, 0x83, target_pc);
                },
                ebpf::JGE_REG    => {
                    emit_cmp(self, src, dst);
                    emit_jcc(self, 0x83, target_pc);
                },
                ebpf::JLT_IMM    => {
                    emit_cmp_imm32(self, dst, insn.imm);
                    emit_jcc(self, 0x82, target_pc);
                },
                ebpf::JLT_REG    => {
                    emit_cmp(self, src, dst);
                    emit_jcc(self, 0x82, target_pc);
                },
                ebpf::JLE_IMM    => {
                    emit_cmp_imm32(self, dst, insn.imm);
                    emit_jcc(self, 0x86, target_pc);
                },
                ebpf::JLE_REG    => {
                    emit_cmp(self, src, dst);
                    emit_jcc(self, 0x86, target_pc);
                },
                ebpf::JSET_IMM   => {
                    emit_alu64_imm32(self, 0xf7, 0, dst, insn.imm);
                    emit_jcc(self, 0x85, target_pc);
                },
                ebpf::JSET_REG   => {
                    emit_alu64(self, 0x85, src, dst);
                    emit_jcc(self, 0x85, target_pc);
                },
                ebpf::JNE_IMM    => {
                    emit_cmp_imm32(self, dst, insn.imm);
                    emit_jcc(self, 0x85, target_pc);
                },
                ebpf::JNE_REG    => {
                    emit_cmp(self, src, dst);
                    emit_jcc(self, 0x85, target_pc);
                },
                ebpf::JSGT_IMM   => {
                    emit_cmp_imm32(self, dst, insn.imm);
                    emit_jcc(self, 0x8f, target_pc);
                },
                ebpf::JSGT_REG   => {
                    emit_cmp(self, src, dst);
                    emit_jcc(self, 0x8f, target_pc);
                },
                ebpf::JSGE_IMM   => {
                    emit_cmp_imm32(self, dst, insn.imm);
                    emit_jcc(self, 0x8d, target_pc);
                },
                ebpf::JSGE_REG   => {
                    emit_cmp(self, src, dst);
                    emit_jcc(self, 0x8d, target_pc);
                },
                ebpf::JSLT_IMM   => {
                    emit_cmp_imm32(self, dst, insn.imm);
                    emit_jcc(self, 0x8c, target_pc);
                },
                ebpf::JSLT_REG   => {
                    emit_cmp(self, src, dst);
                    emit_jcc(self, 0x8c, target_pc);
                },
                ebpf::JSLE_IMM   => {
                    emit_cmp_imm32(self, dst, insn.imm);
                    emit_jcc(self, 0x8e, target_pc);
                },
                ebpf::JSLE_REG   => {
                    emit_cmp(self, src, dst);
                    emit_jcc(self, 0x8e, target_pc);
                },
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
                        emit_jcc(self, 0x85, TARGET_PC_EPILOGUE);

                        // Store Ok value in result register
                        emit_load(self, OperandSize::S64, RDI, REGISTER_MAP[0], 8);
                    } else {
                        match executable.lookup_bpf_call(insn.imm as u32) {
                            Some(target_pc) => {
                                emit_bpf_call(self, Value::Constant(*target_pc as i64), prog.len() / ebpf::INSN_SIZE, insn_ptr);
                            },
                            None => executable.report_unresolved_symbol(insn_ptr)?,
                        }
                    }
                },
                ebpf::CALL_REG  => {
                    emit_bpf_call(self, Value::Register(REGISTER_MAP[insn.imm as usize]), prog.len() / ebpf::INSN_SIZE, insn_ptr);
                },
                ebpf::EXIT      => {
                    emit_load(self, OperandSize::S64, RBP, REGISTER_MAP[STACK_REG], -8 * CALLEE_SAVED_REGISTERS.len() as i32); // load stack_ptr
                    emit_alu64_imm32(self, 0x81, 4, REGISTER_MAP[STACK_REG], !(CALL_FRAME_SIZE as i32 * 2 - 1)); // stack_ptr &= !(CALL_FRAME_SIZE * 2 - 1);
                    emit_alu64_imm32(self, 0x81, 5, REGISTER_MAP[STACK_REG], CALL_FRAME_SIZE as i32 * 2); // stack_ptr -= CALL_FRAME_SIZE * 2;
                    emit_store(self, OperandSize::S64, REGISTER_MAP[STACK_REG], RBP, -8 * CALLEE_SAVED_REGISTERS.len() as i32); // store stack_ptr

                    // if(stack_ptr < MM_STACK_START) goto exit;
                    emit_mov(self, REGISTER_MAP[0], R11);
                    emit_load_imm(self, REGISTER_MAP[0], MM_STACK_START as i64);
                    emit_cmp(self, REGISTER_MAP[0], REGISTER_MAP[STACK_REG]);
                    emit_mov(self, R11, REGISTER_MAP[0]);
                    emit_jcc(self, 0x82, TARGET_PC_EXIT);

                    // else return;
                    emit1(self, 0xc3); // ret near
                },

                _               => return Err(EbpfError::UnsupportedInstruction(insn_ptr)),
            }

            insn_ptr += 1;
        }

        // Quit gracefully
        set_anchor(self, TARGET_PC_EXIT);

        // Store result in optional type
        emit_store(self, OperandSize::S64, REGISTER_MAP[0], RDI, 8);
        // Also store that no error occured
        emit_load_imm(self, REGISTER_MAP[0], 0);
        emit_store(self, OperandSize::S64, REGISTER_MAP[0], RDI, 0);

        // Epilogue
        set_anchor(self, TARGET_PC_EPILOGUE);

        // Restore stack pointer in case the BPF stack was used
        emit_mov(self, RBP, REGISTER_MAP[0]);
        emit_alu64_imm32(self, 0x81, 5, REGISTER_MAP[0], (CALLEE_SAVED_REGISTERS.len()-1) as i32 * 8);
        emit_mov(self, REGISTER_MAP[0], RSP); // RSP = RBP - (CALLEE_SAVED_REGISTERS.len() - 1) * 8;

        // Restore registers
        for reg in CALLEE_SAVED_REGISTERS.iter().rev() {
            emit_pop(self, *reg);
        }

        emit1(self, 0xc3); // ret

        // Handler for EbpfError::CallDepthExceeded
        set_anchor(self, TARGET_PC_CALL_DEPTH_EXCEEDED);
        let err = Result::<u64, EbpfError<E>>::Err(EbpfError::CallDepthExceeded(0, 0));
        let err_kind = unsafe { *(&err as *const _ as *const u64).offset(1) };
        emit_load_imm(self, REGISTER_MAP[0], err_kind as i64);
        emit_store(self, OperandSize::S64, REGISTER_MAP[0], RDI, 8); // err_kind = EbpfError::CallDepthExceeded
        emit_load_imm(self, REGISTER_MAP[0], MAX_CALL_DEPTH as i64);
        emit_store(self, OperandSize::S64, REGISTER_MAP[0], RDI, 24); // depth = MAX_CALL_DEPTH
        emit_jmp(self, TARGET_PC_EXCEPTION_AT);

        // Handler for EbpfError::CallOutsideTextSegment
        set_anchor(self, TARGET_PC_CALL_OUTSIDE_TEXT_SEGMENT);
        emit_store(self, OperandSize::S64, REGISTER_MAP[0], RDI, 24); // target_address = RAX
        let err = Result::<u64, EbpfError<E>>::Err(EbpfError::CallOutsideTextSegment(0, 0));
        let err_kind = unsafe { *(&err as *const _ as *const u64).offset(1) };
        emit_load_imm(self, REGISTER_MAP[0], err_kind as i64);
        emit_store(self, OperandSize::S64, REGISTER_MAP[0], RDI, 8); // err_kind = EbpfError::CallOutsideTextSegment
        emit_jmp(self, TARGET_PC_EXCEPTION_AT);

        // Handler for EbpfError::DivideByZero
        set_anchor(self, TARGET_PC_DIV_BY_ZERO);
        let err = Result::<u64, EbpfError<E>>::Err(EbpfError::DivideByZero(0));
        let err_kind = unsafe { *(&err as *const _ as *const u64).offset(1) };
        emit_load_imm(self, REGISTER_MAP[0], err_kind as i64);
        emit_store(self, OperandSize::S64, REGISTER_MAP[0], RDI, 8); // err_kind = EbpfError::DivideByZero
        // Fall-through to TARGET_PC_EXCEPTION_AT

        // Handler for exceptions which report their PC
        set_anchor(self, TARGET_PC_EXCEPTION_AT);
        emit_load_imm(self, REGISTER_MAP[0], 1);
        emit_store(self, OperandSize::S64, REGISTER_MAP[0], RDI, 0); // is_err = true
        emit_store(self, OperandSize::S64, R11, RDI, 16); // pc = insn_ptr
        // goto exit
        emit_jmp(self, TARGET_PC_EPILOGUE);

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
} // struct JitMemory

impl<'a> Index<usize> for JitMemory<'a> {
    type Output = u8;

    fn index(&self, _index: usize) -> &u8 {
        &self.contents[_index]
    }
}

impl<'a> IndexMut<usize> for JitMemory<'a> {
    fn index_mut(&mut self, _index: usize) -> &mut u8 {
        &mut self.contents[_index]
    }
}

impl<'a> std::fmt::Debug for JitMemory<'a> {
    fn fmt(&self, fmt: &mut Formatter) -> Result<(), FormatterError> {
        fmt.write_str("JIT contents: [")?;
        for i in self.contents as &[u8] {
            fmt.write_fmt(format_args!(" {:#04x},", i))?;
        };
        fmt.write_str(" ] | ")?;
        fmt.debug_struct("JIT state")
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
    syscalls: &HashMap<u32, Syscall<'a, E>>)
    -> Result<JitProgram<E>, EbpfError<E>> {

    // TODO: check how long the page must be to be sure to support an eBPF program of maximum
    // possible length
    let mut jit = JitMemory::new(1);
    jit.jit_compile(prog, executable, syscalls)?;
    jit.resolve_jumps();

    Ok(JitProgram {
        main: unsafe { mem::transmute(jit.contents.as_ptr()) },
        instruction_addresses: jit.pc_locs.iter().map(|offset| unsafe { jit.contents.as_ptr().add(*offset) }).collect(),
    })
}
