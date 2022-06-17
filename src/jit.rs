#![allow(clippy::integer_arithmetic)]
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

#![allow(clippy::deprecated_cfg_attr)]
#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unreachable_code)]

extern crate libc;

use std::{
    fmt::{Debug, Error as FormatterError, Formatter},
    mem,
    ops::{Index, IndexMut},
    pin::Pin, ptr,
};
use rand::{rngs::SmallRng, Rng, SeedableRng};

use crate::{
    elf::Executable,
    vm::{Config, ProgramResult, InstructionMeter},
    ebpf::{self, Insn},
    error::{UserDefinedError, EbpfError},
    memory_region::{MemoryMapping},
};

#[allow(unused_imports)]
use crate::{
    jit_x86::{JitCompilerX86},
    jit_arm64::{JitCompilerARM64},
};

/// Argument for executing a eBPF JIT-compiled program
pub struct JitProgramArgument<'a> {
    /// The MemoryMapping to be used to run the compiled code
    pub memory_mapping: MemoryMapping<'a>,
    /// Pointers to the context objects of syscalls
    pub syscall_context_objects: [*const u8; 0],
}

pub(crate) struct JitProgramSections {
    /// OS page size in bytes and the alignment of the sections
    page_size: usize,
    /// A `*const u8` pointer into the text_section for each BPF instruction
    pub(crate) pc_section: &'static mut [usize],
    /// The machine code
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
                pc_section: std::slice::from_raw_parts_mut(raw as *mut usize, pc),
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

#[cfg(target_arch = "x86_64")]
type JitCompilerNative = JitCompilerX86;

#[cfg(all(target_arch = "aarch64"))]
type JitCompilerNative = JitCompilerARM64;

impl<E: UserDefinedError, I: InstructionMeter> JitProgram<E, I> {
    pub fn new(executable: &Pin<Box<Executable<E, I>>>) -> Result<Self, EbpfError<E>> {
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            let _ = executable;
            panic!("JitProgram is only supported on x86_64 and ARM64");
        }
        #[cfg(all(target_arch = "aarch64", not(feature = "jit-aarch64-not-safe-for-production")))]
        {
            let _ = executable;
            panic!("The aarch64 JIT compiler is intended for developer use only.");
        }

        let program = executable.get_text_bytes().1;
        let jit_core = JitCompilerCore::new::<E>(program, executable.get_config())?;

        let mut jit = JitCompilerNative::new::<E>(jit_core)?;

        jit.compile::<E, I>(executable)?;
        let main = unsafe { mem::transmute(jit.get_core().result.text_section.as_ptr()) };
        Ok(Self {
            sections: jit.get_result(),
            main,
        })
    }

    #[cfg(debug_assertions)]
    pub fn machine_code_bytes(&self) -> &[u8] {
        self.sections.text_section
    }

    #[cfg(debug_assertions)]
    pub fn inst_to_addr(&self, idx: usize) -> usize {
        self.sections.pc_section[idx]
    }

    pub fn mem_size(&self) -> usize {
        mem::size_of::<Self>() +
        self.sections.mem_size()
    }

    pub fn machine_code_length(&self) -> usize {
        self.sections.text_section.len()
    }
}

// Used to define subroutines and then call them
// See JitCompilerCore::set_anchor() and JitCompilerCore::relative_to_anchor()
pub(crate) const ANCHOR_EPILOGUE: usize = 0;
pub(crate) const ANCHOR_TRACE: usize = 1;
pub(crate) const ANCHOR_RUST_EXCEPTION: usize = 2;
pub(crate) const ANCHOR_CALL_EXCEEDED_MAX_INSTRUCTIONS: usize = 3;
pub(crate) const ANCHOR_EXCEPTION_AT: usize = 4;
pub(crate) const ANCHOR_CALL_DEPTH_EXCEEDED: usize = 5;
pub(crate) const ANCHOR_CALL_OUTSIDE_TEXT_SEGMENT: usize = 6;
pub(crate) const ANCHOR_DIV_BY_ZERO: usize = 7;
pub(crate) const ANCHOR_DIV_OVERFLOW: usize = 8;
pub(crate) const ANCHOR_CALLX_UNSUPPORTED_INSTRUCTION: usize = 9;
pub(crate) const ANCHOR_CALL_UNSUPPORTED_INSTRUCTION: usize = 10;
pub(crate) const ANCHOR_EXIT: usize = 11;
pub(crate) const ANCHOR_SYSCALL: usize = 12;
pub(crate) const ANCHOR_BPF_CALL_PROLOGUE: usize = 13;
pub(crate) const ANCHOR_BPF_CALL_REG: usize = 14;
pub(crate) const ANCHOR_TRANSLATE_PC: usize = 15;
pub(crate) const ANCHOR_TRANSLATE_PC_LOOP: usize = 16;
pub(crate) const ANCHOR_MEMORY_ACCESS_VIOLATION: usize = 17;
pub(crate) const ANCHOR_TRANSLATE_MEMORY_ADDRESS: usize = 25;
pub(crate) const ANCHOR_COUNT: usize = 33; // Update me when adding or removing anchors

#[inline]
pub fn emit<T>(jit: &mut JitCompilerCore, data: T) {
    unsafe {
        let ptr = jit.result.text_section.as_ptr().add(jit.offset_in_text_section);
        #[allow(clippy::cast_ptr_alignment)]
        ptr::write_unaligned(ptr as *mut T, data as T);
    }
    jit.offset_in_text_section += mem::size_of::<T>();
}

#[inline]
pub fn emit_variable_length(jit: &mut JitCompilerCore, size: OperandSize, data: u64) {
    match size {
        OperandSize::S0 => {},
        OperandSize::S8 => emit::<u8>(jit, data as u8),
        OperandSize::S16 => emit::<u16>(jit, data as u16),
        OperandSize::S32 => emit::<u32>(jit, data as u32),
        OperandSize::S64 => emit::<u64>(jit, data),
    }
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


#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub enum OperandSize {
    S0  = 0,
    S8  = 8,
    S16 = 16,
    S32 = 32,
    S64 = 64,
}

#[derive(Debug)]
pub struct Jump {
    pub(crate) location: *const u8,
    pub(crate) target_pc: usize,
    pub(crate) fixup_type: u8, // architecture-specific
}

pub struct JitCompilerCore {
    pub(crate) result: JitProgramSections,
    pub(crate) text_section_jumps: Vec<Jump>,
    pub(crate) offset_in_text_section: usize,
    pub(crate) pc: usize,
    pub(crate) last_instruction_meter_validation_pc: usize,
    pub(crate) next_noop_insertion: u32,
    pub(crate) program_vm_addr: u64,
    pub(crate) anchors: [*const u8; ANCHOR_COUNT],
    pub(crate) config: Config,
    pub(crate) diversification_rng: SmallRng,
    pub(crate) stopwatch_is_active: bool,
    pub(crate) environment_stack_key: i32,
    pub(crate) program_argument_key: i32,
}

impl std::fmt::Debug for JitCompilerCore {
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
            .field("anchors", &self.anchors)
            .field("text_section_jumps", &self.text_section_jumps)
            .finish()
    }
}
impl JitCompilerCore {

    // Arguments are unused on windows
    fn new<E: UserDefinedError>(program: &[u8], config: &Config) -> Result<Self, EbpfError<E>> {
        #[cfg(target_os = "windows")]
        {
            let _ = program;
            let _ = config;
            panic!("JitCompilerX86 not supported on windows");
        }

        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            let _ = program;
            let _ = config;
            panic!("JitCompilerCore is only supported on x86_64 and ARM");
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

        let mut code_length_estimate = JitCompilerNative::get_max_empty_machine_code_length() + JitCompilerNative::get_max_machine_code_per_instruction() * pc;
        if config.noop_instruction_rate != 0 {
            code_length_estimate += code_length_estimate / config.noop_instruction_rate as usize;
        }
        let result = JitProgramSections::new(pc + 1, code_length_estimate)?;

        let mut diversification_rng = SmallRng::from_rng(rand::thread_rng()).unwrap();
        let (environment_stack_key, program_argument_key) =
            if config.encrypt_environment_registers {
                (
                    diversification_rng.gen::<i32>() / 16, // -3 bits for 8 Byte alignment, and -1 bit to have encoding space for EnvironmentStackSlot::SlotCount
                    diversification_rng.gen::<i32>() / 2, // -1 bit to have encoding space for (SYSCALL_CONTEXT_OBJECTS_OFFSET + syscall.context_object_slot) * 8
                )
            } else { (0, 0) };

        Ok(Self {
            result,
            text_section_jumps: vec![],
            offset_in_text_section: 0,
            pc: 0,
            last_instruction_meter_validation_pc: 0,
            next_noop_insertion: if config.noop_instruction_rate == 0 { u32::MAX } else { diversification_rng.gen_range(0..config.noop_instruction_rate * 2) },
            program_vm_addr: 0,
            anchors: [std::ptr::null(); ANCHOR_COUNT],
            config: *config,
            diversification_rng,
            stopwatch_is_active: false,
            environment_stack_key,
            program_argument_key,
        })
    }

    #[allow(dead_code)]
    fn print_anchors(&self) {
        for (anchor, addr) in self.anchors.iter().enumerate() {
            println!("Anchor {:#x}: {:p}", (anchor) as i64, *addr);
        }
    }

}


impl Index<usize> for JitCompilerCore {
    type Output = u8;

    fn index(&self, _index: usize) -> &u8 {
        &self.result.text_section[_index]
    }
}

impl IndexMut<usize> for JitCompilerCore {
    fn index_mut(&mut self, _index: usize) -> &mut u8 {
        &mut self.result.text_section[_index]
    }
}

pub(crate) trait JitCompilerImpl where Self: Sized {
    fn get_max_empty_machine_code_length() -> usize;
    fn get_max_machine_code_per_instruction() -> usize;
    fn generate_subroutines<E: UserDefinedError, I: InstructionMeter>(jit: &mut JitCompilerCore);
    fn generate_prologue<E: UserDefinedError, I: InstructionMeter>(jit: &mut JitCompilerCore, executable: &Pin<Box<Executable<E, I>>>);
    fn handle_insn<E: UserDefinedError, I: InstructionMeter>(jit: &mut JitCompilerCore, insn: Insn, executable: &Pin<Box<Executable<E, I>>>, program: &[u8]) -> Result<(), EbpfError<E>>;
    fn emit_profile_instruction_count(jit: &mut JitCompilerCore, target_pc: Option<usize>);
    fn emit_validate_instruction_count(jit: &mut JitCompilerCore, exclusive: bool, pc: Option<usize>);
    fn emit_overrun<E: UserDefinedError>(jit: &mut JitCompilerCore);

    fn get_core(&mut self) -> &mut JitCompilerCore;
    fn get_result(self) -> JitProgramSections;
    fn fixup_text_jumps(jit: &mut JitCompilerCore);
    fn new<E: UserDefinedError>(jit: JitCompilerCore) -> Result<Self, EbpfError<E>>;
    #[inline]
    fn emit_validate_and_profile_instruction_count(jit: &mut JitCompilerCore, exclusive: bool, target_pc: Option<usize>) {
        if jit.config.enable_instruction_meter {
            Self::emit_validate_instruction_count(jit, exclusive, Some(jit.pc));
            Self::emit_profile_instruction_count(jit, target_pc);
        }
    }

    fn compile<E: UserDefinedError, I: InstructionMeter>(&mut self,
            executable: &Pin<Box<Executable<E, I>>>) -> Result<(), EbpfError<E>> {
        let jit = self.get_core();
        let text_section_base = jit.result.text_section.as_ptr();
        let (program_vm_addr, program) = executable.get_text_bytes();
        jit.program_vm_addr = program_vm_addr;

        Self::generate_prologue::<E, I>(jit, executable);

        // Have these in front so that the linear search of TARGET_PC_TRANSLATE_PC does not terminate early
        Self::generate_subroutines::<E, I>(jit);

        while jit.pc * ebpf::INSN_SIZE < program.len() {
            let insn = ebpf::get_insn_unchecked(program, jit.pc);

            jit.result.pc_section[jit.pc] = unsafe { text_section_base.add(jit.offset_in_text_section) } as usize;

            // Regular instruction meter checkpoints to prevent long linear runs from exceeding their budget
            // NOTE; These must be deterministic
            if jit.last_instruction_meter_validation_pc + jit.config.instruction_meter_checkpoint_distance <= jit.pc {
                Self::emit_validate_instruction_count(jit, true, Some(jit.pc));
            }

            Self::handle_insn(jit, insn, executable, program)?;

            jit.pc += 1;
        }
        // Bumper so that the linear search of ANCHOR_TRANSLATE_PC can not run off
        jit.result.pc_section[jit.pc] = unsafe { text_section_base.add(jit.offset_in_text_section) } as usize;

        // Bumper in case there was no final exit
        if jit.offset_in_text_section + Self::get_max_machine_code_per_instruction() > jit.result.text_section.len() {
            return Err(EbpfError::ExhaustedTextSegment(jit.pc));
        }

        // Bumper in case there was no final exit
        Self::emit_overrun::<E>(jit);
        Self::fixup_text_jumps(jit);
        jit.resolve_jumps();
        jit.result.seal(jit.offset_in_text_section)?;

        // Delete secrets
        jit.environment_stack_key = 0;
        jit.program_argument_key = 0;

        Ok(())
    }

}

impl JitCompilerCore {
    pub(crate) fn set_anchor(&mut self, anchor: usize) {
        self.anchors[anchor] = unsafe { self.result.text_section.as_ptr().add(self.offset_in_text_section) };
    }

    // x86 instruction_length = 5 (Unconditional jump / call)
    // x86 instruction_length = 6 (Conditional jump)
    // arm64 instruction length should always be 0 since relative jumps are relative to current pc
    #[inline]
    pub(crate) fn relative_to_anchor(&self, anchor: usize, instruction_length: usize) -> i32 {
        let instruction_end = unsafe { self.result.text_section.as_ptr().add(self.offset_in_text_section).add(instruction_length) };
        let destination = self.anchors[anchor];
        debug_assert!(!destination.is_null(), "{:?}", anchor);
        (unsafe { destination.offset_from(instruction_end) } as i32) // Relative jump
    }

    #[inline]
    pub(crate) fn relative_to_target_pc(&mut self, target_pc: usize, instruction_length: usize, fixup_type: u8) -> i32 {
        let instruction_end = unsafe { self.result.text_section.as_ptr().add(self.offset_in_text_section).add(instruction_length) };
        let destination = if self.result.pc_section[target_pc] != 0 {
            // Backward jump
            self.result.pc_section[target_pc] as *const u8
        } else {
            // Forward jump, needs relocation
            self.text_section_jumps.push(Jump { location: unsafe { instruction_end.sub(4) }, target_pc, fixup_type });
            return 0;
        };
        debug_assert!(!destination.is_null());
        (unsafe { destination.offset_from(instruction_end) } as i32) // Relative jump
    }

    #[inline]
    pub(crate) fn relative_to_target_pc_arm64(&mut self, target_pc: usize, fixup_type: u8) -> i32 {
        let instruction_start = unsafe { self.result.text_section.as_ptr().add(self.offset_in_text_section) };
        let destination = if self.result.pc_section[target_pc] != 0 {
            // Backward jump
            self.result.pc_section[target_pc] as *const u8
        } else {
            // Forward jump, needs relocation
            self.text_section_jumps.push(Jump { location: instruction_start, target_pc, fixup_type });
            return 0;
        };
        debug_assert!(!destination.is_null());
        (unsafe { destination.offset_from(instruction_start) } as i32) // Relative jump
    }

    fn resolve_jumps(&mut self) {
        // There is no `VerifierError::JumpToMiddleOfLDDW` for `call imm` so patch it here
        let call_unsupported_instruction = self.anchors[ANCHOR_CALL_UNSUPPORTED_INSTRUCTION] as usize;
        let callx_unsupported_instruction = self.anchors[ANCHOR_CALLX_UNSUPPORTED_INSTRUCTION] as usize;
        // Fixups need to happen here, before result.pc_section is made non-relative
        for offset in self.result.pc_section.iter_mut() {
            if *offset == call_unsupported_instruction {
                *offset = callx_unsupported_instruction;
            }
        }
    }
}

#[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64"), not(target_os = "windows")))]
mod tests {
    use super::*;
    use crate::{syscalls, vm::{SyscallRegistry, SyscallObject, TestInstructionMeter}, elf::register_bpf_function};
    use std::collections::BTreeMap;
    use byteorder::{LittleEndian, ByteOrder};
    use crate::user_error::UserError;

    fn create_mockup_executable(program: &[u8]) -> Pin<Box<Executable::<UserError, TestInstructionMeter>>> {
        let config = Config {
            noop_instruction_rate: 0,
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
        assert!(empty_program_machine_code_length <= JitCompilerNative::get_max_empty_machine_code_length());

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
            assert!(machine_code_length_per_instruction <= JitCompilerNative::get_max_machine_code_per_instruction());
        }
    }
}
