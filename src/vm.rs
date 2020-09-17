// Derived from uBPF <https://github.com/iovisor/ubpf>
// Copyright 2015 Big Switch Networks, Inc
//      (uBPF: VM architecture, parts of the interpreter, originally in C)
// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//      (Translation to Rust, MetaBuff/multiple classes addition, hashmaps for syscalls)
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Virtual machine and JIT compiler for eBPF programs.

use crate::{
    call_frames::CallFrames,
    disassembler, ebpf,
    elf::EBpfElf,
    error::{EbpfError, UserDefinedError},
    jit,
    memory_region::{AccessType, MemoryMapping, MemoryRegion},
    user_error::UserError,
};
use log::{debug, log_enabled, trace};
use std::{collections::HashMap, u32};

/// Translates a vm_addr into a host_addr and sets the pc in the error if one occurs
macro_rules! translate_memory_access {
    ( $self:ident, $vm_addr:ident, $access_type:expr, $pc:ident, $T:ty ) => {
        match $self.memory_mapping.map::<UserError>(
            $access_type,
            $vm_addr,
            std::mem::size_of::<$T>() as u64,
        ) {
            Ok(host_addr) => host_addr as *mut $T,
            Err(EbpfError::AccessViolation(_pc, access_type, vm_addr, len, regions)) => {
                return Err(EbpfError::AccessViolation(
                    $pc + ebpf::ELF_INSN_DUMP_OFFSET,
                    access_type,
                    vm_addr,
                    len,
                    regions,
                ));
            }
            _ => unreachable!(),
        }
    };
}

/// eBPF verification function that returns an error if the program does not meet its requirements.
///
/// Some examples of things the verifier may reject the program for:
///
///   - Program does not terminate.
///   - Unknown instructions.
///   - Bad formed instruction.
///   - Unknown eBPF syscall index.
pub type Verifier<E> = fn(prog: &[u8]) -> Result<(), E>;

/// eBPF Jit-compiled program.
pub type JitProgram<E> = unsafe fn(u64, &MemoryMapping) -> Result<u64, EbpfError<E>>;

/// Syscall function without context.
pub type SyscallFunction<E> =
    fn(u64, u64, u64, u64, u64, &MemoryMapping) -> Result<u64, EbpfError<E>>;

/// Syscall with context
pub trait SyscallObject<E: UserDefinedError> {
    /// Call the syscall function
    #[allow(clippy::too_many_arguments)]
    fn call(&mut self, u64, u64, u64, u64, u64, &MemoryMapping) -> Result<u64, EbpfError<E>>;
}

/// Contains the syscall
pub enum Syscall<'a, E: UserDefinedError> {
    /// Function
    Function(SyscallFunction<E>),
    /// Trait object
    Object(Box<dyn SyscallObject<E> + 'a>),
}

/// An relocated and ready to execute binary
pub trait Executable<E: UserDefinedError>: Send + Sync {
    /// Get the .text section virtual address and bytes
    fn get_text_bytes(&self) -> Result<(u64, &[u8]), EbpfError<E>>;
    /// Get a vector of virtual addresses for each read-only section
    fn get_ro_sections(&self) -> Result<Vec<(u64, &[u8])>, EbpfError<E>>;
    /// Get the entry point offset into the text section
    fn get_entrypoint_instruction_offset(&self) -> Result<usize, EbpfError<E>>;
    /// Get a symbol's instruction offset
    fn lookup_bpf_call(&self, hash: u32) -> Option<&usize>;
    /// Report information on a symbol that failed to be resolved
    fn report_unresolved_symbol(&self, insn_offset: usize) -> Result<(), EbpfError<E>>;
}

/// Instruction meter
pub trait InstructionMeter {
    /// Consume instructions
    fn consume(&mut self, amount: u64);
    /// Get the number of remaining instructions allowed
    fn get_remaining(&self) -> u64;
}
struct DefaultInstructionMeter {}
impl InstructionMeter for DefaultInstructionMeter {
    fn consume(&mut self, _amount: u64) {}
    fn get_remaining(&self) -> u64 {
        std::u64::MAX
    }
}

/// A virtual machine to run eBPF program.
///
/// # Examples
///
/// ```
/// use solana_rbpf::{vm::EbpfVm, user_error::UserError};
///
/// let prog = &[
///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
/// ];
/// let mem = &mut [
///     0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd
/// ];
///
/// // Instantiate a VM.
/// let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(prog, None).unwrap();
/// let mut vm = EbpfVm::<UserError>::new(executable.as_ref(), mem, &[]).unwrap();
///
/// // Provide a reference to the packet data.
/// let res = vm.execute_program().unwrap();
/// assert_eq!(res, 0);
/// ```
pub struct EbpfVm<'a, E: UserDefinedError> {
    executable: &'a dyn Executable<E>,
    compiled_prog: Option<JitProgram<E>>,
    syscalls: HashMap<u32, Syscall<'a, E>>,
    prog: &'a [u8],
    prog_addr: u64,
    frames: CallFrames,
    memory_mapping: MemoryMapping,
    last_insn_count: u64,
    total_insn_count: u64,
}

impl<'a, E: UserDefinedError> EbpfVm<'a, E> {
    /// Create a new virtual machine instance, and load an eBPF program into that instance.
    /// When attempting to load the program, it passes through a simple verifier.
    ///
    /// # Examples
    ///
    /// ```
    /// use solana_rbpf::{vm::EbpfVm, user_error::UserError};
    ///
    /// let prog = &[
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// // Instantiate a VM.
    /// let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(prog, None).unwrap();
    /// let mut vm = EbpfVm::<UserError>::new(executable.as_ref(), &[], &[]).unwrap();
    /// ```
    pub fn new(
        executable: &'a dyn Executable<E>,
        mem: &[u8],
        granted_regions: &[MemoryRegion],
    ) -> Result<EbpfVm<'a, E>, EbpfError<E>> {
        let frames = CallFrames::default();
        let stack_regions = frames.get_stacks();
        let const_data_regions: Vec<MemoryRegion> =
            if let Ok(sections) = executable.get_ro_sections() {
                sections
                    .iter()
                    .map(|(addr, slice)| MemoryRegion::new_from_slice(slice, *addr, false))
                    .collect()
            } else {
                Vec::new()
            };
        let mut regions: Vec<MemoryRegion> = Vec::with_capacity(
            granted_regions.len() + stack_regions.len() + const_data_regions.len() + 2,
        );
        regions.extend(granted_regions.iter().cloned());
        regions.extend(stack_regions.iter().cloned());
        regions.extend(const_data_regions);
        regions.push(MemoryRegion::new_from_slice(
            &mem,
            ebpf::MM_INPUT_START,
            true,
        ));
        let (prog_addr, prog) = executable.get_text_bytes()?;
        regions.push(MemoryRegion::new_from_slice(prog, prog_addr, false));
        Ok(EbpfVm {
            executable,
            compiled_prog: None,
            syscalls: HashMap::new(),
            prog,
            prog_addr,
            frames,
            memory_mapping: MemoryMapping::new_from_regions(regions),
            last_insn_count: 0,
            total_insn_count: 0,
        })
    }

    /// Creates a post relocaiton/fixup executable
    pub fn create_executable_from_elf(
        elf_bytes: &'a [u8],
        verifier: Option<Verifier<E>>,
    ) -> Result<Box<dyn Executable<E>>, EbpfError<E>> {
        let ebpf_elf = EBpfElf::load(elf_bytes)?;
        let (_, bytes) = ebpf_elf.get_text_bytes()?;
        if let Some(verifier) = verifier {
            verifier(bytes)?;
        }
        Ok(Box::new(ebpf_elf))
    }

    /// Creates a post relocaiton/fixup executable
    pub fn create_executable_from_text_bytes(
        text_bytes: &'a [u8],
        verifier: Option<Verifier<E>>,
    ) -> Result<Box<dyn Executable<E>>, EbpfError<E>> {
        if let Some(verifier) = verifier {
            verifier(text_bytes)?;
        }
        Ok(Box::new(EBpfElf::new_from_text_bytes(text_bytes)))
    }

    /// Returns the number of instructions executed by the last program.
    pub fn get_total_instruction_count(&self) -> u64 {
        self.total_insn_count
    }

    /// Register a built-in or user-defined syscall function in order to use it later from within
    /// the eBPF program. The syscall is registered into a hashmap, so the `key` can be any `u32`.
    ///
    /// If using JIT-compiled eBPF programs, be sure to register all syscalls before compiling the
    /// program. You should be able to change registered syscalls after compiling, but not to add
    /// new ones (i.e. with new keys).
    ///
    /// # Examples
    ///
    /// ```
    /// use solana_rbpf::{vm::EbpfVm, syscalls::bpf_trace_printf, user_error::UserError};
    ///
    /// // This program was compiled with clang, from a C program containing the following single
    /// // instruction: `return bpf_trace_printk("foo %c %c %c\n", 10, 1, 2, 3);`
    /// let prog = &[
    ///     0x18, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // load 0 as u64 into r1 (That would be
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // replaced by tc by the address of
    ///                                                     // the format string, in the .map
    ///                                                     // section of the ELF file).
    ///     0xb7, 0x02, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, // mov r2, 10
    ///     0xb7, 0x03, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // mov r3, 1
    ///     0xb7, 0x04, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, // mov r4, 2
    ///     0xb7, 0x05, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, // mov r5, 3
    ///     0x85, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, // call syscall with key 6
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// // Instantiate a VM.
    /// let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(prog, None).unwrap();
    /// let mut vm = EbpfVm::<UserError>::new(executable.as_ref(), &[], &[]).unwrap();
    ///
    /// // Register a syscall.
    /// // On running the program this syscall will print the content of registers r3, r4 and r5 to
    /// // standard output.
    /// vm.register_syscall(6, bpf_trace_printf::<UserError>).unwrap();
    /// ```
    pub fn register_syscall(
        &mut self,
        key: u32,
        syscall: SyscallFunction<E>,
    ) -> Result<(), EbpfError<E>> {
        self.syscalls.insert(key, Syscall::Function(syscall));
        Ok(())
    }

    /// Register a user-defined syscall function in order to use it later from within
    /// the eBPF program.  Normally syscall functions are referred to by an index. (See syscalls)
    /// but this function takes the name of the function.  The name is then hashed into a 32 bit
    /// number and used in the `call` instructions imm field.  If calling `set_elf` then
    /// the elf's relocations must reference this symbol using the same name.  This can usually be
    /// achieved by building the elf with unresolved symbols (think `extern foo(void)`).  If
    /// providing a program directly via `set_program` then any `call` instructions must already
    /// have the hash of the symbol name in its imm field.  To generate the correct hash of the
    /// symbol name use `ebpf::syscalls::hash_symbol_name`.
    pub fn register_syscall_ex(
        &mut self,
        name: &str,
        syscall: SyscallFunction<E>,
    ) -> Result<(), EbpfError<E>> {
        self.syscalls.insert(
            ebpf::hash_symbol_name(name.as_bytes()),
            Syscall::Function(syscall),
        );
        Ok(())
    }

    /// Same as register_syscall_ex except reguster a syscall trait object that carries
    /// along context needed by the syscall
    pub fn register_syscall_with_context_ex(
        &mut self,
        name: &str,
        syscall: Box<dyn SyscallObject<E> + 'a>,
    ) -> Result<(), EbpfError<E>> {
        self.syscalls.insert(
            ebpf::hash_symbol_name(name.as_bytes()),
            Syscall::Object(syscall),
        );
        Ok(())
    }

    /// Execute the program loaded, with the given packet data.
    ///
    /// Warning: The program is executed without limiting the number of
    /// instructions that can be executed
    ///
    /// # Examples
    ///
    /// ```
    /// use solana_rbpf::{vm::EbpfVm, user_error::UserError};
    ///
    /// let prog = &[
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    /// let mem = &mut [
    ///     0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd
    /// ];
    ///
    /// // Instantiate a VM.
    /// let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(prog, None).unwrap();
    /// let mut vm = EbpfVm::<UserError>::new(executable.as_ref(), mem, &[]).unwrap();
    ///
    /// // Provide a reference to the packet data.
    /// let res = vm.execute_program().unwrap();
    /// assert_eq!(res, 0);
    /// ```
    pub fn execute_program(&mut self) -> Result<u64, EbpfError<E>> {
        self.execute_program_metered(DefaultInstructionMeter {})
    }

    /// Execute the program loaded, with the given instruction meter.
    pub fn execute_program_metered<I: InstructionMeter>(
        &mut self,
        mut instruction_meter: I,
    ) -> Result<u64, EbpfError<E>> {
        let result = self.execute_program_inner(&mut instruction_meter);
        instruction_meter.consume(self.last_insn_count);
        result
    }

    #[rustfmt::skip]
    fn execute_program_inner<I: InstructionMeter>(
        &mut self,
        instruction_meter: &mut I,
    ) -> Result<u64, EbpfError<E>> {
        const U32MAX: u64 = u32::MAX as u64;

        // R1 points to beginning of input memory, R10 to the stack of the first frame
        let mut reg: [u64; 11] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, self.frames.get_stack_top()];

        if self.memory_mapping.map::<UserError>(AccessType::Store, ebpf::MM_INPUT_START, 1).is_ok() {
            reg[1] = ebpf::MM_INPUT_START;
        }

        // Check trace logging outside the instruction loop, saves ~30%
        let insn_trace = log_enabled!(log::Level::Trace);

        // Loop on instructions
        let entry = self.executable.get_entrypoint_instruction_offset()?;
        let mut next_pc: usize = entry;
        let mut remaining_insn_count = instruction_meter.get_remaining();
        self.last_insn_count = 0;
        self.total_insn_count = 0;
        while next_pc * ebpf::INSN_SIZE + ebpf::INSN_SIZE <= self.prog.len() {
            let pc = next_pc;
            next_pc += 1;
            let insn = ebpf::get_insn_unchecked(self.prog, pc);
            let dst = insn.dst as usize;
            let src = insn.src as usize;
            self.last_insn_count += 1;
            self.total_insn_count += 1;

            if insn_trace {
                trace!(
                    "    BPF: {:5?} {:016x?} frame {:?} pc {:4?} {}",
                    self.total_insn_count,
                    reg,
                    self.frames.get_frame_index(),
                    pc + ebpf::ELF_INSN_DUMP_OFFSET,
                    disassembler::to_insn_vec(&self.prog[pc * ebpf::INSN_SIZE..])[0].desc
                );
            }

            match insn.opc {

                // BPF_LD class
                // Since this pointer is constant, and since we already know it (ebpf::MM_INPUT_START), do not
                // bother re-fetching it, just use ebpf::MM_INPUT_START already.
                ebpf::LD_ABS_B   => {
                    let vm_addr = ebpf::MM_INPUT_START.saturating_add((insn.imm as u32) as u64);
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Load, pc, u8);
                    reg[0] = unsafe { *host_ptr as u64 };
                },
                ebpf::LD_ABS_H   =>  {
                    let vm_addr = ebpf::MM_INPUT_START.saturating_add((insn.imm as u32) as u64);
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Load, pc, u16);
                    reg[0] = unsafe { *host_ptr as u64 };
                },
                ebpf::LD_ABS_W   => {
                    let vm_addr = ebpf::MM_INPUT_START.saturating_add((insn.imm as u32) as u64);
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Load, pc, u32);
                    reg[0] = unsafe { *host_ptr as u64 };
                },
                ebpf::LD_ABS_DW  => {
                    let vm_addr = ebpf::MM_INPUT_START.saturating_add((insn.imm as u32) as u64);
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Load, pc, u64);
                    reg[0] = unsafe { *host_ptr as u64 };
                },
                ebpf::LD_IND_B   => {
                    let vm_addr = ebpf::MM_INPUT_START.saturating_add(reg[src]).saturating_add((insn.imm as u32) as u64);
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Load, pc, u8);
                    reg[0] = unsafe { *host_ptr as u64 };
                },
                ebpf::LD_IND_H   => {
                    let vm_addr = ebpf::MM_INPUT_START.saturating_add(reg[src]).saturating_add((insn.imm as u32) as u64);
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Load, pc, u16);
                    reg[0] = unsafe { *host_ptr as u64 };
                },
                ebpf::LD_IND_W   => {
                    let vm_addr = ebpf::MM_INPUT_START.saturating_add(reg[src]).saturating_add((insn.imm as u32) as u64);
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Load, pc, u32);
                    reg[0] = unsafe { *host_ptr as u64 };
                },
                ebpf::LD_IND_DW  => {
                    let vm_addr = ebpf::MM_INPUT_START.saturating_add(reg[src]).saturating_add((insn.imm as u32) as u64);
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Load, pc, u64);
                    reg[0] = unsafe { *host_ptr as u64 };
                },

                ebpf::LD_DW_IMM  => {
                    let next_insn = ebpf::get_insn(self.prog, next_pc);
                    next_pc += 1;
                    reg[dst] = (insn.imm as u32) as u64 + ((next_insn.imm as u64) << 32);
                },

                // BPF_LDX class
                ebpf::LD_B_REG   => {
                    let vm_addr = (reg[src] as i64).saturating_add(insn.off as i64) as u64;
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Load, pc, u8);
                    reg[dst] = unsafe { *host_ptr as u64 };
                },
                ebpf::LD_H_REG   => {
                    let vm_addr = (reg[src] as i64).saturating_add(insn.off as i64) as u64;
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Load, pc, u16);
                    reg[dst] = unsafe { *host_ptr as u64 };
                },
                ebpf::LD_W_REG   => {
                    let vm_addr = (reg[src] as i64).saturating_add(insn.off as i64) as u64;
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Load, pc, u32);
                    reg[dst] = unsafe { *host_ptr as u64 };
                },
                ebpf::LD_DW_REG  => {
                    let vm_addr = (reg[src] as i64).saturating_add(insn.off as i64) as u64;
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Load, pc, u64);
                    reg[dst] = unsafe { *host_ptr as u64 };
                },

                // BPF_ST class
                ebpf::ST_B_IMM   => {
                    let vm_addr = (reg[dst] as i64).saturating_add( insn.off as i64) as u64;
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Store, pc, u8);
                    unsafe { *host_ptr = insn.imm as u8 };
                },
                ebpf::ST_H_IMM   => {
                    let vm_addr = (reg[dst] as i64).saturating_add(insn.off as i64) as u64;
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Store, pc, u16);
                    unsafe { *host_ptr = insn.imm as u16 };
                },
                ebpf::ST_W_IMM   => {
                    let vm_addr = (reg[dst] as i64).saturating_add(insn.off as i64) as u64;
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Store, pc, u32);
                    unsafe { *host_ptr = insn.imm as u32 };
                },
                ebpf::ST_DW_IMM  => {
                    let vm_addr = (reg[dst] as i64).saturating_add(insn.off as i64) as u64;
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Store, pc, u64);
                    unsafe { *host_ptr = insn.imm as u64 };
                },

                // BPF_STX class
                ebpf::ST_B_REG   => {
                    let vm_addr = (reg[dst] as i64).saturating_add(insn.off as i64) as u64;
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Store, pc, u8);
                    unsafe { *host_ptr = reg[src] as u8 };
                },
                ebpf::ST_H_REG   => {
                    let vm_addr = (reg[dst] as i64).saturating_add(insn.off as i64) as u64;
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Store, pc, u16);
                    unsafe { *host_ptr = reg[src] as u16 };
                },
                ebpf::ST_W_REG   => {
                    let vm_addr = (reg[dst] as i64).saturating_add(insn.off as i64) as u64;
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Store, pc, u32);
                    unsafe { *host_ptr = reg[src] as u32 };
                },
                ebpf::ST_DW_REG  => {
                    let vm_addr = (reg[dst] as i64).saturating_add(insn.off as i64) as u64;
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Store, pc, u64);
                    unsafe { *host_ptr = reg[src] as u64 };
                },

                // BPF_ALU class
                ebpf::ADD32_IMM  => reg[dst] = (reg[dst] as i32).wrapping_add(insn.imm)          as u64,
                ebpf::ADD32_REG  => reg[dst] = (reg[dst] as i32).wrapping_add(reg[src] as i32)   as u64,
                ebpf::SUB32_IMM  => reg[dst] = (reg[dst] as i32).wrapping_sub(insn.imm)          as u64,
                ebpf::SUB32_REG  => reg[dst] = (reg[dst] as i32).wrapping_sub(reg[src] as i32)   as u64,
                ebpf::MUL32_IMM  => reg[dst] = (reg[dst] as i32).wrapping_mul(insn.imm)          as u64,
                ebpf::MUL32_REG  => reg[dst] = (reg[dst] as i32).wrapping_mul(reg[src] as i32)   as u64,
                ebpf::DIV32_IMM  => reg[dst] = (reg[dst] as u32 / insn.imm as u32)               as u64,
                ebpf::DIV32_REG  => {
                    if reg[src] as u32 == 0 {
                        return Err(EbpfError::DivideByZero(pc));
                    }
                                    reg[dst] = (reg[dst] as u32 / reg[src] as u32)               as u64;
                },
                ebpf::OR32_IMM   =>   reg[dst] = (reg[dst] as u32             | insn.imm as u32) as u64,
                ebpf::OR32_REG   =>   reg[dst] = (reg[dst] as u32             | reg[src] as u32) as u64,
                ebpf::AND32_IMM  =>   reg[dst] = (reg[dst] as u32             & insn.imm as u32) as u64,
                ebpf::AND32_REG  =>   reg[dst] = (reg[dst] as u32             & reg[src] as u32) as u64,
                ebpf::LSH32_IMM  =>   reg[dst] = (reg[dst] as u32).wrapping_shl(insn.imm as u32) as u64,
                ebpf::LSH32_REG  =>   reg[dst] = (reg[dst] as u32).wrapping_shl(reg[src] as u32) as u64,
                ebpf::RSH32_IMM  =>   reg[dst] = (reg[dst] as u32).wrapping_shr(insn.imm as u32) as u64,
                ebpf::RSH32_REG  =>   reg[dst] = (reg[dst] as u32).wrapping_shr(reg[src] as u32) as u64,
                ebpf::NEG32      => { reg[dst] = (reg[dst] as i32).wrapping_neg()                as u64; reg[dst] &= U32MAX; },
                ebpf::MOD32_IMM  =>   reg[dst] = (reg[dst] as u32             % insn.imm as u32) as u64,
                ebpf::MOD32_REG  => {
                    if reg[src] as u32 == 0 {
                        return Err(EbpfError::DivideByZero(pc));
                    }
                                      reg[dst] = (reg[dst] as u32            % reg[src]  as u32) as u64;
                },
                ebpf::XOR32_IMM  =>   reg[dst] = (reg[dst] as u32            ^ insn.imm  as u32) as u64,
                ebpf::XOR32_REG  =>   reg[dst] = (reg[dst] as u32            ^ reg[src]  as u32) as u64,
                ebpf::MOV32_IMM  =>   reg[dst] = insn.imm  as u32                                as u64,
                ebpf::MOV32_REG  =>   reg[dst] = (reg[src] as u32)                               as u64,
                ebpf::ARSH32_IMM => { reg[dst] = (reg[dst] as i32).wrapping_shr(insn.imm as u32) as u64; reg[dst] &= U32MAX; },
                ebpf::ARSH32_REG => { reg[dst] = (reg[dst] as i32).wrapping_shr(reg[src] as u32) as u64; reg[dst] &= U32MAX; },
                ebpf::LE         => {
                    reg[dst] = match insn.imm {
                        16 => (reg[dst] as u16).to_le() as u64,
                        32 => (reg[dst] as u32).to_le() as u64,
                        64 =>  reg[dst].to_le(),
                        _  => return Err(EbpfError::UnsupportedInstruction(pc)),
                    };
                },
                ebpf::BE         => {
                    reg[dst] = match insn.imm {
                        16 => (reg[dst] as u16).to_be() as u64,
                        32 => (reg[dst] as u32).to_be() as u64,
                        64 =>  reg[dst].to_be(),
                        _  => return Err(EbpfError::UnsupportedInstruction(pc)),
                    };
                },

                // BPF_ALU64 class
                ebpf::ADD64_IMM  => reg[dst] = reg[dst].wrapping_add(insn.imm as u64),
                ebpf::ADD64_REG  => reg[dst] = reg[dst].wrapping_add(reg[src]),
                ebpf::SUB64_IMM  => reg[dst] = reg[dst].wrapping_sub(insn.imm as u64),
                ebpf::SUB64_REG  => reg[dst] = reg[dst].wrapping_sub(reg[src]),
                ebpf::MUL64_IMM  => reg[dst] = reg[dst].wrapping_mul(insn.imm as u64),
                ebpf::MUL64_REG  => reg[dst] = reg[dst].wrapping_mul(reg[src]),
                ebpf::DIV64_IMM  => reg[dst] /= insn.imm as u64,
                ebpf::DIV64_REG  => {
                    if reg[src] == 0 {
                        return Err(EbpfError::DivideByZero(pc));
                    }
                    reg[dst] /= reg[src];
                },
                ebpf::OR64_IMM   => reg[dst] |=  insn.imm as u64,
                ebpf::OR64_REG   => reg[dst] |=  reg[src],
                ebpf::AND64_IMM  => reg[dst] &=  insn.imm as u64,
                ebpf::AND64_REG  => reg[dst] &=  reg[src],
                ebpf::LSH64_IMM  => reg[dst] <<= insn.imm as u64,
                ebpf::LSH64_REG  => {
                    if reg[src] >= 64 {
                        return Err(EbpfError::ShiftWithOverflow(pc));
                    }
                                    reg[dst] <<= reg[src]
                },
                ebpf::RSH64_IMM  => reg[dst] >>= insn.imm as u64,
                ebpf::RSH64_REG  => {
                    if reg[src] >= 64 {
                        return Err(EbpfError::ShiftWithOverflow(pc));
                    }
                                    reg[dst] >>= reg[src]
                },
                ebpf::NEG64      => reg[dst] = -(reg[dst] as i64) as u64,
                ebpf::MOD64_IMM  => reg[dst] %= insn.imm  as u64,
                ebpf::MOD64_REG  => {
                    if reg[src] == 0 {
                        return Err(EbpfError::DivideByZero(pc));
                    }
                                    reg[dst] %= reg[src];
                },
                ebpf::XOR64_IMM  => reg[dst] ^= insn.imm  as u64,
                ebpf::XOR64_REG  => reg[dst] ^= reg[src],
                ebpf::MOV64_IMM  => reg[dst] =  insn.imm  as u64,
                ebpf::MOV64_REG  => reg[dst] =  reg[src],
                ebpf::ARSH64_IMM => reg[dst] = (reg[dst]  as i64 >> insn.imm) as u64,
                ebpf::ARSH64_REG => {
                    if reg[src] >= 64 {
                        return Err(EbpfError::ShiftWithOverflow(pc));
                    }
                    reg[dst] = (reg[dst] as i64 >> reg[src]) as u64
                },

                // BPF_JMP class
                ebpf::JA         =>                                            next_pc = (next_pc as isize + insn.off as isize) as usize,
                ebpf::JEQ_IMM    => if  reg[dst] == insn.imm as u64          { next_pc = (next_pc as isize + insn.off as isize) as usize; },
                ebpf::JEQ_REG    => if  reg[dst] == reg[src]                 { next_pc = (next_pc as isize + insn.off as isize) as usize; },
                ebpf::JGT_IMM    => if  reg[dst] >  insn.imm as u64          { next_pc = (next_pc as isize + insn.off as isize) as usize; },
                ebpf::JGT_REG    => if  reg[dst] >  reg[src]                 { next_pc = (next_pc as isize + insn.off as isize) as usize; },
                ebpf::JGE_IMM    => if  reg[dst] >= insn.imm as u64          { next_pc = (next_pc as isize + insn.off as isize) as usize; },
                ebpf::JGE_REG    => if  reg[dst] >= reg[src]                 { next_pc = (next_pc as isize + insn.off as isize) as usize; },
                ebpf::JLT_IMM    => if  reg[dst] <  insn.imm as u64          { next_pc = (next_pc as isize + insn.off as isize) as usize; },
                ebpf::JLT_REG    => if  reg[dst] <  reg[src]                 { next_pc = (next_pc as isize + insn.off as isize) as usize; },
                ebpf::JLE_IMM    => if  reg[dst] <= insn.imm as u64          { next_pc = (next_pc as isize + insn.off as isize) as usize; },
                ebpf::JLE_REG    => if  reg[dst] <= reg[src]                 { next_pc = (next_pc as isize + insn.off as isize) as usize; },
                ebpf::JSET_IMM   => if  reg[dst] &  insn.imm as u64 != 0     { next_pc = (next_pc as isize + insn.off as isize) as usize; },
                ebpf::JSET_REG   => if  reg[dst] &  reg[src]        != 0     { next_pc = (next_pc as isize + insn.off as isize) as usize; },
                ebpf::JNE_IMM    => if  reg[dst] != insn.imm as u64          { next_pc = (next_pc as isize + insn.off as isize) as usize; },
                ebpf::JNE_REG    => if  reg[dst] != reg[src]                 { next_pc = (next_pc as isize + insn.off as isize) as usize; },
                ebpf::JSGT_IMM   => if  reg[dst] as i64 >   insn.imm  as i64 { next_pc = (next_pc as isize + insn.off as isize) as usize; },
                ebpf::JSGT_REG   => if  reg[dst] as i64 >   reg[src]  as i64 { next_pc = (next_pc as isize + insn.off as isize) as usize; },
                ebpf::JSGE_IMM   => if  reg[dst] as i64 >=  insn.imm  as i64 { next_pc = (next_pc as isize + insn.off as isize) as usize; },
                ebpf::JSGE_REG   => if  reg[dst] as i64 >=  reg[src] as i64  { next_pc = (next_pc as isize + insn.off as isize) as usize; },
                ebpf::JSLT_IMM   => if (reg[dst] as i64) <  insn.imm  as i64 { next_pc = (next_pc as isize + insn.off as isize) as usize; },
                ebpf::JSLT_REG   => if (reg[dst] as i64) <  reg[src] as i64  { next_pc = (next_pc as isize + insn.off as isize) as usize; },
                ebpf::JSLE_IMM   => if (reg[dst] as i64) <= insn.imm  as i64 { next_pc = (next_pc as isize + insn.off as isize) as usize; },
                ebpf::JSLE_REG   => if (reg[dst] as i64) <= reg[src] as i64  { next_pc = (next_pc as isize + insn.off as isize) as usize; },

                ebpf::CALL_REG   => {
                    let target_address = reg[insn.imm as usize];
                    reg[ebpf::STACK_REG] =
                        self.frames.push(&reg[ebpf::FIRST_SCRATCH_REG..ebpf::FIRST_SCRATCH_REG + ebpf::SCRATCH_REGS], next_pc)?;
                    if target_address < ebpf::MM_PROGRAM_START {
                        return Err(EbpfError::CallOutsideTextSegment(pc + ebpf::ELF_INSN_DUMP_OFFSET, reg[insn.imm as usize]));
                    }
                    next_pc = Self::check_pc(&self.prog, pc, (target_address - self.prog_addr) as usize / ebpf::INSN_SIZE)?;
                },

                // Do not delegate the check to the verifier, since registered functions can be
                // changed after the program has been verified.
                ebpf::CALL_IMM => {
                    if let Some(syscall) = self.syscalls.get_mut(&(insn.imm as u32)) {
                        let _ = instruction_meter.consume(self.last_insn_count);
                        self.last_insn_count = 0;
                        reg[0] = match syscall {
                            Syscall::Function(syscall) => syscall(
                                reg[1],
                                reg[2],
                                reg[3],
                                reg[4],
                                reg[5],
                                &self.memory_mapping,
                            )?,
                            Syscall::Object(syscall) => syscall.call(
                                reg[1],
                                reg[2],
                                reg[3],
                                reg[4],
                                reg[5],
                                &self.memory_mapping,
                            )?,
                        };
                        remaining_insn_count = instruction_meter.get_remaining();
                    } else if let Some(new_pc) = self.executable.lookup_bpf_call(insn.imm as u32) {
                        // make BPF to BPF call
                        reg[ebpf::STACK_REG] = self.frames.push(
                            &reg[ebpf::FIRST_SCRATCH_REG
                                ..ebpf::FIRST_SCRATCH_REG + ebpf::SCRATCH_REGS],
                            next_pc,
                        )?;
                        next_pc = Self::check_pc(&self.prog, pc, *new_pc)?;
                    } else {
                        self.executable.report_unresolved_symbol(pc)?;
                    }
                }

                ebpf::EXIT => {
                    match self.frames.pop::<E>() {
                        Ok((saved_reg, stack_ptr, ptr)) => {
                            // Return from BPF to BPF call
                            reg[ebpf::FIRST_SCRATCH_REG
                                ..ebpf::FIRST_SCRATCH_REG + ebpf::SCRATCH_REGS]
                                .copy_from_slice(&saved_reg);
                            reg[ebpf::STACK_REG] = stack_ptr;
                            next_pc = Self::check_pc(&self.prog, pc, ptr)?;
                        }
                        _ => {
                            debug!("BPF instructions executed: {:?}", self.total_insn_count);
                            debug!(
                                "Max frame depth reached: {:?}",
                                self.frames.get_max_frame_index()
                            );
                            return Ok(reg[0]);
                        }
                    }
                }
                _ => return Err(EbpfError::UnsupportedInstruction(pc)),
            }
            if self.last_insn_count >= remaining_insn_count {
                return Err(EbpfError::ExceededMaxInstructions(self.total_insn_count));
            }
        }

        Err(EbpfError::ExecutionOverrun(
            next_pc + ebpf::ELF_INSN_DUMP_OFFSET,
        ))
    }

    fn check_pc(prog: &[u8], current_pc: usize, new_pc: usize) -> Result<usize, EbpfError<E>> {
        let offset = new_pc
            .checked_mul(ebpf::INSN_SIZE)
            .ok_or(EbpfError::CallOutsideTextSegment(current_pc, std::u64::MAX))?;
        let _ = prog
            .get(offset..offset + ebpf::INSN_SIZE)
            .ok_or(EbpfError::CallOutsideTextSegment(current_pc, std::u64::MAX))?;
        Ok(new_pc)
    }

    /// JIT-compile the loaded program. No argument required for this.
    ///
    /// If using syscall functions, be sure to register them into the VM before calling this
    /// function.
    ///
    /// # Examples
    ///
    /// ```
    /// use solana_rbpf::{vm::EbpfVm, user_error::UserError};
    ///
    /// let prog = &[
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// // Instantiate a VM.
    /// let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(prog, None).unwrap();
    /// let mut vm = EbpfVm::<UserError>::new(executable.as_ref(), &[], &[]).unwrap();
    ///
    /// # #[cfg(not(windows))]
    /// vm.jit_compile();
    /// ```
    pub fn jit_compile(&mut self) -> Result<(), EbpfError<E>> {
        self.compiled_prog = Some(jit::compile(self.prog, &self.syscalls)?);
        Ok(())
    }

    /// Execute the previously JIT-compiled program, with the given packet data in a manner
    /// very similar to `execute_program()`.
    ///
    /// # Safety
    ///
    /// **WARNING:** JIT-compiled assembly code is not safe. It may be wise to check that
    /// the program works with the interpreter before running the JIT-compiled version of it.
    ///
    /// For this reason the function should be called from within an `unsafe` bloc.
    ///
    pub unsafe fn execute_program_jit(&self) -> Result<u64, EbpfError<E>> {
        let reg1 = if self
            .memory_mapping
            .map::<UserError>(AccessType::Store, ebpf::MM_INPUT_START, 1)
            .is_ok()
        {
            ebpf::MM_INPUT_START
        } else {
            0
        };
        match self.compiled_prog {
            Some(compiled_prog) => compiled_prog(reg1, &self.memory_mapping),
            None => Err(EbpfError::JITNotCompiled),
        }
    }
}
