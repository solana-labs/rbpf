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
    jit::{JitProgram, JitProgramArgument},
    memory_region::{AccessType, MemoryMapping, MemoryRegion},
    user_error::UserError,
};
use log::{debug, log_enabled, trace};
use std::{collections::HashMap, fmt::Debug, u32};

/// eBPF verification function that returns an error if the program does not meet its requirements.
///
/// Some examples of things the verifier may reject the program for:
///
///   - Program does not terminate.
///   - Unknown instructions.
///   - Bad formed instruction.
///   - Unknown eBPF syscall index.
pub type Verifier<E> = fn(prog: &[u8]) -> Result<(), E>;

/// Return value of programs and syscalls
pub type ProgramResult<E> = Result<u64, EbpfError<E>>;

/// Error handling for SyscallObject::call methods
#[macro_export]
macro_rules! question_mark {
    ( $value:expr, $result:ident ) => {{
        let value = $value;
        if value.is_err() {
            *$result = value;
            return;
        }
        value.unwrap()
    }};
}

/// Syscall function without context
pub type SyscallFunction<E, O> =
    fn(O, u64, u64, u64, u64, u64, &MemoryMapping, &mut ProgramResult<E>);

/// Syscall with context
pub trait SyscallObject<E: UserDefinedError> {
    /// Call the syscall function
    #[allow(clippy::too_many_arguments)]
    fn call(&mut self, u64, u64, u64, u64, u64, &MemoryMapping, &mut ProgramResult<E>);
}

/// Syscall function and binding slot for a context object
pub struct Syscall {
    /// Call the syscall function
    pub function: u64,
    /// Slot of context object
    pub context_object_slot: usize,
}

impl Debug for Syscall {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.write_fmt(format_args!("Syscall {:?}", &self.function as *const _))
    }
}

impl PartialEq for Syscall {
    fn eq(&self, other: &Syscall) -> bool {
        self.function as *const u8 == other.function as *const u8
            && self.context_object_slot == other.context_object_slot
    }
}

/// Holds the syscall function pointers of an Executable
#[derive(Debug, PartialEq, Default)]
pub struct SyscallRegistry {
    /// Syscall resolution map
    entries: HashMap<u32, Syscall>,
}

impl SyscallRegistry {
    /// Register a syscall function (which can later be bound to a context object)
    pub fn register_syscall<E: UserDefinedError, O: SyscallObject<E>>(
        &mut self,
        key: u32,
        function: SyscallFunction<E, &mut O>,
    ) -> Result<(), EbpfError<E>> {
        if self
            .entries
            .insert(
                key,
                Syscall {
                    function: function as *const u8 as u64,
                    context_object_slot: self.entries.len(),
                },
            )
            .is_some()
        {
            Err(EbpfError::SycallAlreadyRegistered)
        } else {
            Ok(())
        }
    }

    /// Get a symbol's function pointer
    pub fn lookup_syscall(&self, hash: u32) -> Option<&Syscall> {
        self.entries.get(&hash)
    }

    /// Get the number of registered syscalls
    pub fn get_number_of_syscalls(&self) -> usize {
        self.entries.len()
    }
}

/// VM configuration settings
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Config {
    /// Maximum call depth
    pub max_call_depth: usize,
    /// Size of a stack frame in bytes, must match the size specified in the LLVM BPF backend
    pub stack_frame_size: usize,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            max_call_depth: 20,
            stack_frame_size: 4_096,
        }
    }
}

/// An relocated and ready to execute binary
pub trait Executable<E: UserDefinedError, I: InstructionMeter>: Send + Sync {
    /// Get the configuration settings
    fn get_config(&self) -> &Config;
    /// Get the .text section virtual address and bytes
    fn get_text_bytes(&self) -> Result<(u64, &[u8]), EbpfError<E>>;
    /// Get a vector of virtual addresses for each read-only section
    fn get_ro_sections(&self) -> Result<Vec<(u64, &[u8])>, EbpfError<E>>;
    /// Get the entry point offset into the text section
    fn get_entrypoint_instruction_offset(&self) -> Result<usize, EbpfError<E>>;
    /// Get a symbol's instruction offset
    fn lookup_bpf_call(&self, hash: u32) -> Option<&usize>;
    /// Get the syscall registry
    fn get_syscall_registry(&self) -> &SyscallRegistry;
    /// Set (overwrite) the syscall registry
    fn set_syscall_registry(&mut self, SyscallRegistry);
    /// Get the JIT compiled program
    fn get_compiled_program(&self) -> Option<&JitProgram<E, I>>;
    /// JIT compile the executable
    fn jit_compile(&mut self) -> Result<(), EbpfError<E>>;
    /// Report information on a symbol that failed to be resolved
    fn report_unresolved_symbol(&self, insn_offset: usize) -> Result<(), EbpfError<E>>;
}

/// Static constructors for Executable
impl<E: UserDefinedError, I: 'static + InstructionMeter> dyn Executable<E, I> {
    /// Creates a post relocaiton/fixup executable from an ELF file
    pub fn from_elf(
        elf_bytes: &[u8],
        verifier: Option<Verifier<E>>,
        config: Config,
    ) -> Result<Box<Self>, EbpfError<E>> {
        let ebpf_elf = EBpfElf::load(config, elf_bytes)?;
        let (_, bytes) = ebpf_elf.get_text_bytes()?;
        if let Some(verifier) = verifier {
            verifier(bytes)?;
        }
        Ok(Box::new(ebpf_elf))
    }
    /// Creates a post relocaiton/fixup executable from machine code
    pub fn from_text_bytes(
        text_bytes: &[u8],
        verifier: Option<Verifier<E>>,
        config: Config,
    ) -> Result<Box<Self>, EbpfError<E>> {
        if let Some(verifier) = verifier {
            verifier(text_bytes)?;
        }
        Ok(Box::new(EBpfElf::new_from_text_bytes(config, text_bytes)))
    }
}

/// Instruction meter
pub trait InstructionMeter {
    /// Consume instructions
    fn consume(&mut self, amount: u64);
    /// Get the number of remaining instructions allowed
    fn get_remaining(&self) -> u64;
}

/// Instruction meter without a limit
#[derive(Debug, PartialEq)]
pub struct DefaultInstructionMeter {}
impl InstructionMeter for DefaultInstructionMeter {
    fn consume(&mut self, _amount: u64) {}
    fn get_remaining(&self) -> u64 {
        std::i64::MAX as u64
    }
}

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

/// A virtual machine to run eBPF program.
///
/// # Examples
///
/// ```
/// use solana_rbpf::{vm::{Config, Executable, EbpfVm, DefaultInstructionMeter}, user_error::UserError};
///
/// let prog = &[
///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
/// ];
/// let mem = &mut [
///     0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd
/// ];
///
/// // Instantiate a VM.
/// let executable = Executable::<UserError, DefaultInstructionMeter>::from_text_bytes(prog, None, Config::default()).unwrap();
/// let mut vm = EbpfVm::<UserError, DefaultInstructionMeter>::new(executable.as_ref(), mem, &[]).unwrap();
///
/// // Provide a reference to the packet data.
/// let res = vm.execute_program_interpreted(&mut DefaultInstructionMeter {}).unwrap();
/// assert_eq!(res, 0);
/// ```
pub struct EbpfVm<'a, E: UserDefinedError, I: InstructionMeter> {
    executable: &'a dyn Executable<E, I>,
    program: &'a [u8],
    program_vm_addr: u64,
    memory_mapping: MemoryMapping,
    syscall_context_objects: Vec<*mut u8>,
    frames: CallFrames,
    last_insn_count: u64,
    total_insn_count: u64,
}

impl<'a, E: UserDefinedError, I: InstructionMeter> EbpfVm<'a, E, I> {
    /// Create a new virtual machine instance, and load an eBPF program into that instance.
    /// When attempting to load the program, it passes through a simple verifier.
    ///
    /// # Examples
    ///
    /// ```
    /// use solana_rbpf::{vm::{Config, Executable, EbpfVm, DefaultInstructionMeter}, user_error::UserError};
    ///
    /// let prog = &[
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// // Instantiate a VM.
    /// let executable = Executable::<UserError, DefaultInstructionMeter>::from_text_bytes(prog, None, Config::default()).unwrap();
    /// let mut vm = EbpfVm::<UserError, DefaultInstructionMeter>::new(executable.as_ref(), &[], &[]).unwrap();
    /// ```
    pub fn new(
        executable: &'a dyn Executable<E, I>,
        mem: &[u8],
        granted_regions: &[MemoryRegion],
    ) -> Result<EbpfVm<'a, E, I>, EbpfError<E>> {
        let config = executable.get_config();
        let frames = CallFrames::new(config.max_call_depth, config.stack_frame_size);
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
        let (program_vm_addr, program) = executable.get_text_bytes()?;
        regions.push(MemoryRegion::new_from_slice(
            program,
            program_vm_addr,
            false,
        ));
        let memory_mapping = MemoryMapping::new_from_regions(regions);
        let mut syscall_context_objects =
            vec![
                std::ptr::null_mut();
                2 + executable.get_syscall_registry().get_number_of_syscalls()
            ];
        unsafe {
            libc::memcpy(
                syscall_context_objects.as_mut_ptr() as _,
                std::mem::transmute::<_, _>(&memory_mapping),
                std::mem::size_of::<MemoryMapping>(),
            );
        }
        Ok(EbpfVm {
            executable,
            program,
            program_vm_addr,
            memory_mapping,
            syscall_context_objects,
            frames,
            last_insn_count: 0,
            total_insn_count: 0,
        })
    }

    /// Returns the number of instructions executed by the last program.
    pub fn get_total_instruction_count(&self) -> u64 {
        self.total_insn_count
    }

    /// Bind an object instance to a registered syscall at the given slot
    pub fn bind_syscall_context_object(
        &mut self,
        hash: u32,
        syscall_context_object: *mut u8,
        // syscall_context_object: &mut dyn SyscallObject::<E>,
    ) -> Result<(), EbpfError<E>> {
        let slot = self
            .executable
            .get_syscall_registry()
            .lookup_syscall(hash)
            .unwrap()
            .context_object_slot;
        if !self.syscall_context_objects[2 + slot].is_null() {
            Err(EbpfError::SycallAlreadyBound)
        } else {
            self.syscall_context_objects[2 + slot] = syscall_context_object;
            Ok(())
        }
    }

    /// Execute the program loaded, with the given packet data.
    ///
    /// Warning: The program is executed without limiting the number of
    /// instructions that can be executed
    ///
    /// # Examples
    ///
    /// ```
    /// use solana_rbpf::{vm::{Config, Executable, EbpfVm, DefaultInstructionMeter}, user_error::UserError};
    ///
    /// let prog = &[
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    /// let mem = &mut [
    ///     0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd
    /// ];
    ///
    /// // Instantiate a VM.
    /// let executable = Executable::<UserError, DefaultInstructionMeter>::from_text_bytes(prog, None, Config::default()).unwrap();
    /// let mut vm = EbpfVm::<UserError, DefaultInstructionMeter>::new(executable.as_ref(), mem, &[]).unwrap();
    ///
    /// // Provide a reference to the packet data.
    /// let res = vm.execute_program_interpreted(&mut DefaultInstructionMeter {}).unwrap();
    /// assert_eq!(res, 0);
    /// ```
    pub fn execute_program_interpreted(&mut self, instruction_meter: &mut I) -> ProgramResult<E> {
        let initial_insn_count = instruction_meter.get_remaining();
        let result = self.execute_program_interpreted_inner(instruction_meter);
        instruction_meter.consume(self.last_insn_count);
        self.total_insn_count = initial_insn_count - instruction_meter.get_remaining();
        result
    }

    #[rustfmt::skip]
    fn execute_program_interpreted_inner(
        &mut self,
        instruction_meter: &mut I,
    ) -> ProgramResult<E> {
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
        let initial_insn_count = remaining_insn_count;
        self.last_insn_count = 0;
        while next_pc * ebpf::INSN_SIZE + ebpf::INSN_SIZE <= self.program.len() {
            let pc = next_pc;
            next_pc += 1;
            let insn = ebpf::get_insn_unchecked(self.program, pc);
            let dst = insn.dst as usize;
            let src = insn.src as usize;
            self.last_insn_count += 1;

            if insn_trace {
                trace!(
                    "    BPF: {:5?} {:016x?} frame {:?} pc {:4?} {}",
                    self.last_insn_count,
                    reg,
                    self.frames.get_frame_index(),
                    pc + ebpf::ELF_INSN_DUMP_OFFSET,
                    disassembler::to_insn_vec(&self.program[pc * ebpf::INSN_SIZE..])[0].desc
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
                    let next_insn = ebpf::get_insn(self.program, next_pc);
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
                        return Err(EbpfError::DivideByZero(pc + ebpf::ELF_INSN_DUMP_OFFSET));
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
                        return Err(EbpfError::DivideByZero(pc + ebpf::ELF_INSN_DUMP_OFFSET));
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
                        _  => return Err(EbpfError::UnsupportedInstruction(pc + ebpf::ELF_INSN_DUMP_OFFSET)),
                    };
                },
                ebpf::BE         => {
                    reg[dst] = match insn.imm {
                        16 => (reg[dst] as u16).to_be() as u64,
                        32 => (reg[dst] as u32).to_be() as u64,
                        64 =>  reg[dst].to_be(),
                        _  => return Err(EbpfError::UnsupportedInstruction(pc + ebpf::ELF_INSN_DUMP_OFFSET)),
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
                        return Err(EbpfError::DivideByZero(pc + ebpf::ELF_INSN_DUMP_OFFSET));
                    }
                    reg[dst] /= reg[src];
                },
                ebpf::OR64_IMM   => reg[dst] |=  insn.imm as u64,
                ebpf::OR64_REG   => reg[dst] |=  reg[src],
                ebpf::AND64_IMM  => reg[dst] &=  insn.imm as u64,
                ebpf::AND64_REG  => reg[dst] &=  reg[src],
                ebpf::LSH64_IMM  => reg[dst] <<= insn.imm as u64,
                ebpf::LSH64_REG  => reg[dst] = reg[dst].wrapping_shl(reg[src] as u32),
                ebpf::RSH64_IMM  => reg[dst] >>= insn.imm as u64,
                ebpf::RSH64_REG  => reg[dst] = (reg[dst] as u64).wrapping_shr(reg[src] as u32),
                ebpf::NEG64      => reg[dst] = -(reg[dst] as i64) as u64,
                ebpf::MOD64_IMM  => reg[dst] %= insn.imm  as u64,
                ebpf::MOD64_REG  => {
                    if reg[src] == 0 {
                        return Err(EbpfError::DivideByZero(pc + ebpf::ELF_INSN_DUMP_OFFSET));
                    }
                                    reg[dst] %= reg[src];
                },
                ebpf::XOR64_IMM  => reg[dst] ^= insn.imm  as u64,
                ebpf::XOR64_REG  => reg[dst] ^= reg[src],
                ebpf::MOV64_IMM  => reg[dst] =  insn.imm  as u64,
                ebpf::MOV64_REG  => reg[dst] =  reg[src],
                ebpf::ARSH64_IMM => reg[dst] = (reg[dst]  as i64 >> insn.imm) as u64,
                ebpf::ARSH64_REG => reg[dst] = (reg[dst] as i64).wrapping_shr(reg[src] as u32) as u64,

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
                    if target_address < self.program_vm_addr {
                        return Err(EbpfError::CallOutsideTextSegment(pc + ebpf::ELF_INSN_DUMP_OFFSET, reg[insn.imm as usize]));
                    }
                    next_pc = Self::check_pc(self.program_vm_addr, &self.program, pc, (target_address - self.program_vm_addr) as usize / ebpf::INSN_SIZE)?;
                },

                // Do not delegate the check to the verifier, since registered functions can be
                // changed after the program has been verified.
                ebpf::CALL_IMM => {
                    if let Some(syscall) = self.executable.get_syscall_registry().lookup_syscall(insn.imm as u32) {
                        let _ = instruction_meter.consume(self.last_insn_count);
                        self.last_insn_count = 0;
                        let mut result: ProgramResult<E> = Ok(0);
                        (unsafe { std::mem::transmute::<u64, SyscallFunction::<E, *mut u8>>(syscall.function) })(
                            self.syscall_context_objects[2 + syscall.context_object_slot],
                            reg[1],
                            reg[2],
                            reg[3],
                            reg[4],
                            reg[5],
                            &self.memory_mapping,
                            &mut result,
                        );
                        reg[0] = result?;
                        remaining_insn_count = instruction_meter.get_remaining();
                    } else if let Some(new_pc) = self.executable.lookup_bpf_call(insn.imm as u32) {
                        // make BPF to BPF call
                        reg[ebpf::STACK_REG] = self.frames.push(
                            &reg[ebpf::FIRST_SCRATCH_REG
                                ..ebpf::FIRST_SCRATCH_REG + ebpf::SCRATCH_REGS],
                            next_pc,
                        )?;
                        next_pc = Self::check_pc(self.program_vm_addr, &self.program, pc, *new_pc)?;
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
                            next_pc = Self::check_pc(self.program_vm_addr, &self.program, pc, ptr)?;
                        }
                        _ => {
                            debug!("BPF instructions executed: {:?}", self.last_insn_count);
                            debug!(
                                "Max frame depth reached: {:?}",
                                self.frames.get_max_frame_index()
                            );
                            return Ok(reg[0]);
                        }
                    }
                }
                _ => return Err(EbpfError::UnsupportedInstruction(pc + ebpf::ELF_INSN_DUMP_OFFSET)),
            }
            if self.last_insn_count >= remaining_insn_count {
                return Err(EbpfError::ExceededMaxInstructions(pc + 1 + ebpf::ELF_INSN_DUMP_OFFSET, initial_insn_count));
            }
        }

        Err(EbpfError::ExecutionOverrun(
            next_pc + ebpf::ELF_INSN_DUMP_OFFSET,
        ))
    }

    fn check_pc(
        program_vm_addr: u64,
        prog: &[u8],
        current_pc: usize,
        new_pc: usize,
    ) -> Result<usize, EbpfError<E>> {
        let offset =
            new_pc
                .checked_mul(ebpf::INSN_SIZE)
                .ok_or(EbpfError::CallOutsideTextSegment(
                    current_pc + ebpf::ELF_INSN_DUMP_OFFSET,
                    program_vm_addr + (new_pc * ebpf::INSN_SIZE) as u64,
                ))?;
        let _ =
            prog.get(offset..offset + ebpf::INSN_SIZE)
                .ok_or(EbpfError::CallOutsideTextSegment(
                    current_pc + ebpf::ELF_INSN_DUMP_OFFSET,
                    program_vm_addr + (new_pc * ebpf::INSN_SIZE) as u64,
                ))?;
        Ok(new_pc)
    }

    /// Execute the previously JIT-compiled program, with the given packet data in a manner
    /// very similar to `execute_program_interpreted()`.
    ///
    /// # Safety
    ///
    /// **WARNING:** JIT-compiled assembly code is not safe. It may be wise to check that
    /// the program works with the interpreter before running the JIT-compiled version of it.
    ///
    pub fn execute_program_jit(&mut self, instruction_meter: &mut I) -> ProgramResult<E> {
        let reg1 = if self
            .memory_mapping
            .map::<UserError>(AccessType::Store, ebpf::MM_INPUT_START, 1)
            .is_ok()
        {
            ebpf::MM_INPUT_START
        } else {
            0
        };
        let initial_insn_count = instruction_meter.get_remaining();
        let result: ProgramResult<E> = Ok(0);
        let compiled_program = self
            .executable
            .get_compiled_program()
            .ok_or(EbpfError::JITNotCompiled)?;
        unsafe {
            self.last_insn_count = (compiled_program.main)(
                &result,
                reg1,
                &*(self.syscall_context_objects.as_ptr() as *const JitProgramArgument),
                instruction_meter,
            )
            .max(0) as u64;
        }
        let remaining_insn_count = instruction_meter.get_remaining();
        self.total_insn_count = remaining_insn_count - self.last_insn_count;
        instruction_meter.consume(self.total_insn_count);
        self.total_insn_count += initial_insn_count - remaining_insn_count;
        match result {
            Err(EbpfError::ExceededMaxInstructions(pc, _)) => {
                Err(EbpfError::ExceededMaxInstructions(pc, initial_insn_count))
            }
            x => x,
        }
    }
}
