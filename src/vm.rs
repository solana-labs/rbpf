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

use crate::disassembler::disassemble_instruction;
use crate::static_analysis::Analysis;
use crate::{
    call_frames::CallFrames,
    ebpf,
    elf::EBpfElf,
    error::{EbpfError, UserDefinedError},
    jit::{JitProgram, JitProgramArgument},
    memory_region::{AccessType, MemoryMapping, MemoryRegion},
    user_error::UserError,
    verifier::VerifierError,
};
use log::debug;
use std::{
    collections::{BTreeMap, HashMap},
    fmt::Debug,
    u32,
};

/// eBPF verification function that returns an error if the program does not meet its requirements.
///
/// Some examples of things the verifier may reject the program for:
///
///   - Program does not terminate.
///   - Unknown instructions.
///   - Bad formed instruction.
///   - Unknown eBPF syscall index.
pub type Verifier = fn(prog: &[u8], config: &Config) -> Result<(), VerifierError>;

/// Return value of programs and syscalls
pub type ProgramResult<E> = Result<u64, EbpfError<E>>;

/// Error handling for SyscallObject::call methods
#[macro_export]
macro_rules! question_mark {
    ( $value:expr, $result:ident ) => {{
        let value = $value;
        match value {
            Err(err) => {
                *$result = Err(err.into());
                return;
            }
            Ok(value) => value,
        }
    }};
}

/// Syscall function without context
pub type SyscallFunction<E, O> =
    fn(O, u64, u64, u64, u64, u64, &MemoryMapping, &mut ProgramResult<E>);

/// Syscall with context
pub trait SyscallObject<E: UserDefinedError> {
    /// Call the syscall function
    #[allow(clippy::too_many_arguments)]
    fn call(
        &mut self,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
        memory_mapping: &MemoryMapping,
        result: &mut ProgramResult<E>,
    );
}

/// Syscall function and binding slot for a context object
#[derive(Debug, PartialEq)]
pub struct Syscall {
    /// Call the syscall function
    pub function: u64,
    /// Slot of context object
    pub context_object_slot: usize,
}

/// A virtual method table for dyn trait objects
pub struct DynTraitVtable {
    /// Drops the dyn trait object
    pub drop: fn(*const u8),
    /// Size of the dyn trait object in bytes
    pub size: usize,
    /// Alignment of the dyn trait object in bytes
    pub align: usize,
    /// The methods of the trait
    pub methods: [*const u8; 32],
}

// Could be replaced by https://doc.rust-lang.org/std/raw/struct.TraitObject.html
/// A dyn trait fat pointer for SyscallObject
#[derive(Clone, Copy)]
pub struct DynTraitFatPointer {
    /// Pointer to the actual object
    pub data: *mut u8,
    /// Pointer to the virtual method table
    pub vtable: &'static DynTraitVtable,
}

/// Holds the syscall function pointers of an Executable
#[derive(Debug, PartialEq, Default)]
pub struct SyscallRegistry {
    /// Function pointers by symbol
    entries: HashMap<u32, Syscall>,
    /// Context object slots by function pointer
    context_object_slots: HashMap<u64, usize>,
}

impl SyscallRegistry {
    /// Register a syscall function by its symbol hash
    pub fn register_syscall_by_hash<E: UserDefinedError, O: SyscallObject<E>>(
        &mut self,
        hash: u32,
        function: SyscallFunction<E, &mut O>,
    ) -> Result<(), EbpfError<E>> {
        let function = function as *const u8 as u64;
        let context_object_slot = self.entries.len();
        if self
            .entries
            .insert(
                hash,
                Syscall {
                    function,
                    context_object_slot,
                },
            )
            .is_some()
            || self
                .context_object_slots
                .insert(function, context_object_slot)
                .is_some()
        {
            Err(EbpfError::SycallAlreadyRegistered(hash as usize))
        } else {
            Ok(())
        }
    }

    /// Register a syscall function by its symbol name
    pub fn register_syscall_by_name<E: UserDefinedError, O: SyscallObject<E>>(
        &mut self,
        name: &[u8],
        function: SyscallFunction<E, &mut O>,
    ) -> Result<(), EbpfError<E>> {
        self.register_syscall_by_hash(ebpf::hash_symbol_name(name), function)
    }

    /// Get a symbol's function pointer and context object slot
    pub fn lookup_syscall(&self, hash: u32) -> Option<&Syscall> {
        self.entries.get(&hash)
    }

    /// Get a function pointer's and context object slot
    pub fn lookup_context_object_slot(&self, function_pointer: u64) -> Option<usize> {
        self.context_object_slots.get(&function_pointer).copied()
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
    /// Enables gaps in VM address space between the stack frames
    pub enable_stack_frame_gaps: bool,
    /// Maximal pc distance after which a new instruction meter validation is emitted by the JIT
    pub instruction_meter_checkpoint_distance: usize,
    /// Enable instruction meter and limiting
    pub enable_instruction_meter: bool,
    /// Enable instruction tracing
    pub enable_instruction_tracing: bool,
    /// Reject ELF files containing syscalls which are not in the SyscallRegistry
    pub reject_unresolved_syscalls: bool,
    /// Ratio of random no-ops per instruction in JIT (0.0 = OFF)
    pub noop_instruction_ratio: f64,
    /// Enable disinfection of immediate values and offsets provided by the user in JIT
    pub sanitize_user_provided_values: bool,
    /// Encrypt the environment registers in JIT
    pub encrypt_environment_registers: bool,
    /// Feature flag for the MUL64_IMM != 0 verification check
    pub verify_mul64_imm_nonzero: bool,
    /// Feature flag for the SHIFT_IMM >= 32 verification check
    pub verify_shift32_imm: bool,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            max_call_depth: 20,
            stack_frame_size: 4_096,
            enable_stack_frame_gaps: true,
            instruction_meter_checkpoint_distance: 10000,
            enable_instruction_meter: true,
            enable_instruction_tracing: false,
            reject_unresolved_syscalls: false,
            noop_instruction_ratio: 1.0 / 256.0,
            sanitize_user_provided_values: true,
            encrypt_environment_registers: true,
            verify_mul64_imm_nonzero: false,
            verify_shift32_imm: false,
        }
    }
}

/// An relocated and ready to execute binary
pub trait Executable<E: UserDefinedError, I: InstructionMeter>: Send + Sync {
    /// Get the configuration settings
    fn get_config(&self) -> &Config;
    /// Get the .text section virtual address and bytes
    fn get_text_bytes(&self) -> (u64, &[u8]);
    /// Get the concatenated read-only sections (including the text section)
    fn get_ro_section(&self) -> &[u8];
    /// Get the entry point offset into the text section
    fn get_entrypoint_instruction_offset(&self) -> Result<usize, EbpfError<E>>;
    /// Get a symbol's instruction offset
    fn lookup_bpf_function(&self, hash: u32) -> Option<usize>;
    /// Get the syscall registry
    fn get_syscall_registry(&self) -> &SyscallRegistry;
    /// Get the JIT compiled program
    fn get_compiled_program(&self) -> Option<&JitProgram<E, I>>;
    /// JIT compile the executable
    fn jit_compile(&mut self) -> Result<(), EbpfError<E>>;
    /// Report information on a symbol that failed to be resolved
    fn report_unresolved_symbol(&self, insn_offset: usize) -> Result<u64, EbpfError<E>>;
    /// Get BPF functions
    fn get_function_symbols(&self) -> BTreeMap<usize, (u32, String)>;
    /// Get syscalls symbols
    fn get_syscall_symbols(&self) -> &BTreeMap<u32, String>;
}

#[cfg(vtable_send_sync_plus_one)]
/// Index of report_unresolved_symbol in the Executable traits vtable
///
/// It is shifted by 1 because Send + Sync needs an extra slot.
pub const REPORT_UNRESOLVED_SYMBOL_INDEX: usize = 9;
#[cfg(not(vtable_send_sync_plus_one))]
/// Index of report_unresolved_symbol in the Executable traits vtable
pub const REPORT_UNRESOLVED_SYMBOL_INDEX: usize = 8;

/// The syscall_context_objects field stores some metadata in the front, thus the entries are shifted
pub const SYSCALL_CONTEXT_OBJECTS_OFFSET: usize = 4;

/// Static constructors for Executable
impl<E: UserDefinedError, I: 'static + InstructionMeter> dyn Executable<E, I> {
    /// Creates a post relocaiton/fixup executable from an ELF file
    pub fn from_elf(
        elf_bytes: &[u8],
        verifier: Option<Verifier>,
        config: Config,
        syscall_registry: SyscallRegistry,
    ) -> Result<Box<Self>, EbpfError<E>> {
        let ebpf_elf = EBpfElf::load(config, elf_bytes, syscall_registry)?;
        let text_bytes = ebpf_elf.get_text_bytes().1;
        if let Some(verifier) = verifier {
            verifier(text_bytes, &config)?;
        }
        Ok(Box::new(ebpf_elf))
    }
    /// Creates a post relocaiton/fixup executable from machine code
    pub fn from_text_bytes(
        text_bytes: &[u8],
        verifier: Option<Verifier>,
        config: Config,
        syscall_registry: SyscallRegistry,
        bpf_functions: BTreeMap<u32, (usize, String)>,
    ) -> Result<Box<Self>, EbpfError<E>> {
        if let Some(verifier) = verifier {
            verifier(text_bytes, &config).map_err(EbpfError::VerifierError)?;
        }
        Ok(Box::new(EBpfElf::new_from_text_bytes(
            config,
            text_bytes,
            syscall_registry,
            bpf_functions,
        )))
    }
}

/// Instruction meter
pub trait InstructionMeter {
    /// Consume instructions
    fn consume(&mut self, amount: u64);
    /// Get the number of remaining instructions allowed
    fn get_remaining(&self) -> u64;
}

/// Simple instruction meter for testing
#[derive(Debug, PartialEq, Eq)]
pub struct TestInstructionMeter {
    /// Maximal amount of instructions which still can be executed
    pub remaining: u64,
}

impl InstructionMeter for TestInstructionMeter {
    fn consume(&mut self, amount: u64) {
        debug_assert!(amount <= self.remaining, "Execution count exceeded");
        self.remaining = self.remaining.saturating_sub(amount);
    }

    fn get_remaining(&self) -> u64 {
        self.remaining
    }
}

/// Statistic of taken branches (from a recorded trace)
pub struct DynamicAnalysis {
    /// Maximal edge counter value
    pub edge_counter_max: usize,
    /// src_node, dst_node, edge_counter
    pub edges: BTreeMap<usize, BTreeMap<usize, usize>>,
}

impl DynamicAnalysis {
    /// Accumulates a trace
    pub fn new<E: UserDefinedError, I: InstructionMeter>(
        tracer: &Tracer,
        analysis: &Analysis<E, I>,
    ) -> Self {
        let mut result = Self {
            edge_counter_max: 0,
            edges: BTreeMap::new(),
        };
        let mut last_basic_block = std::usize::MAX;
        for traced_instruction in tracer.log.iter() {
            let pc = traced_instruction[11] as usize;
            if analysis.cfg_nodes.contains_key(&pc) {
                let counter = result
                    .edges
                    .entry(last_basic_block)
                    .or_insert_with(BTreeMap::new)
                    .entry(pc)
                    .or_insert(0);
                *counter += 1;
                result.edge_counter_max = result.edge_counter_max.max(*counter);
                last_basic_block = pc;
            }
        }
        result
    }
}

/// Used for instruction tracing
#[derive(Default, Clone)]
pub struct Tracer {
    /// Contains the state at every instruction in order of execution
    pub log: Vec<[u64; 12]>,
}

impl Tracer {
    /// Logs the state of a single instruction
    pub fn trace(&mut self, state: [u64; 12]) {
        self.log.push(state);
    }

    /// Use this method to print the log of this tracer
    pub fn write<W: std::io::Write, E: UserDefinedError, I: InstructionMeter>(
        &self,
        output: &mut W,
        analysis: &Analysis<E, I>,
    ) -> Result<(), std::io::Error> {
        let mut pc_to_insn_index = vec![
            0usize;
            analysis
                .instructions
                .last()
                .map(|insn| insn.ptr + 2)
                .unwrap_or(0)
        ];
        for (index, insn) in analysis.instructions.iter().enumerate() {
            pc_to_insn_index[insn.ptr] = index;
            pc_to_insn_index[insn.ptr + 1] = index;
        }
        for index in 0..self.log.len() {
            let entry = &self.log[index];
            let pc = entry[11] as usize;
            let insn = &analysis.instructions[pc_to_insn_index[pc]];
            writeln!(
                output,
                "{:5?} {:016X?} {:5?}: {}",
                index,
                &entry[0..11],
                pc + ebpf::ELF_INSN_DUMP_OFFSET,
                disassemble_instruction(insn, analysis),
            )?;
        }
        Ok(())
    }

    /// Compares an interpreter trace and a JIT trace.
    ///
    /// The log of the JIT can be longer because it only validates the instruction meter at branches.
    pub fn compare(interpreter: &Self, jit: &Self) -> bool {
        let interpreter = interpreter.log.as_slice();
        let mut jit = jit.log.as_slice();
        if jit.len() > interpreter.len() {
            jit = &jit[0..interpreter.len()];
        }
        interpreter == jit
    }
}

/// Translates a vm_addr into a host_addr and sets the pc in the error if one occurs
macro_rules! translate_memory_access {
    ($self:ident, $vm_addr:ident, $access_type:expr, $pc:ident, $T:ty) => {
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
            Err(EbpfError::StackAccessViolation(_pc, access_type, vm_addr, len, stack_frame)) => {
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

/// A virtual machine to run eBPF program.
///
/// # Examples
///
/// ```
/// use solana_rbpf::{ebpf, elf::register_bpf_function, vm::{Config, Executable, EbpfVm, TestInstructionMeter, SyscallRegistry}, user_error::UserError};
///
/// let prog = &[
///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
/// ];
/// let mem = &mut [
///     0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd
/// ];
///
/// // Instantiate a VM.
/// let mut bpf_functions = std::collections::BTreeMap::new();
/// register_bpf_function(&mut bpf_functions, 0, "entrypoint").unwrap();
/// let mut executable = <dyn Executable::<UserError, TestInstructionMeter>>::from_text_bytes(prog, None, Config::default(), SyscallRegistry::default(), bpf_functions).unwrap();
/// let mut vm = EbpfVm::<UserError, TestInstructionMeter>::new(executable.as_ref(), &mut [], mem).unwrap();
///
/// // Provide a reference to the packet data.
/// let res = vm.execute_program_interpreted(&mut TestInstructionMeter { remaining: 1 }).unwrap();
/// assert_eq!(res, 0);
/// ```
pub struct EbpfVm<'a, E: UserDefinedError, I: InstructionMeter> {
    executable: &'a dyn Executable<E, I>,
    program: &'a [u8],
    program_vm_addr: u64,
    memory_mapping: MemoryMapping<'a>,
    tracer: Tracer,
    syscall_context_objects: Vec<*mut u8>,
    syscall_context_object_pool: Vec<Box<dyn SyscallObject<E> + 'a>>,
    stack: CallFrames<'a>,
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
    /// use solana_rbpf::{ebpf, elf::register_bpf_function, vm::{Config, Executable, EbpfVm, TestInstructionMeter, SyscallRegistry}, user_error::UserError};
    ///
    /// let prog = &[
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// // Instantiate a VM.
    /// let mut bpf_functions = std::collections::BTreeMap::new();
    /// register_bpf_function(&mut bpf_functions, 0, "entrypoint").unwrap();
    /// let mut executable = <dyn Executable::<UserError, TestInstructionMeter>>::from_text_bytes(prog, None, Config::default(), SyscallRegistry::default(), bpf_functions).unwrap();
    /// let mut vm = EbpfVm::<UserError, TestInstructionMeter>::new(executable.as_ref(), &mut [], &mut []).unwrap();
    /// ```
    pub fn new(
        executable: &'a dyn Executable<E, I>,
        heap_region: &mut [u8],
        input_region: &mut [u8],
    ) -> Result<EbpfVm<'a, E, I>, EbpfError<E>> {
        let config = executable.get_config();
        let ro_region = executable.get_ro_section();
        let stack = CallFrames::new(config);
        let regions: Vec<MemoryRegion> = vec![
            MemoryRegion::new_from_slice(&[], 0, 0, false),
            MemoryRegion::new_from_slice(ro_region, ebpf::MM_PROGRAM_START, 0, false),
            stack.get_memory_region(),
            MemoryRegion::new_from_slice(heap_region, ebpf::MM_HEAP_START, 0, true),
            MemoryRegion::new_from_slice(input_region, ebpf::MM_INPUT_START, 0, true),
        ];
        let (program_vm_addr, program) = executable.get_text_bytes();
        let number_of_syscalls = executable.get_syscall_registry().get_number_of_syscalls();
        let mut vm = EbpfVm {
            executable,
            program,
            program_vm_addr,
            memory_mapping: MemoryMapping::new(regions, config)?,
            tracer: Tracer::default(),
            syscall_context_objects: vec![
                std::ptr::null_mut();
                SYSCALL_CONTEXT_OBJECTS_OFFSET + number_of_syscalls
            ],
            syscall_context_object_pool: Vec::with_capacity(number_of_syscalls),
            stack,
            last_insn_count: 0,
            total_insn_count: 0,
        };
        unsafe {
            libc::memcpy(
                vm.syscall_context_objects.as_mut_ptr() as _,
                std::mem::transmute::<_, _>(&vm.memory_mapping),
                std::mem::size_of::<MemoryMapping>(),
            );
        }
        Ok(vm)
    }

    /// Returns the number of instructions executed by the last program.
    pub fn get_total_instruction_count(&self) -> u64 {
        self.total_insn_count
    }

    /// Returns the program
    pub fn get_program(&self) -> &[u8] {
        self.program
    }

    /// Returns the tracer
    pub fn get_tracer(&self) -> &Tracer {
        &self.tracer
    }

    /// Bind a context object instance to a previously registered syscall
    ///
    /// # Examples
    ///
    /// ```
    /// use solana_rbpf::{ebpf, elf::register_bpf_function, vm::{Config, Executable, EbpfVm, SyscallObject, SyscallRegistry, TestInstructionMeter}, syscalls::BpfTracePrintf, user_error::UserError};
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
    /// // Register a syscall.
    /// // On running the program this syscall will print the content of registers r3, r4 and r5 to
    /// // standard output.
    /// let mut syscall_registry = SyscallRegistry::default();
    /// syscall_registry.register_syscall_by_hash(6, BpfTracePrintf::call).unwrap();
    /// // Instantiate an Executable and VM
    /// let mut bpf_functions = std::collections::BTreeMap::new();
    /// register_bpf_function(&mut bpf_functions, 0, "entrypoint").unwrap();
    /// let mut executable = <dyn Executable::<UserError, TestInstructionMeter>>::from_text_bytes(prog, None, Config::default(), syscall_registry, bpf_functions).unwrap();
    /// let mut vm = EbpfVm::<UserError, TestInstructionMeter>::new(executable.as_ref(), &mut [], &mut []).unwrap();
    /// // Bind a context object instance to the previously registered syscall
    /// vm.bind_syscall_context_object(Box::new(BpfTracePrintf {}), None);
    /// ```
    pub fn bind_syscall_context_object(
        &mut self,
        syscall_context_object: Box<dyn SyscallObject<E> + 'a>,
        hash: Option<u32>,
    ) -> Result<(), EbpfError<E>> {
        let fat_ptr: DynTraitFatPointer = unsafe { std::mem::transmute(&*syscall_context_object) };
        let syscall_registry = self.executable.get_syscall_registry();
        let slot = match hash {
            Some(hash) => {
                syscall_registry
                    .lookup_syscall(hash)
                    .ok_or(EbpfError::SyscallNotRegistered(hash as usize))?
                    .context_object_slot
            }
            None => syscall_registry
                .lookup_context_object_slot(fat_ptr.vtable.methods[0] as u64)
                .ok_or(EbpfError::SyscallNotRegistered(
                    fat_ptr.vtable.methods[0] as usize,
                ))?,
        };
        if !self.syscall_context_objects[SYSCALL_CONTEXT_OBJECTS_OFFSET + slot].is_null() {
            Err(EbpfError::SyscallAlreadyBound(slot))
        } else {
            self.syscall_context_objects[SYSCALL_CONTEXT_OBJECTS_OFFSET + slot] = fat_ptr.data;
            // Keep the dyn trait objects so that they can be dropped properly later
            self.syscall_context_object_pool
                .push(syscall_context_object);
            Ok(())
        }
    }

    /// Lookup a syscall context object by its function pointer. Used for testing and validation.
    pub fn get_syscall_context_object(&self, syscall_function: usize) -> Option<*mut u8> {
        self.executable
            .get_syscall_registry()
            .lookup_context_object_slot(syscall_function as u64)
            .map(|slot| self.syscall_context_objects[SYSCALL_CONTEXT_OBJECTS_OFFSET + slot])
    }

    /// Execute the program loaded, with the given packet data.
    ///
    /// Warning: The program is executed without limiting the number of
    /// instructions that can be executed
    ///
    /// # Examples
    ///
    /// ```
    /// use solana_rbpf::{ebpf, elf::register_bpf_function, vm::{Config, Executable, EbpfVm, TestInstructionMeter, SyscallRegistry}, user_error::UserError};
    ///
    /// let prog = &[
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    /// let mem = &mut [
    ///     0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd
    /// ];
    ///
    /// // Instantiate a VM.
    /// let mut bpf_functions = std::collections::BTreeMap::new();
    /// register_bpf_function(&mut bpf_functions, 0, "entrypoint").unwrap();
    /// let mut executable = <dyn Executable::<UserError, TestInstructionMeter>>::from_text_bytes(prog, None, Config::default(), SyscallRegistry::default(), bpf_functions).unwrap();
    /// let mut vm = EbpfVm::<UserError, TestInstructionMeter>::new(executable.as_ref(), &mut [], mem).unwrap();
    ///
    /// // Provide a reference to the packet data.
    /// let res = vm.execute_program_interpreted(&mut TestInstructionMeter { remaining: 1 }).unwrap();
    /// assert_eq!(res, 0);
    /// ```
    pub fn execute_program_interpreted(&mut self, instruction_meter: &mut I) -> ProgramResult<E> {
        let initial_insn_count = if self.executable.get_config().enable_instruction_meter {
            instruction_meter.get_remaining()
        } else {
            0
        };
        let result = self.execute_program_interpreted_inner(instruction_meter);
        if self.executable.get_config().enable_instruction_meter {
            instruction_meter.consume(self.last_insn_count);
            self.total_insn_count = initial_insn_count - instruction_meter.get_remaining();
        }
        result
    }

    #[rustfmt::skip]
    fn execute_program_interpreted_inner(
        &mut self,
        instruction_meter: &mut I,
    ) -> ProgramResult<E> {
        const U32MAX: u64 = u32::MAX as u64;

        // R1 points to beginning of input memory, R10 to the stack of the first frame
        let mut reg: [u64; 11] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, self.stack.get_stack_top()];

        if self.memory_mapping.map::<UserError>(AccessType::Store, ebpf::MM_INPUT_START, 1).is_ok() {
            reg[1] = ebpf::MM_INPUT_START;
        }

        // Check config outside of the instruction loop
        let instruction_meter_enabled = self.executable.get_config().enable_instruction_meter;
        let instruction_tracing_enabled = self.executable.get_config().enable_instruction_tracing;

        // Loop on instructions
        let entry = self.executable.get_entrypoint_instruction_offset()?;
        let mut next_pc: usize = entry;
        let mut remaining_insn_count = if instruction_meter_enabled { instruction_meter.get_remaining() } else { 0 };
        let initial_insn_count = remaining_insn_count;
        self.last_insn_count = 0;
        let mut total_insn_count = 0;
        while next_pc * ebpf::INSN_SIZE + ebpf::INSN_SIZE <= self.program.len() {
            let pc = next_pc;
            next_pc += 1;
            let mut insn = ebpf::get_insn_unchecked(self.program, pc);
            let dst = insn.dst as usize;
            let src = insn.src as usize;
            self.last_insn_count += 1;

            if instruction_tracing_enabled {
                let mut state = [0u64; 12];
                state[0..11].copy_from_slice(&reg);
                state[11] = pc as u64;
                self.tracer.trace(state);
            }

            match insn.opc {

                // BPF_LD class
                // Since this pointer is constant, and since we already know it (ebpf::MM_INPUT_START), do not
                // bother re-fetching it, just use ebpf::MM_INPUT_START already.
                ebpf::LD_ABS_B   => {
                    let vm_addr = ebpf::MM_INPUT_START.wrapping_add(insn.imm as u32 as u64);
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Load, pc, u8);
                    reg[0] = unsafe { *host_ptr as u64 };
                },
                ebpf::LD_ABS_H   =>  {
                    let vm_addr = ebpf::MM_INPUT_START.wrapping_add(insn.imm as u32 as u64);
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Load, pc, u16);
                    reg[0] = unsafe { *host_ptr as u64 };
                },
                ebpf::LD_ABS_W   => {
                    let vm_addr = ebpf::MM_INPUT_START.wrapping_add(insn.imm as u32 as u64);
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Load, pc, u32);
                    reg[0] = unsafe { *host_ptr as u64 };
                },
                ebpf::LD_ABS_DW  => {
                    let vm_addr = ebpf::MM_INPUT_START.wrapping_add(insn.imm as u32 as u64);
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Load, pc, u64);
                    reg[0] = unsafe { *host_ptr as u64 };
                },
                ebpf::LD_IND_B   => {
                    let vm_addr = ebpf::MM_INPUT_START.wrapping_add(reg[src]).wrapping_add(insn.imm as u32 as u64);
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Load, pc, u8);
                    reg[0] = unsafe { *host_ptr as u64 };
                },
                ebpf::LD_IND_H   => {
                    let vm_addr = ebpf::MM_INPUT_START.wrapping_add(reg[src]).wrapping_add(insn.imm as u32 as u64);
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Load, pc, u16);
                    reg[0] = unsafe { *host_ptr as u64 };
                },
                ebpf::LD_IND_W   => {
                    let vm_addr = ebpf::MM_INPUT_START.wrapping_add(reg[src]).wrapping_add(insn.imm as u32 as u64);
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Load, pc, u32);
                    reg[0] = unsafe { *host_ptr as u64 };
                },
                ebpf::LD_IND_DW  => {
                    let vm_addr = ebpf::MM_INPUT_START.wrapping_add(reg[src]).wrapping_add(insn.imm as u32 as u64);
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Load, pc, u64);
                    reg[0] = unsafe { *host_ptr as u64 };
                },

                ebpf::LD_DW_IMM  => {
                    ebpf::augment_lddw_unchecked(self.program, &mut insn);
                    next_pc += 1;
                    reg[dst] = insn.imm as u64;
                },

                // BPF_LDX class
                ebpf::LD_B_REG   => {
                    let vm_addr = (reg[src] as i64).wrapping_add(insn.off as i64) as u64;
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Load, pc, u8);
                    reg[dst] = unsafe { *host_ptr as u64 };
                },
                ebpf::LD_H_REG   => {
                    let vm_addr = (reg[src] as i64).wrapping_add(insn.off as i64) as u64;
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Load, pc, u16);
                    reg[dst] = unsafe { *host_ptr as u64 };
                },
                ebpf::LD_W_REG   => {
                    let vm_addr = (reg[src] as i64).wrapping_add(insn.off as i64) as u64;
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Load, pc, u32);
                    reg[dst] = unsafe { *host_ptr as u64 };
                },
                ebpf::LD_DW_REG  => {
                    let vm_addr = (reg[src] as i64).wrapping_add(insn.off as i64) as u64;
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Load, pc, u64);
                    reg[dst] = unsafe { *host_ptr as u64 };
                },

                // BPF_ST class
                ebpf::ST_B_IMM   => {
                    let vm_addr = (reg[dst] as i64).wrapping_add( insn.off as i64) as u64;
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Store, pc, u8);
                    unsafe { *host_ptr = insn.imm as u8 };
                },
                ebpf::ST_H_IMM   => {
                    let vm_addr = (reg[dst] as i64).wrapping_add(insn.off as i64) as u64;
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Store, pc, u16);
                    unsafe { *host_ptr = insn.imm as u16 };
                },
                ebpf::ST_W_IMM   => {
                    let vm_addr = (reg[dst] as i64).wrapping_add(insn.off as i64) as u64;
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Store, pc, u32);
                    unsafe { *host_ptr = insn.imm as u32 };
                },
                ebpf::ST_DW_IMM  => {
                    let vm_addr = (reg[dst] as i64).wrapping_add(insn.off as i64) as u64;
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Store, pc, u64);
                    unsafe { *host_ptr = insn.imm as u64 };
                },

                // BPF_STX class
                ebpf::ST_B_REG   => {
                    let vm_addr = (reg[dst] as i64).wrapping_add(insn.off as i64) as u64;
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Store, pc, u8);
                    unsafe { *host_ptr = reg[src] as u8 };
                },
                ebpf::ST_H_REG   => {
                    let vm_addr = (reg[dst] as i64).wrapping_add(insn.off as i64) as u64;
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Store, pc, u16);
                    unsafe { *host_ptr = reg[src] as u16 };
                },
                ebpf::ST_W_REG   => {
                    let vm_addr = (reg[dst] as i64).wrapping_add(insn.off as i64) as u64;
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Store, pc, u32);
                    unsafe { *host_ptr = reg[src] as u32 };
                },
                ebpf::ST_DW_REG  => {
                    let vm_addr = (reg[dst] as i64).wrapping_add(insn.off as i64) as u64;
                    let host_ptr = translate_memory_access!(self, vm_addr, AccessType::Store, pc, u64);
                    unsafe { *host_ptr = reg[src] as u64 };
                },

                // BPF_ALU class
                ebpf::ADD32_IMM  => reg[dst] = (reg[dst] as i32).wrapping_add(insn.imm as i32)   as u64,
                ebpf::ADD32_REG  => reg[dst] = (reg[dst] as i32).wrapping_add(reg[src] as i32)   as u64,
                ebpf::SUB32_IMM  => reg[dst] = (reg[dst] as i32).wrapping_sub(insn.imm as i32)   as u64,
                ebpf::SUB32_REG  => reg[dst] = (reg[dst] as i32).wrapping_sub(reg[src] as i32)   as u64,
                ebpf::MUL32_IMM  => reg[dst] = (reg[dst] as i32).wrapping_mul(insn.imm as i32)   as u64,
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
                        _  => {
                            return Err(EbpfError::InvalidInstruction(pc + ebpf::ELF_INSN_DUMP_OFFSET));
                        }
                    };
                },
                ebpf::BE         => {
                    reg[dst] = match insn.imm {
                        16 => (reg[dst] as u16).to_be() as u64,
                        32 => (reg[dst] as u32).to_be() as u64,
                        64 =>  reg[dst].to_be(),
                        _  => {
                            return Err(EbpfError::InvalidInstruction(pc + ebpf::ELF_INSN_DUMP_OFFSET));
                        }
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
                ebpf::LSH64_IMM  => reg[dst] = reg[dst].wrapping_shl(insn.imm as u32),
                ebpf::LSH64_REG  => reg[dst] = reg[dst].wrapping_shl(reg[src] as u32),
                ebpf::RSH64_IMM  => reg[dst] = reg[dst].wrapping_shr(insn.imm as u32),
                ebpf::RSH64_REG  => reg[dst] = reg[dst].wrapping_shr(reg[src] as u32),
                ebpf::NEG64      => reg[dst] = (reg[dst] as i64).wrapping_neg() as u64,
                ebpf::MOD64_IMM  => reg[dst] %= insn.imm  as u64,
                ebpf::MOD64_REG  => {
                    if reg[src] == 0 {
                        return Err(EbpfError::DivideByZero(pc + ebpf::ELF_INSN_DUMP_OFFSET));
                    }
                                    reg[dst] %= reg[src];
                },
                ebpf::XOR64_IMM  => reg[dst] ^= insn.imm as u64,
                ebpf::XOR64_REG  => reg[dst] ^= reg[src],
                ebpf::MOV64_IMM  => reg[dst] =  insn.imm as u64,
                ebpf::MOV64_REG  => reg[dst] =  reg[src],
                ebpf::ARSH64_IMM => reg[dst] = (reg[dst] as i64).wrapping_shr(insn.imm as u32) as u64,
                ebpf::ARSH64_REG => reg[dst] = (reg[dst] as i64).wrapping_shr(reg[src] as u32) as u64,

                // BPF_JMP class
                ebpf::JA         =>                                          { next_pc = (next_pc as isize + insn.off as isize) as usize; },
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
                        self.stack.push(&reg[ebpf::FIRST_SCRATCH_REG..ebpf::FIRST_SCRATCH_REG + ebpf::SCRATCH_REGS], next_pc)?;
                    if target_address < self.program_vm_addr {
                        return Err(EbpfError::CallOutsideTextSegment(pc + ebpf::ELF_INSN_DUMP_OFFSET, target_address / ebpf::INSN_SIZE as u64 * ebpf::INSN_SIZE as u64));
                    }
                    next_pc = self.check_pc(pc, (target_address - self.program_vm_addr) as usize / ebpf::INSN_SIZE)?;
                },

                // Do not delegate the check to the verifier, since registered functions can be
                // changed after the program has been verified.
                ebpf::CALL_IMM => {
                    if let Some(syscall) = self.executable.get_syscall_registry().lookup_syscall(insn.imm as u32) {
                        if instruction_meter_enabled {
                            let _ = instruction_meter.consume(self.last_insn_count);
                        }
                        total_insn_count += self.last_insn_count;
                        self.last_insn_count = 0;
                        let mut result: ProgramResult<E> = Ok(0);
                        (unsafe { std::mem::transmute::<u64, SyscallFunction::<E, *mut u8>>(syscall.function) })(
                            self.syscall_context_objects[SYSCALL_CONTEXT_OBJECTS_OFFSET + syscall.context_object_slot],
                            reg[1],
                            reg[2],
                            reg[3],
                            reg[4],
                            reg[5],
                            &self.memory_mapping,
                            &mut result,
                        );
                        reg[0] = result?;
                        if instruction_meter_enabled {
                            remaining_insn_count = instruction_meter.get_remaining();
                        }
                    } else if let Some(target_pc) = self.executable.lookup_bpf_function(insn.imm as u32) {
                        // make BPF to BPF call
                        reg[ebpf::STACK_REG] = self.stack.push(
                            &reg[ebpf::FIRST_SCRATCH_REG
                                ..ebpf::FIRST_SCRATCH_REG + ebpf::SCRATCH_REGS],
                            next_pc,
                        )?;
                        next_pc = self.check_pc(pc, target_pc)?;
                    } else {
                        self.executable.report_unresolved_symbol(pc)?;
                    }
                }

                ebpf::EXIT => {
                    match self.stack.pop::<E>() {
                        Ok((saved_reg, stack_ptr, ptr)) => {
                            // Return from BPF to BPF call
                            reg[ebpf::FIRST_SCRATCH_REG
                                ..ebpf::FIRST_SCRATCH_REG + ebpf::SCRATCH_REGS]
                                .copy_from_slice(&saved_reg);
                            reg[ebpf::STACK_REG] = stack_ptr;
                            next_pc = self.check_pc(pc, ptr)?;
                        }
                        _ => {
                            debug!("BPF instructions executed (interp): {:?}", total_insn_count + self.last_insn_count);
                            debug!(
                                "Max frame depth reached: {:?}",
                                self.stack.get_max_frame_index()
                            );
                            return Ok(reg[0]);
                        }
                    }
                }
                _ => return Err(EbpfError::UnsupportedInstruction(pc + ebpf::ELF_INSN_DUMP_OFFSET)),
            }
            if instruction_meter_enabled && self.last_insn_count >= remaining_insn_count {
                return Err(EbpfError::ExceededMaxInstructions(pc + 1 + ebpf::ELF_INSN_DUMP_OFFSET, initial_insn_count));
            }
        }

        Err(EbpfError::ExecutionOverrun(
            next_pc + ebpf::ELF_INSN_DUMP_OFFSET,
        ))
    }

    fn check_pc(&self, current_pc: usize, target_pc: usize) -> Result<usize, EbpfError<E>> {
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
        let initial_insn_count = if self.executable.get_config().enable_instruction_meter {
            instruction_meter.get_remaining()
        } else {
            0
        };
        let result: ProgramResult<E> = Ok(0);
        let compiled_program = self
            .executable
            .get_compiled_program()
            .ok_or(EbpfError::JitNotCompiled)?;
        unsafe {
            self.syscall_context_objects[SYSCALL_CONTEXT_OBJECTS_OFFSET - 1] =
                &mut self.tracer as *mut _ as *mut u8;
            self.last_insn_count = (compiled_program.main)(
                &result,
                reg1,
                &*(self.syscall_context_objects.as_ptr() as *const JitProgramArgument),
                instruction_meter,
            )
            .max(0) as u64;
        }
        if self.executable.get_config().enable_instruction_meter {
            let remaining_insn_count = instruction_meter.get_remaining();
            self.total_insn_count = remaining_insn_count - self.last_insn_count;
            instruction_meter.consume(self.total_insn_count);
            self.total_insn_count += initial_insn_count - remaining_insn_count;
        }
        match result {
            Err(EbpfError::ExceededMaxInstructions(pc, _)) => {
                Err(EbpfError::ExceededMaxInstructions(pc, initial_insn_count))
            }
            x => x,
        }
    }
}
