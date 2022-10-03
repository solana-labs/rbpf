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

//! Virtual machine for eBPF programs.

use crate::{
    call_frames::CallFrames,
    disassembler::disassemble_instruction,
    ebpf,
    elf::Executable,
    error::EbpfError,
    interpreter::Interpreter,
    memory_region::{MemoryMapping, MemoryRegion},
    static_analysis::Analysis,
    verifier::Verifier,
};
use std::{
    collections::{BTreeMap, HashMap},
    fmt::Debug,
    marker::PhantomData,
    mem, ptr,
};

/// Same as `Result` but provides a stable memory layout
#[derive(Debug)]
#[repr(C, u64)]
pub enum StableResult<T, E> {
    /// Success
    Ok(T),
    /// Failure
    Err(E),
}

impl<T: Debug, E: Debug> StableResult<T, E> {
    /// `true` if `Ok`
    pub fn is_ok(&self) -> bool {
        match self {
            Self::Ok(_) => true,
            Self::Err(_) => false,
        }
    }

    /// `true` if `Err`
    pub fn is_err(&self) -> bool {
        match self {
            Self::Ok(_) => false,
            Self::Err(_) => true,
        }
    }

    /// Returns the inner value if `Ok`, panics otherwise
    pub fn unwrap(self) -> T {
        match self {
            Self::Ok(value) => value,
            Self::Err(error) => panic!("unwrap {:?}", error),
        }
    }

    /// Returns the inner error if `Err`, panics otherwise
    pub fn unwrap_err(self) -> E {
        match self {
            Self::Ok(value) => panic!("unwrap_err {:?}", value),
            Self::Err(error) => error,
        }
    }
}

impl<T, E> From<StableResult<T, E>> for Result<T, E> {
    fn from(result: StableResult<T, E>) -> Self {
        match result {
            StableResult::Ok(value) => Ok(value),
            StableResult::Err(value) => Err(value),
        }
    }
}

impl<T, E> From<Result<T, E>> for StableResult<T, E> {
    fn from(result: Result<T, E>) -> Self {
        match result {
            Ok(value) => Self::Ok(value),
            Err(value) => Self::Err(value),
        }
    }
}

/// Return value of programs and syscalls
pub type ProgramResult = StableResult<u64, EbpfError>;

/// Syscall initialization function
pub type SyscallInit<'a, C> = fn(C) -> Box<(dyn SyscallObject + 'a)>;

/// Syscall function without context
pub type SyscallFunction<O> =
    fn(O, u64, u64, u64, u64, u64, &mut MemoryMapping, &mut ProgramResult);

/// Syscall with context
pub trait SyscallObject {
    /// Call the syscall function
    #[allow(clippy::too_many_arguments)]
    fn call(
        &mut self,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
        memory_mapping: &mut MemoryMapping,
        result: &mut ProgramResult,
    );
}

/// Syscall function and binding slot for a context object
#[derive(Debug, PartialEq, Eq)]
pub struct Syscall {
    /// Syscall init
    pub init: u64,
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
#[derive(Debug, PartialEq, Eq, Default)]
pub struct SyscallRegistry {
    /// Function pointers by symbol
    entries: HashMap<u32, Syscall>,
    /// Context object slots by function pointer
    context_object_slots: HashMap<u64, usize>,
}

impl SyscallRegistry {
    const MAX_SYSCALLS: usize = 128;

    /// Register a syscall function by its symbol hash
    pub fn register_syscall_by_hash<'a, C, O: SyscallObject>(
        &mut self,
        hash: u32,
        init: SyscallInit<'a, C>,
        function: SyscallFunction<&mut O>,
    ) -> Result<(), EbpfError> {
        let init = init as *const u8 as u64;
        let function = function as *const u8 as u64;
        let context_object_slot = self.entries.len();
        if context_object_slot == SyscallRegistry::MAX_SYSCALLS {
            return Err(EbpfError::TooManySyscalls);
        }
        if self
            .entries
            .insert(
                hash,
                Syscall {
                    init,
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
            Err(EbpfError::SyscallAlreadyRegistered(hash as usize))
        } else {
            Ok(())
        }
    }

    /// Register a syscall function by its symbol name
    pub fn register_syscall_by_name<'a, C, O: SyscallObject>(
        &mut self,
        name: &[u8],
        init: SyscallInit<'a, C>,
        function: SyscallFunction<&mut O>,
    ) -> Result<(), EbpfError> {
        self.register_syscall_by_hash::<C, O>(ebpf::hash_symbol_name(name), init, function)
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

    /// Calculate memory size
    pub fn mem_size(&self) -> usize {
        mem::size_of::<Self>()
            + self.entries.capacity() * mem::size_of::<(u32, Syscall)>()
            + self.context_object_slots.capacity() * mem::size_of::<(u64, usize)>()
    }
}

/// VM configuration settings
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// Enable dynamic string allocation for labels
    pub enable_symbol_and_section_labels: bool,
    /// Reject ELF files containing issues that the verifier did not catch before (up to v0.2.21)
    pub reject_broken_elfs: bool,
    /// Ratio of native host instructions per random no-op in JIT (0 = OFF)
    pub noop_instruction_rate: u32,
    /// Enable disinfection of immediate values and offsets provided by the user in JIT
    pub sanitize_user_provided_values: bool,
    /// Encrypt the environment registers in JIT
    pub encrypt_environment_registers: bool,
    /// Throw ElfError::SymbolHashCollision when a BPF function collides with a registered syscall
    pub syscall_bpf_function_hash_collision: bool,
    /// Have the verifier reject "callx r10"
    pub reject_callx_r10: bool,
    /// Use dynamic stack frame sizes
    pub dynamic_stack_frames: bool,
    /// Enable native signed division
    pub enable_sdiv: bool,
    /// Avoid copying read only sections when possible
    pub optimize_rodata: bool,
    /// Support syscalls via pseudo calls (insn.src = 0)
    pub static_syscalls: bool,
    /// Allow sh_addr != sh_offset in elf sections. Used in SBFv2 to align
    /// section vaddrs to MM_PROGRAM_START.
    pub enable_elf_vaddr: bool,
    /// Use the new ELF parser
    pub new_elf_parser: bool,
    /// Ensure that rodata sections don't exceed their maximum allowed size and
    /// overlap with the stack
    pub reject_rodata_stack_overlap: bool,
    /// Use aligned memory mapping
    pub aligned_memory_mapping: bool,
}

impl Config {
    /// Returns the size of the stack memory region
    pub fn stack_size(&self) -> usize {
        self.stack_frame_size * self.max_call_depth
    }
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
            enable_symbol_and_section_labels: false,
            reject_broken_elfs: false,
            noop_instruction_rate: 256,
            sanitize_user_provided_values: true,
            encrypt_environment_registers: true,
            syscall_bpf_function_hash_collision: true,
            reject_callx_r10: true,
            dynamic_stack_frames: true,
            enable_sdiv: true,
            optimize_rodata: true,
            static_syscalls: true,
            enable_elf_vaddr: true,
            new_elf_parser: true,
            reject_rodata_stack_overlap: true,
            aligned_memory_mapping: true,
        }
    }
}

/// Static constructors for Executable
impl<I: 'static + InstructionMeter> Executable<I> {
    /// Creates an executable from an ELF file
    pub fn from_elf(
        elf_bytes: &[u8],
        config: Config,
        syscall_registry: SyscallRegistry,
    ) -> Result<Self, EbpfError> {
        let executable = Executable::load(config, elf_bytes, syscall_registry)?;
        Ok(executable)
    }
    /// Creates an executable from machine code
    pub fn from_text_bytes(
        text_bytes: &[u8],
        config: Config,
        syscall_registry: SyscallRegistry,
        bpf_functions: BTreeMap<u32, (usize, String)>,
    ) -> Result<Self, EbpfError> {
        Ok(Executable::new_from_text_bytes(
            config,
            text_bytes,
            syscall_registry,
            bpf_functions,
        ))
    }
}

/// Verified executable
#[derive(Debug, PartialEq)]
#[repr(transparent)]
pub struct VerifiedExecutable<V: Verifier, I: InstructionMeter> {
    executable: Executable<I>,
    _verifier: PhantomData<V>,
}

impl<V: Verifier, I: InstructionMeter> VerifiedExecutable<V, I> {
    /// Verify an executable
    pub fn from_executable(executable: Executable<I>) -> Result<Self, EbpfError> {
        <V as Verifier>::verify(executable.get_text_bytes().1, executable.get_config())?;
        Ok(VerifiedExecutable {
            executable,
            _verifier: PhantomData,
        })
    }

    /// JIT compile the executable
    #[cfg(feature = "jit")]
    pub fn jit_compile(&mut self) -> Result<(), EbpfError> {
        Executable::<I>::jit_compile(&mut self.executable)
    }

    /// Get a reference to the underlying executable
    pub fn get_executable(&self) -> &Executable<I> {
        &self.executable
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
    pub fn new<I: InstructionMeter>(tracer: &Tracer, analysis: &Analysis<I>) -> Self {
        let mut result = Self {
            edge_counter_max: 0,
            edges: BTreeMap::new(),
        };
        let mut last_basic_block = usize::MAX;
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
    pub fn write<W: std::io::Write, I: InstructionMeter>(
        &self,
        output: &mut W,
        analysis: &Analysis<I>,
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

/// A virtual machine to run eBPF programs.
///
/// # Examples
///
/// ```
/// use solana_rbpf::{ebpf, elf::{Executable, register_bpf_function}, memory_region::MemoryRegion, vm::{Config, EbpfVm, TestInstructionMeter, SyscallRegistry, VerifiedExecutable}, verifier::RequisiteVerifier};
///
/// let prog = &[
///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
/// ];
/// let mem = &mut [
///     0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd
/// ];
///
/// // Instantiate a VM.
/// let config = Config::default();
/// let mut bpf_functions = std::collections::BTreeMap::new();
/// let syscall_registry = SyscallRegistry::default();
/// register_bpf_function(&config, &mut bpf_functions, &syscall_registry, 0, "entrypoint").unwrap();
/// let mut executable = Executable::<TestInstructionMeter>::from_text_bytes(prog, config, syscall_registry, bpf_functions).unwrap();
/// let mem_region = MemoryRegion::new_writable(mem, ebpf::MM_INPUT_START);
/// let verified_executable = VerifiedExecutable::<RequisiteVerifier, TestInstructionMeter>::from_executable(executable).unwrap();
/// let mut vm = EbpfVm::new(&verified_executable, &mut [], vec![mem_region]).unwrap();
///
/// // Provide a reference to the packet data.
/// let res = vm.execute_program_interpreted(&mut TestInstructionMeter { remaining: 1 }).unwrap();
/// assert_eq!(res, 0);
/// ```
pub struct EbpfVm<'a, V: Verifier, I: InstructionMeter> {
    pub(crate) verified_executable: &'a VerifiedExecutable<V, I>,
    pub(crate) program: &'a [u8],
    pub(crate) program_vm_addr: u64,
    pub(crate) program_environment: ProgramEnvironment<'a>,
    syscall_context_object_pool: Vec<Box<dyn SyscallObject + 'a>>,
    pub(crate) stack: CallFrames<'a>,
    pub(crate) total_insn_count: u64,
}

impl<'a, V: Verifier, I: InstructionMeter> EbpfVm<'a, V, I> {
    /// Create a new virtual machine instance, and load an eBPF program into that instance.
    /// When attempting to load the program, it passes through a simple verifier.
    ///
    /// # Examples
    ///
    /// ```
    /// use solana_rbpf::{ebpf, elf::{Executable, register_bpf_function}, vm::{Config, EbpfVm, TestInstructionMeter, SyscallRegistry, VerifiedExecutable}, verifier::RequisiteVerifier};
    ///
    /// let prog = &[
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// // Instantiate a VM.
    /// let config = Config::default();
    /// let mut bpf_functions = std::collections::BTreeMap::new();
    /// let syscall_registry = SyscallRegistry::default();
    /// register_bpf_function(&config, &mut bpf_functions, &syscall_registry, 0, "entrypoint").unwrap();
    /// let mut executable = Executable::<TestInstructionMeter>::from_text_bytes(prog, config, syscall_registry, bpf_functions).unwrap();
    /// let verified_executable = VerifiedExecutable::<RequisiteVerifier, TestInstructionMeter>::from_executable(executable).unwrap();
    /// let mut vm = EbpfVm::new(&verified_executable, &mut [], Vec::new()).unwrap();
    /// ```
    pub fn new(
        verified_executable: &'a VerifiedExecutable<V, I>,
        heap_region: &mut [u8],
        additional_regions: Vec<MemoryRegion>,
    ) -> Result<EbpfVm<'a, V, I>, EbpfError> {
        let executable = verified_executable.get_executable();
        let config = executable.get_config();
        let mut stack = CallFrames::new(config);
        let regions: Vec<MemoryRegion> = vec![
            verified_executable.get_executable().get_ro_region(),
            stack.get_memory_region(),
            MemoryRegion::new_writable(heap_region, ebpf::MM_HEAP_START),
        ]
        .into_iter()
        .chain(additional_regions.into_iter())
        .collect();
        let (program_vm_addr, program) = executable.get_text_bytes();
        let number_of_syscalls = executable.get_syscall_registry().get_number_of_syscalls();
        let vm = EbpfVm {
            verified_executable,
            program,
            program_vm_addr,
            program_environment: ProgramEnvironment {
                memory_mapping: MemoryMapping::new(regions, config)?,
                syscall_context_objects: [ptr::null_mut(); SyscallRegistry::MAX_SYSCALLS],
                tracer: Tracer::default(),
            },
            syscall_context_object_pool: Vec::with_capacity(number_of_syscalls),
            stack,
            total_insn_count: 0,
        };

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
        &self.program_environment.tracer
    }

    /// Initializes and binds the context object instances for all previously registered syscalls
    ///
    /// # Examples
    ///
    /// ```
    /// use solana_rbpf::{ebpf, elf::{Executable, register_bpf_function}, vm::{Config, EbpfVm, SyscallObject, SyscallRegistry, TestInstructionMeter, VerifiedExecutable}, syscalls::BpfTracePrintf, verifier::RequisiteVerifier};
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
    /// syscall_registry.register_syscall_by_hash(6, BpfTracePrintf::init::<u64>, BpfTracePrintf::call).unwrap();
    /// // Instantiate an Executable and VM
    /// let config = Config::default();
    /// let mut bpf_functions = std::collections::BTreeMap::new();
    /// register_bpf_function(&config, &mut bpf_functions, &syscall_registry, 0, "entrypoint").unwrap();
    /// let mut executable = Executable::<TestInstructionMeter>::from_text_bytes(prog, config, syscall_registry, bpf_functions).unwrap();
    /// let verified_executable = VerifiedExecutable::<RequisiteVerifier, TestInstructionMeter>::from_executable(executable).unwrap();
    /// let mut vm = EbpfVm::new(&verified_executable, &mut [], Vec::new()).unwrap();
    /// // Bind a context object instance to the previously registered syscall
    /// vm.bind_syscall_context_objects(0);
    /// ```
    pub fn bind_syscall_context_objects<C: Clone>(
        &mut self,
        syscall_context: C,
    ) -> Result<(), EbpfError> {
        let syscall_registry = self
            .verified_executable
            .get_executable()
            .get_syscall_registry();

        for syscall in syscall_registry.entries.values() {
            let syscall_object_init_fn: SyscallInit<C> =
                unsafe { std::mem::transmute(syscall.init) };
            let syscall_context_object: Box<dyn SyscallObject + 'a> =
                syscall_object_init_fn(syscall_context.clone());
            let fat_ptr: DynTraitFatPointer =
                unsafe { std::mem::transmute(&*syscall_context_object) };
            let slot = syscall_registry
                .lookup_context_object_slot(fat_ptr.vtable.methods[0] as u64)
                .ok_or(EbpfError::SyscallNotRegistered(
                    fat_ptr.vtable.methods[0] as usize,
                ))?;

            debug_assert!(self.program_environment.syscall_context_objects[slot].is_null());
            self.program_environment.syscall_context_objects[slot] = fat_ptr.data;
            // Keep the dyn trait objects so that they can be dropped properly later
            self.syscall_context_object_pool
                .push(syscall_context_object);
        }

        Ok(())
    }

    /// Lookup a syscall context object by its function pointer. Used for testing and validation.
    pub fn get_syscall_context_object(&self, syscall_function: usize) -> Option<*mut u8> {
        self.verified_executable
            .get_executable()
            .get_syscall_registry()
            .lookup_context_object_slot(syscall_function as u64)
            .map(|slot| self.program_environment.syscall_context_objects[slot])
    }

    /// Execute the program loaded, with the given packet data.
    ///
    /// Warning: The program is executed without limiting the number of
    /// instructions that can be executed
    ///
    /// # Examples
    ///
    /// ```
    /// use solana_rbpf::{ebpf, elf::{Executable, register_bpf_function}, memory_region::MemoryRegion, vm::{Config, EbpfVm, TestInstructionMeter, SyscallRegistry, VerifiedExecutable}, verifier::RequisiteVerifier};
    ///
    /// let prog = &[
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    /// let mem = &mut [
    ///     0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd
    /// ];
    ///
    /// // Instantiate a VM.
    /// let config = Config::default();
    /// let mut bpf_functions = std::collections::BTreeMap::new();
    /// let syscall_registry = SyscallRegistry::default();
    /// register_bpf_function(&config, &mut bpf_functions, &syscall_registry, 0, "entrypoint").unwrap();
    /// let mut executable = Executable::<TestInstructionMeter>::from_text_bytes(prog, config, syscall_registry, bpf_functions).unwrap();
    /// let verified_executable = VerifiedExecutable::<RequisiteVerifier, TestInstructionMeter>::from_executable(executable).unwrap();
    /// let mem_region = MemoryRegion::new_writable(mem, ebpf::MM_INPUT_START);
    /// let mut vm = EbpfVm::new(&verified_executable, &mut [], vec![mem_region]).unwrap();
    ///
    /// // Provide a reference to the packet data.
    /// let res = vm.execute_program_interpreted(&mut TestInstructionMeter { remaining: 1 }).unwrap();
    /// assert_eq!(res, 0);
    /// ```
    pub fn execute_program_interpreted(&mut self, instruction_meter: &mut I) -> ProgramResult {
        let mut result = Ok(None);
        let (initial_insn_count, due_insn_count) = {
            let mut interpreter = match Interpreter::new(self, instruction_meter) {
                Ok(interpreter) => interpreter,
                Err(error) => return ProgramResult::Err(error),
            };
            while let Ok(None) = result {
                result = interpreter.step();
            }
            (interpreter.initial_insn_count, interpreter.due_insn_count)
        };
        if self
            .verified_executable
            .get_executable()
            .get_config()
            .enable_instruction_meter
        {
            instruction_meter.consume(due_insn_count);
            self.total_insn_count = initial_insn_count - instruction_meter.get_remaining();
        }
        match result {
            Ok(None) => unreachable!(),
            Ok(Some(value)) => ProgramResult::Ok(value),
            Err(error) => ProgramResult::Err(error),
        }
    }

    /// Execute the previously JIT-compiled program, with the given packet data in a manner
    /// very similar to `execute_program_interpreted()`.
    ///
    /// # Safety
    ///
    /// **WARNING:** JIT-compiled assembly code is not safe. It may be wise to check that
    /// the program works with the interpreter before running the JIT-compiled version of it.
    ///
    #[cfg(feature = "jit")]
    pub fn execute_program_jit(&mut self, instruction_meter: &mut I) -> ProgramResult {
        let executable = self.verified_executable.get_executable();
        let initial_insn_count = if executable.get_config().enable_instruction_meter {
            instruction_meter.get_remaining()
        } else {
            0
        };
        let mut result = ProgramResult::Ok(0);
        let compiled_program = match executable
            .get_compiled_program()
            .ok_or(EbpfError::JitNotCompiled)
        {
            Ok(compiled_program) => compiled_program,
            Err(error) => return ProgramResult::Err(error),
        };
        let instruction_meter_final = unsafe {
            (compiled_program.main)(
                &mut result,
                ebpf::MM_INPUT_START,
                &self.program_environment,
                instruction_meter,
            )
            .max(0) as u64
        };
        if executable.get_config().enable_instruction_meter {
            let remaining_insn_count = instruction_meter.get_remaining();
            let due_insn_count = remaining_insn_count - instruction_meter_final;
            instruction_meter.consume(due_insn_count);
            self.total_insn_count = initial_insn_count + due_insn_count - remaining_insn_count;
            // Same as:
            // self.total_insn_count = initial_insn_count - instruction_meter.get_remaining();
        }
        match result {
            ProgramResult::Err(EbpfError::ExceededMaxInstructions(pc, _)) => {
                ProgramResult::Err(EbpfError::ExceededMaxInstructions(pc, initial_insn_count))
            }
            x => x,
        }
    }
}

/// The execution environment of a program instance.
#[repr(C)]
pub struct ProgramEnvironment<'a> {
    /// The MemoryMapping describing the address space of the program
    pub memory_mapping: MemoryMapping<'a>,
    /// Pointers to the context objects of syscalls
    pub syscall_context_objects: [*mut u8; SyscallRegistry::MAX_SYSCALLS],
    /// The instruction tracer
    pub tracer: Tracer,
}

impl<'a> ProgramEnvironment<'a> {
    /// Offset to Self::memory_mapping
    pub const MEMORY_MAPPING_OFFSET: usize = 0;
    /// Offset of Self::syscalls
    pub const SYSCALLS_OFFSET: usize =
        Self::MEMORY_MAPPING_OFFSET + mem::size_of::<MemoryMapping>();
    /// Offset of Self::tracer
    pub const TRACER_OFFSET: usize =
        Self::SYSCALLS_OFFSET + mem::size_of::<[*mut u8; SyscallRegistry::MAX_SYSCALLS]>();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_program_result_is_stable() {
        let ok = ProgramResult::Ok(42);
        assert_eq!(unsafe { *(&ok as *const _ as *const u64) }, 0);
        let err = ProgramResult::Err(EbpfError::JitNotCompiled);
        assert_eq!(unsafe { *(&err as *const _ as *const u64) }, 1);
    }

    #[test]
    fn test_program_environment_offsets() {
        let config = Config::default();
        let env = ProgramEnvironment {
            memory_mapping: MemoryMapping::new(vec![], &config).unwrap(),
            syscall_context_objects: [ptr::null_mut(); SyscallRegistry::MAX_SYSCALLS],
            tracer: Tracer::default(),
        };
        assert_eq!(
            unsafe {
                (&env.memory_mapping as *const _ as *const u8)
                    .offset_from(&env as *const _ as *const _)
            },
            ProgramEnvironment::MEMORY_MAPPING_OFFSET as isize
        );
        assert_eq!(
            unsafe {
                (&env.syscall_context_objects as *const _ as *const u8)
                    .offset_from(&env as *const _ as *const _)
            },
            ProgramEnvironment::SYSCALLS_OFFSET as isize
        );
        assert_eq!(
            unsafe {
                (&env.tracer as *const _ as *const u8).offset_from(&env as *const _ as *const _)
            },
            ProgramEnvironment::TRACER_OFFSET as isize
        );
    }
}
