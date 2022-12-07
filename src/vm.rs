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
    aligned_memory::AlignedMemory,
    ebpf,
    elf::Executable,
    error::EbpfError,
    interpreter::Interpreter,
    memory_region::{MemoryMapping, MemoryRegion},
    static_analysis::{Analysis, TraceLogEntry},
    verifier::Verifier,
};
use rand::Rng;
use std::{
    collections::{BTreeMap, HashMap},
    fmt::Debug,
    marker::PhantomData,
    mem,
    sync::Arc,
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

/// Holds the function symbols of an Executable
pub type FunctionRegistry = BTreeMap<u32, (usize, String)>;

/// Syscall function without context
pub type BuiltInFunction<C> =
    fn(&mut C, u64, u64, u64, u64, u64, &mut MemoryMapping, &mut ProgramResult);

/// Represents the interface to a fixed functionality program
pub struct BuiltInProgram<C: ContextObject> {
    /// Holds the Config if this is a loader program
    config: Option<Box<Config>>,
    /// Function pointers by symbol
    functions: HashMap<u32, (&'static str, BuiltInFunction<C>)>,
}

impl<C: ContextObject> BuiltInProgram<C> {
    /// Constructs a loader built-in program
    pub fn new_loader(config: Config) -> Self {
        Self {
            config: Some(Box::new(config)),
            functions: HashMap::new(),
        }
    }

    /// Get the configuration settings assuming this is a loader program
    pub fn get_config(&self) -> &Config {
        self.config.as_ref().unwrap()
    }

    /// Register a built-in function
    pub fn register_function_by_name(
        &mut self,
        name: &'static str,
        function: BuiltInFunction<C>,
    ) -> Result<(), EbpfError> {
        let key = ebpf::hash_symbol_name(name.as_bytes());
        if self.functions.insert(key, (name, function)).is_some() {
            Err(EbpfError::FunctionAlreadyRegistered(key as usize))
        } else {
            Ok(())
        }
    }

    /// Get a symbol's function pointer
    pub fn lookup_function(&self, key: u32) -> Option<(&'static str, BuiltInFunction<C>)> {
        self.functions.get(&key).cloned()
    }

    /// Calculate memory size
    pub fn mem_size(&self) -> usize {
        mem::size_of::<Self>()
            + if self.config.is_some() {
                mem::size_of::<Config>()
            } else {
                0
            }
            + self.functions.capacity()
                * mem::size_of::<(u32, (&'static str, BuiltInFunction<C>))>()
    }
}

impl<C: ContextObject> Default for BuiltInProgram<C> {
    fn default() -> Self {
        Self {
            config: None,
            functions: HashMap::new(),
        }
    }
}

impl<C: ContextObject> Debug for BuiltInProgram<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        writeln!(f, "{:?}", unsafe {
            std::mem::transmute::<_, &HashMap<u32, *const u8>>(&self.functions)
        })?;
        Ok(())
    }
}

impl<C: ContextObject> PartialEq for BuiltInProgram<C> {
    fn eq(&self, other: &Self) -> bool {
        for ((a_key, a_function), (b_key, b_function)) in
            self.functions.iter().zip(other.functions.iter())
        {
            if a_key != b_key || a_function as *const _ as usize != b_function as *const _ as usize
            {
                return false;
            }
        }
        true
    }
}

/// Shift the Config::runtime_environment_key by this many bits to the LSB
///
/// 3 bits for 8 Byte alignment, and 1 bit to have encoding space for the RuntimeEnvironment.
pub const PROGRAM_ENVIRONMENT_KEY_SHIFT: u32 = 4;

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
    /// Encrypt the runtime environment in JIT
    ///
    /// Use 0 to disable encryption. Otherwise only leave PROGRAM_ENVIRONMENT_KEY_SHIFT MSBs 0.
    pub runtime_environment_key: i32,
    /// Throw ElfError::SymbolHashCollision when a BPF function collides with a registered syscall
    pub syscall_internal_function_hash_collision: bool,
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
            runtime_environment_key: rand::thread_rng().gen::<i32>()
                >> PROGRAM_ENVIRONMENT_KEY_SHIFT,
            syscall_internal_function_hash_collision: true,
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
impl<C: ContextObject> Executable<C> {
    /// Creates an executable from an ELF file
    pub fn from_elf(elf_bytes: &[u8], loader: Arc<BuiltInProgram<C>>) -> Result<Self, EbpfError> {
        let executable = Executable::load(elf_bytes, loader)?;
        Ok(executable)
    }
    /// Creates an executable from machine code
    pub fn from_text_bytes(
        text_bytes: &[u8],
        loader: Arc<BuiltInProgram<C>>,
        function_registry: FunctionRegistry,
    ) -> Result<Self, EbpfError> {
        Executable::new_from_text_bytes(text_bytes, loader, function_registry)
            .map_err(EbpfError::ElfError)
    }
}

/// Verified executable
#[derive(Debug, PartialEq)]
#[repr(transparent)]
pub struct VerifiedExecutable<V: Verifier, C: ContextObject> {
    executable: Executable<C>,
    _verifier: PhantomData<V>,
}

impl<V: Verifier, C: ContextObject> VerifiedExecutable<V, C> {
    /// Verify an executable
    pub fn from_executable(executable: Executable<C>) -> Result<Self, EbpfError> {
        <V as Verifier>::verify(
            executable.get_text_bytes().1,
            executable.get_config(),
            executable.get_function_registry(),
        )?;
        Ok(VerifiedExecutable {
            executable,
            _verifier: PhantomData,
        })
    }

    /// JIT compile the executable
    #[cfg(all(feature = "jit", not(target_os = "windows"), target_arch = "x86_64"))]
    pub fn jit_compile(&mut self) -> Result<(), EbpfError> {
        Executable::<C>::jit_compile(&mut self.executable)
    }

    /// Get a reference to the underlying executable
    pub fn get_executable(&self) -> &Executable<C> {
        &self.executable
    }
}

/// Runtime context
pub trait ContextObject {
    /// Called for every instruction executed when tracing is enabled
    fn trace(&mut self, state: [u64; 12]);
    /// Consume instructions from meter
    fn consume(&mut self, amount: u64);
    /// Get the number of remaining instructions allowed
    fn get_remaining(&self) -> u64;
}

/// Simple instruction meter for testing
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TestContextObject {
    /// Contains the register state at every instruction in order of execution
    pub trace_log: Vec<TraceLogEntry>,
    /// Maximal amount of instructions which still can be executed
    pub remaining: u64,
}

impl ContextObject for TestContextObject {
    fn trace(&mut self, state: [u64; 12]) {
        self.trace_log.push(state);
    }

    fn consume(&mut self, amount: u64) {
        debug_assert!(amount <= self.remaining, "Execution count exceeded");
        self.remaining = self.remaining.saturating_sub(amount);
    }

    fn get_remaining(&self) -> u64 {
        self.remaining
    }
}

impl TestContextObject {
    /// Initialize with instruction meter
    pub fn new(remaining: u64) -> Self {
        Self {
            trace_log: Vec::new(),
            remaining,
        }
    }

    /// Compares an interpreter trace and a JIT trace.
    ///
    /// The log of the JIT can be longer because it only validates the instruction meter at branches.
    pub fn compare_trace_log(interpreter: &Self, jit: &Self) -> bool {
        let interpreter = interpreter.trace_log.as_slice();
        let mut jit = jit.trace_log.as_slice();
        if jit.len() > interpreter.len() {
            jit = &jit[0..interpreter.len()];
        }
        interpreter == jit
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
    pub fn new(trace_log: &[[u64; 12]], analysis: &Analysis) -> Self {
        let mut result = Self {
            edge_counter_max: 0,
            edges: BTreeMap::new(),
        };
        let mut last_basic_block = usize::MAX;
        for traced_instruction in trace_log.iter() {
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

/// A call frame used for function calls inside the Interpreter
#[derive(Clone, Default)]
pub struct CallFrame {
    /// The caller saved registers
    pub caller_saved_registers: [u64; ebpf::SCRATCH_REGS],
    /// The callers frame pointer
    pub frame_pointer: u64,
    /// The target_pc of the exit instruction which returns back to the caller
    pub target_pc: usize,
}

/// Runtime state
// Keep changes here in sync with RuntimeEnvironmentSlot
#[repr(C)]
pub struct RuntimeEnvironment<'a, C: ContextObject> {
    /// Needed to exit from the guest back into the host
    pub host_stack_pointer: *mut u64,
    /// The current call depth.
    ///
    /// Incremented on calls and decremented on exits. It's used to enforce
    /// config.max_call_depth and to know when to terminate execution.
    pub call_depth: u64,
    /// Guest stack pointer (r11).
    ///
    /// The stack pointer isn't exposed as an actual register. Only sub and add
    /// instructions (typically generated by the LLVM backend) are allowed to
    /// access it when config.dynamic_stack_frames=true. Its value is only
    /// stored here and therefore the register is not tracked in REGISTER_MAP.
    pub stack_pointer: u64,
    /// Pointer to ContextObject
    pub context_object_pointer: &'a mut C,
    /// Last return value of instruction_meter.get_remaining()
    pub previous_instruction_meter: u64,
    /// CPU cycles accumulated by the stop watch
    pub stopwatch_numerator: u64,
    /// Number of times the stop watch was used
    pub stopwatch_denominator: u64,
    /// ProgramResult inlined
    pub program_result: ProgramResult,
    /// MemoryMapping inlined
    pub memory_mapping: MemoryMapping<'a>,
    /// Stack of CallFrames used by the Interpreter
    pub call_frames: Vec<CallFrame>,
}

/// A virtual machine to run eBPF programs.
///
/// # Examples
///
/// ```
/// use solana_rbpf::{ebpf, elf::Executable, memory_region::MemoryRegion, vm::{Config, EbpfVm, TestContextObject, FunctionRegistry, BuiltInProgram, VerifiedExecutable}, verifier::RequisiteVerifier};
///
/// let prog = &[
///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
/// ];
/// let mem = &mut [
///     0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd
/// ];
///
/// let loader = std::sync::Arc::new(BuiltInProgram::new_loader(Config::default()));
/// let function_registry = FunctionRegistry::default();
/// let mut executable = Executable::<TestContextObject>::from_text_bytes(prog, loader, function_registry).unwrap();
/// let mem_region = MemoryRegion::new_writable(mem, ebpf::MM_INPUT_START);
/// let verified_executable = VerifiedExecutable::<RequisiteVerifier, TestContextObject>::from_executable(executable).unwrap();
/// let mut context_object = TestContextObject::new(1);
/// let mut vm = EbpfVm::new(&verified_executable, &mut context_object, &mut [], vec![mem_region]).unwrap();
///
/// let (instruction_count, result) = vm.execute_program(true);
/// assert_eq!(instruction_count, 1);
/// assert_eq!(result.unwrap(), 0);
/// ```
pub struct EbpfVm<'a, V: Verifier, C: ContextObject> {
    pub(crate) verified_executable: &'a VerifiedExecutable<V, C>,
    _stack: AlignedMemory<{ ebpf::HOST_ALIGN }>,
    /// TCP port for the debugger interface
    #[cfg(feature = "debugger")]
    pub debug_port: Option<u16>,
    /// Runtime state
    pub env: RuntimeEnvironment<'a, C>,
}

impl<'a, V: Verifier, C: ContextObject> EbpfVm<'a, V, C> {
    /// Create a new virtual machine instance
    pub fn new(
        verified_executable: &'a VerifiedExecutable<V, C>,
        context_object: &'a mut C,
        heap_region: &mut [u8],
        additional_regions: Vec<MemoryRegion>,
    ) -> Result<EbpfVm<'a, V, C>, EbpfError> {
        let executable = verified_executable.get_executable();
        let config = executable.get_config();
        let mut stack = AlignedMemory::zero_filled(config.stack_size());
        let stack_pointer = ebpf::MM_STACK_START.saturating_add(if config.dynamic_stack_frames {
            // the stack is fully descending, frames start as empty and change size anytime r11 is modified
            stack.len()
        } else {
            // within a frame the stack grows down, but frames are ascending
            config.stack_frame_size
        } as u64);
        let regions: Vec<MemoryRegion> = vec![
            verified_executable.get_executable().get_ro_region(),
            MemoryRegion::new_writable_gapped(
                stack.as_slice_mut(),
                ebpf::MM_STACK_START,
                if !config.dynamic_stack_frames && config.enable_stack_frame_gaps {
                    config.stack_frame_size as u64
                } else {
                    0
                },
            ),
            MemoryRegion::new_writable(heap_region, ebpf::MM_HEAP_START),
        ]
        .into_iter()
        .chain(additional_regions.into_iter())
        .collect();
        let vm = EbpfVm {
            verified_executable,
            _stack: stack,
            #[cfg(feature = "debugger")]
            debug_port: None,
            env: RuntimeEnvironment {
                host_stack_pointer: std::ptr::null_mut(),
                call_depth: 0,
                stack_pointer,
                context_object_pointer: context_object,
                previous_instruction_meter: 0,
                stopwatch_numerator: 0,
                stopwatch_denominator: 0,
                program_result: ProgramResult::Ok(0),
                memory_mapping: MemoryMapping::new(regions, config)?,
                call_frames: vec![CallFrame::default(); config.max_call_depth],
            },
        };
        Ok(vm)
    }

    /// Execute the program
    ///
    /// If interpreted = `false` then the JIT compiled executable is used.
    pub fn execute_program(&mut self, interpreted: bool) -> (u64, ProgramResult) {
        let mut registers = [0u64; 11];
        // R1 points to beginning of input memory, R10 to the stack of the first frame
        registers[1] = ebpf::MM_INPUT_START;
        registers[ebpf::FRAME_PTR_REG] = self.env.stack_pointer;
        let executable = self.verified_executable.get_executable();
        let target_pc = executable.get_entrypoint_instruction_offset();
        let config = executable.get_config();
        let initial_insn_count = if config.enable_instruction_meter {
            self.env.context_object_pointer.get_remaining()
        } else {
            0
        };
        self.env.previous_instruction_meter = initial_insn_count;
        self.env.program_result = ProgramResult::Ok(0);
        let due_insn_count = if interpreted {
            #[cfg(feature = "debugger")]
            let debug_port = self.debug_port.clone();
            let mut interpreter = match Interpreter::new(self, registers, target_pc) {
                Ok(interpreter) => interpreter,
                Err(error) => return (0, ProgramResult::Err(error)),
            };
            #[cfg(feature = "debugger")]
            if let Some(debug_port) = debug_port {
                crate::debugger::execute(&mut interpreter, debug_port);
            } else {
                while interpreter.step() {}
            }
            #[cfg(not(feature = "debugger"))]
            while interpreter.step() {}
            interpreter.due_insn_count
        } else {
            #[cfg(all(feature = "jit", not(target_os = "windows"), target_arch = "x86_64"))]
            {
                let compiled_program = match executable
                    .get_compiled_program()
                    .ok_or(EbpfError::JitNotCompiled)
                {
                    Ok(compiled_program) => compiled_program,
                    Err(error) => return (0, ProgramResult::Err(error)),
                };
                let instruction_meter_final = compiled_program
                    .invoke(config, &mut self.env, registers, target_pc)
                    .max(0) as u64;
                self.env
                    .context_object_pointer
                    .get_remaining()
                    .saturating_sub(instruction_meter_final)
            }
            #[cfg(not(all(feature = "jit", not(target_os = "windows"), target_arch = "x86_64")))]
            {
                return (0, ProgramResult::Err(EbpfError::JitNotCompiled));
            }
        };
        let instruction_count = if config.enable_instruction_meter {
            self.env.context_object_pointer.consume(due_insn_count);
            initial_insn_count.saturating_sub(self.env.context_object_pointer.get_remaining())
        } else {
            0
        };
        if let ProgramResult::Err(EbpfError::ExceededMaxInstructions(pc, _)) =
            self.env.program_result
        {
            self.env.program_result =
                ProgramResult::Err(EbpfError::ExceededMaxInstructions(pc, initial_insn_count));
        }
        let mut result = ProgramResult::Ok(0);
        std::mem::swap(&mut result, &mut self.env.program_result);
        (instruction_count, result)
    }
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
}
