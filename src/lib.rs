// Derived from uBPF <https://github.com/iovisor/ubpf>
// Copyright 2015 Big Switch Networks, Inc
//      (uBPF: VM architecture, parts of the interpreter, originally in C)
// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//      (Translation to Rust, MetaBuff/multiple classes addition, hashmaps for syscalls)
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![allow(clippy::deprecated_cfg_attr)]
#![cfg_attr(rustfmt, rustfmt_skip)]

//! Virtual machine and JIT compiler for eBPF programs.
#![doc(html_logo_url = "https://raw.githubusercontent.com/qmonnet/rbpf/master/misc/rbpf.png",
       html_favicon_url = "https://raw.githubusercontent.com/qmonnet/rbpf/master/misc/rbpf.ico")]

#![warn(missing_docs)]
// There are unused mut warnings due to unsafe code.
#![allow(unused_mut)]
// Allows old-style clippy
#![allow(renamed_and_removed_lints)]

#![cfg_attr(feature = "cargo-clippy", allow(redundant_field_names, single_match, cast_lossless, doc_markdown, match_same_arms, unreadable_literal, new_ret_no_self))]

extern crate byteorder;
extern crate combine;
extern crate hash32;
extern crate log;
extern crate rand;
extern crate thiserror;
extern crate time;

use std::{u32, collections::HashMap, ops::Range};
use elf::EBpfElf;
use log::{debug, trace, log_enabled};
use ebpf::{EbpfError, Syscall, SyscallFunction, SyscallObject, UserDefinedError};
use memory_region::{MemoryRegion, translate_addr};
use rand::Rng;

pub mod assembler;
pub mod disassembler;
pub mod ebpf;
pub mod elf;
pub mod syscalls;
pub mod insn_builder;
pub mod memory_region;
pub mod verifier;
pub mod user_error;
mod asm_parser;
mod jit;

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
pub type JitProgram = unsafe fn(*mut u8, usize, usize) -> u64;

/// One call frame
#[derive(Clone, Debug)]
struct CallFrame {
    stack:       MemoryRegion,
    saved_reg:   [u64; 4],
    return_ptr:  usize,
}

/// When BPF calls a function other then a `syscall` it expect the new
/// function to be called in its own frame.  CallFrames manages
/// call frames
#[derive(Clone, Debug)]
struct CallFrames {
    stack:  Vec<u8>,
    frame:  usize,
    max_frame: usize,
    frames: Vec<CallFrame>,
}
impl CallFrames {
    /// New call frame, depth indicates maximum call depth
    fn new(depth: usize, size: usize) -> Self {
        let mut frames = CallFrames {
            stack: vec![0u8; depth * size],
            frame: 0,
            max_frame: 0,
            frames: vec![CallFrame { stack: MemoryRegion {
                                                addr_host: 0,
                                                addr_vm: 0,
                                                len: 0,
                                            },
                                     saved_reg: [0u64; ebpf::SCRATCH_REGS],
                                     return_ptr: 0
                                   };
                         depth],
        };
        for i in 0..depth {
            let start = i * size;
            let end = start + size;
            // Seperate each stack frame's virtual address so that stack over/under-run is caught explicitly
            let addr_vm = ebpf::MM_STACK_START + (i * 2 * size) as u64;
            frames.frames[i].stack = MemoryRegion::new_from_slice(&frames.stack[start..end], addr_vm);
        }
        frames
    }

    /// Get stack pointers
    fn get_stacks(&self) -> Vec<MemoryRegion> {
        let mut ptrs = Vec::new();
        for frame in self.frames.iter() {
            ptrs.push(frame.stack.clone());
        }
        ptrs
    }

    /// Get the address of a frame's top of stack
    fn get_stack_top(&self) -> u64 {
        self.frames[self.frame].stack.addr_vm + self.frames[self.frame].stack.len
    }

    /// Get current call frame index, 0 is the root frame
    #[allow(dead_code)]
    fn get_frame_index(&self) -> usize {
        self.frame
    }

    fn get_max_frame_index(&self) -> usize {
        self.max_frame
    }

    /// Push a frame
    fn push<E: UserDefinedError>(&mut self, saved_reg: &[u64], return_ptr: usize) -> Result<u64, EbpfError<E>> {
        if self.frame + 1 >= self.frames.len() {
            return Err(EbpfError::CallDepthExceeded(self.frames.len()));
        }
        self.frames[self.frame].saved_reg[..].copy_from_slice(saved_reg);
        self.frames[self.frame].return_ptr = return_ptr;
        self.frame += 1;
        if self.frame > self.max_frame {
            self.max_frame = self.frame;
        }
        Ok(self.get_stack_top())
    }

    /// Pop a frame
    fn pop<E: UserDefinedError>(&mut self) -> Result<([u64; ebpf::SCRATCH_REGS], u64, usize), EbpfError<E>> {
        if self.frame == 0 {
            return Err(EbpfError::ExitRootCallFrame);
        }
        self.frame -= 1;
        Ok((self.frames[self.frame].saved_reg,
            self.get_stack_top(),
            self.frames[self.frame].return_ptr))
    }
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
    fn consume(&mut self, _amount: u64) {
        println!("default consume {:?}", _amount);
    }
    fn get_remaining(&self) -> u64 {
        u64::MAX
    }
}

/// A virtual machine to run eBPF program.
///
/// # Examples
///
/// ```
/// use solana_rbpf::EbpfVm;
/// use solana_rbpf::user_error::UserError;
///
/// let prog = &[
///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
/// ];
/// let mem = &mut [
///     0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd
/// ];
///
/// // Instantiate a VM.
/// let mut vm = EbpfVm::<UserError>::new(Some(prog)).unwrap();
///
/// // Provide a reference to the packet data.
/// let res = vm.execute_program(mem, &[], &[]).unwrap();
/// assert_eq!(res, 0);
/// ```
pub struct EbpfVm<'a, E: UserDefinedError> {
    prog:             Option<&'a [u8]>,
    elf:              Option<EBpfElf>,
    verifier:         Option<Verifier<E>>,
    jit:              Option<JitProgram>,
    syscalls:         HashMap<u32, Syscall<'a, E>>,
    last_insn_count:  u64,
    total_insn_count: u64,
}

impl<'a, E: UserDefinedError> EbpfVm<'a, E> {

    /// Create a new virtual machine instance, and load an eBPF program into that instance.
    /// When attempting to load the program, it passes through a simple verifier.
    ///
    /// # Examples
    ///
    /// ```
    /// use solana_rbpf::EbpfVm;
    /// use solana_rbpf::user_error::UserError;
    ///
    /// let prog = &[
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// // Instantiate a VM.
    /// let mut vm = EbpfVm::<UserError>::new(Some(prog)).unwrap();
    /// ```
    pub fn new(prog: Option<&'a [u8]>) -> Result<EbpfVm<'a, E>, EbpfError<E>> {
        Ok(EbpfVm {
            prog:             prog,
            elf:              None,
            verifier:         None,
            jit:              None,
            syscalls:         HashMap::new(),
            last_insn_count:  0,
            total_insn_count: 0,
        })
    }

    /// Load a new eBPF program into the virtual machine instance.
    ///
    /// # Examples
    ///
    /// ```
    /// use solana_rbpf::EbpfVm;
    /// use solana_rbpf::user_error::UserError;
    ///
    /// let prog1 = &[
    ///     0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, 0
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    /// let prog2 = &[
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// // Instantiate a VM.
    /// let mut vm = EbpfVm::<UserError>::new(Some(prog1)).unwrap();
    /// vm.set_program(prog2).unwrap();
    /// ```
    pub fn set_program(&mut self, prog: &'a [u8]) -> Result<(), EbpfError<E>> {
        if let Some(verifier) = self.verifier {
            verifier(prog)?;
        }
        self.prog = Some(prog);
        Ok(())
    }

    /// Load a new eBPF program into the virtual machine instance.
    pub fn set_elf(&mut self, elf_bytes: &'a [u8]) -> Result<(), EbpfError<E>> {
        let elf = EBpfElf::load(elf_bytes)?;
        let (_, bytes) = elf.get_text_bytes()?;
        if let Some(verifier) = self.verifier {
            verifier(bytes)?;
        }
        self.elf = Some(elf);
        Ok(())
    }

    /// Set a new verifier function. The function should return an `EbpfError` if the program should be
    /// rejected by the virtual machine. If a program has been loaded to the VM already, the
    /// verifier is immediately run.
    ///
    /// # Examples
    ///
    /// ```
    /// use solana_rbpf::EbpfVm;
    /// use solana_rbpf::ebpf;
    /// use solana_rbpf::verifier::VerifierError;
    ///
    /// // Define a simple verifier function.
    /// fn verifier(prog: &[u8]) -> Result<(), VerifierError> {
    ///     let last_insn = ebpf::get_insn(prog, (prog.len() / ebpf::INSN_SIZE) - 1);
    ///     if last_insn.opc != ebpf::EXIT {
    ///        return Err(VerifierError::InvalidLastInstruction.into());
    ///     }
    ///     Ok(())
    /// }
    ///
    /// let prog1 = &[
    ///     0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, 0
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// // Instantiate a VM.
    /// let mut vm = EbpfVm::<VerifierError>::new(Some(prog1)).unwrap();
    /// // Change the verifier.
    /// vm.set_verifier(verifier).unwrap();
    /// ```
    pub fn set_verifier(&mut self, verifier: Verifier<E>) -> Result<(), EbpfError<E>> {
        if let Some(ref elf) = self.elf {
            let (_, bytes) = elf.get_text_bytes()?;
            verifier(bytes)?;
        } else if let Some(ref prog) = self.prog {
            verifier(prog)?;
        }
        self.verifier = Some(verifier);
        Ok(())
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
    /// use solana_rbpf::EbpfVm;
    /// use solana_rbpf::syscalls::bpf_trace_printf;
    /// use solana_rbpf::user_error::UserError;
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
    /// let mut vm = EbpfVm::<UserError>::new(Some(prog)).unwrap();
    ///
    /// // Register a syscall.
    /// // On running the program this syscall will print the content of registers r3, r4 and r5 to
    /// // standard output.
    /// vm.register_syscall(6, bpf_trace_printf::<UserError>).unwrap();
    /// ```
    pub fn register_syscall(&mut self,
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
    pub fn register_syscall_ex(&mut self,
                               name: &str,
                               syscall: SyscallFunction<E>,
    ) -> Result<(), EbpfError<E>> {
        self.syscalls.insert(ebpf::hash_symbol_name(name.as_bytes()), Syscall::Function(syscall));
        Ok(())
    }

    /// Same as register_syscall_ex except reguster a syscall trait object that carries
    /// along context needed by the syscall
    pub fn register_syscall_with_context_ex(&mut self,
        name: &str,
        syscall: Box<dyn SyscallObject<E> + 'a>,
    ) -> Result<(), EbpfError<E>> {
        self.syscalls.insert(ebpf::hash_symbol_name(name.as_bytes()), Syscall::Object(syscall));
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
    /// use solana_rbpf::EbpfVm;
    /// use solana_rbpf::user_error::UserError;
    ///
    /// let prog = &[
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    /// let mem = &mut [
    ///     0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd
    /// ];
    ///
    /// // Instantiate a VM.
    /// let mut vm = EbpfVm::<UserError>::new(Some(prog)).unwrap();
    ///
    /// // Provide a reference to the packet data.
    /// let res = vm.execute_program(mem, &[], &[]).unwrap();
    /// assert_eq!(res, 0);
    /// ```
    pub fn execute_program(&mut self,
                           mem: &[u8],
                           granted_ro_regions: &[MemoryRegion],
                           granted_rw_regions: &[MemoryRegion],
    ) -> Result<u64, EbpfError<E>> {
        self.execute_program_metered(mem,
                                     granted_ro_regions,
                                     granted_rw_regions,
                                     DefaultInstructionMeter{})
    }

    /// Execute the program loaded, with the given packet data and instruction meter. 
    pub fn execute_program_metered<I: InstructionMeter>(&mut self,
        mem: &[u8],
        granted_ro_regions: &[MemoryRegion],
        granted_rw_regions: &[MemoryRegion],
        mut instruction_meter: I,
    ) -> Result<u64, EbpfError<E>> {
        let result = self.execute_program_inner(mem,
                                                  granted_ro_regions,
                                                  granted_rw_regions,
                                                  &mut instruction_meter);
        instruction_meter.consume(self.last_insn_count);
        result
    }
    #[allow(unknown_lints)]
    #[allow(cyclomatic_complexity)]
    #[allow(cognitive_complexity)]
    fn execute_program_inner<I: InstructionMeter>(&mut self,
                                                      mem: &[u8],
                                                      granted_ro_regions: &[MemoryRegion],
                                                      granted_rw_regions: &[MemoryRegion],
                                                      mut instruction_meter: &mut I
    ) -> Result<u64, EbpfError<E>> {
        const U32MAX: u64 = u32::MAX as u64;

        let mut frames = CallFrames::new(ebpf::MAX_CALL_DEPTH, ebpf::STACK_FRAME_SIZE);
        let mut ro_regions = Vec::new();
        let mut rw_regions = Vec::new();
        ro_regions.extend_from_slice(granted_ro_regions);
        ro_regions.extend_from_slice(granted_rw_regions);
        rw_regions.extend_from_slice(granted_rw_regions);
        for ptr in frames.get_stacks() {
            ro_regions.push(ptr.clone());
            rw_regions.push(ptr.clone());
        }

        ro_regions.push(MemoryRegion::new_from_slice(&mem, ebpf::MM_INPUT_START));
        rw_regions.push(MemoryRegion::new_from_slice(&mem, ebpf::MM_INPUT_START));

        let mut entry: usize = 0;
        let (prog_addr, prog) =
        if let Some(ref elf) = self.elf {
            if let Ok(sections) = elf.get_ro_sections() {
                let regions: Vec<_> = sections
                                        .iter()
                                        .map( |(addr, slice)| MemoryRegion::new_from_slice(slice, *addr))
                                        .collect();
                ro_regions.extend(regions);
            }
            entry = elf.get_entrypoint_instruction_offset()?;
            elf.get_text_bytes()?
        } else if let Some(prog) = self.prog {
            (ebpf::MM_PROGRAM_START, prog)
        } else {
            return Err(EbpfError::NothingToExecute);
        };
        ro_regions.push(MemoryRegion::new_from_slice(prog, prog_addr));

        // R1 points to beginning of input memory, R10 to the stack of the first frame
        let mut reg: [u64; 11] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, frames.get_stack_top()];

        if !mem.is_empty() {
            reg[1] = ebpf::MM_INPUT_START;
        }

        let translate_load_addr = | addr: u64, len: usize, pc: usize | {
            translate_addr(addr, len, "load", pc, &ro_regions)
        };
        let translate_store_addr = | addr: u64, len: usize, pc: usize | {
            translate_addr(addr, len, "store", pc, &rw_regions)
        };

        // Check trace logging outside the instruction loop, saves ~30%
        let insn_trace = log_enabled!(log::Level::Trace);

        // Loop on instructions
        let mut next_pc: usize = entry;
        let mut remaining_insn_count = instruction_meter.get_remaining();
        self.last_insn_count = 0;
        self.total_insn_count = 0;
        while next_pc * ebpf::INSN_SIZE + ebpf::INSN_SIZE <= prog.len() {
            let pc = next_pc;
            next_pc += 1;
            let insn = ebpf::get_insn_unchecked(prog, pc);
            let dst = insn.dst as usize;
            let src = insn.src as usize;
            self.last_insn_count += 1;
            self.total_insn_count += 1;

            if insn_trace {
                trace!("    BPF: {:5?} {:016x?} frame {:?} pc {:4?} {}",
                       self.total_insn_count,
                       reg,
                       frames.get_frame_index(),
                       pc + ebpf::ELF_INSN_DUMP_OFFSET,
                       disassembler::to_insn_vec(&prog[pc * ebpf::INSN_SIZE..])[0].desc);
            }

            match insn.opc {

                // BPF_LD class
                // Since this pointer is constant, and since we already know it (mem), do not
                // bother re-fetching it, just use mem already.
                ebpf::LD_ABS_B   => {
                    let vm_addr = (mem.as_ptr() as u64).saturating_add((insn.imm as u32) as u64);
                    let host_ptr = translate_load_addr(vm_addr, 8, pc)? as *const u8;
                    reg[0] = unsafe { *host_ptr as u64 };
                },
                ebpf::LD_ABS_H   =>  {
                    let vm_addr = (mem.as_ptr() as u64).saturating_add((insn.imm as u32) as u64);
                    let host_ptr = translate_load_addr(vm_addr, 8, pc)? as *const u16;
                    reg[0] = unsafe { *host_ptr as u64 };
                },
                ebpf::LD_ABS_W   => {
                    let vm_addr = (mem.as_ptr() as u64).saturating_add((insn.imm as u32) as u64);
                    let host_ptr = translate_load_addr(vm_addr, 8, pc)? as *const u32;
                    reg[0] = unsafe { *host_ptr as u64 };
                },
                ebpf::LD_ABS_DW  => {
                    let vm_addr = (mem.as_ptr() as u64).saturating_add((insn.imm as u32) as u64);
                    let host_ptr = translate_load_addr(vm_addr, 8, pc)? as *const u64;
                    reg[0] = unsafe { *host_ptr as u64 };
                },
                ebpf::LD_IND_B   => {
                    let vm_addr = (mem.as_ptr() as u64).saturating_add(reg[src]).saturating_add((insn.imm as u32) as u64);
                    let host_ptr = translate_load_addr(vm_addr, 8, pc)? as *const u8;
                    reg[0] = unsafe { *host_ptr as u64 };
                },
                ebpf::LD_IND_H   => {
                    let vm_addr = (mem.as_ptr() as u64).saturating_add(reg[src]).saturating_add((insn.imm as u32) as u64);
                    let host_ptr = translate_load_addr(vm_addr, 8, pc)? as *const u16;
                    reg[0] = unsafe { *host_ptr as u64 };
                },
                ebpf::LD_IND_W   => {
                    let vm_addr = (mem.as_ptr() as u64).saturating_add(reg[src]).saturating_add((insn.imm as u32) as u64);
                    let host_ptr = translate_load_addr(vm_addr, 8, pc)? as *const u32;
                    reg[0] = unsafe { *host_ptr as u64 };
                },
                ebpf::LD_IND_DW  => {
                    let vm_addr = (mem.as_ptr() as u64).saturating_add(reg[src]).saturating_add((insn.imm as u32) as u64);
                    let host_ptr = translate_load_addr(vm_addr, 8, pc)? as *const u64;
                    reg[0] = unsafe { *host_ptr as u64 };
                },

                ebpf::LD_DW_IMM  => {
                    let next_insn = ebpf::get_insn(prog, next_pc);
                    next_pc += 1;
                    reg[dst] = (insn.imm as u32) as u64 + ((next_insn.imm as u64) << 32);
                },

                // BPF_LDX class
                ebpf::LD_B_REG   => {
                    #[allow(cast_ptr_alignment)]
                    let vm_addr = (reg[src] as i64).saturating_add(insn.off as i64) as u64;
                    let host_ptr = translate_load_addr(vm_addr, 1, pc)? as *const u8;
                    reg[dst] = unsafe { *host_ptr as u64 };
                },
                ebpf::LD_H_REG   => {
                    #[allow(cast_ptr_alignment)]
                    let vm_addr = (reg[src] as i64).saturating_add(insn.off as i64) as u64;
                    let host_ptr = translate_load_addr(vm_addr, 2, pc)? as *const u16;
                    reg[dst] = unsafe { *host_ptr as u64 };
                },
                ebpf::LD_W_REG   => {
                    #[allow(cast_ptr_alignment)]
                    let vm_addr = (reg[src] as i64).saturating_add(insn.off as i64) as u64;
                    let host_ptr = translate_load_addr(vm_addr, 4, pc)? as *const u32;
                    reg[dst] = unsafe { *host_ptr as u64 };
                },
                ebpf::LD_DW_REG  => {
                    #[allow(cast_ptr_alignment)]
                    let vm_addr = (reg[src] as i64).saturating_add(insn.off as i64) as u64;
                    let host_ptr = translate_load_addr(vm_addr, 8, pc)? as *const u64;
                    reg[dst] = unsafe { *host_ptr as u64 };
                },

                // BPF_ST class
                ebpf::ST_B_IMM   => {
                    let vm_addr = (reg[dst] as i64).saturating_add( insn.off as i64) as u64;
                    let host_ptr = translate_store_addr(vm_addr, 1, pc)? as *mut u8;
                    unsafe { *host_ptr = insn.imm as u8 };
                },
                ebpf::ST_H_IMM   => {
                    #[allow(cast_ptr_alignment)]
                    let vm_addr = (reg[dst] as i64).saturating_add(insn.off as i64) as u64;
                    let host_ptr = translate_store_addr(vm_addr, 2, pc)? as *mut u16;
                    unsafe { *host_ptr = insn.imm as u16 };
                },
                ebpf::ST_W_IMM   => {
                    #[allow(cast_ptr_alignment)]
                    let vm_addr = (reg[dst] as i64).saturating_add(insn.off as i64) as u64;
                    let host_ptr = translate_store_addr(vm_addr, 4, pc)? as *mut u32;
                    unsafe { *host_ptr = insn.imm as u32 };
                },
                ebpf::ST_DW_IMM  => {
                    #[allow(cast_ptr_alignment)]
                    let vm_addr = (reg[dst] as i64).saturating_add(insn.off as i64) as u64;
                    let host_ptr = translate_store_addr(vm_addr, 8, pc)? as *mut u64;
                    unsafe { *host_ptr = insn.imm as u64 };
                },

                // BPF_STX class
                ebpf::ST_B_REG   => {
                    let vm_addr = (reg[dst] as i64).saturating_add(insn.off as i64) as u64;
                    let host_ptr = translate_store_addr(vm_addr, 1, pc)? as *mut u8;
                    unsafe { *host_ptr = reg[src] as u8 };
                },
                ebpf::ST_H_REG   => {
                    #[allow(cast_ptr_alignment)]
                    let vm_addr = (reg[dst] as i64).saturating_add(insn.off as i64) as u64;
                    let host_ptr = translate_store_addr(vm_addr, 2, pc)? as *mut u16;
                    unsafe { *host_ptr = reg[src] as u16 };
                },
                ebpf::ST_W_REG   => {
                    #[allow(cast_ptr_alignment)]
                    let vm_addr = (reg[dst] as i64).saturating_add(insn.off as i64) as u64;
                    let host_ptr = translate_store_addr(vm_addr, 4, pc)? as *mut u32;
                    unsafe { *host_ptr = reg[src] as u32 };
                },
                ebpf::ST_DW_REG  => {
                    #[allow(cast_ptr_alignment)]
                    let vm_addr = (reg[dst] as i64).saturating_add(insn.off as i64) as u64;
                    let host_ptr = translate_store_addr(vm_addr, 8, pc)? as *mut u64;
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
                        frames.push(&reg[ebpf::FIRST_SCRATCH_REG..ebpf::FIRST_SCRATCH_REG + ebpf::SCRATCH_REGS], next_pc)?;
                    if target_address < ebpf::MM_PROGRAM_START {
                        return Err(EbpfError::CallOutsideTextSegment(pc + ebpf::ELF_INSN_DUMP_OFFSET, reg[insn.imm as usize]));
                    }
                    next_pc = Self::check_pc(&prog, pc, (target_address - prog_addr) as usize / ebpf::INSN_SIZE)?;
                },

                // Do not delegate the check to the verifier, since registered functions can be
                // changed after the program has been verified.
                ebpf::CALL_IMM   => {
                    if let Some(mut syscall) = self.syscalls.get_mut(&(insn.imm as u32)) {
                        let _ = instruction_meter.consume(self.last_insn_count);
                        self.last_insn_count = 0;
                        reg[0] = match syscall {
                            Syscall::Function(syscall) => {
                                syscall(reg[1], reg[2], reg[3], reg[4], reg[5], &ro_regions, &rw_regions)?
                            }
                            Syscall::Object(syscall) => {
                                syscall.call(reg[1], reg[2], reg[3], reg[4], reg[5], &ro_regions, &rw_regions)?
                            }
                        };
                        remaining_insn_count = instruction_meter.get_remaining();

                    } else if let Some(ref elf) = self.elf {
                        if let Some(new_pc) = elf.lookup_bpf_call(insn.imm as u32) {
                            // make BPF to BPF call
                            reg[ebpf::STACK_REG] =
                                frames.push(&reg[ebpf::FIRST_SCRATCH_REG..ebpf::FIRST_SCRATCH_REG + ebpf::SCRATCH_REGS], next_pc)?;
                            next_pc = Self::check_pc(&prog, pc, *new_pc)?;
                        } else {
                            elf.report_unresolved_symbol(pc)?;
                        }
                    } else {
                        // Note: Raw BPF programs (without ELF relocations) cannot support relative calls
                        // because there is no way to determine if the imm refers to a syscall or an offset
                        return Err(EbpfError::UnresolvedSymbol(pc + ebpf::ELF_INSN_DUMP_OFFSET));
                    }
                },

                ebpf::EXIT       => {
                    match frames.pop::<E>() {
                        Ok((saved_reg, stack_ptr, ptr)) => {
                            // Return from BPF to BPF call
                            reg[ebpf::FIRST_SCRATCH_REG..ebpf::FIRST_SCRATCH_REG + ebpf::SCRATCH_REGS]
                                .copy_from_slice(&saved_reg);
                            reg[ebpf::STACK_REG] = stack_ptr;
                            next_pc = Self::check_pc(&prog, pc, ptr)?;
                        },
                        _ => {
                            debug!("BPF instructions executed: {:?}", self.total_insn_count);
                            debug!("Max frame depth reached: {:?}", frames.get_max_frame_index());
                            return Ok(reg[0])
                        },
                    }
                },
                _                => return Err(EbpfError::UnsupportedInstruction(pc)),
            }
            println!("last {:?} remaining {:?} remaining {:?}", self.last_insn_count, remaining_insn_count, instruction_meter.get_remaining());
            if self.last_insn_count >= remaining_insn_count {
                return Err(EbpfError::ExceededMaxInstructions(self.total_insn_count));
            }
        }

        Err(EbpfError::ExecutionOverrun(next_pc + ebpf::ELF_INSN_DUMP_OFFSET))
    }

    fn check_pc(prog: &[u8], current_pc: usize, new_pc: usize) -> Result<usize, EbpfError<E>> {
        let offset =
            new_pc.checked_mul(ebpf::INSN_SIZE)
                .ok_or(EbpfError::CallOutsideTextSegment(current_pc, std::u64::MAX))?;
        let _ = prog.get(offset..offset + ebpf::INSN_SIZE).ok_or(
            EbpfError::CallOutsideTextSegment(current_pc, std::u64::MAX),
        )?;
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
    /// use solana_rbpf::EbpfVm;
    /// use solana_rbpf::user_error::UserError;
    ///
    /// let prog = &[
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    ///
    /// // Instantiate a VM.
    /// let mut vm = EbpfVm::<UserError>::new(Some(prog)).unwrap();
    ///
    /// # #[cfg(not(windows))]
    /// vm.jit_compile();
    /// ```
    pub fn jit_compile(&mut self) -> Result<(), EbpfError<E>> {
        let prog =
        if let Some(ref elf) = self.elf {
            if elf.get_ro_sections().is_ok() {
                return Err(EbpfError::ReadOnlyDataUnsupported);
            }
            let (_, bytes) = elf.get_text_bytes()?;
            bytes
        } else if let Some(ref prog) = self.prog {
            prog
        } else {
            return Err(EbpfError::NothingToExecute);
        };
        self.jit = Some(jit::compile(prog, &self.syscalls)?);
        Ok(())
    }

    /// Execute the previously JIT-compiled program, with the given packet data
    /// in a manner very similar to `execute_program(&[], &[])`.
    ///
    /// # Safety
    ///
    /// **WARNING:** JIT-compiled assembly code is not safe, in particular there is no runtime
    /// check for memory access; so if the eBPF program attempts erroneous accesses, this may end
    /// very bad (program may segfault). It may be wise to check that the program works with the
    /// interpreter before running the JIT-compiled version of it.
    ///
    /// For this reason the function should be called from within an `unsafe` bloc.
    ///
    /// # Examples
    ///
    /// ```
    /// use solana_rbpf::EbpfVm;
    /// use solana_rbpf::user_error::UserError;
    ///
    /// let prog = &[
    ///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    /// ];
    /// let mem = &mut [
    ///     0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd
    /// ];
    ///
    /// // Instantiate a VM.
    /// let mut vm = EbpfVm::<UserError>::new(Some(prog)).unwrap();
    ///
    /// # #[cfg(not(windows))]
    /// vm.jit_compile();
    ///
    /// // Provide a reference to the packet data.
    /// # #[cfg(not(windows))]
    /// unsafe {
    ///     let res = vm.execute_program_jit(mem).unwrap();
    ///     assert_eq!(res, 0);
    /// }
    /// ```
    pub unsafe fn execute_program_jit(&self, mem: &mut [u8]) -> Result<u64, EbpfError<E>> {
        // If packet data is empty, do not send the address of an empty slice; send a null pointer
        //  as first argument instead, as this is uBPF's behavior (empty packet should not happen
        //  in the kernel; anyway the verifier would prevent the use of uninitialized registers).
        //  See `mul_loop` test.
        let mem_ptr = match mem.len() {
            0 => std::ptr::null_mut(),
            _ => mem.as_ptr() as *mut u8
        };
        match self.jit {
            Some(jit) => Ok(jit(mem_ptr, mem.len(), 0)),
            None => Err(EbpfError::JITNotCompiled),
        }
    }
}

/// fuzzing utility function
pub fn fuzz<F>(
    bytes: &[u8],
    outer_iters: usize,
    inner_iters: usize,
    offset: Range<usize>,
    value: Range<u8>,
    work: F,
) where
    F: Fn(&mut [u8]),
{
    let mut rng = rand::thread_rng();
    for _ in 0..outer_iters {
        let mut mangled_bytes = bytes.to_vec();
        for _ in 0..inner_iters {
            let offset = rng.gen_range(offset.start, offset.end);
            let value = rng.gen_range(value.start, value.end);
            mangled_bytes[offset] = value;
            work(&mut mangled_bytes);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{user_error::UserError};

    #[test]
    fn test_frames() {
        const DEPTH: usize = 10;
        const SIZE: usize = 5;
        let mut frames = CallFrames::new(DEPTH, SIZE);
        let mut ptrs: Vec<MemoryRegion> = Vec::new();
        for i in 0..DEPTH - 1 {
            let registers = vec![i as u64; SIZE];
            assert_eq!(frames.get_frame_index(), i);
            ptrs.push(frames.get_stacks()[i].clone());
            assert_eq!(ptrs[i].len, SIZE as u64);

            let top = frames.push::<UserError>(&registers[0..4], i).unwrap();
            let new_ptrs = frames.get_stacks();
            assert_eq!(top, new_ptrs[i+1].addr_vm + new_ptrs[i+1].len);
            assert_ne!(top, ptrs[i].addr_vm + ptrs[i].len - 1);
            assert!(!(ptrs[i].addr_vm <= new_ptrs[i+1].addr_vm && new_ptrs[i+1].addr_vm < ptrs[i].addr_vm + ptrs[i].len));
        }
        let i = DEPTH - 1;
        let registers = vec![i as u64; SIZE];
        assert_eq!(frames.get_frame_index(), i);
        ptrs.push(frames.get_stacks()[i].clone());

        assert!(frames.push::<UserError>(&registers, DEPTH - 1).is_err());

        for i in (0..DEPTH - 1).rev() {
            let (saved_reg, stack_ptr, return_ptr) = frames.pop::<UserError>().unwrap();
            assert_eq!(saved_reg, [i as u64, i as u64, i as u64, i as u64]);
            assert_eq!(ptrs[i].addr_vm + ptrs[i].len, stack_ptr);
            assert_eq!(i, return_ptr);
        }

        assert!(frames.pop::<UserError>().is_err());
    }
}
