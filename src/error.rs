// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! This module contains all the definitions related to eBPF, and some functions permitting to
//! manipulate eBPF instructions.
//!
//! The number of bytes in an instruction, the maximum number of instructions in a program, and
//! also all operation codes are defined here as constants.
//!
//! The structure for an instruction used by this crate, as well as the function to extract it from
//! a program, is also defined in the module.
//!
//! To learn more about these instructions, see the Linux kernel documentation:
//! <https://www.kernel.org/doc/Documentation/networking/filter.txt>, or for a shorter version of
//! the list of the operation codes: <https://github.com/iovisor/bpf-docs/blob/master/eBPF.md>

use crate::{elf::ELFError, memory_region::AccessType};

/// User defined errors must implement this trait
pub trait UserDefinedError: 'static + std::error::Error {}

/// Error definitions
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EbpfError<E: UserDefinedError> {
    /// User defined error
    #[error("{0}")]
    UserError(#[from] E),
    /// ELF error
    #[error("ELF error: {0}")]
    ELFError(#[from] ELFError),
    /// Syscall was already registered before
    #[error("syscall was already registered before")]
    SycallAlreadyRegistered,
    /// Syscall already has a bound context object
    #[error("syscall already has a bound context object")]
    SycallAlreadyBound,
    /// Exceeded max BPF to BPF call depth
    #[error("exceeded max BPF to BPF call depth of {1} at instruction #{0}")]
    CallDepthExceeded(usize, usize),
    /// Attempt to exit from root call frame
    #[error("attempted to exit root call frame")]
    ExitRootCallFrame,
    /// Divide by zero"
    #[error("devide by zero at instruction {0}")]
    DivideByZero(usize),
    /// Exceeded max instructions allowed
    #[error("attempted to execute past the end of the text segment at instruction #{0}")]
    ExecutionOverrun(usize),
    /// Attempt to call to an address outside the text segment
    #[error(
        "callx at instruction {0} attempted to call outside of the text segment to addr 0x{1:x}"
    )]
    CallOutsideTextSegment(usize, u64),
    /// Exceeded max instructions allowed
    #[error("exceeded maximum number of instructions allowed ({1}) at instruction #{0}")]
    ExceededMaxInstructions(usize, u64),
    /// Program has not been JIT-compiled
    #[error("program has not been JIT-compiled")]
    JITNotCompiled,
    /// Invalid virtual address
    #[error("invalid virtual address {0:x?}")]
    InvalidVirtualAddress(u64),
    /// Virtual address overlap
    #[error("virtual address overlap {0:x?}")]
    VirtualAddressOverlap(u64),
    /// Access violation
    #[error("Access violation in {4} section at address {2:#x} of size {3:?} by instruction #{0}")]
    AccessViolation(usize, AccessType, u64, u64, &'static str),
    /// Invalid instruction
    #[error("invalid instruction at {0}")]
    InvalidInstruction(usize),
    /// Unsupported instruction
    #[error("unsupported instruction at instruction {0}")]
    UnsupportedInstruction(usize),
}
