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
#![warn(missing_docs)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/qmonnet/rbpf/master/misc/rbpf.png",
    html_favicon_url = "https://raw.githubusercontent.com/qmonnet/rbpf/master/misc/rbpf.ico"
)]

extern crate byteorder;
extern crate combine;
extern crate hash32;
extern crate log;
extern crate rand;
extern crate thiserror;
extern crate time;

pub mod aligned_memory;
mod asm_parser;
pub mod assembler;
pub mod call_frames;
pub mod disassembler;
pub mod ebpf;
pub mod elf;
pub mod error;
pub mod fuzz;
pub mod insn_builder;
mod jit;
pub mod memory_region;
pub mod static_analysis;
pub mod syscalls;
pub mod user_error;
pub mod verifier;
pub mod vm;
mod x86;
