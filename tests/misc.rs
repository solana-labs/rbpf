// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

// This crate would be needed to load bytecode from a BPF-compiled object file. Since the crate
// is not used anywhere else in the library, it is deactivated: we do not want to load and compile
// it just for the tests. If you want to use it, do not forget to add the following
// dependency to your Cargo.toml file:
//
// ---
// elf = "0.0.10"
// ---
//
// extern crate elf;
// use std::path::PathBuf;

extern crate byteorder;
extern crate libc;
extern crate solana_rbpf;
extern crate thiserror;

use byteorder::{ByteOrder, LittleEndian};
use libc::c_char;
use solana_rbpf::{
    assembler::assemble,
    call_frames::MAX_CALL_DEPTH,
    ebpf::{self},
    error::{EbpfError, UserDefinedError},
    fuzz::fuzz,
    memory_region::{translate_addr, AccessType, MemoryRegion},
    user_error::UserError,
    verifier::check,
    vm::{EbpfVm, InstructionMeter, SyscallObject},
};
use std::{fs::File, io::Read, slice::from_raw_parts, str::from_utf8};
use thiserror::Error;

// The following two examples have been compiled from C with the following command:
//
// ```bash
//  clang -O2 -emit-llvm -c <file.c> -o - | llc -march=bpf -filetype=obj -o <file.o>
// ```
//
// The C source code was the following:
//
// ```c
// #include <linux/ip.h>
// #include <linux/in.h>
// #include <linux/tcp.h>
// #include <linux/bpf.h>
//
// #define ETH_ALEN 6
// #define ETH_P_IP 0x0008 /* htons(0x0800) */
// #define TCP_HDR_LEN 20
//
// #define BLOCKED_TCP_PORT 0x9999
//
// struct eth_hdr {
//     unsigned char   h_dest[ETH_ALEN];
//     unsigned char   h_source[ETH_ALEN];
//     unsigned short  h_proto;
// };
//
// #define SEC(NAME) __attribute__((section(NAME), used))
// SEC(".classifier")
// int handle_ingress(struct __sk_buff *skb)
// {
//     void *data = (void *)(long)skb->data;
//     void *data_end = (void *)(long)skb->data_end;
//     struct eth_hdr *eth = data;
//     struct iphdr *iph = data + sizeof(*eth);
//     struct tcphdr *tcp = data + sizeof(*eth) + sizeof(*iph);
//
//     /* single length check */
//     if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*tcp) > data_end)
//         return 0;
//     if (eth->h_proto != ETH_P_IP)
//         return 0;
//     if (iph->protocol != IPPROTO_TCP)
//         return 0;
//     if (tcp->source == BLOCKED_TCP_PORT || tcp->dest == BLOCKED_TCP_PORT)
//         return -1;
//     return 0;
// }
// char _license[] SEC(".license") = "GPL";
// ```
//
// This program, once compiled, can be injected into Linux kernel, with tc for instance. Sadly, we
// need to bring some modifications to the generated bytecode in order to run it: the three
// instructions with opcode 0x61 load data from a packet area as 4-byte words, where we need to
// load it as 8-bytes double words (0x79). The kernel does the same kind of translation before
// running the program, but rbpf does not implement this.
//
// In addition, the offset at which the pointer to the packet data is stored must be changed: since
// we use 8 bytes instead of 4 for the start and end addresses of the data packet, we cannot use
// the offsets produced by clang (0x4c and 0x50), the addresses would overlap. Instead we can use,
// for example, 0x40 and 0x50. See comments on the bytecode below to see the modifications.
//
// Once the bytecode has been (manually, in our case) edited, we can load the bytecode directly
// from the ELF object file. This is easy to do, but requires the addition of two crates in the
// Cargo.toml file (see comments above), so here we use just the hardcoded bytecode instructions
// instead.

fn bpf_syscall_string(
    vm_addr: u64,
    len: u64,
    _arg3: u64,
    _arg4: u64,
    _arg5: u64,
    memory_mapping: &[MemoryRegion],
) -> Result<u64, EbpfError<UserError>> {
    let host_addr = translate_addr(vm_addr, len as usize, AccessType::Load, 0, memory_mapping)?;
    let c_buf: *const c_char = host_addr as *const c_char;
    unsafe {
        for i in 0..len {
            let c = std::ptr::read(c_buf.offset(i as isize));
            if c == 0 {
                break;
            }
        }
        let message = from_utf8(from_raw_parts(host_addr as *const u8, len as usize)).unwrap();
        println!("log: {}", message);
        Ok(0)
    }
}

fn bpf_syscall_u64(
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    _memory_mapping: &[MemoryRegion],
) -> Result<u64, EbpfError<UserError>> {
    println!(
        "dump_64: {:#x}, {:#x}, {:#x}, {:#x}, {:#x}",
        arg1, arg2, arg3, arg4, arg5
    );
    Ok(0)
}

struct SyscallWithContext<'a> {
    context: &'a mut u64,
}
impl<'a> SyscallObject<UserError> for SyscallWithContext<'a> {
    fn call(
        &mut self,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
        _memory_mapping: &[MemoryRegion],
    ) -> Result<u64, EbpfError<UserError>> {
        println!(
            "SyscallWithContext: {:#x}, {:#x}, {:#x}, {:#x}, {:#x}",
            arg1, arg2, arg3, arg4, arg5
        );
        assert_eq!(*self.context, 42);
        *self.context = 84;
        Ok(0)
    }
}

#[cfg(not(windows))]
#[test]
fn test_vm_jit_ldabsb() {
    let prog = assemble(
        "
        ldabsb 0x3
        exit",
    )
    .unwrap();
    let mem1 = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, //
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, //
    ];
    let mut mem2 = mem1;
    let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    assert_eq!(vm.execute_program(&mem1, &[]).unwrap(), 0x33);

    vm.jit_compile().unwrap();
    unsafe {
        assert_eq!(vm.execute_program_jit(&mut mem2).unwrap(), 0x33);
    };
}

#[cfg(not(windows))]
#[test]
fn test_vm_jit_ldabsh() {
    let prog = assemble(
        "
        ldabsh 0x3
        exit",
    )
    .unwrap();
    let mem1 = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, //
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, //
    ];
    let mut mem2 = mem1;
    let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    assert_eq!(vm.execute_program(&mem1, &[]).unwrap(), 0x4433);

    vm.jit_compile().unwrap();
    unsafe {
        assert_eq!(vm.execute_program_jit(&mut mem2).unwrap(), 0x4433);
    };
}

#[cfg(not(windows))]
#[test]
fn test_vm_jit_ldabsw() {
    let prog = assemble(
        "
        ldabsw 0x3
        exit",
    )
    .unwrap();
    let mem1 = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, //
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, //
    ];
    let mut mem2 = mem1;
    let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    assert_eq!(vm.execute_program(&mem1, &[]).unwrap(), 0x66554433);

    vm.jit_compile().unwrap();
    unsafe {
        assert_eq!(vm.execute_program_jit(&mut mem2).unwrap(), 0x66554433);
    };
}

#[cfg(not(windows))]
#[test]
fn test_vm_jit_ldabsdw() {
    let prog = assemble(
        "
        ldabsdw 0x3
        exit",
    )
    .unwrap();
    let mem1 = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, //
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, //
    ];
    let mut mem2 = mem1;
    let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    assert_eq!(vm.execute_program(&mem1, &[]).unwrap(), 0xaa99887766554433);

    vm.jit_compile().unwrap();
    unsafe {
        assert_eq!(
            vm.execute_program_jit(&mut mem2).unwrap(),
            0xaa99887766554433
        );
    };
}

#[test]
#[should_panic(expected = "AccessViolation(Load, 29")]
fn test_vm_err_ldabsb_oob() {
    let prog = assemble(
        "
        ldabsb 0x33
        exit",
    )
    .unwrap();
    let mem = &[
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, //
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, //
    ];
    let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    vm.execute_program(mem, &[]).unwrap();

    // Memory check not implemented for JIT yet.
}

#[test]
#[should_panic(expected = "AccessViolation(Load, 29")]
fn test_vm_err_ldabsb_nomem() {
    let prog = assemble(
        "
        ldabsb 0x33
        exit",
    )
    .unwrap();
    let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    vm.execute_program(&[], &[]).unwrap();

    // Memory check not implemented for JIT yet.
}

#[cfg(not(windows))]
#[test]
fn test_vm_jit_ldindb() {
    let prog = assemble(
        "
        mov64 r1, 0x5
        ldindb r1, 0x3
        exit",
    )
    .unwrap();
    let mem1 = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, //
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, //
    ];
    let mut mem2 = mem1;
    let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    assert_eq!(vm.execute_program(&mem1, &[]).unwrap(), 0x88);

    vm.jit_compile().unwrap();
    unsafe {
        assert_eq!(vm.execute_program_jit(&mut mem2).unwrap(), 0x88);
    };
}

#[cfg(not(windows))]
#[test]
fn test_vm_jit_ldindh() {
    let prog = assemble(
        "
        mov64 r1, 0x5
        ldindh r1, 0x3
        exit",
    )
    .unwrap();
    let mem1 = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, //
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, //
    ];
    let mut mem2 = mem1;
    let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    assert_eq!(vm.execute_program(&mem1, &[]).unwrap(), 0x9988);

    vm.jit_compile().unwrap();
    unsafe {
        assert_eq!(vm.execute_program_jit(&mut mem2).unwrap(), 0x9988);
    };
}

#[cfg(not(windows))]
#[test]
fn test_vm_jit_ldindw() {
    let prog = assemble(
        "
        mov64 r1, 0x4
        ldindw r1, 0x1
        exit",
    )
    .unwrap();
    let mem1 = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, //
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, //
    ];
    let mut mem2 = mem1;
    let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    assert_eq!(vm.execute_program(&mem1, &[]).unwrap(), 0x88776655);

    vm.jit_compile().unwrap();
    unsafe {
        assert_eq!(vm.execute_program_jit(&mut mem2).unwrap(), 0x88776655);
    };
}

#[cfg(not(windows))]
#[test]
fn test_vm_jit_ldinddw() {
    let prog = assemble(
        "
        mov64 r1, 0x2
        ldinddw r1, 0x3
        exit",
    )
    .unwrap();
    let mem1 = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, //
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, //
    ];
    let mut mem2 = mem1;
    let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    assert_eq!(vm.execute_program(&mem1, &[]).unwrap(), 0xccbbaa9988776655);

    vm.jit_compile().unwrap();
    unsafe {
        assert_eq!(
            vm.execute_program_jit(&mut mem2).unwrap(),
            0xccbbaa9988776655
        );
    };
}

#[test]
#[should_panic(expected = "AccessViolation(Load, 30")]
fn test_vm_err_ldindb_oob() {
    let prog = assemble(
        "
        mov64 r1, 0x5
        ldindb r1, 0x33
        exit",
    )
    .unwrap();
    let mem = &mut [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, //
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, //
    ];
    let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    vm.execute_program(mem, &[]).unwrap();

    // Memory check not implemented for JIT yet.
}

#[test]
#[should_panic(expected = "AccessViolation(Load, 30")]
fn test_vm_err_ldindb_nomem() {
    let prog = assemble(
        "
        mov64 r1, 0x3
        ldindb r1, 0x3
        exit",
    )
    .unwrap();
    let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    vm.execute_program(&[], &[]).unwrap();

    // Memory check not implemented for JIT yet.
}

/// Error definitions
#[derive(Debug, Error)]
pub enum VerifierTestError {
    #[error("{0}")]
    Rejected(String),
}
impl UserDefinedError for VerifierTestError {}

fn verifier_success(_prog: &[u8]) -> Result<(), VerifierTestError> {
    Ok(())
}
fn verifier_fail(_prog: &[u8]) -> Result<(), VerifierTestError> {
    Err(VerifierTestError::Rejected("Gaggablaghblagh!".to_string()))
}

#[test]
fn test_verifier_success() {
    let prog = assemble(
        "
        mov32 r0, 0xBEE
        exit",
    )
    .unwrap();
    let executable = EbpfVm::<VerifierTestError>::create_executable_from_text_bytes(
        &prog,
        Some(verifier_success),
    )
    .unwrap();
    let mut vm = EbpfVm::<VerifierTestError>::new(executable.as_ref()).unwrap();
    assert_eq!(vm.execute_program(&[], &[]).unwrap(), 0xBEE);
}

#[test]
#[should_panic(expected = "Gaggablaghblagh!")]
fn test_verifier_fail() {
    let prog = assemble(
        "
        mov32 r0, 0xBEE
        exit",
    )
    .unwrap();
    let _ =
        EbpfVm::<VerifierTestError>::create_executable_from_text_bytes(&prog, Some(verifier_fail))
            .unwrap();
}

const BPF_TRACE_PRINTK_IDX: u32 = 6;
fn bpf_trace_printf<E: UserDefinedError>(
    _arg1: u64,
    _arg2: u64,
    _arg3: u64,
    _arg4: u64,
    _arg5: u64,
    _memory_mapping: &[MemoryRegion],
) -> Result<u64, EbpfError<E>> {
    Ok(0)
}

struct TestInstructionMeter {
    remaining: u64,
}
impl InstructionMeter for TestInstructionMeter {
    fn consume(&mut self, amount: u64) {
        if amount > self.remaining {
            panic!("Execution count exceeded");
        }
        self.remaining = self.remaining.saturating_sub(amount);
    }
    fn get_remaining(&self) -> u64 {
        self.remaining
    }
}

#[test]
#[should_panic(expected = "ExceededMaxInstructions(1000)")]
fn test_non_terminating() {
    let prog = assemble(
        "
        mov64 r6, 0x0
        mov64 r1, 0x0
        mov64 r2, 0x0
        mov64 r3, 0x0
        mov64 r4, 0x0
        mov64 r5, r6
        call 0x6
        add64 r6, 0x1
        ja -0x8
        exit",
    )
    .unwrap();
    let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    vm.register_syscall(BPF_TRACE_PRINTK_IDX, bpf_trace_printf)
        .unwrap();
    let instruction_meter = TestInstructionMeter { remaining: 1000 };
    let _ = vm
        .execute_program_metered(&[], &[], instruction_meter)
        .unwrap();
}

#[test]
fn test_non_terminate_capped() {
    let prog = assemble(
        "
        mov64 r6, 0x0
        mov64 r1, 0x0
        mov64 r2, 0x0
        mov64 r3, 0x0
        mov64 r4, 0x0
        mov64 r5, r6
        call 0x6
        add64 r6, 0x1
        ja -0x8
        exit",
    )
    .unwrap();
    let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    vm.register_syscall(BPF_TRACE_PRINTK_IDX, bpf_trace_printf)
        .unwrap();
    let instruction_meter = TestInstructionMeter { remaining: 6 };
    let _ = vm.execute_program_metered(&[], &[], instruction_meter);
    assert_eq!(vm.get_total_instruction_count(), 6);
}

#[test]
fn test_non_terminate_early() {
    let prog = assemble(
        "
        mov64 r6, 0x0
        mov64 r1, 0x0
        mov64 r2, 0x0
        mov64 r3, 0x0
        mov64 r4, 0x0
        mov64 r5, r6
        call 0x6
        add64 r6, 0x1
        ja -0x8
        exit",
    )
    .unwrap();
    let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    let instruction_meter = TestInstructionMeter { remaining: 100 };
    let _ = vm.execute_program_metered(&[], &[], instruction_meter);
    assert_eq!(vm.get_total_instruction_count(), 7);
}

#[test]
fn test_get_total_instruction_count() {
    let prog = assemble(
        "
        exit",
    )
    .unwrap();
    let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    let _ = vm.execute_program(&[], &[]);
    assert_eq!(vm.get_total_instruction_count(), 1);
}

#[test]
fn test_get_total_instruction_count_with_syscall() {
    let mut prog = assemble(
        "
        mov64 r2, 0x5
        call -0x1
        mov64 r0, 0x0
        exit",
    )
    .unwrap();
    LittleEndian::write_u32(&mut prog[12..16], ebpf::hash_symbol_name(b"log"));

    let mem = [72, 101, 108, 108, 111];

    let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    vm.register_syscall_ex("log", bpf_syscall_string).unwrap();
    let instruction_meter = TestInstructionMeter { remaining: 4 };
    let _ = vm.execute_program_metered(&mem, &[], instruction_meter);
    assert_eq!(vm.get_total_instruction_count(), 4);
}

#[test]
#[should_panic(expected = "ExceededMaxInstructions(3)")]
fn test_get_total_instruction_count_with_syscall_capped() {
    let mut prog = assemble(
        "
        mov64 r2, 0x5
        call -0x1
        mov64 r0, 0x0
        exit",
    )
    .unwrap();
    LittleEndian::write_u32(&mut prog[12..16], ebpf::hash_symbol_name(b"log"));

    let mem = [72, 101, 108, 108, 111];

    let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    vm.register_syscall(BPF_TRACE_PRINTK_IDX, bpf_trace_printf)
        .unwrap();
    vm.register_syscall_ex("log", bpf_syscall_string).unwrap();
    let instruction_meter = TestInstructionMeter { remaining: 3 };
    vm.execute_program_metered(&mem, &[], instruction_meter)
        .unwrap();
}

#[test]
fn test_load_elf() {
    let mut file = File::open("tests/elfs/noop.so").expect("file open failed");
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();

    let executable = EbpfVm::<UserError>::create_executable_from_elf(&elf, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    vm.register_syscall_ex("log", bpf_syscall_string).unwrap();
    vm.register_syscall_ex("log_64", bpf_syscall_u64).unwrap();
    vm.execute_program(&[], &[]).unwrap();
}

#[test]
fn test_load_elf_empty_noro() {
    let mut file = File::open("tests/elfs/noro.so").expect("file open failed");
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();

    let executable = EbpfVm::<UserError>::create_executable_from_elf(&elf, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    vm.register_syscall_ex("log_64", bpf_syscall_u64).unwrap();
    vm.execute_program(&[], &[]).unwrap();
}

#[test]
fn test_load_elf_empty_rodata() {
    let mut file = File::open("tests/elfs/empty_rodata.so").expect("file open failed");
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();

    let executable = EbpfVm::<UserError>::create_executable_from_elf(&elf, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    vm.register_syscall_ex("log_64", bpf_syscall_u64).unwrap();
    vm.execute_program(&[], &[]).unwrap();
}

#[test]
fn test_symbol_relocation() {
    let mut prog = assemble(
        "
        mov64 r1, r10
        sub64 r1, 0x1
        mov64 r2, 0x1
        call -0x1
        mov64 r0, 0x0
        exit",
    )
    .unwrap();
    LittleEndian::write_u32(&mut prog[28..32], ebpf::hash_symbol_name(b"log"));

    let mem = [72, 101, 108, 108, 111];

    let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    vm.register_syscall_ex("log", bpf_syscall_string).unwrap();
    vm.execute_program(&mem, &[]).unwrap();
}

#[test]
fn test_syscall_parameter_on_stack() {
    let mut prog = assemble(
        "
        mov64 r1, r10
        add64 r1, -0x100
        mov64 r2, 0x1
        call -0x1
        mov64 r0, 0x0
        exit",
    )
    .unwrap();
    LittleEndian::write_u32(&mut prog[28..32], ebpf::hash_symbol_name(b"log"));

    let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    vm.register_syscall_ex("log", bpf_syscall_string).unwrap();
    vm.execute_program(&[], &[]).unwrap();
}

#[test]
#[should_panic(expected = "AccessViolation(Load, 29")]
fn test_null_string() {
    let mut prog = assemble(
        "
        mov64 r1, 0x0
        call -0x1
        mov64 r0, 0x0
        exit",
    )
    .unwrap();
    LittleEndian::write_u32(&mut prog[12..16], ebpf::hash_symbol_name(b"log"));

    let mem = [72, 101, 108, 108, 111];

    let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    vm.register_syscall_ex("log", bpf_syscall_string).unwrap();
    vm.execute_program(&mem, &[]).unwrap();
}

#[test]
fn test_syscall_string() {
    let mut prog = assemble(
        "
        mov64 r2, 0x5
        call -0x1
        mov64 r0, 0x0
        exit",
    )
    .unwrap();
    LittleEndian::write_u32(&mut prog[12..16], ebpf::hash_symbol_name(b"log"));

    let mem = [72, 101, 108, 108, 111];

    let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    vm.register_syscall_ex("log", bpf_syscall_string).unwrap();
    vm.execute_program(&mem, &[]).unwrap();
}

#[cfg(not(windows))]
#[test]
fn test_call_syscall() {
    let mut prog = assemble(
        "
        mov64 r1, 0xAA
        mov64 r2, 0xBB
        mov64 r3, 0xCC
        mov64 r4, 0xDD
        mov64 r5, 0xEE
        call -0x1
        mov64 r0, 0x0
        exit",
    )
    .unwrap();
    LittleEndian::write_u32(&mut prog[44..48], ebpf::hash_symbol_name(b"log"));

    let mem1 = [];
    let mut mem2 = mem1;

    let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    vm.register_syscall_ex("log", bpf_syscall_u64).unwrap();
    vm.execute_program(&mem1, &[]).unwrap();
    vm.jit_compile().unwrap();
    unsafe {
        assert_eq!(vm.execute_program_jit(&mut mem2).unwrap(), 0);
    }
}

#[test]
#[should_panic(expected = "UnresolvedSymbol(\"Unknown\", 29, 0)")]
fn test_symbol_unresolved() {
    let mut prog = assemble(
        "
        call -0x1
        mov64 r0, 0x0
        exit",
    )
    .unwrap();
    LittleEndian::write_u32(&mut prog[4..8], ebpf::hash_symbol_name(b"log"));

    let mem = [];

    let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    vm.execute_program(&mem, &[]).unwrap();
}

#[test]
#[should_panic(expected = "UnresolvedSymbol(\"log_64\", 550, 4168)")]
fn test_symbol_unresolved_elf() {
    let mut file = File::open("tests/elfs/unresolved_syscall.so").expect("file open failed");
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();

    let executable = EbpfVm::<UserError>::create_executable_from_elf(&elf, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    vm.register_syscall_ex("log", bpf_syscall_string).unwrap();
    vm.execute_program(&[], &[]).unwrap();
}

#[test]
fn test_custom_entrypoint() {
    let mut file = File::open("tests/elfs/unresolved_syscall.so").expect("file open failed");
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();

    elf[24] = 80; // Move entrypoint to later in the text section

    let executable = EbpfVm::<UserError>::create_executable_from_elf(&elf, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    vm.register_syscall_ex("log", bpf_syscall_string).unwrap();
    vm.execute_program(&[], &[]).unwrap();
    assert_eq!(2, vm.get_total_instruction_count());
}

#[test]
fn test_bpf_to_bpf_depth() {
    let mut file = File::open("tests/elfs/multiple_file.so").expect("file open failed");
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();

    let executable = EbpfVm::<UserError>::create_executable_from_elf(&elf, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    vm.register_syscall_ex("log", bpf_syscall_string).unwrap();

    for i in 0..MAX_CALL_DEPTH {
        let mem = [i as u8];
        assert_eq!(vm.execute_program(&mem, &[]).unwrap(), 0);
    }
}

#[test]
#[should_panic(expected = "CallDepthExceeded(20)")]
fn test_bpf_to_bpf_too_deep() {
    let mut file = File::open("tests/elfs/multiple_file.so").expect("file open failed");
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();

    let executable = EbpfVm::<UserError>::create_executable_from_elf(&elf, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    vm.register_syscall_ex("log", bpf_syscall_string).unwrap();

    let mem = [MAX_CALL_DEPTH as u8];
    vm.execute_program(&mem, &[]).unwrap();
}

#[test]
fn test_relative_call() {
    let mut file = File::open("tests/elfs/relative_call.so").expect("file open failed");
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();

    let executable = EbpfVm::<UserError>::create_executable_from_elf(&elf, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    vm.register_syscall_ex("log", bpf_syscall_string).unwrap();

    let mem = [1 as u8];
    vm.execute_program(&mem, &[]).unwrap();
}

#[test]
fn test_call_reg() {
    let prog = assemble(
        "
        mov64 r0, 0x0
        mov64 r8, 0x1
        lsh64 r8, 0x20
        or64 r8, 0x30
        callx 0x8
        exit
        mov64 r0, 0x2A
        exit",
    )
    .unwrap();

    let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    assert_eq!(42, vm.execute_program(&[], &[]).unwrap());
}

#[test]
#[should_panic(expected = "CallDepthExceeded(20)")]
fn test_call_reg_stack_depth() {
    let prog = assemble(
        "
        mov64 r0, 0x1
        lsh64 r0, 0x20
        callx 0x0
        exit",
    )
    .unwrap();

    let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    assert_eq!(42, vm.execute_program(&[], &[]).unwrap());
}

#[test]
#[should_panic(expected = "CallOutsideTextSegment(30, 0)")]
fn test_oob_callx_low() {
    let prog = assemble(
        "
        mov64 r0, 0x0
        callx 0x0
        exit",
    )
    .unwrap();

    let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    assert_eq!(42, vm.execute_program(&[], &[]).unwrap());
}

#[test]
#[should_panic(expected = "CallOutsideTextSegment(3, 18446744073709551615)")]
fn test_oob_callx_high() {
    let prog = assemble(
        "
        mov64 r0, -0x1
        lsh64 r0, 0x20
        or64 r8, -0x1
        callx 0x0
        exit",
    )
    .unwrap();

    let executable = EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    assert_eq!(42, vm.execute_program(&[], &[]).unwrap());
}

#[test]
fn test_bpf_to_bpf_scratch_registers() {
    let mut file = File::open("tests/elfs/scratch_registers.so").expect("file open failed");
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();

    let executable = EbpfVm::<UserError>::create_executable_from_elf(&elf, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    vm.register_syscall_ex("log", bpf_syscall_string).unwrap();
    vm.register_syscall_ex("log_64", bpf_syscall_u64).unwrap();

    let mem = [1];
    assert_eq!(vm.execute_program(&mem, &[]).unwrap(), 112);
}

#[test]
fn test_bpf_to_bpf_pass_stack_reference() {
    let mut file = File::open("tests/elfs/pass_stack_reference.so").expect("file open failed");
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();

    let executable = EbpfVm::<UserError>::create_executable_from_elf(&elf, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
    vm.register_syscall_ex("log", bpf_syscall_string).unwrap();
    vm.register_syscall_ex("log_64", bpf_syscall_u64).unwrap();

    assert_eq!(vm.execute_program(&[], &[]).unwrap(), 42);
}

fn write_insn(prog: &mut [u8], insn: usize, asm: &str) {
    prog[insn * ebpf::INSN_SIZE..insn * ebpf::INSN_SIZE + ebpf::INSN_SIZE]
        .copy_from_slice(&assemble(asm).unwrap());
}

#[test]
fn test_large_program() {
    let mut prog = vec![0; ebpf::PROG_MAX_INSNS * ebpf::INSN_SIZE];
    let mut add_insn = vec![0; ebpf::INSN_SIZE];
    write_insn(&mut add_insn, 0, "mov64 r0, 0");
    for insn in (0..(ebpf::PROG_MAX_INSNS - 1) * ebpf::INSN_SIZE).step_by(ebpf::INSN_SIZE) {
        prog[insn..insn + ebpf::INSN_SIZE].copy_from_slice(&add_insn);
    }
    write_insn(&mut prog, ebpf::PROG_MAX_INSNS - 1, "exit");

    {
        // Test jumping to pc larger then i16
        write_insn(&mut prog, ebpf::PROG_MAX_INSNS - 2, "ja 0x0");

        let executable =
            EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, None).unwrap();
        let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
        assert_eq!(0, vm.execute_program(&[], &[]).unwrap());
    }
    // reset program
    write_insn(&mut prog, ebpf::PROG_MAX_INSNS - 2, "mov64 r0, 0");

    {
        // test program that is too large
        prog.extend_from_slice(&assemble("exit").unwrap());

        assert!(
            EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, Some(check)).is_err()
        );
    }
    // reset program
    prog.truncate(ebpf::PROG_MAX_INSNS * ebpf::INSN_SIZE);

    {
        // verify program still works
        let executable =
            EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, None).unwrap();
        let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
        assert_eq!(0, vm.execute_program(&[], &[]).unwrap());
    }
}

#[test]
fn test_vm_syscall_with_context() {
    let mut prog = assemble(
        "
        mov64 r1, 0xAA
        mov64 r2, 0xBB
        mov64 r3, 0xCC
        mov64 r4, 0xDD
        mov64 r5, 0xEE
        call -0x1
        mov64 r0, 0x0
        exit",
    )
    .unwrap();
    LittleEndian::write_u32(&mut prog[44..48], ebpf::hash_symbol_name(b"syscall"));

    let mut number = 42;

    {
        let executable =
            EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, None).unwrap();
        let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
        vm.register_syscall_with_context_ex(
            "syscall",
            Box::new(SyscallWithContext {
                context: &mut number,
            }),
        )
        .unwrap();
        vm.execute_program(&[], &[]).unwrap();
    }
    assert_eq!(number, 84);
}

#[cfg(not(windows))]
#[test]
fn test_jit_syscall_with_context() {
    let mut prog = assemble(
        "
        mov64 r1, 0xAA
        mov64 r2, 0xBB
        mov64 r3, 0xCC
        mov64 r4, 0xDD
        mov64 r5, 0xEE
        call -0x1
        mov64 r0, 0x0
        exit",
    )
    .unwrap();
    LittleEndian::write_u32(&mut prog[44..48], ebpf::hash_symbol_name(b"syscall"));

    let mut number = 42;

    {
        let executable =
            EbpfVm::<UserError>::create_executable_from_text_bytes(&prog, None).unwrap();
        let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
        vm.register_syscall_with_context_ex(
            "syscall",
            Box::new(SyscallWithContext {
                context: &mut number,
            }),
        )
        .unwrap();
        vm.jit_compile().unwrap();
        unsafe {
            assert_eq!(vm.execute_program_jit(&mut []).unwrap(), 0);
        }
    }
    assert_eq!(number, 84);
}

#[test]
#[ignore]
fn test_fuzz_execute() {
    let mut file = File::open("tests/elfs/pass_stack_reference.so").expect("file open failed");
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();

    fn user_check(prog: &[u8]) -> Result<(), UserError> {
        check(prog)
    }

    println!("mangle the whole file");
    fuzz(
        &elf,
        1_000_000_000,
        100,
        0..elf.len(),
        0..255,
        |bytes: &mut [u8]| {
            if let Ok(executable) =
                EbpfVm::<UserError>::create_executable_from_elf(&bytes, Some(user_check))
            {
                let mut vm = EbpfVm::<UserError>::new(executable.as_ref()).unwrap();
                vm.register_syscall_ex("log", bpf_syscall_string).unwrap();
                vm.register_syscall_ex("log_64", bpf_syscall_u64).unwrap();
                let _ = vm.execute_program(&[], &[]);
            }
        },
    );
}
