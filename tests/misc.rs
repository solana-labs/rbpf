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

use libc::c_char;
use solana_rbpf::{
    assembler::assemble,
    ebpf::{self},
    error::{EbpfError, UserDefinedError},
    fuzz::fuzz,
    memory_region::{AccessType, MemoryMapping},
    user_error::UserError,
    verifier::check,
    vm::{DefaultInstructionMeter, EbpfVm, InstructionMeter, Syscall},
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

type ExecResult = Result<u64, EbpfError<UserError>>;

fn bpf_syscall_string(
    vm_addr: u64,
    len: u64,
    _arg3: u64,
    _arg4: u64,
    _arg5: u64,
    memory_mapping: &MemoryMapping,
) -> ExecResult {
    let host_addr = memory_mapping.map(AccessType::Load, vm_addr, len)?;
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
    }
    Ok(0)
}

fn bpf_syscall_u64(
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    memory_mapping: &MemoryMapping,
) -> ExecResult {
    println!(
        "dump_64: {:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:?}",
        arg1, arg2, arg3, arg4, arg5, memory_mapping as *const _
    );
    Ok(0)
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
    let mut vm = EbpfVm::<VerifierTestError>::new(executable.as_ref(), &[], &[]).unwrap();
    assert_eq!(
        vm.execute_program_interpreted(&mut DefaultInstructionMeter {})
            .unwrap(),
        0xBEE
    );
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
    _memory_mapping: &MemoryMapping,
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
#[should_panic(expected = "ExceededMaxInstructions(37, 1000)")]
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
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref(), &[], &[]).unwrap();
    vm.register_syscall(BPF_TRACE_PRINTK_IDX, Syscall::Function(bpf_trace_printf))
        .unwrap();
    let mut instruction_meter = TestInstructionMeter { remaining: 1000 };
    let _ = vm
        .execute_program_interpreted(&mut instruction_meter)
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
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref(), &[], &[]).unwrap();
    vm.register_syscall(BPF_TRACE_PRINTK_IDX, Syscall::Function(bpf_trace_printf))
        .unwrap();
    let mut instruction_meter = TestInstructionMeter { remaining: 6 };
    let _ = vm.execute_program_interpreted(&mut instruction_meter);
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
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref(), &[], &[]).unwrap();
    let mut instruction_meter = TestInstructionMeter { remaining: 100 };
    let _ = vm.execute_program_interpreted(&mut instruction_meter);
    assert_eq!(vm.get_total_instruction_count(), 7);
}

#[test]
fn test_custom_entrypoint() {
    let mut file = File::open("tests/elfs/unresolved_syscall.so").expect("file open failed");
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();

    elf[24] = 80; // Move entrypoint to later in the text section

    let executable = EbpfVm::<UserError>::create_executable_from_elf(&elf, None).unwrap();
    let mut vm = EbpfVm::<UserError>::new(executable.as_ref(), &[], &[]).unwrap();
    vm.register_syscall_ex("log", Syscall::Function(bpf_syscall_string))
        .unwrap();
    vm.execute_program_interpreted(&mut DefaultInstructionMeter {})
        .unwrap();
    assert_eq!(2, vm.get_total_instruction_count());
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
        let mut vm = EbpfVm::<UserError>::new(executable.as_ref(), &[], &[]).unwrap();
        assert_eq!(
            0,
            vm.execute_program_interpreted(&mut DefaultInstructionMeter {})
                .unwrap()
        );
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
        let mut vm = EbpfVm::<UserError>::new(executable.as_ref(), &[], &[]).unwrap();
        assert_eq!(
            0,
            vm.execute_program_interpreted(&mut DefaultInstructionMeter {})
                .unwrap()
        );
    }
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
                let mut vm = EbpfVm::<UserError>::new(executable.as_ref(), &[], &[]).unwrap();
                vm.register_syscall_ex("log", Syscall::Function(bpf_syscall_string))
                    .unwrap();
                vm.register_syscall_ex("log_64", Syscall::Function(bpf_syscall_u64))
                    .unwrap();
                let _ = vm.execute_program_interpreted(&mut DefaultInstructionMeter {});
            }
        },
    );
}
