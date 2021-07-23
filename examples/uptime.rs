// Copyright 2017 6WIND S.A. <quentin.monnet@6wind.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

extern crate solana_rbpf;
use solana_rbpf::{
    syscalls,
    user_error::UserError,
    vm::{Config, EbpfVm, Executable, SyscallObject, SyscallRegistry, TestInstructionMeter},
};
use std::collections::BTreeMap;

// The main objectives of this example is to show:
//
// * the use of EbpfVm function,
// * and the use of a syscall.
//
// The two eBPF programs are independent and are not related to one another.
fn main() {
    let prog1 = &[
        0xb4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov32 r0, 0
        0xb4, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, // mov32 r1, 2
        0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // add32 r0, 1
        0x0c, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // add32 r0, r1
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit and return r0
    ];

    // We use syscall `bpf_time_getns()`, which is similar to syscall `bpf_ktime_getns()` from Linux
    // kernel. Hence syscalls module provides the index of this in-kernel syscall as a
    // constant, so that we can remain compatible with programs for the kernel. Here we also cast
    // it to a u8 so as to use it directly in program instructions.
    let hkey = syscalls::BPF_KTIME_GETNS_IDX as u8;
    let prog2 = &[
        0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov64 r1, 0
        0xb7, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov64 r1, 0
        0xb7, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov64 r1, 0
        0xb7, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov64 r1, 0
        0xb7, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov64 r1, 0
        0x85, 0x00, 0x00, 0x00, hkey, 0x00, 0x00, 0x00, // call syscall <hkey>
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit and return r0
    ];

    // Create a VM: this one takes no data. Load prog1 in it.
    let executable = <dyn Executable<UserError, TestInstructionMeter>>::from_text_bytes(
        prog1,
        None,
        Config::default(),
        SyscallRegistry::default(),
        BTreeMap::default(),
    )
    .unwrap();
    let mut vm =
        EbpfVm::<UserError, TestInstructionMeter>::new(executable.as_ref(), &mut [], &mut [])
            .unwrap();
    // Execute prog1.
    assert_eq!(
        vm.execute_program_interpreted(&mut TestInstructionMeter { remaining: 5 })
            .unwrap(),
        0x3
    );

    // We know prog1 will always return 3. There is an exception: when it uses
    // syscalls, the latter may have non-deterministic values, and all calls may not return the same
    // value.
    //
    // In the following example we use a syscall to get the elapsed time since boot time: we
    // reimplement uptime in eBPF, in Rust. Because why not.

    let mut syscall_registry = SyscallRegistry::default();
    syscall_registry
        .register_syscall_by_hash::<UserError, _>(
            syscalls::BPF_KTIME_GETNS_IDX,
            syscalls::BpfTimeGetNs::call,
        )
        .unwrap();
    #[allow(unused_mut)]
    let mut executable = <dyn Executable<UserError, TestInstructionMeter>>::from_text_bytes(
        prog2,
        None,
        Config::default(),
        syscall_registry,
        BTreeMap::default(),
    )
    .unwrap();
    #[cfg(not(windows))]
    {
        executable.jit_compile().unwrap();
    }
    let mut vm =
        EbpfVm::<UserError, TestInstructionMeter>::new(executable.as_ref(), &mut [], &mut [])
            .unwrap();
    vm.bind_syscall_context_object(Box::new(syscalls::BpfTimeGetNs {}), None)
        .unwrap();

    let time;
    #[cfg(not(windows))]
    {
        time = vm
            .execute_program_jit(&mut TestInstructionMeter { remaining: 7 })
            .unwrap();
    }

    #[cfg(windows)]
    {
        time = vm
            .execute_program_interpreted(&mut TestInstructionMeter { remaining: 7 })
            .unwrap();
    }

    let days = time / 10u64.pow(9) / 60 / 60 / 24;
    let hours = (time / 10u64.pow(9) / 60 / 60) % 24;
    let minutes = (time / 10u64.pow(9) / 60) % 60;
    let seconds = (time / 10u64.pow(9)) % 60;
    let nanosec = time % 10u64.pow(9);

    println!(
        "Uptime: {:#x} ns == {} days {:02}:{:02}:{:02}, {} ns",
        time, days, hours, minutes, seconds, nanosec
    );
}
