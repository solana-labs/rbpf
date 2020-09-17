// Copyright 2015 Big Switch Networks, Inc
//      (Algorithms for uBPF syscalls, originally in C)
// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//      (Translation to Rust, other syscalls)
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.


//! This module implements some built-in syscalls that can be called from within an eBPF program.
//!
//! These syscalls may originate from several places:
//!
//! * Some of them mimic the syscalls available in the Linux kernel.
//! * Some of them were proposed as example syscalls in uBPF and they were adapted here.
//! * Other syscalls may be specific to rbpf.
//!
//! The prototype for syscalls is always the same: five `u64` as arguments, and a `u64` as a return
//! value. Hence some syscalls have unused arguments, or return a 0 value in all cases, in order to
//! respect this convention.

use std::u64;
use time;
use crate::{
    ebpf::{EbpfError, UserDefinedError},
    memory_region::{MemoryRegion, MemoryMapping}
};

// Syscalls associated to kernel syscalls
// See also linux/include/uapi/linux/bpf.h in Linux kernel sources.

// bpf_ktime_getns()

/// Index of syscall `bpf_ktime_getns()`, equivalent to `bpf_time_getns()`, in Linux kernel, see
/// <https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/bpf.h>.
pub const BPF_KTIME_GETNS_IDX: u32 = 5;

/// Get monotonic time (since boot time) in nanoseconds. All arguments are unused.
///
/// # Examples
///
/// ```
/// use solana_rbpf::syscalls::bpf_time_getns;
/// use solana_rbpf::memory_region::MemoryRegion;
/// use solana_rbpf::user_error::UserError;
///
/// let regions = [MemoryRegion::default()];
/// let t = bpf_time_getns::<UserError>(0, 0, 0, 0, 0, &regions, &regions).unwrap();
/// let d =  t / 10u64.pow(9)  / 60   / 60  / 24;
/// let h = (t / 10u64.pow(9)  / 60   / 60) % 24;
/// let m = (t / 10u64.pow(9)  / 60 ) % 60;
/// let s = (t / 10u64.pow(9)) % 60;
/// let ns = t % 10u64.pow(9);
/// println!("Uptime: {:#x} == {} days {}:{}:{}, {} ns", t, d, h, m, s, ns);
/// ```
#[allow(dead_code)]
pub fn bpf_time_getns<E: UserDefinedError> (
    _arg1: u64,
    _arg2: u64,
    _arg3: u64,
    _arg4: u64,
    _arg5: u64,
    _ro_regions: &[MemoryRegion],
    _rw_regions: &[MemoryRegion],
) -> Result<u64, EbpfError<E>>
{
    Ok(time::precise_time_ns())
}

// bpf_trace_printk()

/// Index of syscall `bpf_trace_printk()`, equivalent to `bpf_trace_printf()`, in Linux kernel, see
/// <https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/bpf.h>.
pub const BPF_TRACE_PRINTK_IDX: u32 = 6;

/// Prints its **last three** arguments to standard output. The **first two** arguments are
/// **unused**. Returns the number of bytes written.
///
/// By ignoring the first two arguments, it creates a syscall that will have a behavior similar to
/// the one of the equivalent syscall `bpf_trace_printk()` from Linux kernel.
///
/// # Examples
///
/// ```
/// use solana_rbpf::syscalls::bpf_trace_printf;
/// use solana_rbpf::memory_region::MemoryRegion;
/// use solana_rbpf::user_error::UserError;
///
/// let regions = [MemoryRegion::default()];
/// let res = bpf_trace_printf::<UserError>(0, 0, 1, 15, 32, &regions, &regions).unwrap();
/// assert_eq!(res as usize, "bpf_trace_printf: 0x1, 0xf, 0x20\n".len());
/// ```
///
/// This will print `bpf_trace_printf: 0x1, 0xf, 0x20`.
///
/// The eBPF code needed to perform the call in this example would be nearly identical to the code
/// obtained by compiling the following code from C to eBPF with clang:
///
/// ```c
/// #include <linux/bpf.h>
/// #include "path/to/linux/samples/bpf/bpf_syscalls.h"
///
/// int main(struct __sk_buff *skb)
/// {
///     // Only %d %u %x %ld %lu %lx %lld %llu %llx %p %s conversion specifiers allowed.
///     // See <https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/kernel/trace/bpf_trace.c>.
///     char *fmt = "bpf_trace_printk %llx, %llx, %llx\n";
///     return bpf_trace_printk(fmt, sizeof(fmt), 1, 15, 32);
/// }
/// ```
///
/// This would equally print the three numbers in `/sys/kernel/debug/tracing` file each time the
/// program is run.
#[allow(dead_code)]
pub fn bpf_trace_printf<E: UserDefinedError> (
    _arg1: u64,
    _arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    _ro_regions: &[MemoryRegion],
    _rw_regions: &[MemoryRegion]
) -> Result<u64, EbpfError<E>>
{
        println!("bpf_trace_printf: {:#x}, {:#x}, {:#x}", arg3, arg4, arg5);
        let size_arg = | x | {
            if x == 0 {
                1
            } else {
                (x as f64).log(16.0).floor() as u64 + 1
            }
        };
        Ok("bpf_trace_printf: 0x, 0x, 0x\n".len() as u64
            + size_arg(arg3) + size_arg(arg4) + size_arg(arg5))
}


// Syscalls coming from uBPF <https://github.com/iovisor/ubpf/blob/master/vm/test.c>

/// The idea is to assemble five bytes into a single `u64`. For compatibility with the syscalls API,
/// each argument must be a `u64`.
///
/// # Examples
///
/// ```
/// use solana_rbpf::syscalls::gather_bytes;
/// use solana_rbpf::memory_region::MemoryRegion;
/// use solana_rbpf::user_error::UserError;
///
/// let regions = [MemoryRegion::default()];
/// let gathered = gather_bytes::<UserError>(0x11, 0x22, 0x33, 0x44, 0x55, &regions, &regions).unwrap();
/// assert_eq!(gathered, 0x1122334455);
/// ```
pub fn gather_bytes<E: UserDefinedError> (
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    _ro_regions: &[MemoryRegion],
    _rw_regions: &[MemoryRegion]
) -> Result<u64, EbpfError<E>>
{
        Ok(arg1.wrapping_shl(32) |
        arg2.wrapping_shl(24) |
        arg3.wrapping_shl(16) |
        arg4.wrapping_shl(8)  |
        arg5)
}

/// Same as `void *memfrob(void *s, size_t n);` in `string.h` in C. See the GNU manual page (in
/// section 3) for `memfrob`. The memory is directly modified, and the syscall returns 0 in all
/// cases. Arguments 3 to 5 are unused.
///
/// # Examples
///
/// ```
/// use solana_rbpf::syscalls::memfrob;
/// use solana_rbpf::memory_region::MemoryRegion;
/// use solana_rbpf::user_error::UserError;
///
/// let val = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33];
/// let val_va = 0x1000;
/// let regions = [MemoryRegion::new_from_slice(&val, val_va)];
///
/// memfrob::<UserError>(val_va, 8, 0, 0, 0, &regions, &regions);
/// assert_eq!(val, vec![0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x3b, 0x08, 0x19]);
/// memfrob::<UserError>(val_va, 8, 0, 0, 0, &regions, &regions);
/// assert_eq!(val, vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33]);
/// ```
pub fn memfrob<E: UserDefinedError> (
    vm_addr: u64,
    len: u64,
    _arg3: u64,
    _arg4: u64,
    _arg5: u64,
    memory_mapping: &[MemoryRegion]
) -> Result<u64, EbpfError<E>>
{

        let host_addr = memory_mapping.map(AccessType::Store, vm_addr, len as usize)?;
        for i in 0..len {
            unsafe {
                let mut p = (host_addr + i) as *mut u8;
                *p ^= 0b101010;
            }
        }
        Ok(0)
}

// TODO: Try again when asm!() is available in stable Rust.
// #![feature(asm)]
// #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
// #[allow(unused_variables)]
// pub fn memfrob (ptr: u64, len: u64, arg3: u64, arg4: u64, arg5: u64) -> Result<u64, Error> {
//     unsafe {
//         asm!(
//                 "mov $0xf0, %rax"
//             ::: "mov $0xf1, %rcx"
//             ::: "mov $0xf2, %rdx"
//             ::: "mov $0xf3, %rsi"
//             ::: "mov $0xf4, %rdi"
//             ::: "mov $0xf5, %r8"
//             ::: "mov $0xf6, %r9"
//             ::: "mov $0xf7, %r10"
//             ::: "mov $0xf8, %r11"
//         );
//     }
//     0
// }

/// Compute and return the square root of argument 1, cast as a float. Arguments 2 to 5 are
/// unused.
///
/// # Examples
///
/// ```
/// use solana_rbpf::syscalls::sqrti;
/// use solana_rbpf::memory_region::MemoryRegion;
/// use solana_rbpf::user_error::UserError;
///
/// let regions = [MemoryRegion::default()];
/// let x = sqrti::<UserError>(9, 0, 0, 0, 0, &regions, &regions).unwrap();
/// assert_eq!(x, 3);
/// ```
#[allow(dead_code)]
pub fn sqrti<E: UserDefinedError> (
    arg1: u64,
    _arg2: u64,
    _arg3: u64,
    _arg4: u64,
    _arg5: u64,
    _ro_regions: &[MemoryRegion],
    _rw_regions: &[MemoryRegion]
) -> Result<u64, EbpfError<E>>
{
        Ok((arg1 as f64).sqrt() as u64)
}

/// C-like `strcmp`, return 0 if the strings are equal, and a non-null value otherwise.
///
/// # Examples
///
/// ```
/// use solana_rbpf::syscalls::strcmp;
/// use solana_rbpf::memory_region::MemoryRegion;
/// use solana_rbpf::user_error::UserError;
///
/// let foo = "This is a string.";
/// let bar = "This is another sting.";
/// let va_foo = 0x1000;
/// let va_bar = 0x2000;
/// let regions = [MemoryRegion::new_from_slice(foo.as_bytes(), va_foo)];
/// assert!(strcmp::<UserError>(va_foo, va_foo, 0, 0, 0, &regions, &regions).unwrap() == 0);
/// let regions = [MemoryRegion::new_from_slice(foo.as_bytes(), va_foo),
///                MemoryRegion::new_from_slice(bar.as_bytes(), va_bar)];
/// assert!(strcmp::<UserError>(va_foo, va_bar, 0, 0, 0, &regions, &regions).unwrap() != 0);
/// ```
#[allow(dead_code)]
pub fn strcmp<E: UserDefinedError> (
    arg1: u64,
    arg2: u64,
    _arg3: u64,
    _arg4: u64,
    _arg5: u64,
    memory_mapping: &[MemoryRegion]
) -> Result<u64, EbpfError<E>>
{
        // C-like strcmp, maybe shorter than converting the bytes to string and comparing?
        if arg1 == 0 || arg2 == 0 {
            return Ok(u64::MAX);
        }
        let mut a = memory_mapping.map(AccessType::Load, arg1, 1)?;
        let mut b = memory_mapping.map(AccessType::Load, arg2, 1)?;
        unsafe {
            let mut a_val = *(a as *const u8);
            let mut b_val = *(b as *const u8);
            while a_val == b_val && a_val != 0 && b_val != 0 {
                a +=1 ;
                b +=1 ;
                a_val = *(a as *const u8);
                b_val = *(b as *const u8);
            }
            if a_val >= b_val {
                Ok((a_val - b_val) as u64)
            } else {
                Ok((b_val - a_val) as u64)
            }
        }
}

// Some additional syscalls

/// Returns a random u64 value comprised between `min` and `max` values (inclusive). Arguments 3 to
/// 5 are unused.
///
/// Relies on `rand()` function from libc, so `libc::srand()` should be called once before this
/// syscall is used.
///
/// # Examples
///
/// ```
/// extern crate libc;
/// extern crate solana_rbpf;
/// extern crate time;
///
/// use solana_rbpf::syscalls::rand;
/// use solana_rbpf::memory_region::MemoryRegion;
/// use solana_rbpf::user_error::UserError;
///
/// unsafe {
///     libc::srand(time::precise_time_ns() as u32)
/// }
///
/// let regions = [MemoryRegion::default()];
/// let n = rand::<UserError>(3, 6, 0, 0, 0, &regions, &regions).unwrap();
/// assert!(3 <= n && n <= 6);
/// ```
#[allow(dead_code)]
pub fn rand<E: UserDefinedError> (
    min: u64,
    max: u64,
    _arg3: u64,
    _arg4: u64,
    _arg5: u64,
    _ro_regions: &[MemoryRegion],
    _rw_regions: &[MemoryRegion],
) -> Result<u64, EbpfError<E>>
{
        let mut n = unsafe {
            (libc::rand() as u64).wrapping_shl(32) + libc::rand() as u64
        };
        if min < max {
            n = n % (max + 1 - min) + min;
        };
        Ok(n)
}
