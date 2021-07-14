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

extern crate libc;

use crate::{
    error::EbpfError,
    memory_region::{AccessType, MemoryMapping},
    question_mark,
    user_error::UserError,
    vm::SyscallObject,
};
use libc::c_char;
use std::{slice::from_raw_parts, str::from_utf8, u64};

/// Return type of syscalls
pub type Result = std::result::Result<u64, EbpfError<UserError>>;

// syscalls associated to kernel syscalls
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
/// use solana_rbpf::syscalls::{BpfTimeGetNs, Result};
/// use solana_rbpf::memory_region::{MemoryRegion, MemoryMapping};
/// use solana_rbpf::vm::{Config, SyscallObject};
/// use solana_rbpf::user_error::UserError;
///
/// let mut result: Result = Ok(0);
/// let config = Config::default();
/// let memory_mapping = MemoryMapping::new::<UserError>(vec![], &config).unwrap();
/// BpfTimeGetNs::call(&mut BpfTimeGetNs {}, 0, 0, 0, 0, 0, &memory_mapping, &mut result);
/// let t = result.unwrap();
/// let d =  t / 10u64.pow(9)  / 60   / 60  / 24;
/// let h = (t / 10u64.pow(9)  / 60   / 60) % 24;
/// let m = (t / 10u64.pow(9)  / 60 ) % 60;
/// let s = (t / 10u64.pow(9)) % 60;
/// let ns = t % 10u64.pow(9);
/// println!("Uptime: {:#x} == {} days {}:{}:{}, {} ns", t, d, h, m, s, ns);
/// ```
pub struct BpfTimeGetNs {}
impl SyscallObject<UserError> for BpfTimeGetNs {
    fn call(
        &mut self,
        _arg1: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        _memory_mapping: &MemoryMapping,
        result: &mut Result,
    ) {
        *result = Result::Ok(time::precise_time_ns());
    }
}

// bpf_trace_printk()

/// Index of syscall `bpf_trace_printk()`, equivalent to `bpf_trace_printf`, in Linux kernel, see
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
/// use solana_rbpf::syscalls::{BpfTracePrintf, Result};
/// use solana_rbpf::memory_region::{MemoryRegion, MemoryMapping};
/// use solana_rbpf::vm::{Config, SyscallObject};
/// use solana_rbpf::user_error::UserError;
///
/// let mut result: Result = Ok(0);
/// let config = Config::default();
/// let memory_mapping = MemoryMapping::new::<UserError>(vec![], &config).unwrap();
/// BpfTracePrintf::call(&mut BpfTracePrintf {}, 0, 0, 1, 15, 32, &memory_mapping, &mut result);
/// assert_eq!(result.unwrap() as usize, "BpfTracePrintf: 0x1, 0xf, 0x20\n".len());
/// ```
///
/// This will print `BpfTracePrintf: 0x1, 0xf, 0x20`.
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
pub struct BpfTracePrintf {}
impl SyscallObject<UserError> for BpfTracePrintf {
    fn call(
        &mut self,
        _arg1: u64,
        _arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
        _memory_mapping: &MemoryMapping,
        result: &mut Result,
    ) {
        println!("BpfTracePrintf: {:#x}, {:#x}, {:#x}", arg3, arg4, arg5);
        let size_arg = |x| {
            if x == 0 {
                1
            } else {
                (x as f64).log(16.0).floor() as u64 + 1
            }
        };
        *result = Result::Ok(
            "BpfTracePrintf: 0x, 0x, 0x\n".len() as u64
                + size_arg(arg3)
                + size_arg(arg4)
                + size_arg(arg5),
        );
    }
}

// syscalls coming from uBPF <https://github.com/iovisor/ubpf/blob/master/vm/test.c>

/// The idea is to assemble five bytes into a single `u64`. For compatibility with the syscalls API,
/// each argument must be a `u64`.
///
/// # Examples
///
/// ```
/// use solana_rbpf::syscalls::{BpfGatherBytes, Result};
/// use solana_rbpf::memory_region::{MemoryRegion, MemoryMapping};
/// use solana_rbpf::vm::{Config, SyscallObject};
/// use solana_rbpf::user_error::UserError;
///
/// let mut result: Result = Ok(0);
/// let config = Config::default();
/// let memory_mapping = MemoryMapping::new::<UserError>(vec![], &config).unwrap();
/// BpfGatherBytes::call(&mut BpfGatherBytes {}, 0x11, 0x22, 0x33, 0x44, 0x55, &memory_mapping, &mut result);
/// assert_eq!(result.unwrap(), 0x1122334455);
/// ```
pub struct BpfGatherBytes {}
impl SyscallObject<UserError> for BpfGatherBytes {
    fn call(
        &mut self,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
        _memory_mapping: &MemoryMapping,
        result: &mut Result,
    ) {
        *result = Result::Ok(
            arg1.wrapping_shl(32)
                | arg2.wrapping_shl(24)
                | arg3.wrapping_shl(16)
                | arg4.wrapping_shl(8)
                | arg5,
        );
    }
}

/// Same as `void *memfrob(void *s, size_t n);` in `string.h` in C. See the GNU manual page (in
/// section 3) for `memfrob`. The memory is directly modified, and the syscall returns 0 in all
/// cases. Arguments 3 to 5 are unused.
///
/// # Examples
///
/// ```
/// use solana_rbpf::syscalls::{BpfMemFrob, Result};
/// use solana_rbpf::memory_region::{MemoryRegion, MemoryMapping};
/// use solana_rbpf::vm::{Config, SyscallObject};
/// use solana_rbpf::user_error::UserError;
///
/// let val = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33];
/// let val_va = 0x100000000;
///
/// let mut result: Result = Ok(0);
/// let config = Config::default();
/// let memory_mapping = MemoryMapping::new::<UserError>(vec![MemoryRegion::default(), MemoryRegion::new_from_slice(&val, val_va, 0, true)], &config).unwrap();
/// BpfMemFrob::call(&mut BpfMemFrob {}, val_va, 8, 0, 0, 0, &memory_mapping, &mut result);
/// assert_eq!(val, vec![0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x3b, 0x08, 0x19]);
/// BpfMemFrob::call(&mut BpfMemFrob {}, val_va, 8, 0, 0, 0, &memory_mapping, &mut result);
/// assert_eq!(val, vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33]);
/// ```
pub struct BpfMemFrob {}
impl SyscallObject<UserError> for BpfMemFrob {
    fn call(
        &mut self,
        vm_addr: u64,
        len: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &MemoryMapping,
        result: &mut Result,
    ) {
        let host_addr = question_mark!(memory_mapping.map(AccessType::Store, vm_addr, len), result);
        for i in 0..len {
            unsafe {
                let p = (host_addr + i) as *mut u8;
                *p ^= 0b101010;
            }
        }
        *result = Result::Ok(0);
    }
}

/// Compute and return the square root of argument 1, cast as a float. Arguments 2 to 5 are
/// unused.
///
/// # Examples
///
/// ```
/// use solana_rbpf::syscalls::{BpfSqrtI, Result};
/// use solana_rbpf::memory_region::{MemoryRegion, MemoryMapping};
/// use solana_rbpf::vm::{Config, SyscallObject};
/// use solana_rbpf::user_error::UserError;
///
/// let mut result: Result = Ok(0);
/// let config = Config::default();
/// let memory_mapping = MemoryMapping::new::<UserError>(vec![], &config).unwrap();
/// BpfSqrtI::call(&mut BpfSqrtI {}, 9, 0, 0, 0, 0, &memory_mapping, &mut result);
/// assert_eq!(result.unwrap(), 3);
/// ```
pub struct BpfSqrtI {}
impl SyscallObject<UserError> for BpfSqrtI {
    fn call(
        &mut self,
        arg1: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        _memory_mapping: &MemoryMapping,
        result: &mut Result,
    ) {
        *result = Result::Ok((arg1 as f64).sqrt() as u64);
    }
}

/// C-like `strcmp`, return 0 if the strings are equal, and a non-null value otherwise.
///
/// # Examples
///
/// ```
/// use solana_rbpf::syscalls::{BpfStrCmp, Result};
/// use solana_rbpf::memory_region::{MemoryRegion, MemoryMapping};
/// use solana_rbpf::vm::{Config, SyscallObject};
///
/// let foo = "This is a string.";
/// let bar = "This is another sting.";
/// let va_foo = 0x100000000;
/// let va_bar = 0x200000000;
/// use solana_rbpf::user_error::UserError;
///
/// let mut result: Result = Ok(0);
/// let config = Config::default();
/// let memory_mapping = MemoryMapping::new::<UserError>(vec![MemoryRegion::default(), MemoryRegion::new_from_slice(foo.as_bytes(), va_foo, 0, false)], &config).unwrap();
/// BpfStrCmp::call(&mut BpfStrCmp {}, va_foo, va_foo, 0, 0, 0, &memory_mapping, &mut result);
/// assert!(result.unwrap() == 0);
/// let mut result: Result = Ok(0);
/// let memory_mapping = MemoryMapping::new::<UserError>(vec![MemoryRegion::default(), MemoryRegion::new_from_slice(foo.as_bytes(), va_foo, 0, false), MemoryRegion::new_from_slice(bar.as_bytes(), va_bar, 0, false)], &config).unwrap();
/// BpfStrCmp::call(&mut BpfStrCmp {}, va_foo, va_bar, 0, 0, 0, &memory_mapping, &mut result);
/// assert!(result.unwrap() != 0);
/// ```
pub struct BpfStrCmp {}
impl SyscallObject<UserError> for BpfStrCmp {
    fn call(
        &mut self,
        arg1: u64,
        arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &MemoryMapping,
        result: &mut Result,
    ) {
        // C-like strcmp, maybe shorter than converting the bytes to string and comparing?
        if arg1 == 0 || arg2 == 0 {
            *result = Result::Ok(u64::MAX);
            return;
        }
        let mut a = question_mark!(memory_mapping.map(AccessType::Load, arg1, 1), result);
        let mut b = question_mark!(memory_mapping.map(AccessType::Load, arg2, 1), result);
        unsafe {
            let mut a_val = *(a as *const u8);
            let mut b_val = *(b as *const u8);
            while a_val == b_val && a_val != 0 && b_val != 0 {
                a += 1;
                b += 1;
                a_val = *(a as *const u8);
                b_val = *(b as *const u8);
            }
            *result = if a_val >= b_val {
                Result::Ok((a_val - b_val) as u64)
            } else {
                Result::Ok((b_val - a_val) as u64)
            };
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
/// use solana_rbpf::syscalls::{BpfRand, Result};
/// use solana_rbpf::memory_region::{MemoryRegion, MemoryMapping};
/// use solana_rbpf::vm::{Config, SyscallObject};
/// use solana_rbpf::user_error::UserError;
///
/// unsafe {
///     libc::srand(time::precise_time_ns() as u32)
/// }
///
/// let mut result: Result = Ok(0);
/// let config = Config::default();
/// let memory_mapping = MemoryMapping::new::<UserError>(vec![], &config).unwrap();
/// BpfRand::call(&mut BpfRand {}, 3, 6, 0, 0, 0, &memory_mapping, &mut result);
/// let n = result.unwrap();
/// assert!(3 <= n && n <= 6);
/// ```
pub struct BpfRand {}
impl SyscallObject<UserError> for BpfRand {
    fn call(
        &mut self,
        min: u64,
        max: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        _memory_mapping: &MemoryMapping,
        result: &mut Result,
    ) {
        let mut n = unsafe { (libc::rand() as u64).wrapping_shl(32) + libc::rand() as u64 };
        if min < max {
            n = n % (max + 1 - min) + min;
        };
        *result = Result::Ok(n);
    }
}

/// Prints a NULL-terminated UTF-8 string.
pub struct BpfSyscallString {}
impl SyscallObject<UserError> for BpfSyscallString {
    fn call(
        &mut self,
        vm_addr: u64,
        len: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &MemoryMapping,
        result: &mut Result,
    ) {
        let host_addr = question_mark!(memory_mapping.map(AccessType::Load, vm_addr, len), result);
        let c_buf: *const c_char = host_addr as *const c_char;
        unsafe {
            for i in 0..len {
                let c = std::ptr::read(c_buf.offset(i as isize));
                if c == 0 {
                    break;
                }
            }
            let message = from_utf8(from_raw_parts(host_addr as *const u8, len as usize))
                .unwrap_or("Invalid UTF-8 String");
            println!("log: {}", message);
        }
        *result = Result::Ok(0);
    }
}

/// Prints the five arguments formated as u64 in decimal.
pub struct BpfSyscallU64 {}
impl SyscallObject<UserError> for BpfSyscallU64 {
    fn call(
        &mut self,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
        memory_mapping: &MemoryMapping,
        result: &mut Result,
    ) {
        println!(
            "dump_64: {:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:?}",
            arg1, arg2, arg3, arg4, arg5, memory_mapping as *const _
        );
        *result = Result::Ok(0);
    }
}

/// Excample of a syscall with internal state.
pub struct SyscallWithContext {
    /// Mutable state
    pub context: u64,
}
impl SyscallObject<UserError> for SyscallWithContext {
    fn call(
        &mut self,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
        memory_mapping: &MemoryMapping,
        result: &mut Result,
    ) {
        println!(
            "SyscallWithContext: {:?}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:?}",
            self as *const _, arg1, arg2, arg3, arg4, arg5, memory_mapping as *const _
        );
        assert_eq!(self.context, 42);
        self.context = 84;
        *result = Result::Ok(0);
    }
}
