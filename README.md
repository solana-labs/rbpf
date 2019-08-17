# solana_rbpf

![](misc/rbpf_256.png)

Rust (user-space) virtual machine for eBPF

[![Build Status](https://travis-ci.org/solana-labs/rbpf.svg?branch=solana-master)](https://travis-ci.org/solana-labs/rbpf)
[![Crates.io](https://img.shields.io/crates/v/solana_rbpf.svg)](https://crates.io/crates/solana_rbpf)

* [Description](#description)
* [Link to the crate](#link-to-the-crate)
* [API](#api)
* [Example uses](#example-uses)
* [Building eBPF programs](#building-ebpf-programs)
* [Feedback welcome!](#feedback-welcome)
* [Questions / Answers](#questions--answers)
* [Caveats](#caveats)
* [_To do_ list](#to-do-list)
* [License](#license)
* [Inspired by](#inspired-by)
* [Other resources](#other-resources)

## Description

This crate contains a virtual machine for eBPF program execution. BPF, as in
_Berkeley Packet Filter_, is an assembly-like language initially developed for
BSD systems, in order to filter packets in the kernel with tools such as
tcpdump so as to avoid useless copies to user-space. It was ported to Linux,
where it evolved into eBPF (_extended_ BPF), a faster version with more
features. While BPF programs are originally intended to run in the kernel, the
virtual machine of this crate enables running it in user-space applications;
it contains an interpreter, an x86_64 JIT-compiler for eBPF programs, as well as
a disassembler.

It is based on Rich Lane's [uBPF software](https://github.com/iovisor/ubpf/),
which does nearly the same, but is written in C.

The crate is supposed to compile and run on Linux, MacOS X, and Windows,
although the JIT-compiler does not work with Windows at this time.

## Link to the crate

This crate is available from [crates.io](https://crates.io/crates/rbpf), so it
should work out of the box by adding it as a dependency in your `Cargo.toml`
file:

```toml
[dependencies]
solana_rbpf = "0.1.13"
```

You can also use the development version from this GitHub repository. This
should be as simple as putting this inside your `Cargo.toml`:

```toml
[dependencies]
solana_rbpf = { git = "https://github.com/solana-labs/rbpf" }
```

Of course, if you prefer, you can clone it locally, possibly hack the crate,
and then indicate the path of your local version in `Cargo.toml`:

```toml
[dependencies]
solana_rbpf = { path = "path/to/solana_rbpf" }
```

Then indicate in your source code that you want to use the crate:

```rust,ignore
extern crate solana_rbpf;
```

## API

The API is pretty well documented inside the source code. You should also be
able to access [an online version of the documentation from
here](https://docs.rs/solana_rbpf/), automatically generated from the
[crates.io](https://crates.io/crates/solana_rbpf) version (may not be up-to-date with
master branch). [Examples](../../tree/master/examples) and [unit
tests](../../tree/master/tests) should also prove helpful. Here is a summary of
how to use the crate.

Here are the steps to follow to run an eBPF program with rbpf:

1. Create a virtual machine. There are several kinds of machines, we will come
   back on this later. When creating the VM, pass the eBPF program as an
   argument to the constructor.
2. If you want to use some helper functions, register them into the virtual
   machine.
3. If you want a JIT-compiled program, compile it.
4. Execute your program: either run the interpreter or call the JIT-compiled
   function.

This behavior can be replicated with rbpf, but it is not mandatory. For this
reason, we have several structs representing different kinds of virtual
machines:

* `struct EbpfVm` is for programs that want to run directly on packet data.
  The eBPF program directly receives the
  address of the packet data in its first register. This is the behavior of
  uBPF.

Public functions:

```rust,ignore
// called with EbpfVm:: prefix
pub fn new(prog: &'a [u8]) -> Result<EbpfVm<'a>, Error>
```

This is used to create a new instance of a VM. The return type is dependent of
the struct from which the function is called. For instance,
`rbpf::EbpfVm::new(my_program)` would return an instance of `struct
rbpf::EbpfVm` (wrapped in a `Result`). When a program is loaded, it is
checked with a very simple verifier (nothing close to the one for Linux
kernel). Users are also able to replace it with a custom verifier.

```rust,ignore
// for struct EbpfVm
pub fn set_program(&mut self, prog: &'a [u8]) -> Result<(), Error>

```

You can use for example `my_vm.set_program(my_program);` to change the loaded
program after the VM instance creation. This program is checked with the
verifier attached to the VM. The verifying function of the VM can be changed at
any moment.

```rust,ignore
pub type Verifier = fn(prog: &[u8]) -> Result<(), Error>;

pub fn set_verifier(&mut self,
                    verifier: Verifier) -> Result<(), Error>
```

Note that if a program has already been loaded into the VM, setting a new
verifier also immediately runs it on the loaded program. However, the verifier
is not run if no program has been loaded (if `None` was passed to the `new()`
method when creating the VM).

```rust,ignore
pub type Helper = fn (u64, u64, u64, u64, u64) -> u64;

pub fn register_helper(&mut self,
                       key: u32,
                       function: Helper) -> Result<(), Error>
```

This function is used to register a helper function. The VM stores its
registers in a hashmap, so the key can be any `u32` value you want. It may be
useful for programs that should be compatible with the Linux kernel and
therefore must use specific helper numbers.

```rust,ignore
// for struct EbpfVm
pub fn execute_program(&self,
                 mem: &'a mut [u8]) -> Result<(u64), Error>
```

Interprets the loaded program. The function takes a reference to the packet
data. The value returned is the result of the
eBPF program.

```rust,ignore
pub fn jit_compile(&mut self) -> Result<(), Error>
```

JIT-compile the loaded program, for x86_64 architecture. If the program is to
use helper functions, they must be registered into the VM before this function
is called. The generated assembly function is internally stored in the VM.

```rust,ignore
// for struct EbpfVm
pub unsafe fn execute_program_jit(&self, 
                                  mem: &'a mut [u8]) -> Result<(u64), Error>
```

Calls the JIT-compiled program. The arguments to provide are the same as for
`execute_program()`, again depending on the kind of VM that is used. The result of
the JIT-compiled program should be the same as with the interpreter, but it
should run faster. Note that if errors occur during the program execution, the
JIT-compiled version does not handle it as well as the interpreter, and the
program may crash. For this reason, the functions are marked as `unsafe`.

## Example uses

### Simple example

This comes from the unit test `test_vm_add`.

```rust
extern crate rbpf;

fn main() {

    // This is the eBPF program, in the form of bytecode instructions.
    let prog = &[
        0xb4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov32 r0, 0
        0xb4, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, // mov32 r1, 2
        0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // add32 r0, 1
        0x0c, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // add32 r0, r1
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    ];

    // Instantiate a struct EbpfVmNoData. This is an eBPF VM for programs that
    // takes no packet data in argument.
    // The eBPF program is passed to the constructor.
    let vm = rbpf::EbpfVm::new(prog).unwrap();

    // Execute (interpret) the program.
    assert_eq!(vm.execute_program(&[], &[]. &[]).unwrap(), 0x3);
}
```

### With JIT, on packet data

This comes from the unit test `test_jit_ldxh`.

```rust
extern crate rbpf;

fn main() {
    let prog = &[
        0x71, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, // ldxh r0, [r1+2]
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    ];

    // Let's use some data.
    let mem = &mut [
        0xaa, 0xbb, 0x11, 0xcc, 0xdd
    ];

    // This is an eBPF VM for programs reading from a given memory area (it
    // directly reads from packet data)
    let mut vm = rbpf::EbpfVm::new(prog).unwrap();

    // This time we JIT-compile the program.
    vm.jit_compile().unwrap();

    // Then we execute it. For this kind of VM, a reference to the packet data
    // must be passed to the function that executes the program.
    unsafe { assert_eq!(vm.execute_program_jit(mem).unwrap(), 0x11); }
}
```

## Building eBPF programs

Besides passing the raw hexadecimal codes for building eBPF programs, two other
methods are available.

### Assembler

The first method consists in using the assembler provided by the crate.

```rust
extern crate rbpf;
use rbpf::assembler::assemble;

let prog = assemble("add64 r1, 0x605
                     mov64 r2, 0x32
                     mov64 r1, r0
                     be16 r0
                     neg64 r2
                     exit").unwrap();

println!("{:?}", prog);
```

The above snippet will produce:

```rust,ignore
Ok([0x07, 0x01, 0x00, 0x00, 0x05, 0x06, 0x00, 0x00,
    0xb7, 0x02, 0x00, 0x00, 0x32, 0x00, 0x00, 0x00,
    0xbf, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xdc, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    0x87, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
```

Conversely, a disassembler is also available to dump instruction names from
bytecode in a human-friendly format.

```rust
extern crate rbpf;
use rbpf::disassembler::disassemble;

let prog = &[
    0x07, 0x01, 0x00, 0x00, 0x05, 0x06, 0x00, 0x00,
    0xb7, 0x02, 0x00, 0x00, 0x32, 0x00, 0x00, 0x00,
    0xbf, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xdc, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    0x87, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
];

disassemble(prog);
```

This will produce the following output:

```txt
add64 r1, 0x605
mov64 r2, 0x32
mov64 r1, r0
be16 r0
neg64 r2
exit
```

Please refer to [source code](src/assembler.rs) and [tests](tests/assembler.rs)
for the syntax and the list of instruction names.

### Building API

The other way to build programs is to chain commands from the instruction
builder API. It looks less like assembly, maybe more like high-level functions.
What's sure is that the result is more verbose, but if you prefer to build
programs this way, it works just as well. If we take again the same sample as
above, it would be constructed as follows.

```rust
extern crate rbpf;
use rbpf::insn_builder::*;

let mut program = BpfCode::new();
program.add(Source::Imm, Arch::X64).set_dst(1).set_imm(0x605).push()
       .mov(Source::Imm, Arch::X64).set_dst(2).set_imm(0x32).push()
       .mov(Source::Reg, Arch::X64).set_src(0).set_dst(1).push()
       .swap_bytes(Endian::Big).set_dst(0).set_imm(0x10).push()
       .negate(Arch::X64).set_dst(2).push()
       .exit().push();
```

Again, please refer to [the source and related tests](src/insn_builder.rs) to
get more information and examples on how to use it.

## Feedback welcome!

This is the author's first try at writing Rust code. He learned a lot in the
process, but there remains a feeling that this crate has a kind of C-ish style
in some places instead of the Rusty look the author would like it to have. So
feedback (or PRs) are welcome, including about ways you might see to take
better advantage of Rust features.

## Questions / Answers

### What Rust version is needed?

This crate is known to be compatible with Rust version 1.14.0. Older versions
of Rust have not been tested.

### Why implementing an eBPF virtual machine in Rust?

As of this writing, there is no particular use case for this crate at the best
of the author's knowledge. The author happens to work with BPF on Linux and to
know how uBPF works, and he wanted to learn and experiment with Rust—no more
than that.

### What are the differences with uBPF?

Other than the language, obviously? Well, there are some differences:

* Some constants, such as the maximum length for programs or the length for the
  stack, differs between uBPF and rbpf. The latter uses the same values as the
  Linux kernel, while uBPF has its own values.

* When an error occurs while a program is run by uBPF, the function running the
  program silently returns the maximum value as an error code, while rbpf
  returns Rust type `Error`.

* The registration of helper functions, that can be called from within an eBPF
  program, is not handled in the same way.

* As for performance: theoretically the JITted programs are expected to run at
  the same speed, while the C interpreter of uBPF should go slightly faster
  than rbpf. But this has not been asserted yet. Benchmarking both programs
  would be an interesting thing to do.

### Can I use it with the “classic” BPF (a.k.a cBPF) version?

No. This crate only works with extended BPF (eBPF) programs. For cBPF programs,
such as used by tcpdump (as of this writing) for example, you may be interested
in the [bpfjit crate](https://crates.io/crates/bpfjit) written by Alexander
Polakov instead.

### What functionalities are implemented?

Running and JIT-compiling eBPF programs work. There is also a mechanism to
register user-defined helper functions. The eBPF implementation of the Linux
kernel comes with [some additional
features](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md):
a high number of helpers, several kinds of maps, tail calls.

* Additional helpers should be easy to add, but very few of the existing Linux
  helpers have been replicated in rbpf so far.

* Tail calls (“long jumps” from an eBPF program into another) are not
  implemented. This is probably not trivial to design and implement.

* The interaction with maps is done through the use of specific helpers, so
  this should not be difficult to add. The maps themselves can reuse the maps
  in the kernel (if on Linux), to communicate with in-kernel eBPF programs for
  instance; or they can be handled in user space. Rust has arrays and hashmaps,
  so their implementation should be pretty straightforward (and may be added to
  rbpf in the future).

### What about program validation?

The ”verifier” of this crate is very short and has nothing to do with the
kernel verifier, which means that it accepts programs that may not be safe. On
the other hand, you probably do not run this in a kernel here, so it will not
crash your system. Implementing a verifier similar to the one in the kernel is
not trivial, and we cannot “copy” it since it is under GPL license.

### What about safety then?

Rust has a strong emphasis on safety. Yet to have the eBPF VM work, some
`unsafe` blocks of code are used. The VM, taken as an eBPF interpreter, can
return an error but should not crash. Please file an issue otherwise.

As for the JIT-compiler, it is a different story, since runtime memory checks
are more complicated to implement in assembly. It _will_ crash if your
JIT-compiled program tries to perform unauthorized memory accesses. Usually, it
could be a good idea to test your program with the interpreter first.

Oh, and if your program has infinite loops, even with the interpreter, you're
on your own.

## Caveats

* This crate is **under development** and the API may be subject to change.

* The JIT compiler produces an unsafe program: memory access are not tested at
  runtime (yet). Use with caution.

* Contrary to the interpreter, if a division by 0 is attempted, the JIT program
  returns `0xffffffffffffffff` and exits cleanly (no `Error` returned). This is
  because the author has not found how to return something more explicit
  from the generated assembly so far.

* A very little number of eBPF instructions have not been implemented yet. This
  should not be a problem for the majority of eBPF programs.

* Beware of turnips. Turnips are disgusting.

## _To do_ list

* Implement some traits (`Clone`, `Drop`, `Debug` are good candidates).
* Provide built-in support for user-space array and hash BPF maps.
* Improve safety of JIT-compiled programs with runtime memory checks.
* Add helpers (some of those supported in the kernel, such as checksum update,
  could be helpful).
* Improve verifier. Could we find a way to directly support programs compiled
  with clang?
* Maybe one day, tail calls?
* JIT-compilers for other architectures?
* …

## License

Following the effort of the Rust language project itself in order to ease
integration with other projects, the rbpf crate is distributed under the terms
of both the MIT license and the Apache License (Version 2.0).

See
[LICENSE-APACHE](https://github.com/qmonnet/rbpf/blob/master/LICENSE-APACHE)
and [LICENSE-MIT](https://github.com/qmonnet/rbpf/blob/master/LICENSE-MIT) for
details.

## Inspired by

* [uBPF](https://github.com/iovisor/ubpf), a C user-space implementation of an
  eBPF virtual machine, with a JIT-compiler and disassembler (and also
  including the assembler from the human-readable form of the instructions,
  such as in `mov r0, 0x1337`), by Rich Lane for Big Switch Networks (2015)

* [_Building a simple JIT in
  Rust_](http://www.jonathanturner.org/2015/12/building-a-simple-jit-in-rust.html),
  by Jonathan Turner (2015)

* [bpfjit](https://github.com/polachok/bpfjit) (also [on
  crates.io](https://crates.io/crates/bpfjit)), a Rust crate exporting the cBPF
  JIT compiler from FreeBSD 10 tree to Rust, by Alexander Polakov (2016)

## Other resources

* Cilium project documentation about BPF: [_BPF and XDP Reference
  Guide_](http://docs.cilium.io/en/latest/bpf/)

* Kernel documentation about BPF: [Documentation/networking/filter.txt
  file](https://www.kernel.org/doc/Documentation/networking/filter.txt)

* [_Dive into BPF: a list of reading
  material_](https://qmonnet.github.io/whirl-offload/2016/09/01/dive-into-bpf),
  a blog article listing documentation for BPF and related technologies (2016)

* [The Rust programming language](https://www.rust-lang.org)
