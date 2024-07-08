# solana_rbpf

![](misc/rbpf_256.png)

Rust (user-space) virtual machine for eBPF

[![Build Status](https://github.com/solana-labs/rbpf/actions/workflows/main.yml/badge.svg)](https://github.com/solana-labs/rbpf/actions/workflows/main.yml)
[![Crates.io](https://img.shields.io/crates/v/solana_rbpf.svg)](https://crates.io/crates/solana_rbpf)

## Description

This is a fork of [RBPF](https://github.com/qmonnet/rbpf) by Quentin Monnet.

This crate contains a virtual machine for eBPF program execution. BPF, as in
_Berkeley Packet Filter_, is an assembly-like language initially developed for
BSD systems, in order to filter packets in the kernel with tools such as
tcpdump so as to avoid useless copies to user-space. It was ported to Linux,
where it evolved into eBPF (_extended_ BPF), a faster version with more
features. While BPF programs are originally intended to run in the kernel, the
virtual machine of this crate enables running it in user-space applications;
it contains an interpreter, an x86_64 JIT-compiler for eBPF programs, as well as
an assembler, disassembler and verifier.

The crate is supposed to compile and run on Linux, MacOS X, and Windows,
although the JIT-compiler does not work with Windows at this time.

## Link to the crate

This crate is available from [crates.io](https://crates.io/crates/solana_rbpf),
so it should work out of the box by adding it as a dependency in your
`Cargo.toml` file:

```toml
[dependencies]
solana_rbpf = "0.8.2"
```

You can also use the development version from this GitHub repository. This
should be as simple as putting this inside your `Cargo.toml`:

```toml
[dependencies]
solana_rbpf = { git = "https://github.com/solana-labs/rbpf", branch = "main" }
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
[crates.io](https://crates.io/crates/solana_rbpf)
version (may not be up-to-date with master branch).
[Examples](examples), [unit tests](tests) and [performance benchmarks](benches)
should also prove helpful.

Here are the steps to follow to run an eBPF program with rbpf:

1. Create the config and a loader built-in program, add some functions.
2. Create an executable, either from the bytecode or an ELF.
3. If you want a JIT-compiled program, compile it.
4. Create a memory mapping, consisting of multiple memory regions.
5. Create a context object which will also acts as instruction meter.
6. Create a virtual machine using all of the previous steps.
7. Execute your program: Either run the interpreter or call the JIT-compiled
   function.

## Developer

### Dependencies
- rustc version 1.72 or higher

### Build and test instructions
- To build run `cargo build`
- To test run `cargo test`

## License

Following the effort of the Rust language project itself in order to ease
integration with other projects, the rbpf crate is distributed under the terms
of both the MIT license and the Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for details.
