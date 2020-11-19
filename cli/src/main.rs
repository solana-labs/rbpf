use clap::{App, Arg};
use rustc_demangle::demangle;
use solana_rbpf::{
    assembler::assemble,
    disassembler::to_insn_vec,
    ebpf,
    memory_region::{MemoryMapping, MemoryRegion},
    user_error::UserError,
    vm::{Config, EbpfVm, Executable, SyscallObject, SyscallRegistry},
};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use test_utils::{Result, TestInstructionMeter};

pub struct MockSyscall {
    name: String,
}
impl SyscallObject<UserError> for MockSyscall {
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
        println!(
            "Syscall {}: {:#x}, {:#x}, {:#x}, {:#x}, {:#x}",
            self.name, arg1, arg2, arg3, arg4, arg5,
        );
        *result = Result::Ok(0);
    }
}

fn main() {
    let matches = App::new("Solana RBPF CLI")
        .version("0.2.1")
        .author("Solana Maintainers <maintainers@solana.foundation>")
        .about("CLI to test and analyze eBPF programs")
        .arg(
            Arg::new("assembler")
                .about("Assemble and load eBPF executable")
                .short('a')
                .long("asm")
                .value_name("FILE")
                .takes_value(true)
                .required_unless_present("elf"),
        )
        .arg(
            Arg::new("elf")
                .about("Load ELF as eBPF executable")
                .short('e')
                .long("elf")
                .value_name("FILE")
                .takes_value(true)
                .required_unless_present("assembler"),
        )
        .arg(
            Arg::new("input")
                .about("Input for the program to run on")
                .short('i')
                .long("input")
                .value_name("FILE / BYTES")
                .takes_value(true)
                .default_value("0"),
        )
        .arg(
            Arg::new("memory")
                .about("Heap memory for the program to run on")
                .short('m')
                .long("mem")
                .value_name("BYTES")
                .takes_value(true)
                .default_value("0"),
        )
        .arg(
            Arg::new("use")
                .about("Method of execution to use")
                .short('u')
                .long("use")
                .takes_value(true)
                .possible_values(&["disassembler", "interpreter", "jit"])
                .required(true),
        )
        .arg(
            Arg::new("instruction limit")
                .about("Limit the number of instructions to execute")
                .short('l')
                .long("lim")
                .takes_value(true)
                .value_name("COUNT")
                .default_value(&std::i64::MAX.to_string()),
        )
        .arg(
            Arg::new("trace")
                .about("Enables tracing instrumentation")
                .short('t')
                .long("trace"),
        )
        .get_matches();

    let mut config = Config::default();
    config.enable_instruction_tracing = matches.is_present("trace");
    let mut executable = match matches.value_of("assembler") {
        Some(asm_file_name) => {
            let mut file = File::open(&Path::new(asm_file_name)).unwrap();
            let mut source = Vec::new();
            file.read_to_end(&mut source).unwrap();
            let program = assemble(std::str::from_utf8(source.as_slice()).unwrap()).unwrap();
            Executable::<UserError, TestInstructionMeter>::from_text_bytes(&program, None, config)
        }
        None => {
            let mut file = File::open(&Path::new(matches.value_of("elf").unwrap())).unwrap();
            let mut elf = Vec::new();
            file.read_to_end(&mut elf).unwrap();
            Executable::<UserError, TestInstructionMeter>::from_elf(&elf, None, config)
        }
    }
    .unwrap();

    let (syscalls, bpf_functions) = executable.get_symbols();
    let mut syscall_registry = SyscallRegistry::default();
    for hash in syscalls.keys() {
        let _ = syscall_registry.register_syscall_by_hash(*hash, MockSyscall::call);
    }
    executable.set_syscall_registry(syscall_registry);

    match matches.value_of("use") {
        Some("disassembler") => {
            let (_program_vm_addr, program) = executable.get_text_bytes().unwrap();
            for insn in to_insn_vec(program).iter() {
                if let Some(bpf_function) =
                    bpf_functions.get(&((insn.ptr + ebpf::ELF_INSN_DUMP_OFFSET) as u64 * 8))
                {
                    println!("{}:", demangle(&bpf_function.0));
                }
                print!("{:5} ", insn.ptr);
                if insn.name == "call" {
                    if let Some(syscall_name) = syscalls.get(&(insn.imm as u32)) {
                        println!("syscall {}", syscall_name);
                    } else if let Some(target_pc) = executable.lookup_bpf_call(insn.imm as u32) {
                        if let Some(bpf_function) = bpf_functions
                            .get(&((target_pc + ebpf::ELF_INSN_DUMP_OFFSET) as u64 * 8))
                        {
                            println!("call {}", demangle(&bpf_function.0));
                        } else {
                            println!("call {} # unresolved symbol", target_pc);
                        }
                    } else {
                        println!("call {:x} # unresolved relocation", insn.imm);
                    }
                } else {
                    println!("{}", insn.desc);
                }
            }
            return;
        }
        Some("jit") => {
            executable.jit_compile().unwrap();
        }
        _ => {}
    }

    let mut mem = match matches.value_of("input").unwrap().parse::<usize>() {
        Ok(allocate) => vec![0u8; allocate],
        Err(_) => {
            let mut file = File::open(&Path::new(matches.value_of("input").unwrap())).unwrap();
            let mut memory = Vec::new();
            file.read_to_end(&mut memory).unwrap();
            memory
        }
    };
    let mut instruction_meter = TestInstructionMeter {
        remaining: matches
            .value_of("instruction limit")
            .unwrap()
            .parse::<u64>()
            .unwrap(),
    };
    let heap = vec![
        0_u8;
        matches
            .value_of("memory")
            .unwrap()
            .parse::<usize>()
            .unwrap()
    ];
    let heap_region = MemoryRegion::new_from_slice(&heap, ebpf::MM_HEAP_START, 0, true);
    let mut vm = EbpfVm::new(executable.as_ref(), &mut mem, &[heap_region]).unwrap();
    for (hash, name) in &syscalls {
        vm.bind_syscall_context_object(Box::new(MockSyscall { name: name.clone() }), Some(*hash))
            .unwrap();
    }
    let result = if matches.value_of("use").unwrap() == "interpreter" {
        vm.execute_program_interpreted(&mut instruction_meter)
    } else {
        vm.execute_program_jit(&mut instruction_meter)
    };
    println!("Result: {:?}", result);
    println!("Instruction Count: {}", vm.get_total_instruction_count());
    if config.enable_instruction_tracing {
        let mut tracer_display = String::new();
        vm.get_tracer()
            .write(&mut tracer_display, vm.get_program())
            .unwrap();
        println!("Trace:\n{}", tracer_display);
    }
}
