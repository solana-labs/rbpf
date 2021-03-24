use clap::{App, Arg};
use rustc_demangle::demangle;
use solana_rbpf::{
    assembler::assemble,
    ebpf,
    memory_region::{MemoryMapping, MemoryRegion},
    static_analysis::{AnalysisResult, LabelKind},
    user_error::UserError,
    verifier::check,
    vm::{Config, EbpfVm, Executable, SyscallObject, SyscallRegistry},
};
use std::{collections::HashMap, fs::File, io::Read, path::Path};
use test_utils::{Result, TestInstructionMeter};

pub fn print_label_at(analysis_result: &AnalysisResult, ptr: usize) -> bool {
    if let Some(label) = analysis_result.destinations.get(&ptr) {
        if label.kind == LabelKind::Function {
            println!();
        }
        println!("{}:", demangle(&label.name).to_string());
        true
    } else {
        false
    }
}

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
        .version("0.2.8")
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
                .about("Display trace using tracing instrumentation")
                .short('t')
                .long("trace"),
        )
        .arg(
            Arg::new("profile")
                .about("Display profile using tracing instrumentation")
                .short('p')
                .long("prof"),
        )
        .arg(
            Arg::new("verify")
                .about("Run the verifier before execution or disassembly")
                .short('v')
                .long("veri"),
        )
        .get_matches();

    let config = Config {
        enable_instruction_tracing: matches.is_present("trace") || matches.is_present("profile"),
        ..Config::default()
    };
    let verifier: Option<for<'r> fn(&'r [u8]) -> std::result::Result<_, _>> =
        if matches.is_present("verify") {
            Some(check)
        } else {
            None
        };
    let executable = match matches.value_of("assembler") {
        Some(asm_file_name) => {
            let mut file = File::open(&Path::new(asm_file_name)).unwrap();
            let mut source = Vec::new();
            file.read_to_end(&mut source).unwrap();
            let program = assemble(std::str::from_utf8(source.as_slice()).unwrap()).unwrap();
            Executable::<UserError, TestInstructionMeter>::from_text_bytes(
                &program, verifier, config,
            )
        }
        None => {
            let mut file = File::open(&Path::new(matches.value_of("elf").unwrap())).unwrap();
            let mut elf = Vec::new();
            file.read_to_end(&mut elf).unwrap();
            Executable::<UserError, TestInstructionMeter>::from_elf(&elf, verifier, config)
        }
    };
    let mut executable = match executable {
        Ok(executable) => executable,
        Err(err) => {
            println!("Executable constructor failed: {:?}", err);
            return;
        }
    };

    let (syscalls, _bpf_functions) = executable.get_symbols();
    let mut syscall_registry = SyscallRegistry::default();
    for hash in syscalls.keys() {
        let _ = syscall_registry.register_syscall_by_hash(*hash, MockSyscall::call);
    }
    executable.set_syscall_registry(syscall_registry);
    let analysis_result = AnalysisResult::from_executable(executable.as_ref());

    match matches.value_of("use") {
        Some("disassembler") => {
            for insn in analysis_result.instructions.iter() {
                print_label_at(&analysis_result, insn.ptr);
                println!("    {}", insn.desc);
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
    if matches.is_present("trace") {
        let mut tracer_display = String::new();
        vm.get_tracer()
            .write(&mut tracer_display, vm.get_program())
            .unwrap();
        println!("Trace:\n{}", tracer_display);
    }
    if matches.is_present("profile") {
        let mut destination_counters = HashMap::new();
        let mut source_counters = HashMap::new();
        for destination in analysis_result.destinations.keys() {
            destination_counters.insert(*destination as usize, 0usize);
        }
        for (source, destinations) in &analysis_result.sources {
            if destinations.len() == 2 {
                source_counters.insert(*source as usize, vec![0usize; destinations.len()]);
            }
        }
        let trace = &vm.get_tracer().log;
        for (index, traced_instruction) in trace.iter().enumerate() {
            if let Some(destination_counter) =
                destination_counters.get_mut(&(traced_instruction[11] as usize))
            {
                *destination_counter += 1;
            }
            if let Some(source_counter) =
                source_counters.get_mut(&(traced_instruction[11] as usize))
            {
                let next_traced_instruction = trace[index + 1];
                let destinations = analysis_result
                    .sources
                    .get(&(traced_instruction[11] as usize))
                    .unwrap();
                if let Some(destination_index) = destinations
                    .iter()
                    .position(|&ptr| ptr == next_traced_instruction[11] as usize)
                {
                    source_counter[destination_index] += 1;
                }
            }
        }
        println!("Profile:");
        for insn in analysis_result.instructions.iter() {
            if print_label_at(&analysis_result, insn.ptr) {
                println!(
                    "    # Basic block executed: {}",
                    destination_counters[&insn.ptr]
                );
            }
            println!("    {}", insn.desc);
            if let Some(source_counter) = source_counters.get(&insn.ptr) {
                println!(
                    "    # Branch: {} fall through, {} jump",
                    source_counter[0], source_counter[1]
                );
            }
        }
    }
}
