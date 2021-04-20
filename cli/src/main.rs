use clap::{App, Arg};
use rustc_demangle::demangle;
use solana_rbpf::{
    assembler::assemble,
    ebpf,
    error::UserDefinedError,
    memory_region::{MemoryMapping, MemoryRegion},
    static_analysis::Analysis,
    user_error::UserError,
    verifier::check,
    vm::{Config, EbpfVm, Executable, InstructionMeter, SyscallObject, SyscallRegistry},
};
use std::{collections::HashMap, fs::File, io::Read, path::Path};
use test_utils::{Result, TestInstructionMeter};

fn annotate_cfg_nodes_with_labels<E: UserDefinedError, I: InstructionMeter>(
    analysis: &mut Analysis,
    executable: &dyn Executable<E, I>,
) -> HashMap<usize, String> {
    let labels = analysis
        .cfg_nodes
        .keys()
        .map(|pc| {
            (
                *pc,
                if let Some((name, _length)) = analysis.functions.get(&pc) {
                    demangle(&name).to_string()
                } else {
                    format!("lbb_{}", pc)
                },
            )
        })
        .collect::<HashMap<usize, String>>();
    for insn in analysis.instructions.iter_mut() {
        match insn.opc {
            ebpf::CALL_IMM => {
                insn.desc = if let Some(syscall_name) = analysis.syscalls.get(&(insn.imm as u32)) {
                    format!("syscall {}", syscall_name)
                } else if let Some(target_pc) = executable.lookup_bpf_function(insn.imm as u32) {
                    format!("call {}", labels.get(target_pc).unwrap())
                } else {
                    format!("call {:x} # unresolved relocation", insn.imm)
                };
            }
            ebpf::JA => {
                let target_pc = (insn.ptr as isize + insn.off as isize + 1) as usize;
                insn.desc = format!("{} {}", insn.name, labels.get(&target_pc).unwrap());
            }
            ebpf::JEQ_IMM
            | ebpf::JGT_IMM
            | ebpf::JGE_IMM
            | ebpf::JLT_IMM
            | ebpf::JLE_IMM
            | ebpf::JSET_IMM
            | ebpf::JNE_IMM
            | ebpf::JSGT_IMM
            | ebpf::JSGE_IMM
            | ebpf::JSLT_IMM
            | ebpf::JSLE_IMM => {
                let target_pc = (insn.ptr as isize + insn.off as isize + 1) as usize;
                insn.desc = format!(
                    "{} r{}, {:#x}, {}",
                    insn.name,
                    insn.dst,
                    insn.imm,
                    labels.get(&target_pc).unwrap()
                );
            }
            ebpf::JEQ_REG
            | ebpf::JGT_REG
            | ebpf::JGE_REG
            | ebpf::JLT_REG
            | ebpf::JLE_REG
            | ebpf::JSET_REG
            | ebpf::JNE_REG
            | ebpf::JSGT_REG
            | ebpf::JSGE_REG
            | ebpf::JSLT_REG
            | ebpf::JSLE_REG => {
                let target_pc = (insn.ptr as isize + insn.off as isize + 1) as usize;
                insn.desc = format!(
                    "{} r{}, r{}, {}",
                    insn.name,
                    insn.dst,
                    insn.src,
                    labels.get(&target_pc).unwrap()
                );
            }
            _ => {}
        }
    }
    labels
}

fn print_label_at(labels: &HashMap<usize, String>, analysis: &Analysis, pc: usize) -> bool {
    if let Some(name) = labels.get(&pc) {
        if analysis.functions.contains_key(&pc) {
            println!();
        }
        println!("{}:", name);
        true
    } else {
        false
    }
}

struct MockSyscall {
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

    let mut analysis = Analysis::from_executable(executable.as_ref());
    let labels = annotate_cfg_nodes_with_labels(&mut analysis, executable.as_ref());
    let mut syscall_registry = SyscallRegistry::default();
    for hash in analysis.syscalls.keys() {
        let _ = syscall_registry.register_syscall_by_hash(*hash, MockSyscall::call);
    }
    executable.set_syscall_registry(syscall_registry);

    match matches.value_of("use") {
        Some("disassembler") => {
            for insn in analysis.instructions.iter() {
                print_label_at(&labels, &analysis, insn.ptr);
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
    for (hash, name) in &analysis.syscalls {
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
        let mut cfg_node_counters = HashMap::new();
        let mut cfg_edge_counters = HashMap::new();
        for (cfg_node_start, cfg_node) in analysis.cfg_nodes.iter() {
            cfg_node_counters.insert(*cfg_node_start, 0usize);
            if cfg_node.destinations.len() == 2 {
                cfg_edge_counters.insert(
                    analysis.instructions[cfg_node.instructions.end].ptr,
                    (*cfg_node_start, vec![0usize; cfg_node.destinations.len()]),
                );
            }
        }
        let trace = &vm.get_tracer().log;
        for (index, traced_instruction) in trace.iter().enumerate() {
            if let Some(cfg_node_counter) =
                cfg_node_counters.get_mut(&(traced_instruction[11] as usize))
            {
                *cfg_node_counter += 1;
            }
            if let Some(edge_counter) =
                cfg_edge_counters.get_mut(&(traced_instruction[11] as usize))
            {
                let next_traced_instruction = trace[index + 1];
                let destinations = &analysis
                    .cfg_nodes
                    .get(&edge_counter.0)
                    .unwrap()
                    .destinations;
                if let Some(destination_index) = destinations
                    .iter()
                    .position(|&ptr| ptr == next_traced_instruction[11] as usize)
                {
                    edge_counter.1[destination_index] += 1;
                }
            }
        }
        println!("Profile:");
        for insn in analysis.instructions.iter() {
            if print_label_at(&labels, &analysis, insn.ptr) {
                println!(
                    "    # Basic block executed: {}",
                    cfg_node_counters[&insn.ptr]
                );
            }
            println!("    {}", insn.desc);
            if let Some(edge_counter) = cfg_edge_counters.get(&insn.ptr) {
                println!(
                    "    # Branch: {} fall through, {} jump",
                    edge_counter.1[0], edge_counter.1[1]
                );
            }
        }
    }
}
