use clap::{App, Arg};
use rustc_demangle::demangle;
use solana_rbpf::{
    assembler::assemble,
    disassembler::{to_insn_vec, HlInsn},
    ebpf,
    memory_region::{MemoryMapping, MemoryRegion},
    user_error::UserError,
    verifier::check,
    vm::{Config, EbpfVm, Executable, SyscallObject, SyscallRegistry},
};
use std::{
    collections::{BTreeMap, HashMap},
    fs::File,
    io::Read,
    path::Path,
};
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

#[derive(PartialEq)]
enum LabelKind {
    Function,
    BasicBlock,
}

struct Label {
    name: String,
    length: usize,
    kind: LabelKind,
    sources: Vec<usize>,
}

macro_rules! resolve_label {
    ($labels:expr, $target_pc:expr) => {
        if let Some(label) = $labels.get(&$target_pc) {
            label.name.clone()
        } else {
            format!("{} # unresolved symbol", $target_pc)
        }
    };
}

struct AnalysisResult {
    instructions: Vec<HlInsn>,
    destinations: BTreeMap<usize, Label>,
    sources: BTreeMap<usize, Vec<usize>>,
}

impl AnalysisResult {
    fn analyze_executable(executable: &dyn Executable<UserError, TestInstructionMeter>) -> Self {
        let (_program_vm_addr, program) = executable.get_text_bytes().unwrap();
        let mut result = Self {
            instructions: to_insn_vec(program),
            destinations: BTreeMap::new(),
            sources: BTreeMap::new(),
        };
        let (syscalls, bpf_functions) = executable.get_symbols();
        for (pc, bpf_function) in bpf_functions {
            result.destinations.insert(
                pc,
                Label {
                    name: demangle(&bpf_function.0).to_string(),
                    length: 0, // bpf_function.1,
                    kind: LabelKind::Function,
                    sources: Vec::new(),
                },
            );
        }
        let entrypoint_pc = executable.get_entrypoint_instruction_offset().unwrap();
        result.destinations.entry(entrypoint_pc).or_insert(Label {
            name: "entrypoint".to_string(),
            length: 0,
            kind: LabelKind::Function,
            sources: Vec::new(),
        });
        for insn in result.instructions.iter() {
            match insn.opc {
                ebpf::CALL_IMM => {
                    if let Some(target_pc) = executable.lookup_bpf_function(insn.imm as u32) {
                        // result.sources.insert(insn.ptr, vec![*target_pc]);
                        if !result.destinations.contains_key(target_pc) {
                            result.destinations.insert(
                                *target_pc,
                                Label {
                                    name: format!("function_{}", target_pc),
                                    length: 0,
                                    kind: LabelKind::Function,
                                    sources: Vec::new(),
                                },
                            );
                        }
                    }
                }
                ebpf::CALL_REG | ebpf::EXIT => {
                    result.sources.insert(insn.ptr, vec![]);
                }
                _ => {}
            }
        }
        for insn in result.instructions.iter() {
            let target_pc = (insn.ptr as isize + insn.off as isize + 1) as usize;
            match insn.opc {
                ebpf::JA => {
                    result.sources.insert(insn.ptr, vec![target_pc]);
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
                | ebpf::JSLE_IMM
                | ebpf::JEQ_REG
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
                    result
                        .sources
                        .insert(insn.ptr, vec![insn.ptr + 1, target_pc]);
                    result.destinations.insert(
                        insn.ptr + 1,
                        Label {
                            name: format!("lbb_{}", insn.ptr + 1),
                            length: 0,
                            kind: LabelKind::BasicBlock,
                            sources: Vec::new(),
                        },
                    );
                }
                _ => continue,
            }
            result.destinations.entry(target_pc).or_insert(Label {
                name: format!("lbb_{}", target_pc),
                length: 0,
                kind: LabelKind::BasicBlock,
                sources: Vec::new(),
            });
        }
        for (source, destinations) in &result.sources {
            for destination in destinations {
                result
                    .destinations
                    .get_mut(destination)
                    .unwrap()
                    .sources
                    .push(*source);
            }
        }
        let mut destination_iter = result.destinations.iter_mut().peekable();
        let mut source_iter = result.sources.iter().peekable();
        while let Some((begin, label)) = destination_iter.next() {
            match result
                .instructions
                .binary_search_by(|insn| insn.ptr.cmp(begin))
            {
                Ok(_) => {}
                Err(_index) => {
                    println!("WARNING: Invalid symbol {:?}, pc={}", label.name, begin);
                    label.length = 0;
                    continue;
                }
            }
            if label.length > 0 {
                continue;
            }
            while let Some(next_source) = source_iter.peek() {
                if *next_source.0 < *begin {
                    source_iter.next();
                } else {
                    break;
                }
            }
            let end = if let Some(next_destination) = destination_iter.peek() {
                if let Some(next_source) = source_iter.peek() {
                    let next_source = *next_source.0 + 1;
                    if next_source < *next_destination.0 {
                        source_iter.next();
                        next_source
                    } else {
                        *next_destination.0
                    }
                } else {
                    *next_destination.0
                }
            } else if let Some(next_source) = source_iter.next() {
                *next_source.0 + 1
            } else {
                result.instructions.last().unwrap().ptr
            };
            label.length = end - begin;
        }
        for insn in result.instructions.iter_mut() {
            match insn.opc {
                ebpf::CALL_IMM => {
                    insn.desc = if let Some(syscall_name) = syscalls.get(&(insn.imm as u32)) {
                        format!("syscall {}", syscall_name)
                    } else if let Some(target_pc) = executable.lookup_bpf_function(insn.imm as u32)
                    {
                        format!("call {}", resolve_label!(result.destinations, target_pc))
                    } else {
                        format!("call {:x} # unresolved relocation", insn.imm)
                    };
                }
                ebpf::JA => {
                    let target_pc = (insn.ptr as isize + insn.off as isize + 1) as usize;
                    insn.desc = format!(
                        "{} {}",
                        insn.name,
                        resolve_label!(result.destinations, target_pc)
                    );
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
                        resolve_label!(result.destinations, target_pc)
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
                        resolve_label!(result.destinations, target_pc)
                    );
                }
                _ => {}
            }
        }
        result
    }

    pub fn print_label_at(&self, ptr: usize) -> bool {
        if let Some(label) = self.destinations.get(&ptr) {
            if label.kind == LabelKind::Function {
                println!();
            }
            println!("{}:", label.name);
            true
        } else {
            false
        }
    }
}

fn main() {
    let matches = App::new("Solana RBPF CLI")
        .version("0.2.7")
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
    let analysis_result = AnalysisResult::analyze_executable(executable.as_ref());

    match matches.value_of("use") {
        Some("disassembler") => {
            for insn in analysis_result.instructions.iter() {
                analysis_result.print_label_at(insn.ptr);
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
            if analysis_result.print_label_at(insn.ptr) {
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
