use clap::{crate_version, App, Arg};
use solana_rbpf::{
    assembler::assemble,
    debugger, ebpf,
    elf::Executable,
    interpreter::Interpreter,
    memory_region::MemoryRegion,
    static_analysis::Analysis,
    verifier::RequisiteVerifier,
    vm::{Config, DynamicAnalysis, EbpfVm, SyscallRegistry, TestContextObject, VerifiedExecutable},
};
use std::{fs::File, io::Read, path::Path};

fn main() {
    let matches = App::new("Solana RBPF CLI")
        .version(crate_version!())
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
                .possible_values(&["cfg", "debugger", "disassembler", "interpreter", "jit"])
                .required(true),
        )
        .arg(
            Arg::new("instruction limit")
                .about("Limit the number of instructions to execute")
                .short('l')
                .long("lim")
                .takes_value(true)
                .value_name("COUNT")
                .default_value(&i64::MAX.to_string()),
        )
        .arg(
            Arg::new("trace")
                .about("Display trace using tracing instrumentation")
                .short('t')
                .long("trace"),
        )
        .arg(
            Arg::new("port")
                .about("Port to use for the connection with a remote debugger")
                .long("port")
                .takes_value(true)
                .value_name("PORT")
                .default_value("9001"),
        )
        .arg(
            Arg::new("profile")
                .about("Display profile using tracing instrumentation")
                .short('p')
                .long("prof"),
        )
        .get_matches();

    let config = Config {
        enable_instruction_tracing: matches.is_present("trace") || matches.is_present("profile"),
        enable_symbol_and_section_labels: true,
        ..Config::default()
    };
    let syscall_registry = SyscallRegistry::default();
    let executable = match matches.value_of("assembler") {
        Some(asm_file_name) => {
            let mut file = File::open(Path::new(asm_file_name)).unwrap();
            let mut source = Vec::new();
            file.read_to_end(&mut source).unwrap();
            assemble::<TestContextObject>(
                std::str::from_utf8(source.as_slice()).unwrap(),
                config,
                syscall_registry,
            )
        }
        None => {
            let mut file = File::open(Path::new(matches.value_of("elf").unwrap())).unwrap();
            let mut elf = Vec::new();
            file.read_to_end(&mut elf).unwrap();
            Executable::<TestContextObject>::from_elf(&elf, config, syscall_registry)
                .map_err(|err| format!("Executable constructor failed: {:?}", err))
        }
    }
    .unwrap();

    let mut verified_executable =
        VerifiedExecutable::<RequisiteVerifier, TestContextObject>::from_executable(executable)
            .unwrap();

    let mut mem = match matches.value_of("input").unwrap().parse::<usize>() {
        Ok(allocate) => vec![0u8; allocate],
        Err(_) => {
            let mut file = File::open(Path::new(matches.value_of("input").unwrap())).unwrap();
            let mut memory = Vec::new();
            file.read_to_end(&mut memory).unwrap();
            memory
        }
    };
    let mut heap = vec![
        0_u8;
        matches
            .value_of("memory")
            .unwrap()
            .parse::<usize>()
            .unwrap()
    ];
    if matches.value_of("use") == Some("jit") {
        verified_executable.jit_compile().unwrap();
    }
    let mem_region = MemoryRegion::new_writable(&mut mem, ebpf::MM_INPUT_START);
    let mut context_object = TestContextObject::new(
        matches
            .value_of("instruction limit")
            .unwrap()
            .parse::<u64>()
            .unwrap(),
    );
    let mut vm = EbpfVm::new(
        &verified_executable,
        &mut context_object,
        &mut heap,
        vec![mem_region],
    )
    .unwrap();

    let analysis = if matches.value_of("use") == Some("cfg")
        || matches.value_of("use") == Some("disassembler")
        || matches.is_present("trace")
        || matches.is_present("profile")
    {
        Some(Analysis::from_executable(verified_executable.get_executable()).unwrap())
    } else {
        None
    };
    match matches.value_of("use") {
        Some("cfg") => {
            let mut file = File::create("cfg.dot").unwrap();
            analysis
                .as_ref()
                .unwrap()
                .visualize_graphically(&mut file, None)
                .unwrap();
            return;
        }
        Some("disassembler") => {
            let stdout = std::io::stdout();
            analysis
                .as_ref()
                .unwrap()
                .disassemble(&mut stdout.lock())
                .unwrap();
            return;
        }
        _ => {}
    }

    let (instruction_count, result) = if matches.value_of("use").unwrap() == "debugger" {
        let mut interpreter = Interpreter::new(&mut vm).unwrap();
        let port = matches.value_of("port").unwrap().parse::<u16>().unwrap();
        debugger::execute(&mut interpreter, port)
    } else {
        vm.execute_program(matches.value_of("use").unwrap() == "interpreter")
    };
    println!("Result: {:?}", result);
    println!("Instruction Count: {}", instruction_count);
    if matches.is_present("trace") {
        println!("Trace:\n");
        let stdout = std::io::stdout();
        vm.env
            .context_object_pointer
            .write_trace_log(&mut stdout.lock(), analysis.as_ref().unwrap())
            .unwrap();
    }
    if matches.is_present("profile") {
        let dynamic_analysis = DynamicAnalysis::new(
            &vm.env.context_object_pointer.trace_log,
            analysis.as_ref().unwrap(),
        );
        let mut file = File::create("profile.dot").unwrap();
        analysis
            .as_ref()
            .unwrap()
            .visualize_graphically(&mut file, Some(&dynamic_analysis))
            .unwrap();
    }
}
