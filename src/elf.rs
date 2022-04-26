//! This module relocates a BPF ELF

// Note: Typically ELF shared objects are loaded using the program headers and
// not the section headers.  Since we are leveraging the elfkit crate its much
// easier to use the section headers.  There are cases (reduced size, obfuscation)
// where the section headers may be removed from the ELF.  If that happens then
// this loader will need to be re-written to use the program headers instead.

extern crate goblin;
extern crate scroll;

use crate::{
    aligned_memory::AlignedMemory,
    ebpf::{self, EF_SBF_V2},
    error::{EbpfError, UserDefinedError},
    jit::JitProgram,
    memory_region::MemoryRegion,
    vm::{Config, InstructionMeter, SyscallRegistry},
};
use byteorder::{ByteOrder, LittleEndian};
use goblin::{
    elf::{header::*, reloc::*, section_header::*, Elf},
    error::Error as GoblinError,
};
use std::{
    collections::{btree_map::Entry, BTreeMap},
    fmt::Debug,
    mem,
    ops::Range,
    pin::Pin,
    str,
};

/// Error definitions
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ElfError {
    /// Failed to parse ELF file
    #[error("Failed to parse ELF file: {0}")]
    FailedToParse(String),
    /// Entrypoint out of bounds
    #[error("Entrypoint out of bounds")]
    EntrypointOutOfBounds,
    /// Invaid entrypoint
    #[error("Invaid entrypoint")]
    InvalidEntrypoint,
    /// Failed to get section
    #[error("Failed to get section {0}")]
    FailedToGetSection(String),
    /// Unresolved symbol
    #[error("Unresolved symbol ({0}) at instruction #{1:?} (ELF file offset {2:#x})")]
    UnresolvedSymbol(String, usize, usize),
    /// Section no found
    #[error("Section not found: {0}")]
    SectionNotFound(String),
    /// Relative jump out of bounds
    #[error("Relative jump out of bounds at instruction #{0}")]
    RelativeJumpOutOfBounds(usize),
    /// Symbol hash collision
    #[error("Symbol hash collision {0:#x}")]
    SymbolHashCollision(u32),
    /// Incompatible ELF: wrong endianess
    #[error("Incompatible ELF: wrong endianess")]
    WrongEndianess,
    /// Incompatible ELF: wrong ABI
    #[error("Incompatible ELF: wrong ABI")]
    WrongAbi,
    /// Incompatible ELF: wrong mchine
    #[error("Incompatible ELF: wrong machine")]
    WrongMachine,
    /// Incompatible ELF: wrong class
    #[error("Incompatible ELF: wrong class")]
    WrongClass,
    /// Not one text section
    #[error("Multiple or no text sections, consider removing llc option: -function-sections")]
    NotOneTextSection,
    /// Read-write data not supported
    #[error("Found .bss section in ELF, read-write data not supported")]
    BssNotSupported,
    /// Read-write data not supported
    #[error("Found writable section ({0}) in ELF, read-write data not supported")]
    WritableSectionNotSupported(String),
    /// Relocation failed, no loadable section contains virtual address
    #[error("Relocation failed, no loadable section contains virtual address {0:#x}")]
    AddressOutsideLoadableSection(u64),
    /// Relocation failed, invalid referenced virtual address
    #[error("Relocation failed, invalid referenced virtual address {0:#x}")]
    InvalidVirtualAddress(u64),
    /// Relocation failed, unknown type
    #[error("Relocation failed, unknown type {0:?}")]
    UnknownRelocation(u32),
    /// Failed to read relocation info
    #[error("Failed to read relocation info")]
    FailedToReadRelocationInfo,
    /// Incompatible ELF: wrong type
    #[error("Incompatible ELF: wrong type")]
    WrongType,
    /// Unknown symbol
    #[error("Unknown symbol with index {0}")]
    UnknownSymbol(usize),
    /// Offset or value is out of bounds
    #[error("Offset or value is out of bounds")]
    ValueOutOfBounds,
    /// Dynamic stack frames detected but not enabled
    #[error("Dynamic stack frames detected but not enabled")]
    DynamicStackFramesDisabled,
}
impl From<GoblinError> for ElfError {
    fn from(error: GoblinError) -> Self {
        match error {
            GoblinError::Malformed(string) => Self::FailedToParse(format!("malformed: {}", string)),
            GoblinError::BadMagic(magic) => Self::FailedToParse(format!("bad magic: {:#x}", magic)),
            GoblinError::Scroll(error) => Self::FailedToParse(format!("read-write: {}", error)),
            GoblinError::IO(error) => Self::FailedToParse(format!("io: {}", error)),
            GoblinError::BufferTooShort(n, error) => {
                Self::FailedToParse(format!("buffer too short {} {}", n, error))
            }
            _ => Self::FailedToParse("cause unkown".to_string()),
        }
    }
}
impl<E: UserDefinedError> From<GoblinError> for EbpfError<E> {
    fn from(error: GoblinError) -> Self {
        ElfError::from(error).into()
    }
}

/// Generates the hash by which a symbol can be called
pub fn hash_bpf_function(pc: usize, name: &str) -> u32 {
    if name == "entrypoint" {
        ebpf::hash_symbol_name(b"entrypoint")
    } else {
        let mut key = [0u8; mem::size_of::<u64>()];
        LittleEndian::write_u64(&mut key, pc as u64);
        ebpf::hash_symbol_name(&key)
    }
}

/// Register a symbol or throw ElfError::SymbolHashCollision
pub fn register_bpf_function<T: AsRef<str> + ToString>(
    config: &Config,
    bpf_functions: &mut BTreeMap<u32, (usize, String)>,
    syscall_registry: &SyscallRegistry,
    pc: usize,
    name: T,
) -> Result<u32, ElfError> {
    let hash = hash_bpf_function(pc, name.as_ref());
    if config.syscall_bpf_function_hash_collision && syscall_registry.lookup_syscall(hash).is_some()
    {
        return Err(ElfError::SymbolHashCollision(hash));
    }
    match bpf_functions.entry(hash) {
        Entry::Vacant(entry) => {
            entry.insert((
                pc,
                if config.enable_symbol_and_section_labels {
                    name.to_string()
                } else {
                    String::default()
                },
            ));
        }
        Entry::Occupied(entry) => {
            if entry.get().0 != pc {
                return Err(ElfError::SymbolHashCollision(hash));
            }
        }
    }

    Ok(hash)
}

// For more information on the BPF instruction set:
// https://github.com/iovisor/bpf-docs/blob/master/eBPF.md

// msb                                                        lsb
// +------------------------+----------------+----+----+--------+
// |immediate               |offset          |src |dst |opcode  |
// +------------------------+----------------+----+----+--------+

// From least significant to most significant bit:
//   8 bit opcode
//   4 bit destination register (dst)
//   4 bit source register (src)
//   16 bit offset
//   32 bit immediate (imm)

/// Byte offset of the immediate field in the instruction
const BYTE_OFFSET_IMMEDIATE: usize = 4;
/// Byte length of the immediate field
const BYTE_LENGTH_IMMEDIATE: usize = 4;

/// BPF relocation types.
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Copy, Clone)]
enum BpfRelocationType {
    /// No relocation, placeholder
    R_Bpf_None = 0,
    /// R_BPF_64_64 relocation type is used for ld_imm64 instruction.
    /// The actual to-be-relocated data (0 or section offset) is
    /// stored at r_offset + 4 and the read/write data bitsize is 32
    /// (4 bytes). The relocation can be resolved with the symbol
    /// value plus implicit addend.
    R_Bpf_64_64 = 1,
    /// 64 bit relocation of a ldxdw instruction.  The ldxdw
    /// instruction occupies two instruction slots. The 64-bit address
    /// to load from is split into the 32-bit imm field of each
    /// slot. The first slot's pre-relocation imm field contains the
    /// virtual address (typically same as the file offset) of the
    /// location to load. Relocation involves calculating the
    /// post-load 64-bit physical address referenced by the imm field
    /// and writing that physical address back into the imm fields of
    /// the ldxdw instruction.
    R_Bpf_64_Relative = 8,
    /// Relocation of a call instruction.  The existing imm field
    /// contains either an offset of the instruction to jump to (think
    /// local function call) or a special value of "-1".  If -1 the
    /// symbol must be looked up in the symbol table.  The relocation
    /// entry contains the symbol number to call.  In order to support
    /// both local jumps and calling external symbols a 32-bit hash is
    /// computed and stored in the the call instruction's 32-bit imm
    /// field.  The hash is used later to look up the 64-bit address
    /// to jump to.  In the case of a local jump the hash is
    /// calculated using the current program counter and in the case
    /// of a symbol the hash is calculated using the name of the
    /// symbol.
    R_Bpf_64_32 = 10,
}
impl BpfRelocationType {
    fn from_x86_relocation_type(from: u32) -> Option<BpfRelocationType> {
        match from {
            R_X86_64_NONE => Some(BpfRelocationType::R_Bpf_None),
            R_X86_64_64 => Some(BpfRelocationType::R_Bpf_64_64),
            R_X86_64_RELATIVE => Some(BpfRelocationType::R_Bpf_64_Relative),
            R_X86_64_32 => Some(BpfRelocationType::R_Bpf_64_32),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq)]
struct SectionInfo {
    name: String,
    vaddr: u64,
    offset_range: Range<usize>,
}
impl SectionInfo {
    fn mem_size(&self) -> usize {
        mem::size_of::<Self>().saturating_add(self.name.capacity())
    }
}

#[derive(Debug, PartialEq)]
pub(crate) enum Section {
    /// Owned section data.
    Owned(usize, Vec<u8>),
    /// Borrowed section data.
    ///
    /// The borrowed section data can be retrieved indexing the input ELF buffer
    /// with the given range.
    Borrowed(Range<usize>),
}

/// Elf loader/relocator
#[derive(Debug, PartialEq)]
pub struct Executable<E: UserDefinedError, I: InstructionMeter> {
    /// Configuration settings
    config: Config,
    /// Loaded and executable elf
    elf_bytes: AlignedMemory,
    /// Read-only section
    ro_section: Section,
    /// Text section info
    text_section_info: SectionInfo,
    /// Call resolution map (hash, pc, name)
    bpf_functions: BTreeMap<u32, (usize, String)>,
    /// Syscall symbol map (hash, name)
    syscall_symbols: BTreeMap<u32, String>,
    /// Syscall resolution map
    syscall_registry: SyscallRegistry,
    /// Compiled program and argument
    compiled_program: Option<JitProgram<E, I>>,
}

impl<E: UserDefinedError, I: InstructionMeter> Executable<E, I> {
    /// Get the configuration settings
    pub fn get_config(&self) -> &Config {
        &self.config
    }

    /// Get the .text section virtual address and bytes
    pub fn get_text_bytes(&self) -> (u64, &[u8]) {
        let (ro_offset, ro_section) = match &self.ro_section {
            Section::Owned(offset, data) => (*offset, data.as_slice()),
            Section::Borrowed(range) => (range.start, &self.elf_bytes.as_slice()[range.clone()]),
        };

        let offset = self
            .text_section_info
            .vaddr
            .saturating_sub(ebpf::MM_PROGRAM_START)
            .saturating_sub(ro_offset as u64) as usize;
        (
            self.text_section_info.vaddr,
            &ro_section[offset..offset.saturating_add(self.text_section_info.offset_range.len())],
        )
    }

    /// Get the concatenated read-only sections (including the text section)
    pub fn get_ro_section(&self) -> &[u8] {
        match &self.ro_section {
            Section::Owned(_offset, data) => data.as_slice(),
            Section::Borrowed(range) => &self.elf_bytes.as_slice()[range.clone()],
        }
    }

    /// Get a memory region that can be used to access the merged readonly section
    pub fn get_ro_region(&self) -> MemoryRegion {
        get_ro_region(&self.ro_section, self.elf_bytes.as_slice())
    }

    /// Get the entry point offset into the text section
    pub fn get_entrypoint_instruction_offset(&self) -> Result<usize, EbpfError<E>> {
        self.bpf_functions
            .get(&ebpf::hash_symbol_name(b"entrypoint"))
            .map(|(pc, _name)| *pc)
            .ok_or(EbpfError::ElfError(ElfError::InvalidEntrypoint))
    }

    /// Get a symbol's instruction offset
    pub fn lookup_bpf_function(&self, hash: u32) -> Option<usize> {
        self.bpf_functions.get(&hash).map(|(pc, _name)| *pc)
    }

    /// Get the syscall registry
    pub fn get_syscall_registry(&self) -> &SyscallRegistry {
        &self.syscall_registry
    }

    /// Get the JIT compiled program
    pub fn get_compiled_program(&self) -> Option<&JitProgram<E, I>> {
        self.compiled_program.as_ref()
    }

    /// JIT compile the executable
    pub fn jit_compile(executable: &mut Pin<Box<Self>>) -> Result<(), EbpfError<E>> {
        // TODO: Turn back to `executable: &mut self` once Self::report_unresolved_symbol() is gone
        executable.compiled_program = Some(JitProgram::<E, I>::new(executable)?);
        Ok(())
    }

    /// Report information on a symbol that failed to be resolved
    pub fn report_unresolved_symbol(&self, insn_offset: usize) -> Result<u64, EbpfError<E>> {
        let file_offset = insn_offset
            .saturating_mul(ebpf::INSN_SIZE)
            .saturating_add(self.text_section_info.offset_range.start as usize);

        let mut name = "Unknown";
        if let Ok(elf) = Elf::parse(self.elf_bytes.as_slice()) {
            for relocation in &elf.dynrels {
                match BpfRelocationType::from_x86_relocation_type(relocation.r_type) {
                    Some(BpfRelocationType::R_Bpf_64_32) | Some(BpfRelocationType::R_Bpf_64_64) => {
                        if relocation.r_offset as usize == file_offset {
                            let sym = elf
                                .dynsyms
                                .get(relocation.r_sym)
                                .ok_or(ElfError::UnknownSymbol(relocation.r_sym))?;
                            name = elf
                                .dynstrtab
                                .get_at(sym.st_name)
                                .ok_or(ElfError::UnknownSymbol(sym.st_name))?;
                        }
                    }
                    _ => (),
                }
            }
        }
        Err(ElfError::UnresolvedSymbol(
            name.to_string(),
            file_offset
                .checked_div(ebpf::INSN_SIZE)
                .and_then(|offset| offset.checked_add(ebpf::ELF_INSN_DUMP_OFFSET))
                .unwrap_or(ebpf::ELF_INSN_DUMP_OFFSET),
            file_offset,
        )
        .into())
    }

    /// Get syscalls and BPF functions (if debug symbols are not stripped)
    pub fn get_function_symbols(&self) -> BTreeMap<usize, (u32, String)> {
        let mut bpf_functions = BTreeMap::new();
        for (hash, (pc, name)) in self.bpf_functions.iter() {
            bpf_functions.insert(*pc, (*hash, name.clone()));
        }
        bpf_functions
    }

    /// Get syscalls symbols
    pub fn get_syscall_symbols(&self) -> &BTreeMap<u32, String> {
        &self.syscall_symbols
    }

    /// Create from raw text section bytes (list of instructions)
    pub fn new_from_text_bytes(
        config: Config,
        text_bytes: &[u8],
        syscall_registry: SyscallRegistry,
        bpf_functions: BTreeMap<u32, (usize, String)>,
    ) -> Self {
        let elf_bytes = AlignedMemory::new_with_data(text_bytes, ebpf::HOST_ALIGN);
        let enable_symbol_and_section_labels = config.enable_symbol_and_section_labels;
        Self {
            config,
            elf_bytes,
            ro_section: Section::Borrowed(0..text_bytes.len()),
            text_section_info: SectionInfo {
                name: if enable_symbol_and_section_labels {
                    ".text".to_string()
                } else {
                    String::default()
                },
                vaddr: ebpf::MM_PROGRAM_START,
                offset_range: 0..text_bytes.len(),
            },
            bpf_functions,
            syscall_symbols: BTreeMap::default(),
            syscall_registry,
            compiled_program: None,
        }
    }

    /// Fully loads an ELF, including validation and relocation
    pub fn load(
        mut config: Config,
        bytes: &[u8],
        syscall_registry: SyscallRegistry,
    ) -> Result<Self, ElfError> {
        let elf = Elf::parse(bytes)?;
        let mut elf_bytes = AlignedMemory::new_with_data(bytes, ebpf::HOST_ALIGN);

        Self::validate(&mut config, &elf, elf_bytes.as_slice())?;

        // calculate the text section info
        let text_section = Self::get_section(&elf, ".text")?;
        let text_section_info = SectionInfo {
            name: if config.enable_symbol_and_section_labels {
                elf.shdr_strtab
                    .get_at(text_section.sh_name)
                    .unwrap()
                    .to_string()
            } else {
                String::default()
            },
            vaddr: text_section.sh_addr.saturating_add(ebpf::MM_PROGRAM_START),
            offset_range: text_section.file_range().unwrap_or_default(),
        };
        if (config.reject_broken_elfs && text_section.sh_addr != text_section.sh_offset)
            || text_section_info.vaddr > ebpf::MM_STACK_START
        {
            return Err(ElfError::ValueOutOfBounds);
        }

        // relocate symbols
        let mut bpf_functions = BTreeMap::default();
        let mut syscall_symbols = BTreeMap::default();
        Self::relocate(
            &config,
            &mut bpf_functions,
            &mut syscall_symbols,
            &syscall_registry,
            &elf,
            elf_bytes.as_slice_mut(),
        )?;

        // calculate entrypoint offset into the text section
        let offset = elf.header.e_entry.saturating_sub(text_section.sh_addr);
        if offset.checked_rem(ebpf::INSN_SIZE as u64) != Some(0) {
            return Err(ElfError::InvalidEntrypoint);
        }
        if let Some(entrypoint) = (offset as usize).checked_div(ebpf::INSN_SIZE) {
            bpf_functions.remove(&ebpf::hash_symbol_name(b"entrypoint"));
            register_bpf_function(
                &config,
                &mut bpf_functions,
                &syscall_registry,
                entrypoint,
                "entrypoint",
            )?;
        } else {
            return Err(ElfError::InvalidEntrypoint);
        }

        let ro_section = Self::parse_ro_sections(
            &config,
            elf.section_headers
                .iter()
                .map(|s| (elf.shdr_strtab.get_at(s.sh_name), s)),
            elf_bytes.as_slice(),
        )?;

        Ok(Self {
            config,
            elf_bytes,
            ro_section,
            text_section_info,
            bpf_functions,
            syscall_symbols,
            syscall_registry,
            compiled_program: None,
        })
    }

    /// Calculate the total memory size of the executable
    #[rustfmt::skip]
    pub fn mem_size(&self) -> usize {
        let total = mem::size_of::<Self>()
            // elf bytres
            .saturating_add(self.elf_bytes.mem_size())
            // ro section
            .saturating_add(match &self.ro_section {
                Section::Owned(_, data) => data.capacity(),
                Section::Borrowed(_) => 0,
            })
            // text section info
            .saturating_add(self.text_section_info.mem_size())
            // bpf functions
            .saturating_add(mem::size_of_val(&self.bpf_functions))
            .saturating_add(self.bpf_functions
            .iter()
            .fold(0, |state: usize, (_, (val, name))| state
                .saturating_add(mem::size_of_val(&val)
                .saturating_add(mem::size_of_val(&name)
                .saturating_add(name.capacity())))))
            // syscall symbols
            .saturating_add(mem::size_of_val(&self.syscall_symbols))
            .saturating_add(self.syscall_symbols
            .iter()
            .fold(0, |state: usize, (val, name)| state
                .saturating_add(mem::size_of_val(&val)
                .saturating_add(mem::size_of_val(&name)
                .saturating_add(name.capacity())))))
            // syscall registry
            .saturating_add(self.syscall_registry.mem_size())
            // compiled programs
            .saturating_add(self.compiled_program.as_ref().map_or(0, |program| program.mem_size()));

        total as usize
    }

    // Functions exposed for tests

    /// Fix-ups relative calls
    pub fn fixup_relative_calls(
        config: &Config,
        bpf_functions: &mut BTreeMap<u32, (usize, String)>,
        syscall_registry: &SyscallRegistry,
        elf_bytes: &mut [u8],
    ) -> Result<(), ElfError> {
        let instruction_count = elf_bytes
            .len()
            .checked_div(ebpf::INSN_SIZE)
            .ok_or(ElfError::ValueOutOfBounds)?;
        for i in 0..instruction_count {
            let mut insn = ebpf::get_insn(elf_bytes, i);
            if insn.opc == ebpf::CALL_IMM && insn.imm != -1 {
                let target_pc = (i as isize)
                    .saturating_add(1)
                    .saturating_add(insn.imm as isize);
                if target_pc < 0 || target_pc >= instruction_count as isize {
                    return Err(ElfError::RelativeJumpOutOfBounds(
                        i.saturating_add(ebpf::ELF_INSN_DUMP_OFFSET),
                    ));
                }
                let name = if config.enable_symbol_and_section_labels {
                    format!("function_{}", target_pc)
                } else {
                    String::default()
                };

                let hash = register_bpf_function(
                    config,
                    bpf_functions,
                    syscall_registry,
                    target_pc as usize,
                    name,
                )?;
                insn.imm = hash as i64;
                let offset = i.saturating_mul(ebpf::INSN_SIZE);
                let checked_slice = elf_bytes
                    .get_mut(offset..offset.saturating_add(ebpf::INSN_SIZE))
                    .ok_or(ElfError::ValueOutOfBounds)?;
                checked_slice.copy_from_slice(&insn.to_array());
            }
        }
        Ok(())
    }

    /// Validates the ELF
    pub fn validate(config: &mut Config, elf: &Elf, elf_bytes: &[u8]) -> Result<(), ElfError> {
        if elf.header.e_ident[EI_CLASS] != ELFCLASS64 {
            return Err(ElfError::WrongClass);
        }
        if elf.header.e_ident[EI_DATA] != ELFDATA2LSB {
            return Err(ElfError::WrongEndianess);
        }
        if elf.header.e_ident[EI_OSABI] != ELFOSABI_NONE {
            return Err(ElfError::WrongAbi);
        }
        if elf.header.e_machine != EM_BPF {
            return Err(ElfError::WrongMachine);
        }
        if elf.header.e_type != ET_DYN {
            return Err(ElfError::WrongType);
        }

        if elf.header.e_flags == EF_SBF_V2 {
            if !config.dynamic_stack_frames {
                return Err(ElfError::DynamicStackFramesDisabled);
            }
        } else {
            config.dynamic_stack_frames = false;
        }

        let num_text_sections =
            elf.section_headers
                .iter()
                .fold(0, |count: usize, section_header| {
                    if let Some(this_name) = elf.shdr_strtab.get_at(section_header.sh_name) {
                        if this_name == ".text" {
                            return count.saturating_add(1);
                        }
                    }
                    count
                });
        if 1 != num_text_sections {
            return Err(ElfError::NotOneTextSection);
        }

        for section_header in elf.section_headers.iter() {
            if let Some(name) = elf.shdr_strtab.get_at(section_header.sh_name) {
                if name.starts_with(".bss")
                    || (section_header.is_writable()
                        && (name.starts_with(".data") && !name.starts_with(".data.rel")))
                {
                    return Err(ElfError::WritableSectionNotSupported(name.to_owned()));
                } else if name == ".bss" {
                    return Err(ElfError::BssNotSupported);
                }
            }
        }

        for section_header in &elf.section_headers {
            let start = section_header.sh_offset as usize;
            let end = section_header
                .sh_offset
                .checked_add(section_header.sh_size)
                .ok_or(ElfError::ValueOutOfBounds)? as usize;
            let _ = elf_bytes
                .get(start..end)
                .ok_or(ElfError::ValueOutOfBounds)?;
        }
        let text_section = Self::get_section(elf, ".text")?;
        if !text_section
            .vm_range()
            .contains(&(elf.header.e_entry as usize))
        {
            return Err(ElfError::EntrypointOutOfBounds);
        }

        Ok(())
    }

    pub(crate) fn parse_ro_sections<
        'a,
        S: IntoIterator<Item = (Option<&'a str>, &'a SectionHeader)>,
    >(
        config: &Config,
        sections: S,
        elf_bytes: &[u8],
    ) -> Result<Section, ElfError> {
        // the lowest section address
        let mut lowest_addr = usize::MAX;
        // the highest section address
        let mut highest_addr = 0;
        // the aggregated section length, not including gaps between sections
        let mut ro_fill_length = 0usize;
        // whether at least one ro section has non-matching sh_addr and
        // sh_offset
        let mut have_offsets = false;

        // keep track of where ro sections are so we can tell whether they're
        // contiguous
        let mut first_ro_section = 0;
        let mut last_ro_section = 0;
        let mut n_ro_sections = 0usize;

        let mut ro_slices = vec![];
        for (i, (name, section_header)) in sections.into_iter().enumerate() {
            match name {
                Some(name)
                    if name == ".text"
                        || name == ".rodata"
                        || name == ".data.rel.ro"
                        || name == ".eh_frame" => {}
                _ => continue,
            }

            if n_ro_sections == 0 {
                first_ro_section = i;
            }
            last_ro_section = i;
            n_ro_sections = n_ro_sections.saturating_add(1);

            let section_addr = section_header.sh_addr;
            let vaddr = section_addr.saturating_add(ebpf::MM_PROGRAM_START);
            have_offsets = have_offsets || section_addr != section_header.sh_offset;
            if (config.reject_broken_elfs && have_offsets) || vaddr > ebpf::MM_STACK_START {
                return Err(ElfError::ValueOutOfBounds);
            }

            let section_data = elf_bytes
                .get(section_header.file_range().unwrap_or_default())
                .ok_or(ElfError::ValueOutOfBounds)?;

            let section_addr = section_addr as usize;
            lowest_addr = lowest_addr.min(section_addr);
            highest_addr = highest_addr
                .max(section_addr)
                .saturating_add(section_data.len());
            ro_fill_length = ro_fill_length.saturating_add(section_data.len());

            ro_slices.push((section_addr, section_data));
        }

        if highest_addr > elf_bytes.len()
            || (config.reject_broken_elfs
                && lowest_addr.saturating_add(ro_fill_length) > highest_addr)
        {
            return Err(ElfError::ValueOutOfBounds);
        }

        let can_borrow = !have_offsets
            && last_ro_section
                .saturating_add(1)
                .saturating_sub(first_ro_section)
                == n_ro_sections;
        let ro_section = if config.optimize_rodata && can_borrow {
            // Read only sections are grouped together with no intermixed non-ro
            // sections. We can borrow.
            Section::Borrowed(lowest_addr..highest_addr as usize)
        } else {
            // Read only and other non-ro sections are mixed. Zero the non-ro
            // sections and and copy the ro ones at their intended offsets.

            if config.optimize_rodata {
                // The rodata region starts at MM_PROGRAM_START + lowest_addr,
                // [MM_PROGRAM_START, MM_PROGRAM_START + lowest_addr) is not
                // mappable. We only need to allocate highest_addr - lowest_addr
                // bytes.
                highest_addr = highest_addr.saturating_sub(lowest_addr);
            } else {
                // For backwards compatibility, the whole [MM_PROGRAM_START,
                // MM_PROGRAM_START + highest_addr) range is mappable. We need
                // to allocate the whole address range.
                lowest_addr = 0;
            };

            let mut ro_section = vec![0; highest_addr];
            for (mut section_addr, slice) in ro_slices.iter() {
                section_addr = section_addr.saturating_sub(lowest_addr);
                ro_section[section_addr..section_addr.saturating_add(slice.len())]
                    .copy_from_slice(slice);
            }

            Section::Owned(lowest_addr, ro_section)
        };

        Ok(ro_section)
    }

    // Private functions

    /// Get a section by name
    fn get_section(elf: &Elf, name: &str) -> Result<SectionHeader, ElfError> {
        match elf.section_headers.iter().find(|section_header| {
            if let Some(this_name) = elf.shdr_strtab.get_at(section_header.sh_name) {
                return this_name == name;
            }
            false
        }) {
            Some(section) => Ok(section.clone()),
            None => Err(ElfError::SectionNotFound(name.to_string())),
        }
    }

    /// Relocates the ELF in-place
    fn relocate(
        config: &Config,
        bpf_functions: &mut BTreeMap<u32, (usize, String)>,
        syscall_symbols: &mut BTreeMap<u32, String>,
        syscall_registry: &SyscallRegistry,
        elf: &Elf,
        elf_bytes: &mut [u8],
    ) -> Result<(), ElfError> {
        let mut syscall_cache = BTreeMap::new();
        let text_section = Self::get_section(elf, ".text")?;

        // Fixup all program counter relative call instructions
        Self::fixup_relative_calls(
            config,
            bpf_functions,
            syscall_registry,
            elf_bytes
                .get_mut(text_section.file_range().unwrap_or_default())
                .ok_or(ElfError::ValueOutOfBounds)?,
        )?;

        // Fixup all the relocations in the relocation section if exists
        for relocation in &elf.dynrels {
            let r_offset = relocation.r_offset as usize;

            // Offset of the immediate field
            let imm_offset = r_offset.saturating_add(BYTE_OFFSET_IMMEDIATE);
            match BpfRelocationType::from_x86_relocation_type(relocation.r_type) {
                Some(BpfRelocationType::R_Bpf_64_64) => {
                    // Read the instruction's immediate field which contains virtual
                    // address to convert to physical
                    let checked_slice = elf_bytes
                        .get(imm_offset..imm_offset.saturating_add(BYTE_LENGTH_IMMEDIATE))
                        .ok_or(ElfError::ValueOutOfBounds)?;
                    let refd_va = LittleEndian::read_u32(checked_slice) as u64;
                    // final "physical address" from the VM's perspetive is rooted at `MM_PROGRAM_START`
                    let refd_pa = ebpf::MM_PROGRAM_START.saturating_add(refd_va);

                    // The .text section has an unresolved load symbol instruction.
                    let symbol = elf
                        .dynsyms
                        .get(relocation.r_sym)
                        .ok_or(ElfError::UnknownSymbol(relocation.r_sym))?;
                    let addr = symbol.st_value.saturating_add(refd_pa) as u64;
                    let checked_slice = elf_bytes
                        .get_mut(imm_offset..imm_offset.saturating_add(BYTE_LENGTH_IMMEDIATE))
                        .ok_or(ElfError::ValueOutOfBounds)?;
                    LittleEndian::write_u32(checked_slice, (addr & 0xFFFFFFFF) as u32);
                    let file_offset = imm_offset.saturating_add(ebpf::INSN_SIZE);
                    let checked_slice = elf_bytes
                        .get_mut(file_offset..file_offset.saturating_add(BYTE_LENGTH_IMMEDIATE))
                        .ok_or(ElfError::ValueOutOfBounds)?;
                    LittleEndian::write_u32(
                        checked_slice,
                        addr.checked_shr(32).unwrap_or_default() as u32,
                    );
                }
                Some(BpfRelocationType::R_Bpf_64_Relative) => {
                    // Raw relocation between sections.  The instruction being relocated contains
                    // the virtual address that it needs turned into a physical address.  Read it,
                    // locate it in the ELF, convert to physical address

                    // Read the instruction's immediate field which contains virtual
                    // address to convert to physical
                    let checked_slice = elf_bytes
                        .get(imm_offset..imm_offset.saturating_add(BYTE_LENGTH_IMMEDIATE))
                        .ok_or(ElfError::ValueOutOfBounds)?;
                    let refd_va = LittleEndian::read_u32(checked_slice) as u64;

                    if refd_va == 0 {
                        return Err(ElfError::InvalidVirtualAddress(refd_va));
                    }

                    // final "physical address" from the VM's perspetive is rooted at `MM_PROGRAM_START`
                    let refd_pa = ebpf::MM_PROGRAM_START.saturating_add(refd_va);

                    // Write the physical address back into the target location
                    if text_section
                        .file_range()
                        .unwrap_or_default()
                        .contains(&r_offset)
                    {
                        // Instruction lddw spans two instruction slots, split the
                        // physical address into a high and low and write into both slot's imm field

                        let checked_slice = elf_bytes
                            .get_mut(imm_offset..imm_offset.saturating_add(BYTE_LENGTH_IMMEDIATE))
                            .ok_or(ElfError::ValueOutOfBounds)?;
                        LittleEndian::write_u32(checked_slice, (refd_pa & 0xFFFFFFFF) as u32);
                        let file_offset = imm_offset.saturating_add(ebpf::INSN_SIZE);
                        let checked_slice = elf_bytes
                            .get_mut(file_offset..file_offset.saturating_add(BYTE_LENGTH_IMMEDIATE))
                            .ok_or(ElfError::ValueOutOfBounds)?;
                        LittleEndian::write_u32(
                            checked_slice,
                            refd_pa.checked_shr(32).unwrap_or_default() as u32,
                        );
                    } else {
                        // 64 bit memory location, write entire 64 bit physical address directly
                        let checked_slice = elf_bytes
                            .get_mut(r_offset..r_offset.saturating_add(mem::size_of::<u64>()))
                            .ok_or(ElfError::ValueOutOfBounds)?;
                        LittleEndian::write_u64(checked_slice, refd_pa);
                    }
                }
                Some(BpfRelocationType::R_Bpf_64_32) => {
                    // The .text section has an unresolved call to symbol instruction
                    // Hash the symbol name and stick it into the call instruction's imm
                    // field.  Later that hash will be used to look up the function location.

                    let symbol = elf
                        .dynsyms
                        .get(relocation.r_sym)
                        .ok_or(ElfError::UnknownSymbol(relocation.r_sym))?;
                    let name = elf
                        .dynstrtab
                        .get_at(symbol.st_name)
                        .ok_or(ElfError::UnknownSymbol(symbol.st_name))?;
                    let hash = if symbol.is_function() && symbol.st_value != 0 {
                        // bpf call
                        if !text_section
                            .vm_range()
                            .contains(&(symbol.st_value as usize))
                        {
                            return Err(ElfError::ValueOutOfBounds);
                        }
                        let target_pc = (symbol.st_value.saturating_sub(text_section.sh_addr)
                            as usize)
                            .checked_div(ebpf::INSN_SIZE)
                            .unwrap_or_default();
                        register_bpf_function(
                            config,
                            bpf_functions,
                            syscall_registry,
                            target_pc,
                            name,
                        )?
                    } else {
                        // syscall
                        let hash = syscall_cache
                            .entry(symbol.st_name)
                            .or_insert_with(|| (ebpf::hash_symbol_name(name.as_bytes()), name))
                            .0;
                        if config.reject_broken_elfs
                            && syscall_registry.lookup_syscall(hash).is_none()
                        {
                            return Err(ElfError::UnresolvedSymbol(
                                name.to_string(),
                                r_offset
                                    .checked_div(ebpf::INSN_SIZE)
                                    .and_then(|offset| {
                                        offset.checked_add(ebpf::ELF_INSN_DUMP_OFFSET)
                                    })
                                    .unwrap_or(ebpf::ELF_INSN_DUMP_OFFSET),
                                r_offset,
                            ));
                        }
                        hash
                    };
                    let checked_slice = elf_bytes
                        .get_mut(imm_offset..imm_offset.saturating_add(BYTE_LENGTH_IMMEDIATE))
                        .ok_or(ElfError::ValueOutOfBounds)?;
                    LittleEndian::write_u32(checked_slice, hash);
                }
                _ => return Err(ElfError::UnknownRelocation(relocation.r_type)),
            }
        }

        if config.enable_symbol_and_section_labels {
            // Save syscall names
            *syscall_symbols = syscall_cache
                .values()
                .map(|(hash, name)| (*hash, name.to_string()))
                .collect();

            // Register all known function names from the symbol table
            for symbol in &elf.syms {
                if symbol.st_info & 0xEF != 0x02 {
                    continue;
                }
                if !text_section
                    .vm_range()
                    .contains(&(symbol.st_value as usize))
                {
                    return Err(ElfError::ValueOutOfBounds);
                }
                let target_pc = (symbol.st_value.saturating_sub(text_section.sh_addr) as usize)
                    .checked_div(ebpf::INSN_SIZE)
                    .unwrap_or_default();
                let name = elf
                    .strtab
                    .get_at(symbol.st_name)
                    .ok_or(ElfError::UnknownSymbol(symbol.st_name))?;
                register_bpf_function(config, bpf_functions, syscall_registry, target_pc, name)?;
            }
        }

        Ok(())
    }

    #[allow(dead_code)]
    fn dump_data(name: &str, prog: &[u8]) {
        let mut eight_bytes: Vec<u8> = Vec::new();
        println!("{}", name);
        for i in prog.iter() {
            if eight_bytes.len() >= 7 {
                println!("{:02X?}", eight_bytes);
                eight_bytes.clear();
            } else {
                eight_bytes.push(*i);
            }
        }
    }
}

pub(crate) fn get_ro_region(ro_section: &Section, elf: &[u8]) -> MemoryRegion {
    let (offset, ro_data) = match ro_section {
        Section::Owned(offset, data) => (*offset, data.as_slice()),
        Section::Borrowed(range) => (range.start, &elf[range.clone()]),
    };

    // If offset > 0, the region will start at MM_PROGRAM_START + the offset of
    // the first read only byte. [MM_PROGRAM_START, MM_PROGRAM_START + offset)
    // will be unmappable, see MemoryRegion::vm_to_host.
    MemoryRegion::new_readonly(
        ro_data,
        ebpf::MM_PROGRAM_START.saturating_add(offset as u64),
    )
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        ebpf,
        elf::scroll::Pwrite,
        fuzz::fuzz,
        syscalls::{BpfSyscallString, BpfSyscallU64},
        user_error::UserError,
        vm::{SyscallObject, TestInstructionMeter},
    };
    use rand::{distributions::Uniform, Rng};
    use std::{fs::File, io::Read};
    type ElfExecutable = Executable<UserError, TestInstructionMeter>;

    fn syscall_registry() -> SyscallRegistry {
        let mut syscall_registry = SyscallRegistry::default();
        syscall_registry
            .register_syscall_by_name(b"log", BpfSyscallString::call)
            .unwrap();
        syscall_registry
            .register_syscall_by_name(b"log_64", BpfSyscallU64::call)
            .unwrap();
        syscall_registry
    }

    #[test]
    fn test_validate() {
        let mut file = File::open("tests/elfs/noop.so").expect("file open failed");
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .expect("failed to read elf file");
        let mut parsed_elf = Elf::parse(&bytes).unwrap();
        let elf_bytes = bytes.to_vec();
        let mut config = Config::default();

        ElfExecutable::validate(&mut config, &parsed_elf, &elf_bytes).expect("validation failed");
        parsed_elf.header.e_ident[EI_CLASS] = ELFCLASS32;
        ElfExecutable::validate(&mut config, &parsed_elf, &elf_bytes)
            .expect_err("allowed bad class");
        parsed_elf.header.e_ident[EI_CLASS] = ELFCLASS64;
        ElfExecutable::validate(&mut config, &parsed_elf, &elf_bytes).expect("validation failed");
        parsed_elf.header.e_ident[EI_DATA] = ELFDATA2MSB;
        ElfExecutable::validate(&mut config, &parsed_elf, &elf_bytes)
            .expect_err("allowed big endian");
        parsed_elf.header.e_ident[EI_DATA] = ELFDATA2LSB;
        ElfExecutable::validate(&mut config, &parsed_elf, &elf_bytes).expect("validation failed");
        parsed_elf.header.e_ident[EI_OSABI] = 1;
        ElfExecutable::validate(&mut config, &parsed_elf, &elf_bytes)
            .expect_err("allowed wrong abi");
        parsed_elf.header.e_ident[EI_OSABI] = ELFOSABI_NONE;
        ElfExecutable::validate(&mut config, &parsed_elf, &elf_bytes).expect("validation failed");
        parsed_elf.header.e_machine = EM_QDSP6;
        ElfExecutable::validate(&mut config, &parsed_elf, &elf_bytes)
            .expect_err("allowed wrong machine");
        parsed_elf.header.e_machine = EM_BPF;
        ElfExecutable::validate(&mut config, &parsed_elf, &elf_bytes).expect("validation failed");
        parsed_elf.header.e_type = ET_REL;
        ElfExecutable::validate(&mut config, &parsed_elf, &elf_bytes)
            .expect_err("allowed wrong type");
        parsed_elf.header.e_type = ET_DYN;
        ElfExecutable::validate(&mut config, &parsed_elf, &elf_bytes).expect("validation failed");
    }

    #[test]
    fn test_load() {
        let mut file = File::open("tests/elfs/noop.so").expect("file open failed");
        let mut elf_bytes = Vec::new();
        file.read_to_end(&mut elf_bytes)
            .expect("failed to read elf file");
        ElfExecutable::load(Config::default(), &elf_bytes, syscall_registry())
            .expect("validation failed");
    }

    #[test]
    fn test_entrypoint() {
        let mut file = File::open("tests/elfs/noop.so").expect("file open failed");
        let mut elf_bytes = Vec::new();
        file.read_to_end(&mut elf_bytes)
            .expect("failed to read elf file");
        let elf = ElfExecutable::load(Config::default(), &elf_bytes, syscall_registry())
            .expect("validation failed");
        let mut parsed_elf = Elf::parse(&elf_bytes).unwrap();
        let initial_e_entry = parsed_elf.header.e_entry;
        let executable: &Executable<UserError, TestInstructionMeter> = &elf;
        assert_eq!(
            0,
            executable
                .get_entrypoint_instruction_offset()
                .expect("failed to get entrypoint")
        );

        parsed_elf.header.e_entry += 8;
        let mut elf_bytes = elf_bytes.clone();
        elf_bytes.pwrite(parsed_elf.header, 0).unwrap();
        let elf = ElfExecutable::load(Config::default(), &elf_bytes, syscall_registry())
            .expect("validation failed");
        let executable: &Executable<UserError, TestInstructionMeter> = &elf;
        assert_eq!(
            1,
            executable
                .get_entrypoint_instruction_offset()
                .expect("failed to get entrypoint")
        );

        parsed_elf.header.e_entry = 1;
        let mut elf_bytes = elf_bytes;
        elf_bytes.pwrite(parsed_elf.header, 0).unwrap();
        assert_eq!(
            Err(ElfError::EntrypointOutOfBounds),
            ElfExecutable::load(Config::default(), &elf_bytes, syscall_registry())
        );

        parsed_elf.header.e_entry = std::u64::MAX;
        let mut elf_bytes = elf_bytes;
        elf_bytes.pwrite(parsed_elf.header, 0).unwrap();
        assert_eq!(
            Err(ElfError::EntrypointOutOfBounds),
            ElfExecutable::load(Config::default(), &elf_bytes, syscall_registry())
        );

        parsed_elf.header.e_entry = initial_e_entry + ebpf::INSN_SIZE as u64 + 1;
        let mut elf_bytes = elf_bytes;
        elf_bytes.pwrite(parsed_elf.header, 0).unwrap();
        assert_eq!(
            Err(ElfError::InvalidEntrypoint),
            ElfExecutable::load(Config::default(), &elf_bytes, syscall_registry())
        );

        parsed_elf.header.e_entry = initial_e_entry;
        let mut elf_bytes = elf_bytes;
        elf_bytes.pwrite(parsed_elf.header, 0).unwrap();
        let elf = ElfExecutable::load(Config::default(), &elf_bytes, syscall_registry())
            .expect("validation failed");
        let executable: &Executable<UserError, TestInstructionMeter> = &elf;
        assert_eq!(
            0,
            executable
                .get_entrypoint_instruction_offset()
                .expect("failed to get entrypoint")
        );
    }

    #[test]
    fn test_fixup_relative_calls_back() {
        let config = Config {
            enable_symbol_and_section_labels: true,
            ..Config::default()
        };
        let mut bpf_functions = BTreeMap::new();
        let syscall_registry = SyscallRegistry::default();

        // call -2
        #[rustfmt::skip]
        let mut prog = vec![
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x85, 0x10, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff];

        ElfExecutable::fixup_relative_calls(
            &config,
            &mut bpf_functions,
            &syscall_registry,
            &mut prog,
        )
        .unwrap();
        let name = "function_4".to_string();
        let hash = hash_bpf_function(4, &name);
        let insn = ebpf::Insn {
            opc: 0x85,
            dst: 0,
            src: 1,
            imm: hash as i64,
            ..ebpf::Insn::default()
        };
        assert_eq!(insn.to_array(), prog[40..]);
        assert_eq!(*bpf_functions.get(&hash).unwrap(), (4, name));

        // call +6
        let mut bpf_functions = BTreeMap::new();
        prog.splice(44.., vec![0xfa, 0xff, 0xff, 0xff]);
        ElfExecutable::fixup_relative_calls(
            &config,
            &mut bpf_functions,
            &syscall_registry,
            &mut prog,
        )
        .unwrap();
        let name = "function_0".to_string();
        let hash = hash_bpf_function(0, &name);
        let insn = ebpf::Insn {
            opc: 0x85,
            dst: 0,
            src: 1,
            imm: hash as i64,
            ..ebpf::Insn::default()
        };
        assert_eq!(insn.to_array(), prog[40..]);
        assert_eq!(*bpf_functions.get(&hash).unwrap(), (0, name));
    }

    #[test]
    fn test_fixup_relative_calls_forward() {
        let config = Config {
            enable_symbol_and_section_labels: true,
            ..Config::default()
        };
        let mut bpf_functions = BTreeMap::new();
        let syscall_registry = SyscallRegistry::default();

        // call +0
        #[rustfmt::skip]
        let mut prog = vec![
            0x85, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        ElfExecutable::fixup_relative_calls(
            &config,
            &mut bpf_functions,
            &syscall_registry,
            &mut prog,
        )
        .unwrap();
        let name = "function_1".to_string();
        let hash = hash_bpf_function(1, &name);
        let insn = ebpf::Insn {
            opc: 0x85,
            dst: 0,
            src: 1,
            imm: hash as i64,
            ..ebpf::Insn::default()
        };
        assert_eq!(insn.to_array(), prog[..8]);
        assert_eq!(*bpf_functions.get(&hash).unwrap(), (1, name));

        // call +4
        let mut bpf_functions = BTreeMap::new();
        prog.splice(4..8, vec![0x04, 0x00, 0x00, 0x00]);
        ElfExecutable::fixup_relative_calls(
            &config,
            &mut bpf_functions,
            &syscall_registry,
            &mut prog,
        )
        .unwrap();
        let name = "function_5".to_string();
        let hash = hash_bpf_function(5, &name);
        let insn = ebpf::Insn {
            opc: 0x85,
            dst: 0,
            src: 1,
            imm: hash as i64,
            ..ebpf::Insn::default()
        };
        assert_eq!(insn.to_array(), prog[..8]);
        assert_eq!(*bpf_functions.get(&hash).unwrap(), (5, name));
    }

    #[test]
    #[should_panic(
        expected = "called `Result::unwrap()` on an `Err` value: RelativeJumpOutOfBounds(29)"
    )]
    fn test_fixup_relative_calls_out_of_bounds_forward() {
        let config = Config::default();
        let mut bpf_functions = BTreeMap::new();
        let syscall_registry = SyscallRegistry::default();

        // call +5
        #[rustfmt::skip]
        let mut prog = vec![
            0x85, 0x10, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        ElfExecutable::fixup_relative_calls(
            &config,
            &mut bpf_functions,
            &syscall_registry,
            &mut prog,
        )
        .unwrap();
        let name = "function_1".to_string();
        let hash = hash_bpf_function(1, &name);
        let insn = ebpf::Insn {
            opc: 0x85,
            dst: 0,
            src: 1,
            imm: hash as i64,
            ..ebpf::Insn::default()
        };
        assert_eq!(insn.to_array(), prog[..8]);
        assert_eq!(*bpf_functions.get(&hash).unwrap(), (1, name));
    }

    #[test]
    #[should_panic(
        expected = "called `Result::unwrap()` on an `Err` value: RelativeJumpOutOfBounds(34)"
    )]
    fn test_fixup_relative_calls_out_of_bounds_back() {
        let config = Config::default();
        let mut bpf_functions = BTreeMap::new();
        let syscall_registry = SyscallRegistry::default();

        // call -7
        #[rustfmt::skip]
        let mut prog = vec![
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x85, 0x10, 0x00, 0x00, 0xf9, 0xff, 0xff, 0xff];

        ElfExecutable::fixup_relative_calls(
            &config,
            &mut bpf_functions,
            &syscall_registry,
            &mut prog,
        )
        .unwrap();
        let name = "function_4".to_string();
        let hash = hash_bpf_function(4, &name);
        let insn = ebpf::Insn {
            opc: 0x85,
            dst: 0,
            src: 1,
            imm: hash as i64,
            ..ebpf::Insn::default()
        };
        assert_eq!(insn.to_array(), prog[40..]);
        assert_eq!(*bpf_functions.get(&hash).unwrap(), (4, name));
    }

    #[test]
    #[ignore]
    fn test_fuzz_load() {
        // Random bytes, will mostly fail due to lack of ELF header so just do a few
        let mut rng = rand::thread_rng();
        let range = Uniform::new(0, 255);
        println!("random bytes");
        for _ in 0..1_000 {
            let elf_bytes: Vec<u8> = (0..100).map(|_| rng.sample(&range)).collect();
            let _ = ElfExecutable::load(Config::default(), &elf_bytes, SyscallRegistry::default());
        }

        // Take a real elf and mangle it

        let mut file = File::open("tests/elfs/noop.so").expect("file open failed");
        let mut elf_bytes = Vec::new();
        file.read_to_end(&mut elf_bytes)
            .expect("failed to read elf file");
        let parsed_elf = Elf::parse(&elf_bytes).unwrap();

        // focus on elf header, small typically 64 bytes
        println!("mangle elf header");
        fuzz(
            &elf_bytes,
            1_000_000,
            100,
            0..parsed_elf.header.e_ehsize as usize,
            0..255,
            |bytes: &mut [u8]| {
                let _ = ElfExecutable::load(Config::default(), bytes, SyscallRegistry::default());
            },
        );

        // focus on section headers
        println!("mangle section headers");
        fuzz(
            &elf_bytes,
            1_000_000,
            100,
            parsed_elf.header.e_shoff as usize..elf_bytes.len(),
            0..255,
            |bytes: &mut [u8]| {
                let _ = ElfExecutable::load(Config::default(), bytes, SyscallRegistry::default());
            },
        );

        // mangle whole elf randomly
        println!("mangle whole elf");
        fuzz(
            &elf_bytes,
            1_000_000,
            100,
            0..elf_bytes.len(),
            0..255,
            |bytes: &mut [u8]| {
                let _ = ElfExecutable::load(Config::default(), bytes, SyscallRegistry::default());
            },
        );
    }

    #[test]
    fn test_relocs() {
        let mut file = File::open("tests/elfs/reloc.so").expect("file open failed");
        let mut elf_bytes = Vec::new();
        file.read_to_end(&mut elf_bytes)
            .expect("failed to read elf file");
        ElfExecutable::load(Config::default(), &elf_bytes, syscall_registry())
            .expect("validation failed");
    }

    fn new_section(sh_addr: u64, sh_size: u64) -> SectionHeader {
        SectionHeader {
            sh_addr,
            sh_offset: sh_addr,
            sh_size,
            ..SectionHeader::default()
        }
    }

    #[test]
    fn test_owned_ro_sections_not_contiguous() {
        let config = Config::default();
        let elf_bytes = [0u8; 512];

        // there's a non-rodata section between two rodata sections
        let s1 = new_section(10, 10);
        let s2 = new_section(20, 10);
        let s3 = new_section(30, 10);

        assert!(matches!(
            ElfExecutable::parse_ro_sections(
                &config,
                [(Some(".text"), &s1), (Some(".dynamic"), &s2), (Some(".rodata"), &s3)],
                &elf_bytes,
            ),
            Ok(Section::Owned(offset, data)) if offset == 10 && data.len() == 30
        ));
    }

    #[test]
    fn test_owned_ro_sections_with_sh_offset() {
        let config = Config::default();
        let elf_bytes = [0u8; 512];

        // s2 is at a custom sh_offset. We need to merge into an owned buffer so
        // s2 can be moved to the right address offset.
        let s1 = new_section(10, 10);
        let mut s2 = new_section(20, 10);
        s2.sh_offset = 30;

        assert!(matches!(
            ElfExecutable::parse_ro_sections(
                &config,
                [(Some(".text"), &s1), (Some(".rodata"), &s2)],
                &elf_bytes,
            ),
            Ok(Section::Owned(offset, data)) if offset == 10 && data.len() == 20
        ));
    }

    #[test]
    fn test_owned_ro_region_no_initial_gap() {
        let config = Config::default();
        let elf_bytes = [0u8; 512];

        // need an owned buffer so we can zero the address space taken by s2
        let s1 = new_section(0, 10);
        let s2 = new_section(10, 10);
        let s3 = new_section(20, 10);

        let ro_section = ElfExecutable::parse_ro_sections(
            &config,
            [
                (Some(".text"), &s1),
                (Some(".dynamic"), &s2),
                (Some(".rodata"), &s3),
            ],
            &elf_bytes,
        )
        .unwrap();
        let ro_region = get_ro_region(&ro_section, &elf_bytes);
        let owned_section = match &ro_section {
            Section::Owned(_offset, data) => data.as_slice(),
            _ => panic!(),
        };

        // [0..s3.sh_addr + s3.sh_size] is the valid ro memory area
        assert_eq!(
            ro_region.vm_to_host::<UserError>(ebpf::MM_PROGRAM_START, s3.sh_addr + s3.sh_size),
            Ok(owned_section.as_ptr() as u64),
        );

        // one byte past the ro section is not mappable
        assert_eq!(
            ro_region.vm_to_host::<UserError>(ebpf::MM_PROGRAM_START + s3.sh_addr + s3.sh_size, 1),
            Err(EbpfError::InvalidVirtualAddress(
                ebpf::MM_PROGRAM_START + s3.sh_addr + s3.sh_size
            ))
        );
    }

    #[test]
    fn test_owned_ro_region_initial_gap_mappable() {
        let config = Config {
            optimize_rodata: false,
            ..Config::default()
        };
        let elf_bytes = [0u8; 512];

        // the first section starts at a non-zero offset
        let s1 = new_section(10, 10);
        let s2 = new_section(20, 10);
        let s3 = new_section(30, 10);

        let ro_section = ElfExecutable::parse_ro_sections(
            &config,
            [
                (Some(".text"), &s1),
                (Some(".dynamic"), &s2),
                (Some(".rodata"), &s3),
            ],
            &elf_bytes,
        )
        .unwrap();
        let ro_region = get_ro_region(&ro_section, &elf_bytes);
        let owned_section = match &ro_section {
            Section::Owned(_offset, data) => data.as_slice(),
            _ => panic!(),
        };

        // [s1.sh_addr..s3.sh_addr + s3.sh_size] is where the readonly data is.
        // But for backwards compatibility (config.optimize_rodata=false)
        // [0..s1.sh_addr] is mappable too (and zeroed).
        assert_eq!(
            ro_region.vm_to_host::<UserError>(ebpf::MM_PROGRAM_START, s3.sh_addr + s3.sh_size),
            Ok(owned_section.as_ptr() as u64),
        );

        // one byte past the ro section is not mappable
        assert_eq!(
            ro_region.vm_to_host::<UserError>(ebpf::MM_PROGRAM_START + s3.sh_addr + s3.sh_size, 1),
            Err(EbpfError::InvalidVirtualAddress(
                ebpf::MM_PROGRAM_START + s3.sh_addr + s3.sh_size
            ))
        );
    }

    #[test]
    fn test_owned_ro_region_initial_gap_map_error() {
        let config = Config::default();
        let elf_bytes = [0u8; 512];

        // the first section starts at a non-zero offset
        let s1 = new_section(10, 10);
        let s2 = new_section(20, 10);
        let s3 = new_section(30, 10);

        let ro_section = ElfExecutable::parse_ro_sections(
            &config,
            [
                (Some(".text"), &s1),
                (Some(".dynamic"), &s2),
                (Some(".rodata"), &s3),
            ],
            &elf_bytes,
        )
        .unwrap();
        let owned_section = match &ro_section {
            Section::Owned(_offset, data) => data.as_slice(),
            _ => panic!(),
        };
        let ro_region = get_ro_region(&ro_section, &elf_bytes);

        // s1 starts at sh_addr=10 so [MM_PROGRAM_START..MM_PROGRAM_START + 10] is not mappable

        // the low bound of the initial gap is not mappable
        assert_eq!(
            ro_region.vm_to_host::<UserError>(ebpf::MM_PROGRAM_START, 1),
            Err(EbpfError::InvalidVirtualAddress(ebpf::MM_PROGRAM_START))
        );

        // the hi bound of the initial gap is not mappable
        assert_eq!(
            ro_region.vm_to_host::<UserError>(ebpf::MM_PROGRAM_START + s1.sh_addr - 1, 1),
            Err(EbpfError::InvalidVirtualAddress(ebpf::MM_PROGRAM_START + 9))
        );

        // [s1.sh_addr..s3.sh_addr + s3.sh_size] is the valid ro memory area
        assert_eq!(
            ro_region.vm_to_host::<UserError>(
                ebpf::MM_PROGRAM_START + s1.sh_addr,
                s3.sh_addr + s3.sh_size - s1.sh_addr
            ),
            Ok(owned_section.as_ptr() as u64),
        );

        // one byte past the ro section is not mappable
        assert_eq!(
            ro_region.vm_to_host::<UserError>(ebpf::MM_PROGRAM_START + s3.sh_addr + s3.sh_size, 1),
            Err(EbpfError::InvalidVirtualAddress(
                ebpf::MM_PROGRAM_START + s3.sh_addr + s3.sh_size
            ))
        );
    }

    #[test]
    fn test_borrowed_ro_sections_disabled() {
        let config = Config {
            optimize_rodata: false,
            ..Config::default()
        };
        let elf_bytes = [0u8; 512];

        // s1 and s2 are contiguous, the rodata section can be borrowed from the
        // original elf input but config.borrow_rodata=false
        let s1 = new_section(0, 10);
        let s2 = new_section(10, 10);

        assert!(matches!(
            ElfExecutable::parse_ro_sections(
                &config,
                [(Some(".text"), &s1), (Some(".rodata"), &s2)],
                &elf_bytes,
            ),
            Ok(Section::Owned(offset, data)) if offset == 0 && data.len() == 20
        ));
    }

    #[test]
    fn test_borrowed_ro_sections() {
        let config = Config::default();
        let elf_bytes = [0u8; 512];

        let s1 = new_section(0, 10);
        let s2 = new_section(20, 10);
        let s3 = new_section(40, 10);
        let s4 = new_section(50, 10);

        assert_eq!(
            ElfExecutable::parse_ro_sections(
                &config,
                [
                    (Some(".dynsym"), &s1),
                    (Some(".text"), &s2),
                    (Some(".rodata"), &s3),
                    (Some(".dynamic"), &s4)
                ],
                &elf_bytes,
            ),
            Ok(Section::Borrowed(20..50))
        );
    }

    #[test]
    fn test_borrowed_ro_region_no_initial_gap() {
        let config = Config::default();
        let elf_bytes = [0u8; 512];

        let s1 = new_section(0, 10);
        let s2 = new_section(10, 10);
        let s3 = new_section(10, 10);

        let ro_section = ElfExecutable::parse_ro_sections(
            &config,
            [
                (Some(".text"), &s1),
                (Some(".rodata"), &s2),
                (Some(".dynamic"), &s3),
            ],
            &elf_bytes,
        )
        .unwrap();
        let ro_region = get_ro_region(&ro_section, &elf_bytes);

        // s1 starts at sh_addr=0 so [0..s2.sh_addr + s2.sh_size] is the valid
        // ro memory area
        assert_eq!(
            ro_region.vm_to_host::<UserError>(ebpf::MM_PROGRAM_START, s2.sh_addr + s2.sh_size),
            Ok(elf_bytes.as_ptr() as u64),
        );

        // one byte past the ro section is not mappable
        assert_eq!(
            ro_region.vm_to_host::<UserError>(ebpf::MM_PROGRAM_START + s2.sh_addr + s2.sh_size, 1),
            Err(EbpfError::InvalidVirtualAddress(
                ebpf::MM_PROGRAM_START + s2.sh_addr + s2.sh_size
            ))
        );
    }

    #[test]
    fn test_borrowed_ro_region_initial_gap() {
        let config = Config::default();
        let elf_bytes = [0u8; 512];
        let s1 = new_section(0, 10);
        let s2 = new_section(10, 10);
        let s3 = new_section(20, 10);

        let ro_section = ElfExecutable::parse_ro_sections(
            &config,
            [
                (Some(".dynamic"), &s1),
                (Some(".text"), &s2),
                (Some(".rodata"), &s3),
            ],
            &elf_bytes,
        )
        .unwrap();
        let ro_region = get_ro_region(&ro_section, &elf_bytes);

        // s2 starts at sh_addr=10 so [0..10] is not mappable

        // the low bound of the initial gap is not mappable
        assert_eq!(
            ro_region.vm_to_host::<UserError>(ebpf::MM_PROGRAM_START, 1),
            Err(EbpfError::InvalidVirtualAddress(ebpf::MM_PROGRAM_START))
        );

        // the hi bound of the initial gap is not mappable
        assert_eq!(
            ro_region.vm_to_host::<UserError>(ebpf::MM_PROGRAM_START + s2.sh_addr - 1, 1),
            Err(EbpfError::InvalidVirtualAddress(ebpf::MM_PROGRAM_START + 9))
        );

        // [s2.sh_addr..s3.sh_addr + s3.sh_size] is the valid ro memory area
        assert_eq!(
            ro_region.vm_to_host::<UserError>(
                ebpf::MM_PROGRAM_START + s2.sh_addr,
                s3.sh_addr + s3.sh_size - s2.sh_addr
            ),
            Ok(elf_bytes[s2.sh_addr as usize..].as_ptr() as u64),
        );

        // one byte past the ro section is not mappable
        assert_eq!(
            ro_region.vm_to_host::<UserError>(ebpf::MM_PROGRAM_START + s3.sh_addr + s3.sh_size, 1),
            Err(EbpfError::InvalidVirtualAddress(
                ebpf::MM_PROGRAM_START + s3.sh_addr + s3.sh_size
            ))
        );
    }

    #[test]
    #[should_panic(expected = r#"validation failed: WritableSectionNotSupported(".data")"#)]
    fn test_writable_data_section() {
        let elf_bytes =
            std::fs::read("tests/elfs/writable_data_section.so").expect("failed to read elf file");
        ElfExecutable::load(Config::default(), &elf_bytes, syscall_registry())
            .expect("validation failed");
    }

    #[test]
    #[should_panic(expected = r#"validation failed: WritableSectionNotSupported(".bss")"#)]
    fn test_bss_section() {
        let elf_bytes =
            std::fs::read("tests/elfs/bss_section.so").expect("failed to read elf file");
        ElfExecutable::load(Config::default(), &elf_bytes, syscall_registry())
            .expect("validation failed");
    }

    #[cfg(all(not(windows), target_arch = "x86_64"))]
    #[test]
    fn test_size() {
        let mut file = File::open("tests/elfs/noop.so").expect("file open failed");
        let mut elf_bytes = Vec::new();
        file.read_to_end(&mut elf_bytes)
            .expect("failed to read elf file");
        let mut executable =
            ElfExecutable::from_elf(&elf_bytes, None, Config::default(), syscall_registry())
                .expect("validation failed");
        {
            Executable::jit_compile(&mut executable).unwrap();
        }

        assert_eq!(18616, executable.mem_size());
    }
}
