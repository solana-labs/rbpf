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
    ebpf,
    error::{EbpfError, UserDefinedError},
    jit::JitProgram,
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
}
impl From<GoblinError> for ElfError {
    fn from(error: GoblinError) -> Self {
        match error {
            GoblinError::Malformed(string) => Self::FailedToParse(format!("malformed: {}", string)),
            GoblinError::BadMagic(magic) => Self::FailedToParse(format!("bad magic: {:#x}", magic)),
            GoblinError::Scroll(error) => Self::FailedToParse(format!("read-write: {}", error)),
            GoblinError::IO(error) => Self::FailedToParse(format!("io: {}", error)),
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
    bpf_functions: &mut BTreeMap<u32, (usize, String)>,
    pc: usize,
    name: T,
    enable_symbol_and_section_labels: bool,
) -> Result<u32, ElfError> {
    let hash = hash_bpf_function(pc, name.as_ref());
    match bpf_functions.entry(hash) {
        Entry::Vacant(entry) => {
            entry.insert((
                pc,
                if enable_symbol_and_section_labels {
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

/// Elf loader/relocator
#[derive(Debug, PartialEq)]
pub struct Executable<E: UserDefinedError, I: InstructionMeter> {
    /// Configuration settings
    config: Config,
    /// Loaded and executable elf
    elf_bytes: AlignedMemory,
    /// Read-only section
    ro_section: Vec<u8>,
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
        let offset = (self
            .text_section_info
            .vaddr
            .saturating_sub(ebpf::MM_PROGRAM_START)) as usize;
        (
            self.text_section_info.vaddr,
            &self.ro_section
                [offset..offset.saturating_add(self.text_section_info.offset_range.len())],
        )
    }

    /// Get the concatenated read-only sections (including the text section)
    pub fn get_ro_section(&self) -> &[u8] {
        self.ro_section.as_slice()
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
        Self {
            config,
            elf_bytes,
            ro_section: text_bytes.to_vec(),
            text_section_info: SectionInfo {
                name: if config.enable_symbol_and_section_labels {
                    ".text".to_string()
                } else {
                    String::default()
                },
                vaddr: ebpf::MM_PROGRAM_START,
                offset_range: Range {
                    start: 0,
                    end: text_bytes.len(),
                },
            },
            bpf_functions,
            syscall_symbols: BTreeMap::default(),
            syscall_registry,
            compiled_program: None,
        }
    }

    /// Fully loads an ELF, including validation and relocation
    pub fn load(
        config: Config,
        bytes: &[u8],
        mut syscall_registry: SyscallRegistry,
    ) -> Result<Self, ElfError> {
        let elf = Elf::parse(bytes)?;
        let mut elf_bytes = AlignedMemory::new_with_data(bytes, ebpf::HOST_ALIGN);

        Self::validate(&config, &elf, elf_bytes.as_slice())?;

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
            &mut syscall_registry,
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
                &mut bpf_functions,
                entrypoint,
                "entrypoint",
                config.enable_symbol_and_section_labels,
            )?;
        } else {
            return Err(ElfError::InvalidEntrypoint);
        }

        // concatenate the read-only sections into one
        let mut ro_alloc_length =
            (text_section.sh_addr as usize).saturating_add(text_section_info.offset_range.len());
        let mut ro_fill_length = text_section_info.offset_range.len();
        let ro_slices = elf
            .section_headers
            .iter()
            .filter(|section_header| {
                if let Some(name) = elf.shdr_strtab.get_at(section_header.sh_name) {
                    return name == ".rodata" || name == ".data.rel.ro" || name == ".eh_frame";
                }
                false
            })
            .map(|section_header| {
                let vaddr = section_header
                    .sh_addr
                    .saturating_add(ebpf::MM_PROGRAM_START);
                if (config.reject_broken_elfs && section_header.sh_addr != section_header.sh_offset)
                    || vaddr > ebpf::MM_STACK_START
                {
                    return Err(ElfError::ValueOutOfBounds);
                }
                let slice = elf_bytes
                    .as_slice()
                    .get(section_header.file_range().unwrap_or_default())
                    .ok_or(ElfError::ValueOutOfBounds)?;
                ro_alloc_length = ro_alloc_length
                    .max((section_header.sh_addr as usize).saturating_add(slice.len()));
                ro_fill_length = ro_fill_length.saturating_add(slice.len());
                Ok((section_header.sh_addr as usize, slice))
            })
            .collect::<Result<Vec<_>, ElfError>>()?;
        if ro_alloc_length > elf_bytes.len()
            || (config.reject_broken_elfs && ro_fill_length > ro_alloc_length)
        {
            return Err(ElfError::ValueOutOfBounds);
        }
        let mut ro_section = vec![0; ro_alloc_length];
        ro_section[text_section.sh_addr as usize
            ..(text_section.sh_addr as usize).saturating_add(text_section_info.offset_range.len())]
            .copy_from_slice(
                elf_bytes
                    .as_slice()
                    .get(text_section_info.offset_range.clone())
                    .ok_or(ElfError::ValueOutOfBounds)?,
            );
        for (offset, slice) in ro_slices.iter() {
            ro_section[*offset..offset.saturating_add(slice.len())].copy_from_slice(slice);
        }

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
            .saturating_add(self.ro_section.capacity())
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
        enable_symbol_and_section_labels: bool,
        bpf_functions: &mut BTreeMap<u32, (usize, String)>,
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
                let name = if enable_symbol_and_section_labels {
                    format!("function_{}", target_pc)
                } else {
                    String::default()
                };

                let hash = register_bpf_function(
                    bpf_functions,
                    target_pc as usize,
                    name,
                    enable_symbol_and_section_labels,
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
    pub fn validate(_config: &Config, elf: &Elf, elf_bytes: &[u8]) -> Result<(), ElfError> {
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
        syscall_registry: &mut SyscallRegistry,
        elf: &Elf,
        elf_bytes: &mut [u8],
    ) -> Result<(), ElfError> {
        let text_section = Self::get_section(elf, ".text")?;

        // Fixup all program counter relative call instructions
        Self::fixup_relative_calls(
            config.enable_symbol_and_section_labels,
            bpf_functions,
            elf_bytes
                .get_mut(text_section.file_range().unwrap_or_default())
                .ok_or(ElfError::ValueOutOfBounds)?,
        )?;

        let mut syscall_cache = BTreeMap::new();
        let text_section = Self::get_section(elf, ".text")?;

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
                            bpf_functions,
                            target_pc,
                            name,
                            config.enable_symbol_and_section_labels,
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
                register_bpf_function(bpf_functions, target_pc, name, true)?;
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
        let config = Config::default();

        ElfExecutable::validate(&config, &parsed_elf, &elf_bytes).expect("validation failed");
        parsed_elf.header.e_ident[EI_CLASS] = ELFCLASS32;
        ElfExecutable::validate(&config, &parsed_elf, &elf_bytes).expect_err("allowed bad class");
        parsed_elf.header.e_ident[EI_CLASS] = ELFCLASS64;
        ElfExecutable::validate(&config, &parsed_elf, &elf_bytes).expect("validation failed");
        parsed_elf.header.e_ident[EI_DATA] = ELFDATA2MSB;
        ElfExecutable::validate(&config, &parsed_elf, &elf_bytes).expect_err("allowed big endian");
        parsed_elf.header.e_ident[EI_DATA] = ELFDATA2LSB;
        ElfExecutable::validate(&config, &parsed_elf, &elf_bytes).expect("validation failed");
        parsed_elf.header.e_ident[EI_OSABI] = 1;
        ElfExecutable::validate(&config, &parsed_elf, &elf_bytes).expect_err("allowed wrong abi");
        parsed_elf.header.e_ident[EI_OSABI] = ELFOSABI_NONE;
        ElfExecutable::validate(&config, &parsed_elf, &elf_bytes).expect("validation failed");
        parsed_elf.header.e_machine = EM_QDSP6;
        ElfExecutable::validate(&config, &parsed_elf, &elf_bytes)
            .expect_err("allowed wrong machine");
        parsed_elf.header.e_machine = EM_BPF;
        ElfExecutable::validate(&config, &parsed_elf, &elf_bytes).expect("validation failed");
        parsed_elf.header.e_type = ET_REL;
        ElfExecutable::validate(&config, &parsed_elf, &elf_bytes).expect_err("allowed wrong type");
        parsed_elf.header.e_type = ET_DYN;
        ElfExecutable::validate(&config, &parsed_elf, &elf_bytes).expect("validation failed");
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
        // call -2
        let mut bpf_functions = BTreeMap::new();
        #[rustfmt::skip]
        let mut prog = vec![
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x85, 0x10, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff];

        ElfExecutable::fixup_relative_calls(true, &mut bpf_functions, &mut prog).unwrap();
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
        ElfExecutable::fixup_relative_calls(true, &mut bpf_functions, &mut prog).unwrap();
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
        // call +0
        let mut bpf_functions = BTreeMap::new();
        #[rustfmt::skip]
        let mut prog = vec![
            0x85, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        ElfExecutable::fixup_relative_calls(true, &mut bpf_functions, &mut prog).unwrap();
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
        ElfExecutable::fixup_relative_calls(true, &mut bpf_functions, &mut prog).unwrap();
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
        let mut bpf_functions = BTreeMap::new();
        // call +5
        #[rustfmt::skip]
        let mut prog = vec![
            0x85, 0x10, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        ElfExecutable::fixup_relative_calls(true, &mut bpf_functions, &mut prog).unwrap();
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
        let mut bpf_functions = BTreeMap::new();
        // call -7
        #[rustfmt::skip]
        let mut prog = vec![
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x85, 0x10, 0x00, 0x00, 0xf9, 0xff, 0xff, 0xff];

        ElfExecutable::fixup_relative_calls(true, &mut bpf_functions, &mut prog).unwrap();
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

        assert_eq!(22792, executable.mem_size());
    }
}
