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
    vm::{Config, Executable, InstructionMeter, SyscallRegistry},
};
use byteorder::{ByteOrder, LittleEndian};
use goblin::{
    elf::{header::*, reloc::*, section_header::*, Elf},
    error::Error as GoblinError,
};
use std::{collections::BTreeMap, fmt::Debug, mem, ops::Range, str};

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
    /// Multiple text sections
    #[error("Multiple text sections, consider removing llc option: -function-sections")]
    MultipleTextSections,
    /// Read-write data not supported
    #[error("Found .bss section in ELF, read-write data not supported")]
    BssNotSupported,
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
    OutOfBounds,
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
pub fn register_bpf_function(
    bpf_functions: &mut BTreeMap<u32, (usize, String)>,
    pc: usize,
    name: &str,
) -> Result<u32, ElfError> {
    let hash = hash_bpf_function(pc, name);
    if let Some(entry) = bpf_functions.insert(hash, (pc, name.to_string())) {
        if entry.0 != pc {
            return Err(ElfError::SymbolHashCollision(hash));
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
const BYTE_LENGTH_IMMEIDATE: usize = 4;

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
    /// 64 bit relocation of a ldxdw instruction.
    /// The ldxdw instruction occupies two instruction slots. The 64-bit address
    /// to load from is split into the 32-bit imm field of each slot. The first
    /// slot's pre-relocation imm field contains the virtual address (typically same
    /// as the file offset) of the location to load. Relocation involves calculating
    /// the post-load 64-bit physical address referenced by the imm field and writing
    /// that physical address back into the imm fields of the ldxdw instruction.
    R_Bpf_64_Relative = 8,
    /// Relocation of a call instruction.
    /// The existing imm field contains either an offset of the instruction to jump to
    /// (think local function call) or a special value of "-1".  If -1 the symbol must
    /// be looked up in the symbol table.  The relocation entry contains the symbol
    /// number to call.  In order to support both local jumps and calling external
    /// symbols a 32-bit hash is computed and stored in the the call instruction's
    /// 32-bit imm field.  The hash is used later to look up the 64-bit address to
    /// jump to.  In the case of a local jump the hash is calculated using the current
    /// program counter and in the case of a symbol the hash is calculated using the
    /// name of the symbol.
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

/// Elf loader/relocator
#[derive(Debug, PartialEq)]
pub struct EBpfElf<E: UserDefinedError, I: InstructionMeter> {
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

impl<E: UserDefinedError, I: InstructionMeter> Executable<E, I> for EBpfElf<E, I> {
    /// Get the configuration settings
    fn get_config(&self) -> &Config {
        &self.config
    }

    /// Get the .text section virtual address and bytes
    fn get_text_bytes(&self) -> (u64, &[u8]) {
        let offset = (self.text_section_info.vaddr - ebpf::MM_PROGRAM_START) as usize;
        (
            self.text_section_info.vaddr,
            &self.ro_section[offset..offset + self.text_section_info.offset_range.len()],
        )
    }

    /// Get the concatenated read-only sections (including the text section)
    fn get_ro_section(&self) -> &[u8] {
        self.ro_section.as_slice()
    }

    /// Get the entry point offset into the text section
    fn get_entrypoint_instruction_offset(&self) -> Result<usize, EbpfError<E>> {
        self.bpf_functions
            .get(&ebpf::hash_symbol_name(b"entrypoint"))
            .map(|(pc, _name)| *pc)
            .ok_or(EbpfError::ElfError(ElfError::InvalidEntrypoint))
    }

    /// Get a symbol's instruction offset
    fn lookup_bpf_function(&self, hash: u32) -> Option<usize> {
        self.bpf_functions.get(&hash).map(|(pc, _name)| *pc)
    }

    /// Get the syscall registry
    fn get_syscall_registry(&self) -> &SyscallRegistry {
        &self.syscall_registry
    }

    /// Get the JIT compiled program
    fn get_compiled_program(&self) -> Option<&JitProgram<E, I>> {
        self.compiled_program.as_ref()
    }

    /// JIT compile the executable
    fn jit_compile(&mut self) -> Result<(), EbpfError<E>> {
        self.compiled_program = Some(JitProgram::<E, I>::new(self)?);
        Ok(())
    }

    /// Report information on a symbol that failed to be resolved
    fn report_unresolved_symbol(&self, insn_offset: usize) -> Result<u64, EbpfError<E>> {
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
            file_offset / ebpf::INSN_SIZE + ebpf::ELF_INSN_DUMP_OFFSET,
            file_offset,
        )
        .into())
    }

    /// Get syscalls and BPF functions (if debug symbols are not stripped)
    fn get_function_symbols(&self) -> BTreeMap<usize, (u32, String)> {
        let mut bpf_functions = BTreeMap::new();
        for (hash, (pc, name)) in self.bpf_functions.iter() {
            bpf_functions.insert(*pc, (*hash, name.clone()));
        }
        bpf_functions
    }

    /// Get syscalls symbols
    fn get_syscall_symbols(&self) -> &BTreeMap<u32, String> {
        &self.syscall_symbols
    }
}

impl<'a, E: UserDefinedError, I: InstructionMeter> EBpfElf<E, I> {
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
                name: ".text".to_string(),
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

        Self::validate(&elf, elf_bytes.as_slice())?;

        // calculate the text section info
        let text_section = Self::get_section(&elf, ".text")?;
        let text_section_info = SectionInfo {
            name: elf
                .shdr_strtab
                .get_at(text_section.sh_name)
                .unwrap()
                .to_string(),
            vaddr: text_section.sh_addr.saturating_add(ebpf::MM_PROGRAM_START),
            offset_range: text_section.file_range().unwrap_or_default(),
        };
        if text_section_info.vaddr > ebpf::MM_STACK_START {
            return Err(ElfError::OutOfBounds);
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
        let offset = elf.header.e_entry - text_section.sh_addr;
        if offset % ebpf::INSN_SIZE as u64 != 0 {
            return Err(ElfError::InvalidEntrypoint);
        }
        let entrypoint = offset as usize / ebpf::INSN_SIZE;
        bpf_functions.remove(&ebpf::hash_symbol_name(b"entrypoint"));
        register_bpf_function(&mut bpf_functions, entrypoint, "entrypoint")?;

        // concatenate the read-only sections into one
        let mut ro_length = text_section.sh_addr as usize + text_section_info.offset_range.len();
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
                if vaddr > ebpf::MM_STACK_START {
                    return Err(ElfError::OutOfBounds);
                }
                let slice = elf_bytes
                    .as_slice()
                    .get(section_header.file_range().unwrap_or_default())
                    .ok_or(ElfError::OutOfBounds)?;
                ro_length = ro_length.max(section_header.sh_addr as usize + slice.len());
                Ok((section_header.sh_addr as usize, slice))
            })
            .collect::<Result<Vec<_>, ElfError>>()?;
        let mut ro_section = vec![0; ro_length];
        ro_section[text_section.sh_addr as usize
            ..text_section.sh_addr as usize + text_section_info.offset_range.len()]
            .copy_from_slice(
                elf_bytes
                    .as_slice()
                    .get(text_section_info.offset_range.clone())
                    .ok_or(ElfError::OutOfBounds)?,
            );
        for (offset, slice) in ro_slices.iter() {
            ro_section[*offset..*offset + slice.len()].copy_from_slice(slice);
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

    // Functions exposed for tests

    /// Fix-ups relative calls
    pub fn fixup_relative_calls(
        bpf_functions: &mut BTreeMap<u32, (usize, String)>,
        elf_bytes: &mut [u8],
    ) -> Result<(), ElfError> {
        for i in 0..elf_bytes.len() / ebpf::INSN_SIZE {
            let mut insn = ebpf::get_insn(elf_bytes, i);
            if insn.opc == ebpf::CALL_IMM && insn.imm != -1 {
                let target_pc = i as isize + 1 + insn.imm as isize;
                if target_pc < 0 || target_pc >= (elf_bytes.len() / ebpf::INSN_SIZE) as isize {
                    return Err(ElfError::RelativeJumpOutOfBounds(
                        i + ebpf::ELF_INSN_DUMP_OFFSET,
                    ));
                }
                let name = format!("function_{}", target_pc);
                let hash = register_bpf_function(bpf_functions, target_pc as usize, &name)?;
                insn.imm = hash as i64;
                let checked_slice = elf_bytes
                    .get_mut(i * ebpf::INSN_SIZE..(i * ebpf::INSN_SIZE) + ebpf::INSN_SIZE)
                    .ok_or(ElfError::OutOfBounds)?;
                checked_slice.copy_from_slice(&insn.to_vec());
            }
        }
        Ok(())
    }

    /// Validates the ELF
    pub fn validate(elf: &Elf, elf_bytes: &[u8]) -> Result<(), ElfError> {
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

        let num_text_sections = elf.section_headers.iter().fold(0, |count, section_header| {
            if let Some(this_name) = elf.shdr_strtab.get_at(section_header.sh_name) {
                if this_name == ".text" {
                    return count + 1;
                }
            }
            count
        });
        if 1 != num_text_sections {
            return Err(ElfError::MultipleTextSections);
        }

        for section_header in elf.section_headers.iter() {
            if let Some(this_name) = elf.shdr_strtab.get_at(section_header.sh_name) {
                if this_name.starts_with(".bss") {
                    return Err(ElfError::BssNotSupported);
                }
            }
        }

        for section_header in &elf.section_headers {
            let start = section_header.sh_offset as usize;
            let end = section_header
                .sh_offset
                .checked_add(section_header.sh_size)
                .ok_or(ElfError::OutOfBounds)? as usize;
            let _ = elf_bytes.get(start..end).ok_or(ElfError::OutOfBounds)?;
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
            bpf_functions,
            &mut elf_bytes
                .get_mut(text_section.file_range().unwrap_or_default())
                .ok_or(ElfError::OutOfBounds)?,
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
                        .get(imm_offset..imm_offset.saturating_add(BYTE_LENGTH_IMMEIDATE))
                        .ok_or(ElfError::OutOfBounds)?;
                    let refd_va = LittleEndian::read_u32(checked_slice) as u64;
                    // final "physical address" from the VM's perspetive is rooted at `MM_PROGRAM_START`
                    let refd_pa = ebpf::MM_PROGRAM_START.saturating_add(refd_va);

                    // The .text section has an unresolved load symbol instruction.
                    let sym = elf
                        .dynsyms
                        .get(relocation.r_sym)
                        .ok_or(ElfError::UnknownSymbol(relocation.r_sym))?;
                    if !text_section.vm_range().contains(&(sym.st_value as usize)) {
                        return Err(ElfError::OutOfBounds);
                    }
                    let addr = (sym.st_value + refd_pa) as u32;
                    let mut checked_slice = elf_bytes
                        .get_mut(imm_offset..imm_offset.saturating_add(BYTE_LENGTH_IMMEIDATE))
                        .ok_or(ElfError::OutOfBounds)?;
                    LittleEndian::write_u32(&mut checked_slice, addr);
                }
                Some(BpfRelocationType::R_Bpf_64_Relative) => {
                    // Raw relocation between sections.  The instruction being relocated contains
                    // the virtual address that it needs turned into a physical address.  Read it,
                    // locate it in the ELF, convert to physical address

                    // Read the instruction's immediate field which contains virtual
                    // address to convert to physical
                    let checked_slice = elf_bytes
                        .get(imm_offset..imm_offset.saturating_add(BYTE_LENGTH_IMMEIDATE))
                        .ok_or(ElfError::OutOfBounds)?;
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

                        let mut checked_slice = elf_bytes
                            .get_mut(imm_offset..imm_offset.saturating_add(BYTE_LENGTH_IMMEIDATE))
                            .ok_or(ElfError::OutOfBounds)?;
                        LittleEndian::write_u32(&mut checked_slice, (refd_pa & 0xFFFFFFFF) as u32);
                        let mut checked_slice = elf_bytes
                            .get_mut(
                                imm_offset.saturating_add(ebpf::INSN_SIZE)
                                    ..imm_offset
                                        .saturating_add(ebpf::INSN_SIZE + BYTE_LENGTH_IMMEIDATE),
                            )
                            .ok_or(ElfError::OutOfBounds)?;
                        LittleEndian::write_u32(&mut checked_slice, (refd_pa >> 32) as u32);
                    } else {
                        // 64 bit memory location, write entire 64 bit physical address directly
                        let mut checked_slice = elf_bytes
                            .get_mut(r_offset..r_offset.saturating_add(mem::size_of::<u64>()))
                            .ok_or(ElfError::OutOfBounds)?;
                        LittleEndian::write_u64(&mut checked_slice, refd_pa);
                    }
                }
                Some(BpfRelocationType::R_Bpf_64_32) => {
                    // The .text section has an unresolved call to symbol instruction
                    // Hash the symbol name and stick it into the call instruction's imm
                    // field.  Later that hash will be used to look up the function location.

                    let sym = elf
                        .dynsyms
                        .get(relocation.r_sym)
                        .ok_or(ElfError::UnknownSymbol(relocation.r_sym))?;
                    let name = elf
                        .dynstrtab
                        .get_at(sym.st_name)
                        .ok_or(ElfError::UnknownSymbol(sym.st_name))?;
                    let hash = if sym.is_function() && sym.st_value != 0 {
                        // bpf call
                        if !text_section.vm_range().contains(&(sym.st_value as usize)) {
                            return Err(ElfError::OutOfBounds);
                        }
                        let target_pc =
                            (sym.st_value - text_section.sh_addr) as usize / ebpf::INSN_SIZE;
                        register_bpf_function(bpf_functions, target_pc, name)?
                    } else {
                        // syscall
                        let hash = syscall_cache
                            .entry(sym.st_name)
                            .or_insert_with(|| (ebpf::hash_symbol_name(name.as_bytes()), name))
                            .0;
                        if config.reject_unresolved_syscalls
                            && syscall_registry.lookup_syscall(hash).is_none()
                        {
                            return Err(ElfError::UnresolvedSymbol(
                                name.to_string(),
                                r_offset / ebpf::INSN_SIZE + ebpf::ELF_INSN_DUMP_OFFSET,
                                r_offset,
                            ));
                        }
                        hash
                    };
                    let mut checked_slice = elf_bytes
                        .get_mut(imm_offset..imm_offset.saturating_add(BYTE_LENGTH_IMMEIDATE))
                        .ok_or(ElfError::OutOfBounds)?;
                    LittleEndian::write_u32(&mut checked_slice, hash);
                }
                _ => return Err(ElfError::UnknownRelocation(relocation.r_type)),
            }
        }

        // Save hashed syscall names for debugging
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
                return Err(ElfError::OutOfBounds);
            }
            let target_pc = (symbol.st_value - text_section.sh_addr) as usize / ebpf::INSN_SIZE;
            let name = elf
                .strtab
                .get_at(symbol.st_name)
                .ok_or(ElfError::UnknownSymbol(symbol.st_name))?;
            register_bpf_function(bpf_functions, target_pc, name)?;
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
    type ElfExecutable = EBpfElf<UserError, TestInstructionMeter>;

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

        ElfExecutable::validate(&parsed_elf, &elf_bytes).expect("validation failed");
        parsed_elf.header.e_ident[EI_CLASS] = ELFCLASS32;
        ElfExecutable::validate(&parsed_elf, &elf_bytes).expect_err("allowed bad class");
        parsed_elf.header.e_ident[EI_CLASS] = ELFCLASS64;
        ElfExecutable::validate(&parsed_elf, &elf_bytes).expect("validation failed");
        parsed_elf.header.e_ident[EI_DATA] = ELFDATA2MSB;
        ElfExecutable::validate(&parsed_elf, &elf_bytes).expect_err("allowed big endian");
        parsed_elf.header.e_ident[EI_DATA] = ELFDATA2LSB;
        ElfExecutable::validate(&parsed_elf, &elf_bytes).expect("validation failed");
        parsed_elf.header.e_ident[EI_OSABI] = 1;
        ElfExecutable::validate(&parsed_elf, &elf_bytes).expect_err("allowed wrong abi");
        parsed_elf.header.e_ident[EI_OSABI] = ELFOSABI_NONE;
        ElfExecutable::validate(&parsed_elf, &elf_bytes).expect("validation failed");
        parsed_elf.header.e_machine = EM_QDSP6;
        ElfExecutable::validate(&parsed_elf, &elf_bytes).expect_err("allowed wrong machine");
        parsed_elf.header.e_machine = EM_BPF;
        ElfExecutable::validate(&parsed_elf, &elf_bytes).expect("validation failed");
        parsed_elf.header.e_type = ET_REL;
        ElfExecutable::validate(&parsed_elf, &elf_bytes).expect_err("allowed wrong type");
        parsed_elf.header.e_type = ET_DYN;
        ElfExecutable::validate(&parsed_elf, &elf_bytes).expect("validation failed");
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
        let executable: &dyn Executable<UserError, TestInstructionMeter> = &elf;
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
        let executable: &dyn Executable<UserError, TestInstructionMeter> = &elf;
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
        let executable: &dyn Executable<UserError, TestInstructionMeter> = &elf;
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
        let mut bpf_functions: BTreeMap<u32, (usize, String)> = BTreeMap::new();
        #[rustfmt::skip]
        let mut prog = vec![
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x85, 0x10, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff];

        ElfExecutable::fixup_relative_calls(&mut bpf_functions, &mut prog).unwrap();
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
        let mut bpf_functions: BTreeMap<u32, (usize, String)> = BTreeMap::new();
        prog.splice(44.., vec![0xfa, 0xff, 0xff, 0xff]);
        ElfExecutable::fixup_relative_calls(&mut bpf_functions, &mut prog).unwrap();
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
        let mut bpf_functions: BTreeMap<u32, (usize, String)> = BTreeMap::new();
        #[rustfmt::skip]
        let mut prog = vec![
            0x85, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        ElfExecutable::fixup_relative_calls(&mut bpf_functions, &mut prog).unwrap();
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
        let mut bpf_functions: BTreeMap<u32, (usize, String)> = BTreeMap::new();
        prog.splice(4..8, vec![0x04, 0x00, 0x00, 0x00]);
        ElfExecutable::fixup_relative_calls(&mut bpf_functions, &mut prog).unwrap();
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
        let mut bpf_functions: BTreeMap<u32, (usize, String)> = BTreeMap::new();
        // call +5
        #[rustfmt::skip]
        let mut prog = vec![
            0x85, 0x10, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        ElfExecutable::fixup_relative_calls(&mut bpf_functions, &mut prog).unwrap();
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
        let mut bpf_functions: BTreeMap<u32, (usize, String)> = BTreeMap::new();
        // call -7
        #[rustfmt::skip]
        let mut prog = vec![
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x85, 0x10, 0x00, 0x00, 0xf9, 0xff, 0xff, 0xff];

        ElfExecutable::fixup_relative_calls(&mut bpf_functions, &mut prog).unwrap();
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
}
