//! This module relocates a BPF ELF

// Note: Typically ELF shared objects are loaded using the program headers and
// not the section headers.  Since we are leveraging the elfkit crate its much
// easier to use the section headers.  There are cases (reduced size, obfuscation)
// where the section headers may be removed from the ELF.  If that happens then
// this loader will need to be re-written to use the program headers instead.

extern crate goblin;
extern crate scroll;

use crate::{
    ebpf,
    error::{EbpfError, UserDefinedError},
    jit::{compile, JitProgram},
    vm::{Config, Executable, InstructionMeter, SyscallRegistry},
};
use byteorder::{ByteOrder, LittleEndian};
use goblin::{
    elf::{header::*, reloc::*, section_header::*, Elf},
    error::Error as GoblinError,
};
use std::{collections::HashMap, fmt::Debug, mem, ops::Range, str};

/// Error definitions
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ELFError {
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
    /// Relocation hash collision
    #[error("Relocation hash collision while encoding instruction #{0}")]
    RelocationHashCollision(usize),
    /// Incompatible ELF: wrong endianess
    #[error("Incompatible ELF: wrong endianess")]
    WrongEndianess,
    /// Incompatible ELF: wrong ABI
    #[error("Incompatible ELF: wrong ABI")]
    WrongABI,
    /// Incompatible ELF: wrong mchine
    #[error("Incompatible ELF: wrong machine")]
    WrongMachine,
    /// Incompatible ELF: wrong class
    #[error("Incompatible ELF: wrong class")]
    WrongClass,
    /// Multiple text sections
    #[error("Multiple text sections, consider removing llc option: -function-sections")]
    MultipleTextSections,
    /// .bss section mot supported
    #[error(".bss section not supported")]
    BSSNotSupported,
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
impl From<GoblinError> for ELFError {
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
        ELFError::from(error).into()
    }
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
enum BPFRelocationType {
    /// No relocation, placeholder
    R_BPF_NONE = 0,
    /// 64 bit relocation of a ldxdw instruction.
    /// The ldxdw instruction occupies two instruction slots. The 64-bit address
    /// to load from is split into the 32-bit imm field of each slot. The first
    /// slot's pre-relocation imm field contains the virtual address (typically same
    /// as the file offset) of the location to load. Relocation involves calculating
    /// the post-load 64-bit physical address referenced by the imm field and writing
    /// that physical address back into the imm fields of the ldxdw instruction.
    R_BPF_64_RELATIVE = 8,
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
    R_BPF_64_32 = 10,
}
impl BPFRelocationType {
    fn from_x86_relocation_type(from: u32) -> Option<BPFRelocationType> {
        match from {
            R_X86_64_NONE => Some(BPFRelocationType::R_BPF_NONE),
            R_X86_64_RELATIVE => Some(BPFRelocationType::R_BPF_64_RELATIVE),
            R_X86_64_32 => Some(BPFRelocationType::R_BPF_64_32),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq)]
struct SectionInfo {
    vaddr: u64,
    offset_range: Range<usize>,
}

/// Elf loader/relocator
#[derive(Debug, PartialEq)]
pub struct EBpfElf<E: UserDefinedError, I: InstructionMeter> {
    /// Configuration settings
    config: Config,
    /// Loaded and executable elf
    elf_bytes: Vec<u8>,
    /// Entrypoint instruction offset
    entrypoint: usize,
    /// Text section info
    text_section_info: SectionInfo,
    /// Read-only section info
    ro_section_infos: Vec<SectionInfo>,
    /// Call resolution map
    calls: HashMap<u32, usize>,
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
    fn get_text_bytes(&self) -> Result<(u64, &[u8]), EbpfError<E>> {
        Ok((
            self.text_section_info.vaddr,
            &self
                .elf_bytes
                .get(self.text_section_info.offset_range.clone())
                .ok_or(ELFError::OutOfBounds)?,
        ))
    }

    /// Get a vector of virtual addresses for each read-only section
    fn get_ro_sections(&self) -> Result<Vec<(u64, &[u8])>, EbpfError<E>> {
        self.ro_section_infos
            .iter()
            .map(|section_info| {
                Ok((
                    section_info.vaddr,
                    self.elf_bytes
                        .get(section_info.offset_range.clone())
                        .ok_or(ELFError::OutOfBounds)?,
                ))
            })
            .collect::<Result<Vec<_>, EbpfError<E>>>()
    }

    /// Get the entry point offset into the text section
    fn get_entrypoint_instruction_offset(&self) -> Result<usize, EbpfError<E>> {
        Ok(self.entrypoint)
    }

    /// Get a symbol's instruction offset
    fn lookup_bpf_call(&self, hash: u32) -> Option<&usize> {
        self.calls.get(&hash)
    }

    /// Get the syscall registry
    fn get_syscall_registry(&self) -> &SyscallRegistry {
        &self.syscall_registry
    }

    /// Set (overwrite) the syscall registry
    fn set_syscall_registry(&mut self, syscall_registry: SyscallRegistry) {
        self.syscall_registry = syscall_registry;
    }

    /// Get the JIT compiled program
    fn get_compiled_program(&self) -> Option<&JitProgram<E, I>> {
        self.compiled_program.as_ref()
    }

    /// JIT compile the executable
    fn jit_compile(&mut self) -> Result<(), EbpfError<E>> {
        self.compiled_program = Some(compile::<E, I>(self)?);
        Ok(())
    }

    /// Report information on a symbol that failed to be resolved
    fn report_unresolved_symbol(&self, insn_offset: usize) -> Result<(), EbpfError<E>> {
        let file_offset = insn_offset
            .saturating_mul(ebpf::INSN_SIZE)
            .saturating_add(self.text_section_info.offset_range.start as usize);

        let mut name = "Unknown";
        if let Ok(elf) = Elf::parse(&self.elf_bytes) {
            for relocation in &elf.dynrels {
                if let Some(BPFRelocationType::R_BPF_64_32) =
                    BPFRelocationType::from_x86_relocation_type(relocation.r_type)
                {
                    if relocation.r_offset as usize == file_offset {
                        let sym = elf
                            .dynsyms
                            .get(relocation.r_sym)
                            .ok_or(ELFError::UnknownSymbol(relocation.r_sym))?;
                        name = elf
                            .dynstrtab
                            .get(sym.st_name)
                            .ok_or(ELFError::UnknownSymbol(sym.st_name))?
                            .map_err(|_| ELFError::UnknownSymbol(sym.st_name))?;
                    }
                }
            }
        }
        Err(ELFError::UnresolvedSymbol(
            name.to_string(),
            file_offset / ebpf::INSN_SIZE + ebpf::ELF_INSN_DUMP_OFFSET,
            file_offset,
        )
        .into())
    }
}

impl<'a, E: UserDefinedError, I: InstructionMeter> EBpfElf<E, I> {
    /// Create from raw text section bytes (list of instructions)
    pub fn new_from_text_bytes(config: Config, text_bytes: &[u8]) -> Self {
        Self {
            config,
            elf_bytes: text_bytes.to_vec(),
            entrypoint: 0,
            text_section_info: SectionInfo {
                vaddr: ebpf::MM_PROGRAM_START,
                offset_range: Range {
                    start: 0,
                    end: text_bytes.len(),
                },
            },
            ro_section_infos: vec![],
            calls: HashMap::default(),
            syscall_registry: SyscallRegistry::default(),
            compiled_program: None,
        }
    }

    /// Fully loads an ELF, including validation and relocation
    pub fn load(config: Config, bytes: &[u8]) -> Result<Self, ELFError> {
        let elf = Elf::parse(bytes)?;
        let mut elf_bytes = bytes.to_vec();
        Self::validate(&elf, &elf_bytes)?;

        let mut calls = HashMap::default();
        Self::relocate(&elf, &mut elf_bytes, &mut calls)?;

        let text_section = Self::get_section(&elf, ".text")?;

        // calculate entrypoint offset into the text section
        let offset = elf.header.e_entry - text_section.sh_addr;
        if offset % ebpf::INSN_SIZE as u64 != 0 {
            return Err(ELFError::InvalidEntrypoint);
        }
        let entrypoint = offset as usize / ebpf::INSN_SIZE;

        // calculate the text section info
        let text_section_info = SectionInfo {
            vaddr: text_section.sh_addr.saturating_add(ebpf::MM_PROGRAM_START),
            offset_range: text_section.file_range(),
        };

        // calculate the read-only section infos
        let ro_section_infos = elf
            .section_headers
            .iter()
            .filter_map(|section_header| {
                if let Some(Ok(this_name)) = elf.shdr_strtab.get(section_header.sh_name) {
                    if this_name == ".rodata"
                        || this_name == ".data.rel.ro"
                        || this_name == ".eh_frame"
                    {
                        return Some(SectionInfo {
                            vaddr: section_header
                                .sh_addr
                                .saturating_add(ebpf::MM_PROGRAM_START),
                            offset_range: section_header.file_range(),
                        });
                    }
                }
                None
            })
            .collect();

        Ok(Self {
            config,
            elf_bytes,
            entrypoint,
            text_section_info,
            ro_section_infos,
            calls,
            syscall_registry: SyscallRegistry::default(),
            compiled_program: None,
        })
    }

    // Functions exposed for tests

    /// Fix-ups relative calls
    pub fn fixup_relative_calls(
        calls: &mut HashMap<u32, usize>,
        elf_bytes: &mut [u8],
    ) -> Result<(), ELFError> {
        for i in 0..elf_bytes.len() / ebpf::INSN_SIZE {
            let mut insn = ebpf::get_insn(elf_bytes, i);
            if insn.opc == 0x85 && insn.imm != -1 {
                let insn_idx = i as isize + 1 + insn.imm as isize;
                if insn_idx < 0 || insn_idx >= (elf_bytes.len() / ebpf::INSN_SIZE) as isize {
                    return Err(ELFError::RelativeJumpOutOfBounds(
                        i + ebpf::ELF_INSN_DUMP_OFFSET,
                    ));
                }
                // use the instruction index as the key
                let mut key = [0u8; mem::size_of::<i64>()];
                LittleEndian::write_u64(&mut key, i as u64);
                let hash = ebpf::hash_symbol_name(&key);
                if calls.insert(hash, insn_idx as usize).is_some() {
                    return Err(ELFError::RelocationHashCollision(
                        i + ebpf::ELF_INSN_DUMP_OFFSET,
                    ));
                }

                insn.imm = hash as i32;
                let checked_slice = elf_bytes
                    .get_mut(i * ebpf::INSN_SIZE..(i * ebpf::INSN_SIZE) + ebpf::INSN_SIZE)
                    .ok_or(ELFError::OutOfBounds)?;
                checked_slice.copy_from_slice(&insn.to_vec());
            }
        }
        Ok(())
    }

    /// Validates the ELF
    pub fn validate(elf: &Elf, elf_bytes: &[u8]) -> Result<(), ELFError> {
        if elf.header.e_ident[EI_CLASS] != ELFCLASS64 {
            return Err(ELFError::WrongClass);
        }
        if elf.header.e_ident[EI_DATA] != ELFDATA2LSB {
            return Err(ELFError::WrongEndianess);
        }
        if elf.header.e_ident[EI_OSABI] != ELFOSABI_NONE {
            return Err(ELFError::WrongABI);
        }
        if elf.header.e_machine != EM_BPF {
            return Err(ELFError::WrongMachine);
        }
        if elf.header.e_type != ET_DYN {
            return Err(ELFError::WrongType);
        }

        let num_text_sections = elf.section_headers.iter().fold(0, |count, section_header| {
            if let Some(Ok(this_name)) = elf.shdr_strtab.get(section_header.sh_name) {
                if this_name == ".text" {
                    return count + 1;
                }
            }
            count
        });
        if 1 != num_text_sections {
            return Err(ELFError::MultipleTextSections);
        }

        for section_header in elf.section_headers.iter() {
            if let Some(Ok(this_name)) = elf.shdr_strtab.get(section_header.sh_name) {
                if this_name == ".bss" {
                    return Err(ELFError::BSSNotSupported);
                }
            }
        }

        for section_header in &elf.section_headers {
            let start = section_header.sh_offset as usize;
            let end = section_header
                .sh_offset
                .checked_add(section_header.sh_size)
                .ok_or(ELFError::OutOfBounds)? as usize;
            let _ = elf_bytes.get(start..end).ok_or(ELFError::OutOfBounds)?;
        }
        let text_section = Self::get_section(elf, ".text")?;
        if !text_section
            .vm_range()
            .contains(&(elf.header.e_entry as usize))
        {
            return Err(ELFError::EntrypointOutOfBounds);
        }

        Ok(())
    }

    // Private functions

    /// Get a section by name
    fn get_section(elf: &Elf, name: &str) -> Result<SectionHeader, ELFError> {
        match elf.section_headers.iter().find(|section_header| {
            if let Some(Ok(this_name)) = elf.shdr_strtab.get(section_header.sh_name) {
                return this_name == name;
            }
            false
        }) {
            Some(section) => Ok(section.clone()),
            None => Err(ELFError::SectionNotFound(name.to_string())),
        }
    }

    /// Relocates the ELF in-place
    fn relocate(
        elf: &Elf,
        elf_bytes: &mut [u8],
        calls: &mut HashMap<u32, usize>,
    ) -> Result<(), ELFError> {
        let text_section = Self::get_section(elf, ".text")?;

        // Fixup all program counter relative call instructions
        Self::fixup_relative_calls(
            calls,
            &mut elf_bytes
                .get_mut(text_section.file_range())
                .ok_or(ELFError::OutOfBounds)?,
        )?;

        // Fixup all the relocations in the relocation section if exists
        for relocation in &elf.dynrels {
            let r_offset = relocation.r_offset as usize;

            // Offset of the immediate field
            let imm_offset = r_offset.saturating_add(BYTE_OFFSET_IMMEDIATE);
            match BPFRelocationType::from_x86_relocation_type(relocation.r_type) {
                Some(BPFRelocationType::R_BPF_64_RELATIVE) => {
                    // Raw relocation between sections.  The instruction being relocated contains
                    // the virtual address that it needs turned into a physical address.  Read it,
                    // locate it in the ELF, convert to physical address

                    // Read the instruction's immediate field which contains virtual
                    // address to convert to physical
                    let checked_slice = elf_bytes
                        .get(imm_offset..imm_offset.saturating_add(BYTE_LENGTH_IMMEIDATE))
                        .ok_or(ELFError::OutOfBounds)?;
                    let refd_va = LittleEndian::read_u32(&checked_slice) as u64;

                    if refd_va == 0 {
                        return Err(ELFError::InvalidVirtualAddress(refd_va));
                    }

                    // final "physical address" from the VM's perspetive is rooted at `MM_PROGRAM_START`
                    let refd_pa = ebpf::MM_PROGRAM_START.saturating_add(refd_va);

                    // trace!(
                    //     "Relocation section va {:#x} off {:#x} va {:#x} pa {:#x} va {:#x} pa {:#x}",
                    //     section_infos[target_section].va, target_offset, relocation.addr, section_infos[target_section].bytes.as_ptr() as usize + target_offset, refd_va, refd_pa
                    // );

                    // Write the physical address back into the target location
                    if text_section.file_range().contains(&r_offset) {
                        // Instruction lddw spans two instruction slots, split the
                        // physical address into a high and low and write into both slot's imm field

                        let mut checked_slice = elf_bytes
                            .get_mut(imm_offset..imm_offset.saturating_add(BYTE_LENGTH_IMMEIDATE))
                            .ok_or(ELFError::OutOfBounds)?;
                        LittleEndian::write_u32(&mut checked_slice, (refd_pa & 0xFFFFFFFF) as u32);
                        let mut checked_slice = elf_bytes
                            .get_mut(
                                imm_offset.saturating_add(ebpf::INSN_SIZE)
                                    ..imm_offset
                                        .saturating_add(ebpf::INSN_SIZE + BYTE_LENGTH_IMMEIDATE),
                            )
                            .ok_or(ELFError::OutOfBounds)?;
                        LittleEndian::write_u32(&mut checked_slice, (refd_pa >> 32) as u32);
                    } else {
                        // 64 bit memory location, write entire 64 bit physical address directly
                        let mut checked_slice = elf_bytes
                            .get_mut(r_offset..r_offset.saturating_add(mem::size_of::<u64>()))
                            .ok_or(ELFError::OutOfBounds)?;
                        LittleEndian::write_u64(&mut checked_slice, refd_pa);
                    }
                }
                Some(BPFRelocationType::R_BPF_64_32) => {
                    // The .text section has an unresolved call to symbol instruction
                    // Hash the symbol name and stick it into the call instruction's imm
                    // field.  Later that hash will be used to look up the function location.

                    let sym = elf
                        .dynsyms
                        .get(relocation.r_sym)
                        .ok_or(ELFError::UnknownSymbol(relocation.r_sym))?;
                    let name = elf
                        .dynstrtab
                        .get(sym.st_name)
                        .ok_or(ELFError::UnknownSymbol(sym.st_name))?
                        .map_err(|_| ELFError::UnknownSymbol(sym.st_name))?;
                    let hash = ebpf::hash_symbol_name(&name.as_bytes());
                    let mut checked_slice = elf_bytes
                        .get_mut(imm_offset..imm_offset.saturating_add(BYTE_LENGTH_IMMEIDATE))
                        .ok_or(ELFError::OutOfBounds)?;
                    LittleEndian::write_u32(&mut checked_slice, hash);
                    let text_section = Self::get_section(elf, ".text")?;
                    if sym.is_function() && sym.st_value != 0 {
                        if !text_section.vm_range().contains(&(sym.st_value as usize)) {
                            return Err(ELFError::OutOfBounds);
                        }
                        calls.insert(
                            hash,
                            (sym.st_value - text_section.sh_addr) as usize / ebpf::INSN_SIZE,
                        );
                    }
                }
                _ => return Err(ELFError::UnknownRelocation(relocation.r_type)),
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
        ebpf, elf::scroll::Pwrite, fuzz::fuzz, user_error::UserError, vm::DefaultInstructionMeter,
    };
    use rand::{distributions::Uniform, Rng};
    use std::{collections::HashMap, fs::File, io::Read};
    type ElfExecutable = EBpfElf<UserError, DefaultInstructionMeter>;

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
        ElfExecutable::load(Config::default(), &elf_bytes).expect("validation failed");
    }

    #[test]
    fn test_entrypoint() {
        let mut file = File::open("tests/elfs/noop.so").expect("file open failed");
        let mut elf_bytes = Vec::new();
        file.read_to_end(&mut elf_bytes)
            .expect("failed to read elf file");
        let elf = ElfExecutable::load(Config::default(), &elf_bytes).expect("validation failed");
        let mut parsed_elf = Elf::parse(&elf_bytes).unwrap();
        let initial_e_entry = parsed_elf.header.e_entry;
        let executable: &dyn Executable<UserError, DefaultInstructionMeter> = &elf;
        assert_eq!(
            0,
            executable
                .get_entrypoint_instruction_offset()
                .expect("failed to get entrypoint")
        );

        parsed_elf.header.e_entry += 8;
        let mut elf_bytes = elf_bytes.clone();
        elf_bytes.pwrite(parsed_elf.header, 0).unwrap();
        let elf = ElfExecutable::load(Config::default(), &elf_bytes).expect("validation failed");
        let executable: &dyn Executable<UserError, DefaultInstructionMeter> = &elf;
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
            Err(ELFError::EntrypointOutOfBounds),
            ElfExecutable::load(Config::default(), &elf_bytes)
        );

        parsed_elf.header.e_entry = std::u64::MAX;
        let mut elf_bytes = elf_bytes;
        elf_bytes.pwrite(parsed_elf.header, 0).unwrap();
        assert_eq!(
            Err(ELFError::EntrypointOutOfBounds),
            ElfExecutable::load(Config::default(), &elf_bytes)
        );

        parsed_elf.header.e_entry = initial_e_entry + ebpf::INSN_SIZE as u64 + 1;
        let mut elf_bytes = elf_bytes;
        elf_bytes.pwrite(parsed_elf.header, 0).unwrap();
        assert_eq!(
            Err(ELFError::InvalidEntrypoint),
            ElfExecutable::load(Config::default(), &elf_bytes)
        );

        parsed_elf.header.e_entry = initial_e_entry;
        let mut elf_bytes = elf_bytes;
        elf_bytes.pwrite(parsed_elf.header, 0).unwrap();
        let elf = ElfExecutable::load(Config::default(), &elf_bytes).expect("validation failed");
        let executable: &dyn Executable<UserError, DefaultInstructionMeter> = &elf;
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
        let mut calls: HashMap<u32, usize> = HashMap::new();
        #[rustfmt::skip]
        let mut prog = vec![
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x85, 0x10, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff];

        ElfExecutable::fixup_relative_calls(&mut calls, &mut prog).unwrap();
        let key = ebpf::hash_symbol_name(&[5, 0, 0, 0, 0, 0, 0, 0]);
        let insn = ebpf::Insn {
            opc: 0x85,
            dst: 0,
            src: 1,
            off: 0,
            imm: key as i32,
        };
        assert_eq!(insn.to_array(), prog[40..]);
        assert_eq!(*calls.get(&key).unwrap(), 4);

        // // call +6
        let mut calls: HashMap<u32, usize> = HashMap::new();
        prog.splice(44.., vec![0xfa, 0xff, 0xff, 0xff]);
        ElfExecutable::fixup_relative_calls(&mut calls, &mut prog).unwrap();
        let key = ebpf::hash_symbol_name(&[5, 0, 0, 0, 0, 0, 0, 0]);
        let insn = ebpf::Insn {
            opc: 0x85,
            dst: 0,
            src: 1,
            off: 0,
            imm: key as i32,
        };
        assert_eq!(insn.to_array(), prog[40..]);
        assert_eq!(*calls.get(&key).unwrap(), 0);
    }

    #[test]
    fn test_fixup_relative_calls_forward() {
        // call +0
        let mut calls: HashMap<u32, usize> = HashMap::new();
        #[rustfmt::skip]
        let mut prog = vec![
            0x85, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        ElfExecutable::fixup_relative_calls(&mut calls, &mut prog).unwrap();
        let key = ebpf::hash_symbol_name(&[0, 0, 0, 0, 0, 0, 0, 0]);
        let insn = ebpf::Insn {
            opc: 0x85,
            dst: 0,
            src: 1,
            off: 0,
            imm: key as i32,
        };
        assert_eq!(insn.to_array(), prog[..8]);
        assert_eq!(*calls.get(&key).unwrap(), 1);

        // call +4
        let mut calls: HashMap<u32, usize> = HashMap::new();
        prog.splice(4..8, vec![0x04, 0x00, 0x00, 0x00]);
        ElfExecutable::fixup_relative_calls(&mut calls, &mut prog).unwrap();
        let key = ebpf::hash_symbol_name(&[0, 0, 0, 0, 0, 0, 0, 0]);
        let insn = ebpf::Insn {
            opc: 0x85,
            dst: 0,
            src: 1,
            off: 0,
            imm: key as i32,
        };
        assert_eq!(insn.to_array(), prog[..8]);
        assert_eq!(*calls.get(&key).unwrap(), 5);
    }

    #[test]
    #[should_panic(
        expected = "called `Result::unwrap()` on an `Err` value: RelativeJumpOutOfBounds(29)"
    )]
    fn test_fixup_relative_calls_out_of_bounds_forward() {
        let mut calls: HashMap<u32, usize> = HashMap::new();
        // call +5
        #[rustfmt::skip]
        let mut prog = vec![
            0x85, 0x10, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        ElfExecutable::fixup_relative_calls(&mut calls, &mut prog).unwrap();
        let key = ebpf::hash_symbol_name(&[0]);
        let insn = ebpf::Insn {
            opc: 0x85,
            dst: 0,
            src: 1,
            off: 0,
            imm: key as i32,
        };
        assert_eq!(insn.to_array(), prog[..8]);
        assert_eq!(*calls.get(&key).unwrap(), 1);
    }

    #[test]
    #[should_panic(
        expected = "called `Result::unwrap()` on an `Err` value: RelativeJumpOutOfBounds(34)"
    )]
    fn test_fixup_relative_calls_out_of_bounds_back() {
        let mut calls: HashMap<u32, usize> = HashMap::new();
        // call -7
        #[rustfmt::skip]
        let mut prog = vec![
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x85, 0x10, 0x00, 0x00, 0xf9, 0xff, 0xff, 0xff];

        ElfExecutable::fixup_relative_calls(&mut calls, &mut prog).unwrap();
        let key = ebpf::hash_symbol_name(&[5]);
        let insn = ebpf::Insn {
            opc: 0x85,
            dst: 0,
            src: 1,
            off: 0,
            imm: key as i32,
        };
        assert_eq!(insn.to_array(), prog[40..]);
        assert_eq!(*calls.get(&key).unwrap(), 4);
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
            let _ = ElfExecutable::load(Config::default(), &elf_bytes);
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
                let _ = ElfExecutable::load(Config::default(), bytes);
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
                let _ = ElfExecutable::load(Config::default(), bytes);
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
                let _ = ElfExecutable::load(Config::default(), bytes);
            },
        );
    }
}
