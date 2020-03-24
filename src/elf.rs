//! This module relocates a BPF ELF

// Note: Typically ELF shared objects are loaded using the program headers and
// not the section headers.  Since we are leveraging the elfkit crate its much
// easier to use the section headers.  There are cases (reduced size, obfuscation)
// where the section headers may be removed from the ELF.  If that happens then
// this loader will need to be re-written to use the program headers instead.

extern crate elfkit;
extern crate num_traits;

use byteorder::{ByteOrder, LittleEndian, ReadBytesExt};
use ebpf;
use elf::num_traits::FromPrimitive;
use std::collections::HashMap;
use std::io::Cursor;
use std::mem;
use std::str;
use thiserror::Error;

/// Error definitions
#[derive(Debug, Error)]
pub enum ELFError {
    /// Failed to parse ELF file
    #[error("Failed to parse ELF file: {0:?}")]
    FailedToParse(elfkit::Error),
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

// Byte offset of the immediate field in the instruction
const BYTE_OFFSET_IMMEDIATE: usize = 4;
// Byte length of the immediate field
const BYTE_LENGTH_IMMEIDATE: usize = 4;
// Index of the text section in the vector of `SectionInfo`s (always the first)
const TEXT_SECTION_INDEX: usize = 0;

/// BPF relocation types.
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum BPFRelocationType {
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

// Describes a section in the ELF and used for editing in place
struct SectionInfo<'a> {
    // Section virtual address as expressed in the ELF
    va: u64,
    // Length of the section in bytes
    len: u64,
    // Reference to the actual section bytes to be edited in place
    bytes: &'a mut Vec<u8>,
}

impl BPFRelocationType {
    fn from_x86_relocation_type(
        from: &elfkit::relocation::RelocationType,
    ) -> Option<BPFRelocationType> {
        match *from {
            elfkit::relocation::RelocationType::R_X86_64_NONE => {
                Some(BPFRelocationType::R_BPF_NONE)
            }
            elfkit::relocation::RelocationType::R_X86_64_RELATIVE => {
                Some(BPFRelocationType::R_BPF_64_RELATIVE)
            }
            elfkit::relocation::RelocationType::R_X86_64_32 => Some(BPFRelocationType::R_BPF_64_32),
            _ => None,
        }
    }
}

/// Elf loader/relocator
pub struct EBpfElf {
    /// Elf representation
    elf: elfkit::Elf,
    calls: HashMap<u32, usize>,
}

impl EBpfElf {
    /// Fully loads an ELF, including validation and relocation
    pub fn load(elf_bytes: &[u8]) -> Result<EBpfElf, ELFError> {
        let mut reader = Cursor::new(elf_bytes);
        let mut elf = match elfkit::Elf::from_reader(&mut reader) {
            Ok(elf) => elf,
            Err(e) => {
                return Err(ELFError::FailedToParse(e));
            }
        };
        if let Err(e) = elf.load_all(&mut reader) {
            return Err(ELFError::FailedToParse(e));
        }
        let mut ebpf_elf = EBpfElf {
            elf,
            calls: HashMap::new(),
        };
        ebpf_elf.validate()?;
        ebpf_elf.relocate()?;
        Ok(ebpf_elf)
    }

    /// Get the .text section virtual address and bytes
    pub fn get_text_bytes(&self) -> Result<(u64, &[u8]), ELFError> {
        Ok(EBpfElf::content_to_bytes(self.get_section(".text")?)?)
    }

    /// Get a vector of virtual addresses for each read-only section
    pub fn get_ro_sections(&self) -> Result<Vec<(u64, &[u8])>, ELFError> {
        self.elf
            .sections
            .iter()
            .filter(|section| {
                section.name == b".rodata"
                    || section.name == b".data.rel.ro"
                    || section.name == b".eh_frame"
            })
            .map(EBpfElf::content_to_bytes)
            .collect()
    }

    /// Get the entry point offset into the text section
    pub fn get_entrypoint_instruction_offset(&self) -> Result<usize, ELFError> {
        let entry = self.elf.header.entry;
        let text = self.get_section(".text")?;
        if entry < text.header.addr || entry > text.header.addr + text.header.size {
            return Err(ELFError::EntrypointOutOfBounds);
        }
        let offset = (entry - text.header.addr) as usize;
        if offset % ebpf::INSN_SIZE != 0 {
            return Err(ELFError::InvalidEntrypoint);
        }
        Ok(offset / ebpf::INSN_SIZE)
    }

    /// Get a symbol's instruction offset
    pub fn lookup_bpf_call(&self, hash: u32) -> Option<&usize> {
        self.calls.get(&hash)
    }

    /// Report information on a symbol that failed to be resolved
    pub fn report_unresolved_symbol(&self, insn_offset: usize) -> Result<(), ELFError> {
        let file_offset =
            insn_offset * ebpf::INSN_SIZE + self.get_section(".text")?.header.addr as usize;

        let symbols = match self.get_section(".dynsym")?.content {
            elfkit::SectionContent::Symbols(ref bytes) => bytes,
            _ => {
                return Err(ELFError::FailedToGetSection(".dynsym".to_string()));
            }
        };

        let raw_relocation_bytes = match self.get_section(".rel.dyn")?.content {
            elfkit::SectionContent::Raw(ref bytes) => bytes,
            _ => return Err(ELFError::FailedToGetSection(".rel.dyn".to_string())),
        };
        let relocations = EBpfElf::get_relocations(&raw_relocation_bytes[..])?;

        let mut name = "Unknown";
        for relocation in relocations.iter() {
            match BPFRelocationType::from_x86_relocation_type(&relocation.rtype) {
                Some(BPFRelocationType::R_BPF_64_32) => {
                    if relocation.addr as usize == file_offset {
                        name = match str::from_utf8(&symbols[relocation.sym as usize].name) {
                            Ok(string) => string,
                            Err(_) => "Malformed symbol name",
                        };
                    }
                }
                _ => (),
            }
        }
        Err(ELFError::UnresolvedSymbol(
            name.to_string(),
            file_offset / ebpf::INSN_SIZE + ebpf::ELF_INSN_DUMP_OFFSET,
            file_offset,
        ))
    }

    fn get_section(&self, name: &str) -> Result<&elfkit::Section, ELFError> {
        match self
            .elf
            .sections
            .iter()
            .find(|section| section.name == name.as_bytes())
        {
            Some(section) => Ok(section),
            None => Err(ELFError::SectionNotFound(name.to_string())),
        }
    }

    /// Converts a section's raw contents to a slice
    fn content_to_bytes(section: &elfkit::section::Section) -> Result<(u64, &[u8]), ELFError> {
        match section.content {
            elfkit::SectionContent::Raw(ref bytes) => {
                Ok((ebpf::MM_PROGRAM_START + section.header.addr, bytes))
            }
            _ => Err(ELFError::FailedToGetSection(
                std::str::from_utf8(&section.name)
                    .unwrap_or("Invalid UTF8 section name")
                    .to_string(),
            )),
        }
    }

    fn fixup_relative_calls(
        calls: &mut HashMap<u32, usize>,
        prog: &mut Vec<u8>,
    ) -> Result<(), ELFError> {
        for i in 0..prog.len() / ebpf::INSN_SIZE {
            let mut insn = ebpf::get_insn(prog, i);
            if insn.opc == 0x85 && insn.imm != -1 {
                let insn_idx = (i as i32 + 1 + insn.imm) as isize;
                if insn_idx < 0 || insn_idx as usize >= prog.len() / ebpf::INSN_SIZE {
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
                prog.splice(
                    i * ebpf::INSN_SIZE..(i * ebpf::INSN_SIZE) + ebpf::INSN_SIZE,
                    insn.to_vec(),
                );
            }
        }
        Ok(())
    }

    /// Validates the ELF
    fn validate(&self) -> Result<(), ELFError> {
        // Validate header
        if self.elf.header.ident_class != elfkit::types::Class::Class64 {
            return Err(ELFError::WrongClass);
        }
        if self.elf.header.ident_endianness != elfkit::types::Endianness::LittleEndian {
            return Err(ELFError::WrongEndianess);
        }
        if self.elf.header.ident_abi != elfkit::types::Abi::SYSV {
            return Err(ELFError::WrongABI);
        }
        if self.elf.header.machine != elfkit::types::Machine::BPF {
            return Err(ELFError::WrongMachine);
        }
        if self.elf.header.etype != elfkit::types::ElfType::DYN {
            return Err(ELFError::WrongClass);
        }

        let text_sections: Vec<_> = self
            .elf
            .sections
            .iter()
            .filter(|section| section.name.starts_with(b".text"))
            .collect();
        if text_sections.len() > 1 {
            return Err(ELFError::MultipleTextSections);
        }

        if self
            .elf
            .sections
            .iter()
            .any(|section| section.name.starts_with(b".bss"))
        {
            return Err(ELFError::BSSNotSupported);
        }

        Ok(())
    }

    // Splits sections from the elf structure so that they may be edited concurrently and in place
    fn split_sections(sections: &mut [elfkit::Section]) -> Vec<&mut elfkit::Section> {
        let mut section_refs = Vec::new();
        if !sections.is_empty() {
            let (s, rest) = sections.split_at_mut(1);
            section_refs.push(&mut s[0]);
            section_refs.append(&mut EBpfElf::split_sections(rest));
        }
        section_refs
    }

    // Gets a mutable reference to a split section by name
    fn get_section_ref<'a, 'b>(
        sections: &'b mut Vec<&'a mut elfkit::Section>,
        name: &str,
    ) -> Result<&'a mut elfkit::Section, ELFError> {
        match sections
            .iter()
            .enumerate()
            .find(|section| section.1.name == name.as_bytes())
        {
            Some((index, _)) => Ok(sections.remove(index)),
            None => Err(ELFError::SectionNotFound(name.to_string())),
        }
    }

    /// Creates a vector of load sections used to lookup which section
    /// contains a particular ELF virtual address
    fn get_load_sections<'a, 'b>(
        sections: &'a mut Vec<&'b mut elfkit::Section>,
    ) -> Result<Vec<SectionInfo<'b>>, ELFError> {
        let mut section_infos = Vec::new();

        // .text section mandatory
        let mut section = EBpfElf::get_section_ref(sections, ".text")?;
        match (&mut section.content).as_raw_mut() {
            Some(bytes) => {
                section_infos.push(SectionInfo {
                    va: section.header.addr,
                    len: section.header.size,
                    bytes: bytes,
                });
            }
            None => {
                return Err(ELFError::FailedToGetSection(".text".to_string()));
            }
        };

        // .rodata section optional
        let mut section = EBpfElf::get_section_ref(sections, ".rodata");
        if let Ok(section) = section {
            match (&mut section.content).as_raw_mut() {
                Some(bytes) => {
                    section_infos.push(SectionInfo {
                        va: section.header.addr,
                        len: section.header.size,
                        bytes: bytes,
                    });
                }
                None => (),
            };
        }

        // .data.rel.ro optional
        let mut section = EBpfElf::get_section_ref(sections, ".data.rel.ro");
        if let Ok(section) = section {
            match (&mut section.content).as_raw_mut() {
                Some(bytes) => {
                    section_infos.push(SectionInfo {
                        va: section.header.addr,
                        len: section.header.size,
                        bytes: bytes,
                    });
                }
                None => (),
            };
        }

        // .eh_frame optional
        let mut section = EBpfElf::get_section_ref(sections, ".eh_frame");
        if let Ok(section) = section {
            match (&mut section.content).as_raw_mut() {
                Some(bytes) => {
                    section_infos.push(SectionInfo {
                        va: section.header.addr,
                        len: section.header.size,
                        bytes: bytes,
                    });
                }
                None => (),
            };
        }

        Ok(section_infos)
    }

    /// Relocates the ELF in-place
    fn relocate(&mut self) -> Result<(), ELFError> {
        // Split and build a mutable list of sections
        let mut sections = EBpfElf::split_sections(&mut self.elf.sections);
        let mut section_infos = EBpfElf::get_load_sections(&mut sections)?;

        // Fixup all program counter relative call instructions
        EBpfElf::fixup_relative_calls(&mut self.calls, &mut section_infos[0].bytes)?;

        // Fixup all the relocations in the relocation section if exists
        let relocations = match EBpfElf::get_section_ref(&mut sections, ".rel.dyn") {
            Ok(rel_dyn_section) => match (&mut rel_dyn_section.content).as_raw_mut() {
                Some(bytes) => Some(EBpfElf::get_relocations(&bytes[..])?),
                _ => None,
            },
            Err(_) => None,
        };

        if let Some(relocations) = relocations {
            // Get the symbol table up front
            let dynsym_section = EBpfElf::get_section_ref(&mut sections, ".dynsym")?;
            let symbols = match (&dynsym_section.content).as_symbols() {
                Some(bytes) => bytes,
                None => return Err(ELFError::FailedToGetSection(".dynsym".to_string())),
            };

            for relocation in relocations.iter() {
                match BPFRelocationType::from_x86_relocation_type(&relocation.rtype) {
                    Some(BPFRelocationType::R_BPF_64_RELATIVE) => {
                        // Raw relocation between sections.  The instruction being relocated contains
                        // the virtual address that it needs turned into a physical address.  Read it,
                        // locate it in the ELF, convert to physical address

                        let mut target_section = None;
                        for (i, info) in section_infos.iter().enumerate() {
                            if info.va <= relocation.addr && relocation.addr < info.va + info.len {
                                target_section = Some(i);
                                break;
                            }
                        }
                        let target_section = match target_section {
                            Some(i) => i,
                            None => {
                                return Err(ELFError::AddressOutsideLoadableSection(
                                    relocation.addr,
                                ))
                            }
                        };

                        // Offset into the section being relocated
                        let target_offset =
                            (relocation.addr - section_infos[target_section].va) as usize;

                        // Offset of the immediate field
                        let mut imm_offset = target_offset + BYTE_OFFSET_IMMEDIATE;

                        // Read the instruction's immediate field which contains virtual
                        // address to convert to physical
                        let refd_va = LittleEndian::read_u32(
                            &section_infos[target_section].bytes
                                [imm_offset..imm_offset + BYTE_LENGTH_IMMEIDATE],
                        ) as u64;

                        if refd_va == 0 {
                            return Err(ELFError::InvalidVirtualAddress(refd_va));
                        }

                        // final "physical address" from the VM's perspetive is rooted at `MM_PROGRAM_START`
                        let refd_pa = ebpf::MM_PROGRAM_START + refd_va;

                        // trace!(
                        //     "Relocation section va {:#x} off {:#x} va {:#x} pa {:#x} va {:#x} pa {:#x}",
                        //     section_infos[target_section].va, target_offset, relocation.addr, section_infos[target_section].bytes.as_ptr() as usize + target_offset, refd_va, refd_pa
                        // );

                        // Write the physical address back into the target location
                        if target_section == TEXT_SECTION_INDEX {
                            // Instruction lddw spans two instruction slots, split the
                            // physical address into a high and low and write into both slot's imm field

                            LittleEndian::write_u32(
                                &mut section_infos[target_section].bytes
                                    [imm_offset..imm_offset + BYTE_LENGTH_IMMEIDATE],
                                (refd_pa & 0xFFFFFFFF) as u32,
                            );
                            LittleEndian::write_u32(
                                &mut section_infos[target_section].bytes[imm_offset
                                    + ebpf::INSN_SIZE
                                    ..imm_offset + ebpf::INSN_SIZE + BYTE_LENGTH_IMMEIDATE],
                                (refd_pa >> 32) as u32,
                            );
                        } else {
                            // 64 bit memory location, write entire 64 bit physical address directly
                            LittleEndian::write_u64(
                                &mut section_infos[target_section].bytes
                                    [target_offset..target_offset + mem::size_of::<u64>()],
                                refd_pa,
                            );
                        }
                    }
                    Some(BPFRelocationType::R_BPF_64_32) => {
                        // The .text section has an unresolved call to symbol instruction

                        // Hash the symbol name and stick it into the call instruction's imm
                        // field.  Later that hash will be used to look up the function location.

                        let symbol = &symbols[relocation.sym as usize];
                        let hash = ebpf::hash_symbol_name(&symbol.name);
                        let insn_offset = (relocation.addr - section_infos[0].va) as usize;
                        let imm_offset = insn_offset + BYTE_OFFSET_IMMEDIATE;
                        LittleEndian::write_u32(
                            &mut section_infos[0].bytes
                                [imm_offset..imm_offset + BYTE_LENGTH_IMMEIDATE],
                            hash,
                        );
                        if symbol.stype == elfkit::types::SymbolType::FUNC && symbol.value != 0 {
                            self.calls.insert(
                                hash,
                                (symbol.value - section_infos[0].va) as usize / ebpf::INSN_SIZE,
                            );
                        }
                    }
                    _ => return Err(ELFError::UnknownRelocation(relocation.rtype.clone() as u32)),
                }
            }
        }

        Ok(())
    }

    /// Builds a vector of Relocations from raw bytes
    ///
    /// Elfkit does not form BPF relocations and instead just provides raw bytes
    fn get_relocations<R>(mut io: R) -> Result<Vec<elfkit::Relocation>, ELFError>
    where
        R: std::io::Read,
    {
        let mut relocs = Vec::new();

        while let Ok(addr) = io.read_u64::<LittleEndian>() {
            let info = match io.read_u64::<LittleEndian>() {
                Ok(v) => v,
                _ => {
                    return Err(ELFError::FailedToReadRelocationInfo);
                }
            };

            let sym = (info >> 32) as u32;
            let rtype = (info & 0xffffffff) as u32;
            let rtype = match elfkit::relocation::RelocationType::from_u32(rtype) {
                Some(v) => v,
                None => return Err(ELFError::UnknownRelocation(rtype)),
            };

            let addend = 0; // BPF relocation don't have an addend

            relocs.push(elfkit::relocation::Relocation {
                addr,
                sym,
                rtype,
                addend,
            });
        }

        Ok(relocs)
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
                eight_bytes.push(i.clone());
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::fs::File;
    use std::io::Read;

    #[test]
    fn test_validate() {
        let mut file = File::open("tests/elfs/noop.so").expect("file open failed");
        let mut elf_bytes = Vec::new();
        file.read_to_end(&mut elf_bytes)
            .expect("failed to read elf file");
        let mut elf = EBpfElf::load(&elf_bytes).unwrap();

        elf.validate().expect("validation failed");
        elf.elf.header.ident_class = elfkit::types::Class::Class32;
        elf.validate().expect_err("allowed bad class");
        elf.elf.header.ident_class = elfkit::types::Class::Class64;
        elf.validate().expect("validation failed");
        elf.elf.header.ident_endianness = elfkit::types::Endianness::BigEndian;
        elf.validate().expect_err("allowed big endian");
        elf.elf.header.ident_endianness = elfkit::types::Endianness::LittleEndian;
        elf.validate().expect("validation failed");
        elf.elf.header.ident_abi = elfkit::types::Abi::ARM;
        elf.validate().expect_err("allowed wrong abi");
        elf.elf.header.ident_abi = elfkit::types::Abi::SYSV;
        elf.validate().expect("validation failed");
        elf.elf.header.machine = elfkit::types::Machine::QDSP6;
        elf.validate().expect_err("allowed wrong machine");
        elf.elf.header.machine = elfkit::types::Machine::BPF;
        elf.validate().expect("validation failed");
        elf.elf.header.etype = elfkit::types::ElfType::REL;
        elf.validate().expect_err("allowed wrong type");
        elf.elf.header.etype = elfkit::types::ElfType::DYN;
        elf.validate().expect("validation failed");
    }

    #[test]
    fn test_relocate() {
        let mut file = File::open("tests/elfs/noop.so").expect("file open failed");
        let mut elf_bytes = Vec::new();
        file.read_to_end(&mut elf_bytes)
            .expect("failed to read elf file");
        EBpfElf::load(&elf_bytes).expect("validation failed");
    }

    #[test]
    fn test_entrypoint() {
        let mut file = File::open("tests/elfs/noop.so").expect("file open failed");
        let mut elf_bytes = Vec::new();
        file.read_to_end(&mut elf_bytes)
            .expect("failed to read elf file");
        let mut elf = EBpfElf::load(&elf_bytes).expect("validation failed");

        assert_eq!(
            0,
            elf.get_entrypoint_instruction_offset()
                .expect("failed to get entrypoint")
        );
        elf.elf.header.entry = elf.elf.header.entry + 8;
        assert_eq!(
            1,
            elf.get_entrypoint_instruction_offset()
                .expect("failed to get entrypoint")
        );
    }

    #[test]
    #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: EntrypointOutOfBounds")]
    fn test_entrypoint_before_text() {
        let mut file = File::open("tests/elfs/noop.so").expect("file open failed");
        let mut elf_bytes = Vec::new();
        file.read_to_end(&mut elf_bytes)
            .expect("failed to read elf file");
        let mut elf = EBpfElf::load(&elf_bytes).expect("validation failed");

        elf.elf.header.entry = 1;
        elf.get_entrypoint_instruction_offset().unwrap();
    }

    #[test]
    #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: EntrypointOutOfBounds")]
    fn test_entrypoint_after_text() {
        let mut file = File::open("tests/elfs/noop.so").expect("file open failed");
        let mut elf_bytes = Vec::new();
        file.read_to_end(&mut elf_bytes)
            .expect("failed to read elf file");
        let mut elf = EBpfElf::load(&elf_bytes).expect("validation failed");

        elf.elf.header.entry = 1;
        elf.get_entrypoint_instruction_offset().unwrap();
    }

    #[test]
    #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: InvalidEntrypoint")]
    fn test_entrypoint_not_multiple_of_instruction_size() {
        let mut file = File::open("tests/elfs/noop.so").expect("file open failed");
        let mut elf_bytes = Vec::new();
        file.read_to_end(&mut elf_bytes)
            .expect("failed to read elf file");
        let mut elf = EBpfElf::load(&elf_bytes).expect("validation failed");

        elf.elf.header.entry = elf.elf.header.entry + ebpf::INSN_SIZE as u64 + 1;
        elf.get_entrypoint_instruction_offset().unwrap();
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

        EBpfElf::fixup_relative_calls(&mut calls, &mut prog).unwrap();
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
        EBpfElf::fixup_relative_calls(&mut calls, &mut prog).unwrap();
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

        EBpfElf::fixup_relative_calls(&mut calls, &mut prog).unwrap();
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
        EBpfElf::fixup_relative_calls(&mut calls, &mut prog).unwrap();
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

        EBpfElf::fixup_relative_calls(&mut calls, &mut prog).unwrap();
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

        EBpfElf::fixup_relative_calls(&mut calls, &mut prog).unwrap();
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
}
