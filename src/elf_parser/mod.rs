//! Dependency-less 64 bit ELF parser

mod consts;
pub mod types;

use std::convert::TryInto;
use {crate::ebpf, consts::*, types::*};

const EXPECTED_PROGRAM_HEADERS: [(u32, u32, u64); 3] = [
    (PT_LOAD, PF_R | PF_X, ebpf::MM_PROGRAM_START),
    (PT_GNU_STACK, PF_R | PF_W, ebpf::MM_STACK_START),
    (PT_NULL, PF_R | PF_W, ebpf::MM_HEAP_START),
];
const SECTION_COUNT_MAXIMUM: usize = 16;
const SECTION_NAME_LENGTH_MAXIMUM: usize = 16;
const SYMBOL_NAME_LENGTH_MAXIMUM: usize = 64;

/// Error definitions
#[derive(Debug, PartialEq, Eq)]
pub enum ElfParserError {
    /// ELF file header is inconsistent or unsupported
    InvalidFileHeader,
    /// Program header is inconsistent or unsupported
    InvalidProgramHeader,
    /// Section header is inconsistent or unsupported
    InvalidSectionHeader,
    /// Section or symbol name is not UTF8 or too long
    InvalidString,
    /// An index or memory range does exeed its boundaries
    OutOfBounds,
    /// Headers, tables or sections do overlap in the file
    Overlap,
    /// Sections are not sorted in ascending order
    SectionNotInOrder,
}

fn check_that_there_is_no_overlap(
    range_a: &std::ops::Range<usize>,
    range_b: &std::ops::Range<usize>,
) -> Result<(), ElfParserError> {
    if range_a.end <= range_b.start || range_b.end <= range_a.start {
        Ok(())
    } else {
        Err(ElfParserError::Overlap)
    }
}

/// The parsed structure of an ELF file
pub struct Elf64<'a> {
    elf_bytes: &'a [u8],
    file_header: &'a Elf64Ehdr,
    program_header_table: &'a [Elf64Phdr],
    section_header_table: &'a [Elf64Shdr],
    text_section_header: Option<&'a Elf64Shdr>,
    readonly_data_section_header: Option<&'a Elf64Shdr>,
    symbol_section_header: Option<&'a Elf64Shdr>,
    symbol_names_section_header: Option<&'a Elf64Shdr>,
    section_names_section_header: Option<&'a Elf64Shdr>,
}

impl<'a> Elf64<'a> {
    /// Parse from the given byte slice
    pub fn from(elf_bytes: &'a [u8]) -> Result<Self, ElfParserError> {
        let file_header_range = 0..std::mem::size_of::<Elf64Ehdr>();
        let file_header_bytes = elf_bytes
            .get(file_header_range.clone())
            .and_then(|slice| slice.try_into().ok())
            .ok_or(ElfParserError::OutOfBounds)?;
        let file_header = unsafe {
            std::mem::transmute::<&[u8; std::mem::size_of::<Elf64Ehdr>()], &Elf64Ehdr>(
                file_header_bytes,
            )
        };
        if file_header.e_ident.ei_mag != ELFMAG
            || file_header.e_ident.ei_class != ELFCLASS64
            || file_header.e_ident.ei_data != ELFDATA2LSB
            || file_header.e_ident.ei_version != EV_CURRENT as u8
            || file_header.e_version != EV_CURRENT
            || file_header.e_ehsize != std::mem::size_of::<Elf64Ehdr>() as u16
            || file_header.e_phentsize != std::mem::size_of::<Elf64Phdr>() as u16
            || file_header.e_shentsize != std::mem::size_of::<Elf64Shdr>() as u16
            || file_header.e_shstrndx >= file_header.e_shnum
        {
            return Err(ElfParserError::InvalidFileHeader);
        }

        let program_header_table_range = file_header.e_phoff as usize
            ..std::mem::size_of::<Elf64Phdr>()
                .saturating_mul(file_header.e_phnum as usize)
                .saturating_add(file_header.e_phoff as usize);
        check_that_there_is_no_overlap(&file_header_range, &program_header_table_range)?;
        let program_header_table_bytes = elf_bytes
            .get(program_header_table_range.clone())
            .ok_or(ElfParserError::OutOfBounds)?;
        let program_header_table = unsafe {
            std::slice::from_raw_parts::<Elf64Phdr>(
                program_header_table_bytes.as_ptr() as *const Elf64Phdr,
                file_header.e_phnum as usize,
            )
        };

        let section_header_table_range = file_header.e_shoff as usize
            ..std::mem::size_of::<Elf64Shdr>()
                .saturating_mul(file_header.e_shnum as usize)
                .saturating_add(file_header.e_shoff as usize);
        check_that_there_is_no_overlap(&file_header_range, &section_header_table_range)?;
        check_that_there_is_no_overlap(&program_header_table_range, &section_header_table_range)?;
        let section_header_table_bytes = elf_bytes
            .get(section_header_table_range.clone())
            .ok_or(ElfParserError::OutOfBounds)?;
        let section_header_table = unsafe {
            std::slice::from_raw_parts::<Elf64Shdr>(
                section_header_table_bytes.as_ptr() as *const Elf64Shdr,
                file_header.e_shnum as usize,
            )
        };

        for program_header in program_header_table.iter() {
            if program_header.p_type != PT_LOAD {
                continue;
            }
            let program_range = program_header.p_offset as usize
                ..(program_header.p_offset as usize)
                    .saturating_add(program_header.p_filesz as usize);
            check_that_there_is_no_overlap(&program_range, &file_header_range)?;
            check_that_there_is_no_overlap(&program_range, &program_header_table_range)?;
            check_that_there_is_no_overlap(&program_range, &section_header_table_range)?;
            if program_range.end >= elf_bytes.len() {
                return Err(ElfParserError::OutOfBounds);
            }
        }

        let mut offset = 0usize;
        for section_header in section_header_table.iter() {
            if section_header.sh_type == SHT_NOBITS {
                continue;
            }
            let section_range = section_header.sh_offset as usize
                ..(section_header.sh_offset as usize)
                    .saturating_add(section_header.sh_size as usize);
            check_that_there_is_no_overlap(&section_range, &file_header_range)?;
            check_that_there_is_no_overlap(&section_range, &program_header_table_range)?;
            check_that_there_is_no_overlap(&section_range, &section_header_table_range)?;
            if section_range.start < offset {
                return Err(ElfParserError::SectionNotInOrder);
            }
            if section_range.end >= elf_bytes.len() {
                return Err(ElfParserError::OutOfBounds);
            }
            offset = section_range.end;
        }

        Ok(Self {
            elf_bytes,
            file_header,
            program_header_table,
            section_header_table,
            text_section_header: None,
            readonly_data_section_header: None,
            symbol_section_header: None,
            symbol_names_section_header: None,
            section_names_section_header: None,
        })
    }

    /// Check that the platform supports the layout and configuration
    pub fn check_platform_specific(&mut self) -> Result<(), ElfParserError> {
        if self.file_header.e_type != ET_EXEC
            || self.file_header.e_machine != 0xF7
            || self.file_header.e_ident.ei_osabi != 0x00
            || self.file_header.e_ident.ei_abiversion != 0x00
            || self.program_header_table.len() != EXPECTED_PROGRAM_HEADERS.len()
            || self.section_header_table.len() > SECTION_COUNT_MAXIMUM
        {
            return Err(ElfParserError::InvalidFileHeader);
        }
        for (program_header, (p_type, p_flags, addr)) in self
            .program_header_table
            .iter()
            .zip(EXPECTED_PROGRAM_HEADERS.iter())
        {
            if program_header.p_type != *p_type
                || program_header.p_flags != *p_flags
                || program_header.p_vaddr != *addr
                || program_header.p_paddr != *addr
                || program_header.p_memsz >= 0x100000000
            {
                return Err(ElfParserError::InvalidProgramHeader);
            }
        }
        let program_header = self
            .program_header_table
            .get(0)
            .ok_or(ElfParserError::OutOfBounds)?;
        let program_range = program_header.p_vaddr
            ..program_header
                .p_vaddr
                .saturating_add(program_header.p_filesz);
        if !program_range.contains(&self.file_header.e_entry)
            || (self.file_header.e_entry as usize)
                .checked_rem(ebpf::INSN_SIZE)
                .map(|remainder| remainder != 0)
                .unwrap_or(true)
        {
            return Err(ElfParserError::InvalidSectionHeader);
        }
        let section_names_section_header = &self
            .section_header_table
            .get(self.file_header.e_shstrndx as usize)
            .ok_or(ElfParserError::OutOfBounds)?;
        macro_rules! section_header_by_name {
            ($self:expr, $section_header:expr, $section_name:expr,
             $($name:literal => $field:ident,)*) => {
                match $section_name {
                    $($name => {
                        if $self.$field.is_some() {
                            return Err(ElfParserError::InvalidSectionHeader);
                        }
                        $self.$field = Some($section_header);
                    })*
                    _ => {}
                }
            }
        }
        for section_header in self.section_header_table.iter() {
            let section_name = self.get_string_in_section(
                section_names_section_header,
                section_header.sh_name,
                SECTION_NAME_LENGTH_MAXIMUM,
            )?;
            section_header_by_name!(
                self, section_header, section_name,
                ".text" => text_section_header,
                ".rodata" => readonly_data_section_header,
                ".symtab" => symbol_section_header,
                ".strtab" => symbol_names_section_header,
            )
        }
        self.section_names_section_header = Some(section_names_section_header);
        Ok(())
    }

    /// Query a single string from a section which is marked as SHT_STRTAB
    pub fn get_string_in_section(
        &self,
        section_header: &Elf64Shdr,
        offset_in_section: Elf64Word,
        maximum_length: usize,
    ) -> Result<&'a str, ElfParserError> {
        if section_header.sh_type != SHT_STRTAB {
            return Err(ElfParserError::InvalidSectionHeader);
        }
        let offset_in_file =
            (section_header.sh_offset as usize).saturating_add(offset_in_section as usize);
        let string_range = offset_in_file
            ..(section_header.sh_offset as usize)
                .saturating_add(section_header.sh_size as usize)
                .min(offset_in_file.saturating_add(maximum_length));
        let unterminated_string_bytes = self
            .elf_bytes
            .get(string_range)
            .ok_or(ElfParserError::OutOfBounds)?;
        unterminated_string_bytes
            .iter()
            .position(|byte| *byte == 0x00)
            .and_then(|string_length| unterminated_string_bytes.get(0..string_length))
            .and_then(|string_bytes| std::str::from_utf8(string_bytes).ok())
            .ok_or(ElfParserError::InvalidString)
    }

    /// Returns the symbol table of a section which is marked as SHT_SYMTAB
    pub fn get_symbol_table_of_section(
        &self,
        section_header: &Elf64Shdr,
    ) -> Result<&'a [Elf64Sym], ElfParserError> {
        if section_header.sh_type != SHT_SYMTAB
            || (section_header.sh_size as usize)
                .checked_rem(std::mem::size_of::<Elf64Sym>())
                .map(|remainder| remainder != 0)
                .unwrap_or(true)
        {
            return Err(ElfParserError::InvalidSectionHeader);
        }
        let symbol_table_range = section_header.sh_offset as usize
            ..(section_header.sh_offset as usize).saturating_add(section_header.sh_size as usize);
        let symbol_table_bytes = self
            .elf_bytes
            .get(symbol_table_range)
            .ok_or(ElfParserError::OutOfBounds)?;
        let symbol_table = unsafe {
            std::slice::from_raw_parts::<Elf64Sym>(
                symbol_table_bytes.as_ptr() as *const Elf64Sym,
                (section_header.sh_size as usize)
                    .checked_div(std::mem::size_of::<Elf64Sym>())
                    .unwrap_or(0),
            )
        };
        Ok(symbol_table)
    }
}

impl<'a> std::fmt::Debug for Elf64<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(f, "{:#X?}", self.file_header)?;
        for program_header in self.program_header_table.iter() {
            writeln!(f, "{:#X?}", program_header)?;
        }
        for section_header in self.section_header_table.iter() {
            let section_name = self
                .get_string_in_section(
                    self.section_names_section_header.unwrap(),
                    section_header.sh_name,
                    SECTION_NAME_LENGTH_MAXIMUM,
                )
                .unwrap();
            writeln!(f, "{}", section_name)?;
            writeln!(f, "{:#X?}", section_header)?;
        }
        if let Some(section_header) = self.symbol_section_header {
            let symbol_table = self.get_symbol_table_of_section(section_header).unwrap();
            writeln!(f, "{:#X?}", symbol_table)?;
            for symbol in symbol_table.iter() {
                if symbol.st_name != 0 {
                    let symbol_name = self
                        .get_string_in_section(
                            self.symbol_names_section_header.unwrap(),
                            symbol.st_name,
                            SYMBOL_NAME_LENGTH_MAXIMUM,
                        )
                        .unwrap();
                    writeln!(f, "{}", symbol_name)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loading_static_executable() {
        let elf_bytes = std::fs::read("tests/elfs/static.elf").unwrap();
        let mut parsed_elf = Elf64::from(&elf_bytes).unwrap();
        parsed_elf.check_platform_specific().unwrap();
        println!("{:?}", parsed_elf);
    }
}
