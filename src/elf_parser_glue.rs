//! Internal ELF parser abstraction.
use std::{borrow::Cow, iter, ops::Range, slice};

use crate::{
    elf::ElfError,
    elf_parser::{
        consts::{SHF_ALLOC, SHF_WRITE, SHT_NOBITS, STT_FUNC},
        types::{
            Elf64Addr, Elf64Ehdr, Elf64Off, Elf64Phdr, Elf64Rel, Elf64Shdr, Elf64Sym, Elf64Word,
            Elf64Xword,
        },
        Elf64, ElfParserError,
    },
};

#[derive(Debug)]
pub struct NewParser<'a> {
    elf: Elf64<'a>,
}

type ProgramHeaders<'a> = slice::Iter<'a, Elf64Phdr>;

type SectionHeaders<'a> = slice::Iter<'a, Elf64Shdr>;

type Symbols<'a> = iter::Map<slice::Iter<'a, Elf64Sym>, fn(&'a Elf64Sym) -> Cow<'a, Elf64Sym>>;

type Relocations<'a> = iter::Map<slice::Iter<'a, Elf64Rel>, fn(&'a Elf64Rel) -> Cow<'a, Elf64Rel>>;

impl<'a> NewParser<'a> {
    pub fn parse(data: &'a [u8]) -> Result<NewParser<'a>, ElfError> {
        Ok(Self {
            elf: Elf64::parse(data)?,
        })
    }

    pub fn header(&self) -> &Elf64Ehdr {
        self.elf.file_header()
    }

    pub fn program_headers(&'a self) -> ProgramHeaders {
        self.elf.program_header_table().iter()
    }

    pub fn section_headers(&'a self) -> SectionHeaders {
        self.elf.section_header_table().iter()
    }

    pub fn section(&self, name: &[u8]) -> Result<Elf64Shdr, ElfError> {
        for section_header in self.elf.section_header_table() {
            if self.elf.section_name(section_header.sh_name)? == name {
                return Ok(section_header.clone());
            }
        }

        Err(ElfError::SectionNotFound(
            std::str::from_utf8(name)
                .unwrap_or("UTF-8 error")
                .to_string(),
        ))
    }

    pub fn section_name(&self, sh_name: Elf64Word) -> Option<&[u8]> {
        self.elf.section_name(sh_name).ok()
    }

    pub fn symbols(&'a self) -> Symbols {
        self.elf
            .symbol_table()
            .ok()
            .flatten()
            .unwrap_or(&[])
            .iter()
            .map(Cow::Borrowed)
    }

    pub fn symbol_name(&self, st_name: Elf64Word) -> Option<&[u8]> {
        self.elf.symbol_name(st_name).ok()
    }

    pub fn dynamic_symbol(&self, index: Elf64Word) -> Option<Elf64Sym> {
        self.elf
            .dynamic_symbol_table()
            .and_then(|table| table.get(index as usize).cloned())
    }

    pub fn dynamic_symbol_name(&self, st_name: Elf64Word) -> Option<&[u8]> {
        self.elf.dynamic_symbol_name(st_name).ok()
    }

    pub fn dynamic_relocations(&'a self) -> Relocations {
        self.elf
            .dynamic_relocations_table()
            .unwrap_or(&[])
            .iter()
            .map(Cow::Borrowed)
    }
}

impl Elf64Phdr {
    pub fn p_vaddr(&self) -> Elf64Addr {
        self.p_vaddr
    }

    pub fn p_memsz(&self) -> Elf64Xword {
        self.p_memsz
    }

    pub fn p_offset(&self) -> Elf64Off {
        self.p_offset
    }

    pub fn vm_range(&self) -> Range<Elf64Addr> {
        let addr = self.p_vaddr();
        addr..addr.saturating_add(self.p_memsz())
    }
}

impl Elf64Shdr {
    pub fn sh_name(&self) -> Elf64Word {
        self.sh_name as _
    }

    pub fn sh_flags(&self) -> Elf64Xword {
        self.sh_flags
    }

    pub fn sh_addr(&self) -> Elf64Addr {
        self.sh_addr
    }

    pub fn sh_offset(&self) -> Elf64Off {
        self.sh_offset
    }

    pub fn sh_size(&self) -> Elf64Xword {
        self.sh_size
    }

    pub fn sh_type(&self) -> Elf64Word {
        self.sh_type
    }

    pub fn is_writable(&self) -> bool {
        self.sh_flags() & (SHF_ALLOC | SHF_WRITE) == SHF_ALLOC | SHF_WRITE
    }

    pub fn file_range(&self) -> Option<Range<usize>> {
        (self.sh_type() != SHT_NOBITS).then(|| {
            let offset = self.sh_offset() as usize;
            offset..offset.saturating_add(self.sh_size() as usize)
        })
    }

    pub fn vm_range(&self) -> Range<Elf64Addr> {
        let addr = self.sh_addr();
        addr..addr.saturating_add(self.sh_size())
    }
}

impl Elf64Sym {
    pub fn st_name(&self) -> Elf64Word {
        self.st_name
    }

    pub fn st_info(&self) -> u8 {
        self.st_info
    }

    pub fn st_value(&self) -> Elf64Addr {
        self.st_value
    }

    pub fn is_function(&self) -> bool {
        (self.st_info() & 0xF) == STT_FUNC
    }
}

impl Elf64Rel {
    pub fn r_offset(&self) -> Elf64Addr {
        self.r_offset
    }

    pub fn r_type(&self) -> Elf64Word {
        (self.r_info & 0xFFFFFFFF) as Elf64Word
    }

    pub fn r_sym(&self) -> Elf64Word {
        self.r_info.checked_shr(32).unwrap_or(0) as Elf64Word
    }
}

impl From<ElfParserError> for ElfError {
    fn from(err: ElfParserError) -> Self {
        match err {
            ElfParserError::InvalidSectionHeader
            | ElfParserError::InvalidString
            | ElfParserError::InvalidSize
            | ElfParserError::Overlap
            | ElfParserError::SectionNotInOrder
            | ElfParserError::NoSectionNameStringTable
            | ElfParserError::InvalidDynamicSectionTable
            | ElfParserError::InvalidRelocationTable
            | ElfParserError::InvalidAlignment
            | ElfParserError::NoStringTable
            | ElfParserError::NoDynamicStringTable
            | ElfParserError::InvalidFileHeader => ElfError::FailedToParse(err.to_string()),
            ElfParserError::InvalidProgramHeader => ElfError::InvalidProgramHeader,
            ElfParserError::OutOfBounds => ElfError::ValueOutOfBounds,
        }
    }
}
