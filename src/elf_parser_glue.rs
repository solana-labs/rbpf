//! Internal ELF parser abstraction.
use crate::{elf::ElfError, elf_parser::Elf64};

#[derive(Debug)]
pub struct NewParser<'a> {
    pub elf: Elf64<'a>,
}

impl<'a> NewParser<'a> {
    pub fn parse(data: &'a [u8]) -> Result<NewParser<'a>, ElfError> {
        Ok(Self {
            elf: Elf64::parse(data)?,
        })
    }
}
