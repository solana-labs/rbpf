//! This module relocates a BPF ELF

use byteorder::{ByteOrder, LittleEndian};
use ebpf;
use num_traits::FromPrimitive;
use std::io::Cursor;
use std::io::{Error, ErrorKind};
use disassembler::disassemble;

//enum RelocationType {
//     R_BPF_NONE = 0,
//     R_BPF_64_64 = 1,
//     R_BPF_64_32 = 10,
// }

pub fn load(elf_bytes: &[u8]) -> Result<(elfkit::Elf), Error> {
        let mut reader = Cursor::new(elf_bytes);
        let mut elf = match elfkit::Elf::from_reader(&mut reader) {
            Ok(elf) => elf,
            Err(e) => Err(Error::new(
                    ErrorKind::Other,
                    format!("Error: Failed to parse elf: {:?}", e)))?,
        };
        if let Err(e) = elf.load_all(&mut reader) {
            Err(Error::new(
                    ErrorKind::Other,
                    format!("Error: Failed to parse elf: {:?}", e)))?;
        }
        validate(&elf)?;
        relocate(&mut elf)?;
        disassemble(get_text_section(&elf)?);
        Ok(elf)
}

///
pub fn get_text_section<'a>(elf: &'a elfkit::Elf) -> Result<&'a [u8], Error> {
    Ok(match elf
            .sections
            .iter()
            .find(|section| section.name.starts_with(".text".as_bytes()))
        {
            Some(section) => match section.content {
                elfkit::SectionContent::Raw(ref bytes) => bytes,
                _ => Err(Error::new(
                    ErrorKind::Other,
                    "Error: Failed to get .text contents",
                ))?,
            },
            None => Err(Error::new(
                ErrorKind::Other,
                "Error: No .text section found",
            ))?,
        })
}

pub fn validate(elf: &elfkit::Elf) -> Result<(), Error> {
    //TODO
    Ok(())
}

fn content_to_bytes<'a>(section: &'a elfkit::section::Section) -> Result<&'a [u8], Error> {
    match section.content {
        elfkit::SectionContent::Raw(ref bytes) => Ok(bytes),
        _ => Err(Error::new(ErrorKind::Other,
                            "Error: Failed to get .rodata contents",
                 )),
    }
}

pub fn get_rodata<'a>(elf: &'a elfkit::Elf) -> Result<Vec<&'a [u8]>, Error> {
    let rodata: Result<Vec<_>, _> = elf
            .sections
            .iter()
            .filter(|section| section.name.starts_with(".rodata".as_bytes())).map(content_to_bytes).collect();
    rodata
}

// TODOS
// validate the contents of these sections
// block against RW data
// print values in error messages
// relocate symbols
// validate sol_log string
// use unwrap_or instead of matching all the time
// use elf instead of elfkit
///
pub fn relocate(elf: &mut elfkit::Elf) -> Result<(), Error> {
    let text_bytes = {
        let raw_relocation_bytes = match elf
            .sections
            .iter()
            .find(|section| section.name.starts_with(".rel.text".as_bytes()))
        {
            Some(section) => match section.content {
                elfkit::SectionContent::Raw(ref bytes) => bytes.clone(),
                _ => Err(Error::new(
                    ErrorKind::Other,
                    "Error: Failed to get .rel.text contents",
                ))?,
            },
            None => return Ok(()), // no relocation section, no need to relocate
        };
        let relocations = get_relocations(&raw_relocation_bytes[..], &elf.header)?;

        let mut text_bytes = match elf
            .sections
            .iter()
            .find(|section| section.name.starts_with(".text".as_bytes()))
        {
            Some(section) => match section.content {
                elfkit::SectionContent::Raw(ref bytes) => bytes.clone(),
                _ => Err(Error::new(
                    ErrorKind::Other,
                    "Error: Failed to get .text contents",
                ))?,
            },
            None => Err(Error::new(
                ErrorKind::Other,
                "Error: No .text section found",
            ))?,
        };

        let symbols = match elf
            .sections
            .iter()
            .find(|section| section.name.starts_with(".symtab".as_bytes()))
        {
            Some(section) => match section.content {
                elfkit::SectionContent::Symbols(ref bytes) => bytes.clone(),
                _ => Err(Error::new(
                    ErrorKind::Other,
                    "Error: Failed to get .symtab contents",
                ))?,
            },
            None => Err(Error::new(
                ErrorKind::Other,
                "Error: No .symtab section found",
            ))?,
        };

        for relocation in relocations.iter() {
            // elfkit uses x86 relocation types, R_x86_64_64 == R_BPF_64_64
            if relocation.rtype == elfkit::relocation::RelocationType::R_X86_64_64 {
                // The Text section has a reference to a symbol in another section
                // (probably .rodata)
                //
                // Get the 64 bit address of the symbol and fix-up the lddw instruction's
                // imm field

                let symbol = &symbols[relocation.sym as usize];
                let shndx = match symbol.shndx {
                    elfkit::symbol::SymbolSectionIndex::Section(shndx) => shndx,
                    _ => Err(Error::new(
                        ErrorKind::Other,
                        "Error: Failed to get relocations",
                    ))?,
                } as usize;

                let section_base_address = match elf.sections[shndx].content {
                    elfkit::SectionContent::Raw(ref raw) => raw,
                    _ => Err(Error::new(
                        ErrorKind::Other,
                        "Error: Failed to get .rodata contents",
                    ))?,
                }.as_ptr() as u64;

                // base address of containing section plus offset in relocation
                let symbol_addr: u64 = section_base_address + symbol.value;

                // Instruction lddw spans two instruction slots, split
                // symbol's address into two and write into both
                // slot's imm field
                let mut imm_offset = relocation.addr as usize + 4;
                let imm_length = 4;
                LittleEndian::write_u32(
                    &mut text_bytes[imm_offset..imm_offset + imm_length],
                    (symbol_addr & 0xFFFFFFFF) as u32,
                );
                imm_offset += ebpf::INSN_SIZE;
                LittleEndian::write_u32(
                    &mut text_bytes[imm_offset..imm_offset + imm_length],
                    (symbol_addr >> 32) as u32,
                );
            } else {
                Err(Error::new(
                    ErrorKind::Other,
                    "Error: Unhandled relocation type",
                ))?;
            }
        }
        text_bytes
    };
    let mut text_section = match elf
        .sections
        .iter_mut()
        .find(|section| section.name.starts_with(".text".as_bytes()))
{
            Some(section) => &mut section.content,
            None => Err(Error::new(
                ErrorKind::Other,
                "Error: No .text section found",
            ))?,
        };

    *text_section = elfkit::SectionContent::Raw(text_bytes.to_vec());

    Ok(())
}

///
fn get_relocations<R>(mut io: R, eh: &elfkit::Header) -> Result<Vec<elfkit::Relocation>, Error>
where
    R: std::io::Read,
{
    let mut relocs = Vec::new();

    while let Ok(addr) = elfkit::elf_read_u64!(eh, io) {
        let info = match elfkit::elf_read_u64!(eh, io) {
            Ok(v) => v,
            _ => Err(Error::new(
                ErrorKind::Other,
                "Error: Failed to read relocation info",
            ))?,
        };

        let sym = (info >> 32) as u32;
        let rtype = (info & 0xffffffff) as u32;
        let rtype = match elfkit::relocation::RelocationType::from_u32(rtype) {
            Some(v) => v,
            None => Err(Error::new(
                ErrorKind::Other,
                "Error: unkown relocation type",
            ))?,
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

#[cfg(test)]
mod test {
    use super::*;
    use disassembler::disassemble;
    use std::fs::File;
    use std::io::Read;

    #[test]
    fn test_relocate() {
        let mut elf = {
            let mut file = File::open("noop.o").expect("file open failed");
            let mut elf_bytes = Vec::new();
            file.read_to_end(&mut elf_bytes).unwrap();

            let mut reader = Cursor::new(elf_bytes);
            let mut elf = elfkit::Elf::from_reader(&mut reader).expect("from_reader");
            elf.load_all(&mut reader).expect("load_all");
            elf
        };

        // dump_data("elf", &elf);

        relocate(&mut elf).expect("relocate failed");
        let prog = get_text_section(&mut elf).unwrap();

        dump_data("prog", prog);

        disassemble(&prog);
    }
}
