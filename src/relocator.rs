//! This module relocates a BPF ELF

use std::io::{Error, ErrorKind};
use byteorder::{ByteOrder, LittleEndian};
use num_traits::FromPrimitive;
use std::io::Cursor;

///
pub fn reloc_from_reader<R>(
    mut io: R,
    _: Option<&elfkit::SectionContent>,
    eh: &elfkit::Header,
) -> Result<elfkit::SectionContent, Error>
where
    R: std::io::Read,
{
    // if eh.machine != types::Machine::X86_64 {
    //     return Err(Error::UnsupportedMachineTypeForRelocation(
    //         eh.machine.clone(),
    //     ));
    // }

    let mut r = Vec::new();

    while let Ok(addr) = elfkit::elf_read_u64!(eh, io) {
        let info = match elfkit::elf_read_u64!(eh, io) {
            Ok(v) => v,
            _ => break,
        };

        let sym = (info >> 32) as u32;
        let rtype = (info & 0xffffffff) as u32;
        let rtype = match elfkit::relocation::RelocationType::from_u32(rtype) {
            Some(v) => v,
            None => {
                println!(
                    "warning: unknown relocation type {} skipped while reading",
                    rtype
                );
                elfkit::elf_read_u64!(eh, io)?;
                continue;
            }
        };

        let addend = 0; // elfkit::elf_read_u64!(eh, io)?;

        r.push(elfkit::relocation::Relocation {
            addr: addr,
            sym: sym,
            rtype: rtype,
            addend: addend as i64,
        });
    }

    Ok(elfkit::SectionContent::Relocations(r))
}

pub fn get_section<'a>(elf_bytes: &'a mut [u8], index: usize) -> &'a [u8] {
    elf_bytes[index] = 10;
    &elf_bytes[index..]
}

#[test]
fn mytest() {
    let mut foo = vec!(1, 2, 3, 4, 5, 6, 7, 8, 9);
    {
        let bar = get_section(&mut foo, 2);
        println!("bar: {:?}", bar);
    }
    println!("foo: {:?}", foo);
}

///
pub fn relocate_elf(elf: &mut elfkit::Elf) -> Result<((Vec<u8>, Vec<u8>)), Error> {
    let text_section = elf
        .sections
        .iter()
        .find(|section| section.name.starts_with(".text".as_bytes()))
        .expect("No .text section found");
    let rodata_section = elf
        .sections
        .iter()
        .find(|section| section.name.starts_with(".rodata".as_bytes()))
        .expect("No .rodata section found");
    let rel_section = elf
        .sections
        .iter()
        .find(|section| section.name.starts_with(".rel.text".as_bytes()))
        .expect("No .rel.text section found");
    let symtab_section = elf
        .sections
        .iter()
        .find(|section| section.name.starts_with(".symtab".as_bytes()))
        .expect("No .symtab section found");

    // TODO validate the contents of these sections
    // TODO block against RW data
    let mut prog = match text_section.content {
        elfkit::SectionContent::Raw(ref raw) => raw.clone(),
        _ => Err(Error::new(
            ErrorKind::Other,
            "Error: Failed to get .text contents",
        ))?,
    };
    let rodata = match rodata_section.content {
        elfkit::SectionContent::Raw(ref raw) => raw.clone(),
        _ => Err(Error::new(
            ErrorKind::Other,
            "Error: Failed to get .rodata contents",
        ))?,
    };
    let _raw_rel = match rel_section.content {
        elfkit::SectionContent::Raw(ref c) => {
            c.clone()
        }
        _ => Err(Error::new(
            ErrorKind::Other,
            "Error: Failed to get relocations",
        ))?,
    };
    let rel = match reloc_from_reader(&_raw_rel[..], Some(&rel_section.content), &elf.header)
        .unwrap()
    {
        elfkit::SectionContent::Relocations(ref c) => c.clone(),
        _ => Err(Error::new(
            ErrorKind::Other,
            "Error: Failed to get relocations",
        ))?,
    };
    let symbols = match symtab_section.content {
        elfkit::SectionContent::Symbols(ref c) => {
            c.clone()
        }
        _ => Err(Error::new(
            ErrorKind::Other,
            "Error: Failed to get symbol table",
        ))?,
    };

    // println!("ELF Header: {:#?}", elf.header);
    // for section in elf.sections.iter() {
    //     println!(
    //         "Sec Name: {:#?}",
    //         String::from_utf8(section.name.clone()).unwrap()
    //     );
    //     println!("Sec Header: {:#?}", section.header);
    // }
    // println!("rel type {:?}", rel_section.header.shtype);
    // println!("rel content {:?}", rel_section.content);
    // println!("symtab content {:?}", symtab_section.content);
    // for (i, s) in symbols.iter().enumerate() {
    //     println!("Symbol {}: {:?}", i, s);
    // }

    for r in rel.iter() {
        //println!("{:?}", r);
        let sym_addr: u64 = rodata.as_ptr() as u64 + symbols[r.sym as usize].value;
        //println!("sym_addr {:?}", sym_addr);

        let location = r.addr as usize;
        LittleEndian::write_u32(
            &mut prog[location + 4..location + 4 + 4],
            (sym_addr & 0xFFFFFFFF) as u32,
        );
        LittleEndian::write_u32(
            &mut prog[location + 4 + 8..location + 4 + 4 + 8],
            (sym_addr >> 32) as u32,
        );
    }

    Ok((prog, rodata))
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

        let (prog, rodata) = relocate_elf(&mut elf).expect("relocate failed");

        dump_data("prog", &prog);
        dump_data("rodata", &rodata);

        disassemble(&prog);
    }
}
