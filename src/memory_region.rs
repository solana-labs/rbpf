//! This module defines memory regions

use crate::ebpf::ELF_INSN_DUMP_OFFSET;
use std::fmt;
use std::io::{Error, ErrorKind};

/// Memory region for bounds checking and address translation
#[derive(Clone, Default)]
pub struct MemoryRegion {
    /// start host address
    pub addr_host: u64,
    /// start virtual address
    pub addr_vm: u64,
    /// Length in bytes
    pub len: u64,
}
impl MemoryRegion {
    /// Creates a new MemoryRegion structure from a slice
    pub fn new_from_slice(v: &[u8], addr_vm: u64) -> Self {
        MemoryRegion {
            addr_host: v.as_ptr() as u64,
            addr_vm,
            len: v.len() as u64,
        }
    }

    /// Convert a virtual machine address into a host address
    pub fn vm_to_host(&self, vm_addr: u64, len: u64) -> Result<(u64), Error> {
        if self.addr_vm <= vm_addr && vm_addr + len as u64 <= self.addr_vm + self.len {
            let host_addr = self.addr_host + (vm_addr - self.addr_vm);
            Ok(host_addr)
        } else {
            Err(Error::new(ErrorKind::InvalidInput, ""))
        }
    }
}
impl fmt::Debug for MemoryRegion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "addr_host: {:#x?}, addr_vm: {:#x?}, len: {}",
            self.addr_host, self.addr_vm, self.len
        )
    }
}

/// Given a list of regions translate from virtual machine to host address
pub fn translate_addr(
    vm_addr: u64,
    len: usize,
    access_type: &str,
    mut pc: usize, // TODO helpers don't have this info
    regions: &[MemoryRegion],
) -> Result<(u64), Error> {
    for region in regions.iter() {
        if let Ok(host_addr) = region.vm_to_host(vm_addr, len as u64) {
            return Ok(host_addr);
        }
    }

    let mut regions_string = "".to_string();
    if !regions.is_empty() {
        regions_string = "regions:".to_string();
        for region in regions.iter() {
            regions_string = format!(
                "  {} \n{:#x}-{:#x}",
                regions_string,
                region.addr_vm,
                region.addr_vm + region.len - 1,
            );
        }
    }
    if pc == 0 {
        pc = 1;
    };
    Err(Error::new(
        ErrorKind::Other,
        format!(
            "Error: out of bounds memory {} (insn #{:?}), addr {:#x}/{:?} \n{}",
            access_type,
            pc - 1 + ELF_INSN_DUMP_OFFSET,
            vm_addr,
            len,
            regions_string
        ),
    ))
}
