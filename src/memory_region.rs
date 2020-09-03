//! This module defines memory regions

use crate::{
    ebpf::ELF_INSN_DUMP_OFFSET,
    error::{EbpfError, UserDefinedError},
};
use std::fmt;

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
    pub fn vm_to_host<E: UserDefinedError>(
        &self,
        vm_addr: u64,
        len: u64,
    ) -> Result<u64, EbpfError<E>> {
        if self.addr_vm <= vm_addr && vm_addr.saturating_add(len as u64) <= self.addr_vm + self.len
        {
            let host_addr = self.addr_host + (vm_addr - self.addr_vm);
            Ok(host_addr)
        } else {
            Err(EbpfError::InvalidVirtualAddress(vm_addr))
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
pub fn translate_addr<E: UserDefinedError>(
    vm_addr: u64,
    len: usize,
    access_type: &str,
    pc: usize, // TODO syscalls don't have this info
    regions: &[MemoryRegion],
) -> Result<u64, EbpfError<E>> {
    for region in regions.iter() {
        if let Ok(host_addr) = region.vm_to_host::<E>(vm_addr, len as u64) {
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
    Err(EbpfError::AccessViolation(
        access_type.to_string(),
        pc + ELF_INSN_DUMP_OFFSET,
        vm_addr,
        len,
        regions_string,
    ))
}
