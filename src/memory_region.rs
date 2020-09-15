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
    /// Is also writable (otherwise it is readonly)
    pub writable: bool,
}
impl MemoryRegion {
    /// Creates a new MemoryRegion structure from a slice
    pub fn new_from_slice(v: &[u8], addr_vm: u64, writable: bool) -> Self {
        MemoryRegion {
            addr_host: v.as_ptr() as u64,
            addr_vm,
            len: v.len() as u64,
            writable,
        }
    }

    /// Convert a virtual machine address into a host address
    /// Does not perform a lower bounds check, as that is already done by the binary search in translate_addr
    pub fn vm_to_host<E: UserDefinedError>(
        &self,
        vm_addr: u64,
        len: u64,
    ) -> Result<u64, EbpfError<E>> {
        let begin_offset = vm_addr - self.addr_vm;
        if let Some(end_offset) = begin_offset.checked_add(len as u64) {
            if end_offset <= self.len {
                return Ok(self.addr_host + begin_offset);
            }
        }
        Err(EbpfError::InvalidVirtualAddress(vm_addr))
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

/// Type of memory access
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AccessType {
    /// Read
    Load,
    /// Write
    Store,
}

/// Indirection to use instead of a slice to make handling easier
#[derive(Default)]
pub struct MemoryMapping {
    /// Mapped (valid) regions
    regions: Vec<MemoryRegion>,
}
impl MemoryMapping {
    /// Creates a new MemoryMapping structure
    pub fn new() -> Self {
        Self {
            regions: Vec::new(),
        }
    }

    /// Creates a new MemoryMapping structure from the given regions
    pub fn new_from_regions(regions: &[MemoryRegion]) -> Self {
        Self {
            regions: regions.to_vec(),
        }
    }

    /// Adds a region
    pub fn add_region(&mut self, region: MemoryRegion) {
        self.regions.push(region);
    }

    /// Adds multiple regions
    pub fn add_regions(&mut self, regions: Vec<MemoryRegion>) {
        self.regions.extend(regions);
    }

    /// Call after the last change. Sorts regions by addr_vm for binary search
    pub fn finalize(&mut self) {
        self.regions.sort_by(|a, b| a.addr_vm.cmp(&b.addr_vm));
    }

    /// Given a list of regions translate from virtual machine to host address
    pub fn translate_addr<E: UserDefinedError>(
        &self,
        vm_addr: u64,
        len: u64,
        access_type: AccessType,
        pc: usize, // TODO syscalls don't have this info
    ) -> Result<u64, EbpfError<E>> {
        let index = match self
            .regions
            .binary_search_by(|probe| probe.addr_vm.cmp(&vm_addr))
        {
            Ok(index) => index,
            Err(index) => {
                if index == 0 {
                    return Err(self.generate_access_violation(vm_addr, len, access_type, pc));
                }
                index - 1
            }
        };
        let region = &self.regions[index];
        if access_type == AccessType::Load || region.writable {
            if let Ok(host_addr) = region.vm_to_host::<E>(vm_addr, len as u64) {
                return Ok(host_addr);
            }
        }
        Err(self.generate_access_violation(vm_addr, len, access_type, pc))
    }

    /// Helper for translate_addr to generate errors
    fn generate_access_violation<E: UserDefinedError>(
        &self,
        vm_addr: u64,
        len: u64,
        access_type: AccessType,
        pc: usize,
    ) -> EbpfError<E> {
        let mut regions_string = "".to_string();
        if !self.regions.is_empty() {
            regions_string = "regions:".to_string();
            for region in self.regions.iter() {
                regions_string = format!(
                    "  {} \n{:#x} {:#x} {:#x}",
                    regions_string, region.addr_host, region.addr_vm, region.len,
                );
            }
        }
        EbpfError::AccessViolation(
            access_type,
            pc + ELF_INSN_DUMP_OFFSET,
            vm_addr,
            len,
            regions_string,
        )
    }
}
