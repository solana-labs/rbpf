//! This module defines memory regions

use crate::error::{EbpfError, UserDefinedError};
use std::fmt;

/// Memory region for bounds checking and address translation
#[derive(Clone, PartialEq, Eq, Default)]
pub struct MemoryRegion {
    /// start host address
    pub host_addr: u64,
    /// start virtual address
    pub vm_addr: u64,
    /// Length in bytes
    pub len: u64,
    /// Is also writable (otherwise it is readonly)
    pub is_writable: bool,
}
impl MemoryRegion {
    /// Creates a new MemoryRegion structure from a slice
    pub fn new_from_slice(v: &[u8], vm_addr: u64, is_writable: bool) -> Self {
        MemoryRegion {
            host_addr: v.as_ptr() as u64,
            vm_addr,
            len: v.len() as u64,
            is_writable,
        }
    }

    /// Convert a virtual machine address into a host address
    /// Does not perform a lower bounds check, as that is already done by the binary search in MemoryMapping::map()
    pub fn vm_to_host<E: UserDefinedError>(
        &self,
        vm_addr: u64,
        len: u64,
    ) -> Result<u64, EbpfError<E>> {
        let begin_offset = vm_addr - self.vm_addr;
        if let Some(end_offset) = begin_offset.checked_add(len as u64) {
            if end_offset <= self.len {
                return Ok(self.host_addr + begin_offset);
            }
        }
        Err(EbpfError::InvalidVirtualAddress(vm_addr))
    }
}
impl fmt::Debug for MemoryRegion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "host_addr: {:#x?}, vm_addr: {:#x?}, len: {}",
            self.host_addr, self.vm_addr, self.len
        )
    }
}
impl std::cmp::PartialOrd for MemoryRegion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(&other))
    }
}
impl std::cmp::Ord for MemoryRegion {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.vm_addr.cmp(&other.vm_addr)
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
    regions: Box<[MemoryRegion]>,
}
impl MemoryMapping {
    /// Creates a new MemoryMapping structure from the given regions
    pub fn new_from_regions(mut regions: Vec<MemoryRegion>) -> Self {
        regions.sort();
        Self {
            regions: regions.into_boxed_slice(),
        }
    }

    /// Given a list of regions translate from virtual machine to host address
    pub fn map<E: UserDefinedError>(
        &self,
        access_type: AccessType,
        vm_addr: u64,
        len: u64,
    ) -> Result<u64, EbpfError<E>> {
        let index = match self
            .regions
            .binary_search_by(|probe| probe.vm_addr.cmp(&vm_addr))
        {
            Ok(index) => index,
            Err(index) => {
                if index == 0 {
                    return Err(self.generate_access_violation(access_type, vm_addr, len));
                }
                index - 1
            }
        };
        let region = &self.regions[index];
        if access_type == AccessType::Load || region.is_writable {
            if let Ok(host_addr) = region.vm_to_host::<E>(vm_addr, len as u64) {
                return Ok(host_addr);
            }
        }
        Err(self.generate_access_violation(access_type, vm_addr, len))
    }

    /// Helper for map to generate errors
    fn generate_access_violation<E: UserDefinedError>(
        &self,
        access_type: AccessType,
        vm_addr: u64,
        len: u64,
    ) -> EbpfError<E> {
        let mut regions_string = "".to_string();
        if !self.regions.is_empty() {
            regions_string = "regions:".to_string();
            for region in self.regions.iter() {
                regions_string = format!(
                    "  {} \n{:#x} {:#x} {:#x}",
                    regions_string, region.host_addr, region.vm_addr, region.len,
                );
            }
        }
        EbpfError::AccessViolation(
            0, // Filled out later
            access_type,
            vm_addr,
            len,
            regions_string,
        )
    }
}
