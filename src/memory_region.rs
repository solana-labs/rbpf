//! This module defines memory regions

use crate::{
    ebpf,
    error::{EbpfError, UserDefinedError},
    vm::Config,
};
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
    /// Size of regular gaps as bit shift (63 means this region is continuous)
    pub vm_gap_shift: u8,
    /// Is also writable (otherwise it is readonly)
    pub is_writable: bool,
}
impl MemoryRegion {
    /// Creates a new MemoryRegion structure from a slice
    pub fn new_from_slice(slice: &[u8], vm_addr: u64, vm_gap_size: u64, is_writable: bool) -> Self {
        let vm_gap_shift = if vm_gap_size > 0 {
            let vm_gap_shift =
                std::mem::size_of::<u64>() as u8 * 8 - vm_gap_size.leading_zeros() as u8 - 1;
            debug_assert_eq!(vm_gap_size, 1 << vm_gap_shift);
            vm_gap_shift
        } else {
            std::mem::size_of::<u64>() as u8 * 8 - 1
        };
        MemoryRegion {
            host_addr: slice.as_ptr() as u64,
            vm_addr,
            len: slice.len() as u64,
            vm_gap_shift,
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
        let is_in_gap = ((begin_offset >> self.vm_gap_shift as u32) & 1) == 1;
        let gap_mask = (-1i64 << self.vm_gap_shift) as u64;
        let gapped_offset = (begin_offset & gap_mask) >> 1 | (begin_offset & !gap_mask);
        if let Some(end_offset) = gapped_offset.checked_add(len as u64) {
            if end_offset <= self.len && !is_in_gap {
                return Ok(self.host_addr + gapped_offset);
            }
        }
        Err(EbpfError::InvalidVirtualAddress(vm_addr))
    }
}
impl fmt::Debug for MemoryRegion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "host_addr: {:#x?}-{:#x?}, vm_addr: {:#x?}-{:#x?}, len: {}",
            self.host_addr,
            self.host_addr + self.len,
            self.vm_addr,
            self.vm_addr + self.len,
            self.len
        )
    }
}
impl std::cmp::PartialOrd for MemoryRegion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl std::cmp::Ord for MemoryRegion {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.vm_addr.cmp(&other.vm_addr)
    }
}

/// Type of memory access
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AccessType {
    /// Read
    Load,
    /// Write
    Store,
}

/// Indirection to use instead of a slice to make handling easier
pub struct MemoryMapping<'a> {
    /// Mapped memory regions
    regions: Box<[MemoryRegion]>,
    /// VM configuration
    config: &'a Config,
}
impl<'a> MemoryMapping<'a> {
    /// Creates a new MemoryMapping structure from the given regions
    pub fn new<E: UserDefinedError>(
        mut regions: Vec<MemoryRegion>,
        config: &'a Config,
    ) -> Result<Self, EbpfError<E>> {
        regions.sort();
        for (index, region) in regions.iter().enumerate() {
            if region.vm_addr != (index as u64) << ebpf::VIRTUAL_ADDRESS_BITS
                || (region.len > 0
                    && ((region.vm_addr + region.len - 1) >> ebpf::VIRTUAL_ADDRESS_BITS) as usize
                        != index)
            {
                return Err(EbpfError::InvalidMemoryRegion(index));
            }
        }
        Ok(Self {
            regions: regions.into_boxed_slice(),
            config,
        })
    }

    /// Given a list of regions translate from virtual machine to host address
    pub fn map<E: UserDefinedError>(
        &self,
        access_type: AccessType,
        vm_addr: u64,
        len: u64,
    ) -> Result<u64, EbpfError<E>> {
        let index = (vm_addr >> ebpf::VIRTUAL_ADDRESS_BITS) as usize;
        if (1..self.regions.len()).contains(&index) {
            let region = &self.regions[index];
            if access_type == AccessType::Load || region.is_writable {
                if let Ok(host_addr) = region.vm_to_host::<E>(vm_addr, len as u64) {
                    return Ok(host_addr);
                }
            }
        }
        self.generate_access_violation(access_type, vm_addr, len)
    }

    /// Helper for map to generate errors
    pub fn generate_access_violation<E: UserDefinedError>(
        &self,
        access_type: AccessType,
        vm_addr: u64,
        len: u64,
    ) -> Result<u64, EbpfError<E>> {
        let stack_frame =
            (vm_addr as i64 - ebpf::MM_STACK_START as i64) / self.config.stack_frame_size as i64;
        if (-1..self.config.max_call_depth as i64 + 1).contains(&stack_frame) {
            Err(EbpfError::StackAccessViolation(
                0, // Filled out later
                access_type,
                vm_addr,
                len,
                stack_frame,
            ))
        } else {
            let region_name = match vm_addr & !(ebpf::MM_PROGRAM_START - 1) {
                ebpf::MM_PROGRAM_START => "program",
                ebpf::MM_STACK_START => "stack",
                ebpf::MM_HEAP_START => "heap",
                ebpf::MM_INPUT_START => "input",
                _ => "unknown",
            };
            Err(EbpfError::AccessViolation(
                0, // Filled out later
                access_type,
                vm_addr,
                len,
                region_name,
            ))
        }
    }

    /// Resize the memory_region at the given index
    pub fn resize_region<E: UserDefinedError>(
        &mut self,
        index: usize,
        new_len: u64,
    ) -> Result<(), EbpfError<E>> {
        if index >= self.regions.len()
            || (new_len > 0
                && ((self.regions[index].vm_addr + new_len - 1) >> ebpf::VIRTUAL_ADDRESS_BITS)
                    as usize
                    != index)
        {
            return Err(EbpfError::InvalidMemoryRegion(index));
        }
        self.regions[index].len = new_len;
        Ok(())
    }
}
