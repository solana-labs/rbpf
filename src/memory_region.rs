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
    pub fn new_from_slice(v: &[u8], vm_addr: u64, vm_gap_size: u64, is_writable: bool) -> Self {
        let vm_gap_shift = if vm_gap_size > 0 {
            let vm_gap_shift =
                std::mem::size_of::<u64>() as u8 * 8 - vm_gap_size.leading_zeros() as u8 - 1;
            debug_assert_eq!(vm_gap_size, 1 << vm_gap_shift);
            vm_gap_shift
        } else {
            std::mem::size_of::<u64>() as u8 * 8 - 1
        };
        MemoryRegion {
            host_addr: v.as_ptr() as u64,
            vm_addr,
            len: v.len() as u64,
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
        let mut begin_offset = vm_addr - self.vm_addr;
        let is_in_gap = ((begin_offset >> self.vm_gap_shift as u32) & 1) == 1;
        let gap_mask = (1 << self.vm_gap_shift) - 1;
        begin_offset = (begin_offset & !gap_mask) >> 1 | (begin_offset & gap_mask);
        if let Some(end_offset) = begin_offset.checked_add(len as u64) {
            if end_offset <= self.len && !is_in_gap {
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
pub struct MemoryMapping<'a> {
    /// Mapped (valid) regions
    regions: Box<[MemoryRegion]>,
    /// Copy of the regions vm_addr fields to improve cache density
    dense_keys: Box<[u64]>,
    /// VM configuration
    config: &'a Config,
}
impl<'a> MemoryMapping<'a> {
    fn construct_eytzinger_order(
        &mut self,
        ascending_regions: &[MemoryRegion],
        mut in_index: usize,
        out_index: usize,
    ) -> usize {
        if out_index >= self.regions.len() {
            return in_index;
        }
        in_index = self.construct_eytzinger_order(ascending_regions, in_index, 2 * out_index + 1);
        self.regions[out_index] = ascending_regions[in_index].clone();
        self.dense_keys[out_index] = ascending_regions[in_index].vm_addr;
        self.construct_eytzinger_order(ascending_regions, in_index + 1, 2 * out_index + 2)
    }

    /// Creates a new MemoryMapping structure from the given regions
    pub fn new<E: UserDefinedError>(
        mut regions: Vec<MemoryRegion>,
        config: &'a Config,
    ) -> Result<Self, EbpfError<E>> {
        let mut result = Self {
            regions: vec![MemoryRegion::default(); regions.len()].into_boxed_slice(),
            dense_keys: vec![0; regions.len()].into_boxed_slice(),
            config,
        };
        regions.sort();
        for index in 1..regions.len() {
            let first = &regions[index - 1];
            let second = &regions[index];
            if first.vm_addr.saturating_add(first.len) > second.vm_addr {
                return Err(EbpfError::VirtualAddressOverlap(second.vm_addr));
            }
        }
        result.construct_eytzinger_order(&regions, 0, 0);
        Ok(result)
    }

    /// Given a list of regions translate from virtual machine to host address
    pub fn map<E: UserDefinedError>(
        &self,
        access_type: AccessType,
        vm_addr: u64,
        len: u64,
    ) -> Result<u64, EbpfError<E>> {
        let mut index = 1;
        while index <= self.dense_keys.len() {
            index = (index << 1) + (self.dense_keys[index - 1] <= vm_addr) as usize;
        }
        index >>= index.trailing_zeros() + 1;
        if index == 0 {
            return Err(self.generate_access_violation(access_type, vm_addr, len));
        }
        let region = &self.regions[index - 1];
        if access_type == AccessType::Load || region.is_writable {
            if let Ok(host_addr) = region.vm_to_host::<E>(vm_addr, len as u64) {
                return Ok(host_addr);
            }
        }
        Err(self.generate_access_violation(access_type, vm_addr, len))
    }

    /// Resize the memory_region at the given index
    pub fn resize_region<E: UserDefinedError>(
        &mut self,
        index: usize,
        new_len: u64,
    ) -> Result<(), EbpfError<E>> {
        if index < self.regions.len() - 1
            && self.regions[index].vm_addr.saturating_add(new_len) > self.regions[index + 1].vm_addr
        {
            return Err(EbpfError::VirtualAddressOverlap(
                self.regions[index + 1].vm_addr,
            ));
        }
        self.regions[index].len = new_len;
        Ok(())
    }

    /// Helper for map to generate errors
    fn generate_access_violation<E: UserDefinedError>(
        &self,
        access_type: AccessType,
        vm_addr: u64,
        len: u64,
    ) -> EbpfError<E> {
        let stack_frame =
            (vm_addr as i64 - ebpf::MM_STACK_START as i64) / self.config.stack_frame_size as i64;
        if (-1..self.config.max_call_depth as i64 + 1).contains(&stack_frame) {
            EbpfError::StackAccessViolation(
                0, // Filled out later
                access_type,
                vm_addr,
                len,
                stack_frame,
            )
        } else {
            let region_name = match vm_addr & !(ebpf::MM_PROGRAM_START - 1) {
                ebpf::MM_PROGRAM_START => "program",
                ebpf::MM_STACK_START => "stack",
                ebpf::MM_HEAP_START => "heap",
                ebpf::MM_INPUT_START => "input",
                _ => "unknown",
            };
            EbpfError::AccessViolation(
                0, // Filled out later
                access_type,
                vm_addr,
                len,
                region_name,
            )
        }
    }
}
