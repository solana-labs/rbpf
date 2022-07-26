//! This module defines memory regions

use crate::{
    ebpf,
    error::{EbpfError, UserDefinedError},
    vm::Config,
};
use std::fmt;

/* Explaination of the Gapped Memory

    The MemoryMapping supports a special mapping mode which is used for the stack MemoryRegion.
    In this mode the backing address space of the host is sliced in power-of-two aligned frames.
    The exponent of this alignment is specified in vm_gap_shift. Then the virtual address space
    of the guest is spread out in a way which leaves gapes, the same size as the frames, in
    between the frames. This effectively doubles the size of the guests virtual address space.
    But the acutual mapped memory stays the same, as the gaps are not mapped and accessing them
    results in an AccessViolation.

    Guest: frame 0 | gap 0 | frame 1 | gap 1 | frame 2 | gap 2 | ...
              |                /                 /
              |          *----*    *------------*
              |         /         /
    Host:  frame 0 | frame 1 | frame 2 | ...
*/

/// Memory region for bounds checking and address translation
#[derive(Clone, PartialEq, Eq, Default)]
#[repr(C, align(32))]
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
    fn new(slice: &[u8], vm_addr: u64, vm_gap_size: u64, is_writable: bool) -> Self {
        let mut vm_gap_shift = (std::mem::size_of::<u64>() as u8)
            .saturating_mul(8)
            .saturating_sub(1);
        if vm_gap_size > 0 {
            vm_gap_shift = vm_gap_shift.saturating_sub(vm_gap_size.leading_zeros() as u8);
            debug_assert_eq!(Some(vm_gap_size), 1_u64.checked_shl(vm_gap_shift as u32));
        };
        MemoryRegion {
            host_addr: slice.as_ptr() as u64,
            vm_addr,
            len: slice.len() as u64,
            vm_gap_shift,
            is_writable,
        }
    }

    /// Only to be used in tests and benches
    pub fn new_for_testing(
        slice: &[u8],
        vm_addr: u64,
        vm_gap_size: u64,
        is_writable: bool,
    ) -> Self {
        Self::new(slice, vm_addr, vm_gap_size, is_writable)
    }

    /// Creates a new readonly MemoryRegion from a slice
    pub fn new_readonly(slice: &[u8], vm_addr: u64) -> Self {
        Self::new(slice, vm_addr, 0, false)
    }

    /// Creates a new writable MemoryRegion from a mutable slice
    pub fn new_writable(slice: &mut [u8], vm_addr: u64) -> Self {
        Self::new(slice, vm_addr, 0, true)
    }

    /// Creates a new writable gapped MemoryRegion from a mutable slice
    pub fn new_writable_gapped(slice: &mut [u8], vm_addr: u64, vm_gap_size: u64) -> Self {
        Self::new(slice, vm_addr, vm_gap_size, true)
    }

    /// Convert a virtual machine address into a host address
    pub fn vm_to_host<E: UserDefinedError>(
        &self,
        vm_addr: u64,
        len: u64,
    ) -> Result<u64, EbpfError<E>> {
        // This can happen if a region starts at an offset from the base region
        // address, eg with rodata regions if config.optimize_rodata = true, see
        // Elf::get_ro_region.
        if vm_addr < self.vm_addr {
            return Err(EbpfError::InvalidVirtualAddress(vm_addr));
        }

        let begin_offset = vm_addr.saturating_sub(self.vm_addr);
        let is_in_gap = (begin_offset
            .checked_shr(self.vm_gap_shift as u32)
            .unwrap_or(0)
            & 1)
            == 1;
        let gap_mask = (-1i64).checked_shl(self.vm_gap_shift as u32).unwrap_or(0) as u64;
        let gapped_offset =
            (begin_offset & gap_mask).checked_shr(1).unwrap_or(0) | (begin_offset & !gap_mask);
        if let Some(end_offset) = gapped_offset.checked_add(len as u64) {
            if end_offset <= self.len && !is_in_gap {
                return Ok(self.host_addr.saturating_add(gapped_offset));
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
            self.host_addr.saturating_add(self.len),
            self.vm_addr,
            self.vm_addr.saturating_add(self.len),
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

impl fmt::Display for AccessType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccessType::Load => f.write_str("load"),
            AccessType::Store => f.write_str("store"),
        }
    }
}

/// Memory mapping based on eytzinger search.
#[derive(Debug)]
pub struct UnalignedMemoryMapping<'a> {
    /// Mapped memory regions
    regions: Box<[MemoryRegion]>,
    /// Copy of the regions vm_addr fields to improve cache density
    dense_keys: Box<[u64]>,
    /// VM configuration
    config: &'a Config,
}

impl<'a> UnalignedMemoryMapping<'a> {
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
        regions.sort();
        for index in 1..regions.len() {
            let first = &regions[index - 1];
            let second = &regions[index];
            if first.vm_addr.saturating_add(first.len) > second.vm_addr {
                return Err(EbpfError::InvalidMemoryRegion(index));
            }
        }

        let mut result = Self {
            regions: vec![MemoryRegion::default(); regions.len()].into_boxed_slice(),
            dense_keys: vec![0; regions.len()].into_boxed_slice(),
            config,
        };
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
            return self.generate_access_violation(access_type, vm_addr, len);
        }
        let region = &self.regions[index - 1];
        if access_type == AccessType::Load || region.is_writable {
            if let Ok(host_addr) = region.vm_to_host::<E>(vm_addr, len as u64) {
                return Ok(host_addr);
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
        generate_access_violation(self.config, access_type, vm_addr, len)
    }

    /// Returns the `MemoryRegion`s in this mapping
    pub fn get_regions(&self) -> &[MemoryRegion] {
        &self.regions
    }

    /// Replaces the `MemoryRegion` at the given index
    pub fn replace_region<E: UserDefinedError>(
        &mut self,
        index: usize,
        region: MemoryRegion,
    ) -> Result<(), EbpfError<E>> {
        self.regions[index] = region;
        Ok(())
    }
}

/// Memory mapping that uses the upper half of an address to identify the
/// underlying memory region.
#[derive(Debug)]
pub struct AlignedMemoryMapping<'a> {
    /// Mapped memory regions
    regions: Box<[MemoryRegion]>,
    /// VM configuration
    config: &'a Config,
}

impl<'a> AlignedMemoryMapping<'a> {
    /// Creates a new MemoryMapping structure from the given regions
    pub fn new<E: UserDefinedError>(
        mut regions: Vec<MemoryRegion>,
        config: &'a Config,
    ) -> Result<Self, EbpfError<E>> {
        regions.insert(0, MemoryRegion::new_readonly(&[], 0));
        regions.sort();
        for (index, region) in regions.iter().enumerate() {
            if region
                .vm_addr
                .checked_shr(ebpf::VIRTUAL_ADDRESS_BITS as u32)
                .unwrap_or(0)
                != index as u64
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
        let index = vm_addr
            .checked_shr(ebpf::VIRTUAL_ADDRESS_BITS as u32)
            .unwrap_or(0) as usize;
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
        generate_access_violation(self.config, access_type, vm_addr, len)
    }

    /// Returns the `MemoryRegion`s in this mapping
    pub fn get_regions(&self) -> &[MemoryRegion] {
        &self.regions
    }

    /// Replaces the `MemoryRegion` at the given index
    pub fn replace_region<E: UserDefinedError>(
        &mut self,
        index: usize,
        region: MemoryRegion,
    ) -> Result<(), EbpfError<E>> {
        if index >= self.regions.len() {
            return Err(EbpfError::InvalidMemoryRegion(index));
        }
        let begin_index = region
            .vm_addr
            .checked_shr(ebpf::VIRTUAL_ADDRESS_BITS as u32)
            .unwrap_or(0) as usize;
        let end_index = region
            .vm_addr
            .saturating_add(region.len.saturating_sub(1))
            .checked_shr(ebpf::VIRTUAL_ADDRESS_BITS as u32)
            .unwrap_or(0) as usize;
        if begin_index != index || end_index != index {
            return Err(EbpfError::InvalidMemoryRegion(index));
        }
        self.regions[index] = region;
        Ok(())
    }
}

/// Maps virtual addresses to memory regions.
pub type MemoryMapping<'a> = AlignedMemoryMapping<'a>;

/// Helper for map to generate errors
pub fn generate_access_violation<E: UserDefinedError>(
    config: &Config,
    access_type: AccessType,
    vm_addr: u64,
    len: u64,
) -> Result<u64, EbpfError<E>> {
    let stack_frame = (vm_addr as i64)
        .saturating_sub(ebpf::MM_STACK_START as i64)
        .checked_div(config.stack_frame_size as i64)
        .unwrap_or(0);
    if !config.dynamic_stack_frames
        && (-1..(config.max_call_depth as i64).saturating_add(1)).contains(&stack_frame)
    {
        Err(EbpfError::StackAccessViolation(
            0, // Filled out later
            access_type,
            vm_addr,
            len,
            stack_frame,
        ))
    } else {
        let region_name = match vm_addr & (!ebpf::MM_PROGRAM_START.saturating_sub(1)) {
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
