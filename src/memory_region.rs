//! This module defines memory regions

use crate::{
    ebpf,
    error::EbpfError,
    vm::{Config, ProgramResult},
};
use std::{array, cell::UnsafeCell, fmt, ops::Range};

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
    pub fn vm_to_host(&self, vm_addr: u64, len: u64) -> ProgramResult {
        // This can happen if a region starts at an offset from the base region
        // address, eg with rodata regions if config.optimize_rodata = true, see
        // Elf::get_ro_region.
        if vm_addr < self.vm_addr {
            return ProgramResult::Err(EbpfError::InvalidVirtualAddress(vm_addr));
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
        if let Some(end_offset) = gapped_offset.checked_add(len) {
            if end_offset <= self.len && !is_in_gap {
                return ProgramResult::Ok(self.host_addr.saturating_add(gapped_offset));
            }
        }
        ProgramResult::Err(EbpfError::InvalidVirtualAddress(vm_addr))
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

/// Memory mapping based on eytzinger search.
#[derive(Debug)]
pub struct UnalignedMemoryMapping<'a> {
    /// Mapped memory regions
    regions: Box<[MemoryRegion]>,
    /// Copy of the regions vm_addr fields to improve cache density
    region_addresses: Box<[u64]>,
    /// Cache of the last `MappingCache::SIZE` vm_addr => region_index lookups
    cache: UnsafeCell<MappingCache>,
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
        in_index = self.construct_eytzinger_order(
            ascending_regions,
            in_index,
            out_index.saturating_mul(2).saturating_add(1),
        );
        self.regions[out_index] = ascending_regions[in_index].clone();
        self.region_addresses[out_index] = ascending_regions[in_index].vm_addr;
        self.construct_eytzinger_order(
            ascending_regions,
            in_index.saturating_add(1),
            out_index.saturating_mul(2).saturating_add(2),
        )
    }

    /// Creates a new MemoryMapping structure from the given regions
    pub fn new(mut regions: Vec<MemoryRegion>, config: &'a Config) -> Result<Self, EbpfError> {
        regions.sort();
        for index in 1..regions.len() {
            let first = &regions[index.saturating_sub(1)];
            let second = &regions[index];
            if first.vm_addr.saturating_add(first.len) > second.vm_addr {
                return Err(EbpfError::InvalidMemoryRegion(index));
            }
        }

        let mut result = Self {
            regions: vec![MemoryRegion::default(); regions.len()].into_boxed_slice(),
            region_addresses: vec![0; regions.len()].into_boxed_slice(),
            cache: UnsafeCell::new(MappingCache::new()),
            config,
        };
        result.construct_eytzinger_order(&regions, 0, 0);
        Ok(result)
    }

    /// Given a list of regions translate from virtual machine to host address
    #[allow(clippy::integer_arithmetic)]
    pub fn map(&self, access_type: AccessType, vm_addr: u64, len: u64, pc: usize) -> ProgramResult {
        // Safety:
        // &mut references to the mapping cache are only created internally here
        // and in replace_region(). The methods never invoke each other and
        // UnalignedMemoryMapping is !Sync, so the cache reference below is
        // guaranteed to be unique.
        let cache = unsafe { &mut *self.cache.get() };
        let (cache_miss, index) = if let Some(region) = cache.find(vm_addr) {
            (false, region)
        } else {
            let mut index = 1;
            while index <= self.region_addresses.len() {
                // Safety:
                // we start the search at index=1 and in the loop condition check
                // for index <= len, so bound checks can be avoided
                index = (index << 1)
                    + unsafe { *self.region_addresses.get_unchecked(index - 1) <= vm_addr }
                        as usize;
            }
            index >>= index.trailing_zeros() + 1;
            if index == 0 {
                return generate_access_violation(self.config, access_type, vm_addr, len, pc);
            }
            (true, index)
        };

        // Safety:
        // we check for index==0 above, and by construction if we get here index
        // must be contained in region
        let region = unsafe { self.regions.get_unchecked(index - 1) };
        if access_type == AccessType::Load || region.is_writable {
            if let ProgramResult::Ok(host_addr) = region.vm_to_host(vm_addr, len) {
                if cache_miss {
                    cache.insert(
                        region.vm_addr..region.vm_addr.saturating_add(region.len),
                        index,
                    );
                }
                return ProgramResult::Ok(host_addr);
            }
        }

        generate_access_violation(self.config, access_type, vm_addr, len, pc)
    }

    /// Returns the `MemoryRegion`s in this mapping
    pub fn get_regions(&self) -> &[MemoryRegion] {
        &self.regions
    }

    /// Replaces the `MemoryRegion` at the given index
    pub fn replace_region(&mut self, index: usize, region: MemoryRegion) -> Result<(), EbpfError> {
        if index >= self.regions.len() || self.regions[index].vm_addr != region.vm_addr {
            return Err(EbpfError::InvalidMemoryRegion(index));
        }
        self.regions[index] = region;
        self.cache.get_mut().flush();
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
    pub fn new(mut regions: Vec<MemoryRegion>, config: &'a Config) -> Result<Self, EbpfError> {
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
    pub fn map(&self, access_type: AccessType, vm_addr: u64, len: u64, pc: usize) -> ProgramResult {
        let index = vm_addr
            .checked_shr(ebpf::VIRTUAL_ADDRESS_BITS as u32)
            .unwrap_or(0) as usize;
        if (1..self.regions.len()).contains(&index) {
            let region = &self.regions[index];
            if access_type == AccessType::Load || region.is_writable {
                if let ProgramResult::Ok(host_addr) = region.vm_to_host(vm_addr, len) {
                    return ProgramResult::Ok(host_addr);
                }
            }
        }
        generate_access_violation(self.config, access_type, vm_addr, len, pc)
    }

    /// Returns the `MemoryRegion`s in this mapping
    pub fn get_regions(&self) -> &[MemoryRegion] {
        &self.regions
    }

    /// Replaces the `MemoryRegion` at the given index
    pub fn replace_region(&mut self, index: usize, region: MemoryRegion) -> Result<(), EbpfError> {
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

/// Maps virtual memory to host memory.
#[derive(Debug)]
pub enum MemoryMapping<'a> {
    /// Aligned memory mapping which uses the upper half of an address to
    /// identify the underlying memory region.
    Aligned(AlignedMemoryMapping<'a>),
    /// Memory mapping that allows mapping unaligned memory regions.
    Unaligned(UnalignedMemoryMapping<'a>),
}

impl<'a> MemoryMapping<'a> {
    /// Creates a new memory mapping.
    ///
    /// Uses aligned or unaligned memory mapping depending on the value of
    /// `config.aligned_memory_mapping=true`.
    pub fn new(regions: Vec<MemoryRegion>, config: &'a Config) -> Result<Self, EbpfError> {
        if config.aligned_memory_mapping {
            AlignedMemoryMapping::new(regions, config).map(MemoryMapping::Aligned)
        } else {
            UnalignedMemoryMapping::new(regions, config).map(MemoryMapping::Unaligned)
        }
    }

    /// Map virtual memory to host memory.
    pub fn map(&self, access_type: AccessType, vm_addr: u64, len: u64, pc: usize) -> ProgramResult {
        match self {
            MemoryMapping::Aligned(m) => m.map(access_type, vm_addr, len, pc),
            MemoryMapping::Unaligned(m) => m.map(access_type, vm_addr, len, pc),
        }
    }

    /// Returns the `MemoryRegion`s in this mapping.
    pub fn get_regions(&self) -> &[MemoryRegion] {
        match self {
            MemoryMapping::Aligned(m) => m.get_regions(),
            MemoryMapping::Unaligned(m) => m.get_regions(),
        }
    }

    /// Replaces the `MemoryRegion` at the given index
    pub fn replace_region(&mut self, index: usize, region: MemoryRegion) -> Result<(), EbpfError> {
        match self {
            MemoryMapping::Aligned(m) => m.replace_region(index, region),
            MemoryMapping::Unaligned(m) => m.replace_region(index, region),
        }
    }
}

/// Helper for map to generate errors
fn generate_access_violation(
    config: &Config,
    access_type: AccessType,
    vm_addr: u64,
    len: u64,
    pc: usize,
) -> ProgramResult {
    let stack_frame = (vm_addr as i64)
        .saturating_sub(ebpf::MM_STACK_START as i64)
        .checked_div(config.stack_frame_size as i64)
        .unwrap_or(0);
    if !config.dynamic_stack_frames
        && (-1..(config.max_call_depth as i64).saturating_add(1)).contains(&stack_frame)
    {
        ProgramResult::Err(EbpfError::StackAccessViolation(
            pc,
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
        ProgramResult::Err(EbpfError::AccessViolation(
            pc,
            access_type,
            vm_addr,
            len,
            region_name,
        ))
    }
}

/// Fast, small linear cache used to speed up unaligned memory mapping.
#[derive(Debug)]
struct MappingCache {
    // The cached entries.
    entries: [(Range<u64>, usize); MappingCache::SIZE as usize],
    // Index of the last accessed memory region.
    //
    // New entries are written backwards, so that find() can always scan
    // forward which is faster.
    head: isize,
}

impl MappingCache {
    const SIZE: isize = 4;

    fn new() -> MappingCache {
        MappingCache {
            entries: array::from_fn(|_| (0..0, 0)),
            head: 0,
        }
    }

    #[allow(clippy::integer_arithmetic)]
    #[inline]
    fn find(&self, vm_addr: u64) -> Option<usize> {
        for i in 0..Self::SIZE {
            let index = (self.head + i) % Self::SIZE;
            // Safety:
            // index is guaranteed to be between 0..Self::SIZE
            let (vm_range, region_index) = unsafe { self.entries.get_unchecked(index as usize) };
            if vm_range.contains(&vm_addr) {
                return Some(*region_index);
            }
        }

        None
    }

    #[allow(clippy::integer_arithmetic)]
    #[inline]
    fn insert(&mut self, vm_range: Range<u64>, region_index: usize) {
        self.head = (self.head - 1).rem_euclid(Self::SIZE);
        // Safety:
        // self.head is guaranteed to be between 0..Self::SIZE
        unsafe { *self.entries.get_unchecked_mut(self.head as usize) = (vm_range, region_index) };
    }

    #[inline]
    fn flush(&mut self) {
        self.entries = array::from_fn(|_| (0..0, 0));
        self.head = 0;
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_mapping_cache() {
        let mut cache = MappingCache::new();
        assert_eq!(cache.find(0), None);

        let mut ranges = vec![10u64..20, 20..30, 30..40, 40..50];
        for (region, range) in ranges.iter().cloned().enumerate() {
            cache.insert(range, region);
        }
        for (region, range) in ranges.iter().enumerate() {
            if region > 0 {
                assert_eq!(cache.find(range.start - 1), Some(region - 1));
            } else {
                assert_eq!(cache.find(range.start - 1), None);
            }
            assert_eq!(cache.find(range.start), Some(region));
            assert_eq!(cache.find(range.start + 1), Some(region));
            assert_eq!(cache.find(range.end - 1), Some(region));
            if region < 3 {
                assert_eq!(cache.find(range.end), Some(region + 1));
            } else {
                assert_eq!(cache.find(range.end), None);
            }
        }

        cache.insert(50..60, 4);
        ranges.push(50..60);
        for (region, range) in ranges.iter().enumerate() {
            if region == 0 {
                assert_eq!(cache.find(range.start), None);
                continue;
            }
            if region > 1 {
                assert_eq!(cache.find(range.start - 1), Some(region - 1));
            } else {
                assert_eq!(cache.find(range.start - 1), None);
            }
            assert_eq!(cache.find(range.start), Some(region));
            assert_eq!(cache.find(range.start + 1), Some(region));
            assert_eq!(cache.find(range.end - 1), Some(region));
            if region < 4 {
                assert_eq!(cache.find(range.end), Some(region + 1));
            } else {
                assert_eq!(cache.find(range.end), None);
            }
        }
    }

    #[test]
    fn test_mapping_cache_flush() {
        let mut cache = MappingCache::new();
        assert_eq!(cache.find(0), None);
        cache.insert(0..10, 0);
        assert_eq!(cache.find(0), Some(0));
        cache.flush();
        assert_eq!(cache.find(0), None);
    }

    #[test]
    fn test_map_empty() {
        let config = Config::default();
        let m = UnalignedMemoryMapping::new(vec![], &config).unwrap();
        assert!(matches!(
            m.map(AccessType::Load, ebpf::MM_INPUT_START, 8, 0),
            ProgramResult::Err(EbpfError::AccessViolation(..))
        ));

        let m = AlignedMemoryMapping::new(vec![], &config).unwrap();
        assert!(matches!(
            m.map(AccessType::Load, ebpf::MM_INPUT_START, 8, 0),
            ProgramResult::Err(EbpfError::AccessViolation(..))
        ));
    }

    #[test]
    fn test_unaligned_map_overlap() {
        let config = Config::default();
        let mem1 = [1, 2, 3, 4];
        let mem2 = [5, 6];
        assert!(matches!(
            UnalignedMemoryMapping::new(
                vec![
                    MemoryRegion::new_readonly(&mem1, ebpf::MM_INPUT_START),
                    MemoryRegion::new_readonly(&mem2, ebpf::MM_INPUT_START + mem1.len() as u64 - 1),
                ],
                &config,
            )
            .unwrap_err(),
            EbpfError::InvalidMemoryRegion(1),
        ));
        assert!(UnalignedMemoryMapping::new(
            vec![
                MemoryRegion::new_readonly(&mem1, ebpf::MM_INPUT_START),
                MemoryRegion::new_readonly(&mem2, ebpf::MM_INPUT_START + mem1.len() as u64),
            ],
            &config,
        )
        .is_ok());
    }

    #[test]
    fn test_unaligned_map() {
        let config = Config::default();
        let mem1 = [11];
        let mem2 = [22, 22];
        let mem3 = [33];
        let mem4 = [44, 44];
        let m = UnalignedMemoryMapping::new(
            vec![
                MemoryRegion::new_readonly(&mem1, ebpf::MM_INPUT_START),
                MemoryRegion::new_readonly(&mem2, ebpf::MM_INPUT_START + mem1.len() as u64),
                MemoryRegion::new_readonly(
                    &mem3,
                    ebpf::MM_INPUT_START + (mem1.len() + mem2.len()) as u64,
                ),
                MemoryRegion::new_readonly(
                    &mem4,
                    ebpf::MM_INPUT_START + (mem1.len() + mem2.len() + mem3.len()) as u64,
                ),
            ],
            &config,
        )
        .unwrap();

        assert_eq!(
            m.map(AccessType::Load, ebpf::MM_INPUT_START, 1, 0).unwrap(),
            mem1.as_ptr() as u64
        );

        assert_eq!(
            m.map(
                AccessType::Load,
                ebpf::MM_INPUT_START + mem1.len() as u64,
                1,
                0,
            )
            .unwrap(),
            mem2.as_ptr() as u64
        );

        assert_eq!(
            m.map(
                AccessType::Load,
                ebpf::MM_INPUT_START + (mem1.len() + mem2.len()) as u64,
                1,
                0,
            )
            .unwrap(),
            mem3.as_ptr() as u64
        );

        assert_eq!(
            m.map(
                AccessType::Load,
                ebpf::MM_INPUT_START + (mem1.len() + mem2.len() + mem3.len()) as u64,
                1,
                0,
            )
            .unwrap(),
            mem4.as_ptr() as u64
        );

        assert!(matches!(
            m.map(
                AccessType::Load,
                ebpf::MM_INPUT_START + (mem1.len() + mem2.len() + mem3.len() + mem4.len()) as u64,
                1,
                0,
            ),
            ProgramResult::Err(EbpfError::AccessViolation(..))
        ));
    }

    #[test]
    fn test_unaligned_map_replace_region() {
        let config = Config::default();
        let mem1 = [11];
        let mem2 = [22, 22];
        let mem3 = [33];
        let mut m = UnalignedMemoryMapping::new(
            vec![
                MemoryRegion::new_readonly(&mem1, ebpf::MM_INPUT_START),
                MemoryRegion::new_readonly(&mem2, ebpf::MM_INPUT_START + mem1.len() as u64),
            ],
            &config,
        )
        .unwrap();

        assert_eq!(
            m.map(AccessType::Load, ebpf::MM_INPUT_START, 1, 0).unwrap(),
            mem1.as_ptr() as u64
        );

        assert_eq!(
            m.map(
                AccessType::Load,
                ebpf::MM_INPUT_START + mem1.len() as u64,
                1,
                0,
            )
            .unwrap(),
            mem2.as_ptr() as u64
        );

        assert!(matches!(
            m.replace_region(
                2,
                MemoryRegion::new_readonly(&mem3, ebpf::MM_INPUT_START + mem1.len() as u64)
            ),
            Err(EbpfError::InvalidMemoryRegion(2))
        ));

        let region_index = m
            .get_regions()
            .iter()
            .position(|mem| mem.vm_addr == ebpf::MM_INPUT_START + mem1.len() as u64)
            .unwrap();

        // old.vm_addr != new.vm_addr
        assert!(matches!(
            m.replace_region(
                region_index,
                MemoryRegion::new_readonly(&mem3, ebpf::MM_INPUT_START + mem1.len() as u64 + 1)
            ),
            Err(EbpfError::InvalidMemoryRegion(i)) if i == region_index
        ));

        m.replace_region(
            region_index,
            MemoryRegion::new_readonly(&mem3, ebpf::MM_INPUT_START + mem1.len() as u64),
        )
        .unwrap();

        assert_eq!(
            m.map(
                AccessType::Load,
                ebpf::MM_INPUT_START + mem1.len() as u64,
                1,
                0,
            )
            .unwrap(),
            mem3.as_ptr() as u64
        );
    }

    #[test]
    fn test_aligned_map_replace_region() {
        let config = Config::default();
        let mem1 = [11];
        let mem2 = [22, 22];
        let mem3 = [33, 33];
        let mut m = AlignedMemoryMapping::new(
            vec![
                MemoryRegion::new_readonly(&mem1, ebpf::MM_PROGRAM_START),
                MemoryRegion::new_readonly(&mem2, ebpf::MM_STACK_START),
            ],
            &config,
        )
        .unwrap();

        assert_eq!(
            m.map(AccessType::Load, ebpf::MM_STACK_START, 1, 0).unwrap(),
            mem2.as_ptr() as u64
        );

        // index > regions.len()
        assert!(matches!(
            m.replace_region(3, MemoryRegion::new_readonly(&mem3, ebpf::MM_STACK_START)),
            Err(EbpfError::InvalidMemoryRegion(3))
        ));

        // index != addr >> VIRTUAL_ADDRESS_BITS
        assert!(matches!(
            m.replace_region(2, MemoryRegion::new_readonly(&mem3, ebpf::MM_HEAP_START)),
            Err(EbpfError::InvalidMemoryRegion(2))
        ));

        // index + len != addr >> VIRTUAL_ADDRESS_BITS
        assert!(matches!(
            m.replace_region(
                2,
                MemoryRegion::new_readonly(&mem3, ebpf::MM_HEAP_START - 1)
            ),
            Err(EbpfError::InvalidMemoryRegion(2))
        ));

        m.replace_region(2, MemoryRegion::new_readonly(&mem3, ebpf::MM_STACK_START))
            .unwrap();

        assert_eq!(
            m.map(AccessType::Load, ebpf::MM_STACK_START, 1, 0).unwrap(),
            mem3.as_ptr() as u64
        );
    }
}
