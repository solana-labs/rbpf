#![allow(clippy::integer_arithmetic)]
//! Aligned memory

use std::mem;

/// Provides u8 slices at a specified alignment
#[derive(Debug, PartialEq, Eq)]
pub struct AlignedMemory<const ALIGN: usize> {
    max_len: usize,
    align_offset: usize,
    mem: Vec<u8>,
    zero_up_to_max_len: bool,
}

impl<const ALIGN: usize> AlignedMemory<ALIGN> {
    fn get_mem(max_len: usize) -> (Vec<u8>, usize) {
        let mut mem: Vec<u8> = Vec::with_capacity(max_len + ALIGN);
        mem.push(0);
        let align_offset = mem.as_ptr().align_offset(ALIGN);
        mem.resize(align_offset, 0);
        (mem, align_offset)
    }
    fn get_mem_zeroed(max_len: usize) -> (Vec<u8>, usize) {
        // use calloc() to get zeroed memory from the OS instead of using
        // malloc() + memset(), see
        // https://github.com/rust-lang/rust/issues/54628
        let mut mem = vec![0; max_len];
        let align_offset = mem.as_ptr().align_offset(ALIGN);
        mem.resize(align_offset + max_len, 0);
        (mem, align_offset)
    }
    /// Returns a filled AlignedMemory by copying the given slice
    pub fn from_slice(data: &[u8]) -> Self {
        let max_len = data.len();
        let (mut mem, align_offset) = Self::get_mem(max_len);
        mem.extend_from_slice(data);
        Self {
            max_len,
            align_offset,
            mem,
            zero_up_to_max_len: false,
        }
    }
    /// Returns a new empty AlignedMemory with uninitialized preallocated memory
    pub fn with_capacity(max_len: usize) -> Self {
        let (mem, align_offset) = Self::get_mem(max_len);
        Self {
            max_len,
            align_offset,
            mem,
            zero_up_to_max_len: false,
        }
    }
    /// Returns a new empty AlignedMemory with zero initialized preallocated memory
    pub fn with_capacity_zeroed(max_len: usize) -> Self {
        let (mut mem, align_offset) = Self::get_mem_zeroed(max_len);
        mem.truncate(align_offset);
        Self {
            max_len,
            align_offset,
            mem,
            zero_up_to_max_len: true,
        }
    }
    /// Returns a new filled AlignedMemory with zero initialized preallocated memory
    pub fn zero_filled(max_len: usize) -> Self {
        let (mem, align_offset) = Self::get_mem_zeroed(max_len);
        Self {
            max_len,
            align_offset,
            mem,
            zero_up_to_max_len: true,
        }
    }
    /// Calculate memory size
    pub fn mem_size(&self) -> usize {
        mem::size_of::<Self>() + self.mem.capacity()
    }
    /// Get the length of the data
    pub fn len(&self) -> usize {
        self.mem.len() - self.align_offset
    }
    /// Is the memory empty
    pub fn is_empty(&self) -> bool {
        self.mem.len() - self.align_offset == 0
    }
    /// Get the current write index
    pub fn write_index(&self) -> usize {
        self.mem.len()
    }
    /// Get an aligned slice
    pub fn as_slice(&self) -> &[u8] {
        let start = self.align_offset;
        let end = self.mem.len();
        &self.mem[start..end]
    }
    /// Get an aligned mutable slice
    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        let start = self.align_offset;
        let end = self.mem.len();
        &mut self.mem[start..end]
    }
    /// Grows memory with `value` repeated `num` times starting at the `write_index`
    pub fn fill_write(&mut self, num: usize, value: u8) -> std::io::Result<()> {
        if self.mem.len() + num > self.align_offset + self.max_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "aligned memory resize failed",
            ));
        }
        if self.zero_up_to_max_len && value == 0 {
            // Safe because everything up to `max_len` is zeroed and no shrinking is allowed
            unsafe {
                self.mem.set_len(self.mem.len() + num);
            }
        } else {
            self.mem.resize(self.mem.len() + num, value);
        }
        Ok(())
    }
}

// Custom Clone impl is needed to ensure alignment. Derived clone would just
// clone self.mem and there would be no guarantee that the clone allocation is
// aligned.
impl<const ALIGN: usize> Clone for AlignedMemory<ALIGN> {
    fn clone(&self) -> Self {
        AlignedMemory::from_slice(self.as_slice())
    }
}

impl<const ALIGN: usize> std::io::Write for AlignedMemory<ALIGN> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.mem.len() + buf.len() > self.align_offset + self.max_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "aligned memory write failed",
            ));
        }
        self.mem.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<const ALIGN: usize, T: AsRef<[u8]>> From<T> for AlignedMemory<ALIGN> {
    fn from(bytes: T) -> Self {
        AlignedMemory::from_slice(bytes.as_ref())
    }
}

/// Returns true if `data` is aligned to `align`.
pub fn is_memory_aligned(data: &[u8], align: usize) -> bool {
    (data.as_ptr() as usize)
        .checked_rem(align)
        .map(|remainder| remainder == 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn do_test<const ALIGN: usize>() {
        let mut aligned_memory = AlignedMemory::<ALIGN>::with_capacity(10);

        assert_eq!(aligned_memory.write(&[42u8; 1]).unwrap(), 1);
        assert_eq!(aligned_memory.write(&[42u8; 9]).unwrap(), 9);
        assert_eq!(aligned_memory.as_slice(), &[42u8; 10]);
        assert_eq!(aligned_memory.write(&[42u8; 0]).unwrap(), 0);
        assert_eq!(aligned_memory.as_slice(), &[42u8; 10]);
        aligned_memory.write(&[42u8; 1]).unwrap_err();
        assert_eq!(aligned_memory.as_slice(), &[42u8; 10]);
        aligned_memory.as_slice_mut().copy_from_slice(&[84u8; 10]);
        assert_eq!(aligned_memory.as_slice(), &[84u8; 10]);

        let mut aligned_memory = AlignedMemory::<ALIGN>::with_capacity_zeroed(10);
        aligned_memory.fill_write(5, 0).unwrap();
        aligned_memory.fill_write(2, 1).unwrap();
        assert_eq!(aligned_memory.write(&[2u8; 3]).unwrap(), 3);
        assert_eq!(aligned_memory.as_slice(), &[0, 0, 0, 0, 0, 1, 1, 2, 2, 2]);
        aligned_memory.fill_write(1, 3).unwrap_err();
        aligned_memory.write(&[4u8; 1]).unwrap_err();
        assert_eq!(aligned_memory.as_slice(), &[0, 0, 0, 0, 0, 1, 1, 2, 2, 2]);

        let aligned_memory = AlignedMemory::<ALIGN>::zero_filled(10);
        assert_eq!(aligned_memory.len(), 10);
        assert_eq!(aligned_memory.as_slice(), &[0u8; 10]);
    }

    #[test]
    fn test_aligned_memory() {
        do_test::<1>();
        do_test::<32768>();
    }
}
