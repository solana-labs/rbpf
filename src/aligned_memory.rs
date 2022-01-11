#![allow(clippy::integer_arithmetic)]
//! Aligned memory

use std::mem;

/// Provides u8 slices at a specified alignment
#[derive(Clone, Debug, PartialEq)]
pub struct AlignedMemory {
    max_len: usize,
    align_offset: usize,
    mem: Vec<u8>,
}
impl AlignedMemory {
    fn get_mem(max_len: usize, align: usize) -> (Vec<u8>, usize) {
        let mut mem: Vec<u8> = Vec::with_capacity(max_len + align);
        mem.push(0);
        let align_offset = mem.as_ptr().align_offset(align);
        mem.resize(align_offset, 0);
        (mem, align_offset)
    }
    /// Return a new AlignedMemory type
    pub fn new(max_len: usize, align: usize) -> Self {
        let (mem, align_offset) = Self::get_mem(max_len, align);
        Self {
            max_len,
            align_offset,
            mem,
        }
    }
    /// Return a pre-filled AlignedMemory type
    pub fn new_with_size(len: usize, align: usize) -> Self {
        let (mut mem, align_offset) = Self::get_mem(len, align);
        mem.resize(align_offset + len, 0);
        Self {
            max_len: len,
            align_offset,
            mem,
        }
    }
    /// Return a pre-filled AlignedMemory type
    pub fn new_with_data(data: &[u8], align: usize) -> Self {
        let max_len = data.len();
        let (mut mem, align_offset) = Self::get_mem(max_len, align);
        mem.extend_from_slice(data);
        Self {
            max_len,
            align_offset,
            mem,
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
    /// resize memory with value starting at the write_index
    pub fn resize(&mut self, num: usize, value: u8) -> std::io::Result<()> {
        if self.mem.len() + num > self.align_offset + self.max_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "aligned memory resize failed",
            ));
        }
        self.mem.resize(self.mem.len() + num, value);
        Ok(())
    }
}
impl std::io::Write for AlignedMemory {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn do_test(align: usize) {
        let mut aligned_memory = AlignedMemory::new(10, align);

        assert_eq!(aligned_memory.write(&[42u8; 1]).unwrap(), 1);
        assert_eq!(aligned_memory.write(&[42u8; 9]).unwrap(), 9);
        assert_eq!(aligned_memory.as_slice(), &[42u8; 10]);
        assert_eq!(aligned_memory.write(&[42u8; 0]).unwrap(), 0);
        assert_eq!(aligned_memory.as_slice(), &[42u8; 10]);
        aligned_memory.write(&[42u8; 1]).unwrap_err();
        assert_eq!(aligned_memory.as_slice(), &[42u8; 10]);
        aligned_memory.as_slice_mut().copy_from_slice(&[84u8; 10]);
        assert_eq!(aligned_memory.as_slice(), &[84u8; 10]);

        let mut aligned_memory = AlignedMemory::new(10, align);
        aligned_memory.resize(5, 0).unwrap();
        aligned_memory.resize(2, 1).unwrap();
        assert_eq!(aligned_memory.write(&[2u8; 3]).unwrap(), 3);
        assert_eq!(aligned_memory.as_slice(), &[0, 0, 0, 0, 0, 1, 1, 2, 2, 2]);
        aligned_memory.resize(1, 3).unwrap_err();
        aligned_memory.write(&[4u8; 1]).unwrap_err();
        assert_eq!(aligned_memory.as_slice(), &[0, 0, 0, 0, 0, 1, 1, 2, 2, 2]);
    }

    #[test]
    fn test_aligned_memory() {
        do_test(1);
        do_test(32768);
    }
}
