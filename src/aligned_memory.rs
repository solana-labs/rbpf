//! Aligned memory

/// Provides u8 slices at a specified alignment
#[derive(Clone, Debug, PartialEq)]
pub struct AlignedMemory {
    len: usize,
    align_offset: usize,
    write_index: usize,
    mem: Vec<u8>,
}
impl AlignedMemory {
    /// Return a new AlignedMem type
    pub fn new(len: usize, align: usize) -> Self {
        let mem = vec![0u8; len + align];
        let align_offset = mem.as_ptr().align_offset(align);
        Self {
            len,
            align_offset,
            mem,
            write_index: align_offset,
        }
    }
    /// Get the length of the data
    pub fn len(&self) -> usize {
        self.len
    }
    /// Is the memory empty
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// Get the current write index
    pub fn write_index(&self) -> usize {
        self.write_index
    }
    /// Get an aligned slice
    pub fn as_slice(&self) -> &[u8] {
        &self.mem[self.align_offset..self.align_offset + self.len]
    }
    /// Get an aligned mutable slice
    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        &mut self.mem[self.align_offset..self.align_offset + self.len]
    }
    /// Fill memory with value starting at the write_index
    pub fn fill(&mut self, num: usize, value: u8) -> std::io::Result<()> {
        if self.write_index + num > self.align_offset + self.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "aligned memory fill failed",
            ));
        }
        if value != 0 {
            for i in 0..num {
                self.mem[self.write_index + i] = value;
            }
        }
        self.write_index += num;
        Ok(())
    }
}
impl std::io::Write for AlignedMemory {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.write_index + buf.len() > self.align_offset + self.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "aligned memory write failed",
            ));
        }
        self.mem[self.write_index..self.write_index + buf.len()].copy_from_slice(buf);
        self.write_index += buf.len();
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
        assert!(!aligned_memory.is_empty());
        assert_eq!(aligned_memory.len(), 10);
        assert_eq!(aligned_memory.as_slice().len(), 10);
        assert_eq!(aligned_memory.as_slice_mut().len(), 10);

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
        aligned_memory.fill(5, 0).unwrap();
        aligned_memory.fill(2, 1).unwrap();
        assert_eq!(aligned_memory.write(&[2u8; 3]).unwrap(), 3);
        assert_eq!(aligned_memory.as_slice(), &[0, 0, 0, 0, 0, 1, 1, 2, 2, 2]);
        aligned_memory.fill(1, 3).unwrap_err();
        aligned_memory.write(&[4u8; 1]).unwrap_err();
        assert_eq!(aligned_memory.as_slice(), &[0, 0, 0, 0, 0, 1, 1, 2, 2, 2]);
    }

    #[test]
    fn test_aligned_memory() {
        do_test(1);
        do_test(32768);
    }
}
