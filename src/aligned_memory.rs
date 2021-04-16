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
        if self.write_index + num >= self.len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
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
        if self.write_index + buf.len() >= self.mem.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
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
