//! Call frame handler

use crate::{
    aligned_memory::AlignedMemory,
    ebpf::{ELF_INSN_DUMP_OFFSET, HOST_ALIGN, MM_STACK_START, SCRATCH_REGS},
    error::{EbpfError, UserDefinedError},
    memory_region::MemoryRegion,
};

/// One call frame
#[derive(Clone, Debug)]
struct CallFrame {
    vm_addr: u64,
    saved_reg: [u64; 4],
    return_ptr: usize,
}

/// When BPF calls a function other then a `syscall` it expect the new
/// function to be called in its own frame.  CallFrames manages
/// call frames
#[derive(Clone, Debug)]
pub struct CallFrames {
    stack: AlignedMemory,
    region: MemoryRegion,
    frame_index: usize,
    frame_index_max: usize,
    frames: Vec<CallFrame>,
}
impl CallFrames {
    /// New call frame, depth indicates maximum call depth
    pub fn new(depth: usize, frame_size: usize) -> Self {
        let mut stack = AlignedMemory::new(depth * frame_size, HOST_ALIGN);
        stack.resize(depth * frame_size, 0).unwrap();
        let region =
            MemoryRegion::new_from_slice(stack.as_slice(), MM_STACK_START, frame_size as u64, true);
        let mut frames = CallFrames {
            stack,
            region,
            frame_index: 0,
            frame_index_max: 0,
            frames: vec![
                CallFrame {
                    vm_addr: 0,
                    saved_reg: [0u64; SCRATCH_REGS],
                    return_ptr: 0
                };
                depth
            ],
        };
        for i in 0..depth {
            // Seperate each stack frame's virtual address so that stack over/under-run is caught explicitly
            frames.frames[i].vm_addr = MM_STACK_START + (i * 2 * frame_size) as u64;
        }
        frames
    }

    /// Get stack memory region
    pub fn get_region(&self) -> &MemoryRegion {
        &self.region
    }

    /// Get the vm address of the beginning of each stack frame
    pub fn get_frame_pointers(&self) -> Vec<u64> {
        self.frames.iter().map(|frame| frame.vm_addr).collect()
    }

    /// Get the address of a frame's top of stack
    pub fn get_stack_top(&self) -> u64 {
        self.frames[self.frame_index].vm_addr + (1 << self.region.vm_gap_shift)
    }

    /// Get current call frame index, 0 is the root frame
    pub fn get_frame_index(&self) -> usize {
        self.frame_index
    }

    /// Get max frame index
    pub fn get_max_frame_index(&self) -> usize {
        self.frame_index_max
    }

    /// Push a frame
    pub fn push<E: UserDefinedError>(
        &mut self,
        saved_reg: &[u64],
        return_ptr: usize,
    ) -> Result<u64, EbpfError<E>> {
        if self.frame_index + 1 >= self.frames.len() {
            return Err(EbpfError::CallDepthExceeded(
                return_ptr + ELF_INSN_DUMP_OFFSET - 1,
                self.frames.len(),
            ));
        }
        self.frames[self.frame_index].saved_reg[..].copy_from_slice(saved_reg);
        self.frames[self.frame_index].return_ptr = return_ptr;
        self.frame_index += 1;
        self.frame_index_max = self.frame_index_max.max(self.frame_index);
        Ok(self.get_stack_top())
    }

    /// Pop a frame
    pub fn pop<E: UserDefinedError>(
        &mut self,
    ) -> Result<([u64; SCRATCH_REGS], u64, usize), EbpfError<E>> {
        if self.frame_index == 0 {
            return Err(EbpfError::ExitRootCallFrame);
        }
        self.frame_index -= 1;
        Ok((
            self.frames[self.frame_index].saved_reg,
            self.get_stack_top(),
            self.frames[self.frame_index].return_ptr,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user_error::UserError;

    #[test]
    fn test_frames() {
        const DEPTH: usize = 10;
        const FRAME_SIZE: u64 = 8;
        let mut frames = CallFrames::new(DEPTH, FRAME_SIZE as usize);
        let mut ptrs: Vec<u64> = Vec::new();
        for i in 0..DEPTH - 1 {
            let registers = vec![i as u64; FRAME_SIZE as usize];
            assert_eq!(frames.get_frame_index(), i);
            ptrs.push(frames.get_frame_pointers()[i]);

            let top = frames.push::<UserError>(&registers[0..4], i).unwrap();
            let new_ptrs = frames.get_frame_pointers();
            assert_eq!(top, new_ptrs[i + 1] + FRAME_SIZE);
            assert_ne!(top, ptrs[i] + FRAME_SIZE - 1);
            assert!(!(ptrs[i] <= new_ptrs[i + 1] && new_ptrs[i + 1] < ptrs[i] + FRAME_SIZE));
        }
        let i = DEPTH - 1;
        let registers = vec![i as u64; FRAME_SIZE as usize];
        assert_eq!(frames.get_frame_index(), i);
        ptrs.push(frames.get_frame_pointers()[i]);

        assert!(frames.push::<UserError>(&registers, DEPTH - 1).is_err());

        for i in (0..DEPTH - 1).rev() {
            let (saved_reg, stack_ptr, return_ptr) = frames.pop::<UserError>().unwrap();
            assert_eq!(saved_reg, [i as u64, i as u64, i as u64, i as u64]);
            assert_eq!(ptrs[i] + FRAME_SIZE, stack_ptr);
            assert_eq!(i, return_ptr);
        }

        assert!(frames.pop::<UserError>().is_err());
    }
}
