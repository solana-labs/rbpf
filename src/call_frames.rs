//! Call frame handler

use crate::{
    ebpf::{MM_STACK_START, SCRATCH_REGS},
    error::{EbpfError, UserDefinedError},
    memory_region::MemoryRegion,
};

/// Stack for the eBPF stack, in bytes.
pub const CALL_FRAME_SIZE: usize = 4_096; // !! Warning: if you change stack size here also change warning in llvm (BPF_RegisterInfo.cpp)
/// Max BPF to BPF call depth
pub const MAX_CALL_DEPTH: usize = 20;

/// One call frame
#[derive(Clone, Debug)]
struct CallFrame {
    stack: MemoryRegion,
    saved_reg: [u64; 4],
    return_ptr: usize,
}

/// When BPF calls a function other then a `syscall` it expect the new
/// function to be called in its own frame.  CallFrames manages
/// call frames
#[derive(Clone, Debug)]
pub struct CallFrames {
    stack: Vec<u8>,
    frame: usize,
    max_frame: usize,
    frames: Vec<CallFrame>,
}
impl Default for CallFrames {
    fn default() -> Self {
        CallFrames::new(MAX_CALL_DEPTH, CALL_FRAME_SIZE)
    }
}
impl CallFrames {
    /// New call frame, depth indicates maximum call depth
    pub fn new(depth: usize, size: usize) -> Self {
        let mut frames = CallFrames {
            stack: vec![0u8; depth * size],
            frame: 0,
            max_frame: 0,
            frames: vec![
                CallFrame {
                    stack: MemoryRegion::default(),
                    saved_reg: [0u64; SCRATCH_REGS],
                    return_ptr: 0
                };
                depth
            ],
        };
        for i in 0..depth {
            let start = i * size;
            let end = start + size;
            // Seperate each stack frame's virtual address so that stack over/under-run is caught explicitly
            let vm_addr = MM_STACK_START + (i * 2 * size) as u64;
            frames.frames[i].stack =
                MemoryRegion::new_from_slice(&frames.stack[start..end], vm_addr, true);
        }
        frames
    }

    /// Get stack pointers
    pub fn get_stacks(&self) -> Vec<MemoryRegion> {
        let mut ptrs = Vec::new();
        for frame in self.frames.iter() {
            ptrs.push(frame.stack.clone());
        }
        ptrs
    }

    /// Get the address of a frame's top of stack
    pub fn get_stack_top(&self) -> u64 {
        self.frames[self.frame].stack.vm_addr + self.frames[self.frame].stack.len
    }

    /// Get current call frame index, 0 is the root frame
    #[allow(dead_code)]
    pub fn get_frame_index(&self) -> usize {
        self.frame
    }

    /// Get max frame index
    pub fn get_max_frame_index(&self) -> usize {
        self.max_frame
    }

    /// Push a frame
    pub fn push<E: UserDefinedError>(
        &mut self,
        saved_reg: &[u64],
        return_ptr: usize,
    ) -> Result<u64, EbpfError<E>> {
        if self.frame + 1 >= self.frames.len() {
            return Err(EbpfError::CallDepthExceeded(self.frames.len()));
        }
        self.frames[self.frame].saved_reg[..].copy_from_slice(saved_reg);
        self.frames[self.frame].return_ptr = return_ptr;
        self.frame += 1;
        if self.frame > self.max_frame {
            self.max_frame = self.frame;
        }
        Ok(self.get_stack_top())
    }

    /// Pop a frame
    pub fn pop<E: UserDefinedError>(
        &mut self,
    ) -> Result<([u64; SCRATCH_REGS], u64, usize), EbpfError<E>> {
        if self.frame == 0 {
            return Err(EbpfError::ExitRootCallFrame);
        }
        self.frame -= 1;
        Ok((
            self.frames[self.frame].saved_reg,
            self.get_stack_top(),
            self.frames[self.frame].return_ptr,
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
        const SIZE: usize = 5;
        let mut frames = CallFrames::new(DEPTH, SIZE);
        let mut ptrs: Vec<MemoryRegion> = Vec::new();
        for i in 0..DEPTH - 1 {
            let registers = vec![i as u64; SIZE];
            assert_eq!(frames.get_frame_index(), i);
            ptrs.push(frames.get_stacks()[i].clone());
            assert_eq!(ptrs[i].len, SIZE as u64);

            let top = frames.push::<UserError>(&registers[0..4], i).unwrap();
            let new_ptrs = frames.get_stacks();
            assert_eq!(top, new_ptrs[i + 1].vm_addr + new_ptrs[i + 1].len);
            assert_ne!(top, ptrs[i].vm_addr + ptrs[i].len - 1);
            assert!(
                !(ptrs[i].vm_addr <= new_ptrs[i + 1].vm_addr
                    && new_ptrs[i + 1].vm_addr < ptrs[i].vm_addr + ptrs[i].len)
            );
        }
        let i = DEPTH - 1;
        let registers = vec![i as u64; SIZE];
        assert_eq!(frames.get_frame_index(), i);
        ptrs.push(frames.get_stacks()[i].clone());

        assert!(frames.push::<UserError>(&registers, DEPTH - 1).is_err());

        for i in (0..DEPTH - 1).rev() {
            let (saved_reg, stack_ptr, return_ptr) = frames.pop::<UserError>().unwrap();
            assert_eq!(saved_reg, [i as u64, i as u64, i as u64, i as u64]);
            assert_eq!(ptrs[i].vm_addr + ptrs[i].len, stack_ptr);
            assert_eq!(i, return_ptr);
        }

        assert!(frames.pop::<UserError>().is_err());
    }
}
