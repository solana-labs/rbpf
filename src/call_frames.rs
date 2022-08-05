#![allow(clippy::integer_arithmetic)]
//! Call frame handler

use crate::{
    aligned_memory::AlignedMemory,
    ebpf::{ELF_INSN_DUMP_OFFSET, HOST_ALIGN, MM_STACK_START, SCRATCH_REGS},
    error::{EbpfError, UserDefinedError},
    memory_region::MemoryRegion,
    vm::Config,
};

/// One call frame
#[derive(Clone, Debug)]
struct CallFrame {
    frame_ptr: u64,
    saved_reg: [u64; 4],
    return_ptr: usize,
}

/// When BPF calls a function other then a `syscall` it expect the new
/// function to be called in its own frame.  CallFrames manages
/// call frames
#[derive(Clone, Debug)]
pub struct CallFrames<'a> {
    config: &'a Config,
    stack: AlignedMemory<{ HOST_ALIGN }>,
    stack_ptr: u64,
    frame_index: usize,
    frame_index_max: usize,
    frames: Vec<CallFrame>,
}
impl<'a> CallFrames<'a> {
    /// New call frame, depth indicates maximum call depth
    pub fn new(config: &'a Config) -> Self {
        let stack_len = config.stack_size();
        let stack = AlignedMemory::zero_filled(stack_len);

        let mut frames = CallFrames {
            config,
            stack,
            stack_ptr: 0,
            frame_index: 0,
            frame_index_max: 0,
            frames: vec![
                CallFrame {
                    frame_ptr: 0,
                    saved_reg: [0u64; SCRATCH_REGS],
                    return_ptr: 0,
                };
                config.max_call_depth
            ],
        };

        let frame = &mut frames.frames[0];
        if config.dynamic_stack_frames {
            // the stack is fully descending, frames start as empty and change
            // size as resize_stack() is invoked anytime r11 is modified
            frame.frame_ptr = MM_STACK_START + stack_len as u64;
            frames.stack_ptr = frame.frame_ptr;
        } else {
            // within a frame the stack grows down, but frames are ascending
            frame.frame_ptr = MM_STACK_START + config.stack_frame_size as u64;
            frames.stack_ptr = MM_STACK_START;
        }

        frames
    }

    /// Get stack memory region
    pub fn get_memory_region(&mut self) -> MemoryRegion {
        MemoryRegion::new_writable_gapped(
            self.stack.as_slice_mut(),
            MM_STACK_START,
            if !self.config.dynamic_stack_frames && self.config.enable_stack_frame_gaps {
                self.config.stack_frame_size as u64
            } else {
                0
            },
        )
    }

    /// Get the vm address of the beginning of each stack frame
    pub fn get_frame_pointers(&self) -> Vec<u64> {
        self.frames[..=self.frame_index]
            .iter()
            .map(|frame| frame.frame_ptr)
            .collect()
    }

    /// Get the frame pointer for the current frame
    pub fn get_frame_ptr(&self) -> u64 {
        self.frames[self.frame_index].frame_ptr
    }

    /// Get the stack pointer
    pub fn get_stack_ptr(&self) -> u64 {
        self.stack_ptr
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
        let frame_ptr = self.frames[self.frame_index].frame_ptr;
        self.frames[self.frame_index].return_ptr = return_ptr;

        self.frame_index += 1;

        let frame = &mut self.frames[self.frame_index];

        if self.config.dynamic_stack_frames {
            frame.frame_ptr = self.stack_ptr;
        } else {
            frame.frame_ptr = frame_ptr
                + self.config.stack_frame_size as u64
                    * if self.config.enable_stack_frame_gaps {
                        2
                    } else {
                        1
                    };
            self.stack_ptr = frame.frame_ptr - self.config.stack_frame_size as u64;
        }

        self.frame_index_max = self.frame_index_max.max(self.frame_index);

        Ok(self.get_frame_ptr())
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
            self.get_frame_ptr(),
            self.frames[self.frame_index].return_ptr,
        ))
    }

    /// Resize the stack
    pub fn resize_stack(&mut self, amount: i64) {
        debug_assert!(self.config.dynamic_stack_frames);

        // Let the stack overflow. For legitimate programs, this is a nearly
        // impossible condition to hit since programs are metered and we already
        // enforce a maximum call depth. For programs that intentionally mess
        // around with the stack pointer, MemoryRegion::map will return
        // InvalidVirtualAddress(stack_ptr) once an invalid stack address is
        // accessed.
        self.stack_ptr = self.stack_ptr.overflowing_add(amount as u64).0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user_error::UserError;

    #[test]
    fn test_frames() {
        for (enable_stack_frame_gaps, dynamic_stack_frames) in
            [(false, false), (true, false), (false, true)]
        {
            let config = Config {
                max_call_depth: 10,
                stack_frame_size: 8,
                enable_stack_frame_gaps,
                dynamic_stack_frames,
                ..Config::default()
            };
            let mut frames = CallFrames::new(&config);
            let mut frame_ptrs: Vec<u64> = Vec::new();

            for i in 0..config.max_call_depth - 1 {
                let registers = vec![i as u64; 4];

                assert_eq!(frames.get_frame_index(), i);
                frame_ptrs.push(frames.get_frame_pointers()[i]);

                let expected_frame_size = if dynamic_stack_frames {
                    let frame_size = i as i64 * 8;
                    frames.resize_stack(-frame_size);

                    frame_size as u64
                } else {
                    config.stack_frame_size as u64 * if enable_stack_frame_gaps { 2 } else { 1 }
                };

                // push the next frame, get the new frame pointers and check
                // that push returns the newly added frame pointer
                let top = frames.push::<UserError>(&registers[0..4], i).unwrap();
                let new_ptrs = frames.get_frame_pointers();
                assert_eq!(top, new_ptrs[i + 1]);

                // check that the size of the new frame is what we expect. We
                // need to abs() here since dynamic frames grow down but static
                // frames grow up.
                let frame_size = (frame_ptrs[i] as i64 - new_ptrs[i + 1] as i64).unsigned_abs();
                assert_eq!(frame_size, expected_frame_size);
            }

            let i = config.max_call_depth - 1;
            let registers = vec![i as u64; 4];
            assert_eq!(frames.get_frame_index(), i);
            frame_ptrs.push(frames.get_frame_pointers()[i]);

            assert!(frames
                .push::<UserError>(&registers, config.max_call_depth - 1)
                .is_err());

            for i in (0..config.max_call_depth - 1).rev() {
                let (saved_reg, frame_ptr, return_ptr) = frames.pop::<UserError>().unwrap();
                assert_eq!(saved_reg, [i as u64, i as u64, i as u64, i as u64]);
                assert_eq!(frame_ptrs[i], frame_ptr);
                assert_eq!(i, return_ptr);
            }

            assert!(frames.pop::<UserError>().is_err());
        }
    }

    #[test]
    fn test_stack_ptr_overflow() {
        let config = Config {
            enable_stack_frame_gaps: false,
            dynamic_stack_frames: true,
            ..Config::default()
        };
        let mut frames = CallFrames::new(&config);
        frames.resize_stack(-(MM_STACK_START as i64 + config.stack_size() as i64));
        assert_eq!(frames.get_stack_ptr(), 0);

        // test that we overflow the stack without panicking
        frames.resize_stack(-2);
        assert_eq!(frames.get_stack_ptr(), u64::MAX - 1);
    }

    #[test]
    fn test_stack_ptr_underflow() {
        let config = Config {
            enable_stack_frame_gaps: false,
            dynamic_stack_frames: true,
            ..Config::default()
        };
        let mut frames = CallFrames::new(&config);
        frames.resize_stack(-(MM_STACK_START as i64 + config.stack_size() as i64));
        assert_eq!(frames.get_stack_ptr(), 0);

        // test that we underflow the stack without panicking
        frames.resize_stack(u64::MAX as i64);
        frames.resize_stack(2);
        assert_eq!(frames.get_stack_ptr(), 1);
    }
}
