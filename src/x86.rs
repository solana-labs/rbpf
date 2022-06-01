#![allow(clippy::integer_arithmetic)]
use crate::{
    error::{EbpfError, UserDefinedError},
    jit::{emit, emit_variable_length, JitCompiler, OperandSize},
};
use rand::Rng;

pub const RAX: u8 = 0;
pub const RCX: u8 = 1;
pub const RDX: u8 = 2;
pub const RBX: u8 = 3;
pub const RSP: u8 = 4;
pub const RBP: u8 = 5;
pub const RSI: u8 = 6;
pub const RDI: u8 = 7;
pub const R8: u8 = 8;
pub const R9: u8 = 9;
pub const R10: u8 = 10;
pub const R11: u8 = 11;
pub const R12: u8 = 12;
pub const R13: u8 = 13;
pub const R14: u8 = 14;
pub const R15: u8 = 15;

// System V AMD64 ABI
// Works on: Linux, macOS, BSD and Solaris but not on Windows
pub const ARGUMENT_REGISTERS: [u8; 6] = [RDI, RSI, RDX, RCX, R8, R9];
pub const CALLER_SAVED_REGISTERS: [u8; 9] = [RAX, RCX, RDX, RSI, RDI, R8, R9, R10, R11];
pub const CALLEE_SAVED_REGISTERS: [u8; 6] = [RBP, RBX, R12, R13, R14, R15];

macro_rules! exclude_operand_sizes {
    ($size:expr, $($to_exclude:path)|+ $(,)?) => {
        #[cfg(debug_assertions)]
        match $size {
            $($to_exclude)|+ => return Self::DEFAULT,
            _ => {},
        }
    }
}

struct X86Rex {
    w: bool,
    r: bool,
    x: bool,
    b: bool,
}

struct X86ModRm {
    mode: u8,
    r: u8,
    m: u8,
}

struct X86Sib {
    scale: u8,
    index: u8,
    base: u8,
}

#[derive(Copy, Clone)]
pub enum X86IndirectAccess {
    /// [second_operand + offset]
    Offset(i32),
    /// [second_operand + offset + index << shift]
    OffsetIndexShift(i32, u8, u8),
}

#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum FenceType {
    /// lfence
    Load = 5,
    /// mfence
    All = 6,
    /// sfence
    Store = 7,
}

#[derive(Copy, Clone)]
pub struct X86Instruction {
    pub size: OperandSize,
    pub opcode_escape_sequence: u8,
    pub opcode: u8,
    pub modrm: bool,
    pub indirect: Option<X86IndirectAccess>,
    pub first_operand: u8,
    pub second_operand: u8,
    pub immediate_size: OperandSize,
    pub immediate: i64,
}

impl X86Instruction {
    pub const DEFAULT: X86Instruction = X86Instruction {
        size: OperandSize::S0,
        opcode_escape_sequence: 0,
        opcode: 0,
        modrm: true,
        indirect: None,
        first_operand: 0,
        second_operand: 0,
        immediate_size: OperandSize::S0,
        immediate: 0,
    };

    pub fn emit<E: UserDefinedError>(&self, jit: &mut JitCompiler) -> Result<(), EbpfError<E>> {
        debug_assert!(!matches!(self.size, OperandSize::S0));
        let mut rex = X86Rex {
            w: matches!(self.size, OperandSize::S64),
            r: self.first_operand & 0b1000 != 0,
            x: false,
            b: self.second_operand & 0b1000 != 0,
        };
        let mut modrm = X86ModRm {
            mode: 0,
            r: self.first_operand & 0b111,
            m: self.second_operand & 0b111,
        };
        let mut sib = X86Sib {
            scale: 0,
            index: 0,
            base: 0,
        };
        let mut displacement_size = OperandSize::S0;
        let mut displacement = 0;
        if self.modrm {
            match self.indirect {
                Some(X86IndirectAccess::Offset(offset)) => {
                    displacement = offset;
                    debug_assert_ne!(self.second_operand & 0b111, RSP); // Reserved for SIB addressing
                    if (displacement >= -128 && displacement <= 127)
                        || (displacement == 0 && self.second_operand & 0b111 == RBP)
                    {
                        displacement_size = OperandSize::S8;
                        modrm.mode = 1;
                    } else {
                        displacement_size = OperandSize::S32;
                        modrm.mode = 2;
                    }
                }
                Some(X86IndirectAccess::OffsetIndexShift(offset, index, shift)) => {
                    displacement = offset;
                    displacement_size = OperandSize::S32;
                    modrm.mode = 2;
                    modrm.m = RSP;
                    rex.x = index & 0b1000 != 0;
                    sib.scale = shift & 0b11;
                    sib.index = index & 0b111;
                    sib.base = self.second_operand & 0b111;
                }
                None => {
                    modrm.mode = 3;
                }
            }
        }
        if matches!(self.size, OperandSize::S16) {
            emit::<u8, E>(jit, 0x66)?;
        }
        let rex =
            ((rex.w as u8) << 3) | ((rex.r as u8) << 2) | ((rex.x as u8) << 1) | (rex.b as u8);
        if rex != 0 {
            emit::<u8, E>(jit, 0x40 | rex)?;
        }
        match self.opcode_escape_sequence {
            1 => emit::<u8, E>(jit, 0x0f)?,
            2 => emit::<u16, E>(jit, 0x0f38)?,
            3 => emit::<u16, E>(jit, 0x0f3a)?,
            _ => {}
        }
        emit::<u8, E>(jit, self.opcode)?;
        if self.modrm {
            emit::<u8, E>(jit, (modrm.mode << 6) | (modrm.r << 3) | modrm.m)?;
            let sib = (sib.scale << 6) | (sib.index << 3) | sib.base;
            if sib != 0 {
                emit::<u8, E>(jit, sib)?;
            }
            emit_variable_length(jit, displacement_size, displacement as u64)?;
        }
        emit_variable_length(jit, self.immediate_size, self.immediate as u64)?;
        if jit.config.noop_instruction_ratio != 0
            && jit.diversification_rng.gen::<u32>() < jit.config.noop_instruction_ratio
        {
            // X86Instruction::noop().emit(jit)?;
            emit::<u8, E>(jit, 0x90)?;
        }
        Ok(())
    }

    /// Move source to destination
    pub const fn mov(size: OperandSize, source: u8, destination: u8) -> Self {
        Self {
            size,
            opcode: 0x89,
            first_operand: source,
            second_operand: destination,
            ..Self::DEFAULT
        }
    }

    /// Conditionally move source to destination
    pub const fn cmov(size: OperandSize, condition: u8, source: u8, destination: u8) -> Self {
        Self {
            size,
            opcode_escape_sequence: 1,
            opcode: condition,
            first_operand: destination,
            second_operand: source,
            ..Self::DEFAULT
        }
    }

    /// Swap source and destination
    pub const fn xchg(
        size: OperandSize,
        source: u8,
        destination: u8,
        indirect: Option<X86IndirectAccess>,
    ) -> Self {
        exclude_operand_sizes!(
            size,
            OperandSize::S0 | OperandSize::S8 | OperandSize::S16 | OperandSize::S32,
        );
        Self {
            size,
            opcode: 0x87,
            first_operand: source,
            second_operand: destination,
            indirect,
            ..Self::DEFAULT
        }
    }

    /// Swap byte order of destination
    pub const fn bswap(size: OperandSize, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8);
        match size {
            OperandSize::S16 => Self {
                size,
                opcode: 0xc1,
                second_operand: destination,
                immediate_size: OperandSize::S8,
                immediate: 8,
                ..Self::DEFAULT
            },
            OperandSize::S32 | OperandSize::S64 => Self {
                size,
                opcode_escape_sequence: 1,
                opcode: 0xc8 | (destination & 0b111),
                modrm: false,
                second_operand: destination,
                ..Self::DEFAULT
            },
            _ => unimplemented!(),
        }
    }

    /// Sign extend source i32 to destination i64
    pub const fn sign_extend_i32_to_i64(source: u8, destination: u8) -> Self {
        Self {
            size: OperandSize::S64,
            opcode: 0x63,
            first_operand: source,
            second_operand: destination,
            ..Self::DEFAULT
        }
    }

    /// Test source and destination
    pub const fn test(
        size: OperandSize,
        source: u8,
        destination: u8,
        indirect: Option<X86IndirectAccess>,
    ) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0);
        Self {
            size,
            opcode: if let OperandSize::S8 = size {
                0x84
            } else {
                0x85
            },
            first_operand: source,
            second_operand: destination,
            indirect,
            ..Self::DEFAULT
        }
    }

    /// Test immediate and destination
    pub const fn test_immediate(
        size: OperandSize,
        destination: u8,
        immediate: i64,
        indirect: Option<X86IndirectAccess>,
    ) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0);
        Self {
            size,
            opcode: if let OperandSize::S8 = size {
                0xf6
            } else {
                0xf7
            },
            first_operand: RAX,
            second_operand: destination,
            immediate_size: if let OperandSize::S64 = size {
                OperandSize::S32
            } else {
                size
            },
            immediate,
            indirect,
            ..Self::DEFAULT
        }
    }

    /// Compare source and destination
    pub const fn cmp(
        size: OperandSize,
        source: u8,
        destination: u8,
        indirect: Option<X86IndirectAccess>,
    ) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0);
        Self {
            size,
            opcode: if let OperandSize::S8 = size {
                0x38
            } else {
                0x39
            },
            first_operand: source,
            second_operand: destination,
            indirect,
            ..Self::DEFAULT
        }
    }

    /// Compare immediate and destination
    pub const fn cmp_immediate(
        size: OperandSize,
        destination: u8,
        immediate: i64,
        indirect: Option<X86IndirectAccess>,
    ) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0);
        Self {
            size,
            opcode: if let OperandSize::S8 = size {
                0x80
            } else {
                0x81
            },
            first_operand: RDI,
            second_operand: destination,
            immediate_size: if let OperandSize::S64 = size {
                OperandSize::S32
            } else {
                size
            },
            immediate,
            indirect,
            ..Self::DEFAULT
        }
    }

    /// Load effective address of source into destination
    pub const fn lea(
        size: OperandSize,
        source: u8,
        destination: u8,
        indirect: Option<X86IndirectAccess>,
    ) -> Self {
        exclude_operand_sizes!(
            size,
            OperandSize::S0 | OperandSize::S8 | OperandSize::S16 | OperandSize::S32,
        );
        Self {
            size,
            opcode: 0x8d,
            first_operand: destination,
            second_operand: source,
            indirect,
            ..Self::DEFAULT
        }
    }

    /// Load destination from [source + offset]
    pub const fn load(
        size: OperandSize,
        source: u8,
        destination: u8,
        indirect: X86IndirectAccess,
    ) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0);
        Self {
            size: if let OperandSize::S64 = size {
                OperandSize::S64
            } else {
                OperandSize::S32
            },
            opcode_escape_sequence: match size {
                OperandSize::S8 | OperandSize::S16 => 1,
                _ => 0,
            },
            opcode: match size {
                OperandSize::S8 => 0xb6,
                OperandSize::S16 => 0xb7,
                _ => 0x8b,
            },
            first_operand: destination,
            second_operand: source,
            indirect: Some(indirect),
            ..Self::DEFAULT
        }
    }

    /// Store source in [destination + offset]
    pub const fn store(
        size: OperandSize,
        source: u8,
        destination: u8,
        indirect: X86IndirectAccess,
    ) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0);
        Self {
            size,
            opcode: match size {
                OperandSize::S8 => 0x88,
                _ => 0x89,
            },
            first_operand: source,
            second_operand: destination,
            indirect: Some(indirect),
            ..Self::DEFAULT
        }
    }

    /// Load destination from sign-extended immediate
    pub const fn load_immediate(size: OperandSize, destination: u8, immediate: i64) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        let immediate_size =
            if immediate >= std::i32::MIN as i64 && immediate <= std::i32::MAX as i64 {
                OperandSize::S32
            } else {
                OperandSize::S64
            };
        match immediate_size {
            OperandSize::S32 => Self {
                size,
                opcode: 0xc7,
                second_operand: destination,
                immediate_size: OperandSize::S32,
                immediate,
                ..Self::DEFAULT
            },
            OperandSize::S64 => Self {
                size,
                opcode: 0xb8 | (destination & 0b111),
                modrm: false,
                second_operand: destination,
                immediate_size: OperandSize::S64,
                immediate,
                ..Self::DEFAULT
            },
            _ => unimplemented!(),
        }
    }

    /// Store sign-extended immediate in destination
    pub const fn store_immediate(
        size: OperandSize,
        destination: u8,
        indirect: X86IndirectAccess,
        immediate: i64,
    ) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0);
        Self {
            size,
            opcode: match size {
                OperandSize::S8 => 0xc6,
                _ => 0xc7,
            },
            second_operand: destination,
            indirect: Some(indirect),
            immediate_size: if let OperandSize::S64 = size {
                OperandSize::S32
            } else {
                size
            },
            immediate,
            ..Self::DEFAULT
        }
    }

    /// Push source onto the stack
    #[allow(dead_code)]
    pub const fn push_immediate(size: OperandSize, immediate: i32) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S16);
        Self {
            size,
            opcode: match size {
                OperandSize::S8 => 0x6A,
                _ => 0x68,
            },
            modrm: false,
            immediate_size: if let OperandSize::S64 = size {
                OperandSize::S32
            } else {
                size
            },
            immediate: immediate as i64,
            ..Self::DEFAULT
        }
    }

    /// Push source onto the stack
    pub const fn push(source: u8, indirect: Option<X86IndirectAccess>) -> Self {
        if indirect.is_none() {
            Self {
                size: OperandSize::S32,
                opcode: 0x50 | (source & 0b111),
                modrm: false,
                second_operand: source,
                ..Self::DEFAULT
            }
        } else {
            Self {
                size: OperandSize::S64,
                opcode: 0xFF,
                modrm: true,
                first_operand: 6,
                second_operand: source,
                indirect,
                ..Self::DEFAULT
            }
        }
    }

    /// Pop from the stack into destination
    pub const fn pop(destination: u8) -> Self {
        Self {
            size: OperandSize::S32,
            opcode: 0x58 | (destination & 0b111),
            modrm: false,
            second_operand: destination,
            ..Self::DEFAULT
        }
    }

    /// Push RIP and jump to destination
    pub const fn call_reg(destination: u8, indirect: Option<X86IndirectAccess>) -> Self {
        Self {
            size: OperandSize::S64,
            opcode: 0xff,
            first_operand: 2,
            second_operand: destination,
            indirect,
            ..Self::DEFAULT
        }
    }

    /// Pop RIP
    pub const fn return_near() -> Self {
        Self {
            size: OperandSize::S32,
            opcode: 0xc3,
            modrm: false,
            ..Self::DEFAULT
        }
    }

    /// No operation
    #[allow(dead_code)]
    pub const fn noop() -> Self {
        Self {
            size: OperandSize::S32,
            opcode: 0x90,
            modrm: false,
            ..Self::DEFAULT
        }
    }

    /// Trap / software interrupt
    #[allow(dead_code)]
    pub const fn interrupt(immediate: u8) -> Self {
        if immediate == 3 {
            Self {
                size: OperandSize::S32,
                opcode: 0xcc,
                modrm: false,
                ..Self::DEFAULT
            }
        } else {
            Self {
                size: OperandSize::S32,
                opcode: 0xcd,
                modrm: false,
                immediate_size: OperandSize::S8,
                immediate: immediate as i64,
                ..Self::DEFAULT
            }
        }
    }

    /// rdtsc
    pub const fn cycle_count() -> Self {
        Self {
            size: OperandSize::S32,
            opcode_escape_sequence: 1,
            opcode: 0x31,
            modrm: false,
            ..Self::DEFAULT
        }
    }

    /// lfence / sfence / mfence
    #[allow(dead_code)]
    pub const fn fence(fence_type: FenceType) -> Self {
        Self {
            size: OperandSize::S32,
            opcode_escape_sequence: 1,
            opcode: 0xae,
            first_operand: fence_type as u8,
            ..Self::DEFAULT
        }
    }
}
