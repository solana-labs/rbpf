use solana_rbpf::ebpf::Insn;

#[derive(Default, Debug, Clone)]
pub struct Input {
    pub input: Vec<u8>,
    pub op: u8,
    pub dst: u8,
    pub src: u8,
    pub off: u16,
    pub imm: u64,
    pub regs: [u64; 12],
}

impl Input {
    pub const fn encode_instruction(&self) -> u64 {
        assert!(self.dst < 0x10);
        assert!(self.src < 0x10);
        u64::from_le_bytes(Insn {
            ptr: 0,
            opc: self.op,
            dst: self.dst,
            src: self.src,
            off: self.off as i16,
            imm: self.imm as i64,
        }.to_array())
    }
}

#[derive(Default, Debug, Copy, Clone, PartialEq)]
pub enum Status {
    #[default]
    Ok, // ok
    Fault,      // err
    VerifyFail, // vfy
}

#[derive(Default, Debug, Clone)]
pub struct Effects {
    pub status: Status,
    pub regs: [u64; 12],
}

#[derive(Debug)]
pub struct Fixture {
    pub line: usize,
    pub input: Input,
    pub effects: Effects,
}

#[derive(Copy, Clone, PartialEq)]
pub enum State {
    Input,
    Assert,
}
