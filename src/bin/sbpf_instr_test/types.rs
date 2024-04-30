#[derive(Default, Debug, Clone)]
pub struct Input {
    pub input: Vec<u8>,
    pub op: u8,
    pub dst: u8,
    pub src: u8,
    pub off: u16,
    pub imm: u64,
    pub regs: [u64; 11],
}

impl Input {
    pub const fn encode_instruction(&self) -> u64 {
        assert!(self.dst < 0x10);
        assert!(self.src < 0x10);
        self.op as u64
            | ((self.dst as u64) << 8)
            | ((self.src as u64) << 12)
            | ((self.off as u64) << 16)
            | (self.imm << 32)
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
