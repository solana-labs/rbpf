use crate::types::*;
use std::str::FromStr;

macro_rules! abort {
    ($($arg:tt)*) => {{
        eprintln!($($arg)*);
        std::process::exit(1);
    }};
}

pub struct Parser<'a> {
    file_path: &'a str,
    state: State,
    line: usize,
    cur: &'a [u8],
    input: Input,
    effects: Effects,
}

impl<'a> Parser<'a> {
    pub fn new(file_path: &'a str, data: &'a [u8]) -> Parser<'a> {
        Parser {
            file_path,
            state: State::Input,
            line: 1,
            cur: data,
            input: Input::default(),
            effects: Effects::default(),
        }
    }
}

impl<'a> Parser<'a> {
    fn advance(&mut self, n: usize) {
        for i in 0..n {
            if self.cur[i] == b'\n' {
                self.line += 1;
            }
        }
        self.cur = &self.cur[n..];
    }

    fn read_assign_sep(&mut self) {
        while !self.cur.is_empty() && self.cur[0].is_ascii_whitespace() {
            self.advance(1);
        }
        if self.cur.is_empty() || self.cur[0] != b'=' {
            abort!("Expected '=' at {}:{}", self.file_path, self.line);
        }
        while !self.cur.is_empty() && self.cur[0].is_ascii_whitespace() {
            self.advance(1);
        }
        self.advance(1);
    }

    fn read_hex_int(&mut self) -> u64 {
        let mut val = 0;
        let mut empty = true;
        while !self.cur.is_empty() {
            let c = self.cur[0];
            let digit = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => break,
            };
            self.advance(1);
            val <<= 4;
            val |= digit as u64;
            empty = false;
        }
        assert!(
            !empty,
            "expected hex integer at {}:{}",
            self.file_path, self.line
        );
        val
    }

    fn read_hex_buf(&mut self) -> Vec<u8> {
        let mut buf = Vec::<u8>::new();
        while !self.cur.is_empty() {
            let c = self.cur[0];
            if c.is_ascii_whitespace() {
                self.advance(1);
            } else if c.is_ascii_hexdigit() {
                let c2 = self.cur[1];
                self.advance(2);
                assert!(c2.is_ascii_hexdigit());
                let lo = match c {
                    b'0'..=b'9' => c - b'0',
                    b'a'..=b'f' => c - b'a' + 10,
                    b'A'..=b'F' => c - b'A' + 10,
                    _ => unreachable!(),
                };
                let hi = match c2 {
                    b'0'..=b'9' => c2 - b'0',
                    b'a'..=b'f' => c2 - b'a' + 10,
                    b'A'..=b'F' => c2 - b'A' + 10,
                    _ => unreachable!(),
                };
                buf.push(hi << 4 | lo);
            } else {
                break;
            }
        }
        buf
    }
}

impl<'a> Iterator for Parser<'a> {
    type Item = Fixture;
    fn next(&mut self) -> Option<Fixture> {
        'next_token: loop {
            let prev_line = self.line;
            // Skip whitespace
            while !self.cur.is_empty() && self.cur[0].is_ascii_whitespace() {
                self.advance(1);
            }
            if self.cur.is_empty() {
                if self.state == State::Assert {
                    self.state = State::Input;
                    return Some(Fixture {
                        line: prev_line,
                        input: self.input.clone(),
                        effects: self.effects.clone(),
                    });
                } else {
                    return None;
                }
            }
            match self.cur[0] {
                b'$' => {
                    let prev_state = self.state;
                    self.state = State::Input;
                    if prev_state == State::Assert {
                        return Some(Fixture {
                            line: prev_line,
                            input: self.input.clone(),
                            effects: self.effects.clone(),
                        });
                    }
                    self.advance(1);
                    continue 'next_token;
                }
                b'#' => {
                    while !self.cur.is_empty() {
                        let c = self.cur[0];
                        self.advance(1);
                        if c == b'\n' {
                            continue 'next_token;
                        }
                    }
                }
                b':' => {
                    self.state = State::Assert;
                    self.advance(1);
                    continue 'next_token;
                }
                _ => {}
            }
            // Read word
            let cur_pre = self.cur;
            while !self.cur.is_empty() {
                match self.cur[0] {
                    b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' => {
                        self.advance(1);
                    }
                    _ => break,
                }
            }
            let word = &cur_pre[..cur_pre.len() - self.cur.len()];
            match word {
                b"input" => {
                    self.read_assign_sep();
                    self.input.input = self.read_hex_buf();
                }
                b"op" => {
                    self.read_assign_sep();
                    self.input.op = self.read_hex_int() as u8;
                }
                b"dst" => {
                    self.read_assign_sep();
                    self.input.dst = self.read_hex_int() as u8;
                }
                b"src" => {
                    self.read_assign_sep();
                    self.input.src = self.read_hex_int() as u8;
                }
                b"off" => {
                    self.read_assign_sep();
                    self.input.off = self.read_hex_int() as u16;
                }
                b"imm" => {
                    self.read_assign_sep();
                    self.input.imm = self.read_hex_int();
                }
                b"ok" => {
                    self.effects.status = Status::Ok;
                }
                b"err" => {
                    self.effects.status = Status::Fault;
                }
                b"vfy" => {
                    self.effects.status = Status::VerifyFail;
                }
                _ if word.len() >= 2 && word[0] == b'r' && word[1].is_ascii_digit() => {
                    let reg_idx = std::str::from_utf8(&word[1..])
                        .ok()
                        .and_then(|s| u8::from_str(s).ok())
                        .expect("Invalid register index");
                    self.read_assign_sep();
                    match self.state {
                        State::Input => self.input.regs[reg_idx as usize] = self.read_hex_int(),
                        State::Assert => self.effects.regs[reg_idx as usize] = self.read_hex_int(),
                    }
                }
                _ => abort!(
                    "Unexpected token '{}' at {}:{}",
                    unsafe { std::str::from_utf8_unchecked(word) },
                    self.file_path,
                    self.line
                ),
            }
        }
    }
}