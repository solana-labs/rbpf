pub(crate) mod types;
pub use types::*;
mod exec;
mod parse;

fn handle_file(file_path: &str) -> bool {
    eprintln!("++++ {}", file_path);
    let file = std::fs::read(file_path).unwrap();
    let parser = crate::parse::Parser::new(file_path, &file);
    let mut fail = false;
    for fixture in parser {
        fail |= crate::exec::run_fixture(&fixture, file_path);
    }
    fail
}

fn main() {
    let mut args = std::env::args();
    args.next();
    let mut fail = false;
    for arg in args {
        fail |= handle_file(&arg);
    }
    if fail {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_instr_bitwise() {
        assert!(!super::handle_file("tests/instr/bitwise.instr"));
    }

    #[test]
    fn test_instr_int_math() {
        assert!(!super::handle_file("tests/instr/int_math.instr"));
    }

    #[test]
    fn test_instr_jump() {
        assert!(!super::handle_file("tests/instr/jump.instr"));
    }

    #[test]
    fn test_instr_load() {
        assert!(!super::handle_file("tests/instr/load.instr"));
    }

    #[test]
    fn test_instr_opcode() {
        assert!(!super::handle_file("tests/instr/opcode.instr"));
    }

    #[test]
    fn test_instr_shift() {
        assert!(!super::handle_file("tests/instr/shift.instr"));
    }
}
