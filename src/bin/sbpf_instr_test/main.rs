pub(crate) mod types;
pub use types::*;
mod exec;
mod parse;

fn handle_file(file_path: &str) {
    eprintln!("Running {}", file_path);
    let file = std::fs::read(file_path).unwrap();
    let parser = crate::parse::Parser::new(file_path, &file);
    for fixture in parser {
        crate::exec::run_fixture(&fixture, file_path);
    }
}

fn main() {
    let mut args = std::env::args();
    args.next();
    for arg in args {
        handle_file(&arg);
    }
}
