#![feature(linkage)]

#[link_section = ".bss.stack"]
pub static _STACK: [u8; 0x1000] = [0; 0x1000];
#[link_section = ".bss.heap"]
pub static _HEAP: [u8; 0x1000] = [0; 0x1000];

static _VAL_A: u64 = 41;
static VAL_B: u64 = 42;
static _VAL_C: u64 = 43;

#[inline(never)]
#[linkage="external"]
fn foo() -> u64 {
    return unsafe { core::ptr::read_volatile(&VAL_B) };
}

#[no_mangle]
pub fn entrypoint() -> u64 {
    return foo();
}
