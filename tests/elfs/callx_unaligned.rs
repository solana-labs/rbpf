#![feature(asm_experimental_arch)]

#[no_mangle]
pub fn entrypoint() {
    unsafe {
        std::arch::asm!("
rsh64 r1, 2
or64 r1, 0x129
callx r1
        ");
    }
}
