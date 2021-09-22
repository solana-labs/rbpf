extern crate version_check as rustc;

fn main() {
    if rustc::is_min_version("1.56.0").unwrap_or(false) {
        println!("cargo:rustc-cfg=vtable_send_sync_plus_one");
    }
}
