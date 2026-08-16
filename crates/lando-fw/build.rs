use std::fs;
use std::path::PathBuf;

fn main() {
    // cortex-m-rt's link.x includes memory.x from the linker search path, so
    // the layout has to be copied where the linker will find it.
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    fs::write(out.join("memory.x"), include_bytes!("memory.x")).unwrap();
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rustc-link-arg-bins=--nmagic");
    println!("cargo:rustc-link-arg-bins=-Tlink.x");
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-changed=build.rs");
}
