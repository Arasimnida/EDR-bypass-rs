fn main() {
    println!("cargo:rerun-if-changed=asm/direct_syscall.S");
    cc::Build::new()
        .file("asm/direct_syscall.S")
        .compile("asmfuncs");
}
