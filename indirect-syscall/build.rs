fn main() {
    println!("cargo:rerun-if-changed=asm/indirect_syscall.S");
    cc::Build::new()
        .file("asm/indirect_syscall.S")
        .compile("asmfuncs");
}
