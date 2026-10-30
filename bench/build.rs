// Builds ../guest-stage for riscv32im-risc0-zkvm-elf and bundles it with the risc0 kernel
// (same mechanism as ../host/build.rs). Needs `rzup`'s risc0 toolchain.
fn main() {
    risc0_build::embed_methods();
}
