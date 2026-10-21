// Builds ../guest for riscv32im-risc0-zkvm-elf and bundles it with the risc0 kernel
// (this is what makes it a valid ProgramBinary). Needs `rzup`'s risc0 toolchain.
// `RISC0_SKIP_BUILD=1 cargo test -p le-sync` skips the guest build (host-only tests).
fn main() {
    risc0_build::embed_methods();
}
