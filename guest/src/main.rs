use le_sync_wire::{bls::Impl, verify, GuestInput};
use risc0_zkvm::guest::env;

fn main() {
    let t0 = env::cycle_count();
    let input: GuestInput = env::read();
    let t1 = env::cycle_count();
    let out = verify(&input, &Impl);
    let t2 = env::cycle_count();
    env::commit(&out);
    let t3 = env::cycle_count();
    env::log(&format!(
        "guest cycles: read={} verify={} commit={}",
        t1 - t0,
        t2 - t1,
        t3 - t2
    ));
}
