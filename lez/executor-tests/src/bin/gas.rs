//! `cargo run --release --manifest-path lez/executor-tests/Cargo.toml --bin gas [-- N]`
//!
//! Executor cycles of each instruction of `eth_attest` at committee size N (default 512,
//! mainnet; a power of two from 8 to 512). Each transaction runs twice (state machine, then
//! the executor for the count), so allow a few minutes at 512.
fn main() {
    let n: usize = match std::env::args().nth(1) {
        None => 512,
        Some(a) => match a.replace('_', "").parse() {
            Ok(n) if (8..=512usize).contains(&n) && n.is_power_of_two() => n,
            _ => {
                eprintln!("usage: gas [N]   N: a power of two from 8 to 512");
                std::process::exit(2);
            }
        },
    };
    let rows = le_sync_executor_tests::gas::table(n);
    print!("{}", le_sync_executor_tests::gas::format(&rows, n));
}
