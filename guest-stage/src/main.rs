//! One staged update step per run (Sprint 6, M1 cost gate).
//!
//! The host chooses the step by what it sends: `StageInput::Begin`, `Miller` or `Finish`
//! (`le_sync_wire::stage`). The guest reads `(StageConfig, StageInput)`, runs exactly that step,
//! and commits `Result<StageOutput, u16>`: the output bytes, or the stable error code
//! (`Error::code()`). A rejected step commits its code instead of panicking, so the bench sees
//! the typed error.
//!
//! Cycle log, one line per run:
//!   guest-stage cycles: mode=<begin|miller|finish> read=<n> step=<n> commit=<n>
//! With `cycle-trace`, the `bls-blst` stages add their own breakdown (signature decode, key
//! aggregation, hash-to-curve, Miller, final exponentiation).
use le_sync_wire::bls::Impl;
use le_sync_wire::stage::{run_stage, StageConfig, StageInput, StageOutput};
use risc0_zkvm::guest::env;

fn main() {
    let t0 = env::cycle_count();
    let (cfg, input): (StageConfig, StageInput) = env::read();
    let t1 = env::cycle_count();

    let mode = match &input {
        StageInput::Begin { .. } => "begin",
        StageInput::Miller { .. } => "miller",
        StageInput::Finish { .. } => "finish",
    };
    let result: Result<StageOutput, u16> = run_stage(&cfg, &input, &Impl).map_err(|e| e.code());
    let t2 = env::cycle_count();

    env::commit(&result);
    let t3 = env::cycle_count();

    env::log(&format!(
        "guest-stage cycles: mode={} read={} step={} commit={}",
        mode,
        t1 - t0,
        t2 - t1,
        t3 - t2
    ));
}
