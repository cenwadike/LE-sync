//! `eth-attest-ops`: everything the `eth_attest` module and its CLI do, with no Logos code in
//! it, so it builds and tests with plain `cargo`.
//!
//! * `config`: the environment file (one per environment is all that differs).
//! * `source`: where Ethereum material comes from (`EthSource`; `HttpSource`).
//! * `convert`: beacon and execution JSON to the program's wire types.
//! * `lez`: the instructions, the accounts and the sequencer (`LezClient`; `WalletLez`).
//! * `plan`: the submitter's decisions, as pure functions.
//! * `submitter`: fetch, defer, re-check, then the three stages.
//! * `engine`: the module's methods, and the background submitter.
pub mod config;
pub mod convert;
pub mod engine;
pub mod lez;
pub mod plan;
pub mod receipts;
pub mod source;
pub mod submitter;
