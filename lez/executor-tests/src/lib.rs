//! Executor tests of the `eth_attest` LEZ program (Sprint 6, M2).
//!
//! * `world`: a synthetic beacon chain and execution layer with real committees and real
//!   signed updates (no LEZ).
//! * `harness`: LEZ's in-memory state machine with the program deployed, and the executor for
//!   gas.
//!
//! The tests are in `tests/m2.rs`; the gas table is `cargo run --release --bin gas`.
pub mod gas;
pub mod harness;
pub mod world;
