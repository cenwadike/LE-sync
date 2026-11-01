//! One rooted update step, with the input and output layout of a real LEZ program.
//!
//! The rooted design: the store account holds the committee as a keys root and an aggregate
//! (`store_codec` v2, 403 bytes), not its keys. `Begin` is sent the keys of the ABSENT members as
//! packed 96-byte points plus one Merkle multiproof (`RootedOp::Begin`), checks them against the
//! root, and subtracts them from the aggregate. `Miller` is unchanged. `Finish` reads the same
//! rooted store. See `le_sync_wire::rooted` for the step logic and `lez_io` for the layout.
//!
//! Accounts: Begin [store, empty job slot]; Miller [job]; Finish [store, job].
//! Commits `Result<ProgramOutput, u16>`: a rejected step commits its error code.
//!
//! Cycle log, the shape `lez_stage.rs` writes, so the bench parses both:
//!   guest-stage cycles: mode=<begin|miller|finish> read=<n> step=<n> commit=<n>
mod lez_io;

use le_sync_wire::bls::Impl;
use le_sync_wire::rooted::{run_rooted, RootedInput};
use le_sync_wire::stage::{StageConfig, StageOutput};
use lez_io::{
    post, AccountPostState, AccountWithMetadata, ProgramId, ProgramOutput, RootedOp, ValidityWindow,
};
use risc0_zkvm::guest::env;

fn data_of(pre: &[AccountWithMetadata], i: usize) -> Vec<u8> {
    pre[i].account.data.as_slice().to_vec()
}

fn main() {
    let t0 = env::cycle_count();
    let program_id: ProgramId = env::read();
    let caller: Option<ProgramId> = env::read();
    let pre_states: Vec<AccountWithMetadata> = env::read();
    let words: Vec<u32> = env::read();
    let (cfg, op): (StageConfig, RootedOp) =
        risc0_zkvm::serde::from_slice(&words).expect("instruction words decode");
    let t1 = env::cycle_count();

    let mode = op.mode();
    let input = match op {
        RootedOp::Begin { update, absent } => RootedInput::Begin {
            store: data_of(&pre_states, 0),
            update,
            absent,
        },
        RootedOp::Miller => RootedInput::Miller {
            job: data_of(&pre_states, 0),
        },
        RootedOp::Finish { update } => RootedInput::Finish {
            job: data_of(&pre_states, 1),
            store: data_of(&pre_states, 0),
            update,
        },
    };
    let result = run_rooted(&cfg, &input, &Impl).map_err(|e| e.code());
    let out: Result<ProgramOutput, u16> = result.map(|o| {
        let post_states: Vec<AccountPostState> = match (&input, o) {
            (RootedInput::Begin { .. }, StageOutput::Job(j)) => {
                vec![
                    post(&pre_states[0], data_of(&pre_states, 0)),
                    post(&pre_states[1], j),
                ]
            }
            (RootedInput::Miller { .. }, StageOutput::Job(j)) => vec![post(&pre_states[0], j)],
            (RootedInput::Finish { .. }, StageOutput::Store(s)) => {
                vec![post(&pre_states[0], s), post(&pre_states[1], vec![])]
            }
            _ => panic!("step returned an output of the wrong kind"),
        };
        ProgramOutput {
            self_program_id: program_id,
            caller_program_id: caller,
            instruction_data: words,
            pre_states,
            post_states,
            chained_calls: vec![],
            block_validity_window: ValidityWindow::default(),
            timestamp_validity_window: ValidityWindow::default(),
        }
    });
    let t2 = env::cycle_count();

    env::commit(&out);
    let t3 = env::cycle_count();

    env::log(&format!(
        "guest-stage cycles: mode={} read={} step={} commit={}",
        mode,
        t1 - t0,
        t2 - t1,
        t3 - t2
    ));
}
