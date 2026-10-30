//! One staged update step, with the input and output layout of a real LEZ program.
//!
//! Same work as `main.rs` (`run_stage`), but the inputs arrive as the platform writes them and
//! the result leaves as `ProgramOutput::write` commits it. See `lez_io` for what that means and
//! why it costs more than `main.rs` shows: the store account is read (one serde element per
//! byte) and committed twice.
//!
//! Accounts: Begin [store, empty job slot]; Miller [job]; Finish [store, job].
//! Commits `Result<ProgramOutput, u16>`: a rejected step commits its error code (a real LEZ
//! program would fail; the bench wants the typed error).
//!
//! Cycle log, same shape as `main.rs` so the bench parses both:
//!   guest-stage cycles: mode=<begin|miller|finish> read=<n> step=<n> commit=<n>
//! read = the four `env::read` calls and the instruction deserialization;
//! step = building the step input from the accounts, `run_stage`, building the post states;
//! commit = `env::commit` of the whole output.
mod lez_io;

use le_sync_wire::bls::Impl;
use le_sync_wire::stage::{run_stage, StageConfig, StageInput, StageOutput};
use lez_io::{
    post, AccountPostState, AccountWithMetadata, LezOp, ProgramId, ProgramOutput, ValidityWindow,
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
    let (cfg, op): (StageConfig, LezOp) =
        risc0_zkvm::serde::from_slice(&words).expect("instruction words decode");
    let t1 = env::cycle_count();

    let mode = op.mode();
    let input = match op {
        LezOp::Begin { update } => StageInput::Begin {
            store: data_of(&pre_states, 0),
            update,
        },
        LezOp::Miller => StageInput::Miller {
            job: data_of(&pre_states, 0),
        },
        LezOp::Finish { update } => StageInput::Finish {
            job: data_of(&pre_states, 1),
            store: data_of(&pre_states, 0),
            update,
        },
    };
    let result = run_stage(&cfg, &input, &Impl).map_err(|e| e.code());
    let out: Result<ProgramOutput, u16> = result.map(|o| {
        let post_states: Vec<AccountPostState> = match (&input, o) {
            (StageInput::Begin { .. }, StageOutput::Job(j)) => {
                vec![
                    post(&pre_states[0], data_of(&pre_states, 0)),
                    post(&pre_states[1], j),
                ]
            }
            (StageInput::Miller { .. }, StageOutput::Job(j)) => vec![post(&pre_states[0], j)],
            (StageInput::Finish { .. }, StageOutput::Store(s)) => {
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
