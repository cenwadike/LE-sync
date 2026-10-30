//! Differential suite for the staged update (Sprint 6, M1): real BLS, three transactions.
//!
//! Subject: `run_stage` (Begin, Miller, Finish, each through its byte encoding) on the `bls-blst`
//! staged backend. Reference: the single-shot `bls-zk` path (`common::run`, i.e. `verify_trace`).
//! The two share no BLS code: `bls-zk` is the risc0 `bls12_381` crate, `bls-blst` is the
//! risc0-patched `blst`, and the signer is `le-sync-testkit` (independent of both).
//!
//! What each case checks:
//! * `Chained(blst)`, the staged backend run back to back as one `Bls`, gives the SAME `Trace`
//!   (journal and per-update verdicts) as `bls-zk`.
//! * The staged run agrees with the reference on every update: validated, or rejected with the
//!   same typed error (a malformed update is `BadSignature` or `BadSyncCommitteeSize`), and
//!   ends with the same finalized root and slot and the same optimistic slot. A rejected update
//!   leaves the store as it was, so those are also the "no store came out" check.
//! * Where the stage that must reject is known, it is asserted: an update that cannot even be
//!   decoded (bad signature bytes, failed Merkle rule, below 2/3) is refused by Begin; a
//!   well-formed signature that does not verify can only be refused by Finish, the one stage
//!   that compares the pairing result. Every verdict is also printed (`-- --nocapture`).
//!
//! Needs both backends: `cargo test -p le-sync-wire --features bls-zk,bls-blst --test staged_update`.
//! Assumes the blst `Impl` implements `StagedBls` and not `Bls` (a second `Bls for Impl` would
//! not compile next to the `bls-zk` one).
#![cfg(all(feature = "bls-zk", feature = "bls-blst"))]

mod common;

use common::*;
use le_sync_core::store_codec::decode_store;
use le_sync_core::update_job::{Chained, JOB_LEN, STATE_LEN};
use le_sync_core::Error;
use le_sync_testkit as tk;
use le_sync_wire::bls::Impl;
use le_sync_wire::stage::{initial_store_bytes, run_stage, StageConfig, StageInput, StageOutput};
use le_sync_wire::{verify_trace, GuestInput, UpdateOutcome as O, UpdateWire};

const N: usize = 32;
/// `UpdateJob::to_bytes`: `step:1 || store_digest:32 || update_digest:32 || state:576`.
const STATE_AT: usize = 1 + 32 + 32;

/// How one update fared through the three stages: `Err((stage, error))` names the stage that
/// refused it.
type Step = Result<(), (&'static str, Error)>;

// ---- driving the stages ---------------------------------------------------------------------

fn call(cfg: &StageConfig, input: StageInput) -> Result<StageOutput, Error> {
    run_stage(cfg, &input, &Impl)
}

/// Begin, then Miller: the job bytes at the Miller step.
fn begin_miller(
    cfg: &StageConfig,
    store: &[u8],
    u: &UpdateWire,
) -> Result<Vec<u8>, (&'static str, Error)> {
    let job = match call(
        cfg,
        StageInput::Begin {
            store: store.to_vec(),
            update: u.clone(),
        },
    ) {
        Ok(StageOutput::Job(j)) => j,
        Ok(other) => panic!("begin returned {other:?}"),
        Err(e) => return Err(("begin", e)),
    };
    match call(cfg, StageInput::Miller { job }) {
        Ok(StageOutput::Job(j)) => Ok(j),
        Ok(other) => panic!("miller returned {other:?}"),
        Err(e) => Err(("miller", e)),
    }
}

fn finish(cfg: &StageConfig, job: &[u8], store: &[u8], u: &UpdateWire) -> Result<Vec<u8>, Error> {
    match call(
        cfg,
        StageInput::Finish {
            job: job.to_vec(),
            store: store.to_vec(),
            update: u.clone(),
        },
    )? {
        StageOutput::Store(s) => Ok(s),
        other => panic!("finish returned {other:?}"),
    }
}

/// One update through all three stages: the new store bytes, or the stage that refused it.
fn one(cfg: &StageConfig, store: &[u8], u: &UpdateWire) -> Result<Vec<u8>, (&'static str, Error)> {
    let job = begin_miller(cfg, store, u)?;
    finish(cfg, &job, store, u).map_err(|e| ("finish", e))
}

/// Every update of `input.sync` in order, each against the store the previous one left (a
/// refused update leaves it as it was). `Err` if the bootstrap store cannot be built.
fn staged(input: &GuestInput) -> Result<(Vec<Step>, Vec<u8>), Error> {
    let sync = input.sync.as_ref().unwrap();
    let cfg = StageConfig::from_input(input, sync);
    let mut store = initial_store_bytes(input, sync)?;
    let mut steps = vec![];
    for u in &sync.updates {
        match one(&cfg, &store, u) {
            Ok(next) => {
                store = next;
                steps.push(Ok(()));
            }
            Err(e) => steps.push(Err(e)),
        }
    }
    Ok((steps, store))
}

fn agrees(want: O, got: &Step) -> bool {
    match (want, got) {
        (O::Validated, Ok(())) => true,
        (O::NotRelevant, Err((_, Error::UpdateNotRelevant))) => true,
        (O::Rejected(e), Err((_, g))) => e == *g,
        // the reference could not parse the update's bytes; the staged parse is typed
        (O::Malformed, Err((_, Error::BadSignature | Error::BadSyncCommitteeSize))) => true,
        _ => false,
    }
}

/// Run `input` through the reference and the staged path and compare. `stages[i]`, if `Some`,
/// is the stage that must refuse update `i`.
fn check(name: &str, input: &GuestInput, stages: &[Option<&str>]) -> Vec<Step> {
    let want = run(input);
    assert_eq!(
        verify_trace(input, &Chained(&Impl)),
        want,
        "{name}: Chained(blst) differs from bls-zk"
    );
    let (steps, store) = match staged(input) {
        Ok(s) => s,
        Err(e) => {
            // no bootstrap store: the reference reports the same failure for every update
            assert!(
                want.updates.iter().all(|u| *u == O::SetupFailed(e)),
                "{name}: staged setup failed with {e:?}, reference says {:?}",
                want.updates
            );
            eprintln!("{name}: setup failed, {e:?} (reference agrees)");
            return vec![];
        }
    };
    assert_eq!(steps.len(), want.updates.len(), "{name}");
    for (i, (w, g)) in want.updates.iter().zip(&steps).enumerate() {
        eprintln!("{name}: update {i}: reference {w:?}, staged {g:?}");
        assert!(
            agrees(*w, g),
            "{name}: update {i}: reference {w:?}, staged {g:?}"
        );
        if let (Some(Some(want_stage)), Err((got_stage, _))) = (stages.get(i), g) {
            assert_eq!(got_stage, want_stage, "{name}: update {i}: refusing stage");
        }
    }
    let st = decode_store(&store).unwrap();
    let o = &want.output;
    assert_eq!(st.finalized_header.slot, o.finalized_slot, "{name}");
    assert_eq!(
        st.finalized_header.hash_tree_root(),
        o.finalized_root,
        "{name}"
    );
    assert_eq!(st.optimistic_header.slot, o.optimistic_slot, "{name}");
    steps
}

fn accepted(name: &str, input: &GuestInput) {
    let steps = check(name, input, &[]);
    assert!(!steps.is_empty(), "{name}");
    assert!(steps.iter().all(|s| s.is_ok()), "{name}: {steps:?}");
}

fn refused(name: &str, input: &GuestInput, stage: &str) {
    let steps = check(name, input, &[Some(stage)]);
    assert_eq!(steps.len(), 1, "{name}");
    assert!(steps[0].is_err(), "{name}: was accepted");
}

/// A (period 0): carries `next_for_a`, signed by the checkpoint committee.
/// B (period 1): finalizes slot 72, signed by `signer_b`, carries `c3`. As in `negative.rs`.
fn handoff_pair(
    b: &Baseline,
    next_for_a: &tk::Committee,
    signer_b: &tk::Committee,
    c3: &tk::Committee,
) -> (UpdateWire, UpdateWire) {
    let a = build_update(&Spec {
        att_slot: 40,
        fin_slot: 24,
        sig_slot: 41,
        salt: 2,
        state_cur: b.cur.root(),
        state_next: next_for_a.root(),
        carry_next: Some(next_for_a),
        signer: &b.cur,
        bits: full(N),
        net: &b.net,
    });
    let bb = build_update(&Spec {
        att_slot: 88,
        fin_slot: 72,
        sig_slot: 89,
        salt: 6,
        state_cur: b.next.root(),
        state_next: c3.root(),
        carry_next: Some(c3),
        signer: signer_b,
        bits: full(N),
        net: &b.net,
    });
    (a, bb)
}

fn with_update(b: &Baseline, edit: impl FnOnce(&mut UpdateWire)) -> GuestInput {
    let mut u = b.update(full(N));
    edit(&mut u);
    b.input_with(vec![u])
}

// ---- accepted: the staged run lands where the single-shot run does ---------------------------

#[test]
fn baseline_guard_the_reference_accepts_the_fixture() {
    // If this fails, every "refused" case below could be a broken fixture.
    let b = baseline(N);
    let t = run(&b.input_with(vec![b.update(full(N))]));
    assert_eq!(t.updates, vec![O::Validated]);
    assert_eq!(
        (t.output.finalized_slot, t.output.optimistic_slot),
        (24, 40)
    );
}

#[test]
fn full_participation_finality_update() {
    let b = baseline(N);
    accepted("full", &b.input_with(vec![b.update(full(N))]));
}

#[test]
fn exactly_two_thirds_and_scattered_participation() {
    let b = baseline(N);
    accepted(
        "22 of 32",
        &b.input_with(vec![b.update(tk::bits_set(N, 22))]),
    );
    // 0xEE bytes: 6 of 8 bits per byte, not contiguous (24 present, 8 absent)
    accepted(
        "scattered",
        &b.input_with(vec![b.update(vec![0xEE; N / 8])]),
    );
}

#[test]
fn update_that_carries_the_next_committee() {
    let b = baseline(N);
    let (a, _) = handoff_pair(&b, &b.next, &b.next, &tk::committee(3, N));
    accepted("handoff", &b.input_with(vec![a]));
}

#[test]
fn honest_handoff_pair_across_the_period_boundary() {
    // two updates in a row: the second one runs against the store the staged first one wrote
    let b = baseline(N);
    let (a, bb) = handoff_pair(&b, &b.next, &b.next, &tk::committee(3, N));
    let i = b.input_with(vec![a, bb]);
    accepted("pair", &i);
    assert_eq!(run(&i).output.finalized_slot, 72);
}

#[test]
fn committee_of_512_full_and_minimum_participation() {
    if std::env::var_os("LE_SYNC_SKIP_SLOW").is_some() {
        return; // mutation runs skip this; the full `cargo test` run does not
    }
    let n = 512;
    let b = baseline(n);
    accepted("512 full", &b.input_with(vec![b.update(full(n))]));
    accepted(
        "512 at 342",
        &b.input_with(vec![b.update(tk::bits_set(n, 342))]),
    );
    let mut bad = b.update(full(n));
    bad.signature[95] ^= 1;
    refused("512 flipped bit", &b.input_with(vec![bad]), "begin");
}

// ---- refused at Begin: the update cannot be decoded, or breaks a non-signature rule ---------

#[test]
fn undecodable_signatures_are_refused_by_begin() {
    let b = baseline(N);
    let mut flipped = b.update(full(N));
    flipped.signature[95] ^= 1;
    refused("flipped bit", &b.input_with(vec![flipped]), "begin");
    for (name, sig) in [("all-zero", vec![0u8; 96]), ("garbage", vec![0xFFu8; 96])] {
        refused(name, &with_update(&b, |u| u.signature = sig), "begin");
    }
    // wrong lengths are typed errors from the wire parse, not a panic
    for len in [0usize, 48, 95, 97] {
        refused(
            &format!("signature of {len} bytes"),
            &with_update(&b, |u| u.signature = vec![0x11; len]),
            "begin",
        );
    }
}

#[test]
fn the_point_at_infinity_is_rejected_by_some_stage() {
    // A valid encoding of the identity: bls-zk accepts the decode and fails the pairing check.
    // The staged backend may refuse it at Begin or Finish; both are rejections.
    let b = baseline(N);
    let mut infinity = vec![0u8; 96];
    infinity[0] = 0xC0;
    let i = with_update(&b, |u| u.signature = infinity);
    let steps = check("infinity", &i, &[None]);
    assert!(steps[0].is_err());
}

#[test]
fn non_signature_rules_are_refused_by_begin_with_the_reference_error() {
    let b = baseline(N);
    refused(
        "below 2/3 (12 of 32)",
        &b.input_with(vec![b.update(tk::bits_set(N, 12))]),
        "begin",
    );
    refused(
        "21 of 32",
        &b.input_with(vec![b.update(tk::bits_set(N, 21))]),
        "begin",
    );
    refused(
        "bitfield too long",
        &with_update(&b, |u| u.bits = vec![0xFF; N / 8 + 2]),
        "begin",
    );
    refused(
        "tampered finality branch",
        &with_update(&b, |u| u.finality_branch[3][0] ^= 1),
        "begin",
    );
    refused(
        "finalized header not in the attested state",
        &with_update(&b, |u| u.finalized.slot += 1),
        "begin",
    );
    let atk = tk::committee(90, N);
    let forged_next = build_update(&Spec {
        att_slot: 40,
        fin_slot: 24,
        sig_slot: 41,
        salt: 2,
        state_cur: b.cur.root(),
        state_next: b.next.root(),
        carry_next: Some(&atk),
        signer: &b.cur,
        bits: full(N),
        net: &b.net,
    });
    refused(
        "forged next committee",
        &b.input_with(vec![forged_next]),
        "begin",
    );
    // a period-1 update with no handoff submitted
    let (_, bb) = handoff_pair(&b, &b.next, &b.next, &tk::committee(3, N));
    refused("period skipped", &b.input_with(vec![bb]), "begin");
}

// ---- refused at Finish: a well-formed signature that does not verify -------------------------

#[test]
fn signatures_that_decode_but_do_not_verify_are_refused_by_finish() {
    let b = baseline(N);
    let atk = tk::committee(90, N);

    // every Merkle rule passes; only the signing committee is wrong
    let fabricated = build_update(&Spec {
        att_slot: 40,
        fin_slot: 24,
        sig_slot: 41,
        salt: 7,
        state_cur: atk.root(),
        state_next: atk.root(),
        carry_next: None,
        signer: &atk,
        bits: full(N),
        net: &b.net,
    });
    refused(
        "attacker-signed state",
        &b.input_with(vec![fabricated]),
        "finish",
    );

    let attacker_handoff = build_update(&Spec {
        att_slot: 40,
        fin_slot: 24,
        sig_slot: 41,
        salt: 2,
        state_cur: b.cur.root(),
        state_next: atk.root(),
        carry_next: Some(&atk),
        signer: &atk,
        bits: full(N),
        net: &b.net,
    });
    refused(
        "handoff to an attacker committee",
        &b.input_with(vec![attacker_handoff]),
        "finish",
    );

    // claims more (or other) signers than actually signed
    let mut few = b.update(tk::bits_set(N, 16));
    few.bits = full(N);
    refused("bits exceed signers", &b.input_with(vec![few]), "finish");
    let mut other = b.update(tk::bits_from(N, &(0..24).collect::<Vec<_>>()));
    other.bits = tk::bits_from(N, &(8..32).collect::<Vec<_>>());
    refused(
        "bits name other members",
        &b.input_with(vec![other]),
        "finish",
    );

    // the same update under another chain identity: only the signing root differs
    let mut gvr = b.input_with(vec![b.update(full(N))]);
    gvr.sync.as_mut().unwrap().genesis_validators_root = [0x11; 32];
    refused("other genesis validators root", &gvr, "finish");
    let mut fork = b.input_with(vec![b.update(full(N))]);
    fork.sync.as_mut().unwrap().forks = vec![(0, [99, 99, 99, 99])];
    refused("other fork version", &fork, "finish");
    refused(
        "mainnet update under the testnet identity",
        &b.input_with_net(&TESTNET, vec![b.update(full(N))]),
        "finish",
    );

    // the committed aggregate is not the sum of the committed keys
    let mut cur = tk::committee(1, N);
    cur.aggregate = tk::committee(77, N).aggregate;
    let inconsistent = Baseline::new(MAINNET, cur, tk::committee(2, N));
    refused(
        "aggregate inconsistent with keys",
        &inconsistent.input_with(vec![inconsistent.update(full(N))]),
        "finish",
    );
}

#[test]
fn the_retired_committee_cannot_sign_the_next_period() {
    let b = baseline(N);
    let (a, bb) = handoff_pair(&b, &b.next, &b.cur, &tk::committee(3, N));
    let steps = check(
        "retired committee",
        &b.input_with(vec![a, bb]),
        &[None, Some("finish")],
    );
    assert!(steps[0].is_ok());
    assert!(steps[1].is_err());
}

#[test]
fn a_committee_never_handed_off_cannot_sign_the_next_period() {
    let b = baseline(N);
    let atk = tk::committee(90, N);
    let (a, bb) = handoff_pair(&b, &b.next, &atk, &tk::committee(3, N));
    let steps = check(
        "never handed off",
        &b.input_with(vec![a, bb]),
        &[None, Some("finish")],
    );
    assert!(steps[0].is_ok());
    assert!(steps[1].is_err());
}

// ---- bootstrap failures: there is no store to stage against ----------------------------------

#[test]
fn a_bad_bootstrap_agrees_with_the_reference() {
    let honest = baseline(N);
    let atk = Baseline::new(MAINNET, tk::committee(90, N), tk::committee(91, N));
    let mut fabricated = atk.input_with(vec![atk.update(full(N))]);
    fabricated.trusted_root = honest.input.trusted_root;
    check("fabricated bootstrap", &fabricated, &[]);

    let mut corrupt = honest.input_with(vec![honest.update(full(N))]);
    corrupt.pubkeys[0] ^= 0xFF;
    check("corrupted committee key", &corrupt, &[]);
}

// ---- the job in between ----------------------------------------------------------------------

#[test]
fn a_corrupted_miller_state_is_never_accepted_by_finish() {
    // Not the forged-state attack (that needs a state that encodes a passing result, and is the
    // reason the job must live in a program-owned account: see `update_job`). This pins the
    // weaker property: corruption of a real Miller result does not verify, and does not panic.
    let b = baseline(N);
    let input = b.input_with(vec![b.update(full(N))]);
    let sync = input.sync.as_ref().unwrap();
    let cfg = StageConfig::from_input(&input, sync);
    let store = initial_store_bytes(&input, sync).unwrap();
    let u = &sync.updates[0];

    let job = begin_miller(&cfg, &store, u).unwrap();
    assert_eq!(job.len(), JOB_LEN);
    assert_eq!(JOB_LEN - STATE_AT, STATE_LEN);
    assert!(
        finish(&cfg, &job, &store, u).is_ok(),
        "the untouched job finishes"
    );
    for i in [0usize, 1, 47, 48, 100, 287, 288, 527, 575] {
        let mut bad = job.clone();
        bad[STATE_AT + i] ^= 1;
        assert_eq!(
            finish(&cfg, &bad, &store, u),
            Err(Error::BadSignature),
            "state byte {i}"
        );
    }
}
