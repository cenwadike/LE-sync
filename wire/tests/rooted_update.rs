//! Differential suite for the ROOTED staged update (Sprint 6, M1): real BLS, three transactions,
//! a store that holds only the committees' keys roots and aggregates (`store_codec` v2).
//!
//! Subject: `run_rooted` (Begin with hints, Miller, Finish, each through its byte encoding) on
//! the `bls-blst` backend. References:
//! * the full-store staged path (`run_stage`, same backend): per update the SAME verdict (the
//!   same refusing stage and the same typed error), and after every accepted update the rooted
//!   store is exactly the rooted form of the full store (`LightClientStore::to_rooted`);
//! * the single-shot `bls-zk` path (`common::run`): the same accept or reject.
//!
//! The hints are built from the full store the reference run keeps in step: the keys of the
//! members whose bit is zero, in the committee that signs (the current one, or the next one
//! when the update is for the next period).
//!
//! Needs both backends: `cargo test -p le-sync-wire --features bls-zk,bls-blst --test rooted_update`.
#![cfg(all(feature = "bls-zk", feature = "bls-blst"))]

mod common;

use common::*;
use le_sync_core::store_codec::{decode_store, encode_store, MAX_ENCODED_LEN};
use le_sync_core::{BlsPubkey, Error};
use le_sync_testkit as tk;
use le_sync_wire::bls::{uncompress_g1, Impl};
use le_sync_wire::rooted::{
    absent_wire, initial_rooted_store_bytes, run_rooted, to_rooted_update, AbsentWire, RootedInput,
};
use le_sync_wire::stage::{initial_store_bytes, run_stage, StageConfig, StageInput, StageOutput};
use le_sync_wire::{GuestInput, UpdateOutcome as O, UpdateWire};

const N: usize = 32;

/// How one update fared: `Err((stage, error))` names the stage that refused it.
type Step = Result<(), (&'static str, Error)>;

// ---- the full-store path (reference) --------------------------------------------------------

fn job_of(
    o: Result<StageOutput, Error>,
    stage: &'static str,
) -> Result<Vec<u8>, (&'static str, Error)> {
    match o {
        Ok(StageOutput::Job(j)) => Ok(j),
        Ok(other) => panic!("{stage} returned {other:?}"),
        Err(e) => Err((stage, e)),
    }
}

fn store_of(o: Result<StageOutput, Error>) -> Result<Vec<u8>, (&'static str, Error)> {
    match o {
        Ok(StageOutput::Store(s)) => Ok(s),
        Ok(other) => panic!("finish returned {other:?}"),
        Err(e) => Err(("finish", e)),
    }
}

fn one_full(
    cfg: &StageConfig,
    store: &[u8],
    u: &UpdateWire,
) -> Result<Vec<u8>, (&'static str, Error)> {
    let job = job_of(
        run_stage(
            cfg,
            &StageInput::Begin {
                store: store.to_vec(),
                update: u.clone(),
            },
            &Impl,
        ),
        "begin",
    )?;
    let job = job_of(run_stage(cfg, &StageInput::Miller { job }, &Impl), "miller")?;
    store_of(run_stage(
        cfg,
        &StageInput::Finish {
            job,
            store: store.to_vec(),
            update: u.clone(),
        },
        &Impl,
    ))
}

// ---- the rooted path (subject) --------------------------------------------------------------

/// The committee that signs `u` against the full store `store`: the current one, or the next
/// one when the signature is for the next period.
#[inline(never)]
fn signing_keys(store: &[u8], cfg: &StageConfig, u: &UpdateWire) -> Vec<BlsPubkey> {
    let st = Box::new(decode_store(store).unwrap());
    let per = cfg.slots_per_epoch * cfg.epochs_per_period;
    let committee = if u.signature_slot / per == st.finalized_header.slot / per {
        &st.current_sync_committee
    } else {
        &st.next_sync_committee
    };
    committee.keys().to_vec()
}

/// The hints for `u`. Where there are none to build (no keys to take them from, bits that do
/// not cover the committee) the update is refused by a non-signature rule before the hints are
/// read, so an empty set stands in.
fn hints(full: &[u8], cfg: &StageConfig, u: &UpdateWire) -> AbsentWire {
    absent_wire(&signing_keys(full, cfg, u), &u.bits, uncompress_g1).unwrap_or_default()
}

fn one_rooted_with(
    cfg: &StageConfig,
    rooted: &[u8],
    u: &UpdateWire,
    absent: AbsentWire,
) -> Result<Vec<u8>, (&'static str, Error)> {
    let ru = to_rooted_update(u).unwrap_or_else(|e| panic!("to_rooted_update: {e:?}"));
    let job = job_of(
        run_rooted(
            cfg,
            &RootedInput::Begin {
                store: rooted.to_vec(),
                update: ru.clone(),
                absent,
            },
            &Impl,
        ),
        "begin",
    )?;
    let job = job_of(
        run_rooted(cfg, &RootedInput::Miller { job }, &Impl),
        "miller",
    )?;
    store_of(run_rooted(
        cfg,
        &RootedInput::Finish {
            job,
            store: rooted.to_vec(),
            update: ru,
        },
        &Impl,
    ))
}

/// The v2 bytes of a v1 store.
#[inline(never)]
fn rooted_form(full: &[u8]) -> Vec<u8> {
    let s = Box::new(decode_store(full).unwrap());
    let r = Box::new(s.to_rooted().unwrap());
    let mut out = vec![0u8; MAX_ENCODED_LEN];
    let n = encode_store(&r, &mut out).unwrap();
    out.truncate(n);
    out
}

// ---- driving both ---------------------------------------------------------------------------

fn agrees(want: O, got: &Step) -> bool {
    match (want, got) {
        (O::Validated, Ok(())) => true,
        (O::NotRelevant, Err((_, Error::UpdateNotRelevant))) => true,
        (O::Rejected(e), Err((_, g))) => e == *g,
        (O::Malformed, Err((_, Error::BadSignature | Error::BadSyncCommitteeSize))) => true,
        _ => false,
    }
}

/// Every update of `input.sync` in order through the full path and the rooted path, each against
/// its own store, and compare. `stages[i]`, if `Some`, is the stage that must refuse update `i`.
fn differential(name: &str, input: &GuestInput, stages: &[Option<&str>]) -> Vec<Step> {
    let want = run(input);
    let sync = input.sync.as_ref().unwrap();
    let cfg = StageConfig::from_input(input, sync);
    let (mut full, mut rooted) = match (
        initial_store_bytes(input, sync),
        initial_rooted_store_bytes(input, sync),
    ) {
        (Ok(f), Ok(r)) => (f, r),
        (Err(a), Err(b)) => {
            assert_eq!(a, b, "{name}: the two bootstraps fail differently");
            assert!(
                want.updates.iter().all(|u| *u == O::SetupFailed(a)),
                "{name}: setup failed with {a:?}, reference says {:?}",
                want.updates
            );
            return vec![];
        }
        (f, r) => panic!("{name}: bootstrap differs: full {f:?}, rooted {r:?}"),
    };
    assert_eq!(rooted.len(), 403, "{name}");
    assert_eq!(rooted, rooted_form(&full), "{name}: bootstrap store");

    let mut steps = vec![];
    for (i, u) in sync.updates.iter().enumerate() {
        let f = one_full(&cfg, &full, u);
        let r = one_rooted_with(&cfg, &rooted, u, hints(&full, &cfg, u));
        let step = match (f, r) {
            (Ok(nf), Ok(nr)) => {
                assert_eq!(nr.len(), 403, "{name}: update {i}");
                assert_eq!(nr, rooted_form(&nf), "{name}: update {i}: store");
                full = nf;
                rooted = nr;
                Ok(())
            }
            (Err(a), Err(b)) => {
                assert_eq!(a, b, "{name}: update {i}: full {a:?}, rooted {b:?}");
                Err(a)
            }
            (f, r) => panic!(
                "{name}: update {i}: full {:?}, rooted {:?}",
                f.map(|_| ()),
                r.map(|_| ())
            ),
        };
        eprintln!(
            "{name}: update {i}: reference {:?}, rooted {step:?}",
            want.updates[i]
        );
        assert!(agrees(want.updates[i], &step), "{name}: update {i}");
        if let (Some(Some(s)), Err((got, _))) = (stages.get(i), &step) {
            assert_eq!(got, s, "{name}: update {i}: refusing stage");
        }
        steps.push(step);
    }
    assert_eq!(steps.len(), want.updates.len(), "{name}");
    // where the updates left the stores
    let st = Box::new(decode_store(&rooted).unwrap());
    assert_eq!(
        st.finalized_header.slot, want.output.finalized_slot,
        "{name}"
    );
    assert_eq!(
        st.finalized_header.hash_tree_root(),
        want.output.finalized_root,
        "{name}"
    );
    assert_eq!(
        st.optimistic_header.slot, want.output.optimistic_slot,
        "{name}"
    );
    steps
}

fn accepted(name: &str, input: &GuestInput) {
    let steps = differential(name, input, &[]);
    assert!(!steps.is_empty(), "{name}");
    assert!(steps.iter().all(|s| s.is_ok()), "{name}: {steps:?}");
}

fn refused(name: &str, input: &GuestInput, stage: &str) {
    let steps = differential(name, input, &[Some(stage)]);
    assert_eq!(steps.len(), 1, "{name}");
    assert!(steps[0].is_err(), "{name}: was accepted");
}

fn with_update(b: &Baseline, edit: impl FnOnce(&mut UpdateWire)) -> GuestInput {
    let mut u = b.update(full(N));
    edit(&mut u);
    b.input_with(vec![u])
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

// ---- accepted: the rooted run lands where the full run does ----------------------------------

#[test]
fn baseline_guard_the_reference_accepts_the_fixture() {
    let b = baseline(N);
    let t = run(&b.input_with(vec![b.update(full(N))]));
    assert_eq!(t.updates, vec![O::Validated]);
    assert_eq!(
        (t.output.finalized_slot, t.output.optimistic_slot),
        (24, 40)
    );
}

#[test]
fn full_participation_needs_no_hints() {
    let b = baseline(N);
    let input = b.input_with(vec![b.update(full(N))]);
    accepted("full", &input);
    let sync = input.sync.as_ref().unwrap();
    let cfg = StageConfig::from_input(&input, sync);
    let store = initial_store_bytes(&input, sync).unwrap();
    assert_eq!(hints(&store, &cfg, &sync.updates[0]), AbsentWire::default());
}

#[test]
fn partial_participation_with_hints() {
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
    // one absent member, at either end and in the middle
    for gone in [0usize, 17, 31] {
        let bits = tk::bits_from(N, &(0..N).filter(|i| *i != gone).collect::<Vec<_>>());
        accepted(
            &format!("member {gone} absent"),
            &b.input_with(vec![b.update(bits)]),
        );
    }
}

#[test]
fn update_that_carries_the_next_committee() {
    let b = baseline(N);
    let (a, _) = handoff_pair(&b, &b.next, &b.next, &tk::committee(3, N));
    accepted("handoff", &b.input_with(vec![a]));
}

#[test]
fn honest_handoff_pair_across_the_period_boundary() {
    // the second update is signed by the committee the first one carried as a ROOT: its hints
    // come from keys the rooted store never held
    let b = baseline(N);
    let (a, bb) = handoff_pair(&b, &b.next, &b.next, &tk::committee(3, N));
    let i = b.input_with(vec![a, bb]);
    accepted("pair", &i);
    assert_eq!(run(&i).output.finalized_slot, 72);
}

#[test]
fn handoff_pair_with_partial_participation_in_the_second_period() {
    let b = baseline(N);
    let c3 = tk::committee(3, N);
    let (a, _) = handoff_pair(&b, &b.next, &b.next, &c3);
    let bits = tk::bits_set(N, 24);
    let bb = build_update(&Spec {
        att_slot: 88,
        fin_slot: 72,
        sig_slot: 89,
        salt: 6,
        state_cur: b.next.root(),
        state_next: c3.root(),
        carry_next: Some(&c3),
        signer: &b.next,
        bits,
        net: &b.net,
    });
    accepted("pair, 24 of 32 in period 1", &b.input_with(vec![a, bb]));
}

#[test]
fn committee_of_512_full_and_minimum_participation() {
    if std::env::var_os("LE_SYNC_SKIP_SLOW").is_some() {
        return; // mutation runs skip this; the full `cargo test` run does not
    }
    let n = 512;
    let b = baseline(n);
    accepted("512 full", &b.input_with(vec![b.update(full(n))]));
    // exactly 2/3: 170 members absent, the case the cost gate is measured on
    accepted(
        "512 at 342",
        &b.input_with(vec![b.update(tk::bits_set(n, 342))]),
    );
    let bits = tk::bits_from(n, &(0..n).filter(|i| i % 3 != 0).collect::<Vec<_>>());
    accepted("512 scattered", &b.input_with(vec![b.update(bits)]));
    let mut bad = b.update(full(n));
    bad.signature[95] ^= 1;
    refused("512 flipped bit", &b.input_with(vec![bad]), "begin");
}

// ---- refused: the same stage and the same error as the full path -----------------------------

#[test]
fn non_signature_rules_are_refused_by_begin_with_the_same_error() {
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
    // the wrong next committee, as a root: the branch proves another root
    refused(
        "forged next committee",
        &b.input_with(vec![forged_next]),
        "begin",
    );
    let (_, bb) = handoff_pair(&b, &b.next, &b.next, &tk::committee(3, N));
    refused("period skipped", &b.input_with(vec![bb]), "begin");
}

#[test]
fn undecodable_signatures_are_refused_by_begin() {
    let b = baseline(N);
    let mut flipped = b.update(full(N));
    flipped.signature[95] ^= 1;
    refused("flipped bit", &b.input_with(vec![flipped]), "begin");
    for (name, sig) in [("all-zero", vec![0u8; 96]), ("garbage", vec![0xFFu8; 96])] {
        refused(name, &with_update(&b, |u| u.signature = sig), "begin");
    }
    for len in [0usize, 48, 95, 97] {
        refused(
            &format!("signature of {len} bytes"),
            &with_update(&b, |u| u.signature = vec![0x11; len]),
            "begin",
        );
    }
    let mut infinity = vec![0u8; 96];
    infinity[0] = 0xC0;
    refused(
        "infinity",
        &with_update(&b, |u| u.signature = infinity),
        "begin",
    );
}

#[test]
fn signatures_that_decode_but_do_not_verify_are_refused_by_finish() {
    let b = baseline(N);
    let atk = tk::committee(90, N);
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
    // claims more (or other) signers than actually signed: the hints follow the CLAIM, so they
    // are consistent with the bits and the pairing is what refuses
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
    let mut gvr = b.input_with(vec![b.update(full(N))]);
    gvr.sync.as_mut().unwrap().genesis_validators_root = [0x11; 32];
    refused("other genesis validators root", &gvr, "finish");
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
    let steps = differential(
        "retired committee",
        &b.input_with(vec![a, bb]),
        &[None, Some("finish")],
    );
    assert!(steps[0].is_ok());
    assert!(steps[1].is_err());
}

#[test]
fn a_bad_bootstrap_agrees_with_the_reference() {
    let honest = baseline(N);
    let atk = Baseline::new(MAINNET, tk::committee(90, N), tk::committee(91, N));
    let mut fabricated = atk.input_with(vec![atk.update(full(N))]);
    fabricated.trusted_root = honest.input.trusted_root;
    differential("fabricated bootstrap", &fabricated, &[]);
    let mut corrupt = honest.input_with(vec![honest.update(full(N))]);
    corrupt.pubkeys[0] ^= 0xFF;
    differential("corrupted committee key", &corrupt, &[]);
}

// ---- hints that lie: always refused by Begin with AbsentKeys, never accepted ------------------

/// The pieces of the baseline update with 22 of 32 present, for tampering with the hints.
struct Case {
    cfg: StageConfig,
    full: Vec<u8>,
    rooted: Vec<u8>,
    update: UpdateWire,
    keys: Vec<BlsPubkey>,
}

fn case() -> Case {
    let b = baseline(N);
    let input = b.input_with(vec![b.update(tk::bits_set(N, 22))]);
    let sync = input.sync.as_ref().unwrap();
    let cfg = StageConfig::from_input(&input, sync);
    let full = initial_store_bytes(&input, sync).unwrap();
    let rooted = initial_rooted_store_bytes(&input, sync).unwrap();
    let update = sync.updates[0].clone();
    let keys = signing_keys(&full, &cfg, &update);
    Case {
        cfg,
        full,
        rooted,
        update,
        keys,
    }
}

fn run_with(c: &Case, absent: AbsentWire) -> Result<Vec<u8>, (&'static str, Error)> {
    one_rooted_with(&c.cfg, &c.rooted, &c.update, absent)
}

#[test]
fn honest_hints_pass_and_every_kind_of_lie_is_refused() {
    let c = case();
    let honest = hints(&c.full, &c.cfg, &c.update);
    assert_eq!(honest.index, (22..32u16).collect::<Vec<_>>());
    assert!(run_with(&c, honest.clone()).is_ok());
    let refused_begin = |a: AbsentWire, what: &str| {
        assert_eq!(run_with(&c, a), Err(("begin", Error::AbsentKeys)), "{what}");
    };

    // no hints at all, one member dropped, one added, one swapped for a present member
    refused_begin(AbsentWire::default(), "no hints");
    let mut a = honest.clone();
    a.index.pop();
    a.keys.truncate(a.keys.len() - 24);
    refused_begin(a, "member dropped");
    let mut a = honest.clone();
    a.index.insert(0, 21);
    let k21 = words_of(&uncompress_g1(&c.keys[21]).unwrap());
    a.keys.splice(0..0, k21);
    refused_begin(a, "present member listed");
    let mut a = honest.clone();
    a.index[3] = 20;
    refused_begin(a, "wrong position");

    // a valid point of another member, of another committee, and the compressed form
    for (what, key) in [
        ("another member's key", uncompress_g1(&c.keys[1]).unwrap()),
        (
            "another committee's key",
            uncompress_g1(&tk::committee(90, N).pubkeys[22]).unwrap(),
        ),
    ] {
        let mut a = honest.clone();
        a.keys[..24].copy_from_slice(&words_of(&key));
        refused_begin(a, what);
    }
    let mut a = honest.clone();
    let mut compressed = [0u8; 96];
    compressed[..48].copy_from_slice(&c.keys[22]);
    a.keys[..24].copy_from_slice(&words_of(&compressed));
    refused_begin(a, "compressed key");

    // every word of every hinted key and of the proof
    for i in 0..honest.keys.len() {
        let mut a = honest.clone();
        a.keys[i] ^= 1;
        refused_begin(a, &format!("key word {i}"));
    }
    for i in 0..honest.proof.len() {
        let mut a = honest.clone();
        a.proof[i] ^= 1;
        refused_begin(a, &format!("proof word {i}"));
    }
    let mut a = honest.clone();
    a.proof.extend([0u32; 8]);
    refused_begin(a, "proof too long");
    let mut a = honest;
    a.proof.truncate(a.proof.len().saturating_sub(8));
    refused_begin(a, "proof too short");
}

fn words_of(p: &[u8; 96]) -> Vec<u32> {
    p.chunks(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

#[test]
fn hints_for_one_update_do_not_serve_another() {
    // the same signers, a different set of absent members
    let c = case();
    let other_bits = tk::bits_set(N, 24);
    let hints_for_other = absent_wire(&c.keys, &other_bits, uncompress_g1).unwrap();
    assert_ne!(hints_for_other.index, (22..32u16).collect::<Vec<_>>());
    assert_eq!(
        run_with(&c, hints_for_other),
        Err(("begin", Error::AbsentKeys))
    );
}

#[test]
fn the_two_store_forms_do_not_mix() {
    let c = case();
    let honest = hints(&c.full, &c.cfg, &c.update);
    // a full store under the rooted path, a rooted store under the full path
    let r = one_rooted_with(&c.cfg, &c.full, &c.update, honest);
    assert_eq!(r, Err(("begin", Error::AbsentKeys)));
    let f = one_full(&c.cfg, &c.rooted, &c.update);
    assert_eq!(f, Err(("begin", Error::AbsentKeys)));
}

#[test]
fn a_corrupted_miller_state_is_never_accepted_by_finish() {
    // as in `staged_update`: corruption of a real Miller result does not verify, and does not
    // panic. The forged-state attack needs a writable job and is why the job lives in a
    // program-owned account.
    const STATE_AT: usize = 1 + 32 + 32;
    let c = case();
    let honest = hints(&c.full, &c.cfg, &c.update);
    let ru = to_rooted_update(&c.update).unwrap();
    let job = job_of(
        run_rooted(
            &c.cfg,
            &RootedInput::Begin {
                store: c.rooted.clone(),
                update: ru.clone(),
                absent: honest,
            },
            &Impl,
        ),
        "begin",
    )
    .unwrap();
    let job = job_of(
        run_rooted(&c.cfg, &RootedInput::Miller { job }, &Impl),
        "miller",
    )
    .unwrap();
    let fin = |job: &[u8]| {
        run_rooted(
            &c.cfg,
            &RootedInput::Finish {
                job: job.to_vec(),
                store: c.rooted.clone(),
                update: ru.clone(),
            },
            &Impl,
        )
    };
    assert!(fin(&job).is_ok(), "the untouched job finishes");
    for i in [0usize, 1, 47, 48, 100, 287, 288, 527, 575] {
        let mut bad = job.clone();
        bad[STATE_AT + i] ^= 1;
        assert_eq!(fin(&bad), Err(Error::BadSignature), "state byte {i}");
    }
}
