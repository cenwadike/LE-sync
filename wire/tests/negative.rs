//! Real-BLS negative suite (Sprint 3), `cargo test -p le-sync-wire --features bls-zk`.
//!
//! Every case starts from the same baseline (which has its own guard test) and changes one
//! thing. Each rejection asserts the exact typed error via `verify_trace`, never just a count,
//! so a broken fixture cannot masquerade as the check under test.
//!
//! Maps to: Verification Security #1 (fabricated chain), #2 (never-handed-off committee, below
//! threshold, non-finalised header, other chain), Func #5 / #14 (chain binding).
#![cfg(feature = "bls-zk")]

mod common;

use common::*;
use le_sync_core::{Error, ZERO};
use le_sync_testkit as tk;
use le_sync_wire::{check_chain_binding, verify, UpdateOutcome as O};

const N: usize = 32;

fn only(t: &le_sync_wire::Trace) -> O {
    assert_eq!(t.updates.len(), 1, "{t:?}");
    t.updates[0]
}

// ---- baseline ----------------------------------------------------------------------------------

#[test]
fn baseline_signed_fixture_validates() {
    // Guards every rejection below: if this stops passing, a "rejection" could be a broken
    // fixture rather than the check under test.
    let b = baseline(N);
    let t = run(&b.input_with(vec![b.update(full(N))]));
    assert_eq!(t.updates, vec![O::Validated]);
    let o = &t.output;
    assert!(
        o.bootstrap_ok && o.success(false) && o.sync_success(false),
        "{o:?}"
    );
    assert_eq!((o.finalized_slot, o.optimistic_slot), (24, 40));
    assert_eq!(check_chain_binding(o, &expected_binding(&MAINNET)), Ok(()));
}

#[test]
fn trace_output_is_identical_to_the_journal_the_guest_commits() {
    let b = baseline(N);
    let input = b.input_with(vec![b.update(full(N))]);
    assert_eq!(run(&input).output, verify(&input, &le_sync_wire::bls::Impl));
    assert_eq!(run(&input), run(&input), "deterministic");
}

#[test]
fn testkit_signer_is_independent_of_the_production_dst() {
    assert_eq!(le_sync_wire::bls::DST, tk::DST);
}

// ---- Verification Security #1: fabricated chain --------------------------------------------------

#[test]
fn fabricated_bootstrap_with_self_consistent_proofs_rejected() {
    // The attacker builds an entire self-consistent world (own committee, own bootstrap state,
    // own signed update). Every Merkle branch and signature inside it is valid. The only thing
    // wrong is that it is not the configured checkpoint.
    let honest = baseline(N);
    let atk = Baseline::new(MAINNET, tk::committee(90, N), tk::committee(91, N));
    let mut input = atk.input_with(vec![atk.update(full(N))]);
    input.trusted_root = honest.input.trusted_root;

    let t = run(&input);
    assert_eq!(only(&t), O::SetupFailed(Error::TrustedRootMismatch));
    let o = &t.output;
    assert!(!o.bootstrap_ok);
    assert_eq!((o.sync_validated, o.sync_rejected), (0, 1));
    assert_eq!((o.finalized_slot, o.finalized_root), (0, ZERO));
    // Sanity: the attacker's world IS internally valid under its own root.
    let own = run(&atk.input_with(vec![atk.update(full(N))]));
    assert_eq!(own.updates, vec![O::Validated]);
}

#[test]
fn fabricated_finalised_state_signed_by_attacker_rejected() {
    // Honest bootstrap. The attacker fabricates a self-consistent attested state and finality
    // branch (so the Merkle layer passes) and signs with their own full committee.
    let b = baseline(N);
    let atk = tk::committee(90, N);
    let forged = build_update(&Spec {
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
    let t = run(&b.input_with(vec![forged]));
    // Exactly BadSignature: the update got past every branch check and died on the signature.
    assert_eq!(only(&t), rejected(Error::BadSignature));
    let o = &t.output;
    assert_eq!(o.sync_validated, 0);
    assert_eq!(o.finalized_slot, 8, "finalized head must not move");
    assert_eq!(o.finalized_root, b.input.trusted_root);
}

// ---- Verification Security #2: committee handoff -------------------------------------------------

/// A (period 0): carries `next_for_a`, signed by the checkpoint committee.
/// B (period 1): finalizes slot 72, signed by `signer_b`, carries `c3`.
fn handoff_pair(
    b: &Baseline,
    next_for_a: &tk::Committee,
    signer_b: &tk::Committee,
    c3: &tk::Committee,
) -> (le_sync_wire::UpdateWire, le_sync_wire::UpdateWire) {
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

#[test]
fn honest_handoff_is_followed_across_the_period_boundary() {
    let b = baseline(N);
    let c3 = tk::committee(3, N);
    let (a, bb) = handoff_pair(&b, &b.next, &b.next, &c3);
    let t = run(&b.input_with(vec![a, bb]));
    assert_eq!(t.updates, vec![O::Validated, O::Validated]);
    assert_eq!(t.output.finalized_slot, 72);
}

#[test]
fn period_update_without_a_proven_handoff_is_rejected() {
    // A header signed by the genuine next committee, but the handoff to it was never submitted.
    let b = baseline(N);
    let c3 = tk::committee(3, N);
    let (_, bb) = handoff_pair(&b, &b.next, &b.next, &c3);
    let t = run(&b.input_with(vec![bb]));
    assert_eq!(only(&t), rejected(Error::PeriodSkipped));
    assert_eq!(t.output.finalized_slot, 8);
}

#[test]
fn period_update_signed_by_a_committee_never_handed_off_is_rejected() {
    let b = baseline(N);
    let atk = tk::committee(90, N);
    let c3 = tk::committee(3, N);
    let (a, bb) = handoff_pair(&b, &b.next, &atk, &c3);
    let t = run(&b.input_with(vec![a, bb]));
    assert_eq!(t.updates, vec![O::Validated, rejected(Error::BadSignature)]);
    assert_eq!(
        t.output.finalized_slot, 24,
        "attacker must not move the head"
    );
}

#[test]
fn period_update_signed_by_the_retired_committee_is_rejected() {
    // After the handoff, period 1 must be signed by `next`; the old committee no longer counts.
    let b = baseline(N);
    let c3 = tk::committee(3, N);
    let (a, bb) = handoff_pair(&b, &b.next, &b.cur, &c3);
    let t = run(&b.input_with(vec![a, bb]));
    assert_eq!(t.updates, vec![O::Validated, rejected(Error::BadSignature)]);
    assert_eq!(t.output.finalized_slot, 24);
}

#[test]
fn forged_next_committee_under_an_honest_state_rejected() {
    // Right branch, wrong committee: the carried committee is not what the attested state holds.
    let b = baseline(N);
    let atk = tk::committee(90, N);
    let a = build_update(&Spec {
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
    let t = run(&b.input_with(vec![a]));
    assert_eq!(only(&t), rejected(Error::InvalidBranch));
    assert!(!t.output.sync_success(false));
}

#[test]
fn handoff_to_an_attacker_committee_without_checkpoint_signatures_rejected() {
    // The attacker can build a state whose next committee is theirs, but cannot sign for `cur`.
    let b = baseline(N);
    let atk = tk::committee(90, N);
    let a = build_update(&Spec {
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
    let t = run(&b.input_with(vec![a]));
    assert_eq!(only(&t), rejected(Error::BadSignature));
}

// ---- Verification Security #2: finality / non-finalised header -----------------------------------

#[test]
fn claimed_finalized_header_not_in_the_attested_state_rejected() {
    // Attested header validly signed with full participation, but the finalized header it
    // presents is not the one the attested state finalizes.
    let b = baseline(N);
    let mut u = b.update(full(N));
    u.finalized.slot += 1;
    let t = run(&b.input_with(vec![u]));
    assert_eq!(only(&t), rejected(Error::InvalidBranch));
    assert_eq!(t.output.finalized_slot, 8);
}

#[test]
fn signed_attested_header_without_finality_never_advances_finalized() {
    // A validly signed header with no finality proof is accepted as an update (spec) but may
    // only move the optimistic header, never the finalized one.
    let b = baseline(N);
    let mut u = b.update(full(N));
    u.finality_branch = vec![ZERO; 7];
    u.finalized = empty_hdr();
    let t = run(&b.input_with(vec![u]));
    assert_eq!(only(&t), O::Validated);
    assert_eq!(t.output.finalized_slot, 8);
    assert_eq!(t.output.finalized_root, b.input.trusted_root);
    assert_eq!(t.output.optimistic_slot, 40);
}

#[test]
fn tampered_finality_branch_rejected() {
    let b = baseline(N);
    let mut u = b.update(full(N));
    u.finality_branch[3][0] ^= 1;
    assert_eq!(
        only(&run(&b.input_with(vec![u]))),
        rejected(Error::InvalidBranch)
    );
}

// ---- Verification Security #2: participation -----------------------------------------------------

#[test]
fn below_two_thirds_never_advances_finalized() {
    let b = baseline(N);
    let t = run(&b.input_with(vec![b.update(tk::bits_set(N, 12))]));
    assert_eq!(only(&t), rejected(Error::BelowThreshold));
    let o = &t.output;
    assert_eq!((o.sync_below_threshold, o.sync_validated), (1, 0));
    assert_eq!(o.finalized_slot, 8);
    assert_eq!(o.finalized_root, b.input.trusted_root);
}

#[test]
fn two_thirds_boundary_is_exactly_22_of_32() {
    let b = baseline(N);
    let t21 = run(&b.input_with(vec![b.update(tk::bits_set(N, 21))]));
    assert_eq!(only(&t21), rejected(Error::BelowThreshold));
    let t22 = run(&b.input_with(vec![b.update(tk::bits_set(N, 22))]));
    assert_eq!(only(&t22), O::Validated);
}

#[test]
fn scattered_supermajority_validates() {
    // 0xEE bytes: 6 of 8 bits per byte, not contiguous. 24 of 32 >= 2/3.
    let b = baseline(N);
    let bits = vec![0xEE; N / 8];
    let t = run(&b.input_with(vec![b.update(bits)]));
    assert_eq!(only(&t), O::Validated);
}

#[test]
fn claimed_bits_exceed_real_signers_rejected() {
    // Signed by the low 16 members, claims all 32.
    let b = baseline(N);
    let mut u = b.update(tk::bits_set(N, 16));
    u.bits = full(N);
    assert_eq!(
        only(&run(&b.input_with(vec![u]))),
        rejected(Error::BadSignature)
    );
}

#[test]
fn claimed_bits_different_members_than_real_signers_rejected() {
    let b = baseline(N);
    let mut u = b.update(tk::bits_from(N, &(0..24).collect::<Vec<_>>()));
    u.bits = tk::bits_from(N, &(8..32).collect::<Vec<_>>());
    assert_eq!(
        only(&run(&b.input_with(vec![u]))),
        rejected(Error::BadSignature)
    );
}

#[test]
fn bitfield_length_mismatch_rejected() {
    let b = baseline(N);
    let mut u = b.update(full(N));
    u.bits = vec![0xFF; N / 8 + 2];
    assert_eq!(
        only(&run(&b.input_with(vec![u]))),
        rejected(Error::CommitteeSizeMismatch)
    );
}

// ---- Verification Security #2 / Func #5, #14: chain binding --------------------------------------

#[test]
fn other_genesis_validators_root_rejected() {
    let b = baseline(N);
    let mut input = b.input_with(vec![b.update(full(N))]);
    input.sync.as_mut().unwrap().genesis_validators_root = [0x11; 32];
    assert_eq!(only(&run(&input)), rejected(Error::BadSignature));
}

#[test]
fn other_fork_version_rejected() {
    let b = baseline(N);
    let mut input = b.input_with(vec![b.update(full(N))]);
    input.sync.as_mut().unwrap().forks = vec![(0, [99, 99, 99, 99])];
    assert_eq!(only(&run(&input)), rejected(Error::BadSignature));
}

#[test]
fn mainnet_update_presented_under_testnet_identity_rejected_by_the_guest() {
    let b = baseline(N);
    let input = b.input_with_net(&TESTNET, vec![b.update(full(N))]);
    assert_eq!(only(&run(&input)), rejected(Error::BadSignature));
}

#[test]
fn testnet_statement_is_rejected_by_a_mainnet_consumer_and_accepted_by_a_testnet_one() {
    // Same committee, same state shape (same "contract address" on both): the signing domain
    // and the committed binding are the only things that differ.
    let tb = Baseline::new(TESTNET, tk::committee(1, N), tk::committee(2, N));
    let t = run(&tb.input_with(vec![tb.update(full(N))]));
    assert_eq!(
        only(&t),
        O::Validated,
        "valid for the testnet it was produced for"
    );
    assert_eq!(
        check_chain_binding(&t.output, &expected_binding(&MAINNET)),
        Err(Error::ChainMismatch)
    );
    assert_eq!(
        check_chain_binding(&t.output, &expected_binding(&TESTNET)),
        Ok(())
    );
}

#[test]
fn mislabeled_chain_id_passes_the_guest_but_not_the_consumer() {
    // chain_id is an unsigned label: only the consumer-side binding check can catch it.
    let b = baseline(N);
    let mut input = b.input_with(vec![b.update(full(N))]);
    input.sync.as_mut().unwrap().chain_id = TESTNET.chain_id;
    let t = run(&input);
    assert_eq!(only(&t), O::Validated);
    assert_eq!(
        check_chain_binding(&t.output, &expected_binding(&MAINNET)),
        Err(Error::ChainMismatch)
    );
}

// ---- signature / key hardening ---------------------------------------------------------------------

#[test]
fn infinity_garbage_and_zero_signatures_rejected() {
    let b = baseline(N);
    let mut infinity = vec![0u8; 96];
    infinity[0] = 0xC0; // valid encoding of the point at infinity
    for (name, sig) in [
        ("infinity", infinity),
        ("all-zero", vec![0u8; 96]),
        ("garbage", vec![0xFF; 96]),
    ] {
        let mut u = b.update(full(N));
        u.signature = sig;
        assert_eq!(
            only(&run(&b.input_with(vec![u]))),
            rejected(Error::BadSignature),
            "{name}"
        );
    }
}

#[test]
fn wrong_length_signature_is_malformed_not_verified() {
    let b = baseline(N);
    for len in [0usize, 48, 95, 97] {
        let mut u = b.update(full(N));
        u.signature = vec![0x11; len];
        let t = run(&b.input_with(vec![u]));
        assert_eq!(only(&t), O::Malformed, "len {len}");
        assert_eq!(t.output.sync_rejected, 1);
    }
}

#[test]
fn one_flipped_signature_bit_rejected() {
    let b = baseline(N);
    let mut u = b.update(full(N));
    u.signature[95] ^= 1;
    assert_eq!(
        only(&run(&b.input_with(vec![u]))),
        rejected(Error::BadSignature)
    );
}

#[test]
fn committed_aggregate_inconsistent_with_keys_rejected() {
    // The state root commits to a committee whose aggregate_pubkey is not the sum of its keys.
    // Bootstrap (a pure Merkle check) accepts it; the aggregate trick must not.
    let mut cur = tk::committee(1, N);
    cur.aggregate = tk::committee(77, N).aggregate;
    let b = Baseline::new(MAINNET, cur, tk::committee(2, N));
    let t = run(&b.input_with(vec![b.update(full(N))]));
    assert!(t.output.bootstrap_ok);
    assert_eq!(only(&t), rejected(Error::BadSignature));
}

#[test]
fn corrupted_committee_pubkey_breaks_the_bootstrap_commitment() {
    let b = baseline(N);
    let mut input = b.input_with(vec![b.update(full(N))]);
    input.pubkeys[0] ^= 0xFF;
    let t = run(&input);
    assert!(!t.output.bootstrap_ok);
    assert_eq!(only(&t), O::SetupFailed(Error::InvalidBranch));
}

// ---- realistic committee size ------------------------------------------------------------------------

#[test]
fn realistic_512_committee_accepts_and_rejects() {
    if std::env::var_os("LE_SYNC_SKIP_SLOW").is_some() {
        return; // mutation runs skip this; the full `cargo test` run does not
    }
    let n = 512;
    let b = baseline(n);
    let t = run(&b.input_with(vec![b.update(full(n))]));
    assert_eq!(only(&t), O::Validated);

    let mut bad = b.update(full(n));
    bad.signature[95] ^= 1;
    assert_eq!(
        only(&run(&b.input_with(vec![bad]))),
        rejected(Error::BadSignature)
    );

    // scattered 2/3+ participation at full size
    let bits = tk::bits_from(n, &(0..n).filter(|i| i % 4 != 3).collect::<Vec<_>>());
    let t = run(&b.input_with(vec![b.update(bits)]));
    assert_eq!(only(&t), O::Validated);
}

// ---- Sprint stubs -----------------------------------------------------------------------------------

#[test]
#[ignore = "Sprint 4"]
fn stub_inclusion_against_non_finalised_header() {
    panic!("Scheduled for Sprint 4");
}

#[test]
#[ignore = "Sprint 4-5"]
fn stub_tampered_state_or_receipts_root() {
    panic!("Scheduled for Sprints 4-5");
}

#[test]
#[ignore = "Sprint 5"]
fn stub_predicate_over_uncovered_state() {
    panic!("Scheduled for Sprint 5");
}
