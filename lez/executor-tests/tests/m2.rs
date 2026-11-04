//! M2 executor tests: every instruction of `eth_attest` through LEZ's in-memory state machine,
//! with real signed updates. One test per named case of the milestone, then the protocol
//! (duplicate and out-of-order updates), the absence of any instruction that edits the
//! configuration, instance isolation, and the public statement.
//!
//! Committee of 32 (a real signing committee; mainnet size is the `gas` binary's job). Slots
//! are those of `world`: the clock reads slot 41 unless a test moves it.
//!
//! A refusal is checked by the program's own error code (`le-sync error <code>`), so a test
//! cannot pass for the wrong reason. Where the code is whatever the native verifier says
//! (a tampered proof), the native verifier is the oracle.
use std::sync::{Mutex, OnceLock};

use example_program_deployment_methods::ETH_ATTEST_ELF;
use le_sync_core::header_record::{find_record, RECORD_LEN};
use le_sync_core::instance::{Bootstrap, InstanceConfig};
use le_sync_core::store_codec::decode_store;
use le_sync_core::Bytes32;
use le_sync_executor_tests::harness::*;
use le_sync_executor_tests::world::*;
use le_sync_wire::statement_path::{verify_attest, AccountClaim, AttestClaim, StorageClaim, Verified};
use le_sync_wire::{PredicateOp, PredicateTarget, PredicateWire};
use nssa::{AccountId, CLOCK_01_PROGRAM_ACCOUNT_ID, CLOCK_10_PROGRAM_ACCOUNT_ID};

const N: usize = 32;
const RECORD_SLOTS: usize = 16;
const NO_PROGRAM: [u32; 8] = [0; 8];

// ---- setup --------------------------------------------------------------------------------

struct Inst {
    w: World,
    cfg: InstanceConfig,
    ids: Ids,
}

fn new_chain() -> Chain {
    Chain::new(ETH_ATTEST_ELF, clock_ms(41), false)
}

/// The instance of world `world_seed` labelled `chain_id`, on `chain`'s program.
fn inst(chain: &Chain, world_seed: u32, chain_id: u64) -> Inst {
    let w = World::new(N, world_seed);
    let cfg = w.config(chain_id);
    let ids = Ids::new(&chain.program_id(), cfg.id());
    Inst { w, cfg, ids }
}

fn init(chain: &mut Chain, i: &Inst) {
    chain
        .init(&i.ids, &i.cfg, &i.w.bootstrap())
        .expect_ok("init_instance");
}

/// A chain with instance 1 initialised (built once, cloned per test).
fn fresh() -> Chain {
    static C: OnceLock<Mutex<Chain>> = OnceLock::new();
    C.get_or_init(|| {
        let mut c = new_chain();
        let i = inst(&c, 1, 1);
        init(&mut c, &i);
        Mutex::new(c)
    })
    .lock()
    .unwrap()
    .clone()
}

#[derive(Clone)]
struct Synced {
    chain: Chain,
    job: Job,
}

/// A chain with instance 1 after the default update (finalized slot 24).
fn synced() -> Synced {
    static C: OnceLock<Mutex<Synced>> = OnceLock::new();
    C.get_or_init(|| {
        let mut chain = fresh();
        let i = inst(&chain, 1, 1);
        let u = i.w.update(&Spec::new(N));
        let job = chain.job_for(&i.ids, &i.cfg, &u);
        if let Err((step, out)) = chain.update(&i.ids, &i.cfg, &u) {
            panic!("the default update was refused at {step}: {:?}", out.result);
        }
        Mutex::new(Synced { chain, job })
    })
    .lock()
    .unwrap()
    .clone()
}

fn snap(c: &Chain, ids: &Ids) -> Vec<Vec<u8>> {
    [ids.instance, ids.store, ids.records]
        .iter()
        .map(|a| c.data(*a))
        .collect()
}

fn be32(v: u128) -> Bytes32 {
    let mut o = [0u8; 32];
    o[16..].copy_from_slice(&v.to_be_bytes());
    o
}

/// The statement ID the native verifier gives a claim under a record.
fn sid(i: &Inst, u: &Update, claim: &AttestClaim) -> Bytes32 {
    statement_id_of(&i.cfg, &u.record, claim)
}

fn expect_account_already_initialized(out: &Outcome, what: &str) {
    out.expect_refused(what);
    let error = out.result.as_ref().expect_err("transaction was refused");
    assert!(
        error.contains("AccountAlreadyInitialized"),
        "{what}: expected the account init constraint to reject the transaction, got: {error}"
    );
}

// ---- init_instance ------------------------------------------------------------------------

#[test]
fn init_instance_claims_three_accounts_and_writes_the_configuration_once() {
    let mut c = new_chain();
    let i = inst(&c, 1, 1);
    init(&mut c, &i);
    assert_eq!(c.data(i.ids.instance), i.cfg.encode().to_vec());
    let store = c.data(i.ids.store);
    assert_eq!(store.len(), 403);
    assert_eq!(store[0], 2, "store_codec v2: the committee is a root");
    assert_eq!(c.data(i.ids.records), vec![0u8; RECORD_SLOTS * RECORD_LEN]);
    for a in [i.ids.instance, i.ids.store, i.ids.records] {
        assert_eq!(c.owner(a), c.program_id());
    }
    let before = snap(&c, &i.ids);
    c.init(&i.ids, &i.cfg, &i.w.bootstrap())
        .expect_refused("a second init_instance");
    assert_eq!(snap(&c, &i.ids), before);
}

#[test]
fn init_instance_refuses_a_bad_bootstrap_and_changes_nothing() {
    let c0 = new_chain();
    let i = inst(&c0, 1, 1);
    let unowned = |c: &Chain| {
        [i.ids.instance, i.ids.store, i.ids.records]
            .iter()
            .all(|a| c.owner(*a) == NO_PROGRAM && c.data(*a).is_empty())
    };

    // a checkpoint header that is not the configured one
    let mut c = c0.clone();
    let mut boot = i.w.bootstrap();
    boot.header.proposer_index += 1;
    c.init(&i.ids, &i.cfg, &boot).expect_code(200, "wrong checkpoint");
    assert!(unowned(&c));

    // a branch that does not prove the committee
    let mut c = c0.clone();
    let mut branch = i.w.bootstrap().branch.to_vec();
    branch[0][0] ^= 1;
    let boot = Bootstrap {
        branch: &branch,
        ..i.w.bootstrap()
    };
    c.init(&i.ids, &i.cfg, &boot).expect_code(201, "bad branch");
    assert!(unowned(&c));

    // the instance ID is not the digest of the configuration
    let mut c = c0.clone();
    let other = i.w.config(2);
    c.init(&i.ids, &other, &i.w.bootstrap())
        .expect_code(318, "instance id of another configuration");
    assert!(unowned(&c));
}

// ---- time comes from the runtime clock -----------------------------------------------------

#[test]
fn the_slot_is_read_from_the_clock_account_and_nothing_else() {
    // the account in the clock's place must be the 1-block clock
    let c0 = new_chain();
    let i = inst(&c0, 1, 1);
    let mut c = c0.clone();
    c.init_with_clock(&i.ids, &i.cfg, &i.w.bootstrap(), CLOCK_10_PROGRAM_ACCOUNT_ID)
        .expect_code(321, "the 10-block clock");
    let mut c = c0.clone();
    c.init_with_clock(&i.ids, &i.cfg, &i.w.bootstrap(), pda(&c0.program_id(), &[4; 32]))
        .expect_code(321, "an account that is not a clock");

    // a clock far past the checkpoint makes the checkpoint stale: there is no argument that
    // could say otherwise
    let mut c = c0.clone();
    c.set_clock(clock_ms(1_000_000));
    c.init(&i.ids, &i.cfg, &i.w.bootstrap())
        .expect_code(500, "a stale checkpoint under the clock");

    // an update signed at slot 41 is in the future of a clock that reads slot 30
    let mut c = fresh();
    c.set_clock(clock_ms(30));
    let u = i.w.update(&Spec::new(N));
    let job = c.job_for(&i.ids, &i.cfg, &u);
    c.begin(&i.ids, &job, &u).expect_code(302, "an update from the future");

    // and the same update at slot 41 is accepted
    let mut c = fresh();
    let job = c.job_for(&i.ids, &i.cfg, &u);
    c.begin(&i.ids, &job, &u).expect_ok("begin at slot 41");
}

// ---- a valid update ---------------------------------------------------------------------

#[test]
fn a_valid_update_moves_the_store_and_stores_the_record_of_the_finalized_header() {
    let s = synced();
    let i = inst(&s.chain, 1, 1);
    let u = i.w.update(&Spec::new(N));
    let store = decode_store(&s.chain.data(i.ids.store)).expect("a store");
    assert_eq!(store.finalized_header.slot, 24);
    let rec = find_record(&s.chain.data(i.ids.records), &u.finalized_root).expect("a record");
    assert_eq!(rec, u.record);
    assert_eq!(s.chain.data(i.ids.instance), i.cfg.encode().to_vec());
    assert!(s.chain.data(s.job.account).is_empty(), "finish empties the job");
    assert_eq!(s.chain.owner(s.job.account), s.chain.program_id());
}

// ---- the named cases of the milestone ----------------------------------------------------

#[test]
fn a_fabricated_chain_with_a_self_consistent_header_and_proof_is_refused() {
    let mut c = fresh();
    let i = inst(&c, 1, 1);
    // the attacker's own chain: its own committee, header, state, finality branch, signature
    let fake = World::new(N, 5);
    let fu = fake.update(&Spec::new(N));
    let before = snap(&c, &i.ids);
    match c.update(&i.ids, &i.cfg, &fu) {
        Ok(_) => panic!("a fabricated chain moved the store"),
        Err((step, out)) => {
            assert!(
                step == "miller_update" || step == "finish_update",
                "the non-BLS rules all hold on a self-consistent update; refused at {step}"
            );
            out.expect_code(400, "the committee's signature does not verify");
        }
    }
    assert_eq!(snap(&c, &i.ids), before, "store and records unchanged");

    // its header does not exist for an attestation
    let claim = fake.exec.account(ADDR);
    c.attest(&i.ids, false, fu.finalized_root, [9; 32], &claim)
        .expect_code(316, "a header the instance never stored");

    // and the abandoned job of the attacker blocks nobody: the honest update goes through
    let honest = i.w.update(&Spec::new(N));
    if let Err((step, out)) = c.update(&i.ids, &i.cfg, &honest) {
        panic!("the honest update was refused at {step}: {:?}", out.result);
    }
    let store = decode_store(&c.data(i.ids.store)).unwrap();
    assert_eq!(store.finalized_header.slot, 24);
}

#[test]
fn a_handoff_from_a_committee_the_instance_does_not_know_is_its_own_error() {
    let mut c = fresh();
    c.set_clock(clock_ms(71));
    let i = inst(&c, 1, 1);
    // signed in period 1 by period 1's committee, which the store has never been given
    let u = i.w.update(&Spec {
        finalized: 56,
        attested: 69,
        signature: 70,
        salt: 4,
        present: N,
        signer: Signer::Next,
        carry_next: false,
    });
    let before = snap(&c, &i.ids);
    let job = c.job_for(&i.ids, &i.cfg, &u);
    c.begin(&i.ids, &job, &u).expect_code(317, "handoff from an unknown committee");
    assert_eq!(snap(&c, &i.ids), before);
}

#[test]
fn a_signature_below_the_threshold_is_refused_before_any_bls_work() {
    let mut c = fresh();
    let i = inst(&c, 1, 1);
    let below = i.w.update(&Spec {
        present: min_participants(N) - 1,
        ..Spec::new(N)
    });
    let job = c.job_for(&i.ids, &i.cfg, &below);
    c.begin(&i.ids, &job, &below).expect_code(501, "21 of 32 sign");

    // one more signer and the same update is begun
    let at = i.w.update(&Spec {
        present: min_participants(N),
        ..Spec::new(N)
    });
    let job = c.job_for(&i.ids, &i.cfg, &at);
    c.begin(&i.ids, &job, &at).expect_ok("22 of 32 sign");
}

#[test]
fn a_valid_proof_against_a_header_that_is_not_finalized_is_refused() {
    let mut s = synced();
    let i = inst(&s.chain, 1, 1);
    let u = i.w.update(&Spec::new(N));
    let claim = i.w.exec.account(ADDR);
    let id = sid(&i, &u, &claim);
    // the attested header signed the update but is not finalized: it has no record
    s.chain
        .attest(&i.ids, false, u.attested_root, id, &claim)
        .expect_code(316, "the attested header");
    // the finalized one has
    s.chain
        .attest(&i.ids, false, u.finalized_root, id, &claim)
        .expect_ok("the finalized header");
}

#[test]
fn a_tampered_execution_header_is_refused_and_the_staged_update_survives_it() {
    let mut c = fresh();
    let i = inst(&c, 1, 1);
    let u = i.w.update(&Spec::new(N));
    let job = c.job_for(&i.ids, &i.cfg, &u);
    c.begin(&i.ids, &job, &u).expect_ok("begin");
    c.miller(&job).expect_ok("miller");
    let before = snap(&c, &i.ids);

    // a state root, then a receipts root, that the finalized header does not commit to
    let mut bad = i.w.update(&Spec::new(N));
    bad.exec.state_root[0] ^= 1;
    c.finish(&i.ids, &job, &bad).expect_code(201, "a tampered state root");
    let mut bad = i.w.update(&Spec::new(N));
    bad.exec.receipts_root[0] ^= 1;
    c.finish(&i.ids, &job, &bad).expect_code(201, "a tampered receipts root");
    assert_eq!(snap(&c, &i.ids), before, "nothing was stored");

    // the job is intact: the honest finish still goes through
    c.finish(&i.ids, &job, &u).expect_ok("the honest finish");
    assert!(find_record(&c.data(i.ids.records), &u.finalized_root).is_ok());
}

#[test]
fn a_tampered_proof_is_refused_with_the_native_verifiers_code() {
    let mut s = synced();
    let i = inst(&s.chain, 1, 1);
    let u = i.w.update(&Spec::new(N));
    let good = [
        i.w.exec.account(ADDR),
        i.w.exec.storage(SLOT_A),
        i.w.exec.log(LOG_TX, 0),
    ];
    for (k, claim) in good.iter().enumerate() {
        let mut bad = claim.clone();
        match &mut bad {
            AttestClaim::Account(c) => c.account_proof[0][3] ^= 1,
            AttestClaim::Storage(c) => c.storage_proof[0][3] ^= 1,
            AttestClaim::Log(c) => c.receipt_proof[0][3] ^= 1,
        }
        let native = verify_attest(&i.cfg, &u.record, &bad)
            .expect_err("a tampered proof does not verify natively")
            .code();
        let id = sid(&i, &u, claim); // the statement ID of the honest claim: the proof check comes first
        let out = s.chain.attest(&i.ids, k == 2, u.finalized_root, id, &bad);
        out.expect_code(native, &format!("claim {k}: tampered proof"));
    }
}

#[test]
fn a_proof_replayed_on_another_chain_id_is_not_the_same_statement() {
    let mut s = synced();
    let a = inst(&s.chain, 1, 1);
    // the same beacon chain, labelled as chain 2, synced to the same finalized header
    let b = inst(&s.chain, 1, 2);
    init(&mut s.chain, &b);
    let u = b.w.update(&Spec::new(N));
    if let Err((step, out)) = s.chain.update(&b.ids, &b.cfg, &u) {
        panic!("instance 2 was refused at {step}: {:?}", out.result);
    }
    let claim = a.w.exec.account(ADDR);
    let id_a = sid(&a, &u, &claim);
    let id_b = sid(&b, &u, &claim);
    assert_ne!(id_a, id_b, "the chain ID is part of the statement ID");

    s.chain
        .attest(&a.ids, false, u.finalized_root, id_a, &claim)
        .expect_ok("attest on chain 1");
    // chain 1's statement ID does not name a statement of chain 2
    let statement = pda(&s.chain.program_id(), &id_a);
    let before = s.chain.data(statement);
    let replay = s
        .chain
        .attest(&b.ids, false, u.finalized_root, id_a, &claim);
    expect_account_already_initialized(&replay, "replay on chain 2");
    assert_eq!(s.chain.data(statement), before);

    s.chain
        .attest(&b.ids, false, u.finalized_root, id_b, &claim)
        .expect_ok("attest on chain 2");
    let sa = statement_of(&s.chain.data(pda(&s.chain.program_id(), &id_a))).unwrap();
    let sb = statement_of(&s.chain.data(pda(&s.chain.program_id(), &id_b))).unwrap();
    assert_eq!((sa.chain_id, sb.chain_id), (1, 2));
}

#[test]
fn a_predicate_over_state_the_proof_does_not_cover_is_refused() {
    let mut s = synced();
    let i = inst(&s.chain, 1, 1);
    let u = i.w.update(&Spec::new(N));
    let p = |target| PredicateWire {
        target,
        op: PredicateOp::Eq,
        operand: be32(0x1234),
    };
    // an account claim covers the balance, not a storage slot
    let claim = AttestClaim::Account(AccountClaim {
        address: ADDR,
        account_proof: i.w.exec.state.prove(&le_sync_core::state::account_key(&ADDR)),
        predicate: Some(p(PredicateTarget::StorageValue)),
    });
    s.chain
        .attest(&i.ids, false, u.finalized_root, [2; 32], &claim)
        .expect_code(206, "a storage predicate on an account claim");

    // a storage claim covers the slot and the balance, not a topic
    let claim = AttestClaim::Storage(StorageClaim {
        address: ADDR,
        slot: SLOT_A,
        account_proof: i.w.exec.state.prove(&le_sync_core::state::account_key(&ADDR)),
        storage_proof: i.w.exec.storage.prove(&le_sync_core::state::storage_key(&SLOT_A)),
        predicate: Some(p(PredicateTarget::Topic(0))),
    });
    s.chain
        .attest(&i.ids, false, u.finalized_root, [3; 32], &claim)
        .expect_code(206, "a topic predicate on a storage claim");
}

// ---- duplicate and out-of-order updates ----------------------------------------------------

#[test]
fn a_duplicate_update_and_an_older_update_are_refused() {
    let mut s = synced();
    let i = inst(&s.chain, 1, 1);

    // the update that was applied, again
    let again = i.w.update(&Spec::new(N));
    let job = s.chain.job_for(&i.ids, &i.cfg, &again);
    let before = s.chain.data(job.account);
    let duplicate = s.chain.begin(&i.ids, &job, &again);
    expect_account_already_initialized(&duplicate, "the same update again");
    assert_eq!(s.chain.data(job.account), before);

    // an update that finalizes an older header than the store's (slot 24)
    let older = i.w.update(&Spec {
        finalized: 16,
        attested: 24,
        signature: 25,
        salt: 6,
        ..Spec::new(N)
    });
    let job = s.chain.job_for(&i.ids, &i.cfg, &older);
    s.chain.begin(&i.ids, &job, &older).expect_code(304, "an older update");
}

#[test]
fn the_three_steps_run_in_order_or_not_at_all() {
    let mut c = fresh();
    let i = inst(&c, 1, 1);
    let u = i.w.update(&Spec::new(N));
    let job = c.job_for(&i.ids, &i.cfg, &u);

    // Miller or Finish with no job
    c.miller(&job).expect_refused("miller before begin");
    c.finish(&i.ids, &job, &u).expect_refused("finish before begin");

    c.begin(&i.ids, &job, &u).expect_ok("begin");
    // the same update cannot be begun again: its job is already claimed
    c.begin(&i.ids, &job, &u).expect_refused("begin twice");
    // Finish before Miller
    c.finish(&i.ids, &job, &u).expect_code(308, "finish before miller");

    c.miller(&job).expect_ok("miller");
    c.miller(&job).expect_code(308, "miller twice");
    c.finish(&i.ids, &job, &u).expect_ok("finish");
    // the job is empty now: nothing left to continue
    c.finish(&i.ids, &job, &u).expect_refused("finish twice");
}

#[test]
fn an_update_begun_against_a_store_that_has_since_moved_cannot_finish() {
    let mut c = fresh();
    let i = inst(&c, 1, 1);
    let a = i.w.update(&Spec::new(N));
    let b = i.w.update(&Spec {
        finalized: 32,
        attested: 40,
        signature: 41,
        salt: 3,
        ..Spec::new(N)
    });
    let ja = c.job_for(&i.ids, &i.cfg, &a);
    let jb = c.job_for(&i.ids, &i.cfg, &b);
    assert_ne!(ja.account, jb.account, "one job account per update");
    c.begin(&i.ids, &ja, &a).expect_ok("begin a");
    c.miller(&ja).expect_ok("miller a");
    c.begin(&i.ids, &jb, &b).expect_ok("begin b, while a is staged");
    c.miller(&jb).expect_ok("miller b");
    c.finish(&i.ids, &jb, &b).expect_ok("finish b");
    // a was begun against the store before b
    let before = snap(&c, &i.ids);
    c.finish(&i.ids, &ja, &a).expect_code(310, "finish a after b");
    assert_eq!(snap(&c, &i.ids), before);
    let store = decode_store(&c.data(i.ids.store)).unwrap();
    assert_eq!(store.finalized_header.slot, 32);
}

// ---- no instruction edits the configuration ------------------------------------------------

#[test]
fn no_instruction_changes_the_instance_account() {
    let mut c = new_chain();
    let i = inst(&c, 1, 1);
    init(&mut c, &i);
    let account = |c: &Chain| c.state.get_account_by_id(i.ids.instance);
    let baseline = account(&c);

    let u = i.w.update(&Spec::new(N));
    let job = c.job_for(&i.ids, &i.cfg, &u);
    c.begin(&i.ids, &job, &u).expect_ok("begin");
    assert_eq!(account(&c), baseline, "begin_update");
    c.miller(&job).expect_ok("miller");
    assert_eq!(account(&c), baseline, "miller_update");
    c.finish(&i.ids, &job, &u).expect_ok("finish");
    assert_eq!(account(&c), baseline, "finish_update");

    let claim = i.w.exec.account(ADDR);
    c.attest(&i.ids, false, u.finalized_root, sid(&i, &u, &claim), &claim)
        .expect_ok("attest_state");
    assert_eq!(account(&c), baseline, "attest_state");
    let log = i.w.exec.log(LOG_TX, 0);
    c.attest(&i.ids, true, u.finalized_root, sid(&i, &u, &log), &log)
        .expect_ok("attest_log");
    assert_eq!(account(&c), baseline, "attest_log");

    // init_instance cannot rewrite it either, whatever it is given
    let other = i.w.config(2);
    let other_ids = Ids::new(&c.program_id(), other.id());
    c.init(&i.ids, &other, &i.w.bootstrap()).expect_refused("init with another configuration");
    c.init(&i.ids, &i.cfg, &i.w.bootstrap()).expect_refused("init again");
    assert_eq!(account(&c), baseline, "init_instance");
    assert_ne!(other_ids.instance, i.ids.instance);
    assert_eq!(baseline.data.clone().into_inner(), i.cfg.encode().to_vec());
}

// ---- instances are isolated ----------------------------------------------------------------

#[test]
fn instances_do_not_share_accounts_and_cannot_be_given_each_others() {
    let mut c = fresh();
    let a = inst(&c, 1, 1);
    let b = inst(&c, 1, 2);
    init(&mut c, &b);
    assert_ne!(a.ids.instance, b.ids.instance);
    assert_ne!(a.ids.store, b.ids.store);
    assert_ne!(a.ids.records, b.ids.records);
    let b_before = snap(&c, &b.ids);

    // sync A
    let u = a.w.update(&Spec::new(N));
    if let Err((step, out)) = c.update(&a.ids, &a.cfg, &u) {
        panic!("instance A was refused at {step}: {:?}", out.result);
    }
    assert_eq!(snap(&c, &b.ids), b_before, "B did not move");
    assert_ne!(c.data(a.ids.store), c.data(a.ids.records));

    // B's instruction with A's store in B's store position
    let job = c.job_for(&b.ids, &b.cfg, &u);
    let ix = Instruction::BeginUpdate {
        instance_id: b.ids.instance_id,
        store_seed: a.ids.store_seed,
        job_seed: job.seed,
        update: words(&(&u.rooted, &u.absent)),
    };
    c.run(&ix, &[b.ids.instance, a.ids.store, job.account, CLOCK_01_PROGRAM_ACCOUNT_ID])
        .expect_code(318, "A's store given to B");

    // B's attestation with A's records
    let claim = a.w.exec.account(ADDR);
    let id = sid(&a, &u, &claim);
    let ix = Instruction::AttestState {
        instance_id: b.ids.instance_id,
        records_seed: a.ids.records_seed,
        statement_seed: id,
        header_root: u.finalized_root,
        claim: words(&claim),
    };
    let statement = pda(&c.program_id(), &id);
    c.run(&ix, &[b.ids.instance, a.ids.records, statement])
        .expect_code(318, "A's records given to B");

    // A's header does not exist in B
    c.attest(&b.ids, false, u.finalized_root, id, &claim)
        .expect_code(316, "A's header on B");
    assert_eq!(snap(&c, &b.ids), b_before);
}

// ---- the statements ------------------------------------------------------------------------

#[test]
fn account_storage_and_log_statements_carry_what_the_proofs_established() {
    let mut s = synced();
    let i = inst(&s.chain, 1, 1);
    let u = i.w.update(&Spec::new(N));
    let program = s.chain.program_id();

    let account = i.w.exec.account(ADDR);
    let id = sid(&i, &u, &account);
    s.chain
        .attest(&i.ids, false, u.finalized_root, id, &account)
        .expect_ok("attest_state, account");
    let st = statement_of(&s.chain.data(pda(&program, &id))).expect("a statement");
    assert_eq!(st.chain_id, 1);
    assert_eq!(st.header_root, u.finalized_root);
    assert_eq!(st.block_hash, u.record.block_hash);
    assert_eq!(st.statement_id, id);
    assert_eq!(
        st.verified,
        Verified::Account {
            address: ADDR,
            present: true,
            balance: be32(1_000_000)
        }
    );

    let storage = i.w.exec.storage(SLOT_A);
    let id = sid(&i, &u, &storage);
    s.chain
        .attest(&i.ids, false, u.finalized_root, id, &storage)
        .expect_ok("attest_state, storage");
    let st = statement_of(&s.chain.data(pda(&program, &id))).expect("a statement");
    match st.verified {
        Verified::Storage { value, .. } => assert_eq!(value, be32(0x1234)),
        other => panic!("not a storage statement: {other:?}"),
    }

    let log = i.w.exec.log(LOG_TX, 1);
    let id = sid(&i, &u, &log);
    s.chain
        .attest(&i.ids, true, u.finalized_root, id, &log)
        .expect_ok("attest_log");
    let st = statement_of(&s.chain.data(pda(&program, &id))).expect("a statement");
    match st.verified {
        Verified::Log { tx_index, log_index, address, .. } => {
            assert_eq!((tx_index, log_index, address), (LOG_TX, 1, LOG_ADDR));
        }
        other => panic!("not a log statement: {other:?}"),
    }

    // each instruction takes its own kind of claim
    s.chain
        .attest(&i.ids, false, u.finalized_root, [5; 32], &log)
        .expect_code(319, "a log claim to attest_state");
    s.chain
        .attest(&i.ids, true, u.finalized_root, [6; 32], &account)
        .expect_code(319, "an account claim to attest_log");
}

#[test]
fn the_public_statement_does_not_reveal_who_asked_for_it() {
    let mut s = synced();
    let i = inst(&s.chain, 1, 1);
    let u = i.w.update(&Spec::new(N));
    let claim = i.w.exec.account(ADDR);
    let id = sid(&i, &u, &claim);
    let native = verify_attest(&i.cfg, &u.record, &claim).expect("verifies natively");

    s.chain
        .attest(&i.ids, false, u.finalized_root, id, &claim)
        .expect_ok("attest_state");
    let account: AccountId = pda(&s.chain.program_id(), &id);
    let bytes = s.chain.data(account);
    // exactly the verified statement: no field for a caller, a consumer or a payer
    assert_eq!(bytes.len(), words(&native).len() * 4);
    assert_eq!(statement_of(&bytes), Some(native));
    // the address is a function of the statement alone, and there is no signer to name
    assert_eq!(account, pda(&s.chain.program_id(), &native.statement_id));

    // a second consumer asking for the same fact gets the same statement, not another one
    let before = s.chain.data(account);
    s.chain
        .attest(&i.ids, false, u.finalized_root, id, &claim)
        .expect_refused("the same statement again");
    assert_eq!(s.chain.data(account), before);
}

// ---- gas ----------------------------------------------------------------------------------

/// Every instruction fits the per-transaction cap at mainnet committee size. Slow (the
/// executor runs each transaction twice); the numbers are printed by `cargo run --release
/// --bin gas`.
#[test]
#[ignore]
fn every_instruction_fits_the_cycle_cap_at_mainnet_size() {
    let rows = le_sync_executor_tests::gas::table(512);
    for r in &rows {
        let cycles = r.cycles.unwrap_or_else(|| panic!("{} was not measured", r.name));
        assert!(cycles < CYCLE_CAP, "{}: {cycles} cycles", r.name);
    }
}
