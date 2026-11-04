//! `eth_attest`: the LEZ program of the Ethereum state attestation (RFP-021, Sprint 6, M2).
//!
//! One instance is one light client of one chain. Its accounts are program-owned PDAs:
//!
//! | account     | content                                   | written by                       |
//! |-------------|-------------------------------------------|----------------------------------|
//! | `instance`  | `InstanceConfig`, 221 bytes, written once | `init_instance` only             |
//! | `store`     | the tracked store, `store_codec` v2, 403  | `init_instance`, `finish_update` |
//! | `job`       | one staged update, 641 bytes, then empty  | `begin` (claims), `miller`, `finish` |
//! | `records`   | `RECORD_SLOTS` header records, 145 each   | `init_instance`, `finish_update` |
//! | `statement` | one verified statement (risc0 serde)      | `attest_state`, `attest_log`     |
//!
//! No instruction edits `instance`, and no account holds a program ID.
//!
//! Jobs. There is one `job` account per update, at the address derived from the instance and
//! the update's digest (`job_seed_of`), claimed by `begin_update`. So nobody can occupy a shared
//! slot: an update that is begun and never finished leaves one account of its own, and the
//! next update begins in another. `finish_update` empties its job.
//!
//! Time. `current_slot` is not an argument: `init_instance`, `begin_update` and `finish_update`
//! take the 1-block LEZ clock account as an input and read the slot from it (`now_slot`), with
//! the chain's `genesis_time` and `seconds_per_slot` from the instance configuration.
//!
//! Account addresses. Each PDA is derived from ONE seed that is an instruction argument
//! (`pda = arg(..)`): `instance_id` for the instance, and for the others
//! `SHA256("le-sync/seed/v1/" || kind || instance_id)` (`seed`), or the statement ID for a
//! statement. The program recomputes every seed it uses (`check_seed`) and checks
//! `instance_id` against the configuration (`load`), so an account of another instance cannot
//! be passed in place of this instance's. Nothing here depends on the caller: there is no
//! signer, and the public statement carries nothing about who asked for it.
//!
//! Errors. Every failure is a `le_sync_core::Error`, reported as `le-sync error <code>: <text>`
//! (the stable code first). SPEL's own checks (`init` on a written account, a wrong PDA)
//! report their own errors before the handler runs.
//!
//! KEEP IN STEP with `lez/src/lib.rs` (the host copy used for IDL generation): same
//! instruction names, same account attributes, same argument lists. `scripts/check_lez_in_step.sh`
//! compares them.
#![no_main]

use le_sync_core::header_record::{insert_record, HeaderRecord, RECORD_LEN};
use le_sync_core::instance::{ensure_blank, init_store_bytes, Bootstrap, InstanceConfig};
use le_sync_core::store_codec::decode_store;
use le_sync_core::update_job::{miller_update as miller_step, UpdateJob, JOB_LEN};
use le_sync_core::{BeaconBlockHeader, Bytes32, Error};
use le_sync_wire::bls::Impl;
use le_sync_wire::rooted::{run_rooted, AbsentWire, RootedInput, RootedUpdate};
use le_sync_wire::stage::{StageConfig, StageOutput};
use le_sync_wire::statement_path::{attest_header, AttestClaim};
use le_sync_wire::ExecWire;
use clock_core::{ClockAccountData, CLOCK_01_PROGRAM_ACCOUNT_ID};
use nssa_core::account::Data;
use sha2::{Digest, Sha256};
use spel_framework::prelude::*;

#[cfg(not(test))]
risc0_zkvm::guest::entry!(main);

/// Header records an instance keeps. A full log replaces the oldest, so an attestation can
/// only be made against one of the latest `RECORD_SLOTS` finalized headers. Every
/// `finish_update` reads and writes the whole account, so this is also a cycle cost.
const RECORD_SLOTS: usize = 16;

fn fail(e: Error) -> SpelError {
    SpelError::SerializationError {
        message: format!("le-sync error {}: {}", e.code(), e.message()),
    }
}

fn data_of(acc: &AccountWithMetadata) -> &[u8] {
    &acc.account.data[..]
}

fn put(acc: &mut AccountWithMetadata, bytes: Vec<u8>) -> Result<(), SpelError> {
    acc.account.data = Data::try_from(bytes).map_err(|_| SpelError::SerializationError {
        message: "account data exceeds the 100 KiB limit".to_string(),
    })?;
    Ok(())
}

/// `SHA256("le-sync/seed/v1/" || kind || instance_id)`: the seed of the `kind` account.
fn seed(kind: &str, instance_id: &Bytes32) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(b"le-sync/seed/v1/");
    h.update(kind.as_bytes());
    h.update(instance_id);
    h.finalize().into()
}

/// The seed of the job of the update whose digest is `update_digest`:
/// `SHA256("le-sync/seed/v1/job" || instance_id || update_digest)`.
fn job_seed_of(instance_id: &Bytes32, update_digest: &[u8]) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(b"le-sync/seed/v1/job");
    h.update(instance_id);
    h.update(update_digest);
    h.finalize().into()
}

fn check_seed(kind: &str, instance_id: &Bytes32, given: &Bytes32) -> Result<(), SpelError> {
    if seed(kind, instance_id) == *given {
        Ok(())
    } else {
        Err(fail(Error::InstanceIdMismatch))
    }
}

/// The configuration in the `instance` account, which must be the one `instance_id` names.
fn load(instance: &AccountWithMetadata, instance_id: &Bytes32) -> Result<InstanceConfig, SpelError> {
    let cfg = InstanceConfig::decode(data_of(instance)).map_err(fail)?;
    if cfg.id() != *instance_id {
        return Err(fail(Error::InstanceIdMismatch));
    }
    Ok(cfg)
}

/// The beacon slot now, from the runtime clock. `clock` must be the account of the 1-block LEZ
/// clock (`CLOCK_01_PROGRAM_ACCOUNT_ID`): only the clock program writes it, and the sequencer
/// updates it every block, so no caller can choose the time. Its timestamp is milliseconds.
fn now_slot(cfg: &InstanceConfig, clock: &AccountWithMetadata) -> Result<u64, SpelError> {
    if clock.account_id != CLOCK_01_PROGRAM_ACCOUNT_ID || data_of(clock).len() != 16 {
        return Err(fail(Error::ClockAccount));
    }
    let record = ClockAccountData::from_bytes(data_of(clock));
    Ok(cfg.slot_at(record.timestamp))
}

fn stage_config(cfg: &InstanceConfig, current_slot: u64) -> StageConfig {
    StageConfig {
        slots_per_epoch: cfg.slots_per_epoch,
        electra_fork_epoch: cfg.electra_fork_epoch,
        gloas_fork_epoch: cfg.gloas_fork_epoch,
        epochs_per_period: cfg.epochs_per_period,
        genesis_validators_root: cfg.genesis_validators_root,
        forks: cfg.forks.entries().to_vec(),
        current_slot,
    }
}

/// An argument sent as the words of the RISC Zero serde encoding of `T`.
fn from_words<T: serde::de::DeserializeOwned>(words: &[u32]) -> Result<T, SpelError> {
    risc0_zkvm::serde::from_slice(words).map_err(|_| fail(Error::InstructionEncoding))
}

/// The statement as the bytes of the account: the RISC Zero serde words of `Attested`, little
/// endian.
fn statement_bytes<T: serde::Serialize>(statement: &T) -> Result<Vec<u8>, SpelError> {
    let words = risc0_zkvm::serde::to_vec(statement).map_err(|_| fail(Error::InstructionEncoding))?;
    Ok(words.iter().flat_map(|w| w.to_le_bytes()).collect())
}

/// Verify `claim` against the record of `header_root`, and require `statement_seed` to be the
/// statement ID of what was verified. Returns the statement's bytes.
#[allow(clippy::too_many_arguments)]
fn attest(
    instance: &AccountWithMetadata,
    records: &AccountWithMetadata,
    instance_id: &Bytes32,
    records_seed: &Bytes32,
    statement_seed: &Bytes32,
    header_root: &Bytes32,
    claim: &[u32],
    log: bool,
) -> Result<Vec<u8>, SpelError> {
    let cfg = load(instance, instance_id)?;
    check_seed("records", instance_id, records_seed)?;
    let claim: AttestClaim = from_words(claim)?;
    if matches!(claim, AttestClaim::Log(_)) != log {
        return Err(fail(Error::InstructionEncoding));
    }
    let attested = attest_header(&cfg, data_of(records), header_root, &claim).map_err(fail)?;
    if attested.statement_id != *statement_seed {
        return Err(fail(Error::StatementIdMismatch));
    }
    statement_bytes(&attested)
}

#[lez_program]
mod eth_attest {
    #[allow(unused_imports)]
    use super::*;

    /// Writes the configuration once, and starts the store from the trusted checkpoint. The
    /// three accounts are claimed here (the jobs are claimed by `begin_update`). `config` is the canonical
    /// `InstanceConfig`; `instance_id` must be its ID; the bootstrap is the checkpoint header
    /// (`slot`, `proposer_index`, `parent_root`, `state_root`, `body_root`), the current
    /// committee as `keys_root` + `aggregate` (48 bytes) and the `branch` that proves it.
    #[instruction]
    pub fn init_instance(
        #[account(init, pda = arg("instance_id"))] mut instance: AccountWithMetadata,
        #[account(init, pda = arg("store_seed"))] mut store: AccountWithMetadata,
        #[account(init, pda = arg("records_seed"))] mut records: AccountWithMetadata,
        clock: AccountWithMetadata,
        instance_id: [u8; 32],
        store_seed: [u8; 32],
        records_seed: [u8; 32],
        config: Vec<u8>,
        slot: u64,
        proposer_index: u64,
        parent_root: [u8; 32],
        state_root: [u8; 32],
        body_root: [u8; 32],
        keys_root: [u8; 32],
        aggregate: Vec<u8>,
        branch: Vec<[u8; 32]>,
    ) -> SpelResult {
        for acc in [&instance, &store, &records] {
            ensure_blank(data_of(acc)).map_err(fail)?;
        }
        let cfg = InstanceConfig::decode(&config).map_err(fail)?;
        if cfg.id() != instance_id {
            return Err(fail(Error::InstanceIdMismatch));
        }
        check_seed("store", &instance_id, &store_seed)?;
        check_seed("records", &instance_id, &records_seed)?;
        let aggregate: [u8; 48] = aggregate
            .try_into()
            .map_err(|_| fail(Error::BadSyncCommitteeSize))?;
        let boot = Bootstrap {
            header: BeaconBlockHeader {
                slot,
                proposer_index,
                parent_root,
                state_root,
                body_root,
            },
            keys_root,
            aggregate,
            branch: &branch,
        };
        let current_slot = now_slot(&cfg, &clock)?;
        let store_bytes = init_store_bytes(&cfg, &boot, current_slot).map_err(fail)?;
        put(&mut instance, cfg.encode().to_vec())?;
        put(&mut store, store_bytes.to_vec())?;
        put(&mut records, vec![0u8; RECORD_SLOTS * RECORD_LEN])?;
        Ok(SpelOutput::execute(
            vec![instance, store, records, clock],
            vec![],
        ))
    }

    /// Step 1 of an update. `update` is the RISC Zero serde words of `(RootedUpdate,
    /// AbsentWire)`. Claims the job account of this update: `job_seed` must be
    /// `job_seed_of(instance_id, update digest)`.
    #[instruction]
    pub fn begin_update(
        #[account(pda = arg("instance_id"))] instance: AccountWithMetadata,
        #[account(pda = arg("store_seed"))] store: AccountWithMetadata,
        #[account(init, pda = arg("job_seed"))] mut job: AccountWithMetadata,
        clock: AccountWithMetadata,
        instance_id: [u8; 32],
        store_seed: [u8; 32],
        job_seed: [u8; 32],
        update: Vec<u32>,
    ) -> SpelResult {
        let job_seed_arg = job_seed;
        let cfg = load(&instance, &instance_id)?;
        let current_slot = now_slot(&cfg, &clock)?;
        check_seed("store", &instance_id, &store_seed)?;
        let (update, absent): (RootedUpdate, AbsentWire) = from_words(&update)?;
        let input = RootedInput::Begin {
            store: data_of(&store).to_vec(),
            update,
            absent,
        };
        let StageOutput::Job(next) =
            run_rooted(&stage_config(&cfg, current_slot), &input, &Impl).map_err(fail)?
        else {
            return Err(fail(Error::WrongStep));
        };
        // the update's digest is in the job; the address of the job is derived from it
        if next.len() != JOB_LEN || job_seed_of(&instance_id, &next[33..65]) != job_seed_arg {
            return Err(fail(Error::InstanceIdMismatch));
        }
        put(&mut job, next)?;
        Ok(SpelOutput::execute(vec![instance, store, job, clock], vec![]))
    }

    /// Step 2. Reads and writes only the job, which binds everything else it needs.
    #[instruction]
    pub fn miller_update(
        #[account(mut, pda = arg("job_seed"))] mut job: AccountWithMetadata,
        job_seed: [u8; 32],
    ) -> SpelResult {
        let _ = job_seed;
        let current = UpdateJob::from_bytes(data_of(&job)).map_err(fail)?;
        let next = miller_step(&current, &Impl).map_err(fail)?;
        put(&mut job, next.to_bytes().to_vec())?;
        Ok(SpelOutput::execute(vec![job], vec![]))
    }

    /// Step 3. Moves the store, clears the job, and, when the finalized header moved, stores its
    /// record: `exec` is the RISC Zero serde words of the `ExecWire` of that header and
    /// `exec_branch` its branch (empty when the finalized header did not move).
    #[instruction]
    pub fn finish_update(
        #[account(pda = arg("instance_id"))] instance: AccountWithMetadata,
        #[account(mut, pda = arg("store_seed"))] mut store: AccountWithMetadata,
        #[account(mut, pda = arg("job_seed"))] mut job: AccountWithMetadata,
        #[account(mut, pda = arg("records_seed"))] mut records: AccountWithMetadata,
        clock: AccountWithMetadata,
        instance_id: [u8; 32],
        store_seed: [u8; 32],
        job_seed: [u8; 32],
        records_seed: [u8; 32],
        update: Vec<u32>,
        exec: Vec<u32>,
        exec_branch: Vec<[u8; 32]>,
    ) -> SpelResult {
        let job_seed_arg = job_seed;
        let cfg = load(&instance, &instance_id)?;
        let current_slot = now_slot(&cfg, &clock)?;
        check_seed("store", &instance_id, &store_seed)?;
        check_seed("records", &instance_id, &records_seed)?;
        let staged = UpdateJob::from_bytes(data_of(&job)).map_err(fail)?;
        if job_seed_of(&instance_id, &staged.update_digest) != job_seed_arg {
            return Err(fail(Error::InstanceIdMismatch));
        }
        let old = Box::new(decode_store(data_of(&store)).map_err(fail)?);
        let update: RootedUpdate = from_words(&update)?;
        let input = RootedInput::Finish {
            job: data_of(&job).to_vec(),
            store: data_of(&store).to_vec(),
            update,
        };
        let StageOutput::Store(new_bytes) =
            run_rooted(&stage_config(&cfg, current_slot), &input, &Impl).map_err(fail)?
        else {
            return Err(fail(Error::WrongStep));
        };
        let new = Box::new(decode_store(&new_bytes).map_err(fail)?);
        if new.finalized_header != old.finalized_header {
            let exec: ExecWire = from_words(&exec)?;
            let exec = exec
                .to_header()
                .ok_or_else(|| fail(Error::InvalidBranch))?;
            let record =
                HeaderRecord::from_finalized(&cfg, &new, &exec, &exec_branch).map_err(fail)?;
            let mut log = data_of(&records).to_vec();
            insert_record(&mut log, &record).map_err(fail)?;
            put(&mut records, log)?;
        }
        put(&mut store, new_bytes)?;
        put(&mut job, Vec::new())?;
        Ok(SpelOutput::execute(
            vec![instance, store, job, records, clock],
            vec![],
        ))
    }

    /// Attests an account or a storage slot under the record of `header_root`. `claim` is the
    /// RISC Zero serde words of an `AttestClaim::Account` or `::Storage`; `statement_seed` must
    /// be the statement ID of the verified claim, and the statement account is claimed here.
    #[instruction]
    pub fn attest_state(
        #[account(pda = arg("instance_id"))] instance: AccountWithMetadata,
        #[account(pda = arg("records_seed"))] records: AccountWithMetadata,
        #[account(init, pda = arg("statement_seed"))] mut statement: AccountWithMetadata,
        instance_id: [u8; 32],
        records_seed: [u8; 32],
        statement_seed: [u8; 32],
        header_root: [u8; 32],
        claim: Vec<u32>,
    ) -> SpelResult {
        let bytes = attest(
            &instance,
            &records,
            &instance_id,
            &records_seed,
            &statement_seed,
            &header_root,
            &claim,
            false,
        )?;
        put(&mut statement, bytes)?;
        Ok(SpelOutput::execute(
            vec![instance, records, statement],
            vec![],
        ))
    }

    /// Attests a log. As `attest_state`, with an `AttestClaim::Log`.
    #[instruction]
    pub fn attest_log(
        #[account(pda = arg("instance_id"))] instance: AccountWithMetadata,
        #[account(pda = arg("records_seed"))] records: AccountWithMetadata,
        #[account(init, pda = arg("statement_seed"))] mut statement: AccountWithMetadata,
        instance_id: [u8; 32],
        records_seed: [u8; 32],
        statement_seed: [u8; 32],
        header_root: [u8; 32],
        claim: Vec<u32>,
    ) -> SpelResult {
        let bytes = attest(
            &instance,
            &records,
            &instance_id,
            &records_seed,
            &statement_seed,
            &header_root,
            &claim,
            true,
        )?;
        put(&mut statement, bytes)?;
        Ok(SpelOutput::execute(
            vec![instance, records, statement],
            vec![],
        ))
    }
}
