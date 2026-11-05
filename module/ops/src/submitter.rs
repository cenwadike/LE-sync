//! fetch, defer, re-check, then the three stages.
//!
//! State lives on the chain, not here: where an update stands is read from the job account
//! (`STEP_PREPARED`, `STEP_MILLER`), so a restarted submitter resumes from the chain and a
//! second submitter finds the work already done. The only local files are a cache of committee
//! keys (each checked against the root the store holds) and the last material, for tests.
use crate::config::Config;
use crate::convert::{self, Candidate};
use crate::lez::*;
use crate::plan;
use crate::source::{retry, EthSource};
use le_sync_core::header_record::{HeaderRecord, RECORD_LEN};
use le_sync_core::instance::{is_blank, InstanceConfig};
use le_sync_core::multiproof::{absent_matches_bits, verify_multiproof};
use le_sync_core::store_codec::decode_store;
use le_sync_core::sync::LightClientStore;
use le_sync_core::update_job::{UpdateJob, JOB_LEN, STEP_MILLER, STEP_PREPARED};
use le_sync_core::{pubkey_root, pubkeys_root, Bytes32};
use le_sync_wire::bls::{is_canonical_uncompressed_g1, uncompress_g1, Impl};
use le_sync_wire::rooted::{absent_wire, run_rooted, to_rooted_update, RootedInput};
use le_sync_wire::stage::{StageConfig, StageOutput};
use le_sync_wire::statement_path::{
    verify_attest, AccountClaim, AttestClaim, LogClaim, StorageClaim,
};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

type Res<T> = Result<T, String>;

const WAIT_SECS: u64 = 90;

/// Test switches of `eth_attest_ops`; all off in normal use.
#[derive(Clone, Debug, Default)]
pub struct Opts {
    /// Flip a byte of the aggregate signature before submitting.
    pub tamper_signature: bool,
    /// Submit even if the native check refuses (a test of the program's own refusal).
    pub force: bool,
    /// Send only `miller_update` for the update (without `begin_update`).
    pub only_miller: bool,
    /// Stop after `begin_update` is accepted.
    pub stop_after_begin: bool,
}

#[derive(Debug, Clone)]
pub struct Applied {
    pub finalized_slot: u64,
    /// `(instruction, transaction hash)` of each transaction sent.
    pub txs: Vec<(&'static str, String)>,
}

#[derive(Debug)]
pub enum Step {
    Applied(Applied),
    /// Refused by the native check before any transaction; the reason, with the error code.
    Skipped(String),
    /// `stop_after_begin`: stopped after this instruction.
    Stopped(&'static str),
}

#[derive(Debug, Default)]
pub struct Report {
    pub up_to_date_at: Option<u64>,
    pub waiting_for_signature_slot: Option<u64>,
    pub applied: Vec<Applied>,
    pub skipped: Vec<String>,
    pub stopped: Option<&'static str>,
}

fn code_text(e: &le_sync_core::Error) -> String {
    format!("le-sync error {}: {e:?}", e.code())
}

pub fn stage_config(cfg: &InstanceConfig, current_slot: u64) -> StageConfig {
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

/// The newest record of the records account (`None` if it holds none yet).
pub fn latest_record(data: &[u8]) -> Option<HeaderRecord> {
    data.chunks_exact(RECORD_LEN)
        .filter(|c| !is_blank(c))
        .filter_map(|c| HeaderRecord::decode(c).ok())
        .max_by_key(|r| r.slot)
}

/// Committee keys, kept by keys root: a key list is accepted only if it hashes to the root the
/// caller asks for, so the cache and the source need no trust.
pub struct KeyCache(pub PathBuf);

impl KeyCache {
    fn file(&self, root: &Bytes32) -> PathBuf {
        self.0.join(format!("committee-{}.bin", hex::encode(root)))
    }
    pub fn get(&self, root: &Bytes32) -> Option<Vec<[u8; 48]>> {
        let raw = std::fs::read(self.file(root)).ok()?;
        let keys: Vec<[u8; 48]> = raw
            .chunks_exact(48)
            .map(|c| c.try_into().unwrap())
            .collect();
        (pubkeys_root(&keys).ok()? == *root).then_some(keys)
    }
    pub fn put(&self, keys: &[[u8; 48]]) -> Res<Bytes32> {
        let root = pubkeys_root(keys).map_err(|e| format!("committee keys: {e:?}"))?;
        std::fs::create_dir_all(&self.0).map_err(|e| format!("{}: {e}", self.0.display()))?;
        std::fs::write(self.file(&root), keys.concat()).map_err(|e| format!("cache write: {e}"))?;
        Ok(root)
    }
}

pub struct Submitter<'a> {
    pub cfg: &'a Config,
    pub icfg: InstanceConfig,
    pub ids: Ids,
    pub source: &'a dyn EthSource,
    pub lez: &'a dyn LezClient,
    pub state_dir: PathBuf,
}

struct Tracked {
    store: LightClientStore,
    bytes: Vec<u8>,
}

impl<'a> Submitter<'a> {
    pub fn new(
        cfg: &'a Config,
        source: &'a dyn EthSource,
        lez: &'a dyn LezClient,
        state_dir: PathBuf,
    ) -> Res<Submitter<'a>> {
        let icfg = cfg.instance_config()?;
        let program = parse_program_id(cfg.need("lez", "program_id")?)?;
        let ids = Ids::new(program, icfg.id());
        Ok(Submitter {
            cfg,
            icfg,
            ids,
            source,
            lez,
            state_dir,
        })
    }

    fn cache(&self) -> KeyCache {
        KeyCache(self.state_dir.clone())
    }

    fn tracked(&self) -> Res<Tracked> {
        let bytes = self.lez.account_data(self.ids.store)?;
        let store = decode_store(&bytes).map_err(|e| {
            format!(
                "the store account is not an initialised store ({}): run scripts/deploy.sh",
                code_text(&e)
            )
        })?;
        Ok(Tracked { store, bytes })
    }

    /// Slot of the store's finalized header.
    pub fn finalized_slot(&self) -> Res<u64> {
        Ok(self.tracked()?.store.finalized_header.slot)
    }

    /// Keys of the store's current committee.
    fn current_keys(&self, t: &Tracked) -> Res<Vec<[u8; 48]>> {
        let root = t
            .store
            .current_sync_committee
            .keys_root()
            .map_err(|e| format!("current committee: {e:?}"))?;
        if let Some(k) = self.cache().get(&root) {
            return Ok(k);
        }
        // the bootstrap of the store's finalized header carries the committee of its period
        let at = format!(
            "0x{}",
            hex::encode(t.store.finalized_header.hash_tree_root())
        );
        let body = retry(3, 1000, || self.source.bootstrap(&at))?;
        let keys = convert::bootstrap_keys(&body)?;
        if pubkeys_root(&keys).map_err(|e| format!("{e:?}"))? != root {
            return Err(
                "the committee keys the beacon API gave do not hash to the root the store holds"
                    .into(),
            );
        }
        self.cache().put(&keys)?;
        Ok(keys)
    }

    fn validate_absent_hints(
        &self,
        store: &LightClientStore,
        keys: &[[u8; 48]],
        bits: &[u8],
        absent: &le_sync_wire::rooted::AbsentWire,
    ) -> Res<()> {
        let committee = &store.current_sync_committee;
        if !absent.view().well_formed() {
            return Err("locally built absent-key hints have invalid lengths".into());
        }
        if keys.len() != committee.len || bits.len() * 8 != committee.len {
            return Err(format!(
                "committee/key/participation lengths disagree: store={}, keys={}, bits={}",
                committee.len,
                keys.len(),
                bits.len() * 8
            ));
        }
        if !absent_matches_bits(bits, &absent.index) {
            return Err(
                "locally built absent-key positions do not match participation bits".into(),
            );
        }
        let expected_root = committee
            .stored_keys_root()
            .ok_or("the store's current committee is not rooted")?;
        let keys_root = pubkeys_root(keys).map_err(|e| format!("cached committee: {e:?}"))?;
        if keys_root != expected_root {
            return Err(format!(
                "cached committee root 0x{} differs from the store root 0x{}",
                hex::encode(keys_root),
                hex::encode(expected_root)
            ));
        }
        for (hint_index, &committee_index) in absent.index.iter().enumerate() {
            let key = keys
                .get(committee_index as usize)
                .ok_or("absent-key position is outside the cached committee")?;
            let encoded = absent
                .view()
                .key_bytes(hint_index)
                .ok_or("absent-key point is missing")?;
            if !is_canonical_uncompressed_g1(key, &encoded) {
                return Err(format!(
                    "uncompressed absent committee key at index {committee_index} does not round-trip"
                ));
            }
        }
        let leaves: Vec<_> = absent
            .index
            .iter()
            .map(|&i| pubkey_root(&keys[i as usize]))
            .collect();
        if !verify_multiproof(
            &expected_root,
            committee.len,
            &absent.index,
            &leaves,
            absent.view().siblings(),
        ) {
            return Err(
                "locally built absent-key multiproof does not verify against the store root".into(),
            );
        }
        Ok(())
    }

    /// The updates worth trying now, oldest first, and the finality update body they include.
    fn candidates(&self, t: &Tracked) -> Res<(Vec<Candidate>, String)> {
        let (spe, epp) = (self.icfg.slots_per_epoch, self.icfg.epochs_per_period);
        let store_slot = t.store.finalized_header.slot;
        let next_known = !t.store.next_sync_committee.is_empty();
        let fbody = retry(3, 1000, || self.source.finality_update())?;
        let head = convert::candidates(&fbody)?;
        let head_slot = head
            .iter()
            .map(|c| c.finalized_slot)
            .max()
            .unwrap_or(store_slot);
        let mut all = vec![];
        if let Some(n) = plan::period_updates_needed(
            plan::sync_period(store_slot, spe, epp),
            next_known,
            plan::sync_period(head_slot, spe, epp),
        ) {
            let body = retry(3, 1000, || self.source.updates(n.start_period, n.count))?;
            all.extend(convert::candidates(&body)?);
        }
        all.extend(head);
        all.retain(|c| {
            plan::worth_trying(store_slot, next_known, c.finalized_slot, c.carries_next)
        });
        let mut unique = Vec::with_capacity(all.len());
        for candidate in all {
            if !unique.iter().any(|seen: &Candidate| seen == &candidate) {
                unique.push(candidate);
            }
        }
        let mut all = unique;
        all.sort_by_key(|c| (c.finalized_slot, !c.carries_next));
        Ok((all, fbody))
    }

    /// One update through begin, miller and finish, resuming from the job account's step.
    fn apply(&self, c: &Candidate, o: &Opts) -> Res<Step> {
        let t = self.tracked()?;
        let keys = self.current_keys(&t)?;
        let mut wire = c.wire.clone();
        if o.tamper_signature {
            if let Some(b) = wire.signature.first_mut() {
                *b ^= 1;
            }
        }
        let rooted = to_rooted_update(&wire).map_err(|e| code_text(&e))?;
        let absent = absent_wire(&keys, &wire.bits, uncompress_g1)
            .ok_or("could not build the absent-key hints (bits do not cover the committee, or a key does not uncompress)")?;
        self.validate_absent_hints(&t.store, &keys, &wire.bits, &absent)?;

        // the program's own first step, run natively: the verdict before any transaction, and
        // the digest the job's address is derived from
        let now = self.icfg.slot_at(self.lez.clock_ms()?);
        let input = RootedInput::Begin {
            store: t.bytes.clone(),
            update: rooted.clone(),
            absent: absent.clone(),
        };
        let digest: Vec<u8> = match run_rooted(&stage_config(&self.icfg, now), &input, &Impl) {
            Ok(StageOutput::Job(j)) if j.len() == JOB_LEN => j[33..65].to_vec(),
            Ok(_) => return Err("the native begin step returned no job".into()),
            Err(e) if o.force => {
                let w: Vec<u8> = words(&(&rooted, &absent))
                    .iter()
                    .flat_map(|w| w.to_le_bytes())
                    .collect();
                let _ = e;
                Sha256::digest(w).to_vec()
            }
            Err(le_sync_core::Error::AbsentKeys) => {
                return Err(
                    "native rooted begin rejected absent-key hints after the host verified their shape, committee root, point encodings, participation positions, and multiproof"
                        .into(),
                )
            }
            Err(le_sync_core::Error::BadSlotOrder) => {
                return Ok(Step::Skipped(format!(
                    "{} (current={}, signature={}, attested={}, finalized={})",
                    code_text(&le_sync_core::Error::BadSlotOrder),
                    now,
                    wire.signature_slot,
                    wire.attested.slot,
                    wire.finalized.slot
                )))
            }
            Err(e) => return Ok(Step::Skipped(code_text(&e))),
        };
        let job_seed = job_seed_of(&self.ids.instance_id, &digest);
        let job = self.ids.job(&job_seed);
        let clock = clock_account();
        let mut txs = vec![];

        let step = match UpdateJob::from_bytes(&self.lez.account_data(job)?) {
            Ok(j) => j.step,
            Err(_) => 0,
        };

        if o.only_miller {
            if step == 0 {
                return Err(code_text(&le_sync_core::Error::WrongStep));
            }
            let h = self
                .lez
                .send(&Instruction::MillerUpdate { job_seed }, &[job])?;
            return Ok(Step::Applied(Applied {
                finalized_slot: c.finalized_slot,
                txs: vec![("miller_update", h)],
            }));
        }

        if step == 0 {
            let h = self.lez.send(
                &Instruction::BeginUpdate {
                    instance_id: self.ids.instance_id,
                    store_seed: self.ids.store_seed,
                    job_seed,
                    update: words(&(&rooted, &absent)),
                },
                &[self.ids.instance, self.ids.store, job, clock],
            )?;
            txs.push(("begin_update", h));
            wait_account(self.lez, job, WAIT_SECS, |d| {
                UpdateJob::from_bytes(d).is_ok()
            })?;
            if o.stop_after_begin {
                return Ok(Step::Stopped("begin_update"));
            }
        }
        if step <= STEP_PREPARED {
            let h = self
                .lez
                .send(&Instruction::MillerUpdate { job_seed }, &[job])?;
            txs.push(("miller_update", h));
            wait_account(self.lez, job, WAIT_SECS, |d| {
                UpdateJob::from_bytes(d)
                    .map(|j| j.step == STEP_MILLER)
                    .unwrap_or(false)
            })?;
        }
        let h = self.lez.send(
            &Instruction::FinishUpdate {
                instance_id: self.ids.instance_id,
                store_seed: self.ids.store_seed,
                job_seed,
                records_seed: self.ids.records_seed,
                update: words(&rooted),
                exec: words(&c.exec),
                exec_branch: c.exec_branch.clone(),
            },
            &[
                self.ids.instance,
                self.ids.store,
                job,
                self.ids.records,
                clock,
            ],
        )?;
        txs.push(("finish_update", h));
        wait_account(self.lez, self.ids.store, WAIT_SECS, |d| {
            d != t.bytes.as_slice()
        })?;

        if !wire.next_pubkeys.is_empty() {
            let next: Vec<[u8; 48]> = wire
                .next_pubkeys
                .chunks_exact(48)
                .map(|c| c.try_into().unwrap())
                .collect();
            self.cache().put(&next)?;
        }
        Ok(Step::Applied(Applied {
            finalized_slot: c.finalized_slot,
            txs,
        }))
    }

    /// Bring the instance up to the newest finalized header the beacon API can prove, holding
    /// back `defer_max_ms` at most (a number that depends on the operator, the instance and the
    /// update) and looking again before spending anything.
    pub fn run_once(&self, defer_max_ms: u64, o: &Opts) -> Res<Report> {
        let mut report = Report::default();
        let t = self.tracked()?;
        let (first, _) = self.candidates(&t)?;
        let Some(next) = first.first() else {
            report.up_to_date_at = Some(t.store.finalized_header.slot);
            return Ok(report);
        };
        let operator = format!(
            "{}/{}",
            std::env::var("OPERATOR_ID")
                .unwrap_or_else(|_| self.cfg.or("lez", "account", "").to_string()),
            std::process::id()
        );
        let wait = plan::defer_ms(
            operator.as_bytes(),
            &self.ids.instance_id,
            next.finalized_slot,
            defer_max_ms,
        );
        if wait > 0 {
            std::thread::sleep(std::time::Duration::from_millis(wait));
        }
        // look again: another operator may have applied it while we waited
        let t = self.tracked()?;
        let (cands, fbody) = self.candidates(&t)?;
        if cands.is_empty() {
            report.up_to_date_at = Some(t.store.finalized_header.slot);
            return Ok(report);
        }
        for c in &cands {
            let now = self.tracked()?;
            if !plan::worth_trying(
                now.store.finalized_header.slot,
                !now.store.next_sync_committee.is_empty(),
                c.finalized_slot,
                c.carries_next,
            ) {
                continue;
            }
            let current_slot = self.icfg.slot_at(self.lez.clock_ms()?);
            match plan::update_readiness(
                current_slot,
                c.wire.signature_slot,
                c.wire.attested.slot,
                c.wire.finalized.slot,
            ) {
                plan::UpdateReadiness::Ready => {}
                plan::UpdateReadiness::WaitingForSignature(slot) => {
                    report.waiting_for_signature_slot = Some(
                        report
                            .waiting_for_signature_slot
                            .map_or(slot, |waiting| waiting.min(slot)),
                    );
                    continue;
                }
                plan::UpdateReadiness::InvalidSlotOrder => {
                    report.skipped.push(format!(
                        "slot {}: {} (current={}, signature={}, attested={}, finalized={})",
                        c.finalized_slot,
                        code_text(&le_sync_core::Error::BadSlotOrder),
                        current_slot,
                        c.wire.signature_slot,
                        c.wire.attested.slot,
                        c.wire.finalized.slot
                    ));
                    continue;
                }
            }
            match self.apply(c, o)? {
                Step::Applied(a) => report.applied.push(a),
                Step::Skipped(why) => report
                    .skipped
                    .push(format!("slot {}: {why}", c.finalized_slot)),
                Step::Stopped(at) => {
                    report.stopped = Some(at);
                    return Ok(report);
                }
            }
        }
        if !report.applied.is_empty() {
            let _ = std::fs::create_dir_all(&self.state_dir);
            let _ = std::fs::write(self.state_dir.join("last-finality-update.json"), fbody);
        }
        Ok(report)
    }

    /// Send the last applied finality update again (a test: the program must refuse it).
    pub fn replay_last(&self) -> Res<Report> {
        let body = std::fs::read_to_string(self.state_dir.join("last-finality-update.json"))
            .map_err(|e| format!("nothing to replay yet: {e}"))?;
        let c = convert::candidates(&body)?
            .into_iter()
            .next()
            .ok_or("no update in the saved material")?;
        let t = self.tracked()?;
        if !plan::worth_trying(
            t.store.finalized_header.slot,
            !t.store.next_sync_committee.is_empty(),
            c.finalized_slot,
            c.carries_next,
        ) {
            return Ok(Report {
                up_to_date_at: Some(t.store.finalized_header.slot),
                ..Report::default()
            });
        }
        let mut r = Report::default();
        match self.apply(
            &c,
            &Opts {
                force: true,
                ..Opts::default()
            },
        )? {
            Step::Applied(a) => r.applied.push(a),
            Step::Skipped(s) => r.skipped.push(s),
            Step::Stopped(at) => r.stopped = Some(at),
        }
        Ok(r)
    }

    /// `init_instance` from the bootstrap of the configured trusted root. The instance ID.
    pub fn init(&self) -> Res<Bytes32> {
        let trusted = self.icfg.trusted_root;
        let body = retry(3, 1000, || {
            self.source
                .bootstrap(&format!("0x{}", hex::encode(trusted)))
        })?;
        let b = convert::bootstrap(&body)?;
        if b.header.hash_tree_root() != trusted {
            return Err("the bootstrap header does not hash to the trusted root".into());
        }
        let keys_root = pubkeys_root(&b.keys).map_err(|e| format!("bootstrap committee: {e:?}"))?;
        if b.keys.len() != self.icfg.committee_size as usize {
            return Err(format!(
                "the committee has {} keys but [instance] sync_committee_size is {}",
                b.keys.len(),
                self.icfg.committee_size
            ));
        }
        self.cache().put(&b.keys)?;
        let h = self.lez.send(
            &Instruction::InitInstance {
                instance_id: self.ids.instance_id,
                store_seed: self.ids.store_seed,
                records_seed: self.ids.records_seed,
                config: self.icfg.encode().to_vec(),
                slot: b.header.slot,
                proposer_index: b.header.proposer_index,
                parent_root: b.header.parent_root,
                state_root: b.header.state_root,
                body_root: b.header.body_root,
                keys_root,
                aggregate: b.aggregate,
                branch: b.branch,
            },
            &[
                self.ids.instance,
                self.ids.store,
                self.ids.records,
                clock_account(),
            ],
        )?;
        eprintln!("init_instance sent: {h}");
        wait_account(self.lez, self.ids.instance, WAIT_SECS, |d| !is_blank(d))?;
        Ok(self.ids.instance_id)
    }

    /// Attest an account (`slot` None) or a storage slot under the newest header record. The
    /// native verifier runs first, so a bad proof is refused with the program's own code
    /// before anything is sent. The statement ID.
    pub fn attest_state(
        &self,
        address: &str,
        slot: Option<&str>,
        tamper_proof: bool,
        tamper_header: bool,
        instance_id_override: Option<Bytes32>,
    ) -> Res<Bytes32> {
        if instance_id_override.is_some_and(|id| id != self.ids.instance_id) {
            return Err(code_text(&le_sync_core::Error::InstanceIdMismatch));
        }
        let records = self.lez.account_data(self.ids.records)?;
        let rec = latest_record(&records).ok_or("no header record yet: run an update first")?;
        let addr = convert::hex_n::<20>(address)?;
        let slots: Vec<String> = slot.map(|s| vec![s.to_string()]).unwrap_or_default();
        let body = retry(3, 1000, || {
            self.source.proof(address, &slots, rec.block_number)
        })?;
        let (mut account_proof, storage_proof) = convert::state_proof(&body)?;
        if tamper_proof {
            if let Some(b) = account_proof.first_mut().and_then(|n| n.first_mut()) {
                *b ^= 1;
            }
        }
        let claim = match slot {
            None => AttestClaim::Account(AccountClaim {
                address: addr,
                account_proof,
                predicate: None,
            }),
            Some(s) => AttestClaim::Storage(StorageClaim {
                address: addr,
                slot: convert::hex_n::<32>(s)?,
                account_proof,
                storage_proof,
                predicate: None,
            }),
        };
        let attested = verify_attest(&self.icfg, &rec, &claim).map_err(|e| code_text(&e))?;
        let sid = attested.statement_id;
        let mut header_root = rec.header_root;
        if tamper_header {
            header_root[0] ^= 1;
        }
        le_sync_core::header_record::find_record(&records, &header_root)
            .map_err(|e| code_text(&e))?;
        let statement = self.ids.statement(&sid);
        if !self.lez.account_data(statement)?.is_empty() {
            eprintln!("already attested: the statement account exists");
            return Ok(sid);
        }
        let h = self.lez.send(
            &Instruction::AttestState {
                instance_id: self.ids.instance_id,
                records_seed: self.ids.records_seed,
                statement_seed: sid,
                header_root,
                claim: words(&claim),
            },
            &[self.ids.instance, self.ids.records, statement],
        )?;
        eprintln!("attest_state sent: {h}");
        wait_account(self.lez, statement, WAIT_SECS, |d| !d.is_empty())?;
        Ok(sid)
    }

    /// Attest the first matching successful log in the newest finalized execution block.
    pub fn attest_log(
        &self,
        address: &str,
        topic0: &str,
        instance_id_override: Option<Bytes32>,
    ) -> Res<Bytes32> {
        if instance_id_override.is_some_and(|id| id != self.ids.instance_id) {
            return Err(code_text(&le_sync_core::Error::InstanceIdMismatch));
        }
        let records = self.lez.account_data(self.ids.records)?;
        let rec = latest_record(&records).ok_or("no header record yet: run an update first")?;
        let address = convert::hex_n::<20>(address)?;
        let topic0 = convert::hex_n::<32>(topic0)?;
        let body = retry(3, 1000, || self.source.block_receipts(rec.block_number))?;
        let value: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| format!("block receipts: bad JSON: {e}"))?;
        let receipts = crate::receipts::parse_block_receipts(&value)?;
        let trie = crate::receipts::ReceiptsTrie::new(&receipts);
        if trie.root() != rec.receipts_root {
            return Err(format!(
                "the receipts of block {} rebuild to root 0x{} but its finalized header record says 0x{}",
                rec.block_number,
                hex::encode(trie.root()),
                hex::encode(rec.receipts_root)
            ));
        }
        let (tx_index, log_index) = crate::receipts::find_log(&receipts, &address, &topic0)
            .ok_or_else(|| {
                format!(
                    "no successful log in finalized block {} matches address 0x{} and topic0 0x{}",
                    rec.block_number,
                    hex::encode(address),
                    hex::encode(topic0)
                )
            })?;
        let receipt_proof = trie
            .proof(tx_index)
            .ok_or_else(|| format!("the block has no transaction {tx_index}"))?;
        let mut topics = [None; le_sync_core::receipt::MAX_TOPICS];
        topics[0] = Some(topic0);
        let claim = AttestClaim::Log(LogClaim {
            tx_index,
            log_index,
            receipt_proof,
            address,
            topics,
            predicate: None,
        });
        let attested = verify_attest(&self.icfg, &rec, &claim).map_err(|e| code_text(&e))?;
        let sid = attested.statement_id;
        le_sync_core::header_record::find_record(&records, &rec.header_root)
            .map_err(|e| code_text(&e))?;
        let statement = self.ids.statement(&sid);
        if !self.lez.account_data(statement)?.is_empty() {
            eprintln!("already attested: the statement account exists");
            return Ok(sid);
        }
        let h = self.lez.send(
            &Instruction::AttestLog {
                instance_id: self.ids.instance_id,
                records_seed: self.ids.records_seed,
                statement_seed: sid,
                header_root: rec.header_root,
                claim: words(&claim),
            },
            &[self.ids.instance, self.ids.records, statement],
        )?;
        eprintln!("attest_log sent: {h}");
        wait_account(self.lez, statement, WAIT_SECS, |d| !d.is_empty())?;
        Ok(sid)
    }

    /// What the chain holds, next to what the config file says.
    pub fn read_instance(&self) -> Res<InstanceInfo> {
        let on_chain = self.lez.account_data(self.ids.instance)?;
        let t = self.tracked()?;
        let records = self.lez.account_data(self.ids.records)?;
        Ok(InstanceInfo {
            instance_id: self.ids.instance_id,
            config_matches_chain: on_chain == self.icfg.encode(),
            finalized_slot: t.store.finalized_header.slot,
            optimistic_slot: t.store.optimistic_header.slot,
            next_committee_known: !t.store.next_sync_committee.is_empty(),
            newest_record_slot: latest_record(&records).map(|r| r.slot),
            clock_slot: self.icfg.slot_at(self.lez.clock_ms()?),
        })
    }
}

#[derive(Debug, Clone)]
pub struct InstanceInfo {
    pub instance_id: Bytes32,
    /// The instance account on the chain holds exactly the configuration in the file.
    pub config_matches_chain: bool,
    pub finalized_slot: u64,
    pub optimistic_slot: u64,
    pub next_committee_known: bool,
    pub newest_record_slot: Option<u64>,
    pub clock_slot: u64,
}
