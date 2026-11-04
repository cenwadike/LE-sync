//! Runs the program through LEZ's own state machine (`nssa::V03State`) and, to count gas, through
//! the RISC Zero executor the way `nssa::program::Program::execute` does.
//!
//! Every transaction here is a real `PublicTransaction` validated by
//! `V03State::transition_from_public_transaction`: the same checks the sequencer runs (the
//! program's pre-states must match the state, an `init` account must be claimed with its PDA
//! seed, nothing else may change an account it does not own, the cycle cap, ...). The state
//! lives in memory and persists from one transaction to the next, so a test is a sequence of
//! transactions against one chain, exactly as on a node.
//!
//! No transaction here has a signer: the program takes none.
use le_sync_core::Bytes32;
use le_sync_wire::bls::Impl;
use le_sync_wire::rooted::{run_rooted, RootedInput};
use le_sync_wire::stage::{StageConfig, StageOutput};
use nssa::program::Program;
use nssa::program_deployment_transaction::Message as DeployMessage;
use nssa::public_transaction::{Message, WitnessSet};
use nssa::{
    AccountId, ProgramDeploymentTransaction, ProgramId, PublicTransaction, V03State,
    CLOCK_01_PROGRAM_ACCOUNT_ID, CLOCK_PROGRAM_ACCOUNT_IDS,
};
use nssa_core::account::AccountWithMetadata;
use risc0_zkvm::{default_executor, ExecutorEnv};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// The public execution cap of LEZ v0.1.2 (`nssa::program`), for the table.
pub const CYCLE_CAP: u64 = 1024 * 1024 * 32;

/// The instruction enum of the program, as `spel-client-gen` generates it for `eth_attest`
/// (`EthAttestInstruction`): one variant per instruction in declaration order, the fields
/// are the arguments that are not accounts, in order. The encoding is RISC Zero serde, which
/// numbers variants and does not name them, so only order and types matter. If the program's
/// signatures change, change this, and compare it with `src/generated/eth_attest_client.rs`.
#[derive(Clone, Debug, Serialize)]
pub enum Instruction {
    InitInstance {
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
    },
    BeginUpdate {
        instance_id: [u8; 32],
        store_seed: [u8; 32],
        job_seed: [u8; 32],
        update: Vec<u32>,
    },
    MillerUpdate {
        job_seed: [u8; 32],
    },
    FinishUpdate {
        instance_id: [u8; 32],
        store_seed: [u8; 32],
        job_seed: [u8; 32],
        records_seed: [u8; 32],
        update: Vec<u32>,
        exec: Vec<u32>,
        exec_branch: Vec<[u8; 32]>,
    },
    AttestState {
        instance_id: [u8; 32],
        records_seed: [u8; 32],
        statement_seed: [u8; 32],
        header_root: [u8; 32],
        claim: Vec<u32>,
    },
    AttestLog {
        instance_id: [u8; 32],
        records_seed: [u8; 32],
        statement_seed: [u8; 32],
        header_root: [u8; 32],
        claim: Vec<u32>,
    },
}

/// `SHA256("le-sync/seed/v1/" || kind || instance_id)`: the seed of the `kind` account. The
/// same rule as the program's `seed`; written again here on purpose, so a change on either side
/// shows up as a failing test.
pub fn seed(kind: &str, instance_id: &Bytes32) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(b"le-sync/seed/v1/");
    h.update(kind.as_bytes());
    h.update(instance_id);
    h.finalize().into()
}

/// The account a PDA seed names under `program`, as the generated client computes it.
pub fn pda(program: &ProgramId, seed: &Bytes32) -> AccountId {
    spel_framework_core::pda::compute_pda(program, &[seed])
}

/// The accounts and seeds of one instance.
#[derive(Clone, Copy, Debug)]
pub struct Ids {
    pub instance_id: Bytes32,
    pub store_seed: Bytes32,
    pub records_seed: Bytes32,
    pub instance: AccountId,
    pub store: AccountId,
    pub records: AccountId,
}

/// The job account of one update: claimed by `begin_update`, at the address derived from the
/// instance and the update's digest.
#[derive(Clone, Copy, Debug)]
pub struct Job {
    pub seed: Bytes32,
    pub account: AccountId,
}

/// `SHA256("le-sync/seed/v1/job" || instance_id || update_digest)`, as the program's
/// `job_seed_of`.
pub fn job_seed_of(instance_id: &Bytes32, update_digest: &[u8]) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(b"le-sync/seed/v1/job");
    h.update(instance_id);
    h.update(update_digest);
    h.finalize().into()
}

impl Ids {
    pub fn new(program: &ProgramId, instance_id: Bytes32) -> Ids {
        let store_seed = seed("store", &instance_id);
        let records_seed = seed("records", &instance_id);
        Ids {
            instance_id,
            store_seed,
            records_seed,
            instance: pda(program, &instance_id),
            store: pda(program, &store_seed),
            records: pda(program, &records_seed),
        }
    }
}

/// The words of the RISC Zero serde encoding of `value`, as an instruction argument takes them.
pub fn words<T: Serialize>(value: &T) -> Vec<u32> {
    risc0_zkvm::serde::to_vec(value).expect("serializes")
}

/// What one transaction did.
#[derive(Debug)]
pub struct Outcome {
    /// Executor cycles of the program run (only when the chain measures).
    pub cycles: Option<u64>,
    /// `Err` is the state machine's error, text included.
    pub result: Result<(), String>,
}

impl Outcome {
    pub fn is_ok(&self) -> bool {
        self.result.is_ok()
    }

    /// The `le-sync error <code>` the program reported, if the error carries one.
    pub fn code(&self) -> Option<u16> {
        let e = self.result.as_ref().err()?;
        let at = e.find("le-sync error ")? + "le-sync error ".len();
        let digits: String = e[at..].chars().take_while(|c| c.is_ascii_digit()).collect();
        digits.parse().ok()
    }

    #[track_caller]
    pub fn expect_ok(&self, what: &str) {
        if let Err(e) = &self.result {
            panic!("{what}: the transaction was refused: {e}");
        }
    }

    /// The transaction was refused with the program's error `code`.
    #[track_caller]
    pub fn expect_code(&self, code: u16, what: &str) {
        match &self.result {
            Ok(()) => panic!("{what}: the transaction was accepted, expected error {code}"),
            Err(e) => assert_eq!(
                self.code(),
                Some(code),
                "{what}: expected `le-sync error {code}`, the state machine said: {e}"
            ),
        }
    }

    /// The transaction was refused, for any reason (including a check of the framework).
    #[track_caller]
    pub fn expect_refused(&self, what: &str) {
        assert!(
            self.result.is_err(),
            "{what}: the transaction was accepted, expected a refusal"
        );
    }
}

/// An in-memory LEZ chain with the program deployed.
#[derive(Clone)]
pub struct Chain {
    pub state: V03State,
    pub program: Program,
    /// Also run each transaction in the executor and record its cycles.
    pub measure: bool,
    block: u64,
    now_ms: u64,
}

impl Chain {
    /// A chain whose clock reads `clock_ms`, with `elf` deployed.
    pub fn new(elf: &[u8], clock_ms: u64, measure: bool) -> Chain {
        let mut state = V03State::new_with_genesis_accounts(&[], vec![], clock_ms);
        let program = Program::new(elf.to_vec()).expect("a RISC Zero program binary");
        let tx = ProgramDeploymentTransaction::new(DeployMessage::new(elf.to_vec()));
        state
            .transition_from_program_deployment_transaction(&tx)
            .expect("the program deploys");
        Chain {
            state,
            program,
            measure,
            block: 0,
            now_ms: clock_ms,
        }
    }

    pub fn program_id(&self) -> ProgramId {
        self.program.id()
    }

    /// Moves the LEZ clock to `ms`, as the sequencer does at the end of a block: one run of the
    /// clock program over the three clock accounts.
    pub fn set_clock(&mut self, ms: u64) {
        let message = Message::try_new(
            Program::clock().id(),
            CLOCK_PROGRAM_ACCOUNT_IDS.to_vec(),
            vec![],
            ms,
        )
        .expect("the clock instruction serializes");
        let tx = PublicTransaction::new(message, WitnessSet::from_raw_parts(vec![]));
        self.block += 1;
        self.now_ms = ms;
        self.state
            .transition_from_public_transaction(&tx, self.block, ms)
            .expect("the clock advances");
    }

    /// The data of an account (empty for one that does not exist).
    pub fn data(&self, id: AccountId) -> Vec<u8> {
        self.state.get_account_by_id(id).data.into_inner()
    }

    pub fn owner(&self, id: AccountId) -> ProgramId {
        self.state.get_account_by_id(id).program_owner
    }

    /// One transaction of `ix` over `accounts` (in the program's account order).
    pub fn run(&mut self, ix: &Instruction, accounts: &[AccountId]) -> Outcome {
        let message = Message::try_new(self.program.id(), accounts.to_vec(), vec![], ix.clone())
            .expect("the instruction serializes");
        let cycles = if self.measure {
            self.cycles(&message.instruction_data, accounts)
        } else {
            None
        };
        let tx = PublicTransaction::new(message, WitnessSet::from_raw_parts(vec![]));
        self.block += 1;
        let result = self
            .state
            .transition_from_public_transaction(&tx, self.block, self.now_ms)
            .map_err(|e| format!("{e:?}"));
        Outcome { cycles, result }
    }

    /// Executor cycles of the program over the accounts as they are now: the same input layout
    /// as `Program::write_inputs`, the same cap as `Program::execute`.
    fn cycles(&self, instruction: &[u32], accounts: &[AccountId]) -> Option<u64> {
        let pre: Vec<AccountWithMetadata> = accounts
            .iter()
            .map(|id| AccountWithMetadata::new(self.state.get_account_by_id(*id), false, *id))
            .collect();
        let mut b = ExecutorEnv::builder();
        b.session_limit(Some(CYCLE_CAP));
        b.write(&self.program.id()).ok()?;
        b.write(&None::<ProgramId>).ok()?;
        b.write(&pre).ok()?;
        b.write(&instruction.to_vec()).ok()?;
        let env = b.build().ok()?;
        default_executor()
            .execute(env, self.program.elf())
            .ok()
            .map(|info| info.cycles())
    }

    // ---- the six instructions, with the account order of the program ------------------

    /// `init_instance` for `cfg` and the bootstrap of `world`.
    pub fn init(
        &mut self,
        ids: &Ids,
        cfg: &le_sync_core::instance::InstanceConfig,
        boot: &le_sync_core::instance::Bootstrap,
    ) -> Outcome {
        self.init_with_clock(ids, cfg, boot, CLOCK_01_PROGRAM_ACCOUNT_ID)
    }

    /// As `init`, with another account in the place of the clock.
    pub fn init_with_clock(
        &mut self,
        ids: &Ids,
        cfg: &le_sync_core::instance::InstanceConfig,
        boot: &le_sync_core::instance::Bootstrap,
        clock: AccountId,
    ) -> Outcome {
        self.run(
            &Instruction::InitInstance {
                instance_id: ids.instance_id,
                store_seed: ids.store_seed,
                records_seed: ids.records_seed,
                config: cfg.encode().to_vec(),
                slot: boot.header.slot,
                proposer_index: boot.header.proposer_index,
                parent_root: boot.header.parent_root,
                state_root: boot.header.state_root,
                body_root: boot.header.body_root,
                keys_root: boot.keys_root,
                aggregate: boot.aggregate.to_vec(),
                branch: boot.branch.to_vec(),
            },
            &[ids.instance, ids.store, ids.records, clock],
        )
    }

    /// The job account of `u`, as the program derives it: the digest of the update is read
    /// from the job that a native run of `begin` over the chain's current store produces. If
    /// the update does not begin natively (a test of a refusal), the address is one nothing
    /// will claim, so the program's own error is what the transaction reports.
    pub fn job_for(
        &self,
        ids: &Ids,
        cfg: &le_sync_core::instance::InstanceConfig,
        u: &crate::world::Update,
    ) -> Job {
        let input = RootedInput::Begin {
            store: self.data(ids.store),
            update: u.rooted.clone(),
            absent: u.absent.clone(),
        };
        let slot = cfg.slot_at(self.now_ms);
        let digest = match run_rooted(&stage_config(cfg, slot), &input, &Impl) {
            Ok(StageOutput::Job(job)) if job.len() == 641 => job[33..65].to_vec(),
            // not a job the program would store: any digest, distinct per update
            _ => Sha256::digest(words(&(&u.rooted, &u.absent)).iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>()).to_vec(),
        };
        let seed = job_seed_of(&ids.instance_id, &digest);
        Job {
            seed,
            account: pda(&self.program.id(), &seed),
        }
    }

    pub fn begin(&mut self, ids: &Ids, job: &Job, u: &crate::world::Update) -> Outcome {
        self.run(
            &Instruction::BeginUpdate {
                instance_id: ids.instance_id,
                store_seed: ids.store_seed,
                job_seed: job.seed,
                update: words(&(&u.rooted, &u.absent)),
            },
            &[ids.instance, ids.store, job.account, CLOCK_01_PROGRAM_ACCOUNT_ID],
        )
    }

    pub fn miller(&mut self, job: &Job) -> Outcome {
        self.run(
            &Instruction::MillerUpdate { job_seed: job.seed },
            &[job.account],
        )
    }

    pub fn finish(&mut self, ids: &Ids, job: &Job, u: &crate::world::Update) -> Outcome {
        self.run(
            &Instruction::FinishUpdate {
                instance_id: ids.instance_id,
                store_seed: ids.store_seed,
                job_seed: job.seed,
                records_seed: ids.records_seed,
                update: words(&u.rooted),
                exec: words(&u.exec),
                exec_branch: u.exec_branch.clone(),
            },
            &[ids.instance, ids.store, job.account, ids.records, CLOCK_01_PROGRAM_ACCOUNT_ID],
        )
    }

    /// Begin, Miller, Finish. Stops at the first refusal and returns it with the step's name.
    pub fn update(
        &mut self,
        ids: &Ids,
        cfg: &le_sync_core::instance::InstanceConfig,
        u: &crate::world::Update,
    ) -> Result<[Outcome; 3], (&'static str, Outcome)> {
        let job = self.job_for(ids, cfg, u);
        let begin = self.begin(ids, &job, u);
        if !begin.is_ok() {
            return Err(("begin_update", begin));
        }
        let miller = self.miller(&job);
        if !miller.is_ok() {
            return Err(("miller_update", miller));
        }
        let finish = self.finish(ids, &job, u);
        if !finish.is_ok() {
            return Err(("finish_update", finish));
        }
        Ok([begin, miller, finish])
    }

    /// `attest_state` (`log` false) or `attest_log` (`log` true). `statement_seed` is the
    /// statement ID the claim must have.
    pub fn attest(
        &mut self,
        ids: &Ids,
        log: bool,
        header_root: Bytes32,
        statement_seed: Bytes32,
        claim: &le_sync_wire::statement_path::AttestClaim,
    ) -> Outcome {
        let statement = pda(&self.program.id(), &statement_seed);
        let ix = if log {
            Instruction::AttestLog {
                instance_id: ids.instance_id,
                records_seed: ids.records_seed,
                statement_seed,
                header_root,
                claim: words(claim),
            }
        } else {
            Instruction::AttestState {
                instance_id: ids.instance_id,
                records_seed: ids.records_seed,
                statement_seed,
                header_root,
                claim: words(claim),
            }
        };
        self.run(&ix, &[ids.instance, ids.records, statement])
    }
}

/// The ID of the statement `claim` makes under `record` of the instance `cfg`, as the native
/// verifier derives it (the program must derive the same one).
pub fn statement_id_of(
    cfg: &le_sync_core::instance::InstanceConfig,
    record: &le_sync_core::header_record::HeaderRecord,
    claim: &le_sync_wire::statement_path::AttestClaim,
) -> Bytes32 {
    le_sync_wire::statement_path::verify_attest(cfg, record, claim)
        .expect("the claim verifies natively")
        .statement_id
}

/// The staged-update configuration the program builds from the instance and the clock.
pub fn stage_config(cfg: &le_sync_core::instance::InstanceConfig, current_slot: u64) -> StageConfig {
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

/// The statement stored in `account`: the RISC Zero serde words of `Attested`, little endian.
pub fn statement_of(bytes: &[u8]) -> Option<le_sync_wire::statement_path::Attested> {
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return None;
    }
    let words: Vec<u32> = bytes
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect();
    risc0_zkvm::serde::from_slice(&words).ok()
}
