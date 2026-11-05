//! The LEZ side: the program's instructions, the accounts they take, and the one place that
//! knows about the sequencer (`WalletLez`).
//!
//! `Instruction`, `seed`, `pda`, `job_seed_of` and `Ids` are the same as in
//! `lez/executor-tests/src/harness.rs`, which is tested against the program; keep them equal,
//! and compare `Instruction` with `lez/src/generated/eth_attest_client.rs` when the program's
//! signatures change. No transaction has a signer: the program takes none.
use le_sync_core::Bytes32;
use clock_core::CLOCK_01_PROGRAM_ACCOUNT_ID;
use nssa::public_transaction::{Message, WitnessSet};
use nssa::{AccountId, ProgramId, PublicTransaction};
use serde::Serialize;
use sha2::{Digest, Sha256};

type Res<T> = Result<T, String>;

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

/// `SHA256("le-sync/seed/v1/" || kind || instance_id)`.
pub fn seed(kind: &str, instance_id: &Bytes32) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(b"le-sync/seed/v1/");
    h.update(kind.as_bytes());
    h.update(instance_id);
    h.finalize().into()
}

/// `SHA256("le-sync/seed/v1/job" || instance_id || update_digest)`.
pub fn job_seed_of(instance_id: &Bytes32, update_digest: &[u8]) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(b"le-sync/seed/v1/job");
    h.update(instance_id);
    h.update(update_digest);
    h.finalize().into()
}

pub fn pda(program: &ProgramId, seed: &Bytes32) -> AccountId {
    spel_framework_core::pda::compute_pda(program, &[seed])
}

/// The words of the RISC Zero serde encoding of `value`, as an instruction argument takes them.
pub fn words<T: Serialize>(value: &T) -> Vec<u32> {
    risc0_zkvm::serde::to_vec(value).expect("serializes")
}

/// The ID of the program, from the hex of `lez/src/bin/run_eth_attest` (little-endian words).
pub fn parse_program_id(s: &str) -> Res<ProgramId> {
    let raw = hex::decode(s.trim_start_matches("0x")).map_err(|e| format!("program_id: {e}"))?;
    if raw.len() != 32 {
        return Err(format!("program_id must be 32 bytes, got {}", raw.len()));
    }
    let mut id = [0u32; 8];
    for (i, c) in raw.chunks(4).enumerate() {
        id[i] = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
    }
    Ok(id)
}

/// The accounts and seeds of one instance.
#[derive(Clone, Copy, Debug)]
pub struct Ids {
    pub program: ProgramId,
    pub instance_id: Bytes32,
    pub store_seed: Bytes32,
    pub records_seed: Bytes32,
    pub instance: AccountId,
    pub store: AccountId,
    pub records: AccountId,
}

impl Ids {
    pub fn new(program: ProgramId, instance_id: Bytes32) -> Ids {
        let store_seed = seed("store", &instance_id);
        let records_seed = seed("records", &instance_id);
        Ids {
            program,
            instance_id,
            store_seed,
            records_seed,
            instance: pda(&program, &instance_id),
            store: pda(&program, &store_seed),
            records: pda(&program, &records_seed),
        }
    }
    pub fn job(&self, job_seed: &Bytes32) -> AccountId {
        pda(&self.program, job_seed)
    }
    pub fn statement(&self, statement_seed: &Bytes32) -> AccountId {
        pda(&self.program, statement_seed)
    }
}

pub fn clock_account() -> AccountId {
    CLOCK_01_PROGRAM_ACCOUNT_ID
}

/// What the module needs from a chain. Everything environment-specific is behind this.
pub trait LezClient {
    /// Submit one transaction of `ix` over `accounts` (in the program's account order); the
    /// hash it was accepted under. Acceptance is not inclusion: callers wait for the effect.
    fn send(&self, ix: &Instruction, accounts: &[AccountId]) -> Res<String>;
    /// The data of an account (empty if it does not exist yet).
    fn account_data(&self, id: AccountId) -> Res<Vec<u8>>;
    /// The LEZ clock, milliseconds: the same reading the program uses for the slot.
    fn clock_ms(&self) -> Res<u64> {
        let d = self.account_data(CLOCK_01_PROGRAM_ACCOUNT_ID)?;
        if d.len() != 16 {
            return Err(format!(
                "clock account holds {} bytes, expected 16",
                d.len()
            ));
        }
        // ClockAccountData { block_id: u64, timestamp: u64 }, little-endian
        Ok(u64::from_le_bytes(d[8..16].try_into().unwrap()))
    }
}

/// Sends through the wallet of this machine (`WalletCore::from_env`): the sequencer it talks to
/// is the one in the wallet's own configuration, which is how the scaffold's wallet commands
/// select local or testnet. Export the wallet home before running (both names, see
/// `scripts/lez-env.sh`).
pub struct WalletLez {
    wallet: wallet::WalletCore,
    program: ProgramId,
    rt: tokio::runtime::Runtime,
}

impl WalletLez {
    pub fn from_env(program: ProgramId) -> Res<WalletLez> {
        let wallet = wallet::WalletCore::from_env().map_err(|e| format!("wallet init: {e}"))?;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("runtime: {e}"))?;
        Ok(WalletLez {
            wallet,
            program,
            rt,
        })
    }
}

impl LezClient for WalletLez {
    fn send(&self, ix: &Instruction, accounts: &[AccountId]) -> Res<String> {
        use sequencer_service_rpc::RpcClient as _;
        let message = Message::try_new(self.program, accounts.to_vec(), vec![], ix.clone())
            .map_err(|e| format!("message: {e:?}"))?;
        let tx = PublicTransaction::new(message, WitnessSet::from_raw_parts(vec![]));
        let response = self
            .rt
            .block_on(
                self.wallet
                    .sequencer_client
                    .send_transaction(common::transaction::LeeTransaction::Public(tx)),
            )
            .map_err(|e| format!("submit: {e}"))?;
        Ok(hex::encode(response.0))
    }

    fn account_data(&self, id: AccountId) -> Res<Vec<u8>> {
        use sequencer_service_rpc::RpcClient as _;
        let account = self
            .rt
            .block_on(self.wallet.sequencer_client.get_account(id))
            .map_err(|e| format!("get_account {id}: {e}"))?;
        Ok(account.data[..].to_vec())
    }
}

/// Poll until `done(data)` holds for the account, or `secs` pass.
pub fn wait_account(
    lez: &dyn LezClient,
    id: AccountId,
    secs: u64,
    done: impl Fn(&[u8]) -> bool,
) -> Res<Vec<u8>> {
    let start = std::time::Instant::now();
    loop {
        let d = lez.account_data(id)?;
        if done(&d) {
            return Ok(d);
        }
        if start.elapsed().as_secs() >= secs {
            return Err(format!(
                "timed out after {secs}s waiting for account {id} to change"
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}
