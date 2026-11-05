// Host-side program definition for IDL extraction (`build idl`).
// The guest binary (methods/guest/src/bin/eth_attest.rs) is what the sequencer executes.
//
// KEEP IN STEP: this copy has the same instruction names, account attributes and argument
// lists as the guest, and only those. The bodies are stubs: nothing here runs on chain, and the
// light client (le-sync-core, le-sync-wire) is deliberately not a dependency of the host crate.
// `scripts/check_lez_in_step.sh` compares the two declarations.
use nssa_core::account::AccountWithMetadata;
use spel_framework::prelude::*;

#[allow(dead_code)]
pub mod runner_support {
    use nssa::{program::Program, AccountId};

    pub fn parse_account_id(raw: &str) -> AccountId {
        let normalized = raw
            .strip_prefix("Public/")
            .or_else(|| raw.strip_prefix("Private/"))
            .unwrap_or(raw);

        normalized
            .parse()
            .unwrap_or_else(|err| panic!("invalid account_id `{raw}`: {err}"))
    }

    pub fn load_program(program_path: Option<&str>, embedded_elf: &[u8], label: &str) -> Program {
        let bytes = if let Some(path) = program_path {
            std::fs::read(path)
                .unwrap_or_else(|err| panic!("failed to read {label} binary at `{path}`: {err}"))
        } else {
            embedded_elf.to_vec()
        };

        Program::new(bytes.into())
            .unwrap_or_else(|err| panic!("failed to parse {label} program: {err}"))
    }
}

#[allow(dead_code)]
fn host_copy_only() -> SpelError {
    SpelError::SerializationError {
        message: "host copy: the program runs from the guest binary".to_string(),
    }
}

#[lez_program]
#[allow(unused_variables)]
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
        Err(host_copy_only())
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
        Err(host_copy_only())
    }

    /// Step 2. Reads and writes only the job, which binds everything else it needs.
    #[instruction]
    pub fn miller_update(
        #[account(mut, pda = arg("job_seed"))] mut job: AccountWithMetadata,
        job_seed: [u8; 32],
    ) -> SpelResult {
        Err(host_copy_only())
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
        Err(host_copy_only())
    }

    /// Attests an account or a storage slot under the record of `header_root`. `claim` is the
    /// RISC Zero serde words of an `AttestClaim::Account` or `::Storage`; `statement_seed` must
    /// be the statement ID of the verified claim, and the statement account is claimed here.
    #[allow(unused_variables)]
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
        Err(host_copy_only())
    }

    /// Attests a log. As `attest_state`, with an `AttestClaim::Log`.
    #[allow(unused_variables)]
    #[instruction]
    pub fn attest_log(
        #[account(pda = arg("instance_id"))] instance: AccountWithMetadata,
        #[account(pda = arg("records_seed"))] records: AccountWithMetadata,
        #[account(init, pda = arg("statement_seed"))] statement: AccountWithMetadata,
        instance_id: [u8; 32],
        records_seed: [u8; 32],
        statement_seed: [u8; 32],
        header_root: [u8; 32],
        claim: Vec<u32>,
    ) -> SpelResult {
        Err(host_copy_only())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn __lssa_idl_print() {
        println!("--- LSSA IDL BEGIN eth_attest ---");
        println!("{}", super::PROGRAM_IDL_JSON);
        println!("--- LSSA IDL END eth_attest ---");
    }
}
