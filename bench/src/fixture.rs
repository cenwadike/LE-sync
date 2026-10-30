//! Synthetic, self-consistent world for the bench: a bootstrap committing a real committee, and
//! one signed update. Real BLS signatures (testkit signs; the keys are trivially guessable and
//! must never leave tests and benches), mainnet-size committees by default.
//!
//! This is a small copy of the helpers in `wire/tests/common/mod.rs` (`hdr`, `signing_root`,
//! `build_update`, `Baseline::new`): an integration test's `common` module cannot be imported
//! from another crate. If those change, change these. The bench's own guard is that the native
//! reference run must accept the update, or it stops before touching the guest.
//!
//! Slots: bootstrap header at 8; update attested 40, finalized 24, signature slot 41; the clock
//! (`current_slot`) reads 41. Period length is 64 slots, so everything is in period 0 and the
//! store does not yet know its next committee, which is what lets the `handoff` update apply.

use crate::report::min_participants;
use le_sync_core::sync::{compute_domain, compute_signing_root, DOMAIN_SYNC_COMMITTEE};
use le_sync_core::{BeaconBlockHeader, Bytes32};
use le_sync_testkit as tk;
use le_sync_wire::stage::{initial_store_bytes, StageConfig};
use le_sync_wire::{GuestInput, SyncInput, UpdateWire, WireHeader};

const SPE: u64 = 8;
const EPP: u64 = 8;
const CHAIN_ID: u64 = 1;
const GVR: Bytes32 = [0xAA; 32];
const FORK: [u8; 4] = [5, 0, 0, 1];
const CURRENT_SLOT: u64 = 41;

pub struct World {
    pub cfg: StageConfig,
    /// `store_codec` v1 bytes of the bootstrap store.
    pub store: Vec<u8>,
    pub update: UpdateWire,
    pub total: usize,
    pub present: usize,
}

fn hdr(slot: u64, state_root: Bytes32, salt: u64) -> WireHeader {
    WireHeader {
        slot,
        proposer_index: salt,
        parent_root: tk::leaf(100 + salt),
        state_root,
        body_root: tk::leaf(200 + salt),
    }
}

fn root_of(h: &WireHeader) -> Bytes32 {
    BeaconBlockHeader::from(h).hash_tree_root()
}

fn signing_root(att: &WireHeader) -> Bytes32 {
    compute_signing_root(
        &root_of(att),
        &compute_domain(DOMAIN_SYNC_COMMITTEE, FORK, &GVR),
    )
}

/// Build the world for `n` members and one of `report::SCENARIOS`.
///
/// * `full`: finality-only update, every member signs.
/// * `min`: finality-only, the fewest signers the 2/3 gate accepts. The staged code subtracts
///   the absent keys from the committee aggregate, so this is the most absent keys it can face.
/// * `handoff`: the update also carries the next committee (and its branch), at the minimum
///   participation: the largest update, and the one that merkleizes a committee.
pub fn build(n: usize, scenario: &str) -> Result<World, String> {
    let (present, handoff) = match scenario {
        "full" => (n, false),
        "min" => (min_participants(n), false),
        "handoff" => (min_participants(n), true),
        other => return Err(format!("unknown scenario {other}")),
    };
    let cur = tk::committee(1, n);
    let next = tk::committee(2, n);

    // bootstrap: header at slot 8 whose state commits `cur` (and `next`)
    let boot_state = tk::state(1, &tk::leaf(1), &cur.root(), &next.root());
    let boot = hdr(8, boot_state.root, 1);

    // the update: attested state commits the same committees; finalized header at slot 24
    let salt = 2;
    let fin = hdr(24, tk::leaf(300 + salt), salt);
    let st = tk::state(salt, &root_of(&fin), &cur.root(), &next.root());
    let att = hdr(40, st.root, salt + 1);
    let bits = tk::bits_set(n, present);
    let signature = cur.sign(&bits, &signing_root(&att));
    let (next_pubkeys, next_aggregate, next_branch) = if handoff {
        (next.flat(), next.aggregate.to_vec(), st.next_branch.clone())
    } else {
        (vec![], vec![], vec![])
    };
    let update = UpdateWire {
        attested: att,
        next_pubkeys,
        next_aggregate,
        next_branch,
        finalized: fin,
        finality_branch: st.finality_branch,
        bits,
        signature: signature.to_vec(),
        signature_slot: 41,
    };

    let sync = SyncInput {
        chain_id: CHAIN_ID,
        genesis_validators_root: GVR,
        epochs_per_period: EPP,
        forks: vec![(0, FORK)],
        current_slot: CURRENT_SLOT,
        updates: vec![],
    };
    let input = GuestInput {
        slots_per_epoch: SPE,
        electra_fork_epoch: 0,
        gloas_fork_epoch: None,
        trusted_root: root_of(&boot),
        boot_header: boot,
        pubkeys: cur.flat(),
        aggregate: cur.aggregate.to_vec(),
        boot_branch: boot_state.cur_branch,
        finality: vec![],
        sync: Some(sync.clone()),
        state: None,
        log: None,
    };
    let cfg = StageConfig::from_input(&input, &sync);
    let store = initial_store_bytes(&input, &sync)
        .map_err(|e| format!("bootstrap store: error code {}", e.code()))?;
    Ok(World {
        cfg,
        store,
        update,
        total: n,
        present,
    })
}

/// Payload bytes of an update as it travels: committee keys, branches, bits, signature, headers.
pub fn update_bytes(u: &UpdateWire) -> usize {
    const HEADER: usize = 8 + 8 + 32 * 3;
    2 * HEADER
        + u.next_pubkeys.len()
        + u.next_aggregate.len()
        + 32 * (u.next_branch.len() + u.finality_branch.len())
        + u.bits.len()
        + u.signature.len()
        + 8
}
