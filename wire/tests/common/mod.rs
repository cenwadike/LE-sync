//! Wire-typed fixtures for the real-BLS suite. Crypto and tree helpers live in `le-sync-testkit`
//! (which deliberately does not depend on `le-sync-wire`).
#![allow(dead_code)]

use le_sync_core::sync::{compute_domain, compute_signing_root, Version, DOMAIN_SYNC_COMMITTEE};
use le_sync_core::{BeaconBlockHeader, Bytes32, Error, ZERO};
use le_sync_testkit as tk;
use le_sync_wire::bls::Impl;
use le_sync_wire::{
    build_chain_binding, verify_trace, FinalityItem, GuestInput, SyncInput, Trace, UpdateWire,
    WireHeader,
};

pub const SPE: u64 = 8;
pub const EPP: u64 = 8; // period = 64 slots
/// Greater than every signature slot used below.
pub const CURRENT_SLOT: u64 = 120;

/// Everything about a network that the signing domain / chain binding sees.
#[derive(Clone, Copy, Debug)]
pub struct Net {
    pub chain_id: u64,
    pub gvr: Bytes32,
    pub fork: Version,
}
pub const MAINNET: Net = Net {
    chain_id: 1,
    gvr: [0xAA; 32],
    fork: [5, 0, 0, 1],
};
pub const TESTNET: Net = Net {
    chain_id: 11_155_111,
    gvr: [0xBB; 32],
    fork: [0x90, 0, 0, 0x69],
};

pub fn full(n: usize) -> Vec<u8> {
    tk::bits_set(n, n)
}

pub fn hdr(slot: u64, state_root: Bytes32, salt: u64) -> WireHeader {
    WireHeader {
        slot,
        proposer_index: salt,
        parent_root: tk::leaf(100 + salt),
        state_root,
        body_root: tk::leaf(200 + salt),
    }
}
pub fn empty_hdr() -> WireHeader {
    WireHeader {
        slot: 0,
        proposer_index: 0,
        parent_root: ZERO,
        state_root: ZERO,
        body_root: ZERO,
    }
}
pub fn root_of(h: &WireHeader) -> Bytes32 {
    BeaconBlockHeader::from(h).hash_tree_root()
}

/// The signing root a committee of `net` signs for `att` (single-fork schedule).
pub fn signing_root(att: &WireHeader, net: &Net) -> Bytes32 {
    compute_signing_root(
        &root_of(att),
        &compute_domain(DOMAIN_SYNC_COMMITTEE, net.fork, &net.gvr),
    )
}

pub fn expected_binding(net: &Net) -> le_sync_core::sync::ChainBinding {
    build_chain_binding(SPE, EPP, net.chain_id, &net.gvr, &[(0, net.fork)]).unwrap()
}

/// Parameters of one self-consistent update. The attested state is built from the roots given
/// in `state_cur` / `state_next`; `signer` signs the attested header for the bits in `bits`.
pub struct Spec<'a> {
    pub att_slot: u64,
    pub fin_slot: u64,
    pub sig_slot: u64,
    pub salt: u64,
    pub state_cur: Bytes32,
    pub state_next: Bytes32,
    /// Committee carried in the update (with the branch from the attested state). It may differ
    /// from `state_next` to model a forged handoff.
    pub carry_next: Option<&'a tk::Committee>,
    pub signer: &'a tk::Committee,
    pub bits: Vec<u8>,
    pub net: &'a Net,
}

pub fn build_update(s: &Spec) -> UpdateWire {
    let fin = hdr(s.fin_slot, tk::leaf(300 + s.salt), s.salt);
    let st = tk::state(s.salt, &root_of(&fin), &s.state_cur, &s.state_next);
    let att = hdr(s.att_slot, st.root, s.salt + 1);
    let sig = s.signer.sign(&s.bits, &signing_root(&att, s.net));
    let (next_pubkeys, next_aggregate, next_branch) = match s.carry_next {
        Some(c) => (c.flat(), c.aggregate.to_vec(), st.next_branch.clone()),
        None => (vec![], vec![], vec![]),
    };
    UpdateWire {
        attested: att,
        next_pubkeys,
        next_aggregate,
        next_branch,
        finalized: fin,
        finality_branch: st.finality_branch,
        bits: s.bits.clone(),
        signature: sig.to_vec(),
        signature_slot: s.sig_slot,
    }
}

/// An honest world: a bootstrap at slot 8 (period 0) committing `cur`, with `next` as the
/// committee the chain will hand off to. The trusted root is the honest checkpoint.
pub struct Baseline {
    pub net: Net,
    pub cur: tk::Committee,
    pub next: tk::Committee,
    pub input: GuestInput, // no sync section
}

pub fn baseline(n: usize) -> Baseline {
    Baseline::new(MAINNET, tk::committee(1, n), tk::committee(2, n))
}

impl Baseline {
    pub fn new(net: Net, cur: tk::Committee, next: tk::Committee) -> Self {
        let boot_state = tk::state(1, &tk::leaf(1), &cur.root(), &next.root());
        let boot = hdr(8, boot_state.root, 1);
        let mut b = Baseline {
            net,
            input: GuestInput {
                slots_per_epoch: SPE,
                electra_fork_epoch: 0,
                gloas_fork_epoch: None,
                trusted_root: root_of(&boot),
                boot_header: boot,
                pubkeys: cur.flat(),
                aggregate: cur.aggregate.to_vec(),
                boot_branch: boot_state.cur_branch,
                finality: vec![],
                sync: None,
            },
            cur,
            next,
        };
        // Sprint 1 part of the input: the baseline update's finality branch.
        let u = b.update(full(b.cur.len()));
        b.input.finality = vec![FinalityItem {
            attested: u.attested,
            finalized: u.finalized,
            branch: u.finality_branch,
        }];
        b
    }

    /// Finality-only update (attested 40, finalized 24, signature slot 41) signed by `cur` for
    /// exactly `bits`. The baseline "valid update".
    pub fn update(&self, bits: Vec<u8>) -> UpdateWire {
        build_update(&Spec {
            att_slot: 40,
            fin_slot: 24,
            sig_slot: 41,
            salt: 2,
            state_cur: self.cur.root(),
            state_next: self.next.root(),
            carry_next: None,
            signer: &self.cur,
            bits,
            net: &self.net,
        })
    }

    pub fn sync_input(&self, net: &Net, updates: Vec<UpdateWire>) -> SyncInput {
        SyncInput {
            chain_id: net.chain_id,
            genesis_validators_root: net.gvr,
            epochs_per_period: EPP,
            forks: vec![(0, net.fork)],
            current_slot: CURRENT_SLOT,
            updates,
        }
    }

    /// The guest input presenting `updates` under this baseline's own network identity.
    pub fn input_with(&self, updates: Vec<UpdateWire>) -> GuestInput {
        self.input_with_net(&self.net, updates)
    }

    /// The guest input presenting `updates` under an arbitrary network identity.
    pub fn input_with_net(&self, net: &Net, updates: Vec<UpdateWire>) -> GuestInput {
        let mut i = self.input.clone();
        i.sync = Some(self.sync_input(net, updates));
        i
    }
}

/// Real BLS, per-update typed outcomes.
pub fn run(input: &GuestInput) -> Trace {
    verify_trace(input, &Impl)
}

/// A rejection that must be exactly `e`, not merely "rejected".
pub fn rejected(e: Error) -> le_sync_wire::UpdateOutcome {
    le_sync_wire::UpdateOutcome::Rejected(e)
}
