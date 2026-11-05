//! The decisions of the submitter, as pure functions: no network, no chain, no clock.
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdateReadiness {
    Ready,
    WaitingForSignature(u64),
    InvalidSlotOrder,
}

/// Whether an update satisfies `current >= signature > attested >= finalized`.
/// A future signature is transient; either of the other ordering failures is invalid data.
pub fn update_readiness(
    current_slot: u64,
    signature_slot: u64,
    attested_slot: u64,
    finalized_slot: u64,
) -> UpdateReadiness {
    if signature_slot <= attested_slot || attested_slot < finalized_slot {
        UpdateReadiness::InvalidSlotOrder
    } else if current_slot < signature_slot {
        UpdateReadiness::WaitingForSignature(signature_slot)
    } else {
        UpdateReadiness::Ready
    }
}

/// Sync-committee period of a slot.
pub fn sync_period(slot: u64, slots_per_epoch: u64, epochs_per_period: u64) -> u64 {
    slot / (slots_per_epoch * epochs_per_period)
}

/// What the tracked store needs from the beacon API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Need {
    /// Fetch the period updates `start_period..start_period + count` (they carry the next
    /// committee), then the latest finality update.
    pub start_period: u64,
    pub count: u64,
}

/// `store_period`: period of the store's finalized header; `next_known`: whether the store
/// already holds the next committee; `head_period`: period of the newest finalized header.
/// `None` means the finality update alone is enough.
pub fn period_updates_needed(
    store_period: u64,
    next_known: bool,
    head_period: u64,
) -> Option<Need> {
    if head_period > store_period || !next_known {
        // the beacon API serves at most 128 updates per request
        let count = (head_period.saturating_sub(store_period) + 1).min(128);
        Some(Need {
            start_period: store_period,
            count,
        })
    } else {
        None
    }
}

/// An update is worth trying if it finalizes a newer header than the store has, or if it carries
/// the next committee the store does not have yet. The program (and the native check made before
/// any transaction) decides whether it actually applies.
pub fn worth_trying(
    store_finalized_slot: u64,
    store_next_known: bool,
    update_finalized_slot: u64,
    update_carries_next: bool,
) -> bool {
    update_finalized_slot > store_finalized_slot || (update_carries_next && !store_next_known)
}

/// How long to hold back before submitting: a number in `0..max_ms` that depends on who is
/// asking (`operator`), the instance and the update's finalized slot, so over many updates the
/// cost falls on different operators. `max_ms == 0` means no deferral.
pub fn defer_ms(operator: &[u8], instance_id: &[u8; 32], finalized_slot: u64, max_ms: u64) -> u64 {
    if max_ms == 0 {
        return 0;
    }
    let mut h = Sha256::new();
    h.update(b"le-sync/defer/v1");
    h.update(operator);
    h.update(instance_id);
    h.update(finalized_slot.to_le_bytes());
    let d = h.finalize();
    u64::from_le_bytes(d[..8].try_into().unwrap()) % max_ms
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_waits_for_a_future_signature_slot_but_rejects_bad_intrinsic_order() {
        assert_eq!(
            update_readiness(100, 101, 100, 99),
            UpdateReadiness::WaitingForSignature(101)
        );
        assert_eq!(update_readiness(101, 101, 100, 99), UpdateReadiness::Ready);
        assert_eq!(
            update_readiness(101, 100, 100, 99),
            UpdateReadiness::InvalidSlotOrder
        );
        assert_eq!(
            update_readiness(101, 101, 98, 99),
            UpdateReadiness::InvalidSlotOrder
        );
    }

    #[test]
    fn periods_are_slots_over_a_period() {
        assert_eq!(sync_period(0, 32, 256), 0);
        assert_eq!(sync_period(8191, 32, 256), 0);
        assert_eq!(sync_period(8192, 32, 256), 1);
    }

    #[test]
    fn a_handoff_is_needed_when_the_head_is_in_a_later_period_or_the_next_committee_is_unknown() {
        assert_eq!(period_updates_needed(5, true, 5), None);
        assert_eq!(
            period_updates_needed(5, false, 5),
            Some(Need {
                start_period: 5,
                count: 1
            })
        );
        assert_eq!(
            period_updates_needed(5, true, 7),
            Some(Need {
                start_period: 5,
                count: 3
            })
        );
        assert_eq!(
            period_updates_needed(0, true, 1000),
            Some(Need {
                start_period: 0,
                count: 128
            })
        );
    }

    #[test]
    fn an_update_is_worth_trying_only_if_it_moves_something() {
        assert!(worth_trying(10, true, 11, false));
        assert!(!worth_trying(10, true, 10, false));
        assert!(!worth_trying(10, true, 9, true));
        assert!(worth_trying(10, false, 10, true));
        assert!(!worth_trying(10, false, 10, false));
    }

    #[test]
    fn the_deferral_is_bounded_and_depends_on_every_input() {
        let id = [7u8; 32];
        let d = defer_ms(b"op-a", &id, 100, 5_000);
        assert!(d < 5_000);
        assert_eq!(d, defer_ms(b"op-a", &id, 100, 5_000));
        assert_eq!(defer_ms(b"op-a", &id, 100, 0), 0);
        // different operators, instances and slots spread out (not all equal)
        let ds: Vec<u64> = (0..50)
            .map(|i| defer_ms(format!("op-{i}").as_bytes(), &id, 100, 5_000))
            .collect();
        assert!(ds.iter().any(|x| *x != ds[0]));
        let ds: Vec<u64> = (0..50).map(|s| defer_ms(b"op-a", &id, s, 5_000)).collect();
        assert!(ds.iter().any(|x| *x != ds[0]));
        let mut other = id;
        other[0] ^= 1;
        let ds: Vec<u64> = (0..50)
            .map(|s| {
                defer_ms(
                    b"op-a",
                    &if s % 2 == 0 { id } else { other },
                    100 + s / 2,
                    5_000,
                )
            })
            .collect();
        assert!(ds.iter().any(|x| *x != ds[0]));
    }
}
