//! The instance of the LEZ program (Sprint 6, M2): what is written once, and how the tracked
//! light-client store starts (`no_std`, no alloc).
//!
//! An instance is one light client of one chain. It has two accounts of the program:
//!
//! * the **configuration** (`InstanceConfig`, 221 bytes): chain ID, genesis validators root,
//!   fork schedule, preset timing, committee size and the trusted checkpoint. It is written
//!   once by `init_instance` and no instruction changes it. Nothing in it is a program ID.
//! * the **store** (`store_codec` v2, 403 bytes): the tracked light-client state, moved by
//!   the staged update (`update_job`, `rooted`). It starts from the checkpoint (`init_store`).
//!
//! `InstanceConfig::id` (a digest of the canonical bytes) names the instance, so two instances
//! that differ in any field, the checkpoint included, never share accounts.
//!
//! Why `committee_size` is in the configuration: the keys root of a committee does not say how
//! many keys the committee has, and the bootstrap branch proves the root, not the count. The
//! count decides the shape of every multiproof and the length of the participation bits, so
//! it is fixed here, by whoever defines the instance, and every later check reads it from the
//! store that came from it.
//!
//! Initialising from a checkpoint needs no keys: the bootstrap carries the committee's keys
//! root and aggregate, and the branch proves `hash_tree_root(SyncCommittee)` of those two
//! under the checkpoint header's state root. The keys travel later, as hints, with the
//! updates that need them.
//!
//! Layout of the configuration, version 1 (integers little-endian, fixed width):
//!
//! ```text
//! version                 u8   = 1
//! chain_id                u64   a label: signatures do not cover it (see `ChainBinding`)
//! genesis_validators_root 32
//! slots_per_epoch         u64
//! epochs_per_period       u64
//! committee_size          u16   power of two, 1..=512
//! electra_fork_epoch      u64
//! gloas_fork_epoch        u8 flag (0 or 1), u64 (0 when the flag is 0)
//! fork count              u8   1..=MAX_FORKS
//! forks                   MAX_FORKS * (epoch:u64, version:4), unused entries zero
//! genesis_time            u64   beacon chain genesis, Unix seconds
//! seconds_per_slot        u64   non-zero
//! trusted_root            32   block root of the checkpoint header
//! ```
//!
//! The encoding is canonical: `decode` re-encodes what it parsed and accepts only if the bytes
//! are identical, so there is one encoding per configuration.
use crate::store_codec::{encode_store, ROOTED_ENCODED_LEN};
use crate::sync::{
    ChainBinding, ForkSchedule, LightClientStore, SyncCommittee, SyncConfig, Version, MAX_FORKS,
};
use crate::{
    is_valid_normalized_merkle_branch, BeaconBlockHeader, BlsPubkey, Bytes32, ChainConfig, Error,
    MAX_SYNC_COMMITTEE_SIZE,
};
use sha2::{Digest, Sha256};

pub const INSTANCE_VERSION: u8 = 1;

const FORK_ENTRY_LEN: usize = 8 + 4;

/// Encoded length of an `InstanceConfig`.
pub const INSTANCE_LEN: usize =
    1 + 8 + 32 + 8 + 8 + 2 + 8 + (1 + 8) + 1 + MAX_FORKS * FORK_ENTRY_LEN + 8 + 8 + 32;

/// The beacon chain's clock: what turns a LEZ timestamp into a slot (`InstanceConfig::slot_at`).
/// Part of the configuration, so the instance ID commits to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timing {
    /// Beacon chain genesis, Unix seconds.
    pub genesis_time: u64,
    pub seconds_per_slot: u64,
}

/// The configuration of an instance. Build it with `new` or `decode`; both validate.
#[derive(Clone, Copy, Debug)]
pub struct InstanceConfig {
    pub chain_id: u64,
    pub genesis_validators_root: Bytes32,
    pub slots_per_epoch: u64,
    pub epochs_per_period: u64,
    pub committee_size: u16,
    pub electra_fork_epoch: u64,
    pub gloas_fork_epoch: Option<u64>,
    pub forks: ForkSchedule,
    pub timing: Timing,
    /// Block root of the checkpoint header (weak subjectivity).
    pub trusted_root: Bytes32,
}

impl PartialEq for InstanceConfig {
    fn eq(&self, other: &Self) -> bool {
        self.encode() == other.encode()
    }
}
impl Eq for InstanceConfig {}

/// A write cursor over a fixed buffer.
struct Writer {
    buf: [u8; INSTANCE_LEN],
    at: usize,
}
impl Writer {
    fn put(&mut self, bytes: &[u8]) {
        self.buf[self.at..self.at + bytes.len()].copy_from_slice(bytes);
        self.at += bytes.len();
    }
}

/// A read cursor over bytes whose length has been checked to be `INSTANCE_LEN`.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] {
        let s = &self.bytes[self.at..self.at + n];
        self.at += n;
        s
    }
    fn u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        b.copy_from_slice(self.take(8));
        u64::from_le_bytes(b)
    }
    fn b32(&mut self) -> Bytes32 {
        let mut b = [0u8; 32];
        b.copy_from_slice(self.take(32));
        b
    }
}

impl InstanceConfig {
    /// A validated configuration. `BadConfig` for a zero slots or epochs count, a zero
    /// `seconds_per_slot`, an empty,
    /// over-long or unordered fork list, or a Gloas epoch that is not after the Electra one;
    /// `BadSyncCommitteeSize` for a committee size that is not a power of two up to 512.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: u64,
        genesis_validators_root: Bytes32,
        slots_per_epoch: u64,
        epochs_per_period: u64,
        committee_size: u16,
        electra_fork_epoch: u64,
        gloas_fork_epoch: Option<u64>,
        forks: &[(u64, Version)],
        timing: Timing,
        trusted_root: Bytes32,
    ) -> Result<Self, Error> {
        if slots_per_epoch == 0 || epochs_per_period == 0 || timing.seconds_per_slot == 0 {
            return Err(Error::BadConfig);
        }
        let size = committee_size as usize;
        if size == 0 || !size.is_power_of_two() || size > MAX_SYNC_COMMITTEE_SIZE {
            return Err(Error::BadSyncCommitteeSize);
        }
        if gloas_fork_epoch.is_some_and(|g| g <= electra_fork_epoch) {
            return Err(Error::BadConfig);
        }
        Ok(Self {
            chain_id,
            genesis_validators_root,
            slots_per_epoch,
            epochs_per_period,
            committee_size,
            electra_fork_epoch,
            gloas_fork_epoch,
            forks: ForkSchedule::new(forks)?,
            timing,
            trusted_root,
        })
    }

    pub fn encode(&self) -> [u8; INSTANCE_LEN] {
        let mut w = Writer {
            buf: [0u8; INSTANCE_LEN],
            at: 0,
        };
        w.put(&[INSTANCE_VERSION]);
        w.put(&self.chain_id.to_le_bytes());
        w.put(&self.genesis_validators_root);
        w.put(&self.slots_per_epoch.to_le_bytes());
        w.put(&self.epochs_per_period.to_le_bytes());
        w.put(&self.committee_size.to_le_bytes());
        w.put(&self.electra_fork_epoch.to_le_bytes());
        w.put(&[self.gloas_fork_epoch.is_some() as u8]);
        w.put(&self.gloas_fork_epoch.unwrap_or(0).to_le_bytes());
        let entries = self.forks.entries();
        w.put(&[entries.len() as u8]);
        for (epoch, version) in entries {
            w.put(&epoch.to_le_bytes());
            w.put(version);
        }
        // unused fork entries stay zero
        w.at += (MAX_FORKS - entries.len()) * FORK_ENTRY_LEN;
        w.put(&self.timing.genesis_time.to_le_bytes());
        w.put(&self.timing.seconds_per_slot.to_le_bytes());
        w.put(&self.trusted_root);
        w.buf
    }

    /// `InstanceEncoding` for anything but the canonical encoding of a valid configuration.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != INSTANCE_LEN || bytes[0] != INSTANCE_VERSION {
            return Err(Error::InstanceEncoding);
        }
        let mut r = Reader { bytes, at: 1 };
        let chain_id = r.u64();
        let genesis_validators_root = r.b32();
        let slots_per_epoch = r.u64();
        let epochs_per_period = r.u64();
        let mut size = [0u8; 2];
        size.copy_from_slice(r.take(2));
        let electra_fork_epoch = r.u64();
        let gloas_flag = r.take(1)[0];
        let gloas = r.u64();
        let count = r.take(1)[0] as usize;
        if count == 0 || count > MAX_FORKS {
            return Err(Error::InstanceEncoding);
        }
        let mut forks = [(0u64, [0u8; 4]); MAX_FORKS];
        for f in forks.iter_mut().take(count) {
            let epoch = r.u64();
            let mut v = [0u8; 4];
            v.copy_from_slice(r.take(4));
            *f = (epoch, v);
        }
        // the unused entries and the checkpoint root; padding is checked by the re-encode
        r.at += (MAX_FORKS - count) * FORK_ENTRY_LEN;
        let genesis_time = r.u64();
        let seconds_per_slot = r.u64();
        let trusted_root = r.b32();
        let cfg = Self::new(
            chain_id,
            genesis_validators_root,
            slots_per_epoch,
            epochs_per_period,
            u16::from_le_bytes(size),
            electra_fork_epoch,
            (gloas_flag != 0).then_some(gloas),
            &forks[..count],
            Timing {
                genesis_time,
                seconds_per_slot,
            },
            trusted_root,
        )
        .map_err(|_| Error::InstanceEncoding)?;
        if cfg.encode()[..] != *bytes {
            return Err(Error::InstanceEncoding);
        }
        Ok(cfg)
    }

    /// The chain parameters the light-client checks run under.
    pub fn chain(&self) -> ChainConfig {
        ChainConfig {
            slots_per_epoch: self.slots_per_epoch,
            electra_fork_epoch: self.electra_fork_epoch,
            gloas_fork_epoch: self.gloas_fork_epoch,
        }
    }

    pub fn sync_config(&self) -> SyncConfig {
        SyncConfig {
            chain: self.chain(),
            epochs_per_period: self.epochs_per_period,
            genesis_validators_root: self.genesis_validators_root,
            forks: self.forks,
        }
    }

    /// The slot the beacon chain is at when the LEZ clock reads `timestamp_ms` (LEZ timestamps
    /// are milliseconds): whole seconds since genesis over `seconds_per_slot`, and slot 0 for a
    /// clock before genesis.
    pub fn slot_at(&self, timestamp_ms: u64) -> u64 {
        (timestamp_ms / 1000).saturating_sub(self.timing.genesis_time)
            / self.timing.seconds_per_slot
    }

    /// The chain binding statements of this instance commit to.
    pub fn binding(&self) -> ChainBinding {
        self.sync_config().binding(self.chain_id)
    }

    /// `SHA256("LE_SYNC_INSTANCE_V1" || encode())`: names the instance, and is what its
    /// account addresses are derived from.
    pub fn id(&self) -> Bytes32 {
        let mut h = Sha256::new();
        h.update(b"LE_SYNC_INSTANCE_V1");
        h.update(self.encode());
        h.finalize().into()
    }

    /// `CheckpointStale` if `store`'s finalized header is more than the weak-subjectivity
    /// limit behind `current_slot`. Not a spec rule: an operator guideline.
    pub fn check_fresh(&self, store: &LightClientStore, current_slot: u64) -> Result<(), Error> {
        store.assert_within_weak_subjectivity_period(
            current_slot,
            self.slots_per_epoch,
            self.epochs_per_period,
        )
    }
}

/// True for an account with nothing written: no bytes, or only zero bytes.
pub fn is_blank(data: &[u8]) -> bool {
    data.iter().all(|b| *b == 0)
}

/// `AlreadyInitialized` unless `data` is blank. `init_instance` calls it on every account it
/// writes, so a configuration or a store is written once.
pub fn ensure_blank(data: &[u8]) -> Result<(), Error> {
    if is_blank(data) {
        Ok(())
    } else {
        Err(Error::AlreadyInitialized)
    }
}

/// What `init_instance` is given: the checkpoint header, and the current sync committee of
/// its state as a keys root and an aggregate, with the branch that proves them.
#[derive(Clone, Copy, Debug)]
pub struct Bootstrap<'a> {
    pub header: BeaconBlockHeader,
    pub keys_root: Bytes32,
    pub aggregate: BlsPubkey,
    pub branch: &'a [Bytes32],
}

/// The store an instance starts from. The checks, in order:
/// 1. the header hashes to `cfg.trusted_root` (`TrustedRootMismatch`);
/// 2. the fork at its slot is supported (`UnsupportedFork`, `BadConfig`);
/// 3. the branch proves the committee (`keys_root`, `aggregate`) under the header's state
///    root (`InvalidBranch`);
/// 4. the checkpoint is within the weak-subjectivity limit of `current_slot`
///    (`CheckpointStale`).
///
/// Both heads start at the checkpoint, the next committee is unknown, and the committee has
/// `cfg.committee_size` keys, held as the root.
pub fn init_store(
    cfg: &InstanceConfig,
    boot: &Bootstrap,
    current_slot: u64,
) -> Result<LightClientStore, Error> {
    if boot.header.hash_tree_root() != cfg.trusted_root {
        return Err(Error::TrustedRootMismatch);
    }
    let gindex = cfg
        .chain()
        .gindices_at_slot(boot.header.slot)?
        .current_sync_committee;
    let committee =
        SyncCommittee::rooted(cfg.committee_size as usize, boot.keys_root, boot.aggregate)?;
    if !is_valid_normalized_merkle_branch(
        &committee.root()?,
        boot.branch,
        gindex,
        &boot.header.state_root,
    ) {
        return Err(Error::InvalidBranch);
    }
    let store = LightClientStore {
        finalized_header: boot.header,
        current_sync_committee: committee,
        next_sync_committee: SyncCommittee::empty(cfg.committee_size as usize),
        optimistic_header: boot.header,
        previous_max_active_participants: 0,
        current_max_active_participants: 0,
        best_valid_update: None,
    };
    cfg.check_fresh(&store, current_slot)?;
    Ok(store)
}

/// `init_store`, as the 403 bytes of the store account.
pub fn init_store_bytes(
    cfg: &InstanceConfig,
    boot: &Bootstrap,
    current_slot: u64,
) -> Result<[u8; ROOTED_ENCODED_LEN], Error> {
    let store = init_store(cfg, boot, current_slot)?;
    let mut out = [0u8; ROOTED_ENCODED_LEN];
    let n = encode_store(&store, &mut out)?;
    debug_assert_eq!(n, ROOTED_ENCODED_LEN);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store_codec::decode_store;
    use crate::sync::tests::{leaf_n, N};
    use crate::{hash_pair, pubkeys_root};

    const GVR: Bytes32 = [0xAA; 32];
    const FV: Version = [5, 0, 0, 1];
    const TIMING: Timing = Timing {
        genesis_time: 1_606_824_023,
        seconds_per_slot: 12,
    };

    fn config(trusted_root: Bytes32) -> InstanceConfig {
        InstanceConfig::new(
            1,
            GVR,
            8,
            8,
            N as u16,
            0,
            None,
            &[(0, FV), (7, [6, 0, 0, 1])],
            TIMING,
            trusted_root,
        )
        .unwrap()
    }

    fn keys(seed: u64) -> Vec<BlsPubkey> {
        (0..N as u64)
            .map(|i| {
                let mut k = [0u8; 48];
                k[..32].copy_from_slice(&leaf_n(seed * 1000 + i));
                k
            })
            .collect()
    }

    /// A BeaconState-shaped tree of 64 leaves with the committee root at field 22 (Electra
    /// gindex 86). Returns the state root and the branch.
    fn state_with(committee_root: Bytes32) -> (Bytes32, Vec<Bytes32>) {
        let mut level: Vec<Bytes32> = (0..64).map(|i| leaf_n(5000 + i)).collect();
        level[22] = committee_root;
        let mut idx = 22usize;
        let mut branch = vec![];
        while level.len() > 1 {
            branch.push(level[idx ^ 1]);
            level = level.chunks(2).map(|p| hash_pair(&p[0], &p[1])).collect();
            idx /= 2;
        }
        (level[0], branch)
    }

    struct World {
        cfg: InstanceConfig,
        header: BeaconBlockHeader,
        keys_root: Bytes32,
        aggregate: BlsPubkey,
        branch: Vec<Bytes32>,
    }
    impl World {
        fn boot(&self) -> Bootstrap<'_> {
            Bootstrap {
                header: self.header,
                keys_root: self.keys_root,
                aggregate: self.aggregate,
                branch: &self.branch,
            }
        }
    }
    fn world() -> World {
        let ks = keys(1);
        let keys_root = pubkeys_root(&ks).unwrap();
        let mut aggregate = [0u8; 48];
        aggregate[..32].copy_from_slice(&leaf_n(1999));
        let committee = SyncCommittee::rooted(N, keys_root, aggregate).unwrap();
        let (state_root, branch) = state_with(committee.root().unwrap());
        let header = BeaconBlockHeader {
            slot: 8,
            proposer_index: 1,
            parent_root: leaf_n(100),
            state_root,
            body_root: leaf_n(200),
        };
        World {
            cfg: config(header.hash_tree_root()),
            header,
            keys_root,
            aggregate,
            branch,
        }
    }

    // ---- the configuration encoding -----------------------------------------------------

    #[test]
    fn the_fork_count_may_reach_the_cap_and_no_further() {
        let forks: Vec<(u64, Version)> = (0..MAX_FORKS as u64)
            .map(|i| (i * 3, [i as u8, 0, 0, 1]))
            .collect();
        let full =
            InstanceConfig::new(1, GVR, 8, 8, N as u16, 0, None, &forks, TIMING, [7; 32]).unwrap();
        let b = full.encode();
        assert_eq!(b[76], MAX_FORKS as u8);
        assert_eq!(InstanceConfig::decode(&b).unwrap(), full);
        // one more than the cap is refused by the constructor and by the decoder
        let mut over = forks.clone();
        over.push((99, [9, 0, 0, 1]));
        assert!(
            InstanceConfig::new(1, GVR, 8, 8, N as u16, 0, None, &over, TIMING, [7; 32]).is_err()
        );
        let mut bad = b.clone();
        bad[76] = MAX_FORKS as u8 + 1;
        assert_eq!(
            InstanceConfig::decode(&bad).err(),
            Some(Error::InstanceEncoding)
        );
        bad[76] = 0;
        assert_eq!(
            InstanceConfig::decode(&bad).err(),
            Some(Error::InstanceEncoding)
        );
    }

    #[test]
    fn encoding_is_221_bytes_with_each_field_at_its_offset() {
        assert_eq!(INSTANCE_LEN, 221);
        let c = InstanceConfig::new(
            0x0102_0304_0506_0708,
            [0x11; 32],
            0x21,
            0x22,
            0x0100,
            0x23,
            Some(0x24),
            &[(0, [1, 2, 3, 4]), (0x25, [5, 6, 7, 8])],
            Timing {
                genesis_time: 0x41,
                seconds_per_slot: 0x42,
            },
            [0x33; 32],
        )
        .unwrap();
        let b = c.encode();
        assert_eq!(b.len(), INSTANCE_LEN);
        assert_eq!(b[0], INSTANCE_VERSION);
        assert_eq!(b[1..9], 0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(b[9..41], [0x11; 32]);
        assert_eq!(b[41..49], 0x21u64.to_le_bytes());
        assert_eq!(b[49..57], 0x22u64.to_le_bytes());
        assert_eq!(b[57..59], 0x0100u16.to_le_bytes());
        assert_eq!(b[59..67], 0x23u64.to_le_bytes());
        assert_eq!(b[67], 1);
        assert_eq!(b[68..76], 0x24u64.to_le_bytes());
        assert_eq!(b[76], 2);
        assert_eq!(b[77..85], 0u64.to_le_bytes());
        assert_eq!(b[85..89], [1, 2, 3, 4]);
        assert_eq!(b[89..97], 0x25u64.to_le_bytes());
        assert_eq!(b[97..101], [5, 6, 7, 8]);
        assert!(b[101..173].iter().all(|x| *x == 0), "unused fork entries");
        assert_eq!(b[173..181], 0x41u64.to_le_bytes());
        assert_eq!(b[181..189], 0x42u64.to_le_bytes());
        assert_eq!(b[189..221], [0x33; 32]);
        assert_eq!(InstanceConfig::decode(&b), Ok(c));
    }

    #[test]
    fn a_zero_seconds_per_slot_is_refused() {
        let t = Timing {
            seconds_per_slot: 0,
            ..TIMING
        };
        assert_eq!(
            InstanceConfig::new(1, GVR, 8, 8, 32, 0, None, &[(0, FV)], t, [1; 32]),
            Err(Error::BadConfig)
        );
    }

    #[test]
    fn slot_at_counts_whole_seconds_since_genesis_in_slots() {
        let c = config([1; 32]);
        let g_ms = TIMING.genesis_time * 1000;
        assert_eq!(c.slot_at(g_ms), 0);
        assert_eq!(c.slot_at(g_ms + 11_999), 0);
        assert_eq!(c.slot_at(g_ms + 12_000), 1);
        assert_eq!(c.slot_at(g_ms + 12 * 41 * 1000 + 5), 41);
        // before genesis, and at the epoch start of the clock itself
        assert_eq!(c.slot_at(g_ms - 1), 0);
        assert_eq!(c.slot_at(0), 0);
        assert_eq!(
            c.slot_at(u64::MAX),
            (u64::MAX / 1000 - TIMING.genesis_time) / 12
        );
    }

    #[test]
    fn no_gloas_epoch_is_a_zero_flag_and_zero_value() {
        let b = config([1; 32]).encode();
        assert_eq!(b[67], 0);
        assert_eq!(b[68..76], [0u8; 8]);
        // a Gloas epoch of zero is not the same as none (it is refused: not after Electra)
        assert_eq!(
            InstanceConfig::new(1, GVR, 8, 8, 32, 0, Some(0), &[(0, FV)], TIMING, [1; 32]),
            Err(Error::BadConfig)
        );
        let c =
            InstanceConfig::new(1, GVR, 8, 8, 32, 0, Some(1), &[(0, FV)], TIMING, [1; 32]).unwrap();
        assert_eq!(c.encode()[67], 1);
        assert_eq!(InstanceConfig::decode(&c.encode()), Ok(c));
    }

    #[test]
    fn every_byte_matters_and_every_flip_is_refused_or_another_config() {
        let c = config([9; 32]);
        let b = c.encode();
        for i in 0..INSTANCE_LEN {
            let mut f = b;
            f[i] ^= 1;
            match InstanceConfig::decode(&f) {
                Err(e) => assert_eq!(e, Error::InstanceEncoding, "byte {i}"),
                Ok(other) => {
                    assert_ne!(other, c, "byte {i}");
                    assert_eq!(other.encode(), f, "byte {i}");
                }
            }
        }
    }

    #[test]
    fn non_canonical_or_invalid_bytes_are_instance_encoding() {
        let b = config([9; 32]).encode();
        let bad = Error::InstanceEncoding;
        assert_eq!(InstanceConfig::decode(&b[..INSTANCE_LEN - 1]), Err(bad));
        assert_eq!(InstanceConfig::decode(&[]), Err(bad));
        let mut longer = b.to_vec();
        longer.push(0);
        assert_eq!(InstanceConfig::decode(&longer), Err(bad));
        let edit = |f: &dyn Fn(&mut [u8; INSTANCE_LEN])| {
            let mut x = b;
            f(&mut x);
            InstanceConfig::decode(&x)
        };
        assert_eq!(edit(&|x| x[0] = 0), Err(bad));
        assert_eq!(edit(&|x| x[0] = 2), Err(bad));
        assert_eq!(edit(&|x| x[41..49].fill(0)), Err(bad)); // zero slots per epoch
        assert_eq!(edit(&|x| x[49..57].fill(0)), Err(bad)); // zero epochs per period
        assert_eq!(edit(&|x| x[57..59].fill(0)), Err(bad)); // committee size 0
        assert_eq!(
            edit(&|x| x[57..59].copy_from_slice(&24u16.to_le_bytes())),
            Err(bad)
        );
        assert_eq!(
            edit(&|x| x[57..59].copy_from_slice(&1024u16.to_le_bytes())),
            Err(bad)
        );
        assert_eq!(edit(&|x| x[67] = 2), Err(bad)); // flag is 0 or 1
        assert_eq!(edit(&|x| x[68] = 1), Err(bad)); // a value with no flag
        assert_eq!(edit(&|x| x[76] = 0), Err(bad)); // no forks
        assert_eq!(edit(&|x| x[76] = (MAX_FORKS + 1) as u8), Err(bad));
        // padding after the last fork must be zero
        assert_eq!(edit(&|x| x[101] = 1), Err(bad));
        assert_eq!(edit(&|x| x[172] = 1), Err(bad));
        // forks out of order
        assert_eq!(
            edit(&|x| {
                x[77..85].copy_from_slice(&9u64.to_le_bytes());
            }),
            Err(bad)
        );
    }

    #[test]
    fn new_names_each_invalid_field() {
        let ok = |size: u16, spe: u64, epp: u64, forks: &[(u64, Version)]| {
            InstanceConfig::new(1, GVR, spe, epp, size, 0, None, forks, TIMING, [1; 32])
        };
        assert!(ok(32, 8, 8, &[(0, FV)]).is_ok());
        assert_eq!(ok(32, 0, 8, &[(0, FV)]), Err(Error::BadConfig));
        assert_eq!(ok(32, 8, 0, &[(0, FV)]), Err(Error::BadConfig));
        assert_eq!(ok(32, 8, 8, &[]), Err(Error::BadConfig));
        assert_eq!(ok(32, 8, 8, &[(5, FV), (1, FV)]), Err(Error::BadConfig));
        let nine = [(0, FV); MAX_FORKS + 1];
        assert_eq!(ok(32, 8, 8, &nine), Err(Error::BadConfig));
        for size in [0u16, 3, 24, 513, 1024] {
            assert_eq!(
                ok(size, 8, 8, &[(0, FV)]),
                Err(Error::BadSyncCommitteeSize),
                "{size}"
            );
        }
        for size in [1u16, 2, 8, 32, 512] {
            assert!(ok(size, 8, 8, &[(0, FV)]).is_ok(), "{size}");
        }
        // Gloas must come after Electra
        let g = |electra: u64, gloas: Option<u64>| {
            InstanceConfig::new(
                1,
                GVR,
                8,
                8,
                32,
                electra,
                gloas,
                &[(0, FV)],
                TIMING,
                [1; 32],
            )
        };
        assert!(g(5, Some(6)).is_ok());
        assert_eq!(g(5, Some(5)), Err(Error::BadConfig));
        assert_eq!(g(5, Some(4)), Err(Error::BadConfig));
        assert!(g(5, None).is_ok());
    }

    #[test]
    fn equality_is_by_the_canonical_bytes() {
        let a = config([1; 32]);
        assert_eq!(a, config([1; 32]));
        assert_ne!(a, config([2; 32]));
        let other_forks =
            InstanceConfig::new(1, GVR, 8, 8, N as u16, 0, None, &[(0, FV)], TIMING, [1; 32])
                .unwrap();
        assert_ne!(a, other_forks);
    }

    #[test]
    fn id_names_the_instance_and_changes_with_every_field() {
        let base = config([1; 32]);
        assert_eq!(base.id(), config([1; 32]).id());
        let mut seen = vec![base.id()];
        let mut push = |c: Result<InstanceConfig, Error>| {
            let id = c.unwrap().id();
            assert!(!seen.contains(&id));
            seen.push(id);
        };
        let n = N as u16;
        let f = [(0, FV), (7, [6, 0, 0, 1])];
        push(InstanceConfig::new(
            2, GVR, 8, 8, n, 0, None, &f, TIMING, [1; 32],
        ));
        push(InstanceConfig::new(
            1, [0xBB; 32], 8, 8, n, 0, None, &f, TIMING, [1; 32],
        ));
        push(InstanceConfig::new(
            1, GVR, 16, 8, n, 0, None, &f, TIMING, [1; 32],
        ));
        push(InstanceConfig::new(
            1, GVR, 8, 16, n, 0, None, &f, TIMING, [1; 32],
        ));
        push(InstanceConfig::new(
            1, GVR, 8, 8, 64, 0, None, &f, TIMING, [1; 32],
        ));
        push(InstanceConfig::new(
            1, GVR, 8, 8, n, 1, None, &f, TIMING, [1; 32],
        ));
        push(InstanceConfig::new(
            1,
            GVR,
            8,
            8,
            n,
            0,
            Some(9),
            &f,
            TIMING,
            [1; 32],
        ));
        push(InstanceConfig::new(
            1,
            GVR,
            8,
            8,
            n,
            0,
            None,
            &f[..1],
            TIMING,
            [1; 32],
        ));
        push(InstanceConfig::new(
            1, GVR, 8, 8, n, 0, None, &f, TIMING, [2; 32],
        ));
        for t in [
            Timing {
                genesis_time: TIMING.genesis_time + 1,
                ..TIMING
            },
            Timing {
                seconds_per_slot: 6,
                ..TIMING
            },
        ] {
            push(InstanceConfig::new(
                1, GVR, 8, 8, n, 0, None, &f, t, [1; 32],
            ));
        }
        // domain separated: not the plain hash of the bytes
        let mut h = Sha256::new();
        h.update(base.encode());
        let plain: Bytes32 = h.finalize().into();
        assert_ne!(base.id(), plain);
    }

    #[test]
    fn the_config_gives_the_sync_parameters_and_the_binding() {
        let c = InstanceConfig::new(
            7,
            GVR,
            32,
            256,
            512,
            74_240,
            Some(999_999),
            &[(0, FV), (5, [6, 0, 0, 1])],
            TIMING,
            [1; 32],
        )
        .unwrap();
        let s = c.sync_config();
        assert_eq!(s.chain.slots_per_epoch, 32);
        assert_eq!(s.chain.electra_fork_epoch, 74_240);
        assert_eq!(s.chain.gloas_fork_epoch, Some(999_999));
        assert_eq!(s.epochs_per_period, 256);
        assert_eq!(s.genesis_validators_root, GVR);
        assert_eq!(s.forks.entries(), &[(0, FV), (5, [6, 0, 0, 1])]);
        let b = c.binding();
        assert_eq!(b, s.binding(7));
        assert_eq!(b.chain_id, 7);
        assert_eq!(b.slots_per_epoch, 32);
        assert_eq!(b.epochs_per_period, 256);
        assert_eq!(b.fork_schedule_hash, s.forks.hash());
        assert_eq!(c.chain().gloas_fork_epoch, Some(999_999));
    }

    // ---- write once ---------------------------------------------------------------------

    #[test]
    fn blank_accounts_are_empty_or_all_zero() {
        assert!(is_blank(&[]));
        assert!(is_blank(&[0; 205]));
        assert!(!is_blank(&[0, 0, 1]));
        assert!(!is_blank(&[1]));
        assert!(!is_blank(&config([1; 32]).encode()));
        assert_eq!(ensure_blank(&[]), Ok(()));
        assert_eq!(ensure_blank(&[0; 403]), Ok(()));
        assert_eq!(ensure_blank(&[0, 1]), Err(Error::AlreadyInitialized));
        let mut last = [0u8; 403];
        last[402] = 1;
        assert_eq!(ensure_blank(&last), Err(Error::AlreadyInitialized));
    }

    // ---- the store an instance starts from ------------------------------------------------

    #[test]
    fn init_builds_the_rooted_checkpoint_store() {
        let w = world();
        let s = init_store(&w.cfg, &w.boot(), 41).unwrap();
        assert_eq!(s.finalized_header, w.header);
        assert_eq!(s.optimistic_header, w.header);
        assert_eq!(s.current_sync_committee.len, N);
        assert!(s.current_sync_committee.is_rooted());
        assert_eq!(
            s.current_sync_committee.stored_keys_root(),
            Some(w.keys_root)
        );
        assert_eq!(s.current_sync_committee.aggregate_pubkey, w.aggregate);
        assert!(!s.is_next_sync_committee_known());
        assert_eq!(s.next_sync_committee.len, N);
        assert_eq!(
            (
                s.previous_max_active_participants,
                s.current_max_active_participants
            ),
            (0, 0)
        );
        assert!(s.best_valid_update.is_none());
    }

    #[test]
    fn init_bytes_are_the_403_byte_v2_store() {
        let w = world();
        let b = init_store_bytes(&w.cfg, &w.boot(), 41).unwrap();
        assert_eq!(b.len(), 403);
        assert_eq!(b[0], 2);
        let s = decode_store(&b).unwrap();
        let direct = init_store(&w.cfg, &w.boot(), 41).unwrap();
        assert_eq!(s.finalized_header, direct.finalized_header);
        assert_eq!(s.current_sync_committee, direct.current_sync_committee);
        assert_eq!(s.next_sync_committee, direct.next_sync_committee);
        // the same bootstrap gives the same bytes
        assert_eq!(b, init_store_bytes(&w.cfg, &w.boot(), 41).unwrap());
        // errors pass through
        assert_eq!(
            init_store_bytes(&w.cfg, &w.boot(), 5 * 64),
            Err(Error::CheckpointStale)
        );
    }

    #[test]
    fn a_header_that_is_not_the_checkpoint_is_refused() {
        let w = world();
        let mut b = w.boot();
        b.header.proposer_index += 1;
        assert_eq!(
            init_store(&w.cfg, &b, 41).err(),
            Some(Error::TrustedRootMismatch)
        );
        // the configuration names the checkpoint: another one refuses this header
        let other = config([7; 32]);
        assert_eq!(
            init_store(&other, &w.boot(), 41).err(),
            Some(Error::TrustedRootMismatch)
        );
    }

    #[test]
    fn a_committee_the_state_does_not_hold_is_refused() {
        let w = world();
        let mut b = w.boot();
        b.keys_root[0] ^= 1;
        assert_eq!(init_store(&w.cfg, &b, 41).err(), Some(Error::InvalidBranch));
        let mut b = w.boot();
        b.aggregate[0] ^= 1;
        assert_eq!(init_store(&w.cfg, &b, 41).err(), Some(Error::InvalidBranch));
        for i in 0..w.branch.len() {
            let mut br = w.branch.clone();
            br[i][0] ^= 1;
            let b = Bootstrap {
                branch: &br,
                ..w.boot()
            };
            assert_eq!(
                init_store(&w.cfg, &b, 41).err(),
                Some(Error::InvalidBranch),
                "{i}"
            );
        }
        let short = &w.branch[..w.branch.len() - 1];
        let b = Bootstrap {
            branch: short,
            ..w.boot()
        };
        assert_eq!(init_store(&w.cfg, &b, 41).err(), Some(Error::InvalidBranch));
        // the committee at the wrong field: the next committee's slot is not the current one
        let committee = SyncCommittee::rooted(N, w.keys_root, w.aggregate).unwrap();
        let (_, b23) = {
            let mut level: Vec<Bytes32> = (0..64).map(|i| leaf_n(5000 + i)).collect();
            level[23] = committee.root().unwrap();
            let mut idx = 23usize;
            let mut branch = vec![];
            while level.len() > 1 {
                branch.push(level[idx ^ 1]);
                level = level.chunks(2).map(|p| hash_pair(&p[0], &p[1])).collect();
                idx /= 2;
            }
            (level[0], branch)
        };
        let b = Bootstrap {
            branch: &b23,
            ..w.boot()
        };
        assert_eq!(init_store(&w.cfg, &b, 41).err(), Some(Error::InvalidBranch));
    }

    #[test]
    fn the_committee_size_comes_from_the_configuration() {
        // the same root and branch under a configuration of another size give a store of that
        // size: the size is the instance's, and `instance.id()` differs with it
        let w = world();
        let c = InstanceConfig::new(
            1,
            GVR,
            8,
            8,
            64,
            0,
            None,
            &[(0, FV)],
            TIMING,
            w.header.hash_tree_root(),
        )
        .unwrap();
        let s = init_store(&c, &w.boot(), 41).unwrap();
        assert_eq!(s.current_sync_committee.len, 64);
        assert_eq!(s.next_sync_committee.len, 64);
        assert_ne!(c.id(), w.cfg.id());
    }

    #[test]
    fn an_unsupported_fork_at_the_checkpoint_is_refused() {
        let w = world();
        // Gloas from epoch 1: the checkpoint at slot 8 (epoch 1) is in the unsupported era
        let c = InstanceConfig::new(
            1,
            GVR,
            8,
            8,
            N as u16,
            0,
            Some(1),
            &[(0, FV)],
            TIMING,
            w.header.hash_tree_root(),
        )
        .unwrap();
        assert_eq!(
            init_store(&c, &w.boot(), 41).err(),
            Some(Error::UnsupportedFork)
        );
    }

    #[test]
    fn a_stale_checkpoint_is_refused_at_the_limit() {
        let w = world(); // finalized slot 8: period 0 (64-slot periods)
        assert!(init_store(&w.cfg, &w.boot(), 4 * 64).is_ok());
        assert_eq!(
            init_store(&w.cfg, &w.boot(), 5 * 64).err(),
            Some(Error::CheckpointStale)
        );
        let s = init_store(&w.cfg, &w.boot(), 41).unwrap();
        assert_eq!(w.cfg.check_fresh(&s, 4 * 64), Ok(()));
        assert_eq!(w.cfg.check_fresh(&s, 5 * 64), Err(Error::CheckpointStale));
        // the period length is the configuration's
        let long = InstanceConfig::new(
            1,
            GVR,
            8,
            16,
            N as u16,
            0,
            None,
            &[(0, FV)],
            TIMING,
            w.cfg.trusted_root,
        )
        .unwrap();
        assert_eq!(long.check_fresh(&s, 5 * 64), Ok(()));
        assert_eq!(long.check_fresh(&s, 5 * 128), Err(Error::CheckpointStale));
    }
}
