//! Measurement for the "committee as a root" design: what one `begin`-like step costs when the
//! account holds only the committee ROOT and aggregate, and the update carries the keys it needs.
//!
//! Account (one, 176 bytes): committee tree root (32) || aggregate key, compressed (48) ||
//! expected sum of the PRESENT keys, uncompressed (96). The last field is a test oracle, so the
//! bench can tell that the arithmetic is right; a real program does not store it.
//! Instruction (`AggMsg`): the absent keys as 96-byte uncompressed points, their leaf positions,
//! and the Merkle multiproof siblings, either as bytes or packed four to a word (`--pack`).
//!
//! The step does what the real one would: for every supplied key, check the point is on the curve
//! and recompress it (the y-hint); hash it to its tree leaf; verify all leaves against the root
//! with ONE multiproof (SHA-256, accelerated); decompress the aggregate; subtract the keys; and
//! compare the result with the oracle. The leaf is the SSZ one: sha256(pubkey || 16 zero bytes).
//! The tree has 512 leaves (depth 9), as the sync committee's `pubkeys` vector.
//!
//! Layout in and out is the LEZ one (`lez_io`), so the read and commit costs are comparable with
//! `lez-stage`. Log: guest-stage cycles: mode=agg read=<n> step=<n> commit=<n>
//! Commits `Result<ProgramOutput, u16>`; `Err(1)` means a check failed.
//!
//! NOT YET COMPILED: the blst call names are those of `blst_impl.rs` and `keys.rs`.
mod lez_io;

use blst::{
    blst_p1, blst_p1_add_or_double, blst_p1_affine, blst_p1_affine_compress, blst_p1_affine_is_inf,
    blst_p1_affine_serialize, blst_p1_cneg, blst_p1_deserialize, blst_p1_from_affine,
    blst_p1_to_affine, blst_p1_uncompress, BLST_ERROR,
};
use lez_io::{
    post, AccountWithMetadata, AggInput, AggMsg, ProgramId, ProgramOutput, ValidityWindow,
};
use risc0_zkvm::guest::env;
use sha2::{Digest, Sha256};

const DEPTH: usize = 9;

fn leaf(c48: &[u8; 48]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(&c48[..]);
    h.update([0u8; 16]);
    h.finalize().into()
}

fn node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(l);
    h.update(r);
    h.finalize().into()
}

/// Multiproof for the ascending positions `index` (leaf hashes `leaves`) against `root`.
/// At each level, a node whose sibling is also in the set is combined with it; otherwise the
/// next proof sibling is used. Every sibling must be consumed.
fn verify_multiproof(
    root: &[u8; 32],
    index: &[u16],
    leaves: &[[u8; 32]],
    proof: &[Vec<u8>],
) -> bool {
    if index.is_empty() || index.len() != leaves.len() {
        return false;
    }
    if index.windows(2).any(|w| w[0] >= w[1]) || index.iter().any(|&i| i as usize >= 1 << DEPTH) {
        return false;
    }
    let mut level: Vec<(usize, [u8; 32])> = index
        .iter()
        .zip(leaves)
        .map(|(&i, h)| (i as usize, *h))
        .collect();
    let mut used = 0;
    for _ in 0..DEPTH {
        let mut next = Vec::with_capacity(level.len());
        let mut i = 0;
        while i < level.len() {
            let (ix, h) = level[i];
            let sib = if i + 1 < level.len() && level[i + 1].0 == ix ^ 1 {
                i += 2;
                level[i - 1].1
            } else {
                let Some(p) = proof.get(used) else {
                    return false;
                };
                let Ok(s) = <[u8; 32]>::try_from(p.as_slice()) else {
                    return false;
                };
                used += 1;
                i += 1;
                s
            };
            let parent = if ix & 1 == 0 {
                node(&h, &sib)
            } else {
                node(&sib, &h)
            };
            next.push((ix / 2, parent));
        }
        level = next;
    }
    used == proof.len() && level.len() == 1 && level[0].1 == *root
}

/// The checked agg computation: `Some(result as 96 uncompressed bytes)` if every check passes.
fn aggregate_minus(root: &[u8; 32], agg48: &[u8; 48], input: &AggInput) -> Option<[u8; 96]> {
    if input.keys.len() != input.index.len() {
        return None;
    }
    let mut leaves = Vec::with_capacity(input.keys.len());
    let mut points = Vec::with_capacity(input.keys.len());
    for k in &input.keys {
        if k.len() != 96 {
            return None;
        }
        let mut a = blst_p1_affine::default();
        let mut c = [0u8; 48];
        // SAFETY: `k` is 96 readable bytes; out-pointers are valid. `deserialize` checks that
        // the point is on the curve; recompressing and hashing ties it to the committed leaf.
        unsafe {
            if blst_p1_deserialize(&mut a, k.as_ptr()) != BLST_ERROR::BLST_SUCCESS {
                return None;
            }
            blst_p1_affine_compress(c.as_mut_ptr(), &a);
        }
        leaves.push(leaf(&c));
        points.push(a);
    }
    if !verify_multiproof(root, &input.index, &leaves, &input.proof) {
        return None;
    }
    let mut a = blst_p1_affine::default();
    let mut acc = blst_p1::default();
    // SAFETY: `agg48` is 48 readable bytes; pointers are valid.
    unsafe {
        if blst_p1_uncompress(&mut a, agg48.as_ptr()) != BLST_ERROR::BLST_SUCCESS {
            return None;
        }
        blst_p1_from_affine(&mut acc, &a);
    }
    for p in &points {
        let mut q = blst_p1::default();
        // SAFETY: valid pointers; `prev` and `acc` are distinct objects.
        unsafe {
            blst_p1_from_affine(&mut q, p);
            blst_p1_cneg(&mut q, true);
            let prev = acc;
            blst_p1_add_or_double(&mut acc, &prev, &q);
        }
    }
    let mut out_aff = blst_p1_affine::default();
    let mut out = [0u8; 96];
    // SAFETY: valid pointers; `out` has room for 96 bytes.
    unsafe {
        blst_p1_to_affine(&mut out_aff, &acc);
        if blst_p1_affine_is_inf(&out_aff) {
            return None;
        }
        blst_p1_affine_serialize(out.as_mut_ptr(), &out_aff);
    }
    Some(out)
}

fn main() {
    let t0 = env::cycle_count();
    let program_id: ProgramId = env::read();
    let caller: Option<ProgramId> = env::read();
    let pre_states: Vec<AccountWithMetadata> = env::read();
    let words: Vec<u32> = env::read();
    let msg: AggMsg = risc0_zkvm::serde::from_slice(&words).expect("instruction words decode");
    let t1 = env::cycle_count();

    // the packed form is unpacked here, inside the timed step
    let input: Option<AggInput> = match msg {
        AggMsg::Bytes(i) => Some(i),
        AggMsg::Packed(p) => p.unpack(),
    };
    let data = pre_states[0].account.data.as_slice().to_vec();
    let root: [u8; 32] = data[0..32].try_into().unwrap();
    let agg: [u8; 48] = data[32..80].try_into().unwrap();
    let expected = &data[80..176];
    let ok = input
        .and_then(|i| aggregate_minus(&root, &agg, &i))
        .is_some_and(|r| r[..] == *expected);
    let out: Result<ProgramOutput, u16> = if ok {
        Ok(ProgramOutput {
            self_program_id: program_id,
            caller_program_id: caller,
            instruction_data: words,
            post_states: vec![post(&pre_states[0], data)],
            pre_states,
            chained_calls: vec![],
            block_validity_window: ValidityWindow::default(),
            timestamp_validity_window: ValidityWindow::default(),
        })
    } else {
        Err(1)
    };
    let t2 = env::cycle_count();

    env::commit(&out);
    let t3 = env::cycle_count();

    env::log(&format!(
        "guest-stage cycles: mode=agg read={} step={} commit={}",
        t1 - t0,
        t2 - t1,
        t3 - t2
    ));
}
