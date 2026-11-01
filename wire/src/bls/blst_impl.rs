//! Option B: the risc0-patched `blst`, in three stages (Sprint 6, M1).
//!
//! Same maths and same verdicts as Option A (`bls-zk`): aggregate key = `aggregate_pubkey` minus
//! the absent keys (or the sum of the present ones when most signers are absent), then
//!   accept iff e(aggPK, H(msg)) * e(-G1, sig) == 1.
//! The difference is that the check is cut where its state is plain data, so `update_job` can
//! run it over three transactions:
//!
//! * `prepare`: decode the signature (on curve, in G2, not infinity), aggregate the keys, hash
//!   the message to G2. State out: three uncompressed points (aggregate key, hashed message,
//!   signature), `PREPARED_LEN` = 480 bytes at the start of the 576-byte state, rest zero.
//! * `miller`: the two Miller loops, multiplied. State out: one Fp12 (`STATE_LEN` = 576 bytes,
//!   the whole state).
//! * `finish`: the final exponentiation and the comparison with one.
//!
//! Only blst's raw C functions are used. The high-level `fast_aggregate_verify` of the Rust
//! bindings creates a thread pool, which is the likely source of the old
//! `RUST_MIN_STACK` / `sys_getenv` panic in the guest (not confirmed). Raw calls start no threads.
//!
//! Keys are decoded on-curve only, as in Option A: the committee is authenticated by a Merkle
//! branch (see the SECURITY JUDGEMENT in `bls.rs`). The signature, which is untrusted input,
//! also gets the subgroup check.
//!
//! `prepare_rooted` is the same check for a store that keeps only the committee's keys root
//! (`rooted`): the keys of the members that did not sign arrive as uncompressed points, each is
//! checked on the curve, recompressed and hashed to its SSZ leaf, one multiproof ties all the
//! leaves to the keys root, and the aggregate is the committee's aggregate minus those keys.
//! The state it writes is byte for byte the one `prepare` writes for the same update.
//!
//! The saved states are NOT authenticated here. A program must keep them in an account only it
//! can write, and must read them from that account, never from instruction data.
//!
//! NOT YET COMPILED OR RUN. The workspace this was written in cannot fetch the `blst` crate, so
//! the raw call names and signatures below come from the blst C API and its Rust bindings, not
//! from a compiler. Expect small compile errors on the first build, and read the first test run
//! as the first evidence that the maths is right.
use super::*;
use blst::{
    blst_final_exp, blst_fp12, blst_fp12_is_one, blst_fp12_mul, blst_hash_to_g2, blst_miller_loop,
    blst_p1, blst_p1_add_or_double, blst_p1_affine, blst_p1_affine_compress, blst_p1_affine_is_inf,
    blst_p1_affine_serialize, blst_p1_cneg, blst_p1_deserialize, blst_p1_from_affine,
    blst_p1_generator, blst_p1_to_affine, blst_p1_uncompress, blst_p2, blst_p2_affine,
    blst_p2_affine_in_g2, blst_p2_affine_is_inf, blst_p2_affine_serialize, blst_p2_deserialize,
    blst_p2_to_affine, blst_p2_uncompress, BLST_ERROR,
};
use le_sync_core::multiproof::verify_multiproof;
use le_sync_core::pubkey_root;
use le_sync_core::update_job::{AbsentKeys, StageState, StagedBls, STATE_LEN};
use le_sync_core::Error;

const G1_LEN: usize = 96;
const G2_LEN: usize = 192;
/// aggregate key (G1) + hashed message (G2) + signature (G2), uncompressed.
const PREPARED_LEN: usize = G1_LEN + 2 * G2_LEN;
/// The Miller result fills the whole job state.
const MILLER_LEN: usize = STATE_LEN;
const _: () = assert!(PREPARED_LEN == 480 && PREPARED_LEN <= STATE_LEN);
// One Fp12 is 12 Fp of 6 limbs of 8 bytes. `fp12_to_bytes` / `fp12_from_bytes` copy the limbs,
// so a different layout in a future blst is a compile error, not a silent change of the encoding.
const _: () = assert!(core::mem::size_of::<blst_fp12>() == MILLER_LEN);

fn g1_uncompress(pk: &BlsPubkey) -> Option<blst_p1_affine> {
    let mut a = blst_p1_affine::default();
    // SAFETY: `pk` is 48 readable bytes and `a` is a valid out-pointer.
    let r = unsafe { blst_p1_uncompress(&mut a, pk.as_ptr()) };
    (r == BLST_ERROR::BLST_SUCCESS).then_some(a)
}

/// An uncompressed key (96 bytes, compression flag clear) on the curve. Not subgroup-checked,
/// like `g1_uncompress`: the keys are tied to the committee root before they are used.
fn g1_from_uncompressed(b: &[u8; G1_LEN]) -> Option<blst_p1_affine> {
    // `blst_p1_deserialize` also accepts a compressed encoding at the start of the buffer; the
    // canonical uncompressed form has the compression flag (top bit of byte 0) clear.
    if b[0] & 0x80 != 0 {
        return None;
    }
    let mut a = blst_p1_affine::default();
    // SAFETY: `b` is 96 readable bytes and `a` is a valid out-pointer.
    let r = unsafe { blst_p1_deserialize(&mut a, b.as_ptr()) };
    (r == BLST_ERROR::BLST_SUCCESS).then_some(a)
}

fn g1_compress(a: &blst_p1_affine) -> BlsPubkey {
    let mut out = [0u8; 48];
    // SAFETY: `out` has room for the 48-byte compressed point.
    unsafe { blst_p1_affine_compress(out.as_mut_ptr(), a) };
    out
}

/// Host helper: the 96-byte uncompressed point of a compressed key, `None` if it is not on the
/// curve. What `rooted::absent_wire` packs into the hints.
pub fn uncompress_g1(pk: &BlsPubkey) -> Option<[u8; G1_LEN]> {
    let a = g1_uncompress(pk)?;
    let mut out = [0u8; G1_LEN];
    // SAFETY: `out` has room for the serialized point.
    unsafe { blst_p1_affine_serialize(out.as_mut_ptr(), &a) };
    Some(out)
}

fn p1_projective(a: &blst_p1_affine) -> blst_p1 {
    let mut p = blst_p1::default();
    // SAFETY: valid pointers.
    unsafe { blst_p1_from_affine(&mut p, a) };
    p
}

/// `acc = acc + p`, or `acc - p` when `negate`.
fn p1_add(acc: &mut blst_p1, p: &blst_p1, negate: bool) {
    let mut q = *p;
    let prev = *acc;
    // SAFETY: valid pointers; inputs and output are distinct objects.
    unsafe {
        if negate {
            blst_p1_cneg(&mut q, true);
        }
        blst_p1_add_or_double(acc, &prev, &q);
    }
}

fn neg_g1_generator() -> blst_p1_affine {
    // SAFETY: `blst_p1_generator` returns a pointer to a static, valid point.
    let mut g = unsafe { *blst_p1_generator() };
    let mut a = blst_p1_affine::default();
    // SAFETY: valid pointers.
    unsafe {
        blst_p1_cneg(&mut g, true);
        blst_p1_to_affine(&mut a, &g);
    }
    a
}

fn fp12_to_bytes(f: &blst_fp12) -> [u8; MILLER_LEN] {
    // SAFETY: `blst_fp12` is plain limbs (`#[repr(C)]`, no padding); the size is asserted above.
    let limbs: [u64; MILLER_LEN / 8] = unsafe { core::mem::transmute_copy(f) };
    let mut out = [0u8; MILLER_LEN];
    for (i, l) in limbs.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&l.to_le_bytes());
    }
    out
}

fn fp12_from_bytes(b: &[u8; MILLER_LEN]) -> blst_fp12 {
    let mut limbs = [0u64; MILLER_LEN / 8];
    for (i, l) in limbs.iter_mut().enumerate() {
        let mut w = [0u8; 8];
        w.copy_from_slice(&b[i * 8..i * 8 + 8]);
        *l = u64::from_le_bytes(w);
    }
    // SAFETY: as above; every bit pattern is a representable (if not meaningful) `blst_fp12`.
    unsafe { core::mem::transmute_copy(&limbs) }
}

/// The signature is untrusted: on curve, in G2, and not the point at infinity.
fn decode_signature(sig: &BlsSignature) -> Option<blst_p2_affine> {
    let mut s = blst_p2_affine::default();
    // SAFETY: `sig` is 96 readable bytes; `s` is a valid out-pointer.
    if unsafe { blst_p2_uncompress(&mut s, sig.as_ptr()) } != BLST_ERROR::BLST_SUCCESS {
        return None;
    }
    // SAFETY: `s` is a valid point.
    if unsafe { blst_p2_affine_is_inf(&s) || !blst_p2_affine_in_g2(&s) } {
        return None;
    }
    Some(s)
}

fn hash_message(msg: &Bytes32) -> blst_p2_affine {
    let mut h = blst_p2::default();
    let mut h_aff = blst_p2_affine::default();
    // SAFETY: `msg` and `DST` are readable for their lengths; no augmentation (null, 0).
    unsafe {
        blst_hash_to_g2(
            &mut h,
            msg.as_ptr(),
            msg.len(),
            DST.as_ptr(),
            DST.len(),
            core::ptr::null(),
            0,
        );
        blst_p2_to_affine(&mut h_aff, &h);
    }
    h_aff
}

/// The three points of `prepare`'s state: aggregate key, hashed message, signature.
fn seal(agg: &blst_p1_affine, h: &blst_p2_affine, s: &blst_p2_affine) -> [u8; PREPARED_LEN] {
    let mut out = [0u8; PREPARED_LEN];
    // SAFETY: each destination has room for the serialized point.
    unsafe {
        blst_p1_affine_serialize(out.as_mut_ptr(), agg);
        blst_p2_affine_serialize(out[G1_LEN..].as_mut_ptr(), h);
        blst_p2_affine_serialize(out[G1_LEN + G2_LEN..].as_mut_ptr(), s);
    }
    out
}

impl Impl {
    /// `prepare` for a rooted committee. `BadSignature` for anything about the signature or the
    /// aggregate, `AbsentKeys` for hints that are not acceptable (a key not on the curve, a
    /// proof that does not tie the keys to `keys_root`).
    #[allow(clippy::too_many_arguments)]
    fn prepare_rooted_raw(
        &self,
        keys_root: &Bytes32,
        len: usize,
        aggregate_pubkey: &BlsPubkey,
        absent: &AbsentKeys,
        bits: &[u8],
        msg: &Bytes32,
        sig: &BlsSignature,
    ) -> Result<[u8; PREPARED_LEN], Error> {
        if len == 0 || bits.len() * 8 != len {
            return Err(Error::BadSignature);
        }
        let t0 = cc();
        let s = decode_signature(sig).ok_or(Error::BadSignature)?;
        let t_sig = cc();

        // Each hinted key: on the curve, then recompressed, so that the leaf is the SSZ root of
        // the key the committee actually holds (a different encoding of a point cannot pass).
        let n = absent.index.len();
        let mut points = Vec::with_capacity(n);
        let mut leaves = Vec::with_capacity(n);
        for i in 0..n {
            let raw = absent.key_bytes(i).ok_or(Error::AbsentKeys)?;
            let p = g1_from_uncompressed(&raw).ok_or(Error::AbsentKeys)?;
            leaves.push(pubkey_root(&g1_compress(&p)));
            points.push(p);
        }
        let t_keys = cc();
        if !verify_multiproof(keys_root, len, absent.index, &leaves, absent.siblings()) {
            return Err(Error::AbsentKeys);
        }
        let t_proof = cc();

        let mut acc = p1_projective(&g1_uncompress(aggregate_pubkey).ok_or(Error::BadSignature)?);
        for p in &points {
            p1_add(&mut acc, &p1_projective(p), true);
        }
        let mut agg = blst_p1_affine::default();
        // SAFETY: valid pointers.
        unsafe { blst_p1_to_affine(&mut agg, &acc) };
        // SAFETY: valid point.
        if unsafe { blst_p1_affine_is_inf(&agg) } {
            return Err(Error::BadSignature);
        }
        let t_agg = cc();

        let h_aff = hash_message(msg);
        let t_h = cc();
        trace!(
            "bls-blst prepare_rooted cycles: total={} sig={} absent={} keys={} proof={} agg={} hash_to_curve={}",
            t_h - t0,
            t_sig - t0,
            n,
            t_keys - t_sig,
            t_proof - t_keys,
            t_agg - t_proof,
            t_h - t_agg
        );
        Ok(seal(&agg, &h_aff, &s))
    }

    fn prepare_raw(
        &self,
        committee: &[BlsPubkey],
        aggregate_pubkey: &BlsPubkey,
        bits: &[u8],
        msg: &Bytes32,
        sig: &BlsSignature,
    ) -> Option<[u8; PREPARED_LEN]> {
        let total = committee.len();
        if total == 0 || bits.len() * 8 != total {
            return None;
        }
        let t0 = cc();

        let s = decode_signature(sig)?;
        let t_sig = cc();

        let set = |i: usize| (bits[i / 8] >> (i % 8)) & 1 == 1;
        let present = (0..total).filter(|&i| set(i)).count();
        if present == 0 {
            return None;
        }
        let absent = total - present;

        let mut acc;
        if absent < present {
            acc = p1_projective(&g1_uncompress(aggregate_pubkey)?);
            for i in (0..total).filter(|&i| !set(i)) {
                p1_add(
                    &mut acc,
                    &p1_projective(&g1_uncompress(&committee[i])?),
                    true,
                );
            }
        } else {
            acc = blst_p1::default(); // all-zero projective = the point at infinity
            for i in (0..total).filter(|&i| set(i)) {
                p1_add(
                    &mut acc,
                    &p1_projective(&g1_uncompress(&committee[i])?),
                    false,
                );
            }
        }
        let mut agg = blst_p1_affine::default();
        // SAFETY: valid pointers.
        unsafe { blst_p1_to_affine(&mut agg, &acc) };
        // SAFETY: valid point.
        if unsafe { blst_p1_affine_is_inf(&agg) } {
            return None;
        }
        let t_agg = cc();

        let h_aff = hash_message(msg);
        let t_h = cc();

        let out = seal(&agg, &h_aff, &s);
        trace!(
            "bls-blst prepare cycles: total={} sig={} present={} absent={} agg={} hash_to_curve={}",
            t_h - t0,
            t_sig - t0,
            present,
            absent,
            t_agg - t_sig,
            t_h - t_agg
        );
        Some(out)
    }

    fn miller_raw(&self, prepared: &[u8; PREPARED_LEN]) -> Option<[u8; MILLER_LEN]> {
        let t0 = cc();
        let mut agg = blst_p1_affine::default();
        let mut h = blst_p2_affine::default();
        let mut s = blst_p2_affine::default();
        // SAFETY: each source has the serialized length; out-pointers are valid.
        let ok = unsafe {
            blst_p1_deserialize(&mut agg, prepared.as_ptr()) == BLST_ERROR::BLST_SUCCESS
                && blst_p2_deserialize(&mut h, prepared[G1_LEN..].as_ptr())
                    == BLST_ERROR::BLST_SUCCESS
                && blst_p2_deserialize(&mut s, prepared[G1_LEN + G2_LEN..].as_ptr())
                    == BLST_ERROR::BLST_SUCCESS
        };
        if !ok {
            return None;
        }
        let neg_g1 = neg_g1_generator();
        let (mut f1, mut f2, mut f) = (
            blst_fp12::default(),
            blst_fp12::default(),
            blst_fp12::default(),
        );
        // SAFETY: valid pointers; `f` is distinct from both inputs.
        unsafe {
            blst_miller_loop(&mut f1, &h, &agg);
            blst_miller_loop(&mut f2, &s, &neg_g1);
            blst_fp12_mul(&mut f, &f1, &f2);
        }
        let t1 = cc();
        trace!("bls-blst miller cycles: total={}", t1 - t0);
        Some(fp12_to_bytes(&f))
    }

    fn finish_raw(&self, miller: &[u8; MILLER_LEN]) -> bool {
        let t0 = cc();
        let f = fp12_from_bytes(miller);
        let mut r = blst_fp12::default();
        // SAFETY: valid pointers.
        let ok = unsafe {
            blst_final_exp(&mut r, &f);
            blst_fp12_is_one(&r)
        };
        let t1 = cc();
        trace!("bls-blst finish cycles: total={}", t1 - t0);
        ok
    }
}

/// The job state is `[prepared points | zeros]` after `prepare`, and the Fp12 after `miller`.
impl StagedBls for Impl {
    fn prepare(
        &self,
        committee: &[BlsPubkey],
        aggregate_pubkey: &BlsPubkey,
        bits: &[u8],
        signing_root: &Bytes32,
        signature: &BlsSignature,
        state: &mut StageState,
    ) -> bool {
        let Some(p) = self.prepare_raw(committee, aggregate_pubkey, bits, signing_root, signature)
        else {
            return false;
        };
        *state = [0u8; STATE_LEN];
        state[..PREPARED_LEN].copy_from_slice(&p);
        true
    }

    fn prepare_rooted(
        &self,
        keys_root: &Bytes32,
        len: usize,
        aggregate_pubkey: &BlsPubkey,
        absent: &AbsentKeys,
        bits: &[u8],
        signing_root: &Bytes32,
        signature: &BlsSignature,
        state: &mut StageState,
    ) -> Result<(), Error> {
        let p = self.prepare_rooted_raw(
            keys_root,
            len,
            aggregate_pubkey,
            absent,
            bits,
            signing_root,
            signature,
        )?;
        *state = [0u8; STATE_LEN];
        state[..PREPARED_LEN].copy_from_slice(&p);
        Ok(())
    }

    fn miller(&self, state: &mut StageState) -> bool {
        let mut prepared = [0u8; PREPARED_LEN];
        prepared.copy_from_slice(&state[..PREPARED_LEN]);
        let Some(m) = self.miller_raw(&prepared) else {
            return false;
        };
        *state = m;
        true
    }

    fn finish(&self, state: &StageState) -> bool {
        self.finish_raw(state)
    }
}

/// The one-transaction check is the three stages in a row.
/// Compiled only without `bls-zk`: with both features on, `bls-zk` provides `Bls for Impl` and
/// this one would be a conflicting implementation (the differential test needs both).
#[cfg(not(feature = "bls-zk"))]
impl Bls for Impl {
    fn fast_aggregate_verify(
        &self,
        committee: &[BlsPubkey],
        aggregate_pubkey: &BlsPubkey,
        bits: &[u8],
        msg: &Bytes32,
        sig: &BlsSignature,
    ) -> bool {
        le_sync_core::update_job::Chained(self).fast_aggregate_verify(
            committee,
            aggregate_pubkey,
            bits,
            msg,
            sig,
        )
    }
}

// Two separate `cfg` attributes on purpose (see the note in `bls.rs`).
#[cfg(test)]
mod tests {
    use super::*;
    use le_sync_testkit as tk;

    const N: usize = 8;
    const BAD: BlsPubkey = [0xFFu8; 48]; // not a valid compressed G1 point

    /// The three stages, with the state copied through a `Vec` between them (as an account
    /// would hold it).
    fn staged(
        pks: &[BlsPubkey],
        agg: &BlsPubkey,
        bits: &[u8],
        msg: &Bytes32,
        sig: &BlsSignature,
    ) -> bool {
        let mut st = [0u8; STATE_LEN];
        if !Impl.prepare(pks, agg, bits, msg, sig, &mut st) {
            return false;
        }
        let mut st: StageState = st.to_vec().try_into().unwrap();
        if !Impl.miller(&mut st) {
            return false;
        }
        let st: StageState = st.to_vec().try_into().unwrap();
        Impl.finish(&st)
    }

    /// The `Bls` entry point (the three stages chained inside).
    fn one_step(
        pks: &[BlsPubkey],
        agg: &BlsPubkey,
        bits: &[u8],
        msg: &Bytes32,
        sig: &BlsSignature,
    ) -> bool {
        Impl.fast_aggregate_verify(pks, agg, bits, msg, sig)
    }

    fn signed(seed: u32, bits: &[u8], msg: &Bytes32) -> (tk::Committee, BlsSignature) {
        let c = tk::committee(seed, N);
        let sig = c.sign(bits, msg);
        (c, sig)
    }

    fn with_key(c: &tk::Committee, i: usize, k: BlsPubkey) -> Vec<BlsPubkey> {
        let mut p = c.pubkeys.clone();
        p[i] = k;
        p
    }

    /// Both paths must agree, and the answer is returned.
    fn both(
        pks: &[BlsPubkey],
        agg: &BlsPubkey,
        bits: &[u8],
        msg: &Bytes32,
        sig: &BlsSignature,
    ) -> bool {
        let a = staged(pks, agg, bits, msg, sig);
        assert_eq!(a, one_step(pks, agg, bits, msg, sig), "staged != one step");
        a
    }

    #[test]
    fn dst_matches_the_independent_testkit_constant() {
        assert_eq!(DST, tk::DST);
    }

    #[test]
    fn full_participation_accepts() {
        let msg = [0x11u8; 32];
        let bits = tk::bits_set(N, N);
        let (c, sig) = signed(1, &bits, &msg);
        assert!(both(&c.pubkeys, &c.aggregate, &bits, &msg, &sig));
    }

    #[test]
    fn scattered_bits_accept_on_both_paths() {
        let msg = [0x22u8; 32];
        let sparse = tk::bits_from(N, &[1, 4, 6]); // sum-presents
        let (c, sig) = signed(2, &sparse, &msg);
        assert!(both(&c.pubkeys, &c.aggregate, &sparse, &msg, &sig));
        let dense = tk::bits_from(N, &[0, 1, 2, 4, 5, 6, 7]); // subtract-absents
        let (c, sig) = signed(3, &dense, &msg);
        assert!(both(&c.pubkeys, &c.aggregate, &dense, &msg, &sig));
        assert!(!both(&c.pubkeys, &c.aggregate, &sparse, &msg, &sig));
    }

    #[test]
    fn each_path_trusts_only_the_keys_it_reads() {
        let msg = [0x24u8; 32];
        // sum path (3 present, 5 absent): aggregate and absent keys are never decoded
        let bits = tk::bits_from(N, &[1, 4, 6]);
        let (c, sig) = signed(5, &bits, &msg);
        assert!(both(&c.pubkeys, &BAD, &bits, &msg, &sig));
        assert!(both(&with_key(&c, 0, BAD), &c.aggregate, &bits, &msg, &sig));
        assert!(!both(
            &with_key(&c, 4, BAD),
            &c.aggregate,
            &bits,
            &msg,
            &sig
        ));
        // subtract path (7 present, 1 absent): aggregate and the absent key must decode
        let bits = tk::bits_from(N, &[0, 1, 2, 4, 5, 6, 7]);
        let (c, sig) = signed(7, &bits, &msg);
        assert!(!both(&c.pubkeys, &BAD, &bits, &msg, &sig));
        assert!(!both(
            &with_key(&c, 3, BAD),
            &c.aggregate,
            &bits,
            &msg,
            &sig
        ));
        assert!(both(&with_key(&c, 0, BAD), &c.aggregate, &bits, &msg, &sig));
        // an exact tie takes the sum path
        let bits = tk::bits_from(N, &[0, 2, 4, 6]);
        let (c, sig) = signed(6, &bits, &msg);
        assert!(both(&c.pubkeys, &BAD, &bits, &msg, &sig));
    }

    #[test]
    fn inconsistent_aggregate_wrong_message_and_wrong_keys_are_rejected() {
        let msg = [0xAAu8; 32];
        let bits = tk::bits_set(N, N);
        let (c, sig) = signed(8, &bits, &msg);
        let wrong_agg = tk::committee(80, N).aggregate;
        assert!(!both(&c.pubkeys, &wrong_agg, &bits, &msg, &sig));
        assert!(!both(&c.pubkeys, &c.aggregate, &bits, &[0xBB; 32], &sig));
        let other = tk::committee(99, N);
        assert!(!both(&other.pubkeys, &other.aggregate, &bits, &msg, &sig));
    }

    #[test]
    fn bad_signatures_and_bad_shapes_are_rejected() {
        let msg = [0x66u8; 32];
        let bits = tk::bits_set(N, N);
        let (c, mut sig) = signed(11, &bits, &msg);
        assert!(both(&c.pubkeys, &c.aggregate, &bits, &msg, &sig));
        sig[95] ^= 1;
        assert!(!both(&c.pubkeys, &c.aggregate, &bits, &msg, &sig));
        assert!(!both(&c.pubkeys, &c.aggregate, &bits, &msg, &[0u8; 96]));
        assert!(!both(&c.pubkeys, &c.aggregate, &bits, &msg, &[0xFFu8; 96]));
        let mut infinity = [0u8; 96];
        infinity[0] = 0xC0;
        assert!(!both(&c.pubkeys, &c.aggregate, &bits, &msg, &infinity));
        // nobody signed, and shapes that do not fit
        let none = tk::bits_set(N, 0);
        assert!(!both(&c.pubkeys, &c.aggregate, &none, &msg, &[0u8; 96]));
        assert!(!both(&[], &[0u8; 48], &[], &msg, &[0u8; 96]));
        let (c2, sig2) = signed(10, &bits, &msg);
        assert!(!both(
            &c2.pubkeys,
            &c2.aggregate,
            &[0xFF, 0xFF],
            &msg,
            &sig2
        ));
        assert!(!both(&c2.pubkeys, &c2.aggregate, &[], &msg, &sig2));
    }

    #[test]
    fn altered_saved_state_never_passes() {
        let msg = [0x77u8; 32];
        let bits = tk::bits_set(N, N);
        let (c, sig) = signed(12, &bits, &msg);
        let mut p = [0u8; STATE_LEN];
        assert!(Impl.prepare(&c.pubkeys, &c.aggregate, &bits, &msg, &sig, &mut p));
        // prepare fills the first PREPARED_LEN bytes and leaves the rest zero
        assert!(p[PREPARED_LEN..].iter().all(|b| *b == 0));
        assert!(p[..PREPARED_LEN].iter().any(|b| *b != 0));
        let mut m = p;
        assert!(Impl.miller(&mut m));
        assert!(Impl.finish(&m));
        // one bit of the Miller state, at the first and the last byte
        for at in [0, MILLER_LEN - 1] {
            let mut bad = m;
            bad[at] ^= 1;
            assert!(!Impl.finish(&bad), "miller byte {at}");
        }
        // one bit of the prepared state, in the last byte of each of the three points
        for at in [G1_LEN - 1, G1_LEN + G2_LEN - 1, PREPARED_LEN - 1] {
            let mut bad = p;
            bad[at] ^= 1;
            let passed = Impl.miller(&mut bad) && Impl.finish(&bad);
            assert!(!passed, "prepared byte {at}");
        }
    }

    #[test]
    fn fp12_encoding_round_trips() {
        let msg = [0x78u8; 32];
        let bits = tk::bits_set(N, N);
        let (c, sig) = signed(13, &bits, &msg);
        let mut m = [0u8; STATE_LEN];
        assert!(Impl.prepare(&c.pubkeys, &c.aggregate, &bits, &msg, &sig, &mut m));
        assert!(Impl.miller(&mut m));
        assert_eq!(fp12_to_bytes(&fp12_from_bytes(&m)), m);
        assert_ne!(m, [0u8; MILLER_LEN]);
    }

    // ---- rooted committee: hints instead of keys --------------------------------------------

    use crate::rooted::absent_wire;
    use le_sync_core::pubkeys_root;

    /// What a program is handed for a rooted update.
    struct Rooted {
        root: Bytes32,
        wire: crate::rooted::AbsentWire,
    }
    fn rooted(c: &tk::Committee, bits: &[u8]) -> Rooted {
        Rooted {
            root: pubkeys_root(&c.pubkeys).unwrap(),
            wire: absent_wire(&c.pubkeys, bits, uncompress_g1).unwrap(),
        }
    }
    fn prepare_rooted(
        c: &tk::Committee,
        agg: &BlsPubkey,
        r: &Rooted,
        bits: &[u8],
        msg: &Bytes32,
        sig: &BlsSignature,
    ) -> Result<StageState, Error> {
        let mut st = [0u8; STATE_LEN];
        Impl.prepare_rooted(
            &r.root,
            c.pubkeys.len(),
            agg,
            &r.wire.view(),
            bits,
            msg,
            sig,
            &mut st,
        )?;
        Ok(st)
    }
    fn finish_rooted(mut st: StageState) -> bool {
        Impl.miller(&mut st) && Impl.finish(&st)
    }

    #[test]
    fn rooted_state_is_byte_for_byte_the_state_of_prepare() {
        let msg = [0x31u8; 32];
        for absent in [vec![], vec![3], vec![0, 7], vec![1, 2, 3]] {
            // more present than absent in every case: `prepare` takes the subtract path
            let bits = tk::bits_from(
                N,
                &(0..N).filter(|i| !absent.contains(i)).collect::<Vec<_>>(),
            );
            let (c, sig) = signed(21, &bits, &msg);
            let r = rooted(&c, &bits);
            let got = prepare_rooted(&c, &c.aggregate, &r, &bits, &msg, &sig).unwrap();
            let mut want = [0u8; STATE_LEN];
            assert!(Impl.prepare(&c.pubkeys, &c.aggregate, &bits, &msg, &sig, &mut want));
            assert_eq!(got, want, "absent {absent:?}");
            assert!(finish_rooted(got), "absent {absent:?}");
        }
    }

    #[test]
    fn rooted_uses_only_the_aggregate_and_the_hinted_keys() {
        // The present keys are never needed: the committee is just the root and the aggregate.
        let msg = [0x32u8; 32];
        let bits = tk::bits_from(N, &[0, 1, 2, 4, 5, 6, 7]); // 7 present, 1 absent
        let (c, sig) = signed(22, &bits, &msg);
        let r = rooted(&c, &bits);
        assert!(finish_rooted(
            prepare_rooted(&c, &c.aggregate, &r, &bits, &msg, &sig).unwrap()
        ));
        // an aggregate that is not the committee's is a signature failure, not a hint failure
        let wrong = tk::committee(88, N).aggregate;
        let st = prepare_rooted(&c, &wrong, &r, &bits, &msg, &sig).unwrap();
        assert!(!finish_rooted(st));
        assert_eq!(
            prepare_rooted(&c, &BAD, &r, &bits, &msg, &sig).err(),
            Some(Error::BadSignature)
        );
    }

    #[test]
    fn rooted_signature_failures_are_bad_signature() {
        let msg = [0x33u8; 32];
        let bits = tk::bits_from(N, &[0, 1, 2, 4, 5, 6, 7]);
        let (c, sig) = signed(23, &bits, &msg);
        let r = rooted(&c, &bits);
        let mut infinity = [0u8; 96];
        infinity[0] = 0xC0;
        for bad in [[0u8; 96], [0xFFu8; 96], infinity] {
            assert_eq!(
                prepare_rooted(&c, &c.aggregate, &r, &bits, &msg, &bad).err(),
                Some(Error::BadSignature)
            );
        }
        // a signature that decodes but is for another message passes prepare and fails the pairing
        let st = prepare_rooted(&c, &c.aggregate, &r, &bits, &[0x34; 32], &sig).unwrap();
        assert!(!finish_rooted(st));
        // shapes
        assert_eq!(
            prepare_rooted(&c, &c.aggregate, &r, &bits[..0], &msg, &sig).err(),
            Some(Error::BadSignature)
        );
    }

    #[test]
    fn rooted_refuses_hints_that_do_not_match_the_root() {
        let msg = [0x35u8; 32];
        let bits = tk::bits_from(N, &[0, 1, 2, 4, 5, 6, 7]); // member 3 absent
        let (c, sig) = signed(24, &bits, &msg);
        let ok = rooted(&c, &bits);
        assert!(prepare_rooted(&c, &c.aggregate, &ok, &bits, &msg, &sig).is_ok());
        let try_with = |edit: &dyn Fn(&mut Rooted)| {
            let mut r = rooted(&c, &bits);
            edit(&mut r);
            prepare_rooted(&c, &c.aggregate, &r, &bits, &msg, &sig).err()
        };
        // a valid point that is another member's key, in place of the absent one
        let other = uncompress_g1(&c.pubkeys[5]).unwrap();
        assert_eq!(
            try_with(&|r| {
                for (w, ch) in r.wire.keys.iter_mut().zip(other.chunks(4)) {
                    *w = u32::from_le_bytes([ch[0], ch[1], ch[2], ch[3]]);
                }
            }),
            Some(Error::AbsentKeys)
        );
        // a valid point from another committee
        let foreign = uncompress_g1(&tk::committee(90, N).pubkeys[3]).unwrap();
        assert_eq!(
            try_with(&|r| {
                for (w, ch) in r.wire.keys.iter_mut().zip(foreign.chunks(4)) {
                    *w = u32::from_le_bytes([ch[0], ch[1], ch[2], ch[3]]);
                }
            }),
            Some(Error::AbsentKeys)
        );
        // each word of the key: a flipped bit is off the curve or a different point
        for i in 0..KEY_WORDS_TEST {
            assert_eq!(
                try_with(&|r| r.wire.keys[i] ^= 1),
                Some(Error::AbsentKeys),
                "key word {i}"
            );
        }
        // the compressed form of the key where the uncompressed one belongs
        assert_eq!(
            try_with(&|r| {
                let mut p = [0u8; 96];
                p[..48].copy_from_slice(&c.pubkeys[3]);
                for (w, ch) in r.wire.keys.iter_mut().zip(p.chunks(4)) {
                    *w = u32::from_le_bytes([ch[0], ch[1], ch[2], ch[3]]);
                }
            }),
            Some(Error::AbsentKeys)
        );
        // a wrong root, a wrong proof, a proof of the wrong length
        assert_eq!(try_with(&|r| r.root[0] ^= 1), Some(Error::AbsentKeys));
        assert_eq!(try_with(&|r| r.wire.proof[0] ^= 1), Some(Error::AbsentKeys));
        assert_eq!(try_with(&|r| r.wire.proof.push(0)), Some(Error::AbsentKeys));
        assert_eq!(
            try_with(&|r| {
                r.wire.proof.truncate(r.wire.proof.len() - 8);
            }),
            Some(Error::AbsentKeys)
        );
        // a position that is not the member the key belongs to
        assert_eq!(try_with(&|r| r.wire.index[0] = 4), Some(Error::AbsentKeys));
    }
    const KEY_WORDS_TEST: usize = 24;

    #[test]
    fn uncompress_g1_gives_the_canonical_uncompressed_point() {
        let c = tk::committee(25, N);
        for k in c.pubkeys.iter().chain([&c.aggregate]) {
            let u = uncompress_g1(k).unwrap();
            assert_eq!(u[0] & 0x80, 0, "compression flag is clear");
            let p = g1_from_uncompressed(&u).unwrap();
            assert_eq!(&g1_compress(&p), k);
        }
        assert_eq!(uncompress_g1(&BAD), None);
        // the compression flag set: refused even though the deserializer would read it
        let mut u = uncompress_g1(&c.pubkeys[0]).unwrap();
        u[0] |= 0x80;
        assert!(g1_from_uncompressed(&u).is_none());
    }
}
