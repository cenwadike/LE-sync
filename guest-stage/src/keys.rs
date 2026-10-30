//! Micro-benchmark: what decoding the committee keys costs, and what a hint could save.
//!
//! In `begin`, key aggregation was 17.05M cycles for 170 absent keys plus the aggregate
//! (about 100k per key). The suspect is the square root inside decompression. Here, for `n`
//! valid compressed keys (read outside the timed windows):
//!   uncompress : `blst_p1_uncompress` of each compressed key (what `blst_impl.rs` does today)
//!   hinted     : `blst_p1_deserialize` of the 96-byte uncompressed form (the on-curve check, no
//!                square root), then `blst_p1_affine_compress` and a comparison with the
//!                committed 48 bytes. The comparison is what ties a daemon-supplied y to the
//!                committed key: same x, same sign, and the point is on the curve.
//!   add        : one mixed addition per key (`blst_p1_add_or_double_affine`)
//! The uncompressed bytes are produced inside the guest, outside any timed window, so the host
//! needs no `blst`. In a real design they would be the hint the daemon supplies.
//!
//! Subtraction would add `blst_p1_cneg` on the accumulator side per key (cheap); this measures
//! addition. Subgroup membership is not checked on either path (the committee is authenticated
//! by its Merkle branch; see `bls.rs`).
//!
//! Log: keys cycles: n=<n> uncompress=<total> hinted=<total> add=<total>
//!
//! NOT YET COMPILED: the `blst` call names are those used by `blst_impl.rs` plus
//! `blst_p1_deserialize`, `blst_p1_affine_compress` and `blst_p1_add_or_double_affine` from the
//! blst C API.
use blst::{
    blst_p1, blst_p1_add_or_double_affine, blst_p1_affine, blst_p1_affine_compress,
    blst_p1_affine_serialize, blst_p1_deserialize, blst_p1_uncompress, BLST_ERROR,
};
use risc0_zkvm::guest::env;

fn main() {
    let keys: Vec<Vec<u8>> = env::read();
    let n = keys.len();
    assert!(keys.iter().all(|k| k.len() == 48), "keys are 48 bytes");
    let mut aff = vec![blst_p1_affine::default(); n];
    let mut aff2 = vec![blst_p1_affine::default(); n];
    let mut unc = vec![[0u8; 96]; n];
    let mut c48 = [0u8; 48];

    let a0 = env::cycle_count();
    for (i, k) in keys.iter().enumerate() {
        // SAFETY: `k` is 48 readable bytes (length asserted above); out is valid.
        let r = unsafe { blst_p1_uncompress(&mut aff[i], k.as_ptr()) };
        assert!(r == BLST_ERROR::BLST_SUCCESS, "key {i} does not decompress");
    }
    let a1 = env::cycle_count();

    for i in 0..n {
        // SAFETY: `unc[i]` has room for 96 bytes.
        unsafe { blst_p1_affine_serialize(unc[i].as_mut_ptr(), &aff[i]) };
    }

    let b0 = env::cycle_count();
    for i in 0..n {
        // SAFETY: 96 readable bytes; valid out-pointers.
        let r = unsafe { blst_p1_deserialize(&mut aff2[i], unc[i].as_ptr()) };
        assert!(
            r == BLST_ERROR::BLST_SUCCESS,
            "hinted key {i} is not on the curve"
        );
        unsafe { blst_p1_affine_compress(c48.as_mut_ptr(), &aff2[i]) };
        assert!(
            c48[..] == keys[i][..],
            "hinted key {i} differs from the committed key"
        );
    }
    let b1 = env::cycle_count();

    let mut acc = blst_p1::default();
    let c0 = env::cycle_count();
    for a in aff.iter() {
        let prev = acc;
        // SAFETY: valid pointers; `prev` and `acc` are distinct objects.
        unsafe { blst_p1_add_or_double_affine(&mut acc, &prev, a) };
    }
    let c1 = env::cycle_count();

    env::log(&format!(
        "keys cycles: n={} uncompress={} hinted={} add={}",
        n,
        a1 - a0,
        b1 - b0,
        c1 - c0
    ));
}
