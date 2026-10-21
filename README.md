# le-sync — Ethereum light-client verifier for LEZ (RFP-021 PoC)

`core` (`no_std`, no alloc) implements the Altair→Fulu light-client sync protocol; `wire` wraps it
for the RISC Zero guest; `host` fetches beacon-API data and runs the guest; `vectors` replays the
official consensus-spec-tests against `core`.

```
 beacon API ──► host (std) ──GuestInput──► guest (riscv32im-risc0-zkvm-elf)
  /config/spec     collect()                 wire::verify()
  /genesis                                    ├─ verify_bootstrap, verify_finality_branch
  /bootstrap/{root}                           └─ initialize_light_client_store
  /updates?period                                 └─ process_light_client_update (each)
  /finality_update                                     ├─ validate (every spec assert = one Error)
                                                       ├─ signing_root = HTR(attested) ⊕ domain(gvr, fork(sig_slot-1))
 journal ◄── env::commit(GuestOutput)                  └─ Bls trait ◄── wire/src/bls.rs (bls-zk | bls-blst)
```

Layout: `core/` · `wire/` (types + `verify`, risc0-free, native-testable) · `guest/` (own workspace,
thin wrapper) · `host/` (`build.rs` → `risc0_build::embed_methods()`) · `vectors/` (spec-test runner).

## Run

```sh
cargo test --workspace
RISC0_SKIP_BUILD=1 cargo test -p le-sync -p le-sync-wire      # host-only tests, no guest build

# spec vectors (native, real blst): needs <dir>/tests/<preset>/{electra,fulu}/light_client/sync/pyspec_tests/
cargo run -p le-sync-vectors --release -- <consensus-spec-tests dir> minimal
cargo run -p le-sync-vectors --release -- <consensus-spec-tests dir> mainnet

# live run in the zkVM (Sprint 1 checks only / + full update validation with BLS)
B=https://ethereum-beacon-api.publicnode.com
R=$(curl -s $B/eth/v1/beacon/states/finalized/finality_checkpoints | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['finalized']['root'])")
cargo run -p le-sync --release -- --source $B --trusted-root $R                      # Sprint 1
cargo run -p le-sync --release -- --source $B --trusted-root $R --sync               # + BLS
cargo run -p le-sync --release -- --source $B --trusted-root $R --sync --latest-only # newest update only
cargo run -p le-sync --release -- --source $B --trusted-root $R --sync --tamper-sig  # must reject
cargo run -p le-sync --release -- --source $B --trusted-root $R --sync --other-chain # must reject
```

`--trusted-root` is the weak-subjectivity checkpoint: the **block root** of the first block of a
recently finalized epoch (not an execution hash). Confirm it against 2+ independent sources.
Success is judged on the **journal** the guest committed, not on a host re-check.

## What is checked, and where it comes from

| Check | Spec source |
|---|---|
| `htr(bootstrap.header.beacon) == trusted_root` | altair `initialize_light_client_store` |
| current sync committee proven under `header.state_root` | same; gindex 54 (altair..deneb) / **86** (electra, fulu) |
| `finality_branch` proves `htr(finalized_header.beacon)` under `attested_header.state_root` (+ genesis special case) | altair `validate_light_client_update`; gindex 105 / **169** |
| committee size, participants ≥ 1, slot ordering, period and relevance asserts | same |
| next-sync-committee branch (gindex 55 / **87**) and consistency with a known next committee | same |
| BLS aggregate signature over `HTR(attested)` under domain `(0x07000000, fork_version(signature_slot-1), gvr)` | same |
| gindex picked from the header **slot** vs `ELECTRA_FORK_EPOCH`, never from branch length | electra `*_gindex_at_slot` |
| best-update tracking (`is_better_update`), optimistic/finalized updates, `force_update` after `UPDATE_TIMEOUT`, `best_valid_update` cleared after apply | altair `process_light_client_update`, `process_light_client_store_force_update` |

Fulu adds only `proposer_lookahead` (still 64 `BeaconState` leaves): no light-client gindex changes,
and Electra..=Fulu light-client data uses the Electra SSZ types. Fulu's p2p fork digest is
blob-parameter-XORed; it must not gate light-client processing (it does not).

**Gloas** changes the gindices and is *not* implemented: `core` returns `UnsupportedFork` for slots
at/after `GLOAS_FORK_EPOCH` and the host refuses `version` values newer than `fulu` (fail closed).

**Weak-subjectivity period** is an operator-level guideline, not a spec assert. It is not part of
`validate_light_client_update`; `LightClientStore::assert_within_weak_subjectivity_period` exists for
callers that want it.

## Status

| Item | State |
|---|---|
| Spec vectors, `minimal`, electra + fulu, real `blst` | **8/8 PASS**, 0 skip (`light_client_sync`, `…_no_force_update`, `advance_finality_without_sync_committee`, `supply_sync_committee_from_past_update`) |
| Spec vectors, `mainnet` preset | not run yet (preset constants still marked TENTATIVE in `vectors/src/lib.rs`) |
| Live mainnet `--sync` in the guest | **OK**: bootstrap ok, 2 updates validated, 0 rejected, finalized slot 15481824 |
| `--tamper-sig`, `--other-chain` live | run and record |
| Guest BLS impls (`wire/src/bls.rs`) vs the spec vectors | not run yet (see *Choosing BLS + hashing*) |

Not covered by the vectors: `execution_branch` / `execution_root` (`is_valid_light_client_header`) are
not validated, and `upgrade_store` is a no-op (fine for Electra→Fulu, which shares types).
`current_slot` comes from the host wall clock; a real LEZ statement must bind it to chain time.

## Cost: CU = RISC0 user cycles

On LEZ, CU is the executor **user-cycle** count of a program instruction (independent of
`RISC0_DEV_MODE`). The public-execution budget is **33,554,432 cycles** (32M,
`MAX_NUM_CYCLES_PUBLIC_EXECUTION`); it may change during testnet. The cycle counts printed by
`le-sync` are odd numbers, i.e. user cycles, not padded segment totals; confirm this once for risc0 3.0.5.

Platform reference (LEZ v0.2.4, `cycle_bench`, public execution):

| Operation | CU |
|---|---|
| token · Transfer | 127,726 |
| token · Mint / Burn | 116,862 / 116,546 |
| authenticated_transfer · Transfer / Initialize | 79,958 / 43,818 |
| associated_token_account · Create | 174,995 |
| amm · SwapExactInput / AddLiquidity | 508,679 / 643,059 |
| clock · Tick | 137,022 |

Privacy-preserving transactions compose the instruction cost with the PPE circuit.

Measured here (guest cycles; `info.cycles()`):

| Run | Cycles | × budget | Config |
|---|---|---|---|
| Sprint 1 (bootstrap + finality branches, no BLS) | 13,563,835 | 0.40 | unpatched `sha2` |
| `--sync`, mainnet, 2 updates (1 update + `finality_update`) | **1,171,220,353** | **34.9** | `bls-zk` (risc0 `bls12_381` fork) + risc0-patched `sha2` 0.10.8, per `guest/Cargo.toml` |
| ≈ per update (assuming equal cost, baseline subtracted) | ≈ 578.8M | ≈ 17.3 | derived |

For scale: 1.17B cycles is about 9,170 token Transfers. Even one update is ~17x over budget, so
"verify only the newest update" is necessary but not sufficient; BLS acceleration (or moving the
signature check out of the metered program, e.g. verifying a receipt produced elsewhere) is required.

That run already used the accelerated `bls12_381` fork and the patched `sha2` 0.10.8, so the
remaining cost is not "missing patches" by default. Candidate hot spots (the profile below decides):
(a) the pairing check (two Miller loops + final exponentiation), (b) decompressing and
subgroup-checking up to 512 G1 pubkeys per update (field sqrt + torsion check each; ~1.1M cycles
per key if keys were everything: 1.17B / 1,024 decompressions), (c) hash-to-curve, a handful of
SHA-256 blocks, expected negligible. If field arithmetic were really accelerated, ~1M cycles per
key would be surprising, so first check in the profile that the bigint acceleration is active.

### Measure it

```sh
scripts/bench_cycles.sh            # saves one dataset, then runs {bls-blst, bls-zk} x {all updates, latest only}
```
It prints a table and restores `guest/Cargo.toml` on exit. The `sha2` patch is on by default (as in
`guest/Cargo.toml`); run `SHA2_PATCH=off scripts/bench_cycles.sh` for the unpatched comparison and
record both.

Profile where cycles go (executor writes a pprof file; guest ELF must keep symbols):

```sh
RISC0_PPROF_OUT=./profile.pb cargo run -p le-sync --release -- --source fixtures/bench-<date> --trusted-root $R --sync --latest-only
go tool pprof -top -nodecount=30 profile.pb
```

## Choosing BLS + hashing dependencies (guest)

Candidates in `wire/src/bls.rs`:

* **`bls-zk`**: spec FastAggregateVerify on the `bls12_381` crate (risc0 fork, tag `bls12_381/v0.8.0-risczero.1`).
* **`bls-blst`**: risc0-patched `blst` (tag `blst/v0.3.14-risczero.0`), same call shape as the native vectors runner.

Decide on three facts, in order:

1. **Correct**: the impl passes all spec vectors (run the vectors binary with the guest impl: `cargo run -p le-sync-vectors --release --features bls-zk -- <dir> minimal`, and `cargo run -p le-sync-vectors --release --no-default-features --features bls-blst-guest -- <dir> minimal`; the second needs `--no-default-features` because the crates.io `blst` and the risc0 `blst` fork both set `links = "blst"` and cannot coexist), plus `--tamper-sig` / `--other-chain` rejection in the guest.
2. **Cheap**: lowest `--sync --latest-only` cycles with the patches applied, compared to the 32M budget.
3. **Maintainable**: patch provenance (tag, repo, audit scope) and toolchain fit (LEZ-pinned rust 1.98.1, risc0 3.0.5; `blst` needs a C toolchain for riscv32).

Optimization to evaluate (a security judgement, not a free win): committee keys are authenticated
by a Merkle branch to the trusted state root and were proof-of-possession-checked at deposit, so
the per-key subgroup check on every update can likely be skipped (`from_compressed_unchecked` in
`bls12_381`, `PublicKey::uncompress` instead of `key_validate` in `blst`). Keep the signature's
subgroup check. Decide explicitly before enabling.

### The `sha2` 0.9 in hash-to-curve

`bls12_381` 0.8's `ExpandMsgXmd<D>` is written against `digest` 0.9, so `wire` pulls a second copy
`sha2` 0.9 (`sha2_09`) next to the `sha2` 0.10 used by `core`. Consequences to check:

* The 0.9 copy is **not** accelerated: `wire/Cargo.toml` declares `sha2_09 = sha2 0.9.9` from crates.io, and the guest's `[patch.crates-io] sha2` (tag `sha2-v0.10.8-risczero.0`) only replaces versions that 0.10.8 satisfies, so 0.9.9 runs software SHA-256 in the guest.
* Size: hash-to-curve for G2 needs a 256-byte `expand_message_xmd` (≈ 10 SHA-256 blocks) per signature. Expected to be a rounding error next to 512 key decompressions; confirm in the pprof output (look for `expand_message`/`compress256` frames) before deciding anything.
* Duplicate-crate hygiene: `cd guest && cargo tree -d` and `cargo tree -i sha2@0.9` show who pulls it and whether the risc0 `bls12_381` fork already routes through the accelerated hasher.

If it matters, options are: patch 0.9 too (if a risc0 tag exists), hash the XMD blocks through the accelerated `sha2` 0.10 behind a small `ExpandMsg` adapter, or use the `blst` path (which hashes internally).

## Remaining work

| # | Item | Why |
|---|---|---|
| 1 | Cycle matrix (blst vs zk, patched vs unpatched sha2, all vs latest-only) and pprof; record in the table above | pick the guest BLS crate |
| 2 | Run spec vectors with the guest BLS impls (`bls-zk`, `bls-blst-guest`) and with `mainnet` | proves the guest impls, not only native `blst` |
| 3 | Ask on the forum for the LEZ per-transaction cycle budget; attach the numbers above | budget is not final |
| 4 | Get under budget: drop per-update subgroup checks if accepted, verify a single update, or move BLS out of the metered program | currently ~17x over per update |
| 5 | `is_valid_light_client_header` (`execution_branch`, `execution_root`) | Capella+ assert; vectors check `execution_root` |
| 6 | Bind `current_slot` to chain time in the LEZ statement | host clock is untrusted |
| 7 | Dependency provenance checks (Helios bls version, fork provenance, LEZ sha2 patch, audit scope, risc0 3.x BLS acceleration) | RFP Reliability #6 |
| 8 | `single_merkle_proof` vectors | needs full `BeaconState` HTR (optional) |