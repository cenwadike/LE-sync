# le-sync: Logos-Ethereum Synchronizer (RFP-021 PoC)

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
