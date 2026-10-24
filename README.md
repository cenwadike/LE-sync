# le-sync: Logos-Ethereum Synchronizer (RFP-021 PoC)

Prove an Ethereum account balance or storage value inside a RISC Zero guest, starting from one
trusted checkpoint. Nothing the beacon API or the execution RPC says is trusted.

---

## 1. Design

### Chain of trust

```
trusted block root (you, weak subjectivity)
  └─ bootstrap header + current sync committee          (branch, gindex 86)
      └─ sync-committee BLS signature on attested header (2/3 gate)
          └─ finalized beacon header                    (finality branch, gindex 169)
              └─ ExecutionPayloadHeader                 (execution_branch, gindex 25)
                  └─ state_root
                      └─ account  (MPT proof)  → balance, storageRoot
                          └─ slot (MPT proof)  → value
```

Every arrow is checked in the guest. The host only fetches data.

### Crates

| Crate | Role |
|---|---|
| `core` | `no_std`, no alloc. SSZ branches, sync protocol, `exec` (header root), `rlp`, `mpt`, `state`, `keccak` |
| `wire` | Guest input/output types and `verify`. No risc0 dependency, testable natively |
| `guest` | Thin zkVM wrapper around `wire` |
| `host` | CLI. Fetches beacon + `eth_getProof` data, runs the guest, judges the journal |
| `testkit` | Test-only reference trie and fixtures |
| `vectors` | Replays the consensus-spec-tests against `core` |

### What the guest checks (state section)

1. The sync part runs first. Its final finalized header is the anchor.
2. The supplied `ExecutionPayloadHeader` must hash into that header's `body_root` (gindex 25).
3. `state_root` is read from that header. It is never an input.
4. The account proof must verify under `state_root`. An absent account is a verified exclusion.
5. The storage proof must verify under the `storageRoot` of the verified account, never under the RPC's `storageHash`.

### Journal (what the host trusts)

`state_checked`, `state_ok`, `state_error_code`, `exec_block_number`, `exec_block_hash`,
`exec_state_root`, `state_address`, `state_slot`, `state_value`, `account_present`,
`account_balance`. Values are big-endian, 32 bytes.

### Error codes

| Code | Meaning |
|---|---|
| 101 | Unsupported fork (before Electra, or Gloas and later) |
| 201 | Branch does not verify (header, `execution_branch`, or forged state root) |
| 203 | RLP malformed or not canonical |
| 204 | Merkle-Patricia proof does not verify |
| 400 | Bad sync-committee signature |
| 501 | Participation below 2/3 |
| 502 | Chain mismatch |

### Limits

- Electra and Fulu only. Other forks fail closed.
- The proof is fetched at the newest finalized block. The RPC must serve state for it.
- Keccak is software (`tiny-keccak`). Cycle cost is measured in Sprint 6.

---

## 2. Setup

```sh
# optional: pick your own execution RPC (must serve eth_getProof). Default: publicnode
export X=https://<your-execution-rpc>

source scripts/env.sh
```

`env.sh` sets `B`, `X`, `R`, `ADDR`, `SLOT`, then runs `le_check` (does the RPC serve proofs).
`R` is the weak-subjectivity root, fetched from the finalized checkpoint. Confirm it against 2+
independent sources before you rely on a result. Override any variable before sourcing.

---

## 3. Run

### One command per task

| Command | What it does |
|---|---|
| `le_verify` | Proves balance and slot in the guest, then compares both with the RPC at the same block |
| `le_tamper` | Tampered state root must fail with 201. Tampered account proof must fail with 204 |
| `le_all` | `le_verify`, then `le_tamper` |
| `le_replay` | Re-runs from `./fixture`, no network for the proof |
| `le` | Raw host CLI, any flags |

```sh
le_verify                              # default: WETH9, slot 0x0
ADDR=0x<account> SLOT=0x<slot> le_verify   # another account or slot
le_all
```

`le_verify` prints one result block and exits non-zero on any mismatch:

```
verify: block 26262717
  balance  OK        0x1d939a6235e9dff0524d5
  slot 0x0  OK        0x5772...001a
verify: PASS
```

After `le_verify` these shell variables hold the values:
`BLOCK`, `G_BALANCE`, `G_VALUE` (from the guest), `I_BALANCE`, `I_VALUE` (from the RPC).

The independent check needs the block the host chose, so it runs after the proof, not at setup.

### Raw commands

Each task above expands to these (`le` is a shell function from `env.sh`):

```sh
# balance proof (balance is always proven with the account)
le --source $B --trusted-root $R --address $ADDR --execution-rpc $X --save-dir ./fixture

# storage inclusion proof
le --source $B --trusted-root $R --address $ADDR --slot $SLOT --execution-rpc $X --save-dir ./fixture

# enforce expected values (hex, left-padded). Exit 0 only if the guest's values equal them
le --source $B --trusted-root $R --address $ADDR --slot $SLOT --execution-rpc $X \
   --expect-value 0x<value> --expect-balance 0x<balance>

# tampered root must fail
le --source $B --trusted-root $R --address $ADDR --slot $SLOT --execution-rpc $X --tamper-exec    # 201
le --source $B --trusted-root $R --address $ADDR --slot $SLOT --execution-rpc $X --tamper-state   # 204

# offline replay (use the root the fixture was saved with)
le --source ./fixture --trusted-root $(cat ./fixture/trusted_root) --address $ADDR --slot $SLOT --execution-rpc ./fixture
```

A slot value of all zeros means the slot is empty (a verified exclusion). Pick a slot with a
non-zero value to test inclusion.

### Sync only (Sprints 1 to 3)

```sh
le --source $B --trusted-root $R                          # bootstrap + branches
le --source $B --trusted-root $R --sync                   # + full update validation, BLS
le --source $B --trusted-root $R --sync --latest-only     # newest update only
le --source $B --trusted-root $R --sync --tamper-sig      # must reject
le --source $B --trusted-root $R --sync --other-chain     # must reject
le --source $B --trusted-root $R --tamper                 # flip a bit in every branch, must reject
```

### Tests

```sh
cargo test --workspace
RISC0_SKIP_BUILD=1 cargo test -p le-sync -p le-sync-wire   # no guest build
cargo mutants -p le-sync-core                              # also -p le-sync-wire, -p le-sync

# spec vectors (native, real blst)
cargo run -p le-sync-vectors --release -- <consensus-spec-tests dir> minimal
cargo run -p le-sync-vectors --release -- <consensus-spec-tests dir> mainnet
```

---

## 4. Flags

| Flag | Use |
|---|---|
| `--source <URL\|DIR>` | Beacon API URL, or a saved directory |
| `--trusted-root 0x..` | Weak-subjectivity block root |
| `--address 0x..` | Account to prove. Implies `--sync` |
| `--slot 0x..` | Storage slot. Default `0x0` |
| `--execution-rpc <URL\|DIR>` | JSON-RPC with `eth_getProof`, or a saved directory. Required with `--address` |
| `--expect-value 0x..` | Journal slot value must equal this |
| `--expect-balance 0x..` | Journal balance must equal this (wei) |
| `--tamper-state` | Corrupt the account proof. Guest must reject with 204 |
| `--tamper-exec` | Corrupt the execution state root. Guest must reject with 201 |
| `--save-dir DIR` | Save every response for offline replay |
| `--count N` | Sync-committee periods to fetch. Raise it if the trusted root is old |

Exit codes: `0` OK, `1` failed, `2` usage error, `3` chain mismatch.

---

## 5. If it fails

| You see | Cause | Do |
|---|---|---|
| `eth_getProof failed: ... missing trie node` | RPC does not hold state at that block | Use another provider or a full node |
| `no update with a finalized execution header and >= 2/3 sync participation` | Beacon API gave no usable update | Use another beacon API, or raise `--count` |
| `NOT OK ... error code 201` | Execution header or branch does not verify | Keep `./fixture` and report it |
| `NOT OK ... error code 203` or `204` | Proof payload or its encoding does not verify | Keep `./fixture` and report it |
| `NOT OK ... error code 101` | Fork not supported | Use an Electra or Fulu network |
| `trusted root` errors | Checkpoint is stale or wrong | Take a fresh `$R` |

---

### Verified run (mainnet, 2026-10-24)

| Item | Value |
|---|---|
| Account | WETH9, `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2` |
| Finalized slot / block | 15501952 / 26262717 |
| Balance | `0x1d939a6235e9dff0524d5` wei, equals `eth_getBalance` at that block |
| Slot `0x0` | `0x5772617070656420457468657200...1a` ("Wrapped Ether"), equals `eth_getStorageAt` |
| Tamper runs | 201 and 204, as expected |

### Cycles (execute only)

| Part | Cycles |
|---|---|
| Whole guest | 65.7M |
| Read input | 9.0M |
| Sync (mostly BLS) | 54.3M |
| State: anchor | 50K |
| State: account proof | 568K |
| State: storage proof | 453K |
