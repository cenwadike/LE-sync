# le-sync: Logos-Ethereum Synchronizer (RFP-021 PoC)

Prove an Ethereum account balance, storage value or event log inside a RISC Zero guest, starting
from one trusted checkpoint, and save the result as a verifiable receipt. Nothing the beacon API
or the execution RPC says is trusted.

The same light-client logic also runs on LEZ as the `eth_attest` program: an update in three small
steps (Begin, Miller, Finish) that each fit the per-transaction cycle cap, and attestations of
accounts, storage slots and logs against the stored headers. Sections 2 and 3 describe it.

---

## 1. Design

### Chain of trust

```
trusted block root (you, weak subjectivity)
  └─ bootstrap header + current sync committee          (branch, gindex 86)
      └─ sync-committee BLS signature on attested header (2/3 gate)
          └─ finalized beacon header                    (finality branch, gindex 169)
              └─ ExecutionPayloadHeader                 (execution_branch, gindex 25)
                  ├─ state_root
                  │   └─ account  (MPT proof)  → balance, storageRoot
                  │       └─ slot (MPT proof)  → value
                  └─ receipts_root
                      └─ receipt  (MPT proof, key rlp(tx index)) → log (address, topics, data)
```

Every arrow is checked in the guest. The host only fetches data.

### Crates

| Crate | Role |
|---|---|
| `core` | `no_std`, no alloc. SSZ branches, sync protocol, staged update (`update_job`, `multiproof`, `store_codec`), `exec` (header root), `rlp`, `mpt`, `state`, `receipt`, `predicate`, `statement`, `keccak` |
| `wire` | Guest input/output types, `verify`, the staged steps (`stage`, `rooted`) and the BLS backends. No risc0 dependency, testable natively |
| `guest` | Thin zkVM wrapper around `wire::verify` |
| `host` | CLI. Fetches beacon, `eth_getProof` and `eth_getBlockReceipts` data, runs the guest, judges the journal, proves and verifies receipts |
| `guest-stage` | Guest programs for the staged steps: plain, LEZ layout, rooted (LEZ layout), and two micro-benchmarks |
| `bench` | Execute-only cycle gate for the staged steps (`le_cost`). Own workspace |
| `lez` | The `eth_attest` LEZ program (`methods/guest`), its host copy for the IDL (`src/lib.rs`), and `executor-tests` (own workspace) |
| `testkit` | Test-only reference trie, seeded committees, BLS signer and fixtures |
| `vectors` | Replays the consensus-spec-tests against `core` |

### What the guest checks (state section)

1. The sync part runs first. Its final finalized header is the anchor.
2. The supplied `ExecutionPayloadHeader` must hash into that header's `body_root` (gindex 25).
3. `state_root` is read from that header. It is never an input.
4. The account proof must verify under `state_root`. An absent account is a verified exclusion.
5. The storage proof must verify under the `storageRoot` of the verified account, never under the
   RPC's `storageHash`.

### What the guest checks (log section)

1. Same anchor and `execution_branch`. `receipts_root` is read from the verified header.
2. The receipt proof must verify under `receipts_root`, key `rlp(tx index)` (not hashed).
3. The receipt must be a success, of type legacy, `0x01` or `0x02`. Other types fail closed.
4. The log at the given index must match the address and topics asked for (`205` if not).
5. A predicate, if given, must hold (`206` if not). A false predicate emits no statement.
6. The statement ID is computed from the chain, the execution block hash and the log position.

### Journal (what the host trusts)

State section: `state_checked`, `state_ok`, `state_error_code`, `exec_block_number`,
`exec_block_hash`, `exec_state_root`, `state_address`, `state_slot`, `state_value`,
`account_present`, `account_balance`, `account_statement_id`, `state_statement_id`,
`state_predicate`.

Log section: `log_checked`, `log_ok`, `log_error_code`, `log_block_number`, `log_block_hash`,
`log_receipts_root`, `log_tx_index`, `log_index`, `log_address`, `log_topic_count`, `log_topics`,
`log_data_len`, `log_data_hash` (keccak256 of the data), `log_statement_id`, `log_predicate`.

Values are big-endian, 32 bytes. A section that fails commits zeros.

### Proof output

The journal is the statement. The receipt (journal + seal) is the proof of it.

1. The host executes the guest first (fast: cycles, journal, verdict).
2. Only if every check passed and `--prove` is set, it proves the same run.
3. It verifies the receipt against this build's guest image ID, and requires the receipt's journal
   to equal the executed journal.
4. Only then is the receipt written to `--receipt-out`.

`--verify-receipt <file>` checks a saved receipt and judges its journal like a live run. It runs
no guest and, with a saved `--source` directory, needs no network.

Limits: a verifier must build the same guest (same image ID). Receipts made with
`RISC0_DEV_MODE` are fake, so `--prove` and `--verify-receipt` refuse to run while it is set.
Tamper and other-chain runs are not proved (the guest rejects them on purpose).

### Statement ID (provisional)

```
id = SHA-256( "le-sync/statement/v1" || chain_id (8, BE) || execution block hash (32)
              || type (1 account, 2 storage, 3 log) || key )
key: account = address | storage = address, slot | log = tx index (8), log index (8)
```

The same state or event gives the same ID under any later finalized header. The predicate and
the value are not in the ID. The sprint text says "header root": which header is still to be
confirmed (see `design-log-sprint5.md`).

### Predicate (provisional)

`<target><op><word>`. Targets: `balance`, `storage`, `topic0..3`, `data0..` (a 32-byte word of
the log data). Operators: `==`, `!=`. Example: `balance==0x1d939a6235e9dff0524d5`,
`topic0!=0xddf252ad...`. Fail closed: a false predicate, or a target the subject lacks, is 206.

### Error codes

Ranges: 1xx config, 2xx bootstrap, branches and proofs, 3xx update validity, 4xx signature,
5xx policy and chain identity. Numbers are stable and never reused.

| Code | Meaning |
|---|---|
| 100 | Configuration invalid |
| 101 | Unsupported fork (before Electra, or Gloas and later) |
| 102 | Sync-committee size not a power of two within the maximum |
| 201 | Branch does not verify (header, `execution_branch`, or forged state root) |
| 203 | RLP malformed or not canonical |
| 204 | Merkle-Patricia proof does not verify (state, storage or receipt) |
| 205 | Log mismatch: failed receipt, no such log, or address or topics differ |
| 206 | Predicate false (provisional) |
| 300 to 307 | Update validity: committee size, participants, slot order, period, relevance, next committee |
| 308 | Staged step called out of order |
| 309 | Job does not belong to this update |
| 310 | Store changed since Begin |
| 311 | Store bytes are not a canonical `store_codec` encoding |
| 312 | Rooted Begin: the absent keys are not acceptable (wrong members, off the curve, or not proven against the keys root) |
| 313 | Instance configuration is not canonical |
| 314 | Instance already initialised |
| 315 | Header records are malformed |
| 316 | No record for that header (never finalized by this instance, or evicted) |
| 317 | Handoff from a committee the instance has not verified |
| 318 | Instance ID or an account seed is not derived from the configuration |
| 319 | Instruction argument does not decode, or the claim is the wrong kind |
| 320 | Statement seed is not the statement ID of the verified claim |
| 321 | Not the LEZ clock account, or not a clock record |
| 400 | Bad sync-committee signature |
| 500 | Checkpoint older than the weak-subjectivity guideline |
| 501 | Participation below 2/3 |
| 502 | Chain mismatch |

### Limits

- Electra and Fulu only. Other forks fail closed.
- Receipt types: legacy, `0x01`, `0x02`. Types `0x03` and `0x04` fail closed until their receipt
  payload is confirmed.
- Native ETH transfers are not covered: the beacon header's `transactions_root` is an SSZ root, not
  an MPT root.
- The log needs an RPC that serves `eth_getBlockReceipts`. The host rebuilds the receipts trie and
  checks it against the header's `receipts_root` before calling the guest.
- The proof is fetched at the newest finalized block. The RPC must serve state for it.
- Keccak is software (`tiny-keccak`).

---

## 2. Staged update (Sprint 6)

LEZ stops a program at 32 MiB cycles (`33,554,432`, LEZ v0.1.2 public execution). One signature
check costs more, so the update is split into three transactions:

| Step | Does | Reads | Writes |
|---|---|---|---|
| Begin | Checks the update, hashes the message to the curve, aggregates the signing keys | store | job (641 bytes) |
| Miller | The pairing's Miller loop | job | job |
| Finish | Final exponentiation, then applies the update | store, job | new store |

The job holds the step, digests of the store and the update, and the intermediate pairing state.
It is unauthenticated, so it lives in an account only the program can write: one job account per
update (section 3).

### Committee as a root

The first design stored the committee's keys in the store account. Account data costs about 454
cycles per byte per step, and each key costs 92,132 cycles to decompress, so Begin and Finish were
over the cap. The store now holds only the committee's keys root and aggregate (`store_codec` v2,
403 bytes). Begin is sent what it needs:

- the keys of the **absent** members, as 96-byte uncompressed points packed into `u32` words;
- one Merkle multiproof binding them to the keys root (SSZ tree, depth 9, leaf = `pubkey_root`).

The signing key is the committee aggregate minus the absent keys. Their positions must equal the
zero bits of the participation bits, and the 2/3 gate guarantees fewer absent than present. Each
hinted key is checked on the curve and recompressed, so the leaf proven is the committed one. A
handoff update carries the next committee as its keys root and a 48-byte aggregate.
`store_codec` still decodes v1.

### Cost (measured through the program)

Executor cycles per transaction of the real `eth_attest` program, committee of 512, cap 33,554,432
(`cargo run --release --manifest-path lez/executor-tests/Cargo.toml --bin gas`, run 2026-11-03):

| Instruction | Scenario | Cycles | Of the cap |
|---|---|---:|---:|
| `init_instance` | | 1,203,163 | 3.6% |
| `begin_update` | `full` (512 sign) | 4,484,659 | 13.4% |
| `miller_update` | any | 4,818,567 | 14.4% |
| `finish_update` | `full` | 9,572,313 | 28.5% |
| `begin_update` | `min` (342 sign) | 9,890,323 | 29.5% |
| `finish_update` | `min` | 9,572,378 | 28.5% |
| `begin_update` | `handoff` (342 sign, next committee) | 9,812,218 | 29.2% |
| `finish_update` | `handoff` | 9,313,135 | 27.8% |
| `attest_state` | account | 1,756,392 | 5.2% |
| `attest_state` | storage | 1,875,853 | 5.6% |
| `attest_log` | log | 2,731,657 | 8.1% |

The worst step is `begin_update` at minimum participation, 29.5% of the cap. With the committee's
keys in the store (the first design), the same `min` Begin cost 44.29M and `handoff` Finish 41.12M.

The execution-only bench (`le_cost`, below) measures the staged steps without the program around
them. It runs the same steps over a copy of the LEZ account layout.

Open: the transaction size limit (the `min` Begin update is 17,436 bytes), the testnet 0.4 cap, and
the image ID on Linux.

### Run

```sh
source scripts/env.sh
le_cost --rooted --committee 512 --scenario min --input lez --cap 33554432
le_cost --rooted --committee 512 --scenario handoff --input lez --cap 33554432
le_cost --rooted --committee 512 --scenario full --input lez --cap 33554432
```

`le_cost` runs `bench/`, passes every flag through, prints `cost: PASS ...` and sets `COST_BEGIN`,
`COST_MILLER` and `COST_FINISH`. It fails if a step is over `--cap`, or if a guest result differs
from the native one (byte for byte, including the error code). Without `--rooted` it measures the
first design (keys in the store).

| Bench flag | Use |
|---|---|
| `--committee N` | Power of two from 8 to 512 (default 512) |
| `--scenario S` | `full`, `min` (fewest signers the gate accepts, default) or `handoff` (also carries the next committee) |
| `--rooted` | The rooted design. Implies `--input lez` |
| `--input plain\|lez` | Read and commit directly, or as a LEZ program does (accounts, instruction words, whole output) |
| `--cap N` | Cycle cap to compare against |
| `--detail` | Print each step's guest log (per-phase cycles) |
| `--keys N`, `--agg N [--pack]` | Micro-benchmarks: key decoding, and one rooted Begin-like step |

Run the bench from its own manifest: it is its own workspace because `bls-blst` (the risc0 fork of
`blst`) and `le-sync-vectors` (crates.io `blst`) cannot be built together.

---

## 3. LEZ program (`eth_attest`)

One instance is one light client of one chain. Every account is a PDA of the program. There is no
signer: nobody is named in a transaction or in a statement.

| Account | Holds | Written by |
|---|---|---|
| `instance` | `InstanceConfig`, 221 bytes: chain ID, genesis validators root, fork schedule, slot and epoch sizes, committee size, `genesis_time`, `seconds_per_slot`, checkpoint root | `init_instance`, once |
| `store` | The tracked light-client store, `store_codec` v2, 403 bytes | `init_instance`, `finish_update` |
| `records` | 16 header records of 145 bytes: slot, header root, block number, block hash, state root, receipts root | `init_instance`, `finish_update` |
| `job` | One staged update, 641 bytes. One account per update, at the address derived from the instance and the update's digest | `begin_update` claims it, `miller_update`, `finish_update` empties it |
| `statement` | One verified statement, at the address of its statement ID | `attest_state`, `attest_log` |

The instance ID is `SHA-256("LE_SYNC_INSTANCE_V1" || config)`. Every other address is derived from
it, and the program recomputes each seed, so an account of another instance is refused (318). No
instruction edits `instance`, and no account holds a program ID.

| Instruction | Does |
|---|---|
| `init_instance` | Writes the configuration. Starts the store from the checkpoint: the header must hash to the trusted root, and a branch must prove the committee's keys root and aggregate under its state root |
| `begin_update` | Step 1. Claims the job of this update |
| `miller_update` | Step 2 |
| `finish_update` | Step 3. Moves the store, empties the job, and when the finalized header moved stores its record (execution header checked against the header's `body_root`) |
| `attest_state` | Verifies an account or storage claim against a stored record. Claims the statement account |
| `attest_log` | Verifies a log claim the same way |

**Time.** `init_instance`, `begin_update` and `finish_update` take the 1-block LEZ clock account.
The slot is `(timestamp_ms / 1000 - genesis_time) / seconds_per_slot`. No caller supplies it. Any
other account in the clock's place is refused (321).

**Records.** A full log replaces the record with the lowest slot, so an attestation can only be
made against one of the latest 16 finalized headers (316 otherwise).

**Statements.** The statement account's seed must be the statement ID of the verified claim (320
otherwise), so the chain ID and block are part of its address. A predicate reads only what the
claim's proof covers: an account claim the balance, a storage claim the balance and the slot value,
a log claim its topics and data words. Anything else is 206. The statement holds what the proofs
established and nothing about who asked.

**Updates.** The three steps run in order (308). A job is bound to the update and to the store it
was begun against (309, 310). An update that is not newer than the finalized header is refused
(304). An update signed in the next period, before the instance knows that committee, is refused
(317). A begun update that is never finished blocks nobody: the next update has its own job.

### Build and test

```sh
logos-scaffold build        # guest, IDL (lez/idl) and client (lez/src/generated)
sh scripts/check_lez_in_step.sh   # guest and host copy declare the same instructions

cargo test --release --manifest-path lez/executor-tests/Cargo.toml
cargo run  --release --manifest-path lez/executor-tests/Cargo.toml --bin gas [N]   # N default 512
cargo test --release --manifest-path lez/executor-tests/Cargo.toml -- --ignored    # cap at 512
```

The executor tests run each instruction through LEZ's in-memory state machine (`V03State`) with
real BLS-signed updates and proofs, one transaction after another, and check the program's error
code on every refusal. They cover:

- a fabricated chain with a self-consistent header and proof (400, and the honest update still goes
  through);
- a handoff from an unknown committee (317);
- a signature below the threshold (501);
- a valid proof against a header that is not finalized (316);
- a tampered state root or receipts root (201) and a tampered proof (the native verifier's code);
- a proof replayed on another chain ID (320);
- a predicate over state the proof does not cover (206);
- duplicate and out-of-order updates, and out-of-order steps (304, 308, 310);
- the clock as the only source of time (302, 321, 500);
- no instruction changes `instance`, and instances share no accounts;
- the public statement holds the verified statement and nothing else.

---

## 4. Setup

```sh
# optional: pick your own execution RPC (must serve eth_getProof and eth_getBlockReceipts).
# Default: publicnode
export X=https://<your-execution-rpc>

source scripts/env.sh
```

`env.sh` sets `B`, `X`, `R`, `ADDR`, `SLOT`, `LOGADDR`, `TOPIC0`, `RECEIPT_DIR`, then runs
`le_check` (does the RPC serve proofs) and `le_check_receipts` (does it serve block receipts).
`R` is the weak-subjectivity root, fetched from the finalized checkpoint. Confirm it against 2+
independent sources before you rely on a result. Override any variable before sourcing.

---

## 5. Run

### One command per task

| Command | What it does |
|---|---|
| `le_verify` | Proves balance and slot in the guest, then compares both with the RPC at the same block |
| `le_tamper` | Tampered state root must fail with 201. Tampered account proof must fail with 204 |
| `le_all` | `le_verify`, then `le_tamper` |
| `le_replay` | Re-runs from `./fixture`, no network for the proof |
| `le_log` | Proves an event log (default: a USDC `Transfer`), then compares it with the RPC's receipts |
| `le_log_tamper` | Tampered receipts root must fail with 201. Tampered receipt proof must fail with 204 |
| `le_log_predicate` | A true predicate passes. A false one is rejected with 206 |
| `le_log_replay` | Re-runs `le_log` offline from `./fixture-log`. The statement ID must not change |
| `le_log_all` | `le_log`, `le_log_tamper`, `le_log_predicate`, `le_log_replay` |
| `le_prove [state\|log]` | Executes, proves, saves `./receipts/<kind>.receipt`, then verifies the saved file |
| `le_verify_receipt <file> [state\|log]` | Verifies a saved receipt and judges its journal, offline |
| `le_cost [flags]` | Cycle gate for the staged steps (section 2) |
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

After `le_verify`: `BLOCK`, `G_BALANCE`, `G_VALUE` (from the guest), `I_BALANCE`, `I_VALUE` (from the
RPC). The independent check needs the block the host chose, so it runs after the proof.

### Log

```sh
le_log                                       # a USDC Transfer in the newest finalized block
LOGADDR=0x<contract> TOPIC0=0x<sig> le_log   # another contract or event
le_log --log-tx 130 --log-index 2            # a given position in the block
le_log --log-topic2 0x<padded address>       # also match the recipient (topic 2 of Transfer)
le_log --predicate data0==0x2710             # amount equals 10000
le_log_all
```

`le_log` prints a result block like `le_verify` and exits non-zero on any mismatch. After it:
`L_BLOCK`, `L_TX`, `L_LOGINDEX`, `L_ADDR`, `L_TOPICS`, `L_DATALEN`, `L_DATAHASH`, `L_ID` (from the
guest), `I_LOG` (from the RPC). The data itself is bound by `log_data_hash`.

### Prove and verify a receipt

Slow (about 66M cycles to prove). Use a GPU or Bonsai. Unset `RISC0_DEV_MODE`.

```sh
le_prove state                      # balance and slot of ADDR/SLOT
le_prove log                        # the log of LOGADDR/TOPIC0
le_prove log --predicate data0==0x2710
le_verify_receipt ./receipts/log.receipt log     # verify again, offline
```

Pass the same extra flags to `le_verify_receipt` as to the run (for example the predicate).

### Raw commands

Each task above expands to these (`le` is a shell function from `env.sh`):

```sh
# balance proof (always proven with the account), and storage inclusion proof
le --source $B --trusted-root $R --address $ADDR --execution-rpc $X --save-dir ./fixture
le --source $B --trusted-root $R --address $ADDR --slot $SLOT --execution-rpc $X --save-dir ./fixture

# enforce expected values (hex, left-padded). Exit 0 only if the guest's values equal them
le --source $B --trusted-root $R --address $ADDR --slot $SLOT --execution-rpc $X \
   --expect-value 0x<value> --expect-balance 0x<balance>

# tampered state must fail
le --source $B --trusted-root $R --address $ADDR --slot $SLOT --execution-rpc $X --tamper-exec    # 201
le --source $B --trusted-root $R --address $ADDR --slot $SLOT --execution-rpc $X --tamper-state   # 204

# log: first matching log in the finalized block; pinned position, predicate, expected ID
le --source $B --trusted-root $R --execution-rpc $X --log-address $LOGADDR --log-topic0 $TOPIC0
le --source $B --trusted-root $R --execution-rpc $X --log-address $LOGADDR --log-topic0 $TOPIC0 \
   --log-tx 130 --log-index 2 --predicate data0==0x2710 --expect-id 0x<id>

# log tamper runs
le --source $B --trusted-root $R --execution-rpc $X --log-address $LOGADDR --log-topic0 $TOPIC0 --tamper-exec      # 201
le --source $B --trusted-root $R --execution-rpc $X --log-address $LOGADDR --log-topic0 $TOPIC0 --tamper-receipt   # 204

# prove after a successful execute, then verify the saved receipt (offline, from the saved fixture)
le --source $B --trusted-root $R --address $ADDR --slot $SLOT --execution-rpc $X \
   --save-dir ./fixture --prove --receipt-out ./receipts/state.receipt
le --source ./fixture --trusted-root $(cat ./fixture/trusted_root) --address $ADDR --slot $SLOT \
   --execution-rpc ./fixture --verify-receipt ./receipts/state.receipt

# offline replay (use the root the fixture was saved with)
le --source ./fixture --trusted-root $(cat ./fixture/trusted_root) --address $ADDR --slot $SLOT --execution-rpc ./fixture
```

A slot value of all zeros means the slot is empty (a verified exclusion). Pick a slot with a
non-zero value to test inclusion.

### Sync only

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
# unit tests
cargo test -p le-sync-core                                 # 0 failures expected
cargo test -p le-sync-wire
cargo test -p le-sync-wire --features bls-zk,bls-blst --test staged_update --test rooted_update
cargo test --manifest-path bench/Cargo.toml                # argument parsing and the report
cargo test --release --manifest-path lez/executor-tests/Cargo.toml   # the LEZ program (section 3)
RISC0_SKIP_BUILD=1 cargo test -p le-sync -p le-sync-wire   # host and wire, no guest build
cargo test --workspace                                     # everything (builds the guest)

# mutation testing: 0 missed expected
./scripts/mutants.sh core
cargo mutants -p le-sync-wire
cargo mutants -p le-sync

# live (network)
source scripts/env.sh
le_log_all

# proof output (slow, unset RISC0_DEV_MODE)
le_prove state
le_prove log
le_verify_receipt ./receipts/state.receipt state
le_verify_receipt ./receipts/log.receipt log

# spec vectors (native, real blst)
cargo run -p le-sync-vectors --release -- <consensus-spec-tests dir> minimal
cargo run -p le-sync-vectors --release -- <consensus-spec-tests dir> mainnet
```

`staged_update` and `rooted_update` compare the staged runs with the single-shot `run`: same
accept or reject, same error, same resulting store. `rooted_update` also covers tampered hints
(every key and proof word), and a rooted store used with the full-key path.

---

## 6. Flags

| Flag | Use |
|---|---|
| `--source <URL\|DIR>` | Beacon API URL, or a saved directory |
| `--trusted-root 0x..` | Weak-subjectivity block root |
| `--address 0x..` | Account to prove. Implies `--sync` |
| `--slot 0x..` | Storage slot. Default `0x0` |
| `--execution-rpc <URL\|DIR>` | JSON-RPC with `eth_getProof` and `eth_getBlockReceipts`, or a saved directory. Required with `--address` or `--log-address` |
| `--expect-value 0x..` | Journal slot value must equal this |
| `--expect-balance 0x..` | Journal balance must equal this (wei) |
| `--tamper-state` | Corrupt the account proof. Guest must reject with 204 |
| `--tamper-exec` | Corrupt the execution state root and receipts root. Guest must reject with 201 |
| `--tamper-receipt` | Corrupt the receipt proof. Guest must reject with 204 |
| `--log-address 0x..` | Prove a log emitted by this contract. Needs `--execution-rpc` |
| `--log-topic0..3 0x..` | Require this topic at that position |
| `--log-tx N\|0x<hash>` | Transaction in the block: decimal index or hash. Default: first match |
| `--log-index N` | Log position within the receipt. Default 0. Needs `--log-tx` |
| `--predicate <t><op><v>` | Equality or inequality over a verified value. Routed to the state or log by target |
| `--expect-id 0x..` | Journal statement ID must equal this (log ID if a log is requested, else storage ID) |
| `--prove` | After a successful execute, prove the run and verify the receipt. Needs `--receipt-out` |
| `--receipt-out FILE` | With `--prove`: write the receipt here |
| `--verify-receipt FILE` | Verify a saved receipt and judge its journal. Give the flags of the original run |
| `--save-dir DIR` | Save every response for offline replay |
| `--count N` | Sync-committee periods to fetch. Raise it if the trusted root is old |

Exit codes: `0` OK, `1` failed, `2` usage error, `3` chain mismatch.

---

## 7. If it fails

| You see | Cause | Do |
|---|---|---|
| `eth_getProof failed: ... missing trie node` | RPC does not hold state at that block | Use another provider or a full node |
| `no update with a finalized execution header and >= 2/3 sync participation` | Beacon API gave no usable update | Use another beacon API, or raise `--count` |
| `NOT OK ... error code 201` | Execution header or branch does not verify | Keep `./fixture` and report it |
| `NOT OK ... error code 203` or `204` | Proof payload or its encoding does not verify | Keep `./fixture` and report it |
| `NOT OK ... error code 205` | No matching log at that position, or the receipt failed | Check `--log-tx`, `--log-index`, address and topics |
| `NOT OK ... error code 206` | The predicate is false for the verified value | Check the operand. Expected for a false predicate |
| `NOT OK ... error code 101` | Fork not supported | Use an Electra or Fulu network |
| `receipts root` mismatch (host) | The RPC's receipts do not rebuild the header's `receipts_root` | Use another provider. An unsupported receipt type is a possible cause |
| `eth_getBlockReceipts` errors | RPC does not serve block receipts | Use another provider or a full node |
| `RISC0_DEV_MODE is set` | Dev-mode receipts are fake | Unset it, then prove or verify |
| `does not verify against this build's guest image ID` | Receipt made by another guest build, or not a valid proof | Rebuild the same guest, or re-prove |
| `trusted root` errors | Checkpoint is stale or wrong | Take a fresh `$R` |
| `cost: FAIL (bench exit 101)` with `can't find bin` | A file named in `guest-stage/Cargo.toml` is missing | Check `ls guest-stage/src` against the `[[bin]]` paths |
| `cost: FAIL` with `MISMATCH` | The guest and the native run disagree | Report the step and both results |
| `cost: FAIL` with `a step is over the cap` | A step exceeds `--cap` | Read the table: which step, and how far |

---

## Verified runs

### Mainnet, 2026-10-24

| Item | Value |
|---|---|
| Account | WETH9, `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2` |
| Finalized slot / block | 15501952 / 26262717 |
| Balance | `0x1d939a6235e9dff0524d5` wei, equals `eth_getBalance` at that block |
| Slot `0x0` | `0x5772617070656420457468657200...1a` ("Wrapped Ether"), equals `eth_getStorageAt` |
| Tamper runs | 201 and 204, as expected |

### Cycles, single-shot guest (execute only)

| Part | Cycles |
|---|---|
| Whole guest | 65.7M |
| Read input | 9.0M |
| Sync (mostly BLS) | 54.3M |
| State: anchor | 50K |
| State: account proof | 568K |
| State: storage proof | 453K |

The staged steps in sections 2 and 3 are the version of the sync part that fits the LEZ cap.