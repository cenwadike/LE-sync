# LE-sync(Logos Ethereum Synchronizer)

```

  HOST (std: network + JSON only)                CORE (#![no_std]: pure checks, the part that goes into the guest)
 ─────────────────────────────────              ─────────────────────────────────────────────────────────────────

 0  GET /eth/v1/config/spec                     
    └─► Parse JSON to extract parameters:       
        • SLOTS_PER_EPOCH (e.g., 32)            
        • ELECTRA_FORK_EPOCH                    
        • GLOAS_FORK_EPOCH (if scheduled) ──────► Store in ChainConfig struct. 
                                                  (Used to evaluate fork rules dynamically).

 1  GET /eth/v1/beacon/light_client/            
    bootstrap/{trusted_root}                    
    └─► Extract from JSON response:             
        • Header (slot, proposer_index,         
          parent_root, state_root, body_root)   
        • 512 validator BLS pubkeys             
        • Aggregate public key                  
        • current_sync_committee_branch   ──────► verify_bootstrap(cfg, trusted_root, header, pubkeys, aggregate, branch)
                                                  ├── a. htr(header) == trusted_root?
                                                  │      (Checks container of 5 fields across 8 chunks; 
                                                  │       fails with TrustedRootMismatch if false)
                                                  ├── b. gindex = cfg.gindices_at_slot(header.slot)
                                                  │      • epoch = header.slot / slots_per_epoch
                                                  │      • if epoch >= gloas_fork_epoch ──► Err(UnsupportedFork)
                                                  │      • if epoch >= electra_fork_epoch ──► gindex = 86 (Electra+)
                                                  │      • else ──► gindex = 54 (Altair..Deneb)
                                                  ├── c. leaf = sync_committee_root(pubkeys, aggregate)
                                                  │      • Hashes 512 pubkey chunks into a binary tree root
                                                  │      • Combines with aggregate key via hash_pair
                                                  │      • Checks size == 512 (power of two) or returns BadSyncCommitteeSize
                                                  └── d. is_valid_normalized_merkle_branch(leaf, branch, gindex, state_root)
                                                         • floorlog2(gindex) determines required depth (depth 6 for gindex 86)
                                                         • Normalizes branch: extra leading nodes must be all ZERO
                                                         • Hashes leaf up through branch to match state_root

 2  period = bootstrap.slot /                   
    (SLOTS_PER_EPOCH × EPOCHS_PER_PERIOD)       
    GET /eth/v1/beacon/light_client/updates     
    ?start_period=period&count=N                
    └─► Returns array of updates containing     
        attested headers, finalized headers,    
        and finality branches.                  

 3  GET /eth/v1/beacon/light_client/            
    finality_update                             
    └─► Extract for each item:                  
        • attested_header                       
        • finalized_header                      
        • finality_branch                 ──────► check_finality / verify_finality_branch(cfg, attested, finalized, branch)
                                                  ├── a. gindex = cfg.gindices_at_slot(attested.slot)
                                                  │      • if epoch >= gloas_fork_epoch ──► Err(UnsupportedFork)
                                                  │      • if epoch >= electra_fork_epoch ──► gindex = 169 (Electra+)
                                                  │      • else ──► gindex = 105 (Altair..Deneb)
                                                  ├── b. leaf = if finalized.slot == 0 {
                                                  │         if !finalized.is_empty() ──► Err(GenesisFinalizedHeaderNotEmpty)
                                                  │         ZERO (special genesis case)
                                                  │      } else {
                                                  │         htr(finalized_header)
                                                  │      }
                                                  └── c. is_valid_normalized_merkle_branch(leaf, branch, gindex, state_root)
                                                         • floorlog2(169) = depth 7 (Electra) or depth 6 (Pre-Electra)
                                                         • Validates tree path from finalized block root up to 
                                                           attested_header.state_root
                                                         • Fails if any byte is tampered (bit-flip rejection test)

```

## Run

```sh
cargo test --workspace

# live (needs a beacon node that serves /eth/v1/beacon/light_client/*)
cargo run -p le-sync --release -- \
  --source https://<beacon-api> --trusted-root 0x<checkpoint block root> \
  --save-dir fixtures/<chain>-<date>

# same data offline, then the "flipped byte must fail" check
cargo run -p le-sync --release -- --source fixtures/<chain>-<date> --trusted-root 0x<root>
cargo run -p le-sync --release -- --source fixtures/<chain>-<date> --trusted-root 0x<root> --tamper
```

`--trusted-root` is the weak-subjectivity checkpoint: the **block root** of the first block of a
recently finalized epoch (not an execution hash). Confirm it against 2+ independent explorers.
The bootstrap is rejected, and the run aborts, if its header does not hash to it.

## What is checked, and where it comes from

| Check | Spec source |
|---|---|
| `htr(bootstrap.header.beacon) == trusted_root` | altair `initialize_light_client_store` |
| current sync committee proven under `header.state_root` | same; gindex 54 (altair..deneb) / **86** (electra, fulu) |
| `finality_branch` proves `htr(finalized_header.beacon)` under `attested_header.state_root` | altair `validate_light_client_update`; gindex 105 / **169** |
| genesis special case (finalized slot 0 → empty header, zero leaf) | same |
| branch longer than depth: extra leading nodes must be zero | altair `is_valid_normalized_merkle_branch` |
| gindex picked from the header **slot** vs `ELECTRA_FORK_EPOCH` (never from the branch length) | electra `*_gindex_at_slot` |

Depth / subtree index: 105 → (6, 41), 169 → (7, 41), 54 → (5, 22), 86 → (6, 22).

**Fulu** adds only `proposer_lookahead` (38th, last `BeaconState` field; still 64 leaves), so no
light-client gindex changes, and Electra..=Fulu light-client data uses the Electra SSZ types.
`core` has a test deriving 105/54/55 and 169/86/87 from the `BeaconState` field lists.

**Gloas** changes the gindices and is *not* implemented. `core` returns `UnsupportedFork` for slots
at/after `GLOAS_FORK_EPOCH`, and the host refuses `version` values newer than `fulu`
(fail closed). Per `across-protocol/sp1-helios#92`, Sepolia forked to Gloas at epoch 353024
(~2026-10-06), so Sepolia data after that is refused by design. Use mainnet or Hoodi, and check
Hoodi's Gloas schedule.

## Logos / LEZ constraints honoured

* `le-sync-core` is `#![no_std]`, allocation-free, one dependency: `sha2` with
  `default-features = false`. Fixed-size arrays only (the 512-key committee root uses a 16 KiB
  stack buffer; no `Vec`).
* No clocks, randomness, threads, network or filesystem in `core`. All I/O is in `host`.
* The RISC Zero guest build needs the LEZ-pinned toolchain and the risc0 `sha2` `[patch]` in the
  *guest* workspace (see `risc0/risc0` examples). That is Sprint 2's gate; nothing here blocks it.

## Verification status (be precise about this before relying on it)

Done in the authoring sandbox:
* `core`: 11 unit tests pass; the non-test code also compiles with `#![no_std]` active.
* `host`: 4 tests pass (offline pipeline on synthetic Electra-era data, tamper, wrong root,
  Gloas refusal); the CLI was run end-to-end (exit codes checked); the header root was
  cross-checked against an independent Python/hashlib computation.

