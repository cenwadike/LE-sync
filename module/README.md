# eth_attest module

A Logos core module (Rust, cdylib) that follows Ethereum finality, advances an `eth_attest`
instance on LEZ, and attests account and storage state.

```
module/
  metadata.json            module metadata (codegen.rust points at rust-lib)
  rust-lib/                the Logos provider: the contract (.lidl) and a thin implementation
  ops/                     everything else, no Logos code: builds and tests with plain cargo
    src/config.rs          the environment file (config/<env>.toml)
    src/source.rs          EthSource: where Ethereum material comes from (HttpSource)
    src/convert.rs         beacon / execution JSON -> the program's wire types
    src/lez.rs             instructions, accounts, and the sequencer (WalletLez)
    src/plan.rs            the submitter's decisions, pure and tested
    src/submitter.rs       fetch, defer, re-check, begin / miller / finish
    src/engine.rs          the module's methods and the background submitter
    src/bin/eth_attest_ops.rs   the CLI the scripts call
```

Run the CLI (what `scripts/deploy.sh` and `scripts/e2e.sh` do):

```
cargo run --manifest-path module/ops/Cargo.toml --bin eth_attest_ops -- --config config/local.toml update
```

The wallet home must be exported first (both names, see `scripts/lez-env.sh`). The sequencer the
module talks to is the one in that wallet's configuration.

The ops crate also needs the Logos circuits v0.4.2 release. Extract the platform-appropriate
release bundle into `module/ops/.logos-blockchain-circuits/`; Cargo configures
`LOGOS_BLOCKCHAIN_CIRCUITS` to use that repository-local directory, and Git ignores its contents.

Not done: `attest_log` (needs the receipts-trie proof builder of `host/src/receipts.rs`), and a
Logos-module implementation of `EthSource` (`HttpSource` is the only one; the interface is the
place to add it). The e2e script reports log attestation as skipped and waits up to 900 seconds
for a finalized-header advance before testing account and storage attestations; set
`FINALITY_WAIT_SECS` to change that timeout. Its replay check treats an already-applied update as
an idempotent no-op and verifies the finalized slot does not change.
The flipped-signature case runs before the valid update so a fresh candidate is available, and
checks the native verifier's refusal without submitting a deliberately invalid transaction.
