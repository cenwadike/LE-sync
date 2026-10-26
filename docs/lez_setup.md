# LEZ setup

Ran and confirmed on 2026-10-26.

## 1. Prerequisites

- Linux x86_64 or macOS. git, Rust (rustc, cargo), curl, lsof, ps, kill.
- Docker (daemon running) or Podman, for guest builds.
- RISC Zero toolchain: `rzup`, with `cargo-risczero` 3.0.5 (matches our guest).
- About 5 GB disk. First `setup` can take about 20 minutes on four cores.

```bash
curl -L https://risczero.com/install | bash      # source terminal or restart the shell
rzup install rust
rzup install cargo-risczero 3.0.5
```

## 2. Install the scaffold

`lgs` and `logos-scaffold` are the same tool (the repo installs both).
The docs page for deploying with the scaffold says the crates.io release lacks the Docker guest build,
and installs from git at a fixed commit:

```bash
cargo install --locked --git https://github.com/logos-co/scaffold --rev d4b15ff logos-scaffold
```

**Open:** that commit pins LEZ v0.1.2 (confirmed in `scaffold.toml` and `doctor`). This is not "LEZ 0.4".
The scaffold README mentions LEZ v0.2.0. Which scaffold commit gives the LEZ version we target is open.

## 3. Commands (via `scripts/lez_env.sh`)

| Step | Function | Underlying command |
|---|---|---|
| check | `lez_check` | versions only |
| create | `lez_new` | `lgs new lez --template lez-framework` |
| setup | `lez_setup` | `lgs setup`, `lgs doctor` |
| build | `lez_build` | `RISC0_DEV_MODE=1 lgs build --guest local` |
| start | `lez_up` | `RISC0_DEV_MODE=1 lgs localnet start`, `localnet status` (port 3040) |
| deploy | `lez_deploy` | `RISC0_DEV_MODE=1 lgs deploy lez_counter` |
| fund | `lez_authority` | `lgs wallet topup` (default account, becomes the signer) |
| init | `lez_init` | `lgs spel -- --idl idl/lez_counter.json --program <bin> -- initialize --authority <ID>` |
| call | `lez_incr` | same, `increment --amount N --authority <ID>` |
| read | `lez_read` | `lgs wallet -- account get --account-id Public/<PDA>` |
| stop | `lez_down` | `lgs localnet stop` |

Notes (confirmed on the run, 2026-10-26):
- The template program is `lez_counter` (SPEL).
- **The template's client binary `src/bin/run_lez_counter.rs` is a stub** (`// TODO: submit transaction via wallet`):
  it prints and submits nothing. Use the `spel` CLI.
- `spel --dry-run` prints the resolved transaction and the PDA without sending it.
- `deploy` confirms submission, not inclusion. `spel` waits for inclusion and says so.
- Counter state is in `data` (8 bytes little-endian), not `balance`: the program rejects balance changes.
- Wallet exports for any client: `NSSA_WALLET_HOME_DIR` and `LEE_WALLET_HOME_DIR` = `<project>/.scaffold/wallet`.
- `RISC0_DEV_MODE=1` is for the local sequencer only. Receipts are fake.
- Blocks come about every 15 s and every block carries one background transaction.
- The sequencer log is `.scaffold/logs/sequencer.log` (UTC). `lgs localnet logs` shows only the last 40 blocks.
- Docker guest build failed on Apple Silicon: `no match for platform in manifest` for
  `risczero/risc0-guest-builder:r0.1.97.0`. Local build (`--guest local`) works.
- `cargo run` of the template binaries rebuilds the guest crate and failed in `ring` with
  `-mmacosx-version-min` unrecognised by the RISC-V gcc. `RISC0_SKIP_BUILD=1` avoids it. Cause unconfirmed.

## 4. Done-when record

| Item | Value |
|---|---|
| host | macOS, Apple Silicon (toolchain `aarch64-apple-darwin`) |
| scaffold | built from `logos-co/scaffold` rev `d4b15ff` |
| LEZ | tag v0.1.2, commit `cf3639d8252040d13b3d4e933feb19b42c76e14a` |
| SPEL | v0.5.0, commit `73fc462eb8f0a4d00f1a846437c627ec2e523f83` |
| logos-blockchain-circuits | v0.4.1 |
| risc0 / cargo-risczero / r0vm | 3.0.5 (3.0.6 also installed; the template host crates compile risc0-zkvm 3.0.6) |
| guest builder (Docker, unused) | `risczero/risc0-guest-builder:r0.1.97.0` |
| lez_counter program ID, macOS local build | `42772109bf124454bc1dbe9a87a6022aa008fb029586aa9151dec954739ec80d` |
| lez_counter program ID, Linux build | Not measured. The Docker build fails on this Mac (no arm64 manifest). Deferred to M5. Tessera reports the IDs differ, so the pinned one must be the one the sequencer accepts |
| deploy | submitted; included at about 22:54 UTC (block with 2 transactions) |
| counter PDA | `B6s86Rgs6j5myBGbG9jcMs8MCCuRS9NDDo5Wnwk7qWH5` (seeds: program ID, "counter") |
| initialize | confirmed in a block; data `0000000000000000` |
| increment 1 | confirmed in a block; data `0100000000000000` |

## 5. Questions M0 must answer

| Question | Answer |
|---|---|
| Program model in the template | SPEL: `#[lez_program]`, `#[instruction]`, `#[account(...)]` (read from `lib.rs`). Guest in `methods/guest/src/bin/`, host copy in `src/lib.rs` for IDL. Must stay in step |
| Can one program call another (needed for the M3 consumer)? | Not confirmed. Instructions return `SpelOutput::execute(accounts, vec![])`; the second vector may be chained calls. Source check pending |
| Account data size limit | Not yet read from the LEZ source. The counter used 8 bytes |
| Transaction size limit | Not yet read from the LEZ source |
| Per-transaction cycle cap, and whether localnet enforces it | Not yet read from the LEZ source. About 10M is a third-party claim, unverified |
| Dev mode on the local sequencer, effect on the private path | Public transactions are re-executed by the sequencer (the log shows `execution time` per transaction). Private path not tested |