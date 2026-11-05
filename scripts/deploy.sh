#!/usr/bin/env bash
# Usage: scripts/deploy.sh <local|testnet> [--skip-build] [--skip-deploy]
# Builds the guest, deploys it, fills in the chain parameters and the trusted root, runs
# init_instance, and writes program_id and instance_id back into config/<env>.toml.
# Each run takes the current finalized root as the checkpoint, so each run makes a new instance.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
shift || true
SKIP_BUILD=0; SKIP_DEPLOY=0
for a in "$@"; do case "$a" in
  --skip-build) SKIP_BUILD=1 ;; --skip-deploy) SKIP_DEPLOY=1 ;; *) die "unknown flag $a" ;;
esac; done

SEQ="$(cfg lez sequencer_url)"; [ -n "$SEQ" ] || die "[lez] sequencer_url is empty in $CONFIG"
[ -n "$(cfg lez account)" ] || die "[lez] account is empty in $CONFIG"
B="$(beacon)"

say "1/6 chain parameters from $B"
if [ -z "$(cfg instance genesis_time)" ]; then
  gen="$(fetch "$B/eth/v1/beacon/genesis")"
  spec="$(fetch "$B/eth/v1/config/spec")"
  cfg_set instance genesis_time "$(jget "$gen" 'd["data"]["genesis_time"]')"
  cfg_set instance genesis_validators_root "$(jget "$gen" 'd["data"]["genesis_validators_root"]')"
  cfg_set instance seconds_per_slot "$(jget "$spec" 'd["data"]["SECONDS_PER_SLOT"]')"
  cfg_set instance electra_fork_epoch "$(jget "$spec" 'd["data"]["ELECTRA_FORK_EPOCH"]')"
  cfg_set instance forks "$(jget "$spec" '",".join(n.lower()+":"+d["data"][n+"_FORK_EPOCH"]+":"+d["data"][n+"_FORK_VERSION"] for n in ("ELECTRA","FULU"))')"
  echo "   written from the beacon API. The instance trusts these values: compare them with an"
  echo "   independent public source before you rely on the instance."
fi
for k in genesis_time genesis_validators_root seconds_per_slot forks; do
  echo "   $k = $(cfg instance $k)"
done

say "2/6 trusted root (finalized checkpoint)"
root="$(jget "$(fetch "$B/eth/v1/beacon/headers/finalized")" 'd["data"]["root"]')"
B2="$(cfg eth beacon_url_2)"
if [ -n "$B2" ] && [ "$(cfg eth source)" != replay ]; then
  root2="$(jget "$(fetch "$B2/eth/v1/beacon/headers/finalized")" 'd["data"]["root"]')"
  [ "$root" = "$root2" ] || die "the two beacon APIs disagree on the finalized root ($root vs $root2); run again, or check them"
else
  echo "   warning: no second beacon API set, so this root rests on one provider"
fi
cfg_set instance trusted_root "$root"; echo "   trusted_root = $root"

LEZ_DIR="$ROOT/$(cfg lez lez_dir)"
if [ "$SKIP_BUILD" = 0 ]; then
  say "3/6 build the guest"
  (cd "$LEZ_DIR" && lgs build --guest local)
fi
# Use the artifact from the scaffold build, not a possibly stale executor-tests/target copy.
BIN="${BIN:-$LEZ_DIR/target/riscv-guest/execute_attestation_deployment_methods/execute_attestation_deployment_programs/riscv32im-risc0-zkvm-elf/release/eth_attest.bin}"
[ -n "$BIN" ] && [ -f "$BIN" ] || die "guest binary not found; set BIN=/path/to/eth_attest"
echo "   BIN = $BIN"

say "4/6 program id"
pid="$(cd "$LEZ_DIR" && RISC0_SKIP_BUILD=1 cargo run -q --bin run_eth_attest -- --program-path "$BIN" | sed -n 's/^eth_attest program id: //p')"
[ -n "$pid" ] || die "could not read the program id"
cfg_set lez program_id "$pid"; echo "   program_id = $pid"

say "5/6 deploy"
if [ "$SKIP_DEPLOY" = 0 ]; then
  if [ -n "${DEPLOY_CMD:-}" ]; then
    $DEPLOY_CMD "$BIN"
  elif [ "$ENV_NAME" = local ]; then
    (cd "$ROOT/$(cfg lez lez_dir)" && lgs deploy --program-path "$BIN")
  else
    die "set DEPLOY_CMD to the command that deploys a program binary to this sequencer, with the binary path as its last argument"
  fi
fi

say "6/6 init_instance"
iid="$(ops init)"
[ -n "$iid" ] || die "init_instance returned no instance id"
cfg_set lez instance_id "$iid"; echo "   instance_id = $iid"
echo "done: $ENV_NAME is deployed and initialised"
