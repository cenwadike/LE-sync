#!/usr/bin/env bash
# One command for the whole thing:
#
#   scripts/run.sh [local|testnet] [live|replay] [--skip-tests] [--reuse] [--stack-only]
#
#   local|testnet  which config/<env>.toml (default local)
#   live|replay    real Ethereum mainnet endpoints, or recorded fixtures through scripts/replay_server.sh
#                  (default live; replay needs fixtures: scripts/record-fixtures.sh <env>)
#   --skip-tests   skip the cargo unit tests of module/ops
#   --reuse        do not deploy again: use the instance already in the config
#   --stack-only   stop e2e after the on-chain steps (no refusal / race / resume cases)
#
# Steps, each logged to .run/<time>/<n>-<name>.log, stopping at the first failure:
#   1 tools  2 localnet  3 account  4 build + unit tests  5 [replay server]  6 deploy  7 e2e
# A copy of the config is used, so config/<env>.toml is not rewritten (the final copy is kept in
# .run/<time>/ with the program and instance IDs).
set -uo pipefail

ENV_NAME=local; MODE=live; SKIP_TESTS=0; REUSE=0; STACK_ONLY=""
for a in "$@"; do case "$a" in
  local|testnet) ENV_NAME="$a" ;; live|replay) MODE="$a" ;;
  --skip-tests) SKIP_TESTS=1 ;; --reuse) REUSE=1 ;; --stack-only) STACK_ONLY="--stack-only" ;;
  -h|--help) sed -n '2,17p' "$0"; exit 0 ;; *) echo "unknown argument: $a (see --help)" >&2; exit 2 ;;
esac; done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN="$ROOT/.run/$(date +%Y%m%d-%H%M%S)"; mkdir -p "$RUN"
export CONFIG="$RUN/$ENV_NAME.toml"; cp "$ROOT/config/$ENV_NAME.toml" "$CONFIG"
. "$ROOT/scripts/lib.sh" "$ENV_NAME"

N=0; SERVER=""
step() { N=$((N + 1)); STEP="$(printf '%02d' $N)-$1"; LOG="$RUN/$STEP.log"; printf '\n[%s] %s\n' "$N" "$2"; }
tail_log() { echo "---- last lines of $LOG ----" >&2; tail -n "${1:-25}" "$LOG" >&2; }
stop_all() { [ -n "$SERVER" ] && kill "$SERVER" 2>/dev/null; true; }
trap stop_all EXIT
fail() { # message, [hint]
  echo "FAILED at step $STEP: $1" >&2
  [ -f "$LOG" ] && tail_log
  [ -n "${2:-}" ] && echo "hint: $2" >&2
  echo "logs: $RUN" >&2; exit 1
}
ok() { echo "    ok: $*"; }

# with_timeout <seconds> <cmd...>: macOS has no `timeout`
with_timeout() {
  local secs="$1"; shift
  "$@" >>"$LOG" 2>&1 & local pid=$!
  ( sleep "$secs"; kill "$pid" 2>/dev/null ) & local killer=$!
  wait "$pid" 2>/dev/null; local rc=$?
  kill "$killer" 2>/dev/null; wait "$killer" 2>/dev/null
  return $rc
}

LEZ="$ROOT/$(cfg lez lez_dir)"
ACCOUNT="$(cfg lez account)"

# ---- 1 tools ---------------------------------------------------------------------------------
step tools "tools and files"
for t in lgs cargo python3 curl; do
  command -v "$t" >/dev/null 2>&1 || fail "$t is not installed or not on PATH"
done
if [ "$MODE" = replay ]; then
  for t in socat jq; do
    command -v "$t" >/dev/null 2>&1 || fail "$t is required for replay mode"
  done
fi
for f in module/ops/Cargo.toml scripts/deploy.sh scripts/e2e.sh scripts/replay_server.sh; do
  [ -e "$ROOT/$f" ] || fail "$f is missing" "unzip the latest le-sync zips into the repo root"
done
[ -n "$ACCOUNT" ] || fail "[lez] account is empty in config/$ENV_NAME.toml" "put the address from 'lgs wallet list' there"
[ -f "$ROOT/scripts/lez_env.sh" ] && . "$ROOT/scripts/lez_env.sh" >/dev/null 2>&1 || true
export NSSA_WALLET_HOME_DIR="${NSSA_WALLET_HOME_DIR:-${LEE_WALLET_HOME_DIR:-$LEZ/.scaffold/wallet}}"
export LEE_WALLET_HOME_DIR="$NSSA_WALLET_HOME_DIR"
[ "$ENV_NAME" = local ] && export RISC0_DEV_MODE=1
ok "wallet home $NSSA_WALLET_HOME_DIR"

# ---- 2 localnet ------------------------------------------------------------------------------
step localnet "local sequencer"
if [ "$ENV_NAME" = local ]; then
  if (cd "$LEZ" && lgs localnet status) 2>&1 | tee "$LOG" | grep -q "ready: true"; then
    ok "already running"
  else
    (cd "$LEZ" && with_timeout 180 lgs localnet start) || fail "localnet did not start"
    ok "started with RISC0_DEV_MODE=1"
  fi
else
  ok "testnet: using the sequencer in the wallet configuration"
fi

# ---- 3 account -------------------------------------------------------------------------------
step account "funded account $ACCOUNT"
balance() { (cd "$LEZ" && lgs wallet -- account get --account-id "$ACCOUNT") 2>>"$LOG" | tee -a "$LOG" |
  python3 -c 'import sys,json,re; t=sys.stdin.read(); m=re.search(r"\{.*\}",t); print(json.loads(m.group(0)).get("balance",0) if m else 0)' 2>/dev/null; }
b="$(balance)"; b="${b:-0}"
if [ "$b" -gt 0 ] 2>/dev/null; then
  ok "balance $b"
elif [ "$ENV_NAME" = local ]; then
  (cd "$LEZ" && lgs wallet default set "$ACCOUNT") >>"$LOG" 2>&1 || fail "could not set the default account"
  (cd "$LEZ" && with_timeout 150 lgs wallet topup) || {
    echo "    topup did not finish in 150s; sequencer log:" >&2; (cd "$LEZ" && lgs localnet logs --tail 30) >&2
    fail "topup failed or timed out" "a line 'ClaimedUnauthorizedAccount' means this wallet has no key for $ACCOUNT: make a new account (lgs wallet -- account new public) and put it in the config"; }
  b="$(balance)"; [ "${b:-0}" -gt 0 ] 2>/dev/null || fail "still no balance after topup"
  ok "funded, balance $b"
else
  fail "no balance on $ACCOUNT" "fund it on the testnet first"
fi

# ---- 4 build + unit tests --------------------------------------------------------------------
step build "build module/ops and run its unit tests"
cargo build --manifest-path "$ROOT/module/ops/Cargo.toml" --bin eth_attest_ops >"$LOG" 2>&1 \
  || fail "module/ops does not build" "send the first errors in $LOG"
ok "built eth_attest_ops"
if [ "$SKIP_TESTS" = 0 ]; then
  cargo test --manifest-path "$ROOT/module/ops/Cargo.toml" --lib >>"$LOG" 2>&1 || fail "module/ops unit tests failed"
  ok "$(grep -E '^test result' "$LOG" | tail -1)"
fi

# ---- 5 replay server -------------------------------------------------------------------------
if [ "$MODE" = replay ]; then
  step replay "replay server"
  FIX="$ROOT/fixtures/$(cfg eth network)"
  [ -d "$FIX/beacon" ] || fail "no fixtures in $FIX" "run: scripts/record-fixtures.sh $ENV_NAME"
  PORT="$(cfg eth replay_url | sed 's#.*:##; s#/.*##')"
  "$ROOT/scripts/replay_server.sh" --fixtures "$FIX" --port "$PORT" >"$LOG" 2>&1 & SERVER=$!
  for _ in $(seq 1 20); do curl -fs "$(cfg eth replay_url)/eth/v1/beacon/genesis" >/dev/null 2>&1 && break; sleep 0.5; done
  curl -fs "$(cfg eth replay_url)/eth/v1/beacon/genesis" >/dev/null 2>&1 || fail "replay server did not start"
  cfg_set eth source replay; ok "serving $FIX on port $PORT"
fi

# ---- 6 deploy --------------------------------------------------------------------------------
step deploy "deploy eth_attest and init_instance"
if [ "$REUSE" = 1 ] && [ -n "$(cfg lez instance_id)" ]; then
  ok "reusing instance $(cfg lez instance_id)"
else
  "$ROOT/scripts/deploy.sh" "$ENV_NAME" >"$LOG" 2>&1 \
    || { (cd "$LEZ" && lgs localnet logs --tail 15) 2>/dev/null >&2; fail "deploy failed"; }
  ok "program_id $(cfg lez program_id)"; ok "instance_id $(cfg lez instance_id)"
fi

# ---- 7 e2e -----------------------------------------------------------------------------------
step e2e "attestation flow"
"$ROOT/scripts/e2e.sh" "$ENV_NAME" $STACK_ONLY 2>&1 | tee "$LOG" | grep -E "^(PASS|FAIL|==|all steps|stack-only|error)"
rc=${PIPESTATUS[0]}
[ "$rc" = 0 ] || { (cd "$LEZ" && lgs localnet logs --tail 15) 2>/dev/null >&2; fail "e2e failed (see the FAIL line above)"; }

printf '\nALL STEPS PASSED (%s, %s)\nconfig with the IDs: %s\nlogs: %s\n' "$ENV_NAME" "$MODE" "$CONFIG" "$RUN"