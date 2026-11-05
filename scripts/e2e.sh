#!/usr/bin/env bash
# Usage: scripts/e2e.sh <local|testnet> [--stack-only]
# Runs the whole flow against an already deployed and initialised instance (scripts/deploy.sh).
# Every step prints PASS or FAIL; the script stops at the first FAIL.
# Waits up to FINALITY_WAIT_SECS (default 900) for a finalized-header advance.
#   --stack-only   stop after the on-chain steps (no negative or race cases)
set -uo pipefail
. "$(dirname "$0")/lib.sh"
shift || true
STACK_ONLY=0; [ "${1:-}" = "--stack-only" ] && STACK_ONLY=1
[ -n "$(cfg lez instance_id)" ] || die "no instance_id in $CONFIG: run scripts/deploy.sh $ENV_NAME first"

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*" >&2; exit 1; }
expect_ok() { local name="$1"; shift; local out; out="$("$@" 2>&1)" && pass "$name" || { echo "$out" >&2; fail "$name"; }; }
# expect_code <name> <regex> <cmd...>: the command must be refused, with a message matching the
# regex (extended; "le-sync error (a|b)" style codes, or SPEL's own text). Codes marked "confirm"
# below are my reading of the program and are pinned to one value after the first run.
expect_code() { local name="$1" re="$2"; shift 2; local out; out="$("$@" 2>&1)" && { echo "$out" >&2; fail "$name: accepted"; }
  echo "$out" | grep -Eq "$re" && pass "$name" || { echo "$out" >&2; fail "$name: refused, but not with /$re/"; }; }

say "state before"; ops show
before="$(ops slot)"

if [ "$STACK_ONLY" != 1 ]; then
  say "negative cases: reject invalid update attempts"
  tamper_out="$(ops update --tamper signature 2>&1)"
  if [ "$?" = 0 ]; then
    echo "$tamper_out" >&2
    fail "update with a flipped signature byte: accepted"
  elif [[ "$tamper_out" == *"no ready update to test signature rejection"* ]]; then
    echo "SKIP  flipped-signature update (no currently signable update)"
  elif echo "$tamper_out" | grep -Eq "le-sync error 400"; then
    pass "update with a flipped signature byte"
  else
    echo "$tamper_out" >&2
    fail "update with a flipped signature byte: refused with the wrong error"
  fi
  expect_code "miller before begin" "le-sync error 308" ops update --only miller
fi

say "update: wait for a finalized-header advance"
WAIT_SECS="${FINALITY_WAIT_SECS:-900}"
POLL_SECONDS="$(cfg submitter poll_seconds)"
[[ "$WAIT_SECS" =~ ^[0-9]+$ ]] && [ "$WAIT_SECS" -gt 0 ] || fail "FINALITY_WAIT_SECS must be a positive integer"
[[ "$POLL_SECONDS" =~ ^[0-9]+$ ]] && [ "$POLL_SECONDS" -gt 0 ] || fail "[submitter] poll_seconds must be a positive integer"
deadline=$((SECONDS + WAIT_SECS))
while :; do
  update_out="$(ops update 2>&1)" || { echo "$update_out" >&2; fail "submitter update failed"; }
  after="$(ops slot)" || fail "could not read finalized slot after update"
  if [ "$after" -gt "$before" ]; then
    pass "finalized slot $before -> $after"
    break
  fi
  if [ "$SECONDS" -ge "$deadline" ]; then
    echo "$update_out" >&2
    fail "no finalized-header advance from slot $before after ${WAIT_SECS}s (still at $after)"
  fi
  echo "waiting for a newer finalized header (slot $after); retrying in ${POLL_SECONDS}s"
  sleep "$POLL_SECONDS"
done

say "attestations"
ADDR="$(cfg fixtures address)"; SLOT0="$(cfg fixtures storage_slots | cut -d, -f1)"
expect_ok "attest an account"  ops attest-account --address "$ADDR"
expect_ok "attest a storage slot" ops attest-storage --address "$ADDR" --slot "$SLOT0"
TOPIC0="$(cfg fixtures log_topic0)"
log_out="$(ops attest-log --address "$ADDR" --topic0 "$TOPIC0" 2>&1)" \
  && pass "attest an event log" \
  || {
    if [[ "$log_out" == *"no successful log in finalized block"* ]]; then
      echo "SKIP  attest an event log (no configured event in the newest finalized block)"
    else
      echo "$log_out" >&2
      fail "attest an event log"
    fi
  }

[ "$STACK_ONLY" = 1 ] && { echo "stack-only: done"; exit 0; }

say "replay safety and negative cases"
before="$(ops slot)"
replay_out="$(ops update --replay-last 2>&1)" || { echo "$replay_out" >&2; fail "replaying the applied update should be a no-op"; }
after="$(ops slot)"
[[ "$replay_out" == *"up_to_date_at: Some("* ]] && [ "$after" = "$before" ] \
  && pass "replayed update is safely ignored at slot $after" \
  || { echo "$replay_out" >&2; fail "replayed update changed state or was not recognized as up to date"; }
expect_code "attestation, tampered header root"     "le-sync error 316" ops attest-account --address "$ADDR" --tamper header-root
expect_code "attestation, tampered proof"           "le-sync error 204" ops attest-account --address "$ADDR" --tamper proof
expect_code "wrong instance id"                     "le-sync error 318|account validation failed" ops attest-account --address 0x0000000000000000000000000000000000000000 --instance-id 0x$(printf '11%.0s' $(seq 32))   # confirm

say "two submitters at once"
before="$(ops slot)"
( ops update > /tmp/e2e-race-a.log 2>&1; echo $? > /tmp/e2e-race-a.rc ) &
( ops update > /tmp/e2e-race-b.log 2>&1; echo $? > /tmp/e2e-race-b.rc ) &
wait
ra="$(cat /tmp/e2e-race-a.rc)"; rb="$(cat /tmp/e2e-race-b.rc)"
[ $((ra + rb)) -le 1 ] && pass "at most one racer failed ($ra, $rb)" || fail "both racers failed"
after="$(ops slot)"
[ "$after" -ge "$before" ] && pass "state intact, slot $before -> $after" || fail "slot went backwards"
expect_ok "state still readable and attestable" ops attest-account --address "$ADDR"

say "kill mid-update, then resume"
ops update --kill-after begin >/dev/null 2>&1 || true
expect_ok "a restarted submitter finishes from the on-chain job" ops update --resume

echo "all exercised steps passed on $ENV_NAME"
