#!/usr/bin/env bash
# Usage: tests/e2e/run.sh <local|testnet> <replay|live> [--stack-only]
#
# The whole thing against a LEZ sequencer that is already running (the one your wallet points
# at), with one command and a clean exit code:
#   1. works on a COPY of config/<env>.toml, so your file is untouched
#   2. replay: starts scripts/replay_server.sh over fixtures/<network>/ (run scripts/record-fixtures.sh
#      first); live: uses the real beacon and execution endpoints of the config
#   3. scripts/deploy.sh <env>   (guest build, deploy, init_instance)
#   4. scripts/e2e.sh <env>      (update, attestations, refusals, race, resume)
#
# DEPLOY_CMD must be set (see scripts/deploy.sh). The wallet home must be exported (both
# names; scripts/lez-env.sh). A replay run has one recorded cycle, so it advances the instance
# once; the live run keeps advancing with the real chain.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"
ENV="${1:?usage: tests/e2e/run.sh <local|testnet> <replay|live> [--stack-only]}"
MODE="${2:?second argument: replay or live}"
shift 2
case "$MODE" in replay|live) ;; *) echo "mode must be replay or live" >&2; exit 2 ;; esac

TMP="$(mktemp -d)"; export CONFIG="$TMP/$ENV.toml"
cp "$ROOT/config/$ENV.toml" "$CONFIG"
cleanup() { [ -n "${SERVER:-}" ] && kill "$SERVER" 2>/dev/null || true; }
trap cleanup EXIT

. "$ROOT/scripts/lib.sh" "$ENV"

if [ "$MODE" = replay ]; then
  for t in socat jq; do command -v "$t" >/dev/null 2>&1 || die "$t is required for replay mode"; done
  NET="$(cfg eth network)"; FIX="$ROOT/fixtures/$NET"
  [ -d "$FIX/beacon" ] || die "no fixtures for $NET: run scripts/record-fixtures.sh $ENV first"
  PORT="$(cfg eth replay_url | sed 's#.*:##; s#/.*##')"
  "$ROOT/scripts/replay_server.sh" --fixtures "$FIX" --port "$PORT" 2> "$TMP/replay.log" &
  SERVER=$!
  for _ in 1 2 3 4 5 6 7 8 9 10; do curl -fs "$(cfg eth replay_url)/eth/v1/beacon/genesis" >/dev/null 2>&1 && break; sleep 0.5; done
  curl -fs "$(cfg eth replay_url)/eth/v1/beacon/genesis" >/dev/null || die "replay server did not start (see $TMP/replay.log)"
  cfg_set eth source replay
  say "replay server up on port $PORT"
fi

"$ROOT/scripts/deploy.sh" "$ENV"
"$ROOT/scripts/e2e.sh" "$ENV" "$@"
echo "e2e passed ($ENV, $MODE). config used: $CONFIG"
