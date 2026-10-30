#!/usr/bin/env bash
# le-sync environment. Source it, do not execute it:
#
#   source scripts/env.sh
#
# Override before sourcing if needed: B (beacon API), X (execution RPC), R (trusted root),
# ADDR, SLOT, FIXTURE (save dir, default ./fixture),
# LOGADDR (contract to prove an event of, default USDC), TOPIC0 (event signature hash,
# default ERC-20 Transfer), FIXTURE_LOG (save dir for log runs, default ./fixture-log),
# RECEIPT_DIR (where le_prove saves receipts, default ./receipts).
# RISC0_DEV_MODE must be unset to prove or verify: its receipts are fake.
#
# Commands after sourcing:
#   le_verify       prove ADDR/SLOT in the guest, then compare with the RPC at the same block
#   le_tamper       tampered state root (must fail 201) and tampered proof (must fail 204)
#   le_all          le_verify, then le_tamper
#   le_replay       re-run le_verify offline from $FIXTURE
#   le_log          prove an event log (default: an ERC-20 Transfer of LOGADDR in the newest
#                   finalized block), then compare it with the RPC
#   le_log_tamper   tampered receipts root (must fail 201) and tampered receipt proof (204)
#   le_log_predicate  a true predicate passes and is echoed; a false one is rejected (206)
#   le_log_replay   re-run le_log offline from $FIXTURE_LOG: the statement ID must not change
#   le_log_all      le_log, le_log_tamper, le_log_predicate, le_log_replay
#   le_prove [state|log] [flags]
#                   execute, then prove the same run, save the receipt to $RECEIPT_DIR and verify
#                   the saved file offline. Default kind: state (ADDR/SLOT); log: LOGADDR/TOPIC0.
#                   Slow: proving needs a GPU or Bonsai for a reasonable time
#   le_verify_receipt <file> [state|log] [flags]
#                   verify a saved receipt against this build's guest image ID and judge its
#                   journal, offline from the fixture of that kind. Give the flags of the run
#   le_cost [flags] execute-only cycles of the three staged update steps (Begin, Miller, Finish)
#                   from bench/, against a mainnet-size committee. No network and no proving.
#                   Flags go to the bench: --committee N, --scenario NAME, --cap CYCLES, --detail
#   le              raw host CLI (any flags)
# After le_verify these shell variables hold the results:
#   BLOCK  G_BALANCE G_VALUE (from the guest)  I_BALANCE I_VALUE (from the RPC)
# After le_log:
#   L_BLOCK L_TX L_LOGINDEX L_ADDR L_TOPICS L_DATALEN L_DATAHASH L_ID (from the guest)
#   I_LOG (from the RPC: status address data-length topics...)
# After le_cost:
#   COST_SCENARIO  COST_BEGIN COST_MILLER COST_FINISH (executor cycles of each step, from the bench)
# Sourcing this file needs the network (trusted root, RPC checks). If it is offline, run the bench
# directly: cargo run --manifest-path bench/Cargo.toml --release -- [flags]

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  echo "source this file: source scripts/env.sh" >&2
  exit 2
fi

export B="${B:-https://ethereum-beacon-api.publicnode.com}"
export X="${X:-https://ethereum-rpc.publicnode.com}"   # must serve eth_getProof
export ADDR="${ADDR:-0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2}"   # example account (WETH9)
export SLOT="${SLOT:-0x0}"
export FIXTURE="${FIXTURE:-./fixture}"
export FIXTURE_LOG="${FIXTURE_LOG:-./fixture-log}"
export RECEIPT_DIR="${RECEIPT_DIR:-./receipts}"
export LOGADDR="${LOGADDR:-0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48}"   # USDC: a Transfer in almost every block
export TOPIC0="${TOPIC0:-0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef}"   # ERC-20 Transfer(address,address,uint256)
LE_LOG="${TMPDIR:-/tmp}/le-last.log"

# Weak-subjectivity root: block root of the first block of a recently finalized epoch.
if [ -z "${R:-}" ]; then
  R=$(curl -fsS "$B/eth/v1/beacon/states/finalized/finality_checkpoints" \
    | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['finalized']['root'])") || R=""
fi
case "$R" in
  0x????????????????????????????????????????????????????????????????) export R ;;
  *) echo "env: could not get a trusted root from $B (set R by hand)" >&2; return 1 ;;
esac

# ---- helpers ---------------------------------------------------------------------------------

# Raw host CLI.
le() { cargo run -p le-sync --release -- "$@"; }

# Host CLI with the standard state flags. Extra flags are appended.
_le_state() {
  le --source "$B" --trusted-root "$R" --address "$ADDR" --slot "$SLOT" \
     --execution-rpc "$X" "$@"
}

# Host CLI with the standard log flags. Extra flags are appended.
_le_logcmd() {
  le --source "$B" --trusted-root "$R" --log-address "$LOGADDR" --log-topic0 "$TOPIC0" \
     --execution-rpc "$X" "$@"
}

# Run a command function, stream to the terminal, keep the log in $LE_LOG and the exit code in
# $LE_RC.
_le_runcmd() {
  local rcf fn
  fn="$1"; shift
  rcf=$(mktemp)
  { "$fn" "$@"; echo $? >"$rcf"; } 2>&1 | tee "$LE_LOG"
  LE_RC=$(cat "$rcf"); rm -f "$rcf"
}
_le_run() { _le_runcmd _le_state "$@"; }
_le_run_log() { _le_runcmd _le_logcmd "$@"; }

# Lowercase, strip 0x and leading zeros: 0x00ab -> 0xab, 0x00 -> 0x0.
_hexnorm() {
  local h
  h=$(printf '%s' "${1#0x}" | tr 'A-F' 'a-f' | sed 's/^0*//')
  echo "0x${h:-0}"
}

_rpc() {  # _rpc <method> <params-json> -> result string
  curl -fsS -X POST "$X" -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"'"$1"'","params":'"$2"'}' \
    | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['result'] if 'result' in d else 'ERROR '+str(d.get('error')))"
}

# Does the RPC serve proofs?
le_check() {
  local r
  r=$(curl -fsS -X POST "$X" -H 'content-type: application/json' -d \
    '{"jsonrpc":"2.0","id":1,"method":"eth_getProof","params":["'"$ADDR"'",["'"$SLOT"'"],"latest"]}') \
    || { echo "le_check: request to $X failed"; return 1; }
  case "$r" in
    *accountProof*) echo "le_check: OK, $X serves eth_getProof" ;;
    *) echo "le_check: no accountProof in reply:"; echo "$r" | head -c 300; echo; return 1 ;;
  esac
}

# Does the RPC serve receipts of a whole block (needed by le_log)?
le_check_receipts() {
  local r
  r=$(curl -fsS -X POST "$X" -H 'content-type: application/json' -d \
    '{"jsonrpc":"2.0","id":1,"method":"eth_getBlockReceipts","params":["latest"]}') \
    || { echo "le_check_receipts: request to $X failed"; return 1; }
  case "$r" in
    *logsBloom*) echo "le_check_receipts: OK, $X serves eth_getBlockReceipts" ;;
    *) echo "le_check_receipts: no receipts in reply (le_log needs eth_getBlockReceipts):"; echo "$r" | head -c 300; echo; return 1 ;;
  esac
}

# Independent balance and slot at block N (decimal). Sets I_BALANCE, I_VALUE.
le_independent() {
  [ -n "${1:-}" ] || { echo "usage: le_independent <block number>"; return 2; }
  local h
  h=$(printf '0x%x' "$1")
  I_BALANCE=$(_rpc eth_getBalance '["'"$ADDR"'","'"$h"'"]')
  I_VALUE=$(_rpc eth_getStorageAt '["'"$ADDR"'","'"$SLOT"'","'"$h"'"]')
  export I_BALANCE I_VALUE
}

# ---- one-command tasks ----------------------------------------------------------------------

# Prove balance and slot in the guest, then check both against the RPC at the same block.
le_verify() {
  _le_run --save-dir "$FIXTURE" "$@"
  [ "$LE_RC" = "0" ] && printf '%s\n' "$R" >"$FIXTURE/trusted_root"
  _le_check_run
}

# Re-run from the saved fixture: beacon data and proof come from $FIXTURE, no network for the
# proof (the RPC is still used for the independent check). Uses the root saved by le_verify.
le_replay() {
  [ -f "$FIXTURE/trusted_root" ] || { echo "replay: run le_verify first (no $FIXTURE/trusted_root)"; return 1; }
  local b0="$B" x0="$X" r0="$R"
  B="$FIXTURE"; X="$FIXTURE"; R=$(cat "$FIXTURE/trusted_root")
  _le_run
  B="$b0"; X="$x0"; R="$r0"
  _le_check_run
}

_le_check_run() {
  if [ "$LE_RC" != "0" ]; then echo "verify: FAIL (host exit $LE_RC)"; return 1; fi
  BLOCK=$(grep 'verified in the guest' "$LE_LOG" | sed -n 's/.*): block \([0-9]*\) hash.*/\1/p' | tail -1)
  G_BALANCE=$(grep '^  account ' "$LE_LOG" | sed -n 's/.* balance \(0x[0-9a-fA-F]*\).*/\1/p' | tail -1)
  G_VALUE=$(grep '^  slot ' "$LE_LOG" | sed -n 's/.* value \(0x[0-9a-fA-F]*\).*/\1/p' | tail -1)
  if [ -z "$BLOCK" ] || [ -z "$G_BALANCE" ] || [ -z "$G_VALUE" ]; then
    echo "verify: FAIL (no verified state in the output)"; return 1
  fi
  export BLOCK G_BALANCE G_VALUE
  le_independent "$BLOCK"
  local ok=0
  echo
  echo "verify: block $BLOCK"
  if [ "$(_hexnorm "$G_BALANCE")" = "$(_hexnorm "$I_BALANCE")" ]; then
    echo "  balance  OK        $(_hexnorm "$G_BALANCE")"
  else
    echo "  balance  MISMATCH  guest $(_hexnorm "$G_BALANCE")  rpc $I_BALANCE"; ok=1
  fi
  if [ "$(_hexnorm "$G_VALUE")" = "$(_hexnorm "$I_VALUE")" ]; then
    echo "  slot $SLOT  OK        $(_hexnorm "$G_VALUE")"
  else
    echo "  slot $SLOT  MISMATCH  guest $(_hexnorm "$G_VALUE")  rpc $I_VALUE"; ok=1
  fi
  if [ "$ok" = "0" ]; then echo "verify: PASS"; else echo "verify: FAIL"; fi
  return $ok
}

# Both tamper runs must be rejected by the guest with the right typed error.
le_tamper() {
  local bad=0
  _le_run --tamper-exec
  if [ "$LE_RC" = "0" ] && grep -q 'as expected for this run (code 201)' "$LE_LOG"; then
    echo "tamper-exec : PASS (guest rejected with 201)"
  else echo "tamper-exec : FAIL"; bad=1; fi
  _le_run --tamper-state
  if [ "$LE_RC" = "0" ] && grep -q 'as expected for this run (code 204)' "$LE_LOG"; then
    echo "tamper-state: PASS (guest rejected with 204)"
  else echo "tamper-state: FAIL"; bad=1; fi
  return $bad
}

le_all() { le_verify && le_tamper; }

# ---- log tasks (Sprint 5) ---------------------------------------------------------------------

# Independent read of one log: "<status> <address> <data length> <topic>..." from the RPC's own
# receipts of the block, lowercased. Sets I_LOG.
le_independent_log() {
  [ $# -eq 3 ] || { echo "usage: le_independent_log <block> <tx index> <log index>"; return 2; }
  local h raw
  h=$(printf '0x%x' "$1")
  raw=$(curl -fsS -X POST "$X" -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"eth_getBlockReceipts","params":["'"$h"'"]}') \
    || { echo "le_independent_log: request to $X failed"; return 1; }
  I_LOG=$(printf '%s' "$raw" | python3 -c '
import sys, json
tx, li = int(sys.argv[1]), int(sys.argv[2])
d = json.load(sys.stdin)
if not d.get("result"):
    print("ERROR", d.get("error")); sys.exit(1)
r = d["result"][tx]
l = r["logs"][li]
print(r["status"], l["address"].lower(), (len(l["data"]) - 2) // 2, *[t.lower() for t in l["topics"]])
' "$2" "$3") || { echo "le_independent_log: $I_LOG"; return 1; }
  export I_LOG
}

# Read the guest's verified log out of $LE_LOG into the L_* variables.
_le_log_parse() {
  L_BLOCK=$(grep 'log (verified in the guest' "$LE_LOG" | sed -n 's/.*): block \([0-9]*\) hash.*/\1/p' | tail -1)
  L_TX=$(grep '^  transaction ' "$LE_LOG" | sed -n 's/^  transaction \([0-9]*\) log.*/\1/p' | tail -1)
  L_LOGINDEX=$(grep '^  transaction ' "$LE_LOG" | sed -n 's/.* log \([0-9]*\) emitted.*/\1/p' | tail -1)
  L_ADDR=$(grep '^  transaction ' "$LE_LOG" | sed -n 's/.* emitted by \(0x[0-9a-fA-F]*\).*/\1/p' | tail -1)
  L_TOPICS=$(grep '^  topic[0-9] ' "$LE_LOG" | sed -n 's/^  topic[0-9] \(0x[0-9a-fA-F]*\).*/\1/p' | tr '\n' ' ' | sed 's/ $//')
  L_DATALEN=$(grep '^  data ' "$LE_LOG" | sed -n 's/^  data \([0-9]*\) bytes.*/\1/p' | tail -1)
  L_DATAHASH=$(grep '^  data ' "$LE_LOG" | sed -n 's/.*keccak256 \(0x[0-9a-fA-F]*\).*/\1/p' | tail -1)
  L_ID=$(grep '^  statement id ' "$LE_LOG" | sed -n 's/^  statement id \(0x[0-9a-fA-F]*\).*/\1/p' | tail -1)
  if [ -z "$L_BLOCK" ] || [ -z "$L_TX" ] || [ -z "$L_ADDR" ] || [ -z "$L_TOPICS" ] || [ -z "$L_ID" ]; then
    return 1
  fi
  export L_BLOCK L_TX L_LOGINDEX L_ADDR L_TOPICS L_DATALEN L_DATAHASH L_ID
}

_le_log_check_run() {
  if [ "$LE_RC" != "0" ]; then echo "log: FAIL (host exit $LE_RC)"; return 1; fi
  if ! _le_log_parse; then echo "log: FAIL (no verified log in the output)"; return 1; fi
  le_independent_log "$L_BLOCK" "$L_TX" "$L_LOGINDEX" || return 1
  local g
  g=$(printf '0x1 %s %s %s' "$L_ADDR" "$L_DATALEN" "$L_TOPICS" | tr 'A-F' 'a-f')
  echo
  echo "log: block $L_BLOCK, transaction $L_TX, log $L_LOGINDEX"
  echo "  statement id $L_ID"
  if [ "$g" = "$I_LOG" ]; then
    echo "  address, topics, data length  OK        $L_ADDR $L_TOPICS"
    echo "log: PASS"
    return 0
  fi
  echo "  MISMATCH"
  echo "    guest $g"
  echo "    rpc   $I_LOG"
  echo "log: FAIL"
  return 1
}

# Prove one event log in the guest, then check it against the RPC's own receipts.
# Extra flags go to the host: --log-tx N --log-index N --log-topic1 0x.. --expect-id 0x.. ...
le_log() {
  _le_run_log --save-dir "$FIXTURE_LOG" "$@"
  [ "$LE_RC" = "0" ] && printf '%s\n' "$R" >"$FIXTURE_LOG/trusted_root"
  _le_log_check_run
}

# Both tamper runs must be rejected by the guest with the right typed error.
le_log_tamper() {
  local bad=0
  _le_run_log --tamper-exec
  if [ "$LE_RC" = "0" ] && grep -q 'as expected for this run (code 201)' "$LE_LOG"; then
    echo "tamper-exec   : PASS (guest rejected with 201)"
  else echo "tamper-exec   : FAIL"; bad=1; fi
  _le_run_log --tamper-receipt
  if [ "$LE_RC" = "0" ] && grep -q 'as expected for this run (code 204)' "$LE_LOG"; then
    echo "tamper-receipt: PASS (guest rejected with 204)"
  else echo "tamper-receipt: FAIL"; bad=1; fi
  return $bad
}

# A predicate that holds passes and is echoed in the journal. One that does not hold is
# rejected by the guest with 206 and the host exits 1.
le_log_predicate() {
  local bad=0
  _le_run_log --predicate "topic0==$TOPIC0"
  if [ "$LE_RC" = "0" ] && grep -q 'predicate held' "$LE_LOG"; then
    echo "predicate true : PASS (held and echoed)"
  else echo "predicate true : FAIL"; bad=1; fi
  _le_run_log --predicate "topic0!=$TOPIC0"
  if [ "$LE_RC" = "1" ] && grep -q 'error code 206' "$LE_LOG"; then
    echo "predicate false: PASS (guest rejected with 206)"
  else echo "predicate false: FAIL"; bad=1; fi
  return $bad
}

# Re-run the last le_log offline from $FIXTURE_LOG: same block, so the statement ID must be
# identical.
le_log_replay() {
  [ -f "$FIXTURE_LOG/trusted_root" ] || { echo "replay: run le_log first (no $FIXTURE_LOG/trusted_root)"; return 1; }
  [ -n "${L_ID:-}" ] || { echo "replay: run le_log first (no L_ID)"; return 1; }
  local first="$L_ID" b0="$B" x0="$X" r0="$R"
  B="$FIXTURE_LOG"; X="$FIXTURE_LOG"; R=$(cat "$FIXTURE_LOG/trusted_root")
  _le_run_log --log-tx "$L_TX" --log-index "$L_LOGINDEX"
  B="$b0"; X="$x0"; R="$r0"
  if [ "$LE_RC" != "0" ] || ! _le_log_parse; then echo "replay: FAIL (host exit $LE_RC)"; return 1; fi
  if [ "$L_ID" = "$first" ]; then
    echo "replay: PASS (statement id unchanged $L_ID)"
  else
    echo "replay: FAIL (id $first became $L_ID)"; return 1
  fi
}

le_log_all() { le_log && le_log_tamper && le_log_predicate && le_log_replay; }

# ---- cost gate (Sprint 6, M1) -----------------------------------------------------------------

# Execute-only cycles of the three staged update steps, from bench/. Prints the bench's table, then
# reads its last machine line:
#   cost: scenario=<name> begin=<n> miller=<n> finish=<n>
# and sets COST_SCENARIO, COST_BEGIN, COST_MILLER, COST_FINISH. Fails if the bench exits non-zero
# (a guest result that differs from the native run, a rejected step, a step over --cap) or prints
# no such line. Extra flags go to the bench, e.g. le_cost --committee 512 --cap 10000000 --detail
le_cost() {
  unset COST_SCENARIO COST_BEGIN COST_MILLER COST_FINISH
  _le_runcmd cargo run --manifest-path bench/Cargo.toml --release -- "$@"
  if [ "$LE_RC" != "0" ]; then echo "cost: FAIL (bench exit $LE_RC)"; return 1; fi
  local line
  line=$(grep '^cost: ' "$LE_LOG" | tail -1)
  COST_SCENARIO=$(printf '%s' "$line" | sed -n 's/^cost: scenario=\([^ ]*\) .*/\1/p')
  COST_BEGIN=$(printf '%s' "$line" | sed -n 's/.* begin=\([0-9]*\).*/\1/p')
  COST_MILLER=$(printf '%s' "$line" | sed -n 's/.* miller=\([0-9]*\).*/\1/p')
  COST_FINISH=$(printf '%s' "$line" | sed -n 's/.* finish=\([0-9]*\).*/\1/p')
  if [ -z "$COST_SCENARIO" ] || [ -z "$COST_BEGIN" ] || [ -z "$COST_MILLER" ] || [ -z "$COST_FINISH" ]; then
    unset COST_SCENARIO COST_BEGIN COST_MILLER COST_FINISH
    echo "cost: FAIL (no cost line in the bench output)"; return 1
  fi
  export COST_SCENARIO COST_BEGIN COST_MILLER COST_FINISH
  echo
  echo "cost: PASS $COST_SCENARIO begin=$COST_BEGIN miller=$COST_MILLER finish=$COST_FINISH"
}

# ---- proof output -----------------------------------------------------------------------------

# Verify a saved receipt offline and judge its journal like a live run.
# usage: le_verify_receipt <file> [state|log] [flags of the original run]
le_verify_receipt() {
  [ $# -ge 1 ] || { echo "usage: le_verify_receipt <file> [state|log] [flags]"; return 2; }
  local f="$1" kind="${2:-state}" dir root
  shift; [ $# -gt 0 ] && shift
  [ -f "$f" ] || { echo "receipt: no such file $f"; return 1; }
  case "$kind" in
    state) dir="$FIXTURE" ;;
    log)   dir="$FIXTURE_LOG" ;;
    *) echo "receipt: kind must be state or log"; return 2 ;;
  esac
  [ -f "$dir/trusted_root" ] || { echo "receipt: no $dir/trusted_root (run le_prove $kind first)"; return 1; }
  root=$(cat "$dir/trusted_root")
  if [ "$kind" = "state" ]; then
    _le_runcmd le --source "$dir" --trusted-root "$root" --address "$ADDR" --slot "$SLOT" \
      --execution-rpc "$dir" --verify-receipt "$f" "$@"
  else
    _le_runcmd le --source "$dir" --trusted-root "$root" --log-address "$LOGADDR" \
      --log-topic0 "$TOPIC0" --execution-rpc "$dir" --verify-receipt "$f" "$@"
  fi
  if [ "$LE_RC" = "0" ] && grep -q 'receipt verified against guest id' "$LE_LOG"; then
    echo "receipt: PASS ($f)"
  else
    echo "receipt: FAIL (host exit $LE_RC)"; return 1
  fi
}

# Execute, then prove the same run, save the receipt and verify the saved file.
# usage: le_prove [state|log] [flags]
le_prove() {
  local kind="${1:-state}" dir out
  [ $# -gt 0 ] && shift
  case "$kind" in
    state) dir="$FIXTURE" ;;
    log)   dir="$FIXTURE_LOG" ;;
    *) echo "prove: kind must be state or log"; return 2 ;;
  esac
  mkdir -p "$RECEIPT_DIR" "$dir" || return 1
  out="$RECEIPT_DIR/$kind.receipt"
  rm -f "$out"
  if [ "$kind" = "state" ]; then
    _le_run --save-dir "$dir" --prove --receipt-out "$out" "$@"
  else
    _le_run_log --save-dir "$dir" --prove --receipt-out "$out" "$@"
  fi
  if [ "$LE_RC" != "0" ] || ! grep -q 'receipt verified and saved' "$LE_LOG"; then
    echo "prove: FAIL (host exit $LE_RC)"; return 1
  fi
  printf '%s\n' "$R" >"$dir/trusted_root"
  le_verify_receipt "$out" "$kind" "$@" || return 1
  echo "prove: PASS ($out)"
}

# ---- setup check ------------------------------------------------------------------------------

echo "env: B=$B"
echo "env: X=$X"
echo "env: R=$R"
echo "env: ADDR=$ADDR SLOT=$SLOT"
echo "env: LOGADDR=$LOGADDR"
le_check || return 1
le_check_receipts || echo "env: warning: le_log will not work with this RPC (set X to a node with eth_getBlockReceipts)" >&2
echo "env: ready. commands: le_verify  le_tamper  le_all  le_replay  le_log  le_log_tamper  le_log_predicate  le_log_replay  le_log_all  le_prove  le_verify_receipt  le_cost  le"