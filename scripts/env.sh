#!/usr/bin/env bash
# le-sync environment. Source it, do not execute it:
#
#   source scripts/env.sh
#
# Override before sourcing if needed: B (beacon API), X (execution RPC), R (trusted root),
# ADDR, SLOT, FIXTURE (save dir, default ./fixture).
#
# Commands after sourcing:
#   le_verify   prove ADDR/SLOT in the guest, then compare with the RPC at the same block
#   le_tamper   tampered state root (must fail 201) and tampered proof (must fail 204)
#   le_all      le_verify, then le_tamper
#   le_replay   re-run le_verify offline from $FIXTURE
#   le          raw host CLI (any flags)
# After le_verify these shell variables hold the results:
#   BLOCK  G_BALANCE G_VALUE (from the guest)  I_BALANCE I_VALUE (from the RPC)

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  echo "source this file: source scripts/env.sh" >&2
  exit 2
fi

export B="${B:-https://ethereum-beacon-api.publicnode.com}"
export X="${X:-https://ethereum-rpc.publicnode.com}"   # must serve eth_getProof
export ADDR="${ADDR:-0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2}"   # example account (WETH9)
export SLOT="${SLOT:-0x0}"
export FIXTURE="${FIXTURE:-./fixture}"
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

# Run _le_state, stream to the terminal, keep the log in $LE_LOG and the exit code in $LE_RC.
_le_run() {
  local rcf
  rcf=$(mktemp)
  { _le_state "$@"; echo $? >"$rcf"; } 2>&1 | tee "$LE_LOG"
  LE_RC=$(cat "$rcf"); rm -f "$rcf"
}

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

# ---- setup check ------------------------------------------------------------------------------

echo "env: B=$B"
echo "env: X=$X"
echo "env: R=$R"
echo "env: ADDR=$ADDR SLOT=$SLOT"
le_check || return 1
echo "env: ready. commands: le_verify  le_tamper  le_all  le_replay  le"