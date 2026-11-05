#!/usr/bin/env bash
# Usage: [BACK=6] scripts/record-fixtures.sh <local|testnet>
# Records one real update cycle into fixtures/<network>/ in the shape of the APIs themselves
# (beacon paths as paths; execution calls as <method>-<n>.json request/response pairs), so
# scripts/replay_server.sh can serve them back unchanged.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

[ "$(cfg eth source)" != replay ] || die "set [eth] source = live to record"
B="$(cfg eth beacon_url)"; X="$(cfg eth execution_url)"
NET="$(cfg eth network)"; OUT="$ROOT/fixtures/$NET"
ADDR="$(cfg fixtures address)"; SLOTS="$(cfg fixtures storage_slots)"
mkdir -p "$OUT/beacon" "$OUT/execution"

save_beacon() { # path
  local f="$OUT/beacon/$(echo "$1" | sed 's#[/?&=]#_#g')"
  fetch "$B$1" > "$f"; echo "   $1 -> ${f#$ROOT/}" >&2; cat "$f"
}
n=0
rpc() { # method params-json  -> response on stdout, request+response saved
  n=$((n + 1))
  local req="{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}"
  local res; res="$(curl -fsS --retry 3 --max-time 60 -H 'content-type: application/json' -d "$req" "$X")"
  case "$res" in *'"error"'*) die "$1 failed: $res" ;; esac
  printf '%s\n' "$req" > "$OUT/execution/$1-$n.request.json"
  printf '%s\n' "$res" > "$OUT/execution/$1-$n.response.json"
  echo "   $1 -> execution/$1-$n.*.json" >&2
  printf '%s' "$res"
}

# The replay has to be able to make progress: the instance starts from an OLDER finalized
# checkpoint (the one the server answers `finalized/finality_checkpoints` with), and the recorded
# finality update is newer. BACK says how many epochs older.
BACK="${BACK:-6}"
SPE="$(cfg instance slots_per_epoch)"

say "newest finality update"
fu="$(save_beacon /eth/v1/beacon/light_client/finality_update)"
fin_slot="$(jget "$fu" 'd["data"]["finalized_header"]["beacon"]["slot"]')"
blk="$(jget "$fu" 'd["data"]["finalized_header"]["execution"]["block_number"]')"
new_epoch=$((fin_slot / SPE))
echo "   finalized slot $fin_slot (epoch $new_epoch), execution block $blk"

say "older checkpoint to start the instance from ($BACK epochs back)"
old_slot=$(((new_epoch - BACK) * SPE))
old="$(fetch "$B/eth/v1/beacon/states/$old_slot/finality_checkpoints")"
root="$(jget "$old" 'd["data"]["finalized"]["root"]')"
old_epoch="$(jget "$old" 'd["data"]["finalized"]["epoch"]')"
# saved under the name of the "finalized" path: that is what the replay server answers
printf '%s' "$old" > "$OUT/beacon/$(echo /eth/v1/beacon/states/finalized/finality_checkpoints | sed 's#[/?&=]#_#g')"
echo "   checkpoint epoch $old_epoch, root $root"

say "light-client material"
save_beacon "/eth/v1/beacon/light_client/bootstrap/$root" >/dev/null
period=$((old_epoch / $(cfg instance epochs_per_period)))
save_beacon "/eth/v1/beacon/light_client/updates?start_period=$period&count=2" >/dev/null
save_beacon /eth/v1/beacon/genesis >/dev/null
save_beacon /eth/v1/config/spec >/dev/null

say "execution proofs under the newest finalized block"
hexblk="$(printf '0x%x' "$blk")"
slots_json="[$(echo "$SLOTS" | sed 's/[^,][^,]*/"&"/g')]"
rpc eth_getProof "[\"$ADDR\",$slots_json,\"$hexblk\"]" >/dev/null
rpc eth_getBlockByNumber "[\"$hexblk\",false]" >/dev/null
rpc eth_getBlockReceipts "[\"$hexblk\"]" >/dev/null

cat > "$OUT/MANIFEST.txt" <<M
recorded: $(date -u +%Y-%m-%dT%H:%M:%SZ)
network: $NET
instance starts from: epoch $old_epoch root $root
newest finalized: slot $fin_slot, execution block $blk
address: $ADDR
M
say "recorded to ${OUT#$ROOT/}"; cat "$OUT/MANIFEST.txt"
