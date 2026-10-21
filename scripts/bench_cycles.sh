#!/usr/bin/env bash
# Cycle matrix: {bls-blst, bls-zk} x {all updates, latest update only}, on ONE saved dataset.
# Usage: scripts/bench_cycles.sh            (from the repo root)
# Assumes the BLS feature name appears literally in guest/Cargo.toml (e.g. features = ["bls-zk"]).
# SHA2_PATCH=on (default, as in guest/Cargo.toml) | off (comments out the risc0 sha2 [patch] line).
# Run both and compare.
set -euo pipefail
SHA2_PATCH=${SHA2_PATCH:-on}

B=${B:-https://ethereum-beacon-api.publicnode.com}
R=${R:-$(curl -s "$B/eth/v1/beacon/states/finalized/finality_checkpoints" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['finalized']['root'])")}
FIX=${FIX:-fixtures/bench-$(date +%F)}
GCT=guest/Cargo.toml

cp "$GCT" "$GCT.orig"
trap 'mv "$GCT.orig" "$GCT"' EXIT

if [ "$SHA2_PATCH" = off ]; then
  sed -E -i.bak 's|^(sha2 = \{ git)|# \1|' "$GCT"; rm -f "$GCT.bak"
fi
echo "sha2 patch: $SHA2_PATCH"

if [ ! -f "$FIX/bootstrap.json" ]; then
  echo "saving dataset to $FIX (root $R)"
  cargo run -p le-sync --release -- --source "$B" --trusted-root "$R" --sync --save-dir "$FIX" >/dev/null
fi

run() { # $1 = extra flags
  # shellcheck disable=SC2086
  cargo run -q -p le-sync --release -- --source "$FIX" --trusted-root "$R" --sync $1 2>&1 \
    | awk '/^cycles:/ {c=$2} /^OK$/ {ok="ok"} /NOT OK/ {ok="FAILED"} END {print c, ok}'
}

printf '%-10s %-14s %16s %8s %7s\n' bls mode cycles xbudget status
for f in bls-blst bls-zk; do
  sed -E -i.bak "s/bls-(zk|blst)/$f/g" "$GCT"; rm -f "$GCT.bak"
  touch host/build.rs   # make sure the guest is rebuilt with the new feature
  for mode in "all:" "latest-only:--latest-only"; do
    name=${mode%%:*}; flags=${mode#*:}
    read -r cyc st <<<"$(run "$flags")"
    printf '%-10s %-14s %16s %8s %7s\n' "$f" "$name" "${cyc:-?}" \
      "$(python3 -c "print(round(${cyc:-0}/33554432,1))")" "${st:-?}"
  done
done
echo "budget = 33,554,432 cycles (MAX_NUM_CYCLES_PUBLIC_EXECUTION). Record the sha2 patch state with these numbers."