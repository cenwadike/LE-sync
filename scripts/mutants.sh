#!/usr/bin/env sh
# Three separate mutation runs, so each is attributable and none is diluted.
#   scripts/mutants.sh wire   # wire/src/{lib,bls}.rs with the real-BLS suite compiled in
#   scripts/mutants.sh core   # the audit surface; run on its own
#   scripts/mutants.sh all
set -eu

# The 512-member test is for the full `cargo test` run; skip it under mutation.
export LE_SYNC_SKIP_SLOW=1

wire() {
  cargo mutants --package le-sync-wire --features bls-zk \
    --file 'wire/src/lib.rs' --file 'wire/src/bls.rs'
}
core() {
  cargo mutants --package le-sync-core
}
host() {
  RISC0_SKIP_BUILD=1 cargo mutants --package le-sync --file 'host/src/lib.rs'
}

case "${1:-wire}" in
  wire) wire ;;
  core) core ;;
  host) host ;;
  all)  wire; core; host ;;
  *) echo "usage: $0 [wire|core|host|all]" >&2; exit 2 ;;
esac