# Shared helpers. Source it: . scripts/lib.sh <env>   (env = local | testnet)
# Reads config/<env>.toml. Flat `key = value` lines under [section] headers.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_NAME="${1:?usage: <script> <local|testnet>}"
CONFIG="${CONFIG:-$ROOT/config/$ENV_NAME.toml}"
[ -f "$CONFIG" ] || { echo "no such config: $CONFIG" >&2; exit 2; }

die() { echo "error: $*" >&2; exit 1; }
say() { echo "== $*"; }

# cfg <section> <key>  -> the value, quotes and trailing comment removed ("" if empty)
cfg() {
  awk -v s="[$1]" -v k="$2" '
    /^\[/ { insec = ($0 == s); next }
    insec {
      i = index($0, "="); if (i == 0) next
      key = substr($0, 1, i - 1); gsub(/[ \t]/, "", key)
      if (key == k) {
        v = substr($0, i + 1)
        sub(/^[ \t]*/, "", v)
        if (substr(v, 1, 1) == "\"") { sub(/^"/, "", v); sub(/".*$/, "", v) }
        else { sub(/[ \t]*#.*$/, "", v); sub(/[ \t]*$/, "", v) }
        print v; found = 1; exit
      }
    }
    END { if (!found) exit 3 }' "$CONFIG"
}

# cfg_set <section> <key> <value>: replaces an existing key in place (the template has them all)
cfg_set() {
  local tmp; tmp="$(mktemp)"
  awk -v s="[$1]" -v k="$2" -v val="$3" '
    /^\[/ { insec = ($0 == s) }
    insec && !done {
      i = index($0, "=")
      if (i > 0) {
        key = substr($0, 1, i - 1); gsub(/[ \t]/, "", key)
        if (key == k) {
          rest = substr($0, i + 1); c = ""
          if (match(rest, /"[^"]*"[ \t]*#.*$/)) { c = substr(rest, index(rest, "#") - 1) ; sub(/^[^#]*/, "", c); c = "   " c }
          printf "%s = \"%s\"%s\n", key, val, c; done = 1; next
        }
      }
    }
    { print }
    END { if (!done) exit 3 }' "$CONFIG" > "$tmp" || { rm -f "$tmp"; die "no key [$1] $2 in $CONFIG"; }
  mv "$tmp" "$CONFIG"
}

# Where the Ethereum APIs are for this run: the real ones, or the replay server.
beacon() { if [ "$(cfg eth source)" = replay ]; then cfg eth replay_url; else cfg eth beacon_url; fi; }
execution() { if [ "$(cfg eth source)" = replay ]; then cfg eth replay_url; else cfg eth execution_url; fi; }

# jget <json> <python expression over d>: one value out of a JSON document (python3, stdlib only)
jget() { python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print(eval(sys.argv[2]))' "$1" "$2"; }

# GET <url> with a retry; prints the body
fetch() { curl -fsS --retry 3 --retry-delay 2 --max-time 60 "$1"; }

# The command that runs the ops tool (module/ops)
ops() { RISC0_SKIP_BUILD=1 cargo run -q --manifest-path "$ROOT/module/ops/Cargo.toml" --bin eth_attest_ops -- --config "$CONFIG" "$@"; }
