#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"
guest="$repo_root/lez/methods/guest/src/bin/eth_attest.rs"
host="$repo_root/lez/src/lib.rs"
guest_declarations="$(mktemp)"
host_declarations="$(mktemp)"
trap 'rm -f "$guest_declarations" "$host_declarations"' EXIT

extract_declarations() {
  awk '
    /^[[:space:]]*#\[instruction\][[:space:]]*$/ {
      in_instruction = 1
      print
      next
    }
    in_instruction {
      if ($0 ~ /^[[:space:]]*\/\/\//) {
        next
      }
      print
      if ($0 ~ /^[[:space:]]*\) -> SpelResult \{[[:space:]]*$/) {
        in_instruction = 0
      }
    }
  ' "$1"
}

for source in "$guest" "$host"; do
  if [[ ! -f "$source" ]]; then
    echo "missing instruction source: $source" >&2
    exit 1
  fi
done

extract_declarations "$guest" >"$guest_declarations"
extract_declarations "$host" >"$host_declarations"

guest_count="$(grep -c '^[[:space:]]*#\[instruction\]' "$guest_declarations" || true)"
host_count="$(grep -c '^[[:space:]]*#\[instruction\]' "$host_declarations" || true)"
if [[ "$guest_count" -eq 0 || "$guest_count" -ne "$host_count" ]]; then
  echo "instruction extraction mismatch: guest=$guest_count host=$host_count" >&2
  exit 1
fi

if diff -u "$guest_declarations" "$host_declarations"; then
  echo "in step: $guest_count instructions"
else
  echo "NOT in step: guest handler declarations differ from the host IDL stub" >&2
  exit 1
fi
