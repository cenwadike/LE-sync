#!/usr/bin/env bash
set -euo pipefail

MATRIX_FILE="${1:-README.md}"
TEST_LIST=$(mktemp)
MATRIX_LIST=$(mktemp)
trap 'rm -f "$TEST_LIST" "$MATRIX_LIST"' EXIT

echo "[*] Generating current cargo test list..."
# stderr hidden: cargo prints "Doc-tests ..." / "Running ..." banners there.
# Keep only "path::name: test" lines and reduce each to its final path segment.
cargo test --workspace -- --list --quiet 2>/dev/null \
  | awk -F': ' '/: test$/ { n = split($1, a, "::"); print a[n] }' \
  | sort -u > "$TEST_LIST"

if [ ! -s "$TEST_LIST" ]; then
    echo "[!] ERROR: 'cargo test -- --list' produced no tests; cannot validate."
    exit 1
fi

# Populate the matrix only if the file is missing or empty (never overwrite content).
if [ ! -s "$MATRIX_FILE" ]; then
    echo "[*] $MATRIX_FILE is missing or empty; populating it from the test list..."
    {
        echo '| Test | Description |'
        echo '|---|---|'
        while IFS= read -r name; do
            echo "| \`$name\` | |"
        done < "$TEST_LIST"
    } > "$MATRIX_FILE"
    echo "[+] Wrote $(wc -l < "$TEST_LIST" | tr -d ' ') rows to $MATRIX_FILE."
    echo "[i] This matrix was generated from the live list, so the check below passes trivially."
    echo "[i] Fill in the Description column and curate the rows to make the check meaningful."
fi

echo "[*] Checking matrix file: $MATRIX_FILE"
# Matrix side: only markdown table rows whose first column is a backticked identifier.
grep -E '^\|[[:space:]]*`[a-zA-Z0-9_]+`' "$MATRIX_FILE" \
  | sed -E 's/^\|[[:space:]]*`([a-zA-Z0-9_]+)`.*/\1/' \
  | sort -u > "$MATRIX_LIST" || true

if [ ! -s "$MATRIX_LIST" ]; then
    echo "[!] ERROR: no matrix rows found in $MATRIX_FILE (expected table rows like: | \`test_name\` | ... |)."
    exit 1
fi

MISSING_TESTS=0
while IFS= read -r test_name; do
    if ! grep -qxF "$test_name" "$TEST_LIST"; then
        echo "[!] ERROR: Test '$test_name' found in matrix ($MATRIX_FILE) but missing from 'cargo test -- --list'."
        MISSING_TESTS=$((MISSING_TESTS + 1))
    fi
done < "$MATRIX_LIST"

if [ "$MISSING_TESTS" -gt 0 ]; then
    echo "[!] Matrix check failed with $MISSING_TESTS missing test(s)."
    exit 1
else
    echo "[+] All $(wc -l < "$MATRIX_LIST" | tr -d ' ') matrix tests are registered in cargo test."
    exit 0
fi