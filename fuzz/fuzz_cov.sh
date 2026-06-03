#!/usr/bin/env bash
# fuzz_cov.sh – Run cargo‑fuzz coverage and generate HTML & text reports
# Usage: ./fuzz_cov.sh <target> 
# (execute from project root)
# -------------------------------------------------------------

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Error: exactly one argument (the fuzz target name) is required."
    echo "Usage: $0 <target>"
    exit 1
fi

TARGET="$1"
REPORT_DIR="cov_reports"

# create report directory
mkdir -p "${REPORT_DIR}";

# generate coverage files
echo "Running cargo fuzz coverage for target \"${TARGET}\" ..."
cargo fuzz coverage "${TARGET}"

# generate HTML cov report
HTML_OUT="${REPORT_DIR}/cov_${TARGET}.html"
COV_DIR="fuzz/coverage/${TARGET}"
COV_PROFILE="${COV_DIR}/coverage.profdata"
BIN_PATH="target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/release/${TARGET}"

echo "Creating HTML coverage report → ${HTML_OUT} ..."
cargo cov -- \
    show "${BIN_PATH}" \
    --format=html \
    -instr-profile="${COV_PROFILE}" \
    -ignore-filename-regex='/.cargo/|/.rustup/' \
    > "${HTML_OUT}"

# generate textual cov report
TXT_OUT="${REPORT_DIR}/cov_${TARGET}.txt"

echo "Creating textual coverage report → ${TXT_OUT} ..."
cargo cov -- \
    report "${BIN_PATH}" \
    -instr-profile="${COV_PROFILE}" \
    -ignore-filename-regex='/.cargo/|/.rustup/|/fuzz_targets/' \
    > "${TXT_OUT}"

echo "All done."
