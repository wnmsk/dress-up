#!/usr/bin/env bash
# fuzz_cov.sh – Run cargo‑fuzz coverage and generate HTML & text reports
# Usage: ./fuzz_cov.sh <target> <output_path> <outfile_name_stem>
#
# Execute from project root
# -------------------------------------------------------------

set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "Usage: $0 <target> <output_path> outfile_name_stem"
    echo "  Example: $0 raw_unauth results/coverage cov_report"
    echo "    --> will then create reports in 'results/coverage/cov_report.html' and 'results/coverage/cov_report.txt'"
    exit 2
fi

TOOLCHAIN="$(rustup default | awk '{print $1}')"
echo "Using toolchain: ${TOOLCHAIN}"

TARGET="$1"
OUT_PATH="$2"
OUT_STEM="$3"

REPORT_NAME="${OUT_PATH}/${OUT_STEM}"

# use direct binary path since 'cargo cov' doesn't seem to work on the VM
# --> https://github.com/rust-fuzz/cargo-fuzz/issues/308
LLVM_COV_BIN="${HOME}/.rustup/toolchains/${TOOLCHAIN}/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-cov"

# generate coverage files
echo "Running cargo fuzz coverage for target \"${TARGET}\" ..."
cargo fuzz coverage "${TARGET}"

# generate HTML cov report
HTML_OUT="${REPORT_NAME}.html"
COV_DIR="fuzz/coverage/${TARGET}"
COV_PROFILE="${COV_DIR}/coverage.profdata"
BIN_PATH="target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/release/${TARGET}"

echo "Creating HTML coverage report → ${HTML_OUT} ..."
# ignoring code in .cargo and .rustup to leave out dependency code
# and focus on the actual project code
"${LLVM_COV_BIN}" \
    show "${BIN_PATH}" \
    --format=html \
    -instr-profile="${COV_PROFILE}" \
    -ignore-filename-regex='/.cargo/|/.rustup/' \
    > "${HTML_OUT}"

# generate textual cov report
TXT_OUT="${REPORT_NAME}.txt"

echo "Creating textual coverage report → ${TXT_OUT} ..."
# ignoring code in .cargo and .rustup to leave out dependency code
# and focus on the actual project code
#
# ALSO: ignoring code of fuzzer itself to only have coverage percentages
# of the actual project code
"${LLVM_COV_BIN}" \
    report "${BIN_PATH}" \
    -instr-profile="${COV_PROFILE}" \
    -ignore-filename-regex='/.cargo/|/.rustup/|/fuzz/|/rustc/' \
    > "${TXT_OUT}"

echo "All done."
