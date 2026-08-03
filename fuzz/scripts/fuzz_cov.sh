#!/usr/bin/env bash
# fuzz_cov.sh – Run cargo‑fuzz coverage and generate HTML & text reports
# Usage: ./fuzz_cov.sh <output_path> [TARGET ...]
#
# Execute from project root
# -------------------------------------------------------------

set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <output_path> [TARGET ...]"
    echo "  Example: $0 results/coverage unaware "
    echo "  TARGET: list of cargo-fuzz targets"
    exit 2
fi

TOOLCHAIN="$(rustup default | awk '{print $1}')"
echo "Using toolchain: ${TOOLCHAIN}"

OUT_PATH="$1"
shift || true
echo "Using out_path: ${OUT_PATH}"
TARGETS=("$@")
echo "Using targets: ${TARGETS[@]}"

MERGE_CACHE="${OUT_PATH}/merge_cache"

# use direct binary path since 'cargo cov' doesn't seem to work on the VM
# --> https://github.com/rust-fuzz/cargo-fuzz/issues/308
LLVM_BIN="$(rustup show home)/toolchains/${TOOLCHAIN}/lib/rustlib/x86_64-unknown-linux-gnu/bin"

DATE_TIME="$(date +%F_%H-%M-%S)"

for target in "${TARGETS[@]}"; do

    echo "Running cargo fuzz coverage for target \"${target}\" ..."
    cargo fuzz coverage "${target}"

    # save coverage files for merging later
    mkdir -p "${MERGE_CACHE}"
    mv fuzz/coverage "${MERGE_CACHE}/coverage_${target}"

    PROFDATA="${MERGE_CACHE}/coverage_${target}/${target}/coverage.profdata"
    BINARY="target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/release/${target}"

    PROFDATA_FILES+=("${PROFDATA}")
    BINARIES+=("${BINARY}")

    # generate HTML cov report
    HTML_OUT="${OUT_PATH}/${DATE_TIME}_cov_${target}.html"
    echo "Creating HTML coverage report -> ${HTML_OUT} ..."
    # ignoring code in .cargo and .rustup to leave out dependency code
    # and focus on the actual project code
    "${LLVM_BIN}"/llvm-cov \
        show "${BINARY}" \
        --format=html \
        -instr-profile="${PROFDATA}" \
        -ignore-filename-regex='/.cargo/|/.rustup/' \
        > "${HTML_OUT}"

    # generate textual cov report
    TXT_OUT="${OUT_PATH}/${DATE_TIME}_cov_${target}.txt"
    echo "Creating textual coverage report -> ${TXT_OUT} ..."
    # ignoring code in .cargo and .rustup to leave out dependency code
    # and focus on the actual project code
    #
    # ALSO: ignoring code of fuzzer itself to only have coverage percentages
    # of the actual project code
    "${LLVM_BIN}"/llvm-cov \
        report "${BINARY}" \
        -instr-profile="${PROFDATA}" \
        -ignore-filename-regex='/.cargo/|/.rustup/|/fuzz/|/rustc/' \
        > "${TXT_OUT}"

done

echo "All done."
