#!/usr/bin/env bash
# run_tests.sh – Run list of fuzzing targets for specific time
# Usage: ./run_tests.sh <runtime> [TARGET ...]
#
# Execute from project root
#----------------------------------------------------------

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 RUNTIME [TARGET ...]"
  echo "  RUNTIME: value passed to -max_total_time (e.g. 60, 300)"
  echo "  TARGET:  optional list of cargo-fuzz targets; if omitted uses: cargo fuzz list"
  exit 2
fi

TEST_ARGS=(
  -seed=0
  -max_len=8192
  -timeout=5
  -rss_limit_mb=4096
  -print_final_stats=1
)

RUNTIME="$1"
shift || true

# Dates/paths
DATE="$(date +%F)"              # YYYY-MM-DD
DATE_TIME="$(date +%F_%H-%M-%S)" # safe for filenames

RESULTS_DIR="fuzz/results/${DATE}"
LOG_DIR="${RESULTS_DIR}/test_logs"
CORPUS_RESULTS_DIR="${RESULTS_DIR}/corpus"
ARTIFACTS_RESULTS_DIR="${RESULTS_DIR}/artifacts"
CSV_DIR="${RESULTS_DIR}/csv"
PLOT_DIR="${RESULTS_DIR}/plots"
SUM_DIR="${RESULTS_DIR}/run_summary"
COV_DIR="${RESULTS_DIR}/cov_reports"
METRICS_DIR="${RESULTS_DIR}/metrics"

mkdir -p "${LOG_DIR}" "${CORPUS_RESULTS_DIR}" "${ARTIFACTS_RESULTS_DIR}" "${CSV_DIR}" "${PLOT_DIR}" "${SUM_DIR}" "${COV_DIR}" "${METRICS_DIR}"

# # Backup existing corpus/artifacts at beginning
if [[ -d "fuzz/corpus" ]]; then
  mv "fuzz/corpus" "fuzz/corpus_bkp_${DATE_TIME}"
fi

if [[ -d "fuzz/artifacts" ]]; then
  mv "fuzz/artifacts" "fuzz/artifacts_bkp_${DATE_TIME}"
fi

# Build target list
if [[ $# -gt 0 ]]; then
  TARGETS=("$@")
else
  mapfile -t TARGETS < <(cargo fuzz list)
fi

# Run targets
for target in "${TARGETS[@]}"; do
  [[ -n "${target}" ]] || continue

  echo "Running target: ${target}"
  cargo fuzz build "${target}"

  METRICS_OUTFILE="${METRICS_DIR}/${DATE_TIME}_${target}_time_to_exit.json"
  COV_REP_NAME="${DATE_TIME}_${target}_cov"

  LOG_FILE="${LOG_DIR}/testrun_${DATE_TIME}_${target}.txt"
  CSV_FILE="${CSV_DIR}/testrun_${DATE_TIME}_${target}.csv"

  {
    echo "runtime=${RUNTIME}"
    echo "target=${target}"
    echo "date_time=${DATE_TIME}"
    echo "command=./fuzz/scripts/run_fuzz.sh ${target} ${METRICS_OUTFILE} -- ${TEST_ARGS[@]} -max_total_time=${RUNTIME}"
    echo "----------------------------------------"
  } | tee "${LOG_FILE}" >/dev/null

  set +e
  ./fuzz/scripts/run_fuzz.sh "${target}" "${METRICS_OUTFILE}" -- "${TEST_ARGS[@]}" -max_total_time="${RUNTIME}" 2>&1 | ts '%s' | tee -a "${LOG_FILE}"
  set -e

  ./fuzz/scripts/fuzz_cov.sh "${target}" "${COV_DIR}" "${COV_REP_NAME}"

  # python scripts to parse and plot run
  # IMPORTANT: matplotlib must be installed in Python for this to work

  # summarize run and save csv for plot
  python3 fuzz/tools/metrics_parser.py "${LOG_FILE}" --csv "${CSV_FILE}" 2>&1 | tee -a "${SUM_DIR}"/testrun_"${DATE_TIME}"_"${target}"_summary.txt

  # plot full run, first 10 min and first 30 min
  python3 fuzz/tools/metrics_plotter.py "${CSV_FILE}" --output "${PLOT_DIR}"/testrun_"${DATE_TIME}"_"${target}".png
  if [[ "${RUNTIME}" -gt 600 ]]; then
    python3 fuzz/tools/metrics_plotter.py "${CSV_FILE}" --end-time 10m --output "${PLOT_DIR}"/testrun_"${DATE_TIME}"_"${target}"_first_10m.png
  fi
  if [[ "${RUNTIME}" -gt 1800 ]]; then
    python3 fuzz/tools/metrics_plotter.py "${CSV_FILE}" --end-time 30m --output "${PLOT_DIR}"/testrun_"${DATE_TIME}"_"${target}"_first_30m.png
  fi

done

# Move resulting corpus/artifacts to results at end
# If destination exists, add a timestamp suffix to avoid clobbering.
move_dir_if_exists() {
  local src="$1"
  local dst_dir="$2"   # directory that should contain the moved folder (date dir)
  local name="$3"      # corpus/artifacts

  [[ -d "${src}" ]] || return 0

  local dst="${dst_dir}/${name}_${DATE_TIME}"
  mv "${src}" "${dst}"
}

move_dir_if_exists "fuzz/corpus"    "${CORPUS_RESULTS_DIR}"    "corpus"
move_dir_if_exists "fuzz/artifacts" "${ARTIFACTS_RESULTS_DIR}" "artifacts"
