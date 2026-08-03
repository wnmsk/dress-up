#!/usr/bin/env bash
# run_tests.sh – Run list of fuzzing targets for specific time
# Usage: ./run_tests.sh <runtime> [TARGET ...]
#
# Execute from project root
#----------------------------------------------------------

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <runtime> [TARGET ...]"
  echo "  <runtime>: value passed to -max_total_time (e.g. 60, 300)"
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
DATE="$(date +%F)"
DATE_TIME="$(date +%F_%H-%M-%S)"

RESULTS_DIR="fuzz/results/${DATE}/${DATE_TIME}"
LOG_DIR="${RESULTS_DIR}/test_logs"
CSV_DIR="${RESULTS_DIR}/csv"
PLOT_DIR="${RESULTS_DIR}/plots"
SUM_DIR="${RESULTS_DIR}/run_summary"
COV_DIR="${RESULTS_DIR}/cov_reports"
METRICS_DIR="${RESULTS_DIR}/metrics"

# Use venv if existing
if [[ -d ".venv" ]]; then
  source .venv/bin/activate
fi

mkdir -p \
  "${LOG_DIR}" \
  "${CSV_DIR}" \
  "${PLOT_DIR}" \
  "${SUM_DIR}" \
  "${COV_DIR}" \
  "${METRICS_DIR}"

# Backup existing corpus/artifacts at beginning
if [[ -d "fuzz/corpus" ]]; then
  echo "Backing up fuzz/corpus -> fuzz/corpus_bkp_${DATE_TIME}"
  mv "fuzz/corpus" "fuzz/corpus_bkp_${DATE_TIME}"
fi

if [[ -d "fuzz/artifacts" ]]; then
  echo "Backing up fuzz/artifacts -> fuzz/artifacts_bkp_${DATE_TIME}"
  mv "fuzz/artifacts" "fuzz/artifacts_bkp_${DATE_TIME}"
fi

# Build target list
if [[ $# -gt 0 ]]; then
  TARGETS=("$@")
else
  mapfile -t TARGETS < <(cargo fuzz list)
fi

# Gather information about host
HOSTNAME=$(hostname)
OS_INFO=$(uname -a)
CPU_INFO=$(lscpu)
MEMORY_INFO=$(free -h)
DISK_INFO=$(df -h)
UPTIME_INFO=$(uptime)

echo "======================="
echo "=== Running Targets ==="
echo "======================="

# Run targets
for target in "${TARGETS[@]}"; do
  [[ -n "${target}" ]] || continue

  echo "Running target: ${target}"
  cargo fuzz build "${target}"

  METRICS_OUTFILE="${METRICS_DIR}/${target}_time_to_exit.json"
  COV_REP_NAME="${target}_cov"

  LOG_FILE="${LOG_DIR}/testrun_${target}.txt"
  CSV_FILE="${CSV_DIR}/testrun_${target}.csv"


  cat > "$LOG_FILE" <<EOF
=== System Information ===
Generated: $DATE

Hostname:
$HOSTNAME

Operating System:
$OS_INFO

CPU Information:
$CPU_INFO

Memory Information:
$MEMORY_INFO

Disk Usage:
$DISK_INFO

Uptime:
$UPTIME_INFO

----------------------------------------

=== Target Information ===

runtime=${RUNTIME}
target=${target}
date_time=${DATE_TIME}
command=./fuzz/scripts/run_fuzz.sh ${target} ${METRICS_OUTFILE} -- ${TEST_ARGS[@]} -max_total_time=${RUNTIME}

----------------------------------------

=== Run Log ===

EOF

  set +e
  ./fuzz/scripts/run_fuzz.sh \
    "${target}" \
    "${METRICS_OUTFILE}" \
    -- \
    "${TEST_ARGS[@]}" \
    -max_total_time="${RUNTIME}" \
    2>&1 | ts '%s' | tee -a "${LOG_FILE}"
  set -e

  # python scripts to parse and plot run
  # IMPORTANT: matplotlib must be installed in Python for this to work

  # summarize run and save csv for plot
  python3 fuzz/tools/metrics_parser.py \
    "${LOG_FILE}" \
    --csv "${CSV_FILE}" \
    2>&1 | tee -a "${SUM_DIR}"/"${target}"_summary.txt

  # plot full run, first 10 min and first 30 min
  python3 fuzz/tools/metrics_plotter.py \
    "${CSV_FILE}" \
    --output "${PLOT_DIR}"/"${target}".png
  if [[ "${RUNTIME}" -gt 600 ]]; then
    python3 fuzz/tools/metrics_plotter.py \
      "${CSV_FILE}" \
      --end-time 10m \
      --output "${PLOT_DIR}"/"${target}"_first_10m.png
  fi
  if [[ "${RUNTIME}" -gt 1800 ]]; then
    python3 fuzz/tools/metrics_plotter.py \
      "${CSV_FILE}" \
      --end-time 30m \
      --output "${PLOT_DIR}"/"${target}"_first_30m.png
  fi

done

echo "==================================="
echo "=== Generating Coverage Reports ==="
echo "==================================="

# Generate coverage reports
./fuzz/scripts/fuzz_cov.sh "${COV_DIR}" "${TARGETS[@]}"

# Move corpus and artifact directories to results directory
mv "fuzz/corpus" "${RESULTS_DIR}"
mv "fuzz/artifacts" "${RESULTS_DIR}"
