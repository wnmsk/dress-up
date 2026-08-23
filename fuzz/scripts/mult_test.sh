#!/bin/bash

SCRIPT="./fuzz/scripts/run_tests.sh"

usage() {
    cat <<EOF
Usage: $(basename "$0") <count> <time> [target ...]

Runs the test script multiple times.

Arguments:
  count       Number of test runs to execute
  time        Time parameter passed to run_tests.sh
  target      Optional list of targets passed to run_tests.sh

Examples:
  $(basename "$0") 10 60
  $(basename "$0") 5 120 targetA targetB
EOF
}

# Show usage if help is requested or required args are missing
if [[ "$1" == "-h" || "$1" == "--help" || $# -lt 2 ]]; then
    usage
    exit $([[ $# -lt 2 ]] && echo 1 || echo 0)
fi

COUNT="$1"
TIME="$2"

shift 2 || true

TARGETS=$#

if (( TARGETS == 0 )); then
    FACTOR=3
else
    FACTOR=$TARGETS
fi

SECONDS_PER_RUN=$((TIME * FACTOR))

for ((i=1; i<=COUNT; i++)); do
    REMAINING_RUNS=$((COUNT - i + 1))
    REMAINING_SECONDS=$((REMAINING_RUNS * SECONDS_PER_RUN))

    HOURS=$((REMAINING_SECONDS / 3600))
    MINUTES=$(((REMAINING_SECONDS % 3600) / 60))
    SECS=$((REMAINING_SECONDS % 60))

    printf '\033]0;Run %d/%d | ETA %02d:%02d:%02d\007' \
        "$i" "$COUNT" "$HOURS" "$MINUTES" "$SECS"

    bash "$SCRIPT" "$TIME" "$@"
done
