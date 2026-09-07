#!/usr/bin/env python3
"""
Aggregate plateau_finder.py --tsv output: median per basename.

Rows are grouped by os.path.basename(file), so the same target measured
across several run directories collapses into one line.

Medians are taken column-wise and independently, so the output row is a
summary, not any actual run. NaN values are dropped per column rather than
per row, meaning different columns may be computed over different n.
"""

import argparse
import csv
import math
import os
import statistics
import sys
from collections import Counter, defaultdict

NUMERIC = ["it_plateau", "cov_plateau", "it_final", "cov_final",
           "frac_budget", "rate_global", "rate_crossing",
           "t_a_sec", "t_b_sec", "ratio"]

INTEGRAL = {"it_plateau", "cov_plateau", "it_final", "cov_final"}


def median_or_nan(values):
    clean = [v for v in values if not math.isnan(v)]
    return (statistics.median(clean), len(clean)) if clean else (float("nan"), 0)


def main():
    ap = argparse.ArgumentParser(
        description="Median-aggregate plateau_finder.py TSV output by filename.")
    ap.add_argument("tsv", nargs="?", default="-",
                    help="TSV from plateau_finder.py --tsv (default: stdin)")
    ap.add_argument("-k", "--key", choices=["basename", "dirname", "path"],
                    default="basename",
                    help="grouping key (default: basename)")
    ap.add_argument("-m", "--min-runs", type=int, default=1,
                    help="skip groups with fewer than this many rows")
    args = ap.parse_args()

    fh = sys.stdin if args.tsv == "-" else open(args.tsv, newline="")
    try:
        reader = csv.DictReader(fh, delimiter="\t")
        if reader.fieldnames is None or "file" not in reader.fieldnames:
            sys.exit("input does not look like plateau_finder.py --tsv output")

        groups = defaultdict(lambda: defaultdict(list))
        flags = defaultdict(Counter)
        counts = Counter()

        for lineno, row in enumerate(reader, start=2):
            path = row["file"]
            if args.key == "basename":
                key = os.path.basename(path)
            elif args.key == "dirname":
                key = os.path.dirname(path) or "."
            else:
                key = path

            counts[key] += 1
            flags[key][row.get("flag", "")] += 1
            for col in NUMERIC:
                raw = row.get(col, "")
                try:
                    groups[key][col].append(float(raw))
                except (TypeError, ValueError):
                    print(f"  warning: line {lineno}: bad {col}={raw!r}",
                          file=sys.stderr)
    finally:
        if fh is not sys.stdin:
            fh.close()

    if not counts:
        sys.exit("no data rows")

    out = csv.writer(sys.stdout, delimiter="\t", lineterminator="\n")
    out.writerow(["group", "n"] + [f"median_{c}" for c in NUMERIC]
                 + ["n_ok", "n_disagree", "n_inconclusive"])

    for key in sorted(counts):
        n = counts[key]
        if n < args.min_runs:
            continue
        cells = []
        for col in NUMERIC:
            med, used = median_or_nan(groups[key][col])
            if math.isnan(med):
                cells.append("nan")
            elif col in INTEGRAL:
                cells.append(f"{med:.0f}")
            else:
                cells.append(f"{med:.4f}" if col == "frac_budget"
                             else f"{med:.1f}")
            if used < n:
                print(f"  note: {key}: {col} median over {used}/{n} rows",
                      file=sys.stderr)
        out.writerow([key, n] + cells
                     + [flags[key]["ok"], flags[key]["disagree"],
                        flags[key]["inconclusive"]])


if __name__ == "__main__":
    main()
