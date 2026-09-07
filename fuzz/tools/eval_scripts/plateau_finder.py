#!/usr/bin/env python3
"""
Iterations-to-plateau via the alpha-fraction-of-final-coverage rule,
with two independent wall-clock estimates.

Plateau = first iteration at which cov >= alpha * cov_final.

Time estimators:
  A  global average rate = it_final / time_final, taken from the last row only.
  B  the fuzzer's own reported exec_per_sec at the crossing row.

Their ratio is reported as a sanity check. A large spread means the timing
data does not support a wall-clock answer.

Paths may be files or directories; directories are walked recursively for
files matching --glob (default *.csv). With no paths at all, the current
directory is walked.
"""

import argparse
import csv
import math
import os
import sys

# Ratio beyond which the two estimates are considered to disagree.
DISAGREE_FACTOR = 2.0

# exec_per_sec values at or below this are treated as the libFuzzer
# startup artefact (rate == iteration when elapsed time is 0 or 1s).
MIN_PLAUSIBLE_RATE = 1.0

DEFAULT_GLOB = "*.csv"


def collect_inputs(paths, pattern=DEFAULT_GLOB, follow_symlinks=False):
    """Expand paths into a sorted, de-duplicated list of files.

    Explicit file arguments are taken as-is regardless of pattern;
    directories are walked recursively and filtered by pattern.
    """
    import fnmatch

    found = []
    seen = set()

    def add(p):
        try:
            key = os.path.realpath(p)
        except OSError:
            key = os.path.abspath(p)
        if key not in seen:
            seen.add(key)
            found.append(p)

    for path in paths:
        if os.path.isfile(path):
            add(path)
        elif os.path.isdir(path):
            walked = []
            for dirpath, dirnames, filenames in os.walk(
                    path, followlinks=follow_symlinks):
                # Skip hidden directories (.git, .venv, ...) in place.
                dirnames[:] = sorted(d for d in dirnames
                                     if not d.startswith("."))
                for name in sorted(filenames):
                    if fnmatch.fnmatch(name, pattern):
                        walked.append(os.path.join(dirpath, name))
            for p in walked:
                add(p)
            if not walked:
                print(f"  warning: {path}: no files matching {pattern!r}",
                      file=sys.stderr)
        else:
            print(f"  warning: {path}: not found, skipped", file=sys.stderr)

    return found


def load_run(path):
    """Return a list of (iteration, cov, time_elapsed, exec_per_sec), sorted."""
    rows = []
    with open(path, newline="") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None:
            raise ValueError(f"{path}: empty file")
        needed = {"iteration", "cov", "time_elapsed", "exec_per_sec"}
        missing = needed - set(reader.fieldnames)
        if missing:
            raise ValueError(f"{path}: missing column(s): {', '.join(sorted(missing))}")
        for lineno, row in enumerate(reader, start=2):
            try:
                rows.append((
                    int(row["iteration"]),
                    int(row["cov"]),
                    int(row["time_elapsed"]),
                    float(row["exec_per_sec"]),
                ))
            except (TypeError, ValueError):
                print(f"  warning: {path}:{lineno}: unparsable row, skipped",
                      file=sys.stderr)
                continue
    if not rows:
        raise ValueError(f"{path}: no usable data rows")
    rows.sort(key=lambda r: r[0])
    return rows


def fmt_duration(sec):
    """Seconds -> compact human-readable string."""
    if math.isnan(sec):
        return "n/a"
    if sec < 90:
        return f"{sec:.0f}s"
    if sec < 5400:
        return f"{sec / 60:.1f}min"
    return f"{sec / 3600:.2f}h"


def fmt_rate(r):
    return "n/a" if math.isnan(r) else f"{r:,.0f}/s"


def plateau(rows, alpha):
    """Locate the alpha crossing and estimate wall-clock time two ways."""
    it_final, cov_final, t_final, _ = rows[-1]
    target = alpha * cov_final

    for it, cov, _, eps in rows:
        if cov >= target:
            it_plateau, cov_plateau, eps_crossing = it, cov, eps
            break
    else:  # pragma: no cover - cov_final always satisfies the test
        it_plateau, cov_plateau, eps_crossing = rows[-1][0], cov_final, rows[-1][3]

    # A: global average rate, from the final row only.
    rate_global = it_final / t_final if t_final > 0 else float("nan")
    t_a = it_plateau / rate_global if rate_global > 0 else float("nan")

    # B: the fuzzer's reported rate at the crossing row, unless it is the
    # startup artefact (exec_per_sec == iteration for elapsed 0 or 1s).
    if eps_crossing > MIN_PLAUSIBLE_RATE and eps_crossing != it_plateau:
        rate_crossing = eps_crossing
        t_b = it_plateau / rate_crossing
    else:
        rate_crossing = float("nan")
        t_b = float("nan")

    if not math.isnan(t_a) and not math.isnan(t_b) and min(t_a, t_b) > 0:
        ratio = max(t_a, t_b) / min(t_a, t_b)
    else:
        ratio = float("nan")

    return {
        "it_plateau": it_plateau,
        "cov_plateau": cov_plateau,
        "it_final": it_final,
        "cov_final": cov_final,
        "t_final": t_final,
        "frac_budget": it_plateau / it_final if it_final else float("nan"),
        "rate_global": rate_global,
        "rate_crossing": rate_crossing,
        "t_a": t_a,
        "t_b": t_b,
        "ratio": ratio,
    }


def main():
    ap = argparse.ArgumentParser(
        description="Iterations-to-plateau for libFuzzer coverage CSVs.")
    ap.add_argument("paths", nargs="*", default=["."],
                    help="CSV files and/or directories to search "
                         "(default: current directory)")
    ap.add_argument("-a", "--alpha", type=float, default=0.95,
                    help="fraction of final coverage defining plateau "
                         "(default: 0.95)")
    ap.add_argument("-g", "--glob", default=DEFAULT_GLOB,
                    help=f"filename pattern for directory search "
                         f"(default: {DEFAULT_GLOB})")
    ap.add_argument("-L", "--follow-symlinks", action="store_true",
                    help="follow symlinked directories while walking")
    ap.add_argument("-d", "--disagree-factor", type=float,
                    default=DISAGREE_FACTOR,
                    help=f"flag runs whose two time estimates differ by more "
                         f"than this factor (default: {DISAGREE_FACTOR})")
    ap.add_argument("--tsv", action="store_true",
                    help="machine-readable output instead of a report")
    args = ap.parse_args()

    if not 0 < args.alpha <= 1:
        ap.error("--alpha must be in (0, 1]")

    files = collect_inputs(args.paths, args.glob, args.follow_symlinks)
    if not files:
        print("no input files", file=sys.stderr)
        sys.exit(1)

    results = []
    exit_code = 0
    for path in files:
        try:
            rows = load_run(path)
        except (OSError, ValueError) as exc:
            print(f"  warning: {exc}", file=sys.stderr)
            exit_code = 1
            continue
        results.append((path, plateau(rows, args.alpha)))

    if not results:
        print("no files yielded usable data", file=sys.stderr)
        sys.exit(1)

    if args.tsv:
        cols = ["file", "it_plateau", "cov_plateau", "it_final", "cov_final",
                "frac_budget", "rate_global", "rate_crossing",
                "t_a_sec", "t_b_sec", "ratio", "flag"]
        print("\t".join(cols))
        for path, r in results:
            flag = ("inconclusive" if math.isnan(r["ratio"])
                    else "disagree" if r["ratio"] > args.disagree_factor
                    else "ok")
            print("\t".join([
                path,
                str(r["it_plateau"]), str(r["cov_plateau"]),
                str(r["it_final"]), str(r["cov_final"]),
                f"{r['frac_budget']:.4f}",
                f"{r['rate_global']:.1f}", f"{r['rate_crossing']:.1f}",
                f"{r['t_a']:.1f}", f"{r['t_b']:.1f}", f"{r['ratio']:.3f}",
                flag,
            ]))
        sys.exit(exit_code)

    print(f"alpha = {args.alpha:g}, {len(results)} run(s)\n")
    for path, r in results:
        bad = math.isnan(r["ratio"]) or r["ratio"] > args.disagree_factor
        if bad and exit_code == 0:
            exit_code = 2

        print(f"{path}")
        print(f"  final                : it {r['it_final']:,}, "
              f"cov {r['cov_final']}, t_elapsed {r['t_final']}s")
        print(f"  plateau              : it {r['it_plateau']:,} "
              f"(cov {r['cov_plateau']}, "
              f"{100 * r['frac_budget']:.1f}% of budget)")
        print(f"  est. A (global rate) : {fmt_duration(r['t_a'])}"
              f"   [rate {fmt_rate(r['rate_global'])}]")
        print(f"  est. B (rate at xing): {fmt_duration(r['t_b'])}"
              f"   [rate {fmt_rate(r['rate_crossing'])}]")

        if math.isnan(r["ratio"]):
            print("  sanity check         : INCONCLUSIVE "
                  "(one estimate unavailable) -- quote iterations only")
        elif bad:
            print(f"  sanity check         : DISAGREE by {r['ratio']:.1f}x "
                  f"-- timing data unreliable")
        else:
            lo, hi = sorted((r["t_a"], r["t_b"]))
            print(f"  sanity check         : ok ({r['ratio']:.2f}x) -- "
                  f"time-to-plateau ~ {fmt_duration(lo)}..{fmt_duration(hi)}")
        print()

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
