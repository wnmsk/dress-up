#!/usr/bin/env python3

import argparse
import csv
import json
import re
from pathlib import Path


PROGRESS_RE = re.compile(
    r"""
    ^(?P<timestamp>\d+)\s+
    \#(?P<iteration>\d+)\s+
    (?P<event>[A-Z_]+)\s+
    .*?
    cov:\s*(?P<cov>\d+)
    .*?
    ft:\s*(?P<ft>\d+)
    .*?
    corp:\s*(?P<corp_count>\d+)/
        (?P<corp_size_value>\d+)
        (?P<corp_size_unit>[KMG]?b)
    .*?
    exec/s:\s*(?P<exec_per_sec>\d+)
    """,
    re.VERBOSE,
)


def parse_size(value, unit):
    """
    Convert libFuzzer-style sizes to bytes.

    Examples:
      15819b -> 15819
      16Kb   -> 16384
      2Mb    -> 2097152
      1Gb    -> 1073741824
    """

    value = int(value)

    multipliers = {
        "b": 1,
        "Kb": 1024,
        "Mb": 1024 * 1024,
        "Gb": 1024 * 1024 * 1024,
    }

    if unit not in multipliers:
        raise ValueError(f"Unknown size unit: {unit}")

    return value * multipliers[unit]


def parse_log(path):
    samples = []
    first_timestamp = None

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.rstrip("\n")

            match = PROGRESS_RE.search(line)
            if not match:
                continue

            timestamp = int(match.group("timestamp"))

            if first_timestamp is None:
                first_timestamp = timestamp

            corp_size_raw = (
                match.group("corp_size_value") + match.group("corp_size_unit")
            )

            corp_bytes = parse_size(
                match.group("corp_size_value"),
                match.group("corp_size_unit"),
            )

            sample = {
                "line_number": line_number,
                "timestamp": timestamp,
                "time_elapsed": timestamp - first_timestamp,
                "iteration": int(match.group("iteration")),
                "event": match.group("event"),
                "cov": int(match.group("cov")),
                "ft": int(match.group("ft")),
                "corp_count": int(match.group("corp_count")),
                "corp_size_raw": corp_size_raw,
                "corp_bytes": corp_bytes,
                "exec_per_sec": int(match.group("exec_per_sec")),
            }

            samples.append(sample)

    return samples


def time_to_coverage(samples, target_cov):
    for sample in samples:
        if sample["cov"] >= target_cov:
            return sample

    return None


def write_csv(samples, output_path):
    fieldnames = [
        "line_number",
        "timestamp",
        "time_elapsed",
        "iteration",
        "event",
        "cov",
        "ft",
        "exec_per_sec",
        "corp_count",
        "corp_size_raw",
        "corp_bytes",
    ]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(samples)


def write_json(samples, output_path):
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(samples, f, indent=2)


def print_summary(samples, target_cov=None):
    if not samples:
        print("No metric samples found.")
        return

    first = samples[0]
    last = samples[-1]

    print("Summary")
    print("-------")
    print(f"Samples parsed:        {len(samples)}")
    print(f"Start timestamp:       {first['timestamp']}")
    print(f"End timestamp:         {last['timestamp']}")
    print(f"Duration:              {last['time_elapsed']} seconds")
    print(f"Final coverage:        {last['cov']}")
    print(f"Final ft:              {last['ft']}")
    print(f"Final exec/s:          {last['exec_per_sec']}")
    print(f"Final corpus entries:  {last['corp_count']}")
    print(f"Final corpus size:     {last['corp_size_raw']} = {last['corp_bytes']} bytes")

    print(f"Max coverage:          {max(s['cov'] for s in samples)}")
    print(f"Max ft:                {max(s['ft'] for s in samples)}")
    print(f"Max exec/s:            {max(s['exec_per_sec'] for s in samples)}")
    print(f"Max corpus entries:    {max(s['corp_count'] for s in samples)}")
    print(f"Max corpus bytes:      {max(s['corp_bytes'] for s in samples)}")

    if target_cov is not None:
        reached = time_to_coverage(samples, target_cov)

        print()
        print(f"Time to coverage >= {target_cov}")
        print("----------------------")

        if reached is None:
            print("Target coverage was not reached.")
        else:
            print(f"Reached at timestamp:  {reached['timestamp']}")
            print(f"Reached after:         {reached['time_elapsed']} seconds")
            print(f"Line number:           {reached['line_number']}")
            print(f"Iteration:             {reached['iteration']}")
            print(f"Coverage:              {reached['cov']}")


def main():
    parser = argparse.ArgumentParser(
        description="Parse libFuzzer logs and extract coverage, exec/s, and corpus metrics."
    )

    parser.add_argument(
        "logfile",
        type=Path,
        help="Path to the log file.",
    )

    parser.add_argument(
        "--target-cov",
        type=int,
        default=None,
        help="Coverage value for calculating time-to-coverage.",
    )

    parser.add_argument(
        "--csv",
        type=Path,
        default=None,
        help="Optional output CSV path.",
    )

    parser.add_argument(
        "--json",
        type=Path,
        default=None,
        help="Optional output JSON path.",
    )

    args = parser.parse_args()

    samples = parse_log(args.logfile)

    print_summary(samples, args.target_cov)

    if args.csv:
        write_csv(samples, args.csv)
        print(f"\nCSV written to: {args.csv}")

    if args.json:
        write_json(samples, args.json)
        print(f"JSON written to: {args.json}")


if __name__ == "__main__":
    main()
