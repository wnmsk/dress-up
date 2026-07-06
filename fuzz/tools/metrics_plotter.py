#!/usr/bin/env python3

import argparse
import csv
import re
from pathlib import Path

import matplotlib.pyplot as plt


DURATION_RE = re.compile(r"^(?P<value>\d+(?:\.\d+)?)(?P<unit>s|m|h)?$")


def parse_duration(value):
    """
    Parse duration strings into seconds.

    Supported examples:
      30      -> 30 seconds
      30s     -> 30 seconds
      30m     -> 1800 seconds
      1h      -> 3600 seconds
      1.5h    -> 5400 seconds
    """

    if value is None:
        return None

    value = str(value).strip()

    match = DURATION_RE.match(value)
    if not match:
        raise ValueError(
            f"Invalid duration: {value}. "
            "Use plain seconds or suffixes s, m, h. Examples: 30, 30s, 30m, 1h"
        )

    number = float(match.group("value"))
    unit = match.group("unit") or "s"

    multipliers = {
        "s": 1,
        "m": 60,
        "h": 60 * 60,
    }

    return number * multipliers[unit]


def read_metrics_csv(path):
    """
    Read metrics CSV produced by metrics_parser.py.

    Returns a list of dictionaries with numeric values converted.
    """

    samples = []

    with open(path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)

        for row in reader:
            sample = {
                "timestamp": int(row["timestamp"]),
                "time_elapsed": float(row["time_elapsed"]),
                "iteration": int(row["iteration"]),
                "event": row["event"],
                "cov": int(row["cov"]),
                "exec_per_sec": int(row["exec_per_sec"]),
                "corp_count": int(row["corp_count"]),
                "corp_bytes": int(row["corp_bytes"]),
            }

            if "line_number" in row and row["line_number"]:
                sample["line_number"] = int(row["line_number"])

            if "ft" in row and row["ft"]:
                sample["ft"] = int(row["ft"])

            if "corp_size_raw" in row and row["corp_size_raw"]:
                sample["corp_size_raw"] = row["corp_size_raw"]

            samples.append(sample)

    return samples


def filter_by_timeframe(samples, start_time=None, end_time=None):
    """
    Filter samples by elapsed time.

    start_time and end_time are in seconds.
    """

    if start_time is None and end_time is None:
        return samples

    filtered = []

    for sample in samples:
        t = sample["time_elapsed"]

        if start_time is not None and t < start_time:
            continue

        if end_time is not None and t > end_time:
            continue

        filtered.append(sample)

    return filtered


def describe_timeframe(start_time=None, end_time=None):
    if start_time is None and end_time is None:
        return "full run"

    if start_time is None:
        return f"first {end_time:g}s"

    if end_time is None:
        return f"from {start_time:g}s onward"

    return f"{start_time:g}s to {end_time:g}s"


def plot_metrics(samples, output_path=None, use_iterations=False, title_suffix=None):
    """
    Plot fuzzing metrics.

    If use_iterations is False:
        x-axis = elapsed time in seconds

    If use_iterations is True:
        x-axis = fuzzer iteration number
    """

    if not samples:
        raise ValueError("No samples to plot after applying filters.")

    if use_iterations:
        x = [s["iteration"] for s in samples]
        x_label = "Iteration"
    else:
        x = [s["time_elapsed"] for s in samples]
        x_label = "Elapsed time [s]"

    cov = [s["cov"] for s in samples]
    exec_per_sec = [s["exec_per_sec"] for s in samples]
    corp_count = [s["corp_count"] for s in samples]
    corp_bytes = [s["corp_bytes"] for s in samples]

    suffix = f" [{title_suffix}]" if title_suffix else ""

    fig, axes = plt.subplots(4, 1, figsize=(12, 10), sharex=True)

    axes[0].plot(x, cov)
    axes[0].set_ylabel("Coverage")
    axes[0].set_title(f"Coverage over time{suffix}")
    axes[0].grid(True)

    axes[1].plot(x, exec_per_sec)
    axes[1].set_ylabel("Exec/s")
    axes[1].set_title(f"Executions per second over time{suffix}")
    axes[1].grid(True)

    axes[2].plot(x, corp_count)
    axes[2].set_ylabel("Corpus entries")
    axes[2].set_title(f"Corpus entries over time{suffix}")
    axes[2].grid(True)

    axes[3].plot(x, corp_bytes)
    axes[3].set_ylabel("Corpus bytes")
    axes[3].set_title(f"Corpus size over time{suffix}")
    axes[3].set_xlabel(x_label)
    axes[3].grid(True)

    fig.tight_layout()

    if output_path:
        plt.savefig(output_path, dpi=150)
        print(f"Plot written to: {output_path}")
    else:
        plt.show()


def plot_time_to_coverage(
    samples,
    target_coverages,
    output_path=None,
    use_iterations=False,
    title_suffix=None,
):
    """
    Plot coverage over time and mark when target coverage values are reached.

    Important:
      This uses the already-filtered samples. So if you select --end-time 30m,
      then targets reached after 30 minutes will be reported as not reached
      within that selected timeframe.
    """

    if not samples:
        raise ValueError("No samples to plot after applying filters.")

    if use_iterations:
        x = [s["iteration"] for s in samples]
        x_label = "Iteration"
    else:
        x = [s["time_elapsed"] for s in samples]
        x_label = "Elapsed time [s]"

    cov = [s["cov"] for s in samples]
    suffix = f" [{title_suffix}]" if title_suffix else ""

    fig, ax = plt.subplots(figsize=(12, 5))

    ax.plot(x, cov, label="Coverage")

    for target in target_coverages:
        reached = next((s for s in samples if s["cov"] >= target), None)

        if reached is None:
            print(f"Coverage target {target} was not reached in selected timeframe.")
            continue

        reached_x = reached["iteration"] if use_iterations else reached["time_elapsed"]

        ax.axhline(target, linestyle="--", linewidth=1)
        ax.axvline(reached_x, linestyle="--", linewidth=1)
        ax.scatter([reached_x], [reached["cov"]])

        ax.annotate(
            f"cov >= {target}\n{x_label}: {reached_x:g}",
            xy=(reached_x, reached["cov"]),
            xytext=(8, 8),
            textcoords="offset points",
        )

        print(
            f"Coverage target {target} reached at "
            f"{x_label.lower()}={reached_x:g}, "
            f"iteration={reached['iteration']}, "
            f"coverage={reached['cov']}"
        )

    ax.set_title(f"Time to reach coverage{suffix}")
    ax.set_xlabel(x_label)
    ax.set_ylabel("Coverage")
    ax.grid(True)
    ax.legend()

    fig.tight_layout()

    if output_path:
        plt.savefig(output_path, dpi=150)
        print(f"Coverage target plot written to: {output_path}")
    else:
        plt.show()


def print_filter_summary(original_samples, filtered_samples, start_time=None, end_time=None):
    print("Input summary")
    print("-------------")
    print(f"Original samples:      {len(original_samples)}")
    print(f"Filtered samples:      {len(filtered_samples)}")
    print(f"Selected timeframe:    {describe_timeframe(start_time, end_time)}")

    if filtered_samples:
        first = filtered_samples[0]
        last = filtered_samples[-1]

        print(f"First plotted time:    {first['time_elapsed']:g}s")
        print(f"Last plotted time:     {last['time_elapsed']:g}s")
        print(f"First iteration:       {first['iteration']}")
        print(f"Last iteration:        {last['iteration']}")
        print(f"First coverage:        {first['cov']}")
        print(f"Last coverage:         {last['cov']}")
    else:
        print("No samples remain after filtering.")


def main():
    parser = argparse.ArgumentParser(
        description="Plot fuzzing metrics from CSV generated by metrics_parser.py."
    )

    parser.add_argument(
        "csv_file",
        type=Path,
        help="CSV file produced by the fuzz log parser.",
    )

    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=None,
        help="Optional output image path, for example metrics.png.",
    )

    parser.add_argument(
        "--x-axis",
        choices=["time", "iteration"],
        default="time",
        help="Use elapsed time or fuzzer iteration as x-axis. Default: time.",
    )

    parser.add_argument(
        "--start-time",
        default=None,
        help=(
            "Start of timeframe based on elapsed time. "
            "Supports seconds or suffixes s, m, h. Examples: 0, 30s, 10m, 1h"
        ),
    )

    parser.add_argument(
        "--end-time",
        default=None,
        help=(
            "End of timeframe based on elapsed time. "
            "Supports seconds or suffixes s, m, h. Examples: 1800, 30m, 1h"
        ),
    )

    parser.add_argument(
        "--target-cov",
        type=int,
        nargs="*",
        default=None,
        help="Optional coverage target values to mark, for example: --target-cov 400 600 800",
    )

    parser.add_argument(
        "--target-output",
        type=Path,
        default=None,
        help="Optional output image path for the target coverage plot.",
    )

    args = parser.parse_args()

    start_time = parse_duration(args.start_time)
    end_time = parse_duration(args.end_time)

    if start_time is not None and end_time is not None and start_time > end_time:
        raise ValueError("--start-time must be <= --end-time")

    original_samples = read_metrics_csv(args.csv_file)
    filtered_samples = filter_by_timeframe(
        original_samples,
        start_time=start_time,
        end_time=end_time,
    )

    print_filter_summary(
        original_samples,
        filtered_samples,
        start_time=start_time,
        end_time=end_time,
    )

    if not filtered_samples:
        return

    use_iterations = args.x_axis == "iteration"
    title_suffix = describe_timeframe(start_time, end_time)

    plot_metrics(
        filtered_samples,
        output_path=args.output,
        use_iterations=use_iterations,
        title_suffix=title_suffix,
    )

    if args.target_cov:
        plot_time_to_coverage(
            filtered_samples,
            target_coverages=args.target_cov,
            output_path=args.target_output,
            use_iterations=use_iterations,
            title_suffix=title_suffix,
        )


if __name__ == "__main__":
    main()
