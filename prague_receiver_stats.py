#!/usr/bin/env python3
"""
Aggregate UDP Prague receiver JSON files by scenario.

Run this on the receiver node (where udp_prague_receiver writes JSON files).
Parses *_rx_*_port*.json files, groups by scenario (app, cc, network, etc.),
and outputs mean rcvd_rate (goodput Mbps), RTT, mark_prob, loss_prob across
all flows and trials for each scenario.

Workflow:
  1. Upload this script to the receiver node (e.g. rxL4S)
  2. On receiver: cd ~/L4S_Project/udp_prague && python3 prague_receiver_stats.py -o prague_receiver_agg.json
  3. Download prague_receiver_agg.json to your local mgen/ directory
  4. Run: python3 collect_and_plot_mgen.py --prague-receiver-json prague_receiver_agg.json

Usage:
  # From directory containing JSON files (e.g. ~/L4S_Project/udp_prague)
  python3 prague_receiver_stats.py

  # Or specify directory
  python3 prague_receiver_stats.py /path/to/json/files

  # Output JSON for downstream use
  python3 prague_receiver_stats.py -o prague_receiver_agg.json
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict

# Filename: {app}-PRAGUE_{app_legacy}-{proto}_{cc_L4S}_{cc_legacy}_{aqm}_{ecn}_{rtt}ms_{cap}Mbps_t{trial}_rx_{L4S|legacy}_port{port}.json
PAT = re.compile(
    r"^([^-]+)-PRAGUE_([^-]+)-([^_]+)_([^_]+)_([^_]+)_([^_]+)_([^_]+)_(\d+)ms_(\d+)Mbps_t(\d+)_rx_(L4S|legacy)_port(\d+)\.json$"
)


# Minimum rcvd_rate (Mbps) to consider a sample as "ON" for streaming.
# OFF periods have near-zero rate (~0.0006); ON periods have 1-3+ Mbps.
STREAMING_ON_THRESHOLD_MBPS = 0.1


def parse_file(
    filepath: str,
    skip_warmup: int = 2,
    app_L4S: str | None = None,
    streaming_on_threshold_mbps: float = STREAMING_ON_THRESHOLD_MBPS,
) -> dict | None:
    """
    Parse a receiver JSON file. Each line is a JSON object.
    Returns dict with avg rcvd_rate_mbps, rtt_ms, mark_prob, loss_prob, n_samples.
    Skips first skip_warmup samples (often near-zero during startup).
    For streaming (app_L4S=="streaming"), keeps only samples with rcvd_rate above threshold
    (ON periods have 1-3+ Mbps; OFF periods have ~0.0006 Mbps).
    """
    samples = []
    try:
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                t_us = int(obj.get("time_since_start", 0))
                samples.append({
                    "time_since_start_us": t_us,
                    "rcvd_rate": float(obj.get("rcvd_rate", 0)),
                    "RTT": float(obj.get("RTT", 0)),
                    "mark_prob": float(obj.get("mark_prob", 0)),
                    "loss_prob": float(obj.get("loss_prob", 0)),
                })
    except (json.JSONDecodeError, KeyError, ValueError):
        return None

    if len(samples) <= skip_warmup:
        return None

    samples = samples[skip_warmup:]

    # For streaming: keep only samples during ON periods (rcvd_rate above threshold)
    if app_L4S == "streaming":
        samples = [s for s in samples if s["rcvd_rate"] >= streaming_on_threshold_mbps]
        if not samples:
            return None

    rcvd = [s["rcvd_rate"] for s in samples]
    rtt = [s["RTT"] for s in samples]
    mark = [s["mark_prob"] for s in samples]
    loss = [s["loss_prob"] for s in samples]
    n = len(samples)
    return {
        "rcvd_rate_mbps": sum(rcvd) / n,
        "rtt_ms": sum(rtt) / n,
        "mark_prob": sum(mark) / n,
        "loss_prob": sum(loss) / n,
        "n_samples": n,
    }


def run(
    directory: str,
    skip_warmup: int,
    output_path: str | None,
    streaming_on_threshold_mbps: float = STREAMING_ON_THRESHOLD_MBPS,
) -> dict:
    """
    Scan directory for receiver JSON files, group by scenario, aggregate.
    Returns dict: scenario_key -> {mean_goodput_mbps, std_goodput_mbps, mean_rtt_ms, ...}
    """
    groups = defaultdict(list)  # scenario_key -> list of per-file stats

    for f in os.listdir(directory):
        if not f.endswith(".json") or "_rx_" not in f or "_port" not in f:
            continue
        m = PAT.match(f)
        if not m:
            continue

        (
            app_L4S,
            app_legacy,
            proto_legacy,
            cc_L4S,
            cc_legacy,
            aqm,
            ecn,
            rtt,
            cap,
            trial,
            side,
            port,
        ) = m.groups()

        filepath = os.path.join(directory, f)
        stats = parse_file(
            filepath,
            skip_warmup,
            app_L4S=app_L4S,
            streaming_on_threshold_mbps=streaming_on_threshold_mbps,
        )
        if stats is None:
            continue

        # Group key: scenario (exclude trial, port)
        key = (
            app_L4S,
            app_legacy,
            proto_legacy,
            cc_L4S,
            cc_legacy,
            aqm,
            ecn,
            rtt,
            cap,
            side,
        )
        stats["port"] = int(port)
        stats["trial"] = int(trial)
        stats["app_L4S"] = app_L4S
        stats["app_legacy"] = app_legacy
        stats["proto_legacy"] = proto_legacy
        stats["cc_L4S"] = cc_L4S
        stats["cc_legacy"] = cc_legacy
        stats["aqm"] = aqm
        stats["ecn"] = ecn
        stats["rtt"] = rtt
        stats["cap"] = cap
        stats["side"] = side
        groups[key].append(stats)

    # Aggregate per scenario
    result = {}
    for key, files_stats in groups.items():
        n = len(files_stats)
        goodput_vals = [s["rcvd_rate_mbps"] for s in files_stats]
        rtt_vals = [s["rtt_ms"] for s in files_stats]
        mark_vals = [s["mark_prob"] for s in files_stats]
        loss_vals = [s["loss_prob"] for s in files_stats]

        mean_g = sum(goodput_vals) / n
        mean_r = sum(rtt_vals) / n
        mean_m = sum(mark_vals) / n
        mean_l = sum(loss_vals) / n

        std_g = (sum((x - mean_g) ** 2 for x in goodput_vals) / n) ** 0.5 if n > 1 else 0.0
        std_r = (sum((x - mean_r) ** 2 for x in rtt_vals) / n) ** 0.5 if n > 1 else 0.0
        std_m = (sum((x - mean_m) ** 2 for x in mark_vals) / n) ** 0.5 if n > 1 else 0.0
        std_l = (sum((x - mean_l) ** 2 for x in loss_vals) / n) ** 0.5 if n > 1 else 0.0

        app_L4S, app_legacy, proto_legacy, cc_L4S, cc_legacy, aqm, ecn, rtt, cap, side = key
        scenario_str = f"{app_L4S}-PRAGUE_{app_legacy}-{proto_legacy}_{cc_L4S}_{cc_legacy}_{aqm}_{ecn}_{rtt}ms_{cap}Mbps_rx_{side}"

        result[scenario_str] = {
            "scenario": scenario_str,
            "app_L4S": app_L4S,
            "app_legacy": app_legacy,
            "proto_legacy": proto_legacy,
            "cc_L4S": cc_L4S,
            "cc_legacy": cc_legacy,
            "aqm": aqm,
            "ecn": ecn,
            "rtt": rtt,
            "cap": cap,
            "side": side,
            "mean_goodput_mbps": mean_g,
            "std_goodput_mbps": std_g,
            "mean_rtt_ms": mean_r,
            "std_rtt_ms": std_r,
            "mean_mark_prob": mean_m,
            "std_mark_prob": std_m,
            "mean_loss_prob": mean_l,
            "std_loss_prob": std_l,
            "n_flows": n,
            "n_trials": len(set(s["trial"] for s in files_stats)),
        }

    return result


def build_scenario_key(app_L4S: str, app_legacy: str, proto_legacy: str,
                      cc_L4S: str, cc_legacy: str, aqm: str, ecn: str,
                      rtt: str, cap: str, side: str = "L4S") -> str:
    """Build scenario key matching run() output format."""
    return f"{app_L4S}-PRAGUE_{app_legacy}-{proto_legacy}_{cc_L4S}_{cc_legacy}_{aqm}_{ecn}_{rtt}ms_{cap}Mbps_rx_{side}"


def load_prague_receiver_stats(json_path: str) -> dict:
    """
    Load aggregated receiver stats from JSON file (from prague_receiver_stats.py -o).
    Returns dict: scenario_key -> {mean_goodput_mbps, std_goodput_mbps, mean_rtt_ms, ...}
    """
    with open(json_path) as f:
        return json.load(f)


def main():
    p = argparse.ArgumentParser(
        description="Aggregate UDP Prague receiver JSON files by scenario.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run in current directory (e.g. ~/L4S_Project/udp_prague)
  python3 prague_receiver_stats.py

  # Specify directory
  python3 prague_receiver_stats.py /path/to/json/files

  # Output to JSON file
  python3 prague_receiver_stats.py -o prague_receiver_agg.json
        """,
    )
    p.add_argument(
        "directory",
        nargs="?",
        default=".",
        help="Directory containing receiver JSON files (default: current dir)",
    )
    p.add_argument(
        "--skip-warmup",
        type=int,
        default=2,
        help="Skip first N samples per file (default: 2)",
    )
    p.add_argument(
        "--streaming-on-threshold-mbps",
        type=float,
        default=STREAMING_ON_THRESHOLD_MBPS,
        help="For streaming: keep only samples with rcvd_rate >= this (Mbps); OFF periods ~0.0006 (default: 0.1)",
    )
    p.add_argument(
        "-o", "--output",
        default="",
        help="Write aggregated stats to JSON file",
    )
    p.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress human-readable output",
    )
    args = p.parse_args()

    if not os.path.isdir(args.directory):
        print(f"Error: not a directory: {args.directory}", file=sys.stderr)
        sys.exit(1)

    result = run(
        args.directory,
        args.skip_warmup,
        args.output,
        streaming_on_threshold_mbps=args.streaming_on_threshold_mbps,
    )

    if not result:
        if not args.quiet:
            print("No matching receiver JSON files found.", file=sys.stderr)
        sys.exit(1)

    if not args.quiet:
        print("=" * 70)
        print("UDP Prague receiver stats (rcvd_rate = goodput Mbps)")
        print("=" * 70)
        for scenario, s in sorted(result.items()):
            print(f"\n{scenario}:")
            print(f"  Goodput:  {s['mean_goodput_mbps']:.3f} ± {s['std_goodput_mbps']:.3f} Mbps")
            print(f"  RTT:      {s['mean_rtt_ms']:.3f} ± {s['std_rtt_ms']:.3f} ms")
            print(f"  Mark:     {s['mean_mark_prob']:.2f} ± {s['std_mark_prob']:.2f}%")
            print(f"  Loss:     {s['mean_loss_prob']:.2f} ± {s['std_loss_prob']:.2f}%")
            print(f"  Flows:    {s['n_flows']}  Trials: {s['n_trials']}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        if not args.quiet:
            print(f"\nWrote {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
