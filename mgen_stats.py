#!/usr/bin/env python3
"""
Compute statistics from MGEN TCPINFO/PRAGUEINFO log files.
==========================================================

Reports average goodput and average RTT, with app-aware behavior:
  - Bulk flows (updates): average over entire duration
  - Paced flows (gamer, call): average over entire duration
  - Streaming: average only during burst periods (uses burst_ms/gap_ms from config)

For streaming, burst periods are determined from configuration (MGEN script or
--burst-ms/--gap-ms), not inferred from the data.

For one experiment (one sender, one app type): averages across all flows.
For multiple trials: reports per-trial stats and mean across trials.

Usage:
  # Single experiment
  python3 mgen_stats.py tx_downlink.log

  # Streaming: pass MGEN script to read burst/gap from config
  python3 mgen_stats.py tx_streaming.log --script streaming.mgn

  # Or specify burst/gap explicitly (ms)
  python3 mgen_stats.py tx_streaming.log --app streaming --burst-ms 2500 --gap-ms 3500

  # Multiple trials
  python3 mgen_stats.py trial1.log trial2.log trial3.log --script streaming.mgn

  # Output to JSON
  python3 mgen_stats.py tx.log -o stats.json
"""

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime

# Reuse parsing from plot_tcpinfo
TCPINFO_RE = re.compile(
    r"(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+TCPINFO\s+"
    r"flow>(?P<flow>\d+)\s+"
    r"window>(?P<window>[\d.]+)\s+"
    r"samples>(?P<samples>\d+)\s+"
    r"rtt_avg_us>(?P<rtt_avg>\d+)\s+"
    r"rtt_min_us>(?P<rtt_min>\d+)\s+"
    r"rtt_max_us>(?P<rtt_max>\d+)\s+"
    r"cwnd>(?P<cwnd>\d+)\s+"
    r"cwnd_min>(?P<cwnd_min>\d+)\s+"
    r"cwnd_max>(?P<cwnd_max>\d+)\s+"
    r"throughput_kbps>(?P<throughput>[\d.]+)\s+"
    r"goodput_kbps>(?P<goodput>[\d.]+)\s+"
    r"retrans>(?P<retrans>\d+)\s+"
    r"total_retrans>(?P<total_retrans>\d+)"
    r"(?:\s+bytes_acked>(?P<bytes_acked>\d+))?"
)

PRAGUEINFO_RE = re.compile(
    r"(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+PRAGUEINFO\s+"
    r"flow>(?P<flow>\d+)\s+"
    r"window>(?P<window>[\d.]+)\s+"
    r"samples>(?P<samples>\d+)\s+"
    r"state>(?P<state>\w+)\s+"
    r"rtt_avg_us>(?P<rtt_avg>\d+)\s+"
    r"rtt_min_us>(?P<rtt_min>\d+)\s+"
    r"rtt_max_us>(?P<rtt_max>\d+)\s+"
    r"cwnd>(?P<cwnd>\d+)\s+"
    r"cwnd_min>(?P<cwnd_min>\d+)\s+"
    r"cwnd_max>(?P<cwnd_max>\d+)\s+"
    r"rate_avg_kbps>(?P<rate_avg>[\d.]+)\s+"
    r"rate_min_kbps>(?P<rate_min>[\d.]+)\s+"
    r"rate_max_kbps>(?P<rate_max>[\d.]+)\s+"
    r"alpha_avg>(?P<alpha_avg>[\d.]+)\s+"
    r"alpha_min>(?P<alpha_min>[\d.]+)\s+"
    r"alpha_max>(?P<alpha_max>[\d.]+)\s+"
    r"inflight>(?P<inflight>\d+)\s+"
    r"sent>(?P<sent>\d+)\s+"
    r"lost>(?P<lost>\d+)\s+"
    r"total_lost>(?P<total_lost>\d+)"
)

ON_RE_LOG = re.compile(r"ON\s+flow>(?P<flow>\d+)\s+.*dst>[\d.]+/(?P<port>\d+)")
ON_RE_SCRIPT = re.compile(
    r"ON\s+(?P<flow>\d+)\s+\w+\s+DST\s+[\d.]+/(?P<port>\d+)",
    re.IGNORECASE,
)

# Port ranges for app inference (matches generate_vh.py and notebook base_port_L4S/legacy)
# L4S: 5001+, 5101+, 5201+, 5301+  |  Legacy: 6001+, 6101+, 6201+, 6301+
PORT_TO_APP = {
    (5001, 5099): "gamer",
    (5101, 5199): "call",
    (5201, 5299): "streaming",
    (5301, 5399): "updates",
    (6001, 6099): "gamer",
    (6101, 6199): "call",
    (6201, 6299): "streaming",
    (6301, 6399): "updates",
}

# Regex to parse streaming burst/gap from MGEN script comments
# e.g. "# --- Video streaming downlink x1 (TCP, ~25.0 Mbps burst, 2500ms on / 3500ms off) ---"
STREAMING_CONFIG_RE = re.compile(
    r"(\d+)\s*ms\s+on\s*/\s*(\d+)\s*ms\s+off",
    re.IGNORECASE,
)


def port_to_app(port: int) -> str:
    """Infer app type from destination port."""
    for (lo, hi), app in PORT_TO_APP.items():
        if lo <= port <= hi:
            return app
    return "unknown"


def parse_log(filepath: str) -> tuple:
    """
    Parse an MGEN log file. Returns:
      data: dict {flow_id: {"goodput_mbps": [...], "rtt_avg_ms": [...], "time": [...]}}
      flow_ports: dict {flow_id: port}
      has_prague: bool
    """
    data = defaultdict(lambda: defaultdict(list))
    flow_ports = {}
    has_prague = False

    with open(filepath) as f:
        for line in f:
            m = ON_RE_LOG.search(line) or ON_RE_SCRIPT.search(line)
            if m:
                fid = int(m.group("flow"))
                flow_ports[fid] = int(m.group("port"))
                continue

            m = PRAGUEINFO_RE.search(line)
            if m:
                has_prague = True
                fid = int(m.group("flow"))
                d = data[fid]
                ts = m.group("time")
                t = datetime.strptime(ts, "%H:%M:%S.%f")
                d["time"].append(t)
                d["goodput_mbps"].append(float(m.group("rate_avg")) / 1000.0)
                d["rtt_avg_ms"].append(int(m.group("rtt_avg")) / 1000.0)
                d["samples"].append(int(m.group("samples")))
                sent = int(m.group("sent"))
                lost = int(m.group("lost"))
                total = sent + lost
                d["loss_pct"].append(100.0 * lost / total if total > 0 else 0.0)
                continue

            m = TCPINFO_RE.search(line)
            if m:
                fid = int(m.group("flow"))
                d = data[fid]
                ts = m.group("time")
                t = datetime.strptime(ts, "%H:%M:%S.%f")
                d["time"].append(t)
                d["goodput_mbps"].append(float(m.group("goodput")) / 1000.0)
                d["rtt_avg_ms"].append(int(m.group("rtt_avg")) / 1000.0)
                samples = int(m.group("samples"))
                d["samples"].append(samples)
                # TCP: use retrans as loss proxy (retrans/samples ≈ loss rate)
                retrans = int(m.group("retrans"))
                d["loss_pct"].append(100.0 * retrans / samples if samples > 0 else 0.0)

    return dict(data), flow_ports, has_prague


def parse_streaming_config_from_script(script_path: str) -> tuple:
    """
    Parse burst_ms and gap_ms from an MGEN streaming script.
    Returns (burst_ms, gap_ms) or (None, None) if not found.
    """
    if not os.path.exists(script_path):
        return None, None
    with open(script_path) as f:
        for line in f:
            m = STREAMING_CONFIG_RE.search(line)
            if m:
                return int(m.group(1)), int(m.group(2))
    return None, None


def infer_app_type(flow_ports: dict) -> str:
    """Infer app type from the majority of flow ports."""
    ports = list(flow_ports.values())
    if not ports:
        return "unknown"
    apps = [port_to_app(p) for p in ports]
    # majority vote
    return Counter(apps).most_common(1)[0][0]


def compute_trial_stats(
    data: dict,
    flow_ports: dict,
    app: str,
    streaming_config: tuple,
) -> dict:
    """
    Compute average goodput and RTT for one trial (one log file).

    streaming_config: (burst_ms, gap_ms) or (None, None).
    For streaming with config: only include samples whose timestamp falls within
    a burst period (based on cycle = burst_ms + gap_ms).
    For gamer, call, updates: include all windows.
    """
    burst_ms, gap_ms = streaming_config if streaming_config else (None, None)
    per_flow = {}  # fid -> {avg_goodput_mbps, avg_rtt_ms, n_windows}
    inferred_app = infer_app_type(flow_ports)

    # Find t0 = earliest timestamp across all flows (experiment start)
    t0 = None
    for d in data.values():
        for t in d.get("time", []):
            if t0 is None or t < t0:
                t0 = t
    if t0 is None:
        t0 = datetime.min

    cycle_s = (burst_ms + gap_ms) / 1000.0 if (burst_ms and gap_ms is not None) else None
    burst_s = burst_ms / 1000.0 if burst_ms else None

    def in_burst_period(t: datetime) -> bool:
        """True if timestamp t falls within a configured burst period."""
        if cycle_s is None or burst_s is None:
            return True  # No config: include all (non-streaming or no streaming config)
        t_sec = (t - t0).total_seconds()
        if t_sec < 0:
            return False
        return (t_sec % cycle_s) < burst_s

    for fid, d in data.items():
        if not d.get("goodput_mbps"):
            continue

        port = flow_ports.get(fid)
        flow_app = port_to_app(port) if port else "unknown"

        # When --app is specified: trust user and include all flows.
        # When --app is auto: only include flows matching inferred app (exclude mixed apps).
        if app == "auto" and flow_app != inferred_app:
            continue

        times = d.get("time", [])
        loss_vals = d.get("loss_pct", [])
        flow_goodput = []
        flow_rtt = []
        flow_loss = []

        for i, g in enumerate(d["goodput_mbps"]):
            # For streaming with config: only include samples in burst periods
            if flow_app == "streaming" and burst_ms is not None and gap_ms is not None:
                t = times[i] if i < len(times) else t0
                if not in_burst_period(t):
                    continue
            flow_goodput.append(g)
            flow_rtt.append(d["rtt_avg_ms"][i])
            flow_loss.append(loss_vals[i] if i < len(loss_vals) else 0.0)

        if flow_goodput:
            avg_loss = sum(flow_loss) / len(flow_loss) if flow_loss else 0.0
            per_flow[fid] = {
                "avg_goodput_mbps": sum(flow_goodput) / len(flow_goodput),
                "avg_rtt_ms": sum(flow_rtt) / len(flow_rtt),
                "avg_loss_pct": avg_loss,
                "n_windows": len(flow_goodput),
            }

    if not per_flow:
        return {
            "avg_goodput_mbps": 0.0,
            "avg_rtt_ms": 0.0,
            "avg_loss_pct": 0.0,
            "aggregate_goodput_mbps": 0.0,
            "n_windows": 0,
            "n_flows": 0,
            "per_flow": {},
        }

    # Per-flow average (mean of per-flow averages)
    mean_goodput = sum(p["avg_goodput_mbps"] for p in per_flow.values()) / len(per_flow)
    mean_rtt = sum(p["avg_rtt_ms"] for p in per_flow.values()) / len(per_flow)
    mean_loss = sum(p["avg_loss_pct"] for p in per_flow.values()) / len(per_flow)

    # Aggregate: total throughput = sum of per-flow goodput
    aggregate_goodput = sum(p["avg_goodput_mbps"] for p in per_flow.values())

    return {
        "avg_goodput_mbps": mean_goodput,
        "avg_rtt_ms": mean_rtt,
        "avg_loss_pct": mean_loss,
        "aggregate_goodput_mbps": aggregate_goodput,
        "n_windows": sum(p["n_windows"] for p in per_flow.values()),
        "n_flows": len(per_flow),
        "per_flow": per_flow,
    }


def run_stats(
    log_files: list,
    app: str = "auto",
    streaming_config: tuple = None,
) -> dict:
    """
    Programmatic API: compute stats from log files, return result dict.
    Use from notebooks or other Python code.

    Args:
        log_files: List of paths to MGEN log files (one per trial).
        app: App type (gamer, call, streaming, updates, auto).
        streaming_config: (burst_ms, gap_ms) for streaming, or None for defaults.

    Returns:
        Result dict with trials, across_trials (if multiple files), etc.
    """
    if not log_files:
        return {"trials": [], "app_type": app or "unknown"}

    app_filter = None if app == "auto" else app
    burst_ms, gap_ms = streaming_config if streaming_config else (None, None)
    if burst_ms is None:
        burst_ms = 2500
    if gap_ms is None:
        gap_ms = 3500
    streaming_config = (burst_ms, gap_ms) if (burst_ms and gap_ms) else (None, None)

    trial_stats = []
    for logfile in log_files:
        if not os.path.exists(logfile):
            trial_stats.append({
                "file": logfile,
                "avg_goodput_mbps": 0.0,
                "avg_rtt_ms": 0.0,
                "avg_loss_pct": 0.0,
                "aggregate_goodput_mbps": 0.0,
                "n_windows": 0,
                "n_flows": 0,
                "per_flow": {},
            })
            continue
        data, flow_ports, _ = parse_log(logfile)
        if not data:
            trial_stats.append({
                "file": logfile,
                "avg_goodput_mbps": 0.0,
                "avg_rtt_ms": 0.0,
                "avg_loss_pct": 0.0,
                "aggregate_goodput_mbps": 0.0,
                "n_windows": 0,
                "n_flows": 0,
                "per_flow": {},
            })
            continue
        stats = compute_trial_stats(data, flow_ports, app=app_filter, streaming_config=streaming_config)
        stats["file"] = logfile
        stats["inferred_app"] = infer_app_type(flow_ports)
        trial_stats.append(stats)

    result = {
        "trials": trial_stats,
        "app_type": app_filter or (trial_stats[0]["inferred_app"] if trial_stats else "unknown"),
    }
    if streaming_config and streaming_config[0]:
        result["streaming_config"] = {"burst_ms": streaming_config[0], "gap_ms": streaming_config[1]}

    if len(trial_stats) > 1:
        valid = [t for t in trial_stats if t["n_windows"] > 0]
        if valid:
            mean_g = sum(t["avg_goodput_mbps"] for t in valid) / len(valid)
            mean_r = sum(t["avg_rtt_ms"] for t in valid) / len(valid)
            mean_l = sum(t.get("avg_loss_pct", 0) for t in valid) / len(valid)
            mean_agg = sum(t.get("aggregate_goodput_mbps", 0) for t in valid) / len(valid)
            std_g = (sum((t["avg_goodput_mbps"] - mean_g) ** 2 for t in valid) / len(valid)) ** 0.5 if len(valid) > 1 else 0.0
            std_r = (sum((t["avg_rtt_ms"] - mean_r) ** 2 for t in valid) / len(valid)) ** 0.5 if len(valid) > 1 else 0.0
            std_l = (sum((t.get("avg_loss_pct", 0) - mean_l) ** 2 for t in valid) / len(valid)) ** 0.5 if len(valid) > 1 else 0.0
            std_agg = (sum((t.get("aggregate_goodput_mbps", 0) - mean_agg) ** 2 for t in valid) / len(valid)) ** 0.5 if len(valid) > 1 else 0.0
            result["across_trials"] = {
                "mean_goodput_mbps": mean_g,
                "mean_rtt_ms": mean_r,
                "mean_loss_pct": mean_l,
                "mean_aggregate_goodput_mbps": mean_agg,
                "std_goodput_mbps": std_g,
                "std_rtt_ms": std_r,
                "std_loss_pct": std_l,
                "std_aggregate_goodput_mbps": std_agg,
                "n_trials": len(valid),
            }
    return result


def main():
    p = argparse.ArgumentParser(
        description="Compute average goodput and RTT from MGEN TCPINFO/PRAGUEINFO logs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single experiment
  %(prog)s tx_downlink.log

  # Specify app type (gamer, call, streaming, updates)
  %(prog)s tx_downlink.log --app streaming

  # Multiple trials (reports per-trial + mean across trials)
  %(prog)s trial1.log trial2.log trial3.log

  # Streaming: pass MGEN script to read burst/gap from config
  %(prog)s tx_streaming.log --script streaming.mgn

  # Or specify burst/gap explicitly
  %(prog)s tx_streaming.log --app streaming --burst-ms 2500 --gap-ms 3500

  # Output to JSON
  %(prog)s tx.log -o stats.json
        """,
    )
    p.add_argument(
        "logfiles",
        nargs="+",
        help="MGEN log file(s). One file = one trial.",
    )
    p.add_argument(
        "--app",
        choices=["gamer", "call", "streaming", "updates", "auto"],
        default="auto",
        help="App type for filtering. 'auto' infers from port (default).",
    )
    p.add_argument(
        "--script",
        metavar=".mgn",
        help="MGEN script path. For streaming, burst_ms and gap_ms are parsed "
             "from script comments (e.g. '2500ms on / 3500ms off').",
    )
    p.add_argument(
        "--burst-ms",
        type=int,
        default=None,
        metavar="ms",
        help="Streaming burst duration (ms). Overrides --script. Default: 2500.",
    )
    p.add_argument(
        "--gap-ms",
        type=int,
        default=None,
        metavar="ms",
        help="Streaming gap duration (ms). Overrides --script. Default: 3500.",
    )
    p.add_argument(
        "-o", "--output",
        default="",
        help="Write JSON output to file.",
    )
    p.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress human-readable output; only write JSON if -o given.",
    )
    args = p.parse_args()

    app_filter = None if args.app == "auto" else args.app

    # Resolve streaming config: --burst-ms/--gap-ms override --script
    burst_ms = args.burst_ms
    gap_ms = args.gap_ms
    if burst_ms is None or gap_ms is None:
        if args.script:
            parsed_burst, parsed_gap = parse_streaming_config_from_script(args.script)
            if burst_ms is None:
                burst_ms = parsed_burst
            if gap_ms is None:
                gap_ms = parsed_gap
        # Defaults from generate_vh.py
        if burst_ms is None:
            burst_ms = 2500
        if gap_ms is None:
            gap_ms = 3500
    streaming_config = (burst_ms, gap_ms) if (burst_ms and gap_ms) else (None, None)
    if not args.quiet and streaming_config[0] is not None and args.app in ("streaming", "auto"):
        src = "script" if args.script and args.burst_ms is None else "CLI/defaults"
        print(f"Streaming config: burst={streaming_config[0]}ms, gap={streaming_config[1]}ms ({src})")

    trial_stats = []

    for logfile in args.logfiles:
        if not os.path.exists(logfile):
            print(f"Error: file not found: {logfile}", file=sys.stderr)
            sys.exit(1)

        data, flow_ports, _ = parse_log(logfile)
        if not data:
            print(f"Warning: no TCPINFO/PRAGUEINFO data in {logfile}", file=sys.stderr)
            trial_stats.append({
                "file": logfile,
                "avg_goodput_mbps": 0.0,
                "avg_rtt_ms": 0.0,
                "aggregate_goodput_mbps": 0.0,
                "n_windows": 0,
                "n_flows": 0,
                "per_flow": {},
            })
            continue

        inferred = infer_app_type(flow_ports)
        if not args.quiet:
            print(f"Parsed {logfile}: {len(data)} flows, inferred app={inferred}")

        stats = compute_trial_stats(
            data, flow_ports,
            app=app_filter,
            streaming_config=streaming_config,
        )
        stats["file"] = logfile
        stats["inferred_app"] = inferred
        trial_stats.append(stats)

    # Build result
    result = {
        "trials": trial_stats,
        "app_type": app_filter or (trial_stats[0]["inferred_app"] if trial_stats else "unknown"),
    }
    if streaming_config[0] is not None:
        result["streaming_config"] = {"burst_ms": streaming_config[0], "gap_ms": streaming_config[1]}

    if len(trial_stats) > 1:
        valid = [t for t in trial_stats if t["n_windows"] > 0]
        if valid:
            mean_g = sum(t["avg_goodput_mbps"] for t in valid) / len(valid)
            mean_r = sum(t["avg_rtt_ms"] for t in valid) / len(valid)
            mean_agg = sum(t.get("aggregate_goodput_mbps", 0) for t in valid) / len(valid)
            std_g = (
                (sum((t["avg_goodput_mbps"] - mean_g) ** 2 for t in valid) / len(valid)) ** 0.5
                if len(valid) > 1 else 0.0
            )
            std_r = (
                (sum((t["avg_rtt_ms"] - mean_r) ** 2 for t in valid) / len(valid)) ** 0.5
                if len(valid) > 1 else 0.0
            )
            std_agg = (
                (sum((t.get("aggregate_goodput_mbps", 0) - mean_agg) ** 2 for t in valid) / len(valid)) ** 0.5
                if len(valid) > 1 else 0.0
            )
            result["across_trials"] = {
                "mean_goodput_mbps": mean_g,
                "mean_rtt_ms": mean_r,
                "mean_aggregate_goodput_mbps": mean_agg,
                "std_goodput_mbps": std_g,
                "std_rtt_ms": std_r,
                "std_aggregate_goodput_mbps": std_agg,
                "n_trials": len(valid),
            }

    # Human-readable output
    if not args.quiet:
        print()
        print("=" * 60)
        print("Per-trial statistics")
        print("=" * 60)
        for t in trial_stats:
            print(f"  {os.path.basename(t['file'])}:")
            print(f"    per-flow avg goodput:  {t['avg_goodput_mbps']:.3f} Mbps")
            print(f"    aggregate goodput:    {t.get('aggregate_goodput_mbps', 0):.3f} Mbps")
            print(f"    avg_rtt_ms:            {t['avg_rtt_ms']:.3f}")
            print(f"    avg_loss_pct:          {t.get('avg_loss_pct', 0):.3f}%")
            print(f"    n_windows:             {t['n_windows']}")
            print(f"    n_flows:               {t['n_flows']}")
            if t.get("per_flow"):
                for fid, pf in sorted(t["per_flow"].items()):
                    print(f"      flow {fid}: {pf['avg_goodput_mbps']:.3f} Mbps, {pf['avg_rtt_ms']:.3f} ms RTT, {pf['avg_loss_pct']:.3f}% loss")
            if t.get("inferred_app"):
                print(f"    inferred_app:          {t['inferred_app']}")
            print()

        if "across_trials" in result:
            at = result["across_trials"]
            print("=" * 60)
            print("Across trials (mean ± std)")
            print("=" * 60)
            print(f"  per-flow avg goodput:  {at['mean_goodput_mbps']:.3f} ± {at['std_goodput_mbps']:.3f} Mbps")
            print(f"  aggregate goodput:     {at['mean_aggregate_goodput_mbps']:.3f} ± {at['std_aggregate_goodput_mbps']:.3f} Mbps")
            print(f"  mean_rtt_ms:           {at['mean_rtt_ms']:.3f} ± {at['std_rtt_ms']:.3f}")
            print(f"  mean_loss_pct:         {at.get('mean_loss_pct', 0):.3f} ± {at.get('std_loss_pct', 0):.3f}%")
            print(f"  n_trials:              {at['n_trials']}")
            print()

    if args.output:
        # Remove non-JSON-serializable items for clean output
        out = {k: v for k, v in result.items() if k != "trials" or True}
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        if not args.quiet:
            print(f"Wrote {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
