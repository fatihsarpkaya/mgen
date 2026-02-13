#!/usr/bin/env python3
"""
Plot TCPINFO metrics from MGEN sender log files.
=================================================

Parses MGEN log lines containing TCPINFO and plots per-flow time series
for goodput, RTT, retransmissions, and CWND.

Usage:
  # Basic — auto-detect flow labels from destination ports
  python3 plot_tcpinfo.py tx_downlink.log

  # Custom flow labels (flow_id:label)
  python3 plot_tcpinfo.py tx_downlink.log --labels 1:Streaming-1 2:Streaming-2 \\
      3:Update-1 4:Update-2 5:Update-3 6:Update-4

  # Save to file instead of showing interactive window
  python3 plot_tcpinfo.py tx_downlink.log -o results.png

  # Combine multiple log files (e.g. uplink + downlink)
  # Flows are namespaced per file to avoid ID collisions.
  python3 plot_tcpinfo.py tx_downlink.log tx_uplink.log

  # Filter specific flows only (matches flow ID across all files)
  python3 plot_tcpinfo.py tx_downlink.log --flows 1 2 3
"""

import argparse
import os
import re
import sys
from collections import defaultdict

import matplotlib.pyplot as plt
from datetime import datetime


# ── Default port-range to label mapping ──────────────────────────────
# Matches the default ports from generate_vh.py
PORT_LABELS = {
    (5001, 5099): "Gamer",
    (5101, 5199): "Video Call",
    (5201, 5299): "Streaming",
    (5301, 5399): "Update",
}


def port_to_label(port: int) -> str:
    """Map a destination port to a human-readable application label."""
    for (lo, hi), label in PORT_LABELS.items():
        if lo <= port <= hi:
            return label
    return f"port-{port}"


# ── Log parsing ──────────────────────────────────────────────────────

# Example TCPINFO line:
# 19:39:47.862600 TCPINFO flow>5 window>1.000 samples>4067 rtt_avg_us>11158 ...
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
)

# ON line to extract dst port for auto-labeling.
# Matches both MGEN log format and script format:
#   Log:    19:27:32.215099 ON flow>1 srcPort>44973 dst>10.0.5.100/5001 ...
#   Script: 0.000   ON  1 TCP DST 10.0.5.100/5001 PERIODIC [...]
ON_RE_LOG = re.compile(
    r"ON\s+flow>(?P<flow>\d+)\s+.*dst>[\d.]+/(?P<port>\d+)"
)
ON_RE_SCRIPT = re.compile(
    r"ON\s+(?P<flow>\d+)\s+\w+\s+DST\s+[\d.]+/(?P<port>\d+)",
    re.IGNORECASE,
)


def parse_log(filepath: str) -> tuple:
    """
    Parse an MGEN log file.

    Returns:
        data: dict  {flow_id: {metric: [values]}}
        flow_ports: dict  {flow_id: dst_port}  (from ON lines)
    """
    data = defaultdict(lambda: defaultdict(list))
    flow_ports = {}

    with open(filepath) as f:
        for line in f:
            # Try ON line first (for port mapping) — try both formats
            m = ON_RE_LOG.search(line) or ON_RE_SCRIPT.search(line)
            if m:
                fid = int(m.group("flow"))
                port = int(m.group("port"))
                flow_ports[fid] = port
                continue

            # Try TCPINFO line
            m = TCPINFO_RE.search(line)
            if m:
                fid = int(m.group("flow"))
                d = data[fid]

                # Parse timestamp as seconds-since-midnight
                ts = m.group("time")
                t = datetime.strptime(ts, "%H:%M:%S.%f")
                d["time"].append(t)

                d["goodput_mbps"].append(float(m.group("goodput")) / 1000.0)
                d["throughput_mbps"].append(float(m.group("throughput")) / 1000.0)
                d["rtt_avg_ms"].append(int(m.group("rtt_avg")) / 1000.0)
                d["rtt_min_ms"].append(int(m.group("rtt_min")) / 1000.0)
                d["rtt_max_ms"].append(int(m.group("rtt_max")) / 1000.0)
                d["cwnd"].append(int(m.group("cwnd")))
                d["cwnd_min"].append(int(m.group("cwnd_min")))
                d["cwnd_max"].append(int(m.group("cwnd_max")))
                d["retrans"].append(int(m.group("retrans")))
                d["total_retrans"].append(int(m.group("total_retrans")))
                d["samples"].append(int(m.group("samples")))

    return dict(data), flow_ports


def to_elapsed_seconds(times: list) -> list:
    """Convert datetime list to elapsed seconds from the earliest time."""
    if not times:
        return []
    t0 = times[0]
    result = []
    for t in times:
        delta = (t - t0).total_seconds()
        # Handle midnight wrap-around
        if delta < 0:
            delta += 86400
        result.append(delta)
    return result


# ── Multi-file merge ─────────────────────────────────────────────────

def merge_log_data(logfiles: list) -> tuple:
    """Parse and merge data from one or more log files.

    When multiple files are given, flow keys are namespaced as
    "filename:N" to avoid collisions (e.g. both files having flow>1).
    When a single file is given, keys stay as plain integers for
    backward compatibility with --flows and --labels.

    Returns:
        all_data: dict  {key: {metric: [values]}}
        all_ports: dict  {key: dst_port}
        multi: bool  whether multiple files were merged
    """
    multi = len(logfiles) > 1
    all_data = {}
    all_ports = {}

    for logfile in logfiles:
        print(f"Parsing {logfile} ...")
        data, ports = parse_log(logfile)

        if multi:
            tag = os.path.splitext(os.path.basename(logfile))[0]
            for fid, d in data.items():
                key = f"{tag}:{fid}"
                if key in all_data:
                    print(f"  WARNING: duplicate key '{key}', skipping",
                          file=sys.stderr)
                    continue
                all_data[key] = d
            for fid, port in ports.items():
                all_ports[f"{tag}:{fid}"] = port
        else:
            # Single file: use plain int keys (backward compatible)
            all_data.update(data)
            all_ports.update(ports)

    return all_data, all_ports, multi


def key_flow_id(key) -> int:
    """Extract the numeric flow ID from a data key.

    Works for both plain int keys (single file) and
    "tag:N" string keys (multi-file).
    """
    if isinstance(key, int):
        return key
    # "tx_downlink:3" -> 3
    return int(str(key).rsplit(":", 1)[-1])


# ── Plotting ─────────────────────────────────────────────────────────

# Distinct colors for up to ~12 flows
COLORS = [
    "#e6194b", "#3cb44b", "#4363d8", "#f58231",
    "#911eb4", "#42d4f4", "#f032e6", "#bfef45",
    "#fabed4", "#469990", "#dcbeff", "#9A6324",
]


def build_label(key, flow_ports: dict, user_labels: dict, multi: bool) -> str:
    """Build a display label for a flow.

    For single-file mode, key is an int (e.g. 3).
    For multi-file mode, key is a string (e.g. "tx_downlink:3").
    """
    fid = key_flow_id(key)

    # User-supplied labels: match by key or by flow ID
    if key in user_labels:
        return user_labels[key]
    if fid in user_labels:
        return user_labels[fid]

    # Auto-label from port
    port = flow_ports.get(key)
    if port is None and isinstance(key, int):
        port = flow_ports.get(key)

    if multi:
        tag = str(key).rsplit(":", 1)[0] if ":" in str(key) else ""
        if port:
            app = port_to_label(port)
            return f"[{tag}] {app} (flow {fid})"
        return f"[{tag}] Flow {fid}"
    else:
        if port:
            app = port_to_label(port)
            return f"{app} (flow {fid})"
        return f"Flow {fid}"


def plot_metrics(data: dict, flow_ports: dict, user_labels: dict,
                 flow_filter: list, output: str, title_prefix: str,
                 multi: bool):
    """Create a 4-panel figure with goodput, RTT, retrans, and CWND."""

    # Determine which flows to plot
    flow_keys = sorted(data.keys(), key=lambda k: (str(k)))
    if flow_filter:
        # --flows matches on the numeric flow ID part
        filter_set = set(flow_filter)
        flow_keys = [k for k in flow_keys if key_flow_id(k) in filter_set]

    if not flow_keys:
        print("No matching flows found in the log file(s).", file=sys.stderr)
        sys.exit(1)

    # Find global t0 across all flows for consistent x-axis
    all_times = []
    for key in flow_keys:
        all_times.extend(data[key]["time"])
    global_t0 = min(all_times) if all_times else datetime.now()

    def elapsed(times):
        result = []
        for t in times:
            delta = (t - global_t0).total_seconds()
            if delta < 0:
                delta += 86400
            result.append(delta)
        return result

    # ── Create figure ────────────────────────────────────────────
    fig, axes = plt.subplots(4, 1, figsize=(14, 12), sharex=True)
    fig.suptitle(f"{title_prefix}TCPINFO Metrics Over Time",
                 fontsize=14, fontweight="bold")

    ax_goodput, ax_rtt, ax_retrans, ax_cwnd = axes

    handles = []
    labels = []

    for i, key in enumerate(flow_keys):
        d = data[key]
        t = elapsed(d["time"])
        color = COLORS[i % len(COLORS)]
        label = build_label(key, flow_ports, user_labels, multi)

        # 1) Goodput
        h, = ax_goodput.plot(t, d["goodput_mbps"], color=color, label=label,
                             linewidth=1.2, alpha=0.85)
        handles.append(h)
        labels.append(label)

        # 2) RTT (avg with min/max shading)
        ax_rtt.plot(t, d["rtt_avg_ms"], color=color, label=label,
                    linewidth=1.2, alpha=0.85)
        ax_rtt.fill_between(t, d["rtt_min_ms"], d["rtt_max_ms"],
                            color=color, alpha=0.12)

        # 3) Retransmissions (per window)
        ax_retrans.plot(t, d["retrans"], color=color, label=label,
                        linewidth=1.2, alpha=0.85)

        # 4) CWND (latest sample with min/max shading)
        ax_cwnd.plot(t, d["cwnd"], color=color, label=label,
                     linewidth=1.2, alpha=0.85)
        ax_cwnd.fill_between(t, d["cwnd_min"], d["cwnd_max"],
                             color=color, alpha=0.12)

    # ── Axis labels and formatting ───────────────────────────────
    ax_goodput.set_ylabel("Goodput (Mbps)")
    ax_goodput.set_title("Goodput")
    ax_goodput.grid(True, alpha=0.3)

    ax_rtt.set_ylabel("RTT (ms)")
    ax_rtt.set_title("RTT  (avg line, min/max shaded)")
    ax_rtt.grid(True, alpha=0.3)

    ax_retrans.set_ylabel("Retransmissions")
    ax_retrans.set_title("Retransmissions per Window")
    ax_retrans.grid(True, alpha=0.3)

    ax_cwnd.set_ylabel("CWND (segments)")
    ax_cwnd.set_title("Congestion Window  (latest sample, min/max shaded)")
    ax_cwnd.set_xlabel("Time (seconds)")
    ax_cwnd.grid(True, alpha=0.3)

    # Single shared legend below the title, above the first subplot
    fig.legend(handles, labels, loc="upper center",
               bbox_to_anchor=(0.5, 0.97), ncol=min(len(labels), 4),
               fontsize=8, framealpha=0.9)

    plt.tight_layout(rect=[0, 0, 1, 0.95])  # leave room for legend

    if output:
        plt.savefig(output, dpi=150, bbox_inches="tight")
        print(f"Saved plot to {output}")
    else:
        plt.show()


# ── CLI ──────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="Plot TCPINFO metrics from MGEN sender log files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s tx_downlink.log
  %(prog)s tx_downlink.log --labels 1:Streaming-1 2:Streaming-2 3:Bulk-1
  %(prog)s tx_downlink.log tx_uplink.log -o combined.png
  %(prog)s tx_downlink.log --flows 1 2

Notes:
  When multiple log files are given, flow IDs are prefixed with the
  filename to avoid collisions (e.g. "tx_downlink:1", "tx_uplink:1").
  The --flows filter still matches by numeric flow ID across all files.
        """)

    p.add_argument("logfiles", nargs="+", help="MGEN log file(s) to parse")
    p.add_argument("-o", "--output", default="",
                   help="Save plot to file (e.g. results.png). "
                        "If omitted, shows interactive window.")
    p.add_argument("--labels", nargs="*", default=[],
                   help="Custom flow labels as flow_id:label pairs "
                        "(e.g. 1:Streaming 3:Bulk)")
    p.add_argument("--flows", nargs="*", type=int, default=[],
                   help="Only plot these flow IDs (default: all). "
                        "Matches by numeric ID across all files.")
    p.add_argument("--title", default="",
                   help="Optional title prefix for the plot")

    return p.parse_args()


def main():
    args = parse_args()

    # Parse user labels
    user_labels = {}
    for item in args.labels:
        if ":" in item:
            fid_str, label = item.split(":", 1)
            try:
                user_labels[int(fid_str)] = label
            except ValueError:
                # Could be "tag:fid:label" for multi-file
                user_labels[fid_str] = label

    # Parse and merge all log files
    all_data, all_ports, multi = merge_log_data(args.logfiles)

    if not all_data:
        print("No TCPINFO data found in the log file(s).", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(all_data)} flows: {sorted(all_data.keys(), key=str)}")
    for key in sorted(all_data.keys(), key=str):
        n = len(all_data[key]["time"])
        label = build_label(key, all_ports, user_labels, multi)
        print(f"  {key}: {n} samples — {label}")

    # Plot
    prefix = f"{args.title} — " if args.title else ""
    plot_metrics(all_data, all_ports, user_labels,
                 args.flows, args.output, prefix, multi)


if __name__ == "__main__":
    main()
