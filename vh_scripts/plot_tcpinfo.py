#!/usr/bin/env python3
"""
Plot TCPINFO / PRAGUEINFO metrics from MGEN sender log files.
==============================================================

Parses MGEN log lines containing TCPINFO or PRAGUEINFO and plots per-flow
time series for rate/goodput, RTT, retransmissions/loss, CWND, and (for
Prague) ECN alpha.  Optionally overlays receiver-side JSON stats.

Usage:
  # Basic TCPINFO — auto-detect flow labels from destination ports
  python3 plot_tcpinfo.py tx_downlink.log

  # Prague sender log
  python3 plot_tcpinfo.py senderprague.log

  # Prague sender + receiver JSON overlay
  python3 plot_tcpinfo.py senderprague.log --receiver receiver_stats.json

  # Custom flow labels (flow_id:label)
  python3 plot_tcpinfo.py tx_downlink.log --labels 1:Streaming-1 3:Update-1

  # Save to file instead of showing interactive window
  python3 plot_tcpinfo.py tx_downlink.log -o results.png

  # Combine multiple log files (e.g. uplink + downlink)
  # Flows are namespaced per file to avoid ID collisions.
  python3 plot_tcpinfo.py tx_downlink.log tx_uplink.log

  # Filter specific flows only (matches flow ID across all files)
  python3 plot_tcpinfo.py tx_downlink.log --flows 1 2 3
"""

import argparse
import json
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

# TCPINFO line (standard MGEN TCPINFO output)
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

# PRAGUEINFO line (Prague CC sender output)
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

# ON line to extract dst port for auto-labeling.
ON_RE_LOG = re.compile(
    r"ON\s+flow>(?P<flow>\d+)\s+.*dst>[\d.]+/(?P<port>\d+)"
)
ON_RE_SCRIPT = re.compile(
    r"ON\s+(?P<flow>\d+)\s+\w+\s+DST\s+[\d.]+/(?P<port>\d+)",
    re.IGNORECASE,
)


def parse_log(filepath: str) -> tuple:
    """
    Parse an MGEN log file containing TCPINFO and/or PRAGUEINFO lines.

    Returns:
        data: dict  {flow_id: {metric: [values]}}
        flow_ports: dict  {flow_id: dst_port}
        has_prague: bool  whether any PRAGUEINFO lines were found
    """
    data = defaultdict(lambda: defaultdict(list))
    flow_ports = {}
    has_prague = False

    with open(filepath) as f:
        for line in f:
            # Try ON line first (for port mapping)
            m = ON_RE_LOG.search(line) or ON_RE_SCRIPT.search(line)
            if m:
                fid = int(m.group("flow"))
                port = int(m.group("port"))
                flow_ports[fid] = port
                continue

            # Try PRAGUEINFO first (more specific keyword)
            m = PRAGUEINFO_RE.search(line)
            if m:
                has_prague = True
                fid = int(m.group("flow"))
                d = data[fid]

                ts = m.group("time")
                t = datetime.strptime(ts, "%H:%M:%S.%f")
                d["time"].append(t)

                # Rate (Prague reports sending rate, not goodput/throughput split)
                d["goodput_mbps"].append(float(m.group("rate_avg")) / 1000.0)
                d["throughput_mbps"].append(float(m.group("rate_avg")) / 1000.0)
                d["rate_min_mbps"].append(float(m.group("rate_min")) / 1000.0)
                d["rate_max_mbps"].append(float(m.group("rate_max")) / 1000.0)

                d["rtt_avg_ms"].append(int(m.group("rtt_avg")) / 1000.0)
                d["rtt_min_ms"].append(int(m.group("rtt_min")) / 1000.0)
                d["rtt_max_ms"].append(int(m.group("rtt_max")) / 1000.0)
                d["cwnd"].append(int(m.group("cwnd")))
                d["cwnd_min"].append(int(m.group("cwnd_min")))
                d["cwnd_max"].append(int(m.group("cwnd_max")))
                d["retrans"].append(int(m.group("lost")))
                d["total_retrans"].append(int(m.group("total_lost")))
                d["samples"].append(int(m.group("samples")))

                # Prague-specific fields
                d["alpha_avg"].append(float(m.group("alpha_avg")))
                d["alpha_min"].append(float(m.group("alpha_min")))
                d["alpha_max"].append(float(m.group("alpha_max")))
                d["inflight"].append(int(m.group("inflight")))
                d["state"].append(m.group("state"))
                continue

            # Try TCPINFO line
            m = TCPINFO_RE.search(line)
            if m:
                fid = int(m.group("flow"))
                d = data[fid]

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

    return dict(data), flow_ports, has_prague


def parse_receiver_json(filepath: str) -> dict:
    """
    Parse a Prague receiver JSON stats file.

    Each line is a JSON object with fields:
      time_since_start (us), rcvd_rate (Mbps), sent_rate (Mbps),
      RTT (ms), mark_prob (%), loss_prob (%), pkt_rcvd, pkt_mark, pkt_lost

    Returns dict with lists for each metric.
    """
    data = defaultdict(list)

    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue

            t_us = int(rec.get("time_since_start", 0))
            data["time_s"].append(t_us / 1_000_000.0)
            data["rcvd_rate_mbps"].append(float(rec.get("rcvd_rate", 0)))
            data["sent_rate_mbps"].append(float(rec.get("sent_rate", 0)))
            data["rtt_ms"].append(float(rec.get("RTT", 0)))
            data["mark_prob"].append(float(rec.get("mark_prob", 0)))
            data["loss_prob"].append(float(rec.get("loss_prob", 0)))
            data["pkt_rcvd"].append(int(rec.get("pkt_rcvd", 0)))
            data["pkt_mark"].append(int(rec.get("pkt_mark", 0)))
            data["pkt_lost"].append(int(rec.get("pkt_lost", 0)))

    return dict(data)


def to_elapsed_seconds(times: list) -> list:
    """Convert datetime list to elapsed seconds from the earliest time."""
    if not times:
        return []
    t0 = times[0]
    result = []
    for t in times:
        delta = (t - t0).total_seconds()
        if delta < 0:
            delta += 86400
        result.append(delta)
    return result


# ── Multi-file merge ─────────────────────────────────────────────────

def merge_log_data(logfiles: list) -> tuple:
    """Parse and merge data from one or more log files.

    Returns:
        all_data, all_ports, multi, has_prague
    """
    multi = len(logfiles) > 1
    all_data = {}
    all_ports = {}
    has_prague = False

    for logfile in logfiles:
        print(f"Parsing {logfile} ...")
        data, ports, prague = parse_log(logfile)
        if prague:
            has_prague = True

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
            all_data.update(data)
            all_ports.update(ports)

    return all_data, all_ports, multi, has_prague


def key_flow_id(key) -> int:
    """Extract the numeric flow ID from a data key."""
    if isinstance(key, int):
        return key
    return int(str(key).rsplit(":", 1)[-1])


# ── Plotting ─────────────────────────────────────────────────────────

COLORS = [
    "#e6194b", "#3cb44b", "#4363d8", "#f58231",
    "#911eb4", "#42d4f4", "#f032e6", "#bfef45",
    "#fabed4", "#469990", "#dcbeff", "#9A6324",
]


def build_label(key, flow_ports: dict, user_labels: dict, multi: bool) -> str:
    """Build a display label for a flow."""
    fid = key_flow_id(key)

    if key in user_labels:
        return user_labels[key]
    if fid in user_labels:
        return user_labels[fid]

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
                 multi: bool, has_prague: bool, rx_data: dict = None):
    """Create a multi-panel figure.

    Base panels (always): Rate/Goodput, RTT, Retrans/Lost, CWND.
    Prague panel (if has_prague): ECN Alpha.
    Receiver overlay (if rx_data): rcvd_rate on goodput, mark_prob on alpha.
    """

    # Determine which flows to plot
    flow_keys = sorted(data.keys(), key=lambda k: (str(k)))
    if flow_filter:
        filter_set = set(flow_filter)
        flow_keys = [k for k in flow_keys if key_flow_id(k) in filter_set]

    if not flow_keys:
        print("No matching flows found in the log file(s).", file=sys.stderr)
        sys.exit(1)

    # Detect if we actually have alpha data in the selected flows
    show_alpha = has_prague and any(
        "alpha_avg" in data[k] and len(data[k]["alpha_avg"]) > 0
        for k in flow_keys
    )
    # Also show alpha panel if receiver has mark_prob data
    if rx_data and "mark_prob" in rx_data and any(v > 0 for v in rx_data["mark_prob"]):
        show_alpha = True

    num_panels = 5 if show_alpha else 4

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

    # Align receiver timestamps to sender's timeline.
    # Receiver time_s is elapsed from receiver start; sender global_t0 is
    # the first data point. We align by offsetting receiver time so that
    # the first non-trivial receiver sample lines up with the sender's
    # first data point. This is a heuristic; for exact alignment, both
    # clocks must be synchronized.
    rx_time = None
    if rx_data and "time_s" in rx_data:
        rx_t = rx_data["time_s"]
        # Find offset: first sender data point is at elapsed=0,
        # receiver's first sample is at rx_t[0] seconds from rx start.
        # We assume sender and receiver started approximately together.
        # The receiver often has an extra ~1-2s warmup before meaningful
        # data; we align the first rx sample to elapsed=0.
        if rx_t:
            rx_offset = rx_t[0]
            rx_time = [t - rx_offset for t in rx_t]

    # ── Create figure ────────────────────────────────────────────
    fig, axes = plt.subplots(num_panels, 1,
                             figsize=(14, 3 * num_panels),
                             sharex=True)
    if num_panels == 1:
        axes = [axes]

    metric_type = "PRAGUEINFO" if has_prague else "TCPINFO"
    fig.suptitle(f"{title_prefix}{metric_type} Metrics Over Time",
                 fontsize=14, fontweight="bold")

    ax_goodput = axes[0]
    ax_rtt = axes[1]
    ax_retrans = axes[2]
    ax_cwnd = axes[3]
    ax_alpha = axes[4] if show_alpha else None

    handles = []
    labels_list = []

    for i, key in enumerate(flow_keys):
        d = data[key]
        t = elapsed(d["time"])
        color = COLORS[i % len(COLORS)]
        label = build_label(key, flow_ports, user_labels, multi)

        # 1) Rate / Goodput
        rate_label = "Rate" if has_prague else "Goodput"
        h, = ax_goodput.plot(t, d["goodput_mbps"], color=color, label=label,
                             linewidth=1.2, alpha=0.85)
        if has_prague and "rate_min_mbps" in d:
            ax_goodput.fill_between(t, d["rate_min_mbps"], d["rate_max_mbps"],
                                    color=color, alpha=0.10)
        handles.append(h)
        labels_list.append(label)

        # 2) RTT (avg with min/max shading)
        ax_rtt.plot(t, d["rtt_avg_ms"], color=color, label=label,
                    linewidth=1.2, alpha=0.85)
        ax_rtt.fill_between(t, d["rtt_min_ms"], d["rtt_max_ms"],
                            color=color, alpha=0.12)

        # 3) Retransmissions / Lost (per window)
        ax_retrans.plot(t, d["retrans"], color=color, label=label,
                        linewidth=1.2, alpha=0.85)

        # 4) CWND (latest sample with min/max shading)
        ax_cwnd.plot(t, d["cwnd"], color=color, label=label,
                     linewidth=1.2, alpha=0.85)
        ax_cwnd.fill_between(t, d["cwnd_min"], d["cwnd_max"],
                             color=color, alpha=0.12)

        # 5) Alpha (Prague only)
        if ax_alpha is not None and "alpha_avg" in d and len(d["alpha_avg"]) > 0:
            ax_alpha.plot(t, d["alpha_avg"], color=color, label=label,
                          linewidth=1.2, alpha=0.85)
            ax_alpha.fill_between(t, d["alpha_min"], d["alpha_max"],
                                  color=color, alpha=0.12)

    # ── Overlay receiver data ────────────────────────────────────
    if rx_data and rx_time:
        rx_color = "#888888"
        rx_style = {"color": rx_color, "linewidth": 1.5, "alpha": 0.7,
                    "linestyle": "--"}

        # Receiver goodput overlay
        if "rcvd_rate_mbps" in rx_data:
            h, = ax_goodput.plot(rx_time, rx_data["rcvd_rate_mbps"],
                                 label="Receiver goodput", **rx_style)
            handles.append(h)
            labels_list.append("Receiver goodput")

        # Receiver RTT overlay
        if "rtt_ms" in rx_data:
            ax_rtt.plot(rx_time, rx_data["rtt_ms"],
                        label="Receiver RTT", **rx_style)

        # Receiver pkt_lost overlay
        if "pkt_lost" in rx_data:
            ax_retrans.plot(rx_time, rx_data["pkt_lost"],
                            label="Receiver pkt_lost", **rx_style)

        # Receiver mark_prob on alpha panel
        if ax_alpha is not None and "mark_prob" in rx_data:
            ax_alpha_rx = ax_alpha.twinx()
            ax_alpha_rx.plot(rx_time, rx_data["mark_prob"],
                             color="#cc6600", linewidth=1.5, alpha=0.7,
                             linestyle=":", label="Receiver mark_prob (%)")
            ax_alpha_rx.set_ylabel("Mark Probability (%)", color="#cc6600")
            ax_alpha_rx.tick_params(axis="y", labelcolor="#cc6600")
            # Add to legend manually
            from matplotlib.lines import Line2D
            rx_mark_handle = Line2D([0], [0], color="#cc6600", linewidth=1.5,
                                    linestyle=":", alpha=0.7)
            handles.append(rx_mark_handle)
            labels_list.append("Receiver mark_prob (%)")

    # ── Axis labels and formatting ───────────────────────────────
    rate_label = "Sending Rate" if has_prague else "Goodput"
    ax_goodput.set_ylabel(f"{rate_label} (Mbps)")
    ax_goodput.set_title(f"{rate_label}" +
                         (" (avg line, min/max shaded)" if has_prague else ""))
    ax_goodput.grid(True, alpha=0.3)

    ax_rtt.set_ylabel("RTT (ms)")
    ax_rtt.set_title("RTT  (avg line, min/max shaded)")
    ax_rtt.grid(True, alpha=0.3)

    loss_label = "Lost per Window" if has_prague else "Retransmissions per Window"
    ax_retrans.set_ylabel("Lost" if has_prague else "Retransmissions")
    ax_retrans.set_title(loss_label)
    ax_retrans.grid(True, alpha=0.3)

    ax_cwnd.set_ylabel("CWND (segments)")
    ax_cwnd.set_title("Congestion Window  (latest sample, min/max shaded)")
    ax_cwnd.grid(True, alpha=0.3)

    if ax_alpha is not None:
        ax_alpha.set_ylabel("Alpha (ECN fraction)")
        ax_alpha.set_title("Prague Alpha  (avg line, min/max shaded)")
        ax_alpha.grid(True, alpha=0.3)
        ax_alpha.set_xlabel("Time (seconds)")
    else:
        ax_cwnd.set_xlabel("Time (seconds)")

    # Single shared legend
    fig.legend(handles, labels_list, loc="upper center",
               bbox_to_anchor=(0.5, 0.97),
               ncol=min(len(labels_list), 4),
               fontsize=8, framealpha=0.9)

    plt.tight_layout(rect=[0, 0, 1, 0.95])

    if output:
        plt.savefig(output, dpi=150, bbox_inches="tight")
        print(f"Saved plot to {output}")
    else:
        plt.show()


# ── CLI ──────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="Plot TCPINFO / PRAGUEINFO metrics from MGEN sender logs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Standard TCPINFO
  %(prog)s tx_downlink.log
  %(prog)s tx_downlink.log --labels 1:Streaming-1 2:Streaming-2 3:Bulk-1
  %(prog)s tx_downlink.log tx_uplink.log -o combined.png

  # Prague sender log
  %(prog)s senderprague.log

  # Prague sender + receiver JSON overlay
  %(prog)s senderprague.log --receiver receiver_stats.json

  # Filter flows
  %(prog)s tx_downlink.log --flows 1 2

Notes:
  - Supports both TCPINFO and PRAGUEINFO log formats automatically.
  - PRAGUEINFO adds a 5th panel for Prague alpha (ECN marking fraction).
  - When multiple log files are given, flow IDs are prefixed with the
    filename to avoid collisions (e.g. "tx_downlink:1", "tx_uplink:1").
  - The --flows filter matches by numeric flow ID across all files.
  - Receiver JSON (--receiver) is overlaid as dashed lines on sender plots.
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
    p.add_argument("--receiver", nargs="*", default=[],
                   help="Prague receiver JSON stats file(s) to overlay. "
                        "Plotted as dashed lines on sender panels.")

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
                user_labels[fid_str] = label

    # Parse and merge all sender log files
    all_data, all_ports, multi, has_prague = merge_log_data(args.logfiles)

    if not all_data:
        print("No TCPINFO/PRAGUEINFO data found in the log file(s).",
              file=sys.stderr)
        sys.exit(1)

    data_type = "PRAGUEINFO" if has_prague else "TCPINFO"
    print(f"Found {len(all_data)} flows ({data_type}): "
          f"{sorted(all_data.keys(), key=str)}")
    for key in sorted(all_data.keys(), key=str):
        n = len(all_data[key]["time"])
        label = build_label(key, all_ports, user_labels, multi)
        print(f"  {key}: {n} samples — {label}")

    # Parse receiver JSON files (if any)
    rx_data = None
    if args.receiver:
        rx_merged = defaultdict(list)
        for rx_file in args.receiver:
            print(f"Parsing receiver: {rx_file} ...")
            rx = parse_receiver_json(rx_file)
            for k, v in rx.items():
                rx_merged[k].extend(v)
        rx_data = dict(rx_merged)
        if rx_data and "time_s" in rx_data:
            print(f"  Receiver: {len(rx_data['time_s'])} samples, "
                  f"{rx_data['time_s'][0]:.1f}s – {rx_data['time_s'][-1]:.1f}s")

    # Plot
    prefix = f"{args.title} — " if args.title else ""
    plot_metrics(all_data, all_ports, user_labels,
                 args.flows, args.output, prefix, multi,
                 has_prague, rx_data)


if __name__ == "__main__":
    main()
