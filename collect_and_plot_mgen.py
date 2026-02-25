#!/usr/bin/env python3
"""
Collect MGEN stats and plot bar charts — run from mgen/ directory.

For UDP Prague flows, use receiver-side goodput (rcvd_rate) when available.
Upload prague_receiver_stats.py to the receiver node, run it there, download
the output JSON, then pass it here with --prague-receiver-json.

Usage:
  python collect_and_plot_mgen.py
  python collect_and_plot_mgen.py --prague-receiver-json prague_receiver_agg.json
"""
import argparse
import os
import re
from collections import defaultdict
import matplotlib.pyplot as plt
import numpy as np
import sys

# Ensure we can import mgen_stats (run from mgen/ or add to path)
_root = os.getcwd()
for _d in [_root, os.path.dirname(_root), os.path.join(_root, "mgen")]:
    if _d and os.path.exists(os.path.join(_d, "mgen_stats.py")):
        sys.path.insert(0, _d)
        break
from mgen_stats import run_stats

# Optional: prague_receiver_stats for receiver-side goodput
try:
    from prague_receiver_stats import build_scenario_key, load_prague_receiver_stats
except ImportError:
    build_scenario_key = load_prague_receiver_stats = None

# Parse args (--prague-receiver-json for receiver-side goodput)
_parser = argparse.ArgumentParser(description="Collect MGEN stats and plot bar charts")
_parser.add_argument(
    "--prague-receiver-json",
    default="",
    help="Path to prague_receiver_agg.json from prague_receiver_stats.py (run on receiver node)",
)
_args = _parser.parse_args()
PRAGUE_RECEIVER_JSON = _args.prague_receiver_json

# Try multiple locations for mgen_results
RESULTS_DIR = "mgen_results"
for cand in ["mgen_results", "mgen/mgen_results", "vh_scripts/mgen_results",
             os.path.join(os.getcwd(), "mgen_results"), os.path.join(os.getcwd(), "mgen", "mgen_results")]:
    if cand and os.path.exists(cand):
        RESULTS_DIR = cand
        break

# ============ PLOT CONFIGURATION ============
# "by_app"    : Fix network, compare app performances (x-axis = apps)
# "by_network": Fix app, compare network performances (x-axis = network settings)
# "all"       : Show all (app, network) combinations
PLOT_MODE = "by_app"  # or "by_network" or "all"

# When PLOT_MODE == "by_app": filter to this network. Must match network_str exactly.
# Format: {aqm}_{ecn}ms_{rtt}ms_{cap}Mbps (e.g. "DualPI2_5ms_10ms_100Mbps")
# If no data: run once and check "Available networks:" in output, then copy-paste here.
FILTER_NETWORK = "DualPI2_5ms_10ms_100Mbps"

# When PLOT_MODE == "by_network": filter to this app.
# Use "updates" to filter by L4S app, or "updates/streaming" for exact (app_L4S, app_legacy) pair
FILTER_APP = "updates"
# =============================================

print(f"Scanning: {os.path.abspath(RESULTS_DIR)}")
if not os.path.exists(RESULTS_DIR):
    print(f"ERROR: No mgen_results found. CWD: {os.getcwd()}")
    sys.exit(1)

# Load Prague receiver stats if provided (receiver-side goodput for Prague flows)
prague_receiver_stats = {}
if PRAGUE_RECEIVER_JSON and os.path.isfile(PRAGUE_RECEIVER_JSON) and load_prague_receiver_stats:
    try:
        prague_receiver_stats = load_prague_receiver_stats(PRAGUE_RECEIVER_JSON)
        print(f"Loaded Prague receiver stats from {PRAGUE_RECEIVER_JSON} ({len(prague_receiver_stats)} scenarios)")
    except Exception as e:
        print(f"Warning: could not load {PRAGUE_RECEIVER_JSON}: {e}")

# Regex: use (\d+) for digit matching (single backslash in raw string)
PAT = re.compile(
    r"^([^-]+)-([^_]+)_([^-]+)-([^_]+)_([^_]+)_([^_]+)_([^_]+)_([^_]+)_(\d+)ms_(\d+)Mbps_t(\d+)_(tx_L4S|tx_legacy)\.log$"
)

parsed = []
for f in os.listdir(RESULTS_DIR):
    if not f.endswith(".log") or "_tx_" not in f:
        continue
    m = PAT.match(f)
    if not m:
        print(f"  No match: {f}")
        continue
    app_L4S, proto_L4S, app_legacy, proto_legacy, cc_L4S, cc_legacy, aqm, ecn, rtt, cap, trial, suffix = m.groups()
    parsed.append({
        "file": os.path.join(RESULTS_DIR, f),
        "app_L4S": app_L4S, "app_legacy": app_legacy, "proto_L4S": proto_L4S, "proto_legacy": proto_legacy,
        "cc_L4S": cc_L4S, "cc_legacy": cc_legacy,
        "aqm": aqm, "ecn": ecn, "rtt": rtt, "cap": cap, "trial": int(trial),
        "suffix": suffix,
    })

if not parsed:
    print("No matching log files. Check RESULTS_DIR and filename format.")
    sys.exit(1)

print(f"Parsed {len(parsed)} files")

def group_key(p):
    """One group = one exact experiment condition (except trial)."""
    return (p["app_L4S"], p["proto_L4S"], p["cc_L4S"],
            p["app_legacy"], p["proto_legacy"], p["cc_legacy"],
            p["aqm"], p["ecn"], p["rtt"], p["cap"])

groups = defaultdict(lambda: {"tx_L4S": [], "tx_legacy": [], "app_L4S": None, "app_legacy": None,
                               "proto_L4S": None, "proto_legacy": None, "cc_L4S": None, "cc_legacy": None})
for p in parsed:
    k = group_key(p)
    groups[k][p["suffix"]].append(p["file"])
    groups[k]["app_L4S"] = p["app_L4S"]
    groups[k]["app_legacy"] = p["app_legacy"]
    groups[k]["proto_L4S"] = p["proto_L4S"]
    groups[k]["proto_legacy"] = p["proto_legacy"]
    groups[k]["cc_L4S"] = p["cc_L4S"]
    groups[k]["cc_legacy"] = p["cc_legacy"]

STREAMING = (2500, 3500)
rows = []
for (app_L4S, proto_L4S, cc_L4S, app_legacy, proto_legacy, cc_legacy, aqm, ecn, rtt, cap), g in groups.items():
    # When L4S and legacy run different apps, show both (e.g. "updates/streaming")
    app_label = f"{app_L4S}/{app_legacy}" if app_L4S != app_legacy else app_L4S
    label = f"{app_label}_{aqm}_{ecn}ms_{rtt}ms_{cap}Mbps"
    network_str = f"{aqm}_{ecn}ms_{rtt}ms_{cap}Mbps"
    label_L4S = f"{g['proto_L4S']}-{g['cc_L4S']}-L4S"
    label_legacy = f"{g['proto_legacy']}-{g['cc_legacy']}-legacy"
    for sender, suffix, app, sender_label in [
            ("L4S", "tx_L4S", g["app_L4S"], label_L4S),
            ("Legacy", "tx_legacy", g["app_legacy"], label_legacy)]:
        files = g[suffix]
        if not files:
            rows.append({"setting": label, "app": app_label, "app_L4S": app_L4S, "app_legacy": app_legacy,
                        "network": network_str, "sender": sender, "sender_label": sender_label,
                        "goodput": 0, "rtt": 0, "loss": 0, "std_g": 0, "std_r": 0, "std_loss": 0,
                        "per_flow": {}})
            continue
        cfg = STREAMING if app == "streaming" else None
        try:
            r = run_stats(files, app=app, streaming_config=cfg)
        except Exception as e:
            print(f"  Warning: run_stats failed for {sender_label} ({len(files)} files): {e}")
            rows.append({"setting": label, "app": app_label, "app_L4S": app_L4S, "app_legacy": app_legacy,
                        "network": network_str, "sender": sender, "sender_label": sender_label,
                        "goodput": 0, "rtt": 0, "loss": 0, "std_g": 0, "std_r": 0, "std_loss": 0,
                        "per_flow": {}})
            continue
        t = r["trials"][0] if r["trials"] else {}
        per_flow = t.get("per_flow", {})
        if "across_trials" in r:
            at = r["across_trials"]
            goodput = at["mean_aggregate_goodput_mbps"]
            std_g = at["std_aggregate_goodput_mbps"]
            rtt_ms = at["mean_rtt_ms"]
            std_r = at["std_rtt_ms"]
            loss = at.get("mean_loss_pct", 0)
            std_loss = at.get("std_loss_pct", 0)
        else:
            goodput = t.get("aggregate_goodput_mbps", 0)
            std_g = 0
            rtt_ms = t.get("avg_rtt_ms", 0)
            std_r = 0
            loss = t.get("avg_loss_pct", 0)
            std_loss = 0

        # Override goodput with receiver-side rcvd_rate for Prague flows when available
        if prague_receiver_stats and build_scenario_key and proto_L4S == "PRAGUE" and sender == "L4S":
            side = "L4S"
            scenario_key = build_scenario_key(
                app_L4S, app_legacy, proto_legacy, cc_L4S, cc_legacy, aqm, ecn, rtt, cap, side
            )
            if scenario_key in prague_receiver_stats:
                recv = prague_receiver_stats[scenario_key]
                goodput = recv["mean_goodput_mbps"]
                std_g = recv["std_goodput_mbps"]
                rtt_ms = recv["mean_rtt_ms"]
                std_r = recv["std_rtt_ms"]
                loss = recv.get("mean_loss_prob", loss)
                std_loss = recv.get("std_loss_prob", std_loss)

        rows.append({"setting": label, "app": app_label, "app_L4S": app_L4S, "app_legacy": app_legacy,
                    "network": network_str, "sender": sender, "sender_label": sender_label,
                    "goodput": goodput, "rtt": rtt_ms, "loss": loss, "std_g": std_g,
                    "std_r": std_r, "std_loss": std_loss, "per_flow": per_flow})

# Filter and select x-axis based on PLOT_MODE
if PLOT_MODE == "by_app":
    plot_rows = [r for r in rows if r["network"] == FILTER_NETWORK]
    if not plot_rows:
        available = sorted(set(r["network"] for r in rows))
        print(f"WARNING: FILTER_NETWORK='{FILTER_NETWORK}' matched no data.")
        print(f"Available networks: {available}")
    x_labels = sorted(set(r["app"] for r in plot_rows))
    key_field = "app"
elif PLOT_MODE == "by_network":
    # Support "updates" (filter by L4S app) or "updates/streaming" (exact app pair)
    if "/" in FILTER_APP:
        plot_rows = [r for r in rows if r["app"] == FILTER_APP]
    else:
        plot_rows = [r for r in rows if r["app_L4S"] == FILTER_APP]
    x_labels = sorted(set(r["network"] for r in plot_rows))
    key_field = "network"
else:
    plot_rows = rows
    x_labels = sorted(set(r["setting"] for r in plot_rows))
    key_field = "setting"

settings = x_labels
rows = plot_rows
# Legend labels from first row of each sender type
l4s_label = next((r["sender_label"] for r in rows if r["sender"] == "L4S"), "L4S")
legacy_label = next((r["sender_label"] for r in rows if r["sender"] == "Legacy"), "Legacy")
print("\n" + "=" * 60)
print(f"Plot mode: {PLOT_MODE}" + (f" (network: {FILTER_NETWORK})" if PLOT_MODE == "by_app" else f" (app: {FILTER_APP})" if PLOT_MODE == "by_network" else ""))
for s in settings:
    sub = [r for r in rows if r[key_field] == s]
    print(f"\n{s}:")
    for r in sub:
        print(f"  {r['sender_label']:20s}: Goodput: {r['goodput']:.2f} Mbps  |  RTT: {r['rtt']:.2f} ms  |  Loss: {r.get('loss', 0):.2f}%")
        for fid, pf in sorted(r.get("per_flow", {}).items()):
            print(f"      flow {fid}: {pf['avg_goodput_mbps']:.2f} Mbps, {pf['avg_rtt_ms']:.2f} ms RTT, {pf['avg_loss_pct']:.2f}% loss")

if not settings:
    print("No data to plot.")
    sys.exit(1)

x = np.arange(len(settings))
w = 0.35
fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(16, 5))
l4s_g = [next((r["goodput"] for r in rows if r[key_field] == s and r["sender"] == "L4S"), 0) for s in settings]
leg_g = [next((r["goodput"] for r in rows if r[key_field] == s and r["sender"] == "Legacy"), 0) for s in settings]
l4s_std = [next((r["std_g"] for r in rows if r[key_field] == s and r["sender"] == "L4S"), 0) for s in settings]
leg_std = [next((r["std_g"] for r in rows if r[key_field] == s and r["sender"] == "Legacy"), 0) for s in settings]
ax1.bar(x - w/2, l4s_g, w, label=l4s_label, yerr=l4s_std, capsize=3)
ax1.bar(x + w/2, leg_g, w, label=legacy_label, yerr=leg_std, capsize=3)
ax1.set_ylabel("Throughput (Mbps)")
ax1.set_title("Throughput")
ax1.set_xticks(x)
ax1.set_xticklabels(settings)
ax1.legend()

l4s_r = [next((r["rtt"] for r in rows if r[key_field] == s and r["sender"] == "L4S"), 0) for s in settings]
leg_r = [next((r["rtt"] for r in rows if r[key_field] == s and r["sender"] == "Legacy"), 0) for s in settings]
l4s_std_r = [next((r["std_r"] for r in rows if r[key_field] == s and r["sender"] == "L4S"), 0) for s in settings]
leg_std_r = [next((r["std_r"] for r in rows if r[key_field] == s and r["sender"] == "Legacy"), 0) for s in settings]
ax2.bar(x - w/2, l4s_r, w, label=l4s_label, yerr=l4s_std_r, capsize=3)
ax2.bar(x + w/2, leg_r, w, label=legacy_label, yerr=leg_std_r, capsize=3)
ax2.set_ylabel("RTT (ms)")
ax2.set_title("RTT")
ax2.set_xticks(x)
ax2.set_xticklabels(settings)
ax2.legend()

l4s_loss = [next((r.get("loss", 0) for r in rows if r[key_field] == s and r["sender"] == "L4S"), 0) for s in settings]
leg_loss = [next((r.get("loss", 0) for r in rows if r[key_field] == s and r["sender"] == "Legacy"), 0) for s in settings]
l4s_std_loss = [next((r.get("std_loss", 0) for r in rows if r[key_field] == s and r["sender"] == "L4S"), 0) for s in settings]
leg_std_loss = [next((r.get("std_loss", 0) for r in rows if r[key_field] == s and r["sender"] == "Legacy"), 0) for s in settings]
ax3.bar(x - w/2, l4s_loss, w, label=l4s_label, yerr=l4s_std_loss, capsize=3)
ax3.bar(x + w/2, leg_loss, w, label=legacy_label, yerr=leg_std_loss, capsize=3)
ax3.set_ylabel("Loss (%)")
ax3.set_title("Loss")
ax3.set_xticks(x)
ax3.set_xticklabels(settings)
ax3.legend()

plt.tight_layout()
plt.savefig("mgen_plots.png", dpi=150)
print("\nSaved mgen_plots.png")
plt.show()
