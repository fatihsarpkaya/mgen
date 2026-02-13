#!/usr/bin/env python3
"""
Virtual Household (VH) MGEN Script Generator
=============================================
Generates MGEN script files that emulate realistic household traffic:
  - Gamer:           low-rate paced uplink (interactive gaming)
  - Video Call:      medium-rate paced uplink (camera feed)
  - Video Streaming: bursty paced downlink (DASH/HLS-like)
  - Background Updates: saturating bulk TCP downlink

Usage examples:
  # Default: 1 of each application, 30s, TCP
  python3 generate_vh.py

  # 3 gamers, 2 video calls, 2 streaming, 1 update user, 60s duration
  python3 generate_vh.py --gamers 3 --calls 2 --streams 2 --updates 1 --duration 60

  # Custom IPs
  python3 generate_vh.py --server-ip 192.168.1.1 --client-ip 192.168.1.2

  # UDP for latency-sensitive apps (gamer + video call)
  python3 generate_vh.py --gamer-proto udp --call-proto udp

  # Custom video call bitrate
  python3 generate_vh.py --call-mbps 4.0

  # Generate only specific application types
  python3 generate_vh.py --apps gamer,streaming

  # Output to custom directory
  python3 generate_vh.py --outdir /tmp/my_experiment
"""

import argparse
import os
import math
from dataclasses import dataclass, field
from typing import List, Optional


# ============================================================
# Configuration dataclasses
# ============================================================

@dataclass
class GamerConfig:
    """Gamer uplink traffic configuration."""
    mbps: float = 0.256          # Target rate (kbps class)
    frame_ms: int = 20           # Pacing interval (ms)
    proto: str = "TCP"           # TCP or UDP
    base_port: int = 5001        # Starting destination port (each flow gets its own)
    # UDP-specific: pps is computed from mbps / udp_pkt_bytes.
    # Default (0.256 Mbps, 500B) => 64 pps, matching a typical game tick rate.
    udp_pkt_bytes: int = 500     # Packet size for UDP


@dataclass
class VideoCallConfig:
    """Video call uplink traffic configuration."""
    mbps: float = 3.0            # Target rate (HD video call)
    frame_ms: int = 20           # Pacing interval (ms)
    proto: str = "TCP"           # TCP or UDP
    base_port: int = 5101        # Starting destination port (each flow gets its own)
    # UDP-specific overrides (WebRTC/RTP-like)
    udp_pkt_bytes: int = 1200    # RTP packet size


@dataclass
class StreamingConfig:
    """Video streaming downlink traffic configuration."""
    burst_mbps: float = 25.0     # Burst rate
    burst_ms: int = 2500         # Burst duration (ms)
    gap_ms: int = 3500           # Gap duration (ms)
    pkt_bytes: int = 1448        # TCP segment size (MSS with timestamps)
    base_port: int = 5201        # Starting destination port (each flow gets its own)
    mode: str = "mod"            # "mod" (long-lived) or "onoff" (per-burst connections)


@dataclass
class UpdatesConfig:
    """Background updates downlink traffic configuration."""
    streams_per_user: int = 4    # Concurrent TCP streams per update user
    pkt_bytes: int = 1448        # TCP segment size
    pkt_rate: int = 100000       # Packets/sec (saturating)
    base_port: int = 5301        # Starting destination port (each flow gets its own)


@dataclass
class ScenarioConfig:
    """Overall VH scenario configuration."""
    duration: float = 30.0       # Experiment duration (seconds)
    server_ip: str = "10.0.5.100"  # Server IP (receives uplink)
    client_ip: str = "10.0.5.200"  # Client IP (receives downlink)
    tcpinfo_window: float = 1.0  # TCPINFO reporting window (seconds)
    num_gamers: int = 1
    num_calls: int = 1
    num_streams: int = 1
    num_updates: int = 1
    gamer: GamerConfig = field(default_factory=GamerConfig)
    call: VideoCallConfig = field(default_factory=VideoCallConfig)
    streaming: StreamingConfig = field(default_factory=StreamingConfig)
    updates: UpdatesConfig = field(default_factory=UpdatesConfig)
    apps: Optional[List[str]] = None  # None = all apps


# ============================================================
# MGEN line generation helpers
# ============================================================

def calc_paced_upload_params(mbps: float, frame_ms: int) -> tuple:
    """
    Calculate MGEN PERIODIC parameters for paced upload,
    matching the VH startPacedUploadStream() logic.

    If the ideal packet size exceeds MGEN's 8192-byte limit,
    pps is increased to compensate so the target rate is met.
    NOTE: this means pps may differ from the nominal 1000/frame_ms.
    The summary prints effective pps so the user can verify.
    If frame-accurate pacing matters more than hitting the exact
    target rate, the user should lower --call-mbps so that the
    ideal packet size stays below 8192.

    Packet size is floored at 200 bytes (realistic app minimum for
    video/gaming payloads). The absolute MGEN minimum (76B) is only
    used for keepalive / gap traffic.

    Returns (pps, pkt_size_bytes)
    """
    APP_MIN = 200   # realistic minimum for video/gaming payloads
    MGEN_MAX = 8192

    bytes_per_second = mbps * 1_000_000 / 8
    pps = max(1, int(round(1000.0 / frame_ms)))
    ideal_bytes = bytes_per_second / pps

    if ideal_bytes > MGEN_MAX:
        # Packet too big — keep MGEN_MAX and increase pps to hit target rate.
        # Trade-off: pps no longer equals 1000/frame_ms.
        pkt_size = MGEN_MAX
        pps = max(1, int(round(bytes_per_second / MGEN_MAX)))
    else:
        pkt_size = max(APP_MIN, int(round(ideal_bytes)))

    return pps, pkt_size


def calc_udp_upload_params_gamer(cfg: GamerConfig) -> tuple:
    """Calculate UDP parameters for gamer.

    Computes pps from cfg.mbps and cfg.udp_pkt_bytes so that
    --gamer-mbps is respected.  The default (0.256 Mbps, 500B)
    gives 64 pps — matching the original tick-rate model.
    """
    bytes_per_second = cfg.mbps * 1_000_000 / 8
    pps = max(1, int(round(bytes_per_second / cfg.udp_pkt_bytes)))
    return pps, cfg.udp_pkt_bytes


def calc_udp_upload_params_call(cfg: VideoCallConfig) -> tuple:
    """Calculate UDP parameters for video call (RTP-like)."""
    bytes_per_second = cfg.mbps * 1_000_000 / 8
    pps = max(1, int(round(bytes_per_second / cfg.udp_pkt_bytes)))
    return pps, cfg.udp_pkt_bytes


def calc_streaming_burst_params(cfg: StreamingConfig) -> tuple:
    """Calculate MGEN PERIODIC parameters for streaming burst."""
    bytes_per_second = cfg.burst_mbps * 1_000_000 / 8
    pps = max(1, int(round(bytes_per_second / cfg.pkt_bytes)))
    return pps, cfg.pkt_bytes


def format_on(time: float, flow_id: int, proto: str, dst_ip: str,
              port: int, pps: int, pkt_size: int) -> str:
    """Format an MGEN ON command line."""
    return f"{time:<8.3f}ON  {flow_id} {proto} DST {dst_ip}/{port} PERIODIC [{pps} {pkt_size}]"


def format_off(time: float, flow_id: int) -> str:
    """Format an MGEN OFF command line."""
    return f"{time:<8.3f}OFF {flow_id}"


def format_mod(time: float, flow_id: int, pps: int, pkt_size: int) -> str:
    """Format an MGEN MOD command line (change rate without closing connection)."""
    return f"{time:<8.3f}MOD {flow_id} PERIODIC [{pps} {pkt_size}]"


def sort_event_lines(lines):
    """Sort MGEN script body lines by event timestamp.

    MGEN requires events in strict chronological order within a script file.
    This function separates comment/directive lines (placed first) from
    timestamped event lines (sorted by timestamp, stable for ties).
    """
    preamble = []
    events = []

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue  # skip blank separators
        # Check if line starts with a digit (timestamped event)
        first_char = stripped[0]
        if first_char.isdigit() or (first_char == '-' and len(stripped) > 1 and stripped[1].isdigit()):
            try:
                t = float(stripped.split()[0])
                events.append((t, line))
            except (ValueError, IndexError):
                preamble.append(line)
        else:
            preamble.append(line)

    events.sort(key=lambda x: x[0])

    result = preamble
    if preamble:
        result.append("")  # blank line after comments/directives
    for _, line in events:
        result.append(line)
    return result


# ============================================================
# Per-application script generators
# ============================================================

def generate_gamer_lines(cfg: GamerConfig, scenario: ScenarioConfig,
                         flow_id_start: int, count: int) -> tuple:
    """Generate MGEN lines for gamer uplink flows.
    Returns (lines, next_flow_id, ports_tcp, ports_udp)
    """
    lines = []
    ports_tcp = set()
    ports_udp = set()
    fid = flow_id_start

    if cfg.proto.upper() == "TCP":
        pps, pkt_size = calc_paced_upload_params(cfg.mbps, cfg.frame_ms)
    else:
        pps, pkt_size = calc_udp_upload_params_gamer(cfg)

    proto = cfg.proto.upper()
    actual_rate = pps * pkt_size * 8 / 1_000_000

    lines.append(f"# --- Gamer uplink x{count} ({proto}, ~{actual_rate:.3f} Mbps each, "
                 f"{pps} pps x {pkt_size}B) ---")

    for i in range(count):
        port = cfg.base_port + i
        lines.append(format_on(0.0, fid, proto, scenario.server_ip, port, pps, pkt_size))
        if proto == "TCP":
            ports_tcp.add(port)
        else:
            ports_udp.add(port)
        fid += 1

    return lines, fid, ports_tcp, ports_udp


def generate_call_lines(cfg: VideoCallConfig, scenario: ScenarioConfig,
                        flow_id_start: int, count: int) -> tuple:
    """Generate MGEN lines for video call uplink flows."""
    lines = []
    ports_tcp = set()
    ports_udp = set()
    fid = flow_id_start

    if cfg.proto.upper() == "TCP":
        pps, pkt_size = calc_paced_upload_params(cfg.mbps, cfg.frame_ms)
    else:
        pps, pkt_size = calc_udp_upload_params_call(cfg)

    proto = cfg.proto.upper()
    actual_rate = pps * pkt_size * 8 / 1_000_000

    lines.append(f"# --- Video call uplink x{count} ({proto}, ~{actual_rate:.3f} Mbps each, "
                 f"{pps} pps x {pkt_size}B) ---")

    for i in range(count):
        port = cfg.base_port + i
        lines.append(format_on(0.0, fid, proto, scenario.server_ip, port, pps, pkt_size))
        if proto == "TCP":
            ports_tcp.add(port)
        else:
            ports_udp.add(port)
        fid += 1

    return lines, fid, ports_tcp, ports_udp


def generate_streaming_lines(cfg: StreamingConfig, scenario: ScenarioConfig,
                             flow_id_start: int, count: int) -> tuple:
    """Generate MGEN lines for video streaming downlink flows (burst/gap).

    Dispatches to MOD or ON/OFF variant based on cfg.mode.
    Returns (lines, next_flow_id, ports_tcp)
    """
    if cfg.mode == "onoff":
        return _streaming_onoff(cfg, scenario, flow_id_start, count)
    else:
        return _streaming_mod(cfg, scenario, flow_id_start, count)


def _streaming_mod(cfg: StreamingConfig, scenario: ScenarioConfig,
                   flow_id_start: int, count: int) -> tuple:
    """MOD variant: one long-lived TCP connection per stream user.

    Uses MOD to switch between burst rate and near-zero rate instead of
    OFF/ON, because MGEN TCP does not reliably reconnect after OFF/ON
    on the same flow ID. The connection stays alive the whole time;
    during the gap, 1 pps x 76B (~608 bps) is sent — negligible.
    """
    lines = []
    ports_tcp = set()
    fid = flow_id_start

    # Burst rate
    pps, pkt_size = calc_streaming_burst_params(cfg)
    # Gap rate: minimal keepalive (1 pps x MIN_FRAG_SIZE)
    gap_pps = 1
    gap_pkt_size = 76  # MIN_FRAG_SIZE

    cycle_ms = cfg.burst_ms + cfg.gap_ms
    cycle_s = cycle_ms / 1000.0
    burst_s = cfg.burst_ms / 1000.0
    # Use ceil so a final partial burst is included if duration ends mid-cycle.
    # The t < duration guards below prevent events past the experiment end.
    num_cycles = int(math.ceil(scenario.duration / cycle_s))
    actual_rate = pps * pkt_size * 8 / 1_000_000

    lines.append(f"# --- Video streaming downlink x{count} (TCP, ~{actual_rate:.1f} Mbps burst, "
                 f"{cfg.burst_ms}ms on / {cfg.gap_ms}ms off) ---")
    lines.append(f"# Mode: MOD (keeps TCP connection alive throughout)")

    for i in range(count):
        port = cfg.base_port + i
        lines.append(f"# Stream user {i+1} (flow {fid}, port {port})")

        # Start with burst at t=0
        lines.append(format_on(0.0, fid, "TCP", scenario.client_ip, port, pps, pkt_size))

        for c in range(num_cycles):
            t_gap = round(c * cycle_s + burst_s, 3)
            t_burst = round((c + 1) * cycle_s, 3)

            # Switch to gap (near-zero rate)
            if t_gap < scenario.duration:
                lines.append(format_mod(t_gap, fid, gap_pps, gap_pkt_size))

            # Switch back to burst
            if t_burst < scenario.duration:
                lines.append(format_mod(t_burst, fid, pps, pkt_size))

        # Final OFF at end of experiment
        lines.append(format_off(scenario.duration, fid))

        ports_tcp.add(port)
        fid += 1

    return lines, fid, ports_tcp


def _streaming_onoff(cfg: StreamingConfig, scenario: ScenarioConfig,
                     flow_id_start: int, count: int) -> tuple:
    """ON/OFF variant: fresh TCP connection per burst cycle.

    Each burst uses a unique flow ID so that MGEN creates a brand-new
    TCP connection (avoiding the reconnect bug when reusing the same
    flow ID). Each user also uses a unique port so the receiver (socat)
    can accept multiple sequential connections via fork.

    Trade-offs vs MOD:
      + More realistic: mimics short-lived DASH/HLS chunk downloads
      + Each burst starts with TCP slow-start (realistic)
      - Uses many more flow IDs
      - TCP connection setup overhead per burst
    """
    lines = []
    ports_tcp = set()
    fid = flow_id_start

    pps, pkt_size = calc_streaming_burst_params(cfg)
    cycle_ms = cfg.burst_ms + cfg.gap_ms
    cycle_s = cycle_ms / 1000.0
    burst_s = cfg.burst_ms / 1000.0
    # Use ceil so a final partial burst is included if duration ends mid-cycle.
    # The t_on >= duration guard below prevents events past the experiment end.
    num_cycles = int(math.ceil(scenario.duration / cycle_s))
    actual_rate = pps * pkt_size * 8 / 1_000_000

    lines.append(f"# --- Video streaming downlink x{count} (TCP, ~{actual_rate:.1f} Mbps burst, "
                 f"{cfg.burst_ms}ms on / {cfg.gap_ms}ms off) ---")
    lines.append(f"# Mode: ON/OFF (fresh TCP connection per burst cycle)")
    lines.append(f"# Each burst uses a unique flow ID to avoid MGEN reconnect issues.")

    for i in range(count):
        port = cfg.base_port + i
        lines.append(f"# Stream user {i+1} (port {port})")

        for c in range(num_cycles):
            t_on = round(c * cycle_s, 3)
            t_off = round(c * cycle_s + burst_s, 3)

            if t_on >= scenario.duration:
                break

            lines.append(format_on(t_on, fid, "TCP", scenario.client_ip, port, pps, pkt_size))

            if t_off < scenario.duration:
                lines.append(format_off(t_off, fid))
            else:
                lines.append(format_off(scenario.duration, fid))

            fid += 1

        ports_tcp.add(port)

    return lines, fid, ports_tcp


def generate_updates_lines(cfg: UpdatesConfig, scenario: ScenarioConfig,
                           flow_id_start: int, count: int) -> tuple:
    """Generate MGEN lines for background updates downlink flows."""
    lines = []
    ports_tcp = set()
    fid = flow_id_start
    total_streams = count * cfg.streams_per_user

    lines.append(f"# --- Background updates downlink x{count} users "
                 f"({cfg.streams_per_user} streams each = {total_streams} TCP flows, saturating) ---")

    port_idx = 0
    for i in range(count):
        for s in range(cfg.streams_per_user):
            port = cfg.base_port + port_idx
            lines.append(format_on(0.0, fid, "TCP", scenario.client_ip, port,
                                   cfg.pkt_rate, cfg.pkt_bytes))
            ports_tcp.add(port)
            port_idx += 1
            fid += 1

    return lines, fid, ports_tcp


# ============================================================
# Full script assembly
# ============================================================

def generate_uplink_script(scenario: ScenarioConfig) -> tuple:
    """
    Generate the full uplink MGEN script (client -> server).
    Returns (script_text, tcp_ports, udp_ports)
    """
    header_lines = [
        "# ==========================================================",
        "# Virtual Household — UPLINK traffic (client -> server)",
        "# ==========================================================",
        f"# Server IP: {scenario.server_ip}",
        f"# Duration:  {scenario.duration}s",
        f"# Gamers:    {scenario.num_gamers} x {scenario.gamer.mbps} Mbps ({scenario.gamer.proto})",
        f"# Calls:     {scenario.num_calls} x {scenario.call.mbps} Mbps ({scenario.call.proto})",
        "# ==========================================================",
        "",
    ]

    body_lines = []
    off_lines = []
    all_tcp_ports = set()
    all_udp_ports = set()
    has_tcp = False
    fid = 1

    apps = scenario.apps or ["gamer", "call"]

    if "gamer" in apps and scenario.num_gamers > 0:
        lines, fid, tcp_p, udp_p = generate_gamer_lines(
            scenario.gamer, scenario, fid, scenario.num_gamers)
        body_lines.extend(lines)
        all_tcp_ports |= tcp_p
        all_udp_ports |= udp_p
        if tcp_p:
            has_tcp = True
        body_lines.append("")

    if "call" in apps and scenario.num_calls > 0:
        lines, fid, tcp_p, udp_p = generate_call_lines(
            scenario.call, scenario, fid, scenario.num_calls)
        body_lines.extend(lines)
        all_tcp_ports |= tcp_p
        all_udp_ports |= udp_p
        if tcp_p:
            has_tcp = True
        body_lines.append("")

    # OFF lines for all flows
    off_lines.append(f"# --- Stop all uplink flows ---")
    for i in range(1, fid):
        off_lines.append(format_off(scenario.duration, i))

    # Assemble
    tcpinfo_line = []
    if has_tcp:
        tcpinfo_line = [f"TCPINFO {scenario.tcpinfo_window}", ""]

    # MGEN requires events in chronological order — sort all event lines.
    sorted_body = sort_event_lines(body_lines + off_lines)
    all_lines = header_lines + tcpinfo_line + sorted_body + [""]
    return "\n".join(all_lines), all_tcp_ports, all_udp_ports


def generate_downlink_script(scenario: ScenarioConfig) -> tuple:
    """
    Generate the full downlink MGEN script (server -> client).
    Returns (script_text, tcp_ports)
    """
    header_lines = [
        "# ==========================================================",
        "# Virtual Household — DOWNLINK traffic (server -> client)",
        "# ==========================================================",
        f"# Client IP: {scenario.client_ip}",
        f"# Duration:  {scenario.duration}s",
        f"# Streams:   {scenario.num_streams} x {scenario.streaming.burst_mbps} Mbps burst",
        f"# Updates:   {scenario.num_updates} users x {scenario.updates.streams_per_user} streams",
        "# ==========================================================",
        "",
        f"TCPINFO {scenario.tcpinfo_window}",
        "",
    ]

    body_lines = []
    all_tcp_ports = set()
    fid = 1

    apps = scenario.apps or ["streaming", "updates"]

    if "streaming" in apps and scenario.num_streams > 0:
        lines, fid, tcp_p = generate_streaming_lines(
            scenario.streaming, scenario, fid, scenario.num_streams)
        body_lines.extend(lines)
        all_tcp_ports |= tcp_p
        body_lines.append("")

    update_fid_start = fid
    if "updates" in apps and scenario.num_updates > 0:
        lines, fid, tcp_p = generate_updates_lines(
            scenario.updates, scenario, fid, scenario.num_updates)
        body_lines.extend(lines)
        all_tcp_ports |= tcp_p
        body_lines.append("")

        # OFF lines for update flows
        off_lines = [f"# --- Stop background update flows ---"]
        for i in range(update_fid_start, fid):
            off_lines.append(format_off(scenario.duration, i))
        body_lines.extend(off_lines)
        body_lines.append("")

    # MGEN requires events in chronological order.
    # Sort all timestamped event lines; comments/directives stay on top.
    sorted_body = sort_event_lines(body_lines)
    all_lines = header_lines + sorted_body + [""]
    return "\n".join(all_lines), all_tcp_ports


def generate_receiver_script(label: str, tcp_ports: set, udp_ports: set) -> str:
    """Generate a TCP/UDP sink receiver script (shell).

    Uses socat for TCP sinks (one per port) and MGEN LISTEN for UDP.
    This avoids the MGEN TCP receiver crash at high data rates.

    IMPORTANT: socat must be run with -u (unidirectional) so that it only
    reads from the TCP socket and writes to /dev/null.  Without -u, socat
    also reads from /dev/null (which returns EOF immediately) and closes
    the TCP connection, causing MGEN's sender to see a disconnect.
    """
    lines = [
        "#!/usr/bin/env bash",
        f"# ==========================================================",
        f"# Virtual Household — RECEIVER ({label})",
        f"# ==========================================================",
        f"# Each TCP flow needs its own port for independent connections.",
        f"# Uses socat -u (unidirectional) as a TCP sink: reads from the",
        f"# TCP socket and discards data.  The -u flag is critical —",
        f"# without it, socat reads EOF from /dev/null and closes the",
        f"# connection immediately.",
        f"# Sender-side TCPINFO provides all needed TCP stats.",
        f"# ==========================================================",
        "",
    ]

    if tcp_ports:
        sorted_ports = sorted(tcp_ports)
        lines.append("# --- TCP sinks (socat -u) ---")
        lines.append("# Start a unidirectional socat sink for each TCP port:")
        for p in sorted_ports:
            lines.append(f"socat -u TCP-LISTEN:{p},fork,reuseaddr OPEN:/dev/null &")
        lines.append("")
        lines.append("# Or if socat is not available, use this Python one-liner:")
        port_list = ",".join(str(p) for p in sorted_ports)
        lines.append(f"# python3 -c \"import socket,threading;ports=[{port_list}]")
        lines.append("# def d(c):")
        lines.append("#  try:")
        lines.append("#   while c.recv(65536): pass")
        lines.append("#  except: pass")
        lines.append("#  finally: c.close()")
        lines.append("# def s(p):")
        lines.append("#  k=socket.socket();k.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)")
        lines.append("#  k.bind(('',p));k.listen(64)")
        lines.append("#  while True:")
        lines.append("#   c,_=k.accept();threading.Thread(target=d,args=(c,),daemon=True).start()")
        lines.append("# for p in ports: threading.Thread(target=s,args=(p,),daemon=True).start()")
        lines.append("# import time")
        lines.append("# try: ")
        lines.append("#  while True: time.sleep(3600)")
        lines.append("# except KeyboardInterrupt: pass\" &")
        lines.append("")

    if udp_ports:
        sorted_ports = sorted(udp_ports)
        port_str = ",".join(str(p) for p in sorted_ports)
        lines.append("# --- UDP listener (MGEN) ---")
        lines.append("# MGEN LISTEN is safe for UDP: each datagram is self-contained,")
        lines.append("# so there is no stream-parsing desync like with TCP.")
        lines.append(f"mgen input \"0.0 LISTEN UDP {port_str}\" &")
        lines.append("")
        lines.append("# Alternative: socat UDP sinks (if you prefer consistency with TCP):")
        for p in sorted_ports:
            lines.append(f"# socat -u UDP-RECVFROM:{p},fork OPEN:/dev/null &")
        lines.append("")

    lines.append('echo "Receiver sinks started. Press Ctrl+C to stop."')
    lines.append("wait")
    lines.append("")
    return "\n".join(lines)


def generate_summary(scenario: ScenarioConfig) -> str:
    """Generate a human-readable summary of the scenario.

    Prints effective parameters (pps, pkt_size, achieved Mbps) for each
    app type so there is no ambiguity about the actual traffic generated.
    """
    gamer_pps, gamer_size = (calc_paced_upload_params(scenario.gamer.mbps, scenario.gamer.frame_ms)
                              if scenario.gamer.proto.upper() == "TCP"
                              else calc_udp_upload_params_gamer(scenario.gamer))
    gamer_rate = gamer_pps * gamer_size * 8 / 1_000_000

    call_pps, call_size = (calc_paced_upload_params(scenario.call.mbps, scenario.call.frame_ms)
                            if scenario.call.proto.upper() == "TCP"
                            else calc_udp_upload_params_call(scenario.call))
    call_rate = call_pps * call_size * 8 / 1_000_000

    stream_pps, stream_size = calc_streaming_burst_params(scenario.streaming)
    stream_rate = stream_pps * stream_size * 8 / 1_000_000
    cycle_s = (scenario.streaming.burst_ms + scenario.streaming.gap_ms) / 1000.0
    stream_avg = stream_rate * (scenario.streaming.burst_ms / 1000.0) / cycle_s
    num_cycles = int(math.ceil(scenario.duration / cycle_s))

    update_rate_per_stream = scenario.updates.pkt_rate * scenario.updates.pkt_bytes * 8 / 1_000_000

    total_uplink = (scenario.num_gamers * gamer_rate +
                    scenario.num_calls * call_rate)
    total_downlink_burst = scenario.num_streams * stream_rate
    total_update_streams = scenario.num_updates * scenario.updates.streams_per_user

    # Count flow IDs used
    ul_flows = scenario.num_gamers + scenario.num_calls
    if scenario.streaming.mode == "onoff":
        stream_flows = scenario.num_streams * num_cycles
    else:
        stream_flows = scenario.num_streams
    dl_flows = stream_flows + total_update_streams

    lines = [
        "=" * 60,
        "SCENARIO SUMMARY",
        "=" * 60,
        f"Duration:    {scenario.duration}s",
        f"Server IP:   {scenario.server_ip} (receives uplink)",
        f"Client IP:   {scenario.client_ip} (receives downlink)",
        f"TCPINFO:     {scenario.tcpinfo_window}s window",
        "",
        "UPLINK (client -> server):",
        f"  Gamer x{scenario.num_gamers}:      {scenario.gamer.proto}",
        f"    Requested:    {scenario.gamer.mbps} Mbps",
        f"    Effective:    {gamer_pps} pps x {gamer_size}B = {gamer_rate:.3f} Mbps each"
        f" = {scenario.num_gamers * gamer_rate:.3f} Mbps total",
        f"  Video call x{scenario.num_calls}:  {scenario.call.proto}",
        f"    Requested:    {scenario.call.mbps} Mbps",
        f"    Effective:    {call_pps} pps x {call_size}B = {call_rate:.3f} Mbps each"
        f" = {scenario.num_calls * call_rate:.3f} Mbps total",
        f"  Total uplink:    ~{total_uplink:.3f} Mbps",
        "",
        "DOWNLINK (server -> client):",
        f"  Streaming x{scenario.num_streams}:  mode={scenario.streaming.mode}",
        f"    Burst:        {stream_pps} pps x {stream_size}B = {stream_rate:.1f} Mbps"
        f" ({scenario.streaming.burst_ms}ms on / {scenario.streaming.gap_ms}ms off)",
        f"    Avg rate:     ~{stream_avg:.1f} Mbps per stream",
        f"    Cycles:       {num_cycles} per {scenario.duration}s",
    ]
    if scenario.streaming.mode == "onoff":
        lines.append(f"    Flow IDs:     {stream_flows} (one per burst cycle)")
    else:
        lines.append(f"    Flow IDs:     {stream_flows} (one long-lived connection per user)")

    lines += [
        f"  Updates x{scenario.num_updates}:    {total_update_streams} TCP streams (saturating)",
        f"    Effective:    {scenario.updates.pkt_rate} pps x {scenario.updates.pkt_bytes}B"
        f" = {update_rate_per_stream:.1f} Mbps/stream offered (congestion-limited in practice)",
        f"  Total downlink:  streaming ~{total_downlink_burst:.0f} Mbps burst"
        f" + {total_update_streams} saturating update streams"
        f" (delivered rate limited by bottleneck)",
        "",
        "TOTAL FLOWS:",
        f"  Uplink flow IDs:    {ul_flows}",
        f"  Downlink flow IDs:  {dl_flows}",
        f"  Grand total:        {ul_flows + dl_flows}",
    ]

    # Count TCP and UDP ports separately
    ul_tcp_ports = 0
    ul_udp_ports = 0
    if scenario.gamer.proto.upper() == "TCP":
        ul_tcp_ports += scenario.num_gamers
    else:
        ul_udp_ports += scenario.num_gamers
    if scenario.call.proto.upper() == "TCP":
        ul_tcp_ports += scenario.num_calls
    else:
        ul_udp_ports += scenario.num_calls
    dl_tcp_ports = scenario.num_streams + total_update_streams

    port_parts = []
    if ul_tcp_ports + dl_tcp_ports > 0:
        port_parts.append(f"TCP {ul_tcp_ports} UL + {dl_tcp_ports} DL = {ul_tcp_ports + dl_tcp_ports}")
    if ul_udp_ports > 0:
        port_parts.append(f"UDP {ul_udp_ports} UL")
    lines.append(f"  Ports needed:       {'; '.join(port_parts)}")

    lines += [
        "=" * 60,
    ]
    return "\n".join(lines)


# ============================================================
# CLI
# ============================================================

def parse_args():
    p = argparse.ArgumentParser(
        description="Generate MGEN scripts for Virtual Household traffic simulation.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s
  %(prog)s --gamers 3 --calls 2 --streams 2 --updates 1 --duration 60
  %(prog)s --server-ip 192.168.1.1 --client-ip 192.168.1.2
  %(prog)s --gamer-proto udp --call-proto udp
  %(prog)s --call-mbps 4.0 --gamer-mbps 0.5
  %(prog)s --apps gamer,streaming
  %(prog)s --stream-mode onoff   # fresh TCP connections per burst cycle

Scaling notes:
  Each TCP flow uses a unique port + socat listener (fork mode).
  Tested up to ~50 flows without issues. Beyond ~200 flows,
  socat fork overhead may become noticeable (each new TCP
  connection forks a child process). For very high flow counts,
  consider a multi-threaded Python TCP sink instead.
        """)

    # Scenario
    p.add_argument("--duration", type=float, default=30.0,
                   help="Experiment duration in seconds (default: 30)")
    p.add_argument("--server-ip", default="10.0.5.100",
                   help="Server IP address (receives uplink, default: 10.0.5.100)")
    p.add_argument("--client-ip", default="10.0.5.200",
                   help="Client IP address (receives downlink, default: 10.0.5.200)")
    p.add_argument("--tcpinfo-window", type=float, default=1.0,
                   help="TCPINFO reporting window in seconds (default: 1.0)")

    # Counts
    p.add_argument("--gamers", type=int, default=1,
                   help="Number of gamer users (default: 1)")
    p.add_argument("--calls", type=int, default=1,
                   help="Number of video call users (default: 1)")
    p.add_argument("--streams", type=int, default=1,
                   help="Number of video streaming users (default: 1)")
    p.add_argument("--updates", type=int, default=1,
                   help="Number of background update users (default: 1)")

    # App selection
    p.add_argument("--apps", type=str, default=None,
                   help="Comma-separated list of apps to include "
                        "(gamer,call,streaming,updates). Default: all")

    # Gamer params
    p.add_argument("--gamer-mbps", type=float, default=0.256,
                   help="Gamer upload rate in Mbps (default: 0.256)")
    p.add_argument("--gamer-frame-ms", type=int, default=20,
                   help="Gamer pacing frame interval in ms (default: 20)")
    p.add_argument("--gamer-proto", default="TCP", choices=["TCP", "UDP", "tcp", "udp"],
                   help="Gamer protocol (default: TCP)")
    p.add_argument("--gamer-base-port", type=int, default=5001,
                   help="Gamer starting port (each flow gets its own, default: 5001)")
    p.add_argument("--gamer-udp-pkt-bytes", type=int, default=500,
                   help="Gamer UDP packet size in bytes (default: 500). "
                        "With --gamer-mbps 0.256, this gives ~64 pps (game tick rate).")

    # Video call params
    p.add_argument("--call-mbps", type=float, default=3.0,
                   help="Video call upload rate in Mbps (default: 3.0)")
    p.add_argument("--call-frame-ms", type=int, default=20,
                   help="Video call pacing frame interval in ms (default: 20)")
    p.add_argument("--call-proto", default="TCP", choices=["TCP", "UDP", "tcp", "udp"],
                   help="Video call protocol (default: TCP)")
    p.add_argument("--call-base-port", type=int, default=5101,
                   help="Video call starting port (each flow gets its own, default: 5101)")

    # Streaming params
    p.add_argument("--stream-burst-mbps", type=float, default=25.0,
                   help="Streaming burst rate in Mbps (default: 25.0)")
    p.add_argument("--stream-burst-ms", type=int, default=2500,
                   help="Streaming burst duration in ms (default: 2500)")
    p.add_argument("--stream-gap-ms", type=int, default=3500,
                   help="Streaming gap duration in ms (default: 3500)")
    p.add_argument("--stream-base-port", type=int, default=5201,
                   help="Streaming starting port (each flow gets its own, default: 5201)")
    p.add_argument("--stream-pkt-bytes", type=int, default=1448,
                   help="Streaming TCP segment size (default: 1448)")
    p.add_argument("--stream-mode", default="mod", choices=["mod", "onoff"],
                   help="Streaming burst/gap mechanism: "
                        "'mod' keeps one long-lived TCP connection and MODs rate "
                        "(default, reliable); 'onoff' creates fresh TCP connections "
                        "per burst cycle (more realistic chunk behavior, uses more "
                        "flow IDs but the same number of ports)")

    # Updates params
    p.add_argument("--update-streams", type=int, default=4,
                   help="TCP streams per update user (default: 4)")
    p.add_argument("--update-base-port", type=int, default=5301,
                   help="Updates starting port (each stream gets its own, default: 5301)")
    p.add_argument("--update-pkt-bytes", type=int, default=1448,
                   help="Updates TCP segment size (default: 1448)")
    p.add_argument("--update-pkt-rate", type=int, default=100000,
                   help="Updates packet rate per stream in pps "
                        "(default: 100000, saturating; use lower values for "
                        "lighter background load, e.g. 1000 for ~11.6 Mbps/stream)")

    # Output
    p.add_argument("--outdir", default=".",
                   help="Output directory for generated .mgn files (default: .)")
    p.add_argument("--prefix", default="vh",
                   help="Filename prefix (default: vh)")
    p.add_argument("--dry-run", action="store_true",
                   help="Print scripts to stdout instead of writing files")

    args = p.parse_args()

    # --- Input validation (catch division-by-zero and negative nonsense) ---
    errors = []
    if args.duration <= 0:
        errors.append("--duration must be > 0")
    if args.gamer_mbps < 0:
        errors.append("--gamer-mbps must be >= 0")
    if args.call_mbps < 0:
        errors.append("--call-mbps must be >= 0")
    if args.stream_burst_mbps < 0:
        errors.append("--stream-burst-mbps must be >= 0")
    if args.gamer_frame_ms < 1:
        errors.append("--gamer-frame-ms must be >= 1")
    if args.call_frame_ms < 1:
        errors.append("--call-frame-ms must be >= 1")
    if args.stream_burst_ms < 1:
        errors.append("--stream-burst-ms must be >= 1")
    if args.stream_gap_ms < 0:
        errors.append("--stream-gap-ms must be >= 0")
    if args.stream_pkt_bytes < 1:
        errors.append("--stream-pkt-bytes must be >= 1")
    if args.update_pkt_bytes < 1:
        errors.append("--update-pkt-bytes must be >= 1")
    if args.update_pkt_rate < 1:
        errors.append("--update-pkt-rate must be >= 1")
    if args.gamer_udp_pkt_bytes < 1:
        errors.append("--gamer-udp-pkt-bytes must be >= 1")
    if errors:
        p.error("; ".join(errors))

    return args


def main():
    args = parse_args()

    # Build configuration
    scenario = ScenarioConfig(
        duration=args.duration,
        server_ip=args.server_ip,
        client_ip=args.client_ip,
        tcpinfo_window=args.tcpinfo_window,
        num_gamers=args.gamers,
        num_calls=args.calls,
        num_streams=args.streams,
        num_updates=args.updates,
        gamer=GamerConfig(
            mbps=args.gamer_mbps,
            frame_ms=args.gamer_frame_ms,
            proto=args.gamer_proto.upper(),
            base_port=args.gamer_base_port,
            udp_pkt_bytes=args.gamer_udp_pkt_bytes,
        ),
        call=VideoCallConfig(
            mbps=args.call_mbps,
            frame_ms=args.call_frame_ms,
            proto=args.call_proto.upper(),
            base_port=args.call_base_port,
        ),
        streaming=StreamingConfig(
            burst_mbps=args.stream_burst_mbps,
            burst_ms=args.stream_burst_ms,
            gap_ms=args.stream_gap_ms,
            pkt_bytes=args.stream_pkt_bytes,
            base_port=args.stream_base_port,
            mode=args.stream_mode,
        ),
        updates=UpdatesConfig(
            streams_per_user=args.update_streams,
            pkt_bytes=args.update_pkt_bytes,
            pkt_rate=args.update_pkt_rate,
            base_port=args.update_base_port,
        ),
    )

    if args.apps:
        scenario.apps = [a.strip().lower() for a in args.apps.split(",")]

    # Generate scripts
    uplink_text, ul_tcp, ul_udp = generate_uplink_script(scenario)
    downlink_text, dl_tcp = generate_downlink_script(scenario)
    rx_server_text = generate_receiver_script("server — listens for uplink", ul_tcp, ul_udp)
    rx_client_text = generate_receiver_script("client — listens for downlink", dl_tcp, set())
    summary = generate_summary(scenario)

    # Output
    if args.dry_run:
        print(summary)
        print()
        for name, text in [("UPLINK", uplink_text), ("DOWNLINK", downlink_text),
                           ("RX_SERVER", rx_server_text), ("RX_CLIENT", rx_client_text)]:
            print(f"{'='*20} {name} {'='*20}")
            print(text)
        return

    os.makedirs(args.outdir, exist_ok=True)

    files = {
        f"{args.prefix}_uplink.mgn": uplink_text,
        f"{args.prefix}_downlink.mgn": downlink_text,
        f"{args.prefix}_rx_server.sh": rx_server_text,
        f"{args.prefix}_rx_client.sh": rx_client_text,
    }

    print(summary)
    print()

    for filename, content in files.items():
        path = os.path.join(args.outdir, filename)
        with open(path, "w") as f:
            f.write(content)
        print(f"  Written: {path}")

    print()
    print("Run instructions:")
    print(f"  Server:  bash {args.prefix}_rx_server.sh &    # TCP sinks for uplink")
    print(f"           mgen input {args.prefix}_downlink.mgn output tx_downlink.log")
    print(f"  Client:  bash {args.prefix}_rx_client.sh &    # TCP sinks for downlink")
    print(f"           mgen input {args.prefix}_uplink.mgn output tx_uplink.log")


if __name__ == "__main__":
    main()
