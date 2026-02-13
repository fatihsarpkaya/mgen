# Virtual Household (VH) traffic simulation — implementation notes

This document explains how Virtual Household (VH) mode simulates multiple traffic types, with code references and short snippets from `pages/vh/vh.js`.

## Overview
VH simulates four concurrent household roles for ~30 seconds:
- **Gamer** (interactive, low-rate uplink + ping sensitivity)
- **Video Calls** (paced uplink + ping sensitivity)
- **Video Streaming** (paced downlink with burst/gap pattern)
- **Background Updates** (saturating downlink)

Each role runs its own latency sampling loop (WebSocket pings), plus a traffic generator tailored to the role. Per-role metrics are collected (latency samples, loss, bytes up/down).

Core constants:
```js
const DURATION_MS = 30000;
const LOSS_THRESH_MS = { gamer: 150, calls: 300, stream: 1000, updates: 1000 };
const STREAM_BURST_MBPS = 25;
const STREAM_BURST_MS = 2500;
const STREAM_GAP_MS = 3500;
```

## 1) Latency + loss sampling (all roles)
Each role uses WebSocket RTT pings and counts “late/loss” based on per-role thresholds.

```js
async function startPings(key){
  const wsAdapter = new WebSocketPingAdapter(HOSTS[key].ping);
  await wsAdapter.connect();
  const tick = async () => {
    const p = await wsAdapter.ping();
    const rtt = (p && typeof p.rtt === 'number') ? p.rtt : -1;

    if (vhPhase === 'run') {
      members[key].pings++;
      if (rtt <= 0 || rtt > (LOSS_THRESH_MS[key] || 1000)) members[key].loss++;
    }

    // Record baseline vs run latency
    if (rtt > 0) {
      const sample = { t: (now()-members[key].start)/1000, v: rtt };
      if (vhPhase === 'baseline') members[key].baseLat.push(sample);
      else if (vhPhase === 'run') members[key].runLat.push(sample);
    }

    timers.push(setTimeout(tick, 150));
  };
  tick();
}
```

Key points:
- **Sampling cadence:** every ~150 ms.
- **Late/loss:** any RTT > role threshold counts as loss during run.
- **Baseline vs load:** samples are separated into baseline and run arrays.

## 2) Gamer traffic
Gamer simulates **interactive latency sensitivity** with a small, paced **uplink** (256 kbps class) and ping monitoring. Uplink uses `startPacedUploadStream()` with low Mbps.

```js
function startPacedUploadStream(key, mbps, frameMs = 20, splits = 1){
  const bytesPerSecond = mbps*1_000_000/8;
  const bytesPerFrame = Math.max(200, Math.floor(bytesPerSecond * (frameMs/1000)));
  const subBytes = Math.max(100, Math.floor(bytesPerFrame / Math.max(1, splits)));

  const stream = new ReadableStream({
    start(controller){
      const frameTimer = setInterval(() => {
        if (stopFlag || (now()-members[key].start) >= DURATION_MS) {
          controller.close(); clearInterval(frameTimer); return;
        }
        for (let i=0;i<splits;i++){
          const t = i * Math.max(2, Math.floor(frameMs/Math.max(1,splits)));
          timers.push(setTimeout(() => {
            const chunk = new Uint8Array(subBytes);
            controller.enqueue(chunk);
            members[key].bytesUp += subBytes;
          }, t));
        }
      }, frameMs);
      timers.push(frameTimer);
    }
  });

  fetch(HOSTS[key].base + '/upload', { method:'POST', body: stream }).catch(()=>{});
}
```

## 3) Video calls traffic
Video calls use the same **paced upload** mechanism as gamer but at a higher target rate (a few Mbps), and also use ping loss/late thresholds.

Implementation detail:
- Calls share `startPacedUploadStream()` with a higher Mbps argument.
- Loss threshold is higher than gamer (`LOSS_THRESH_MS.calls = 300`).

## 4) Video streaming traffic
Streaming simulates a **paced downlink** with a burst/gap pattern:
- **Burst** at `STREAM_BURST_MBPS` for `STREAM_BURST_MS`
- **Gap** for `STREAM_GAP_MS`

Download pacing uses `startPacedDownload()` which reads a download stream and sleeps to enforce the target Mbps.

```js
async function startPacedDownload(key, mbps, maxDurationMs = DURATION_MS){
  const targetBps = mbps*1_000_000/8;
  let last = now();
  let accBytes = 0;

  const res = await fetch(HOSTS[key].base + `/download?size=100mb${token}`, { cache:'no-cache' });
  const reader = res.body.getReader();

  while (!stopFlag && (now()-members[key].start) < DURATION_MS) {
    const {done, value} = await reader.read();
    if (done) break;
    accBytes += value.byteLength;
    members[key].bytesDown += value.byteLength;

    const since = (now()-last)/1000;
    const allowed = targetBps*since;
    if (accBytes > allowed) {
      const over = accBytes - allowed;
      const sleepMs = Math.max(5, Math.floor((over/targetBps)*1000));
      await new Promise(r => timers.push(setTimeout(r, sleepMs)));
      last = now(); accBytes = 0;
    }
  }
}
```

## 5) Background updates traffic
Updates simulate a **saturating download** using multiple concurrent download streams.

```js
async function startSaturatingDownload(key, streams=4){
  for (let i=0;i<streams;i++) {
    (async ()=>{
      while(!stopFlag && (now()-members[key].start) < DURATION_MS){
        const res = await fetch(HOSTS[key].base + `/download?size=100mb${token}`, { cache:'no-cache' });
        const reader = res.body.getReader();
        while(!stopFlag && (now()-members[key].start) < DURATION_MS){
          const {done, value} = await reader.read();
          if (done) break;
          members[key].bytesDown += value.byteLength;
        }
        try { await reader.cancel(); } catch(_){ }
      }
    })();
  }
}
```

## 6) Optional server‑pushed downlink channel
There is also a WebSocket downlink path (server‑pushed packets) to simulate downlink traffic without pulling via HTTP.

```js
async function startWsDownlink(key, role){
  const url = HOSTS[key].base.replace('https://','wss://') + `/vh/ws?role=${encodeURIComponent(role)}`;
  const ws = new WebSocket(url);
  ws.binaryType = 'arraybuffer';
  ws.onmessage = (ev) => {
    const len = (ev.data && ev.data.byteLength) ? ev.data.byteLength : 0;
    members[key].bytesDown += len;
  };
}
```

## 7) Traffic timing and phases
VH runs in phases (baseline then run). Latency and loss are tracked separately by phase.

- **Baseline phase**: ping only, collects baseline latency distribution.
- **Run phase**: traffic generators run concurrently and pings continue.

Key state:
```js
let vhPhase = 'idle'; // 'baseline' | 'run'
const members = {
  gamer:   { baseLat: [], runLat: [], bytesUp:0, bytesDown:0, start:0, pings:0, loss:0 },
  calls:   { baseLat: [], runLat: [], bytesUp:0, bytesDown:0, start:0, pings:0, loss:0 },
  stream:  { baseLat: [], runLat: [], bytesUp:0, bytesDown:0, start:0, pings:0, loss:0 },
  updates: { baseLat: [], runLat: [], bytesUp:0, bytesDown:0, start:0, pings:0, loss:0 }
};
```

## 8) How roles map to traffic types
- **Gamer** → paced upload + low latency threshold (interactive sensitivity)
- **Video calls** → paced upload (higher Mbps) + medium latency threshold
- **Video streaming** → paced download in burst/gap cycles
- **Background updates** → saturating download with multiple streams

These are intentionally simple, repeatable traffic patterns that mimic common household use cases while remaining stable enough for measurement.

---

If you need to cite the source files:
- Main VH controller and traffic generators: `pages/vh/vh.js`
- VH UI: `pages/vh/index.html`


## 9) How to run / reproduce
This VH client is UI-only and expects backend endpoints for uploads, downloads, and ping WebSockets.

**Local UI**
- Run: `wrangler pages dev pages`
- Or open `pages/vh/index.html` directly (requires CORS-friendly endpoints).

**Expected backend endpoints** (per role host):
- `GET /download?size=100mb&token=...` — streaming download
- `POST /upload` — streaming upload (ReadableStream)
- `GET /vh/ws?role=...` — optional WS downlink traffic channel
- `WS /ws` — ping adapter endpoint for RTT (WebSocketPingAdapter)

The test starts by requesting a download token from:
```js
const API_HOST = 'https://api-bufferbloat.libreqos.com';
const res = await fetch(`${API_HOST}/test/start`, { method:'POST' });
```
For offline use, you can stub this and skip tokens (the code already handles a null token).

## 10) Role → traffic mapping (quick table)

| Role | Direction | Generator | Notes |
|---|---|---|---|
| Gamer | Up | `startPacedUploadStream()` | Low‑rate interactive uplink, strict late/loss threshold |
| Video Calls | Up | `startPacedUploadStream()` | Higher Mbps uplink, medium late/loss threshold |
| Video Streaming | Down | `startPacedDownload()` | Burst/gap pacing: `STREAM_BURST_MS` + `STREAM_GAP_MS` |
| Background Updates | Down | `startSaturatingDownload()` | Multiple concurrent download streams |

## 11) Tunable parameters (recommended knobs)

**Latency/loss thresholds**
```js
const LOSS_THRESH_MS = { gamer: 150, calls: 300, stream: 1000, updates: 1000 };
```
- RTTs over this threshold are counted as “late” (loss) during run.

**Streaming burst pattern**
```js
const STREAM_BURST_MBPS = 25;
const STREAM_BURST_MS = 2500;
const STREAM_GAP_MS = 3500;
```
- Adjust to mimic different adaptive streaming behaviors.

**Upload pacing**
```js
startPacedUploadStream(key, mbps, frameMs = 20, splits = 1)
```
- `mbps`: target upload rate
- `frameMs`: pacing interval
- `splits`: sub‑chunk count per frame

**Saturating download**
```js
startSaturatingDownload(key, streams = 4)
```
- Increase `streams` for more aggressive saturation.

## 12) Measurement semantics
- **Baseline**: pings only (no synthetic traffic); used to compute baseline median latency.
- **Run**: traffic + pings; p90 latency and late/loss are measured under load.
- **Late/loss**: any ping RTT over `LOSS_THRESH_MS[role]` counts as loss during run.
- **Mbps**: computed from bytes over elapsed time (simple rolling window updates in UI).

## 13) Notes for researchers
- The traffic patterns are intentionally **deterministic and repeatable**, not application‑level protocol emulations.
- All traffic is plain HTTP(S)/WS so it is easy to replicate in other tooling.
- DSCP is **not used** in VH mode.


## 14) Timing / timeline
- **Baseline phase:** pings only (no synthetic traffic), collects baseline latency.
- **Run phase:** traffic generators + pings for the remainder of the 30s window.

The top‑level VH duration is controlled by:
```js
const DURATION_MS = 30000;
```

## 15) Suggested outputs to log
If you are re‑implementing the VH logic, these are the most useful per‑role signals to log for analysis:
- **Latency samples** (baseline and run): timestamp + RTT
- **Packet “late/loss” count**: pings, loss, and derived loss%
- **Throughput**: bytesUp/bytesDown over time (Mbps)

In VH, these live in:
```js
members[key].baseLat
members[key].runLat
members[key].pings
members[key].loss
members[key].bytesUp
members[key].bytesDown
```

