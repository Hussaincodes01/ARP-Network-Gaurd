"""ARPGuard HTTP API (FastAPI).

  GET  /api/health          what this deployment can do (LLM provider, live mode)
  POST /api/analyze         body = raw .pcap / .pcapng (optionally gzipped) -> result JSON
  POST /api/explain         {"evidence": {...}} -> AI explanation of one incident
  POST /api/live/start      start sniffing (local only, needs root)     {"iface", "gateway"}
  POST /api/live/stop
  GET  /api/live/stream     Server-Sent Events: alerts, verdicts, ARP frames, score ticks
  GET  /api/live/snapshot   the live session's current result JSON

On Vercel the dashboard in public/ is served by the CDN; locally this app
serves it too, so `python -m arpguard serve` is all you need.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

from .. import __version__
from ..ai import explainer
from ..pipeline import analyze

ON_VERCEL = os.environ.get("VERCEL") == "1"
MAX_UPLOAD = int(float(os.environ.get("ARPGUARD_MAX_UPLOAD_MB", "4.4")) * 1_000_000)
MAX_PACKETS = int(os.environ.get("ARPGUARD_MAX_PACKETS", "60000"))
EXPLAIN_PER_MINUTE = int(os.environ.get("ARPGUARD_EXPLAIN_PER_MINUTE", "6"))
PUBLIC_DIR = Path(__file__).resolve().parents[2] / "public"

app = FastAPI(title="ARPGuard", version=__version__,
              description="AI-assisted ARP spoofing detection: rules + Kitsune + LLM explainer")
app.add_middleware(GZipMiddleware, minimum_size=2000)

_live = None          # LiveMonitor, local mode only
_explain_calls: dict[str, deque] = defaultdict(deque)


def _live_supported() -> tuple[bool, str]:
    if ON_VERCEL:
        return False, "Live sniffing needs raw-socket access on your own machine; run ARPGuard locally."
    from ..core.live import scapy_available
    if not scapy_available():
        return False, "Install Scapy (pip install scapy) to enable live mode."
    return True, ""


@app.get("/api/health")
def health() -> dict:
    live_ok, live_why = _live_supported()
    return {"status": "ok", "version": __version__, "llm": explainer.status(),
            "live": {"available": live_ok, "reason": live_why, "running": bool(_live and _live.running)},
            "limits": {"max_upload_bytes": MAX_UPLOAD, "max_packets": MAX_PACKETS},
            "platform": "vercel" if ON_VERCEL else "local"}


@app.post("/api/analyze")
async def analyze_capture(request: Request,
                          gateway: Optional[str] = Query(None, description="gateway IP, if known"),
                          kitsune: bool = Query(True, description="run the Kitsune model"),
                          limit: Optional[int] = Query(None, ge=100),
                          name: Optional[str] = Query(None, max_length=200)) -> JSONResponse:
    body = await request.body()
    if not body:
        raise HTTPException(400, "send the capture file as the request body")
    if len(body) > MAX_UPLOAD:
        raise HTTPException(413, f"capture is {len(body) / 1e6:.1f} MB; the limit here is "
                                 f"{MAX_UPLOAD / 1e6:.1f} MB. Gzip it, or run ARPGuard locally for big files.")
    packets = min(limit or MAX_PACKETS, MAX_PACKETS)

    def run() -> dict:
        sess = analyze(body, gateway_ip=gateway, use_kitsune=kitsune, limit=packets,
                       source_name=name or "upload")
        result = sess.result()
        result["meta"]["truncated_to"] = packets if sess.packets >= packets else None
        return explainer.explain_result(result, use_llm=False)

    try:
        result = await asyncio.to_thread(run)
    except ValueError as e:
        raise HTTPException(400, f"could not read the capture: {e}")
    if result["meta"]["packets"] == 0:
        raise HTTPException(400, "no Ethernet frames found in the capture")
    return JSONResponse(result)


class ExplainRequest(BaseModel):
    evidence: dict


@app.post("/api/explain")
def explain_incident(req: ExplainRequest, request: Request) -> dict:
    who = (request.headers.get("x-forwarded-for") or (request.client.host if request.client else "?")).split(",")[0]
    calls = _explain_calls[who]
    now = time.time()
    while calls and now - calls[0] > 60:
        calls.popleft()
    if explainer.provider() != "template" and len(calls) >= EXPLAIN_PER_MINUTE:
        raise HTTPException(429, "too many explanation requests; wait a minute")
    calls.append(now)
    ev = req.evidence
    for key in ("verdict", "kind", "time", "kitsune", "rule_evidence", "confidence"):
        if key not in ev:
            raise HTTPException(400, f"evidence is missing '{key}'")
    try:
        return explainer.explain(ev, use_llm=True)
    except ValueError as e:
        raise HTTPException(413, str(e))


# ---------------------------------------------------------------- live mode

class LiveStart(BaseModel):
    iface: Optional[str] = None
    gateway: Optional[str] = None
    kitsune: bool = True


@app.post("/api/live/start")
def live_start(req: LiveStart) -> dict:
    global _live
    ok, why = _live_supported()
    if not ok:
        raise HTTPException(501, why)
    from ..core.live import LiveMonitor
    if _live and _live.running:
        _live.stop()
    _live = LiveMonitor(iface=req.iface, gateway_ip=req.gateway, use_kitsune=req.kitsune)
    try:
        _live.start()
    except PermissionError:
        _live = None
        raise HTTPException(403, "permission denied: run ARPGuard as root/Administrator to sniff")
    except OSError as e:
        _live = None
        raise HTTPException(400, f"could not open the interface: {e}")
    return {"running": True, "iface": req.iface}


@app.post("/api/live/stop")
def live_stop() -> dict:
    if _live:
        _live.stop()
    return {"running": False}


@app.get("/api/live/snapshot")
def live_snapshot() -> dict:
    if not _live:
        raise HTTPException(404, "live mode is not running")
    return explainer.explain_result(_live.snapshot(), use_llm=False)


@app.get("/api/live/stream")
async def live_stream(request: Request, after: int = 0) -> StreamingResponse:
    if not _live:
        raise HTTPException(404, "live mode is not running")

    async def gen():
        seq = after
        while not await request.is_disconnected():
            for ev in _live.events_after(seq):
                seq = ev["seq"]
                yield f"data: {json.dumps(ev)}\n\n"
            if not _live.running:
                yield "event: end\ndata: {}\n\n"
                return
            await asyncio.sleep(0.3)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# The CDN serves public/ on Vercel; locally, serve the dashboard from here.
if not ON_VERCEL and PUBLIC_DIR.is_dir():
    from fastapi.staticfiles import StaticFiles
    app.mount("/", StaticFiles(directory=PUBLIC_DIR, html=True), name="dashboard")
