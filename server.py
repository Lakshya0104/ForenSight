"""
ForenSight Dashboard Server
Standalone: python server.py
Via main.py: python main.py / --serve
"""
import os
import json
import queue
import threading
import time
from datetime import datetime, timezone
from flask import Flask, Response, jsonify, send_from_directory, request

app = Flask(__name__, static_folder="dashboard")

# ── Global state ──────────────────────────────────────────────
_scan_result  = {}      # full accumulated result
_module_log   = []      # ordered list of {module, data} for replay
_scan_running = False
_sse_clients  = []      # one Queue per connected browser tab
_lock         = threading.Lock()

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_outputs")
os.makedirs(OUTPUT_DIR, exist_ok=True)


# ── Internal push helper ──────────────────────────────────────
def _broadcast(payload_str: str):
    """Send a raw SSE data string to every connected client."""
    with _lock:
        dead = []
        for q in _sse_clients:
            try:
                q.put_nowait(payload_str)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _sse_clients.remove(q)


def _encode(event_type: str, data: dict) -> str:
    return json.dumps({"type": event_type, "data": data}, default=str)


# ── Public API called by server_bridge ───────────────────────
def push_scan_start(target: str):
    global _scan_running
    with _lock:
        _scan_result.clear()
        _module_log.clear()
        _scan_running = True
    _broadcast(_encode("scan_start", {
        "target": target,
        "ts": datetime.now(timezone.utc).isoformat()
    }))


def push_module_update(module: str, data):
    """Called after each of the 6 scan modules completes."""
    with _lock:
        _scan_result[module] = data
        _module_log.append({"module": module, "data": data})
    _broadcast(_encode("module", {"module": module, "payload": data}))


def push_scan_complete(result: dict):
    """Called once after all modules + evasion/verdict are calculated."""
    global _scan_running
    with _lock:
        _scan_result.update(result)
        _scan_running = False

    # Save to scan_outputs for case history
    ts    = result.get("scan_meta", {}).get("scan_time", "")[:19].replace(":", "-")
    fname = f"forensight_{ts or int(time.time())}.json"
    try:
        with open(os.path.join(OUTPUT_DIR, fname), "w") as f:
            json.dump(result, f, indent=2, default=str)
    except Exception:
        pass

    _broadcast(_encode("scan_complete", result))


# ── Flask routes ──────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory("dashboard", "index.html")


@app.route("/api/status")
def status():
    with _lock:
        return jsonify({
            "running":    _scan_running,
            "has_result": bool(_scan_result),
            "modules":    list(_scan_result.keys()),
        })


@app.route("/api/result")
def result():
    with _lock:
        return jsonify(dict(_scan_result))


@app.route("/api/events")
def sse():
    """
    Server-Sent Events stream.
    New tabs get a replay of all past module events, then stream live.
    """
    q = queue.Queue(maxsize=200)

    with _lock:
        _sse_clients.append(q)
        replay_modules = list(_module_log)
        already_done   = not _scan_running and bool(_scan_result)
        full_snapshot  = dict(_scan_result) if already_done else {}

    def generate():
        # 1. Replay individual module events so each section populates
        for entry in replay_modules:
            msg = _encode("module", {"module": entry["module"], "payload": entry["data"]})
            yield f"data: {msg}\n\n"

        # 2. If scan already finished, send the complete result too
        if already_done and full_snapshot:
            msg = _encode("scan_complete", full_snapshot)
            yield f"data: {msg}\n\n"

        # 3. Stream live events as they arrive
        while True:
            try:
                msg = q.get(timeout=20)
                yield f"data: {msg}\n\n"
            except queue.Empty:
                yield ": keepalive\n\n"

    resp = Response(generate(), mimetype="text/event-stream")
    resp.headers["Cache-Control"]     = "no-cache"
    resp.headers["X-Accel-Buffering"] = "no"
    resp.headers["Connection"]        = "keep-alive"
    return resp


@app.route("/api/cases")
def cases():
    items = []
    for fname in sorted(os.listdir(OUTPUT_DIR), reverse=True):
        if not fname.endswith(".json"):
            continue
        try:
            with open(os.path.join(OUTPUT_DIR, fname)) as f:
                d = json.load(f)
            meta = d.get("scan_meta", {})
            items.append({
                "file":      fname,
                "target":    meta.get("target", "—"),
                "scan_time": meta.get("scan_time", ""),
                "verdict":   d.get("verdict", ""),
                "score":     d.get("evasion_score", 0),
            })
        except Exception:
            pass
    return jsonify(items)


@app.route("/api/load", methods=["POST"])
def load():
    body  = request.get_json(silent=True) or {}
    fname = body.get("file", "")
    path  = os.path.join(OUTPUT_DIR, os.path.basename(fname))
    try:
        with open(path) as f:
            data = json.load(f)
        push_scan_complete(data)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


if __name__ == "__main__":
    import webbrowser
    print("\n  ForenSight Dashboard  →  http://localhost:5000\n")
    threading.Timer(1.0, lambda: webbrowser.open("http://localhost:5000")).start()
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)