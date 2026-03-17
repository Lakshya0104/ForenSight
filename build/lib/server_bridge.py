"""
ForenSight Server Bridge
Imported lazily by main.py only when --serve is passed.
"""
import threading
import time

_srv = None


def start_server(port: int = 5000, open_browser: bool = True) -> bool:
    global _srv
    try:
        import server as srv
        _srv = srv

        def _run():
            import logging
            logging.getLogger("werkzeug").setLevel(logging.ERROR)
            srv.app.run(
                host="0.0.0.0", port=port,
                debug=False, threaded=True, use_reloader=False
            )

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        time.sleep(1.5)   # wait for Flask to bind

        if open_browser:
            import webbrowser
            webbrowser.open(f"http://localhost:{port}")

        return True
    except Exception as e:
        print(f"[server_bridge] Failed to start: {e}")
        return False


def push_start(target: str):
    if _srv:
        _srv.push_scan_start(target)


def push_module(module: str, data):
    if _srv:
        _srv.push_module_update(module, data)


def push_complete(result: dict):
    if _srv:
        _srv.push_scan_complete(result)