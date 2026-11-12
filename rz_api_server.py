"""RZ API Server — Razorpay ₹1 card-check walker.

Flask server on port 5003.

  GET /razorpay-135-1?cc=<card>&proxy=<proxy>&site=<payment-page-url>
  → picks a Razorpay payment page (from the pool, or the `site` in the request)
  → mints the reCAPTCHA token the order API now demands (see README)
  → creates order → submits card → returns verbatim gateway response

  Requests WITHOUT proxy are rejected — the proxy is MANDATORY
  (razorpay blocks datacenter IPs at the payment step — only resi egress works).
"""
import sys, os, json, time, asyncio, threading, subprocess
from urllib.parse import urlsplit
from flask import Flask, request, jsonify

_BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _BASE)

import threading as _th
_loop = asyncio.new_event_loop()
_loop_thread = _th.Thread(target=_loop.run_forever, daemon=True)
_loop_thread.start()

from gates.hsin_rz.checker import check_razorpay

app = Flask(__name__)

def _exc(e):
    name = type(e).__name__
    msg = str(e) or repr(e)
    return f"{name}: {msg}" if msg else name

def process_rz(cc, mm, yy, cvv, proxy_str=None, site=None):
    fut = asyncio.run_coroutine_threadsafe(
        check_razorpay(cc, mm, yy, cvv, proxy=proxy_str, site=site),
        _loop
    )
    result = fut.result(timeout=240)
    return result

@app.route("/razorpay-135-1")
def razorpay_check():
    cc = request.args.get("cc", "")
    proxy = request.args.get("proxy", "")
    site = request.args.get("site", "").strip() or None
    if not cc or "|" not in cc:
        return jsonify({"error": "missing or invalid cc"})

    # ── proxy is MANDATORY — no proxy → return error (razorpay blocks DC IPs) ──
    if not proxy or proxy == "no" or proxy == "":
        return jsonify({
            "error": "proxy parameter is MANDATORY — razorpay blocks datacenter IPs at the checkout step. "
                     "Use a resi proxy: GET /razorpay-135-1?cc=...&proxy=http://user:pass@host:port"
        }), 400

    parts = cc.split("|")
    _cc, _mm, _yy, _cvv = parts[0], parts[1], parts[2][-2:] if len(parts[2]) == 4 else parts[2], parts[3]

    t0 = time.time()
    try:
        res = process_rz(_cc, _mm, _yy, _cvv, proxy, site)
        status = str(res.get("status", "ERROR")).upper()
        response = str(res.get("response") or res.get("message") or "Unknown")

        return jsonify({
            "cc": cc,
            "Gateway": "Razorpay ₹1",
            "Status": status,
            "Response": response,
            "Price": "1",
            "Currency": "INR",
            "IP": proxy.split("@")[-1].split(":")[0] if "@" in proxy else proxy,
            "timetaken": f"{time.time()-t0:.1f}s",
        })
    except Exception as e:
        return jsonify({
            "cc": cc, "Gateway": "Razorpay ₹1",
            "Response": f"Error: {_exc(e)}",
            "Status": False, "IP": proxy or "no", "timetaken": f"{time.time()-t0:.1f}s",
        })

@app.route("/debug-captcha")
def debug_captcha():
    site = request.args.get("site", "").strip()
    proxy = request.args.get("proxy", "").strip()
    if not site:
        return jsonify({"error": "missing site"})
    args = {"site": site, "proxy_server": None, "proxy_user": None, "proxy_pass": None}
    if proxy:
        u = urlsplit(proxy if proxy.startswith("http") else "http://" + proxy)
        args["proxy_server"] = f"{u.scheme or 'http'}://{u.hostname}:{u.port or 8080}"
        if u.username:
            args["proxy_user"] = u.username
            args["proxy_pass"] = u.password or ""
    cap_py = os.path.join(_BASE, "gates", "hsin_rz", "captcha.py")
    try:
        proc = subprocess.run([sys.executable, cap_py, json.dumps(args)],
                              capture_output=True, text=True, timeout=120)
        return jsonify({"py": sys.executable, "rc": proc.returncode,
                        "stdout": proc.stdout[:2000], "stderr": proc.stderr[:2000]})
    except Exception as e:
        return jsonify({"py": sys.executable, "error": _exc(e)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5003)), debug=False)
