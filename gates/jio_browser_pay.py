"""Browser leg for the payglocal payment step — run as a subprocess.

CF blocks non-browser clients on api.payglocal.com; this script finishes the
payment in a real chromium (express saved-card pay, or full card entry).

Input (JSON on stdin):
  {"token": "...", "cc": "4111111111111111", "mm": "05", "yy": "2027", "cvv": "842",
   "proxy": "http://user:pass@host:port" | "" (empty -> direct), "timeout": 90}

Output (JSON on stdout): {"status": "charged|approved|declined|error",
                          "response": "...", "amount": "308.46",
                          "reason": "GL-...", "blocked": bool}
"""
import sys, os, json, time, re, tempfile


def _log(msg):
    print(msg, file=sys.stderr, flush=True)


def out(d):
    print(json.dumps(d, default=str), flush=True)
    sys.stdout.flush()
    os._exit(0)


def main():
    try:
        req = json.loads(sys.stdin.read())
    except Exception:
        out({"status": "error", "response": "bad request payload", "blocked": False})

    token = (req.get("token") or "").strip()
    if not token.startswith("eyJ"):
        out({"status": "error", "response": "missing payglocal token", "blocked": False})

    cc = req.get("cc") or ""
    mm = req.get("mm") or ""
    yy = req.get("yy") or ""
    cvv = req.get("cvv") or ""
    proxy_raw = (req.get("proxy") or "").strip()
    total_to = float(req.get("timeout") or 90)

    from playwright.sync_api import sync_playwright

    url = f"https://api.payglocal.com/gl/payflow-ui/?x-gl-token={token}"
    proxy = None
    if proxy_raw and proxy_raw.lower() not in ("no", "direct"):
        p = proxy_raw
        user = pwd = None
        m = re.match(r"https?://([^:]+):([^@]+)@(.+)", p)
        if m:
            user, pwd, host = m.group(1), m.group(2), m.group(3)
        else:
            host = p.split("://")[-1]
        proxy = {"server": "http://" + host}
        if user:
            proxy["username"], proxy["password"] = user, pwd

    captured = {}

    with sync_playwright() as p:
        b = p.chromium.launch(headless=True,
                              proxy=proxy,
                              args=["--no-sandbox", "--disable-dev-shm-usage"])
        pg = b.new_page(locale="en-IN", timezone_id="Asia/Kolkata")

        def on_resp(r):
            try:
                u = r.url
                if "payglocal" in u and "/cdn" not in u and "zrn." not in u:
                    if "/ipay" in u or "/risk/fp" in u or "redirect/dc" in u or "/pd/paynow" in u:
                        try:
                            captured[u.split("?")[0].split("/gl/")[-1]] = r.json()
                        except Exception:
                            captured[u.split("?")[0].split("/gl/")[-1]] = f"HTTP{r.status}"
            except Exception:
                pass

        pg.on("response", on_resp)

        servlet = {}
        def on_resp2(r):
            try:
                if "paymentservlet" in r.url or "jio-common-servlet" in r.url:
                    servlet["body"] = (r.text() or "")[:1200]
                    servlet["url"] = r.url[:120]
            except Exception:
                pass
        pg.on("response", on_resp2)

        try:
            pg.goto(url, timeout=int(total_to * 1000), wait_until="domcontentloaded")
        except Exception as e:
            _log(f"goto: {type(e).__name__}")

        deadline = time.time() + total_to

        # CF block?
        for _ in range(8):
            try:
                t = pg.title() or ""
            except Exception:
                t = ""
            if "attention required" in t.lower() or "just a moment" in t.lower():
                b.close()
                out({"status": "error", "response": "payglocal blocked by Cloudflare", "blocked": True})
            if "payglocal" in t.lower() or pg.query_selector("#network_dcc_v2_pay_INR"):
                break
            time.sleep(1)

        # wait for pay controls to render (SPA hydration)
        try:
            pg.wait_for_selector("#network_dcc_v2_pay_INR, #network_dcc_v2_pay_USD, input[name*=card]",
                                 timeout=25000)
        except Exception:
            _log("selector wait timeout")

        # express saved-card path
        clicked = False
        for sel in ("#network_dcc_v2_pay_INR", "#network_dcc_v2_pay_USD"):
            el = pg.query_selector(sel)
            if el:
                amt_txt = (el.inner_text() or "")
                m = re.search(r"([0-9]+(?:\.[0-9]+)?)", amt_txt.replace(",", ""))
                amt = m.group(1) if m else ""
                cur = "INR" if "INR" in sel else "USD"
                try:
                    el.click(timeout=8000)
                    clicked = True
                    _log(f"clicked {sel} amt={amt} {cur}")
                except Exception as e:
                    _log(f"click fail {sel}: {type(e).__name__}")
                break

        if not clicked:
            # full card entry fallback — expand the card section
            try:
                card_sec = pg.query_selector("text=Credit or debit card")
                if card_sec:
                    card_sec.click(timeout=5000)
                    time.sleep(2)
            except Exception:
                pass
            filled = False
            fields = {
                "card": ("input[name*=card], input[placeholder*=card], input[id*=card]", cc),
                "exp": ("input[name*=exp], input[placeholder*=xpi], input[id*=exp]", (mm + "/" + yy[-2:]) if mm else ""),
                "cvv": ("input[name*=cvv], input[placeholder*=cvv], input[id*=cvv]", cvv),
                "name": ("input[name*=name], input[placeholder*=name], input[id*=name]", "John Doe"),
            }
            for _k, (sel, val) in fields.items():
                if not val:
                    continue
                el = pg.query_selector(sel)
                if el:
                    try:
                        el.click()
                        el.type(val, delay=40)
                        filled = True
                    except Exception:
                        pass
            if filled:
                for sel in ("button:has-text('Pay')", "button:has-text('Submit')",
                            "button:has-text('Pay Now')"):
                    btn = pg.query_selector(sel)
                    if btn:
                        try:
                            btn.click(timeout=8000)
                            clicked = True
                            _log(f"clicked card-form {sel}")
                            break
                        except Exception:
                            pass
            if not clicked:
                body = ""
                try:
                    body = pg.inner_text("body")[:300]
                except Exception:
                    pass
                try:
                    ctrls = pg.eval_on_selector_all(
                        "button, input", "els => els.filter(e => e.offsetParent).length")
                except Exception:
                    ctrls = -1
                b.close()
                out({"status": "error",
                     "response": f"no pay control on payflow page (vis={ctrls}; {body[:80]})",
                     "blocked": False})

        # poll for verdict
        verdict = None
        while time.time() < deadline:
            time.sleep(1.2)

            ipay = captured.get("v2/payments/dc/ipay") or captured.get("v1/payments/dc/ipay")
            if isinstance(ipay, dict):
                st = ipay.get("status") or ""
                rc = ipay.get("reasonCode") or ""
                data = ipay.get("data") or {}
                errs = ipay.get("errors") or {}
                dm = (errs.get("detailedMessage") if isinstance(errs, dict) else "") or ipay.get("message") or ""
                verdict = {"ipay": ipay, "st": st, "rc": rc, "data": data, "dm": str(dm)}
                break

            # verdict page: payglocal handed back to the jio return servlet
            try:
                if "jio.com" in (pg.url or ""):
                    body = servlet.get("body") or ""
                    if not body:
                        try:
                            body = pg.content()[:1200]
                        except Exception:
                            body = ""
                    low = body.lower()
                    if any(k in low for k in ("success", "successful", "payment done",
                                              "recharge successful", "thank you")):
                        out({"status": "charged", "response": "payment successful",
                             "amount": "", "reason": "SERVLET", "blocked": False})
                    if any(k in low for k in ("fail", "declin", "error", "unable")):
                        m = re.search(r"(GL-[0-9]{3}-[0-9]{3})", body)
                        rsn = m.group(1) if m else ""
                        out({"status": "declined",
                             "response": (rsn or "declined by issuer") if not rsn else rsn,
                             "amount": "", "reason": rsn or "SERVLET", "blocked": False})
                    out({"status": "error", "response": f"return servlet unreadable: {body[:90]}",
                         "blocked": False})
            except SystemExit:
                raise
            except Exception:
                pass

            # 3DS challenge frame by URL (cross-origin safe)
            try:
                for f in pg.frames:
                    fu = (f.url or "").lower()
                    if any(k in fu for k in ("capitalone", "/acs/", "3ds", "idcheck",
                                             "mastercard.us", "verifiedbyvisa",
                                             "arcot", "centinelapistag")):
                        out({"status": "approved", "response": "3ds required",
                             "amount": "", "reason": "3DS", "blocked": False})
            except SystemExit:
                raise
            except Exception:
                pass

            # 3DS challenge in any frame?
            try:
                hit = pg.evaluate(
                    """() => {
                      const kw = ['verify your identity', 'id check', '3d secure',
                                  'enter otp', 'authentication required', 'capital one'];
                      const texts = [document.body ? document.body.innerText : ''];
                      for (const f of window.frames) { try { texts.push(f.document.body.innerText); } catch (e) {}
                        for (const ff of (f.frames || [])) { try { texts.push(ff.document.body.innerText); } catch (e) {} } }
                      const t = texts.join(' ').toLowerCase();
                      return kw.filter(k => t.includes(k)).join(',') || '';
                    }""")
                if hit:
                    b.close()
                    out({"status": "approved", "response": "3ds required",
                         "amount": "", "reason": "3DS", "blocked": False})
            except Exception:
                pass

            # inline decline / error text?
            try:
                txt = (pg.inner_text("body") or "").strip()
                if txt and any(k in txt.lower() for k in (
                        "declined", "transaction failed", "payment failed",
                        "insufficient", "do not honor", "do not honour",
                        "not successful", "unable to process", "error occurred")):
                    b.close()
                    out({"status": "declined", "response": txt[:70].replace("\n", " "),
                         "amount": "", "reason": "PAGE", "blocked": False})
            except Exception:
                pass

        b.close()

        if verdict:
            from gates.jio import _classify
            st, resp = _classify(verdict["st"], verdict["dm"], verdict["data"], verdict["rc"])
            amt = ""
            try:
                d = verdict["data"] or {}
                amt = str(d.get("totalAmount") or d.get("amount") or "")
            except Exception:
                pass
            out({"status": st, "response": resp, "amount": amt,
                 "reason": verdict["rc"], "blocked": False})

        out({"status": "error", "response": "payflow verdict timeout", "blocked": False})


if __name__ == "__main__":
    main()
