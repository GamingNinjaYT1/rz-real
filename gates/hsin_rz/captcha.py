"""Mint a reCAPTCHA token for Razorpay payment pages using a real headless browser.

Razorpay order creation (POST /v1/payment_pages/{plink}/order) requires:
  captcha: {provider: "recaptcha_v3", token: ..., action: "payment_handle_pay"}
Google's anchor/reload endpoint mint no longer returns tokens (rresp: null),
so the token must come from a real grecaptcha client. This helper spins up
headless chromium through the resi proxy, loads the payment page, and executes
the widget exactly like the page's own bundle does.

Usage: /usr/bin/python3 captcha.py '<json>'
  json: {"site": "https://...", "proxy_server": "http://host:port", "proxy_user": ..., "proxy_pass": ...}
Output: {"captcha": {...} | null, "error": "..." } on stdout.
"""
import sys, json

def _kill_fb():
    import os, signal
    try:
        os.kill(os.getppid(), signal.SIGKILL)
    except Exception:
        pass

def main():
    args = json.loads(sys.argv[1])
    site = args["site"]
    out = {"captcha": None, "error": ""}
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        proxy = {"server": args["proxy_server"]}
        if args.get("proxy_user"):
            proxy["username"] = args["proxy_user"]
            proxy["password"] = args.get("proxy_pass", "")
        b = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"], proxy=proxy)
        try:
            pg = b.new_page(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                                        "Chrome/131.0.0.0 Safari/537.36")
            pg.route("**/*", lambda r: r.continue_()
                     if r.request.resource_type in ("document", "script", "xhr", "fetch")
                     else r.abort())
            pg.goto(site, timeout=60000, wait_until="commit")
            pg.wait_for_timeout(4000)
            cfg = pg.evaluate(
                "() => { const m = document.documentElement.innerHTML.match(/var data = (\\{.*?\\});/s);"
                " if (!m) return null; const d = JSON.parse(m[1]); return d.captcha || null; }"
            )
            if not cfg or not (cfg.get("v3_site_key") or (cfg.get("fallback") or {}).get("v2_site_key")):
                out["error"] = "no captcha config on page"
                print(json.dumps(out)); return
            v3k = cfg.get("v3_site_key")
            v2k = (cfg.get("fallback") or {}).get("v2_site_key")
            action = cfg.get("action") or "payment_handle_pay"
            if v3k:
                pg.add_script_tag(url=f"https://www.google.com/recaptcha/api.js?render={v3k}")
                pg.wait_for_function(
                    "() => typeof window.grecaptcha !== 'undefined' && typeof window.grecaptcha.execute === 'function'",
                    timeout=30000)
                tok = pg.evaluate(
                    "() => grecaptcha.execute('%s', {action:'%s'}).then(t=>t).catch(e=>'ERR:'+String(e))" % (v3k, action))
                if isinstance(tok, str) and not tok.startswith("ERR:") and len(tok) > 40:
                    out["captcha"] = {"provider": "recaptcha_v3", "token": tok, "action": action}
            if not out["captcha"] and v2k:
                tok = pg.evaluate(
                    """async (v2k) => {
                        const t = await new Promise((res, rej) => {
                            const div = document.createElement('div'); document.body.appendChild(div);
                            const w = grecaptcha.render(div, {sitekey: v2k, size: 'invisible',
                                callback: t => res(t), 'error-callback': () => rej('err')});
                            grecaptcha.execute(w);
                        });
                        return t;
                    }""", v2k)
                if isinstance(tok, str) and len(tok) > 40:
                    out["captcha"] = {"provider": "recaptcha_v2", "token": tok}
            print(json.dumps(out))
        except Exception as e:
            out["error"] = f"{type(e).__name__}: {str(e)[:100]}"
            print(json.dumps(out))
        finally:
            try:
                b.close()
            except Exception:
                pass

if __name__ == "__main__":
    main()
