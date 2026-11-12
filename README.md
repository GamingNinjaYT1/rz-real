# rz — Razorpay ₹1 Card-Check API

HTTP API that checks a card against a live Razorpay checkout (₹1 order placed on a
Razorpay payment page) and returns the gateway's own verbatim response —
DECLINED / APPROVED / REQUIRES_ACTION plus the exact message Razorpay produced.

It is a Flask front (`rz_api_server.py`) over an async walker (`gates/hsin_rz/checker.py`)
that replays the full browser flow of a Razorpay `pages.razorpay.com` /
`razorpay.me` payment page:

```
load payment page ──▶ parse "var data" (payment_link id, page items, key ids)
      │
      ├─▶ headless chromium: mint reCAPTCHA v3 token for this page      ──┐
      │                                                                    │
      ├─▶ POST /v1/payment_pages/{plink}/order        (order + captcha)  ◀─┘
      ├─▶ GET  /v1/checkout/public                    (session token)
      ├─▶ POST /v2/standard_checkout/preferences      (merchant + methods ctx)
      ├─▶ GET  /v2/.../customers/status/{phone}       (skip_otp)
      └─▶ POST /v1/standard_checkout/payments/create/ajax   (the card)
               └─▶ geohint cancel probe when needed
```

Response classification mirrors Razorpay's error taxonomy: `insufficient balance`,
wrong CVV, transaction-limit, 3DS/auth-required, international-not-allowed, expired,
card-declined — status mapped to `APPROVED` (live card, bank responded) /
`REQUIRES_ACTION` (3DS) / `DECLINED` with the gateway text passed through untouched.

## API

```
GET http://127.0.0.1:5003/razorpay-135-1?cc=CC|MM|YY|CVV&proxy=PROXY[&site=URL]
```

| param  | required | meaning |
|--------|----------|---------|
| `cc`   | yes | `number\|month\|year\|cvv` (4-digit year is trimmed to 2) |
| `proxy`| yes | residential proxy, `http://user:pass@host:port`. **Mandatory** — Razorpay drops datacenter IPs at the payment step |
| `site` | no  | a specific Razorpay payment-page URL. Omitted → the walker shuffles `gates/hsin_rz/sites_razor.txt` and picks one that yields an order (dead pages get pruned from the file automatically) |

```bash
curl --get "http://127.0.0.1:5003/razorpay-135-1" \
     --data-urlencode "cc=4427568030387685|12|29|583" \
     --data-urlencode "proxy=http://user:pass@resi.example:8080" \
     --data-urlencode "site=https://razorpay.me/@somepage"
```

```json
{
  "cc": "4427568030387685|12|29|583",
  "Gateway": "Razorpay ₹1",
  "Status": "DECLINED",
  "Response": "Card Declined",
  "Price": "1",
  "Currency": "INR",
  "IP": "resi.example",
  "timetaken": "21.6s"
}
```

`site=` failures are reported verbatim, e.g.
`All Razorpay endpoints busy or deactivated — last: https://…: Captcha mint failed`.

## Setup

```bash
pip install -r requirements.txt
playwright install chromium          # the captcha mint runs real headless chromium
python3 rz_api_server.py             # :5003, or use rzapi.service (systemd)
```

- Site pool lives in `gates/hsin_rz/sites_razor.txt` (one payment-page URL per line),
  override with `RZ_SITES_FILE`.
- `RZ_CAPTCHA_PYTHON` — path of a python interpreter that has playwright installed
  (default `/usr/bin/python3`); the mint runs as a subprocess under it.
- The proxy is mandatory on every check; a missing one returns `400` with usage text.
- Chromium needs the usual headless deps present (this repo was built/tested on a
  Debian-ish VPS: `libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libxkbcommon0 …`).

## How the captcha is bypassed

Razorpay hardened the payment-pages **order-creation** endpoint:
`POST /v1/payment_pages/{plink}/order` now answers

```json
{"error":{"code":"BAD_REQUEST_ERROR","description":"Captcha token not present",
          "reason":"input_validation_failed","step":"payment_initiation"}}
```

The bypass works off four findings:

1. **The order body contract** (from `cdn.razorpay.com/static/payment-handle/bundle.js`):
   the browser posts `{notes, line_items, captcha}`, where `captcha` is
   `{provider: "recaptcha_v3", token, action}` — or the v2 fallback
   `{provider: "recaptcha_v2", token}` which the bundle itself switches to when the
   API answers `"Low captcha score"`.

2. **The keys ship with the page.** The HTML of every payment page embeds
   `var data = {...}` whose `captcha` block carries everything needed:
   ```json
   {"provider": "recaptcha_v3",
    "v3_site_key": "6LdiYS0tAAAA…",
    "action": "payment_handle_pay",
    "fallback": {"provider": "recaptcha_v2", "v2_site_key": "6LeXqS8tAAAA…"}}
   ```
   So no scraping of external config is needed — the checker lifts the keys from the
   same page it is about to order on.

3. **Pure server-side minting is dead.** Two things kill it:
   - `api2/anchor` rejects the v2 site key on the page's own origin
     (`"Invalid domain for site key"` for `razorpay.me`; the key only accepts
     `api.razorpay.com` / `www.razorpay.com` origins);
   - even with an accepted origin, `api2/reload` now returns `["rresp", null, …]` —
     Google gates the response token behind real browser entropy (bgdata / behavior
     telemetry), so a bare anchor→reload request never yields a usable token.
     Feeding an anchor token straight into the order POST gets `"Captcha Failed"`.

4. **A real grecaptcha client passes.** So the repo mints the token inside an actual
   browser instead of forging one — `gates/hsin_rz/captcha.py`:
   - headless **chromium** (playwright), launched **through the same residential proxy**
     as the whole flow, so the token's IP context matches the order's;
   - loads the payment page, reads the `captcha` block from `var data`;
   - injects `https://www.google.com/recaptcha/api.js?render=<v3_site_key>`;
   - waits for `grecaptcha.execute` and runs it with the page's own action
     (`payment_handle_pay`) — a genuine ~1.9 KB `03…`/`0c…` token comes back;
   - falls back to v2 (`grecaptcha.render` invisible widget + `execute`) if the v3
     path cannot produce a token;
   - prints the ready `captcha` object as JSON on stdout.

   The walker (`mint_rz_captcha()`) shells this out per attempt (async subprocess,
   110 s budget) and attaches the object to the order POST. One mint ≈ 8–15 s
   with a warm page load over resi egress; the rest of the flow stays pure aiohttp.

Practical notes: tokens are single-use and short-lived (mint per order, never reuse);
the same payment page that served the token must be the one the order is created on;
if Razorpay flips to hard-v2 scoring the helper already emits the v2 shape the bundle
expects.

## Layout

```
rz_api_server.py            Flask API (:5003)
gates/hsin_rz/checker.py    async walker + response classification + pool mgmt
gates/hsin_rz/captcha.py    headless-chromium reCAPTCHA mint (subprocess)
gates/hsin_rz/sites_razor.txt   payment-page pool (one URL per line)
gates/hsin_stripe_auth/bin_lookup.py   BIN enrichment (brand/type/bank/country)
rzapi.service               systemd example
```
