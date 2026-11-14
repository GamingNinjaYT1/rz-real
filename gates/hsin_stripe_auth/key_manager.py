import asyncio
from gates.hsin_stripe_auth.hsin_conf import STRIPE_KEYS

BLACKLISTED_KEYS = set()
_key_index = 0
_lock = asyncio.Lock()


def blacklist_key(key: str):
    if key and key not in BLACKLISTED_KEYS:
        BLACKLISTED_KEYS.add(key)
        print(f"[KEY BLACKLISTED] {key[:24]}... (Total: {len(BLACKLISTED_KEYS)}/{len(STRIPE_KEYS)})")


def next_stripe_key() -> str:
    global _key_index
    available = [k for k in STRIPE_KEYS if k not in BLACKLISTED_KEYS]
    if not available:
        # Fallback if all blacklisted
        available = STRIPE_KEYS
    key = available[_key_index % len(available)]
    _key_index += 1
    return key


def is_key_restricted_error(code: str, msg: str) -> bool:
    code_l = (code or "").lower()
    msg_l = (msg or "").lower()
    return (
        "unsupported" in msg_l
        or "tokenization" in msg_l
        or "restricted" in msg_l
        or "restricted" in code_l
        or "cannot currently make live charges" in msg_l
        or "account cannot currently" in msg_l
        or code_l in ("account_restricted", "api_key_expired", "invalid_api_key",
                      "account_problem_livemode", "account_under_problem")
    )
