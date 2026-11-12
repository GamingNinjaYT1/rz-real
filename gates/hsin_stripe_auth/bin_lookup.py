import random
import string
import aiohttp
from datetime import datetime
from gates.hsin_stripe_auth.hsin_conf import PROXY_POOL

_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)
_BIN_API = "https://bins.antipublic.cc/bins/{}"


def proxy_url_from_line(line: str) -> str:
    if not line:
        return None
    line = line.strip()
    if line.startswith("http://") or line.startswith("https://") or line.startswith("socks5://"):
        return line
    parts = line.split(":")
    if len(parts) == 4:
        host, port, user, pwd = parts
        return f"http://{user}:{pwd}@{host}:{port}"
    if len(parts) == 2:
        host, port = parts
        return f"http://{host}:{port}"
    return None


def random_proxy() -> str:
    if not PROXY_POOL:
        return None
    while True:
        line = random.choice(PROXY_POOL)
        url = proxy_url_from_line(line)
        if url:
            return url


def generate_random_email() -> str:
    username = ''.join(random.choices(string.ascii_lowercase, k=random.randint(8, 12)))
    number = random.randint(100, 9999)
    domains = ['gmail.com', 'yahoo.com', 'outlook.com', 'protonmail.com']
    return f"{username}{number}@{random.choice(domains)}"


def is_expired(mes: str, ano: str) -> bool:
    try:
        now = datetime.now()
        m = int(mes)
        y = int(ano)
        if y < 100:
            y += 2000
        return (y < now.year) or (y == now.year and m < now.month)
    except:
        return False


def random_str(n: int) -> str:
    return "".join(random.choices(string.ascii_lowercase, k=n))


def country_flag(code: str) -> str:
    if not code or len(code) != 2:
        return ""
    return chr(0x1F1E6 + ord(code[0].upper()) - ord('A')) + chr(0x1F1E6 + ord(code[1].upper()) - ord('A'))


async def lookup_bin(session: aiohttp.ClientSession, bin6: str) -> dict:
    info = {"brand": "", "type": "", "country": "", "country_name": "", "country_flag": "", "bank": ""}
    try:
        async with session.get(
            _BIN_API.format(bin6),
            headers={"User-Agent": _UA},
            timeout=aiohttp.ClientTimeout(total=8),
        ) as r:
            if r.status == 200:
                data = await r.json(content_type=None)
                cc = (data.get("country") or data.get("country_code") or "").upper()
                c_name = (data.get("country_name") or cc).upper()
                info["brand"] = (data.get("brand") or "").upper()
                info["type"] = (data.get("type") or "").upper()
                info["country"] = cc
                info["country_name"] = c_name
                info["country_flag"] = data.get("country_flag") or country_flag(cc)
                info["bank"] = data.get("bank") or ""
    except Exception as e:
        print(f"[BIN lookup] {bin6}: {type(e).__name__}: {e}")
    return info
