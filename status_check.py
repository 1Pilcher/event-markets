import time
import datetime
import base64
import requests
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

# --- CONFIG ---
API_BASE = "https://api.elections.kalshi.com"
KEY_ID = "770c1d42-cebf-4033-81f1-6eaa7b90e6c4"
PRIVATE_KEY_PATH = r"C:\Users\jpilc\Desktop\event markets\keys\kalshi_private.txt"

# This is a specific market ticker. If this one is closed, pick a live one from the UI.
TICKER = "KXFED-26MAR-T3.50"


def sign_kalshi_request(method, path):
    timestamp = str(int(time.time() * 1000))
    message = timestamp + method + path
    with open(PRIVATE_KEY_PATH, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
    sig = private_key.sign(message.encode('utf-8'),
                           padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
                           hashes.SHA256())
    return base64.b64encode(sig).decode('utf-8'), timestamp


def diagnostic_audit():
    path = f"/trade-api/v2/markets/{TICKER}"
    print(f"--- ATTEMPTING PULSE CHECK ON {TICKER} ---")

    try:
        sig, ts = sign_kalshi_request("GET", path)
        headers = {"KALSHI-ACCESS-KEY": KEY_ID, "KALSHI-ACCESS-SIGNATURE": sig, "KALSHI-ACCESS-TIMESTAMP": ts}
        response = requests.get(API_BASE + path, headers=headers).json()

        # 1. RAW DUMP: See exactly what the 2026 API is sending
        market = response.get('market', {})
        print(json.dumps(market, indent=4))

        # 2. AUDIT ANALYSIS: Check for the unit mismatch
        no_ask_legacy = market.get('no_ask')
        no_ask_2026 = market.get('no_ask_dollars')

        print(f"\n--- AUDIT RESULTS ---")
        print(f"Legacy 'no_ask': {no_ask_legacy} (Type: {type(no_ask_legacy)})")
        print(f"2026 'no_ask_dollars': {no_ask_2026} (Type: {type(no_ask_2026)})")

        if no_ask_2026 and isinstance(no_ask_2026, str):
            cent_val = int(float(no_ask_2026) * 100)
            print(f"Calculated Cent Value: {cent_val}¢")

    except Exception as e:
        print(f"Diagnostic Failed: {e}")


if __name__ == "__main__":
    diagnostic_audit()