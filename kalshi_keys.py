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

# THE TARGET TICKER
TICKER = "KXFED-26MAR-T3.50"


def sign_kalshi_request(method, path):
    timestamp = str(int(time.time() * 1000))
    message = timestamp + method + path
    with open(PRIVATE_KEY_PATH, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
    sig = private_key.sign(
        message.encode('utf-8'),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
        hashes.SHA256()
    )
    return base64.b64encode(sig).decode('utf-8'), timestamp


def diagnostic_audit():
    path = f"/trade-api/v2/markets/{TICKER}"
    print(f"--- ATTEMPTING POSITIVE CONFIRMATION ON {TICKER} ---")

    try:
        sig, ts = sign_kalshi_request("GET", path)
        headers = {"KALSHI-ACCESS-KEY": KEY_ID, "KALSHI-ACCESS-SIGNATURE": sig, "KALSHI-ACCESS-TIMESTAMP": ts}
        response = requests.get(API_BASE + path, headers=headers).json()

        market = response.get('market', {})
        if not market:
            print("ERROR: Market not found in response. Check if the ticker is still active.")
            return

        print("\n--- RAW DATA DUMP ---")
        print(json.dumps(market, indent=4))

        print("\n--- AUDIT ANALYSIS ---")
        print(f"Ticker: {market.get('ticker')}")
        print(f"Price (Dollars): {market.get('no_ask_dollars')}")
        print(f"Volume (Fixed-Point): {market.get('volume_fp')}")
        print(f"Status: {market.get('status')}")

    except Exception as e:
        print(f"Diagnostic Failed: {e}")


if __name__ == "__main__":
    diagnostic_audit()