import time, datetime, base64, requests, os
import pandas as pd
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

# --- PRODUCTION CONFIGURATION ---
API_BASE = "https://api.elections.kalshi.com"
KEY_ID = "770c1d42-cebf-4033-81f1-6eaa7b90e6c4"
PRIVATE_KEY_PATH = r"C:\Users\jpilc\Desktop\event markets\keys\kalshi_private.txt"
EXPORT_PATH = r"C:\Users\jpilc\Desktop\event markets\data analysis\csv"

if not os.path.exists(EXPORT_PATH):
    os.makedirs(EXPORT_PATH)

# Filters
NO_TARGET_MIN = 80
NO_TARGET_MAX = 98
MIN_HOURS = 5
MAX_HOURS = 240
MIN_VOLUME = 50


def sign_kalshi_request(method, path):
    ts = str(int(time.time() * 1000))
    msg = ts + method + path
    with open(PRIVATE_KEY_PATH, "rb") as f:
        pk = serialization.load_pem_private_key(f.read(), password=None)
    sig = pk.sign(msg.encode('utf-8'),
                  padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
                  hashes.SHA256())
    return base64.b64encode(sig).decode('utf-8'), ts


def to_dollar_format(val):
    """Normalizes any price to the requested 0.80 format."""
    if val is None: return None
    try:
        f = float(val)
        if f > 1.0: return f / 100
        return f
    except:
        return None


def calculate_efficiency(price_dollars, hours):
    if hours <= 0 or not price_dollars: return 0
    p = price_dollars
    fee = (0.07 * p * (1 - p))
    profit = (1.0 - p) - fee
    # ROI/Hour as a percentage of cost
    return (profit * 100) / (hours * p) if profit > 0 else 0


def run_global_audit():
    path = "/trade-api/v2/portfolio/balance"
    try:
        sig, ts = sign_kalshi_request("GET", path)
        headers = {"KALSHI-ACCESS-KEY": KEY_ID, "KALSHI-ACCESS-SIGNATURE": sig, "KALSHI-ACCESS-TIMESTAMP": ts}
        bal = requests.get(API_BASE + path, headers=headers).json().get('balance', 0)
        print(f"--- AUTHENTICATED | Balance: ${bal / 100:.2f} ---", flush=True)
    except:
        return

    print(f"Scan running...", flush=True)
    now = datetime.datetime.now(datetime.timezone.utc)
    all_matches = []
    cursor = ""

    while True:
        query = f"limit=200&status=open&mve_filter=exclude"
        if cursor: query += f"&cursor={cursor}"
        full_path = f"/trade-api/v2/markets?{query}"

        try:
            sig, ts = sign_kalshi_request("GET", full_path)
            headers = {"KALSHI-ACCESS-KEY": KEY_ID, "KALSHI-ACCESS-SIGNATURE": sig, "KALSHI-ACCESS-TIMESTAMP": ts}
            data = requests.get(API_BASE + full_path, headers=headers).json()
            markets = data.get('markets', [])
            if not markets: break

            for m in markets:
                vol = float(m.get('volume_fp', 0))
                if vol < MIN_VOLUME: continue

                close_time = datetime.datetime.fromisoformat(m['close_time'].replace('Z', '+00:00'))
                hours_left = (close_time - now).total_seconds() / 3600
                if not (MIN_HOURS <= hours_left <= MAX_HOURS): continue

                price = to_dollar_format(m.get('no_ask_dollars'))
                if not price or price >= 0.99:
                    yb = to_dollar_format(m.get('yes_bid_dollars'))
                    price = (1.0 - yb) if yb else (1.0 - to_dollar_format(m.get('last_price_dollars')))

                if price and (NO_TARGET_MIN / 100 <= price <= NO_TARGET_MAX / 100):
                    eff = calculate_efficiency(price, hours_left)
                    all_matches.append({
                        'EFFICIENCY': round(eff, 3),
                        'PRICE': f"{price:.2f}",
                        'VOL': int(vol),
                        'TIME_H': int(hours_left),
                        'TICKER': m['ticker'],
                        'TITLE': m.get('title', 'N/A')
                    })

            cursor = data.get('cursor', "")
            if not cursor: break
            time.sleep(0.1)
        except:
            break

    if all_matches:
        df = pd.DataFrame(all_matches)
        df.sort_values(by='EFFICIENCY', ascending=False, inplace=True)
        df.insert(0, 'RANK', range(1, len(df) + 1))

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"kalshi_results_{timestamp}.csv"
        file_path = os.path.join(EXPORT_PATH, filename)

        df.to_csv(file_path, index=False)
        print(f"\nScan complete. | {len(all_matches)} Matches Found ---")
        print(f"File Saved: {file_path}")
        # Show truncated output for scannability
        print(df[['RANK', 'EFFICIENCY', 'PRICE', 'TICKER']].head(10).to_string(index=False))
    else:
        print("\nNo matches found.")


if __name__ == "__main__":
    run_global_audit()