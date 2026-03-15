"""
=============================================================
  European Cyber Threat Collector
=============================================================
  Converted from abuseipdb_collector.ipynb

  Architecture (3-stage pipeline):
    Stage 1 - AbuseIPDB /blacklist  : downloads 10,000 IPs (1 request)
    Stage 2 - ip-api.com batch      : geolocates all IPs for free (no key)
    Stage 3 - AbuseIPDB /check      : enriches European IPs only (1 req/IP)

  Output:
    abuseipdb_europe.csv  (appends on each run, deduplicates automatically)

  Columns:
    ip_address, country_name, abuse_score, attack_categories,
    total_reports, isp, is_tor, last_reported_at

  Requirements:
    pip install requests pandas tqdm

  Usage:
    python threat_collector.py

  Free tier limits:
    - 1,000 API requests/day
    - Resets at midnight UTC = 1:00 AM Prague (CET)
    - Max 365 days lookback

  API key:
    Get a free key at https://www.abuseipdb.com/register
    Then either:
      - Paste it into ABUSEIPDB_API_KEY below, OR
      - Set environment variable: set ABUSEIPDB_API_KEY=your_key
=============================================================
"""

import requests
import pandas as pd
import os
import time
from datetime import datetime, timezone
from tqdm import tqdm


# ─────────────────────────────────────────────────────────────
#  CONFIG — paste your API key here
# ─────────────────────────────────────────────────────────────
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "PASTE_YOUR_API_KEY_HERE")

DAYS_BACK      = 365   # max 365 on free tier
MIN_CONFIDENCE = 75    # minimum abuse confidence score (0-100)
OUTPUT_FILE    = os.path.join(os.path.dirname(os.path.abspath(__file__)), "abuseipdb_europe.csv")


# ─────────────────────────────────────────────────────────────
#  REFERENCE DATA
# ─────────────────────────────────────────────────────────────
EUROPEAN_COUNTRIES = {
    "AL","AD","AT","BY","BE","BA","BG","HR","CY","CZ","DK","EE","FI",
    "FR","DE","GR","HU","IS","IE","IT","XK","LV","LI","LT","LU","MT",
    "MD","MC","ME","NL","MK","NO","PL","PT","RO","RU","SM","RS","SK",
    "SI","ES","SE","CH","UA","GB","VA"
}

COUNTRY_NAMES = {
    "AT":"Austria",    "BE":"Belgium",        "BG":"Bulgaria",    "HR":"Croatia",
    "CY":"Cyprus",     "CZ":"Czech Republic",  "DK":"Denmark",    "EE":"Estonia",
    "FI":"Finland",    "FR":"France",          "DE":"Germany",    "GR":"Greece",
    "HU":"Hungary",    "IE":"Ireland",         "IT":"Italy",      "LV":"Latvia",
    "LT":"Lithuania",  "LU":"Luxembourg",      "MT":"Malta",      "NL":"Netherlands",
    "PL":"Poland",     "PT":"Portugal",        "RO":"Romania",    "SK":"Slovakia",
    "SI":"Slovenia",   "ES":"Spain",           "SE":"Sweden",     "GB":"United Kingdom",
    "UA":"Ukraine",    "RU":"Russia",          "NO":"Norway",     "CH":"Switzerland",
    "IS":"Iceland",    "BA":"Bosnia",          "RS":"Serbia",     "ME":"Montenegro",
    "MK":"North Macedonia", "AL":"Albania",    "MD":"Moldova",    "BY":"Belarus",
    "XK":"Kosovo",     "AD":"Andorra",         "LI":"Liechtenstein", "MC":"Monaco",
    "SM":"San Marino", "VA":"Vatican",
}

ATTACK_CATEGORIES = {
     1:"DNS Compromise",  2:"DNS Poisoning",   3:"Fraud Orders",   4:"DDoS Attack",
     5:"FTP Brute-Force", 6:"Ping of Death",   7:"Phishing",       8:"Fraud VoIP",
     9:"Open Proxy",     10:"Web Spam",        11:"Email Spam",    12:"Blog Spam",
    13:"VPN IP",         14:"Port Scan",       15:"Hacking",       16:"SQL Injection",
    17:"Spoofing",       18:"Brute-Force",     19:"Bad Web Bot",   20:"Exploited Host",
    21:"Web App Attack", 22:"SSH Abuse",       23:"IoT Targeted",
}


# ═════════════════════════════════════════════════════════════
#  STAGE 0 — Validate & Check Quota
# ═════════════════════════════════════════════════════════════

def check_quota(api_key):
    """Checks remaining daily API quota. Returns (quota_remaining, max_eu_checks)."""
    headers = {"Key": api_key, "Accept": "application/json"}
    print("Checking API quota...")
    try:
        test = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params={"ipAddress": "8.8.8.8", "maxAgeInDays": 1},
            timeout=15,
        )
        if test.status_code == 401:
            print("❌ Invalid API key. Check ABUSEIPDB_API_KEY in the script.")
            return 0, 0
        if test.status_code == 429:
            print("❌ Daily limit already reached.")
            print("   Resets at midnight UTC = 1:00 AM Prague (CET).")
            return 0, 0

        quota_remaining = int(test.headers.get("X-RateLimit-Remaining", 0))
        quota_limit     = int(test.headers.get("X-RateLimit-Limit", 1000))
        quota_used      = quota_limit - quota_remaining
        max_eu_checks   = max(0, quota_remaining - 3)

        print(f"✅ Quota status:")
        print(f"   Daily limit          : {quota_limit:,}")
        print(f"   Used today           : {quota_used:,}")
        print(f"   Remaining            : {quota_remaining:,}")
        print(f"   Max EU IPs to enrich : {max_eu_checks:,}")
        print()
        print("ℹ️  Uses ip-api.com (free, no key) to geolocate all 10,000 IPs")
        print("   and spends AbuseIPDB quota on European IPs only.")

        if quota_remaining < 10:
            print()
            print("⚠️  Not enough quota left today.")
            print("   Come back after 1:00 AM Prague time.")
            return 0, 0

        return quota_remaining, max_eu_checks

    except requests.exceptions.ConnectionError:
        print("❌ No internet connection.")
        return 0, 0
    except Exception as e:
        print(f"❌ Error checking quota: {e}")
        return 0, 0


# ═════════════════════════════════════════════════════════════
#  STAGE 1 — Download AbuseIPDB Blacklist
# ═════════════════════════════════════════════════════════════

def download_blacklist(api_key):
    """Downloads up to 10,000 IPs from AbuseIPDB blacklist. Uses 1 API request."""
    headers = {"Key": api_key, "Accept": "application/json"}
    print(f"\n[1/3] Downloading blacklist (confidence >= {MIN_CONFIDENCE}%, last {DAYS_BACK} days)...")
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/blacklist",
            headers=headers,
            params={
                "confidenceMinimum": MIN_CONFIDENCE,
                "limit"            : 10000,
                "maxAgeInDays"     : DAYS_BACK,
            },
            timeout=60,
        )
        if resp.status_code == 429:
            print("   ❌ Rate limit hit on blacklist download.")
            return []
        resp.raise_for_status()
        blacklist = resp.json().get("data", [])
        print(f"   ✅ Got {len(blacklist):,} IPs from blacklist")
        return blacklist
    except Exception as e:
        print(f"   ❌ Failed to download blacklist: {e}")
        return []


# ═════════════════════════════════════════════════════════════
#  STAGE 2 — Geolocate All IPs via ip-api.com (free, no key)
# ═════════════════════════════════════════════════════════════

def geolocate_and_filter(blacklist, max_eu_checks):
    """
    Geolocates all IPs via ip-api.com batch endpoint (free, no key needed).
    Returns list of European IP entries from the blacklist.
    ip-api free tier: 100 IPs per batch, 15 requests/min.
    """
    print(f"\n[2/3] Geolocating {len(blacklist):,} IPs via ip-api.com (free, no quota used)...")
    est_min = (len(blacklist) / 100) * 4.2 / 60
    print(f"      Estimated time: {est_min:.0f}–{est_min * 1.2:.0f} minutes")

    ip_to_country = {}
    batch_size    = 100
    all_ips       = [entry["ipAddress"] for entry in blacklist if entry.get("ipAddress")]

    for i in tqdm(range(0, len(all_ips), batch_size), desc="   Geolocating batches"):
        batch = all_ips[i:i + batch_size]
        try:
            geo_resp = requests.post(
                "http://ip-api.com/batch",
                json=[{"query": ip, "fields": "query,countryCode"} for ip in batch],
                timeout=15,
            )
            if geo_resp.status_code == 200:
                for item in geo_resp.json():
                    ip_to_country[item["query"]] = item.get("countryCode", "").upper()
            elif geo_resp.status_code == 429:
                print("   ⚠️  ip-api.com rate limit — waiting 60 seconds...")
                time.sleep(61)
                geo_resp = requests.post(
                    "http://ip-api.com/batch",
                    json=[{"query": ip, "fields": "query,countryCode"} for ip in batch],
                    timeout=15,
                )
                if geo_resp.status_code == 200:
                    for item in geo_resp.json():
                        ip_to_country[item["query"]] = item.get("countryCode", "").upper()
        except Exception:
            continue
        time.sleep(4.2)   # ip-api free: 15 requests/min = 1 per 4 seconds

    european_candidates = [
        entry for entry in blacklist
        if ip_to_country.get(entry.get("ipAddress", ""), "") in EUROPEAN_COUNTRIES
    ]

    print(f"\n   ✅ Geolocation complete")
    print(f"      Total IPs geolocated  : {len(ip_to_country):,}")
    print(f"      European IPs found    : {len(european_candidates):,}")
    print(f"      AbuseIPDB quota used  : 1 request (blacklist only)")

    if len(european_candidates) > max_eu_checks:
        print()
        print(f"   ⚠️  {len(european_candidates):,} EU IPs found but only {max_eu_checks:,} quota remaining.")
        print(f"      Will enrich first {max_eu_checks:,} — run again tomorrow for the rest.")

    return european_candidates, ip_to_country


# ═════════════════════════════════════════════════════════════
#  STAGE 3 — Enrich European IPs via AbuseIPDB /check
# ═════════════════════════════════════════════════════════════

def enrich_european_ips(european_candidates, ip_to_country, api_key, quota_remaining, max_eu_checks):
    """
    Calls AbuseIPDB /check (verbose=True) for each European IP.
    Returns list of enriched IP records with all 8 columns.
    """
    headers   = {"Key": api_key, "Accept": "application/json"}
    to_enrich = european_candidates[:max_eu_checks]

    est_min = len(to_enrich) * 0.15 / 60
    print(f"\n[3/3] Enriching {len(to_enrich):,} European IPs via AbuseIPDB /check...")
    print(f"      Estimated time: {est_min:.0f}–{est_min * 1.3:.0f} minutes")

    european_ips  = []
    requests_used = 0

    for entry in tqdm(to_enrich, desc="   Enriching EU IPs"):
        ip           = entry.get("ipAddress")
        country_code = ip_to_country.get(ip, "")
        if not ip:
            continue

        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers=headers,
                params={
                    "ipAddress"   : ip,
                    "maxAgeInDays": DAYS_BACK,
                    "verbose"     : True,
                },
                timeout=15,
            )
            requests_used += 1

            if resp.status_code == 429:
                print(f"\n   ⚠️  Rate limit reached after {requests_used} requests.")
                print(f"      Saving {len(european_ips)} enriched IPs collected so far.")
                break

            if resp.status_code != 200:
                time.sleep(0.15)
                continue

            detail = resp.json().get("data", {})

            all_cat_ids = []
            for report in detail.get("reports", []):
                all_cat_ids.extend(report.get("categories", []))
            unique_cat_ids = sorted(set(all_cat_ids))
            cat_names      = [ATTACK_CATEGORIES.get(c, f"Category {c}") for c in unique_cat_ids]

            european_ips.append({
                "ip_address"       : ip,
                "country_name"     : COUNTRY_NAMES.get(country_code, country_code),
                "abuse_score"      : detail.get("abuseConfidenceScore"),
                "attack_categories": ", ".join(cat_names) if cat_names else "Unknown",
                "total_reports"    : detail.get("totalReports"),
                "isp"              : detail.get("isp", ""),
                "is_tor"           : detail.get("isTor", False),
                "last_reported_at" : detail.get("lastReportedAt"),
            })

            time.sleep(0.15)

        except requests.exceptions.Timeout:
            continue
        except Exception:
            continue

    print(f"\n   ✅ Enriched {len(european_ips):,} European IPs")
    print(f"      AbuseIPDB requests used : {requests_used + 1:,} (including blacklist)")
    print(f"      Remaining quota         : ~{max(0, quota_remaining - requests_used):,}")

    if european_ips:
        sample_cats = set()
        for row in european_ips:
            for cat in row["attack_categories"].split(", "):
                sample_cats.add(cat)
        sample_cats.discard("Unknown")
        if sample_cats:
            print(f"      Attack types found      : {', '.join(sorted(sample_cats)[:8])}")

    return european_ips


# ═════════════════════════════════════════════════════════════
#  SAVE TO CSV & PRINT SUMMARY
# ═════════════════════════════════════════════════════════════

def save_and_summarize(european_ips):
    """Appends new results to CSV, deduplicates, and prints summary."""
    if not european_ips:
        print("\n⚠️  No data to save.")
        return

    COLUMNS = [
        "ip_address", "country_name", "abuse_score",
        "attack_categories", "total_reports", "isp",
        "is_tor", "last_reported_at"
    ]

    new_df = pd.DataFrame(european_ips, columns=COLUMNS)
    new_df["last_reported_at"] = pd.to_datetime(
        new_df["last_reported_at"], errors="coerce", utc=True
    ).dt.date

    if os.path.exists(OUTPUT_FILE):
        existing_df = pd.read_csv(OUTPUT_FILE)
        combined_df = pd.concat([existing_df, new_df], ignore_index=True)
        combined_df.drop_duplicates(
            subset=["ip_address", "last_reported_at"], keep="last", inplace=True
        )
        combined_df.sort_values(
            ["last_reported_at", "abuse_score"], ascending=[False, False], inplace=True
        )
        combined_df.reset_index(drop=True, inplace=True)
        combined_df.to_csv(OUTPUT_FILE, index=False, encoding="utf-8-sig")
        mode_label = "Appended & deduplicated"
        df = combined_df
    else:
        new_df.sort_values(
            ["last_reported_at", "abuse_score"], ascending=[False, False], inplace=True
        )
        new_df.reset_index(drop=True, inplace=True)
        new_df.to_csv(OUTPUT_FILE, index=False, encoding="utf-8-sig")
        mode_label = "Created"
        df = new_df

    print(f"\n💾 {mode_label} → {OUTPUT_FILE}")
    print(f"   New rows this run  : {len(new_df):,}")
    print(f"   Total rows in file : {len(df):,}")

    scores = pd.to_numeric(df["abuse_score"], errors="coerce")
    dates  = pd.to_datetime(df["last_reported_at"], errors="coerce").dropna()

    print()
    print("=" * 50)
    print("  DATASET SUMMARY")
    print("=" * 50)
    print(f"  Total rows          : {len(df):,}")
    print(f"  Unique IPs          : {df['ip_address'].nunique():,}")
    print(f"  Countries           : {df['country_name'].nunique()}")
    print(f"  Unique ISPs         : {df['isp'].nunique():,}")
    print(f"  Avg abuse score     : {scores.mean():.1f} / 100")
    print(f"  TOR exit nodes      : {int(df['is_tor'].sum()):,}")

    if len(dates) > 0:
        print(f"  Date range          : {dates.min().date()} → {dates.max().date()}")
    else:
        print(f"  Date range          : N/A")

    print()
    print("  Abuse Score Breakdown:")
    print(f"    Critical (100)   : {(scores == 100).sum():,} IPs")
    print(f"    High     (90-99) : {((scores >= 90) & (scores < 100)).sum():,} IPs")
    print(f"    Medium   (75-89) : {((scores >= 75) & (scores < 90)).sum():,} IPs")

    print()
    print("  Top 5 Countries:")
    print(df["country_name"].value_counts().head(5).to_string())

    print()
    print("  Top 5 Attack Types:")
    top_attacks = (
        df["attack_categories"].dropna()
        .str.split(", ").explode().str.strip()
        .value_counts().head(5)
    )
    print(top_attacks.to_string())

    print()
    print("  Top 5 ISPs:")
    print(df["isp"].value_counts().head(5).to_string())

    print()
    print("=" * 50)
    print("  ✅ Done! Run again after 1:00 AM Prague time.")
    print("=" * 50)


# ═════════════════════════════════════════════════════════════
#  MAIN
# ═════════════════════════════════════════════════════════════

def main():
    print("=" * 50)
    print("  AbuseIPDB European Threat Collector v3.0")
    print(f"  Run time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print("=" * 50)

    if ABUSEIPDB_API_KEY == "YOUR_API_KEY_HERE":
        print("\n❌ API key not set.")
        print("   Open this file and paste your key into ABUSEIPDB_API_KEY on line 47")
        print("   Or set environment variable: set ABUSEIPDB_API_KEY=your_key")
        print("   Get a free key at: https://www.abuseipdb.com/register")
        return

    quota_remaining, max_eu_checks = check_quota(ABUSEIPDB_API_KEY)
    if quota_remaining == 0:
        return

    blacklist = download_blacklist(ABUSEIPDB_API_KEY)
    if not blacklist:
        return

    european_candidates, ip_to_country = geolocate_and_filter(blacklist, max_eu_checks)
    if not european_candidates:
        print("\n⚠️  No European IPs found in blacklist sample.")
        return

    european_ips = enrich_european_ips(
        european_candidates, ip_to_country,
        ABUSEIPDB_API_KEY, quota_remaining, max_eu_checks
    )

    save_and_summarize(european_ips)


if __name__ == "__main__":
    main()
