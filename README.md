# Overview

This project collects and analyses malicious IP intelligence with a focus on European networks. It pulls suspicious IP addresses from the AbuseIPDB blacklist, a community-driven database where system administrators, hosting providers, security researchers and automated honeypot systems report malicious activity observed on their infrastructure. Each report contributes to a confidence score, building a continuously updated list of IPs associated with activities such as brute-force attacks, port scanning, spam campaigns and other forms of abuse.

Every day the pipeline takes a fresh snapshot of this blacklist, filters for European IP addresses, and enriches each record with additional context: ISP information, attack categories and TOR exit node status. The result is a structured, growing dataset that reflects potentially malicious activity originating from European networks at any given point in time.

As the dataset accumulates over daily runs, it can be used to explore trends, identify which hosting providers or regions appear most frequently in abuse reports and build visualisations or analyses grounded in real-world cybersecurity data.

# Use cases

- Tracking which European ISPs/hosting providers host the most malicious IPs
- Seeing which attack types are most common (SSH brute-force, port scanning, etc.)
- Spotting trends over time as you accumulate daily snapshots
- A solid, real-world dataset for cybersecurity research and visualization

# How it works

This project uses a three-stage collection pipeline to maximize the free API quota.

| Stage | API | Cost | What it does |
|---|---|---|---|
| 1 | AbuseIPDB `/blacklist` | 1 request | Downloads all 10,000 IPs |
| 2 | ip-api.com batch | Free, no key | Geolocates all 10,000 IPs at once |
| 3 | AbuseIPDB `/check` | 1 req per EU IP | Gets ISP, TOR, attack categories for European IPs only |

To run the project, you will need a free API key from AbuseIPDB. No credit card is required. To obtain a key, register at abuseipdb.com/register using your email address and a password. After logging in, navigate to Account > API in the top menu and click Create Key. Give the key any name, confirm the creation and copy the generated value. Paste the API key into the script before running the project.

```python
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "PASTE_YOUR_KEY_HERE")
```
The free tier of AbuseIPDB allows 1,000 API requests per day, resetting at midnight UTC. In addition, this service allows 15 batch requests per minute, so the geolocation stage typically takes about 7-8 minutes per run. When the script starts, it checks the remaining API quota and exits cleanly with a clear message if the daily limit has already been reached.

The remaining quota is read directly from the API response headers (``X-RateLimit-Remaining``) during the initial request. This ensures the script always knows exactly how many IP addresses it can process before continuing.

```python
test = requests.get(
    "https://api.abuseipdb.com/api/v2/check",
    headers=headers,
    params={"ipAddress": "8.8.8.8", "maxAgeInDays": 1},
    timeout=15,
)

QUOTA_REMAINING = int(test.headers.get("X-RateLimit-Remaining", 0))
QUOTA_LIMIT     = int(test.headers.get("X-RateLimit-Limit", 1000))
MAX_EU_CHECKS   = max(0, QUOTA_REMAINING - 3)   # safety buffer

if QUOTA_REMAINING < 10:
    print("⚠️ Not enough quota left. Come back after 1:00 AM.")
```

View my notebook with detailed steps here: [api_data_collector.ipynb](api_data_collector.ipynb)

**Result**

Instead of randomly checking ~1,000 IPs per day, the pipeline downloads the entire blacklist, filters for IPs located in Europe and uses the daily quota to enrich European IPs only. This is the key efficiency gain: without this step, roughly 85% of the daily quota would be wasted on non-European IPs. Each day, the pipeline identifies approximately 1,500-2,000 European IPs, enriching around 995 IPs using the free quota. Each enrichment call counts as one request against the daily quota. If the quota runs out mid-run, the pipeline stops cleanly and saves all collected data up to that point.

**Output CSV columns**

Results are saved to abuseipdb_europe.csv. Each run appends new records to the existing file and automatically deduplicates by IP address and date, ensuring that the same IP is never counted twice on the same day. Running the collector daily builds a growing historical dataset over time, with the following fields:

| Column | Example |
|---|---|
| `ip_address` | 185.220.101.47 |
| `country_name` | Germany |
| `abuse_score` | 100 |
| `attack_categories` | SSH Abuse, Brute-Force |
| `total_reports` | 342 |
| `isp` | Hetzner Online GmbH |
| `is_tor` | True |
| `last_reported_at` | 2026-03-12 |

# Automating the script

On Windows, you can automate the script using Task Scheduler by creating a task named "Threat Collector", enabling "Run whether user is logged on or not" and setting a daily trigger for around 1:05 AM. In the Actions tab, configure it to run Python (for example, C:\Python312\python.exe) with threat_collector.py as the argument and set the working directory to the folder containing the script. To ensure everything runs smoothly, define the ABUSEIPDB_API_KEY as a system-wide environment variable (via System Properties > Environment Variables).

# Conclusion

Building this project came with several practical challenges, from managing API rate limits and working within the free AbuseIPDB quota to efficiently filtering, enriching, and maintaining a growing dataset. Developing the three-stage pipeline helped me better understand how to design reliable data workflows, work with external APIs and handle real-world limitations such as interruptions, duplicated records and incomplete data.

Beyond the technical aspects, this project shows how threat intelligence data can be turned into useful insights. By focusing on European IPs and collecting daily snapshots, the pipeline creates a historical view of malicious activity that can help identify attack trends, highlight high-risk hosting providers and support further analysis and visualization. Overall, this project was a practical exercise in building an automated data pipeline and extracting meaningful insights from a limited but valuable data source.