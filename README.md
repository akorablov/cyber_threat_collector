# Overview

This project was developed to gather and analyze malicious IP intelligence with a focus on European networks. It retrieves suspicious IP addresses from the community-driven blacklist maintained by AbuseIPDB, a platform where system administrators, hosting providers, security researchers, and automated honeypot systems report malicious activity observed on their infrastructure. Each report contributes to a confidence score, creating a continuously updated list of IP addresses suspected of participating in activities such as brute-force attacks, port scanning, spam campaigns, or other forms of abuse.

The project collects daily snapshots of this blacklist, filters for European IP addresses, and enriches them with additional threat intelligence such as ISP information, attack categories, and TOR exit node status. The resulting dataset acts as a structured “snapshot” of potentially malicious activity originating from European networks at a given moment in time. Over time, the accumulated data can be used to explore trends, identify which hosting providers or regions are most frequently associated with abuse reports, and build visualizations or analyses based on real-world cybersecurity data.

# What It Is Good For

- Tracking which European ISPs/hosting providers host the most malicious IPs
- Seeing which attack types are most common (SSH brute-force, port scanning, etc.)
- Spotting trends over time as you accumulate daily snapshots
- A solid, real-world dataset for cybersecurity research and visualization

# How It Works

This project uses a three-stage collection pipeline to maximize the free API quota.

| Stage | API | Cost | What it does |
|---|---|---|---|
| 1 | AbuseIPDB `/blacklist` | 1 request | Downloads all 10,000 IPs |
| 2 | ip-api.com batch | Free, no key | Geolocates all 10,000 IPs at once |
| 3 | AbuseIPDB `/check` | 1 req per EU IP | Gets ISP, TOR, attack categories for European IPs only |

To run the project, you will need a free API key from AbuseIPDB. No credit card is required. To obtain a key, register at abuseipdb.com/register using your email address and a password, then verify your email. After logging in, navigate to Account > API in the top menu and click Create Key. Give the key any name, confirm the creation, and copy the generated value. Paste the API key into the script before running the project.

```python
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "PASTE_YOUR_KEY_HERE")
```
The free tier of AbuseIPDB allows 1,000 API requests per day, resetting at midnight UTC. The free tier of ip-api.com allows 15 batch requests per minute, so the geolocation stage typically takes about 7-8 minutes per run. When the script starts, it checks the remaining API quota and exits cleanly with a clear message if the daily limit has already been reached.

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

Instead of randomly checking ~1,000 IPs per day, the pipeline downloads the entire blacklist, filters for IPs located in Europe, and uses the daily quota to enrich European IPs only. This is the key efficiency gain: without this step, roughly 85% of the daily quota would be wasted on non-European IPs. Each day, the pipeline identifies approximately 1,500-2,000 European IPs, enriching around 995 IPs using the free quota. Each enrichment call counts as one request against the daily quota. If the quota runs out mid-run, the pipeline stops cleanly and saves all collected data up to that point.

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

# Conclusion

Developing this project presented several challenges, including managing API rate limits, efficiently filtering and enriching IPs while staying within the free AbuseIPDB quota and handling large datasets with deduplication and consistent formatting. Implementing the three-stage pipeline taught me how to optimize workflows, work with batch APIs, and build a resilient system that gracefully handles interruptions or quota exhaustion. I also gained deeper experience in data cleaning, aggregation, and automation, which are essential skills for any data analyst working with real-world cybersecurity datasets.

Beyond technical skills, this project demonstrates the practical importance of threat intelligence. By focusing on European IPs and maintaining daily snapshots, it creates a structured historical record of malicious activity that can be used to track attack patterns, identify high-risk hosting providers, and support research or visualization efforts. The resulting dataset is not only a powerful tool for cybersecurity analysis, but also a showcase of how efficient data pipelines can extract maximum value from limited resources.