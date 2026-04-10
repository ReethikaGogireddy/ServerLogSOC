from collections import Counter, defaultdict
from datetime import datetime, timedelta
from urllib.parse import urlparse
import os
import requests
from dotenv import load_dotenv


load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

SUSPICIOUS_PATHS = [
    "/admin", "/login", "/wp-login", "/phpmyadmin",
    "/backup", "/bak", "/self.logs", ".log", ".gz",
    "/sqlbf", "/bf", "/diguo", "/etc/passwd"
]

BOT_HINTS = ["bot", "spider", "crawler", "python-requests", "scrapy", "curl", "wget"]


def valid_entries(entries):
    return [e for e in entries if isinstance(e, dict) and not e.get("parse_error")]


def parse_time(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None

# Returns the most accessed pages by request count. 
# This can help identify which endpoints are most frequently used and may warrant closer security review.
def get_most_accessed_pages(entries, n=5):
    logs = valid_entries(entries)
    counts = Counter(e.get("path") for e in logs if e.get("path"))
    return [{"path": p, "count": c} for p, c in counts.most_common(n)]

# Returns the least accessed pages by request count. 
# This can help identify rarely used endpoints that may be overlooked but could be sensitive or vulnerable.
def get_least_accessed_pages(entries, n=5):
    logs = valid_entries(entries)
    counts = Counter(e.get("path") for e in logs if e.get("path"))
    least = sorted(counts.items(), key=lambda x: (x[1], x[0]))[:n]
    return [{"path": p, "count": c} for p, c in least]

# Returns the top N IP addresses by request count. 
# This can help identify which clients are most active on the server.
def get_top_ips(entries, n=5):
    logs = valid_entries(entries)
    counts = Counter(e.get("ip") for e in logs if e.get("ip"))
    return [{"ip": ip, "count": c} for ip, c in counts.most_common(n)]

# Returns the single most active IP address based on request count.
# This can help identify potential attackers or heavy users.
def get_most_active_ip(entries):
    top_ips = get_top_ips(entries, 1)
    return top_ips[0] if top_ips else None

# Classifies HTTP status codes into broader categories for a high-level breakdown of allowed vs blocked vs error responses.
def get_status_breakdown(entries):
    logs = valid_entries(entries)
    counts = Counter()

    for e in logs:
        status = e.get("status")
        if status is None:
            continue

        if 200 <= status < 300:
            counts["Allowed"] += 1
        elif status in (401, 403, 404, 429):
            counts["Blocked"] += 1
        elif 500 <= status < 600:
            counts["Server Error"] += 1
        else:
            counts["Other"] += 1

    return dict(counts)

# Classifies device type based on user agent string. 
# This is a heuristic approach and may not be 100% accurate, 
# but it can provide a general breakdown of desktop vs mobile vs bot traffic.
def get_device_breakdown(entries):
    logs = valid_entries(entries)
    counts = Counter()

    for e in logs:
        ua = (e.get("user_agent") or "").lower()
        if any(h in ua for h in BOT_HINTS):
            counts["Bot"] += 1
        elif "mobile" in ua:
            counts["Mobile"] += 1
        elif "tablet" in ua:
            counts["Tablet"] += 1
        else:
            counts["Desktop"] += 1

    return dict(counts)

# Extracts the top referrer domains from the log entries. 
# External Referrer tells from which sites users are coming.
# A high number of referrers from a single domain could indicate a potential source of traffic or an attack vector. 

def get_top_referrers(entries, n=5):
    logs = valid_entries(entries)
    domains = []

    for e in logs:
        ref = e.get("referrer")
        if not ref or ref == "-":
            continue

        try:
            parsed = urlparse(ref)
            if parsed.netloc:
                domains.append(parsed.netloc.lower())
        except Exception:
            pass

    counts = Counter(domains)
    return [{"domain": d, "count": c} for d, c in counts.most_common(n)]


def check_domain_virustotal(domain):
    if not domain or not VIRUSTOTAL_API_KEY:
        return {
            "domain": domain,
            "status": "no_api_key",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
        }

    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        res = requests.get(url, headers=headers, timeout=3)

        if res.status_code != 200:
            return {
                "domain": domain,
                "status": f"error_{res.status_code}",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
            }

        data = res.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]

        return {
            "domain": domain,
            "status": "ok",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }

    except requests.Timeout:
        return {
            "domain": domain,
            "status": "timeout",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
        }
    except Exception as e:
        return {
            "domain": domain,
            "status": "failed",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
        }

def enrich_referrers_with_virustotal(top_referrers):
    """
    Enrich referrers with VirusTotal data.
    Skips VirusTotal check if no API key to avoid blocking.
    Only checks top 5 domains to avoid rate limiting.
    """
    if not VIRUSTOTAL_API_KEY:
        return top_referrers
    
    enriched = []
    
    # Only check top 5 to avoid rate limiting and timeouts
    for idx, item in enumerate(top_referrers[:5]):
        domain = item.get("domain")
        vt = check_domain_virustotal(domain)
        
        enriched.append({
            **item,
            "virustotal": vt
        })
    
    # Return rest without VirusTotal data
    enriched.extend(top_referrers[5:])
    
    return enriched

def get_timeline(entries, bucket_minutes=120):
    logs = valid_entries(entries)
    buckets = defaultdict(int)

    for e in logs:
        dt = parse_time(e.get("timestamp"))
        if not dt:
            continue

        # bucket by 2 hours by default
        bucket_hour = (dt.hour // (bucket_minutes // 60)) * (bucket_minutes // 60)
        bucket_time = dt.replace(hour=bucket_hour, minute=0, second=0, microsecond=0)
        buckets[bucket_time.isoformat()] += 1

    return [{"time": t, "count": c} for t, c in sorted(buckets.items())]


def is_suspicious_path(path):
    p = (path or "").lower()
    return any(s in p for s in SUSPICIOUS_PATHS)

# Detects potential sensitive file access by looking for requests to paths that match common sensitive endpoints or file patterns.
def detect_sensitive_access(entries):
    logs = valid_entries(entries)
    alerts = []

    for e in logs:
        path = e.get("path", "")
        if is_suspicious_path(path):
            alerts.append({
                "time": e.get("timestamp"),
                "ip": e.get("ip"),
                "type": "Sensitive File Access",
                "severity": "high",
                "reason": f"Suspicious path accessed: {path}",
                "confidence": 0.90
            })

    return alerts

# Detects potential data exfiltration by looking for multiple large downloads of sensitive files from the same IP address.
def detect_data_exfiltration(entries):
    valid = valid_entries(entries)
    by_ip = defaultdict(list)

    for e in valid:
        ip = e.get("ip")
        if ip:
            by_ip[ip].append(e)

    alerts = []

    for ip, logs in by_ip.items():
        sensitive_hits = []

        for e in logs:
            path = (e.get("path") or "").lower()
            size = e.get("size") or 0

            if is_suspicious_path(path):
                sensitive_hits.append(e)

        large_downloads = [e for e in sensitive_hits if (e.get("size") or 0) > 10000]

        if len(large_downloads) >= 3:
            total_size = sum(e.get("size") or 0 for e in large_downloads)

            alerts.append({
                "ip": ip,
                "type": "Data Exfiltration",
                "severity": "high",
                "reason": f"{len(large_downloads)} large sensitive downloads, total size {total_size}",
                "confidence": 0.95
            })

    return alerts

# Detects potential directory scanning by looking for a high number of 404 Not Found responses from the same IP across multiple unique paths.
def detect_404_scanning(entries, min_404s=10, min_unique_paths=5):
    logs = valid_entries(entries)
    by_ip = defaultdict(list)

    for e in logs:
        ip = e.get("ip")
        if ip:
            by_ip[ip].append(e)

    alerts = []

    for ip, items in by_ip.items():
        not_found = [e for e in items if e.get("status") == 404]
        unique_paths = {e.get("path") for e in not_found if e.get("path")}

        if len(not_found) >= min_404s and len(unique_paths) >= min_unique_paths:
            times = [parse_time(e.get("timestamp")) for e in not_found]
            times = [t for t in times if t]

            span_seconds = None
            if times:
                span_seconds = int((max(times) - min(times)).total_seconds())

            alerts.append({
                "ip": ip,
                "type": "Directory Scanning",
                "severity": "high",
                "reason": f"{len(not_found)} 404 responses across {len(unique_paths)} paths",
                "confidence": 0.95 if span_seconds is not None and span_seconds <= 300 else 0.85,
                "count_404": len(not_found),
                "unique_paths": len(unique_paths),
            })

    return alerts

# Detects potential scraping or brute force activity by looking for a high number of 429 Too Many Requests responses from the same IP.
def detect_429_abuse(entries, min_429s=5):
    logs = valid_entries(entries)
    by_ip = defaultdict(list)

    for e in logs:
        ip = e.get("ip")
        if ip:
            by_ip[ip].append(e)

    alerts = []

    for ip, items in by_ip.items():
        hits = [e for e in items if e.get("status") == 429]
        if len(hits) >= min_429s:
            alerts.append({
                "ip": ip,
                "type": "Scraping / Brute Force",
                "severity": "medium",
                "reason": f"{len(hits)} requests returned 429 Too Many Requests",
                "confidence": 0.88
            })

    return alerts

# Detects burst activity from an IP by looking for a high number of requests within a short time window.
def detect_burst_activity(entries, window_seconds=60, threshold=20):
    logs = valid_entries(entries)
    by_ip = defaultdict(list)

    for e in logs:
        ip = e.get("ip")
        dt = parse_time(e.get("timestamp"))
        if ip and dt:
            by_ip[ip].append(dt)

    alerts = []

    for ip, times in by_ip.items():
        times.sort()
        start = 0

        for end in range(len(times)):
            while (times[end] - times[start]).total_seconds() > window_seconds:
                start += 1

            if end - start + 1 >= threshold:
                alerts.append({
                    "ip": ip,
                    "type": "Burst Activity",
                    "severity": "medium",
                    "reason": f"{end - start + 1} requests in {window_seconds} seconds",
                    "confidence": 0.90
                })
                break

    return alerts

# Builds a unified event feed by combining the outputs of various detection functions.
# The sensitive access alerts are filtered to exclude any that come from IPs already flagged for potential data exfiltration,
# as those may be part of the same attack pattern and to avoid duplicate alerts.
def build_event_feed(entries):
    sensitive = detect_sensitive_access(entries)
    exfil = detect_data_exfiltration(entries)

    exfil_ips = {e["ip"] for e in exfil if e.get("ip")}

    filtered_sensitive = [
        e for e in sensitive if e.get("ip") not in exfil_ips
    ]
    alerts = []
    alerts.extend(detect_404_scanning(entries))
    alerts.extend(detect_429_abuse(entries))
    alerts.extend(detect_burst_activity(entries))
    alerts.extend(filtered_sensitive)
    alerts.extend(exfil)

    return sorted(alerts, key=lambda x: x.get("time") or "")

# Classifies an alert event into a broader attack category for distribution analysis.
def classify_attack(event):
    t = event.get("type", "").lower()

    if "scanning" in t:
        return "Scanning"
    elif "429" in t or "rate" in t or "brute" in t:
        return "Brute Force / Rate Abuse"
    elif "burst" in t:
        return "Burst Traffic"
    elif "sensitive" in t:
        return "Sensitive Access"
    elif "exfiltration" in t:
        return "Data Exfiltration"
    else:
        return "Other"

# Builds a distribution of attack types based on the generated event feed.
def get_attack_distribution(entries):
    events = build_event_feed(entries)

    categories = [classify_attack(e) for e in events]

    counts = Counter(categories)

    return [
        {"name": k, "value": v}
        for k, v in counts.items()
    ]


def analyze_logs(entries):
    result = {
        "most_accessed_pages": get_most_accessed_pages(entries),
        "least_accessed_pages": get_least_accessed_pages(entries),
        "top_ips": get_top_ips(entries),
        "most_active_ip": get_most_active_ip(entries),
        "status_breakdown": get_status_breakdown(entries),
        "device_breakdown": get_device_breakdown(entries),
        "top_referrers": get_top_referrers(entries),
        "timeline": get_timeline(entries),
        "event_feed": build_event_feed(entries),
        "attack_distribution": get_attack_distribution(entries)
    }

    # Enrich referrers with VirusTotal threat intelligence
    result["top_referrers"] = enrich_referrers_with_virustotal(result["top_referrers"])
    print(result["top_referrers"])

    return result