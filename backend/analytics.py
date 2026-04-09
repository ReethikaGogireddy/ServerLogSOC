from collections import Counter, defaultdict
from datetime import datetime, timedelta
from urllib.parse import urlparse


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


def get_most_accessed_pages(entries, n=5):
    logs = valid_entries(entries)
    counts = Counter(e.get("path") for e in logs if e.get("path"))
    return [{"path": p, "count": c} for p, c in counts.most_common(n)]


def get_least_accessed_pages(entries, n=5):
    logs = valid_entries(entries)
    counts = Counter(e.get("path") for e in logs if e.get("path"))
    least = sorted(counts.items(), key=lambda x: (x[1], x[0]))[:n]
    return [{"path": p, "count": c} for p, c in least]


def get_top_ips(entries, n=5):
    logs = valid_entries(entries)
    counts = Counter(e.get("ip") for e in logs if e.get("ip"))
    return [{"ip": ip, "count": c} for ip, c in counts.most_common(n)]


def get_most_active_ip(entries):
    top_ips = get_top_ips(entries, 1)
    return top_ips[0] if top_ips else None


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


def build_event_feed(entries):
    alerts = []
    alerts.extend(detect_404_scanning(entries))
    alerts.extend(detect_429_abuse(entries))
    alerts.extend(detect_burst_activity(entries))
    alerts.extend(detect_sensitive_access(entries))

    return sorted(alerts, key=lambda x: x.get("time") or "")


def analyze_logs(entries):
    return {
        "most_accessed_pages": get_most_accessed_pages(entries),
        "least_accessed_pages": get_least_accessed_pages(entries),
        "top_ips": get_top_ips(entries),
        "most_active_ip": get_most_active_ip(entries),
        "status_breakdown": get_status_breakdown(entries),
        "device_breakdown": get_device_breakdown(entries),
        "top_referrers": get_top_referrers(entries),
        "timeline": get_timeline(entries),
        "event_feed": build_event_feed(entries),
    }