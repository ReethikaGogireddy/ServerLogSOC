from pathlib import Path
import re
from datetime import datetime
from typing import Optional, List, Dict, Any

LOG_LINE_REGEX = re.compile(
    r'^(?P<ip>\S+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\S+)\s+'
    r'(?P<size>\S+)\s+'
    r'"(?P<referrer>[^"]*)"\s+'
    r'"(?P<user_agent>[^"]*)"\s*$'
)

# This regex is designed to capture the method, path, and protocol from the request line.
# It basically checks if the request starts with uppercase letters (method), followed by a space, then a non-space sequence (path), and optionally followed by another space and the protocol version.
#Example request line: GET /home HTTP/1.1
REQUEST_REGEX = re.compile(r'^(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+(?P<protocol>HTTP/\d\.\d))?$')


def parse_timestamp(ts: str) -> Optional[str]:
    """
    Example input:
    27/Nov/2019:02:20:36 -0800
    Output:
    ISO string if possible, otherwise original string.
    """
    try:
        dt = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
        return dt.isoformat()
    except ValueError:
        return ts

# Parses the request line into method, path, and protocol.
def parse_request(request: str) -> Dict[str, Any]:
    """
    Example request:
    GET /home HTTP/1.1
    """
    match = REQUEST_REGEX.match(request.strip())
    if not match:
        return {
            "method": None,
            "path": None,
            "protocol": None,
            "raw_request": request
        }

    return {
        "method": match.group("method"),
        "path": match.group("path"),
        "protocol": match.group("protocol"),
        "raw_request": request
    }

# Parses a single log line into a structured dictionary. If parsing fails, returns a dictionary with a parse_error flag.
def parse_log_line(line: str) -> Optional[Dict[str, Any]]:
    line = line.strip()
    if not line:
        return None

    match = LOG_LINE_REGEX.match(line)
    if not match:
        return {
            "parse_error": True,
            "raw_line": line
        }

    request_data = parse_request(match.group("request"))

    status_raw = match.group("status")
    size_raw = match.group("size")

    try:
        status = int(status_raw)
    except ValueError:
        status = None

    try:
        size = int(size_raw)
    except ValueError:
        size = None

    return {
        "ip": match.group("ip"),
        "ident": match.group("ident"),
        "user": match.group("user"),
        "timestamp": parse_timestamp(match.group("timestamp")),
        "status": status,
        "size": size,
        "referrer": match.group("referrer"),
        "user_agent": match.group("user_agent"),
        **request_data,
        "raw_line": line
    }

# Reads a log file and parses each line into a structured dictionary.
def parse_log_file(file_path: Path) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []

    with file_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line_number, line in enumerate(f, start=1):
            parsed = parse_log_line(line)
            if parsed is None:
                continue

            parsed["source_file"] = file_path.name
            parsed["line_number"] = line_number
            entries.append(parsed)

    return entries


def parse_uploaded_logs(folder_path: str = "uploaded_logs") -> List[Dict[str, Any]]:
    """
    Reads every file in uploaded_logs/ and parses them into structured rows.
    """
    folder = Path(folder_path)
    if not folder.exists():
        raise FileNotFoundError(f"Folder not found: {folder.resolve()}")

    all_entries: List[Dict[str, Any]] = []

    for file_path in sorted(folder.iterdir()):
        if file_path.is_file():
            all_entries.extend(parse_log_file(file_path))
    
    print(f"Parsed {len(all_entries)} log entries from {folder_path}")

    return all_entries