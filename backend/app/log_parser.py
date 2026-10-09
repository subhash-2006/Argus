import csv
import io
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple
from app.engine import LogEntry

# Regex for Common / Combined Log Format (Apache / Nginx)
CLF_REGEX = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<endpoint>\S+)\s+HTTP/[^"]+"\s+(?P<status_code>\d{3})\s+(?P<size>\S+)(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

# Fallback pattern for simple logs: IP METHOD ENDPOINT STATUS
SIMPLE_LOG_REGEX = re.compile(
    r'(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+)\s+.*?["\']?(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(?P<endpoint>/\S*)\s+.*? (?P<status_code>\d{3})'
)

# Secret redaction pattern
SECRET_PATTERNS = [
    (re.compile(r'(?i)(password|pwd|pass|secret|token|api_key|access_token|authorization)=([^&\s]+)'), r'\1=[REDACTED]'),
    (re.compile(r'(?i)(Bearer\s+)[A-Za-z0-9\-\._~\+\/]+=*'), r'\1[REDACTED]'),
]

def redact_sensitive_data(text: str) -> str:
    """Redacts credentials, secrets, and auth tokens from log strings."""
    if not text:
        return ""
    result = text
    for pattern, replacement in SECRET_PATTERNS:
        result = pattern.sub(replacement, result)
    return result

def parse_csv_content(content: str) -> Tuple[List[LogEntry], int, int]:
    entries = []
    valid = 0
    invalid = 0
    reader = csv.reader(io.StringIO(content))
    header = None

    rows = list(reader)
    if not rows:
        return entries, valid, invalid

    # Check if first row is header
    first_row = [c.strip().lower() for c in rows[0]]
    if any(h in first_row for h in ['ip', 'method', 'endpoint', 'url', 'status_code', 'status', 'raw_log']):
        header = first_row
        rows = rows[1:]

    for row in rows:
        if not row or all(c.strip() == "" for c in row):
            continue
        try:
            ip = "127.0.0.1"
            method = "GET"
            endpoint = "/"
            status_code = 200
            user_agent = "Mozilla/5.0 (Uploaded Log)"
            raw_log = ",".join(row)
            timestamp = datetime.now(timezone.utc).isoformat()

            if header:
                row_dict = {header[i]: row[i] for i in range(min(len(header), len(row)))}
                ip = row_dict.get('ip') or row_dict.get('client_ip') or row_dict.get('host') or ip
                method = (row_dict.get('method') or row_dict.get('http_method') or method).upper()
                endpoint = row_dict.get('endpoint') or row_dict.get('url') or row_dict.get('uri') or row_dict.get('path') or endpoint
                
                st_raw = row_dict.get('status_code') or row_dict.get('status') or row_dict.get('code')
                if st_raw and str(st_raw).isdigit():
                    status_code = int(st_raw)
                
                user_agent = row_dict.get('user_agent') or row_dict.get('agent') or user_agent
                timestamp = row_dict.get('timestamp') or row_dict.get('time') or timestamp
                raw_log = row_dict.get('raw_log') or raw_log
            else:
                # Unheadered CSV: heuristic mapping
                for col in row:
                    col_s = col.strip()
                    if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', col_s):
                        ip = col_s
                    elif col_s.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']:
                        method = col_s.upper()
                    elif col_s.startswith('/'):
                        endpoint = col_s
                    elif col_s.isdigit() and len(col_s) == 3:
                        status_code = int(col_s)

            entries.append(LogEntry(
                ip=ip,
                method=method,
                endpoint=redact_sensitive_data(endpoint),
                status_code=status_code,
                user_agent=redact_sensitive_data(user_agent),
                raw_log=redact_sensitive_data(raw_log),
                timestamp=timestamp
            ))
            valid += 1
        except Exception:
            invalid += 1

    return entries, valid, invalid

def parse_json_content(content: str) -> Tuple[List[LogEntry], int, int]:
    entries = []
    valid = 0
    invalid = 0
    
    try:
        data = json.loads(content)
        if isinstance(data, dict):
            items = [data]
        elif isinstance(data, list):
            items = data
        else:
            items = []

        for item in items:
            if not isinstance(item, dict):
                invalid += 1
                continue
            
            ip = item.get('ip') or item.get('client_ip') or item.get('host') or '127.0.0.1'
            method = (item.get('method') or item.get('http_method') or 'GET').upper()
            endpoint = item.get('endpoint') or item.get('url') or item.get('path') or '/'
            st_raw = item.get('status_code') or item.get('status') or 200
            try:
                status_code = int(st_raw)
            except Exception:
                status_code = 200
            user_agent = item.get('user_agent') or item.get('agent') or 'Mozilla/5.0 (Uploaded JSON Log)'
            raw_log = item.get('raw_log') or json.dumps(item)
            timestamp = item.get('timestamp') or item.get('time') or datetime.now(timezone.utc).isoformat()

            entries.append(LogEntry(
                ip=ip,
                method=method,
                endpoint=redact_sensitive_data(endpoint),
                status_code=status_code,
                user_agent=redact_sensitive_data(user_agent),
                raw_log=redact_sensitive_data(raw_log),
                timestamp=timestamp
            ))
            valid += 1
    except Exception:
        invalid += 1

    return entries, valid, invalid

def parse_jsonl_content(content: str) -> Tuple[List[LogEntry], int, int]:
    entries = []
    valid = 0
    invalid = 0

    lines = content.splitlines()
    for line in lines:
        line_str = line.strip()
        if not line_str:
            continue
        try:
            item = json.loads(line_str)
            if not isinstance(item, dict):
                invalid += 1
                continue
            
            ip = item.get('ip') or item.get('client_ip') or item.get('host') or '127.0.0.1'
            method = (item.get('method') or item.get('http_method') or 'GET').upper()
            endpoint = item.get('endpoint') or item.get('url') or item.get('path') or '/'
            st_raw = item.get('status_code') or item.get('status') or 200
            try:
                status_code = int(st_raw)
            except Exception:
                status_code = 200
            user_agent = item.get('user_agent') or item.get('agent') or 'Mozilla/5.0 (Uploaded JSONL Log)'
            raw_log = item.get('raw_log') or line_str
            timestamp = item.get('timestamp') or item.get('time') or datetime.now(timezone.utc).isoformat()

            entries.append(LogEntry(
                ip=ip,
                method=method,
                endpoint=redact_sensitive_data(endpoint),
                status_code=status_code,
                user_agent=redact_sensitive_data(user_agent),
                raw_log=redact_sensitive_data(raw_log),
                timestamp=timestamp
            ))
            valid += 1
        except Exception:
            invalid += 1

    return entries, valid, invalid

def parse_text_log_content(content: str) -> Tuple[List[LogEntry], int, int]:
    entries = []
    valid = 0
    invalid = 0

    lines = content.splitlines()
    for line in lines:
        line_str = line.strip()
        if not line_str:
            continue

        # Try CLF regex
        m = CLF_REGEX.search(line_str)
        if m:
            gd = m.groupdict()
            try:
                st = int(gd['status_code'])
            except Exception:
                st = 200
            entries.append(LogEntry(
                ip=gd['ip'],
                method=gd['method'],
                endpoint=redact_sensitive_data(gd['endpoint']),
                status_code=st,
                user_agent=redact_sensitive_data(gd.get('user_agent') or "Common Log Format"),
                raw_log=redact_sensitive_data(line_str),
                timestamp=gd.get('timestamp') or datetime.now(timezone.utc).isoformat()
            ))
            valid += 1
            continue

        # Try simple regex
        m_simple = SIMPLE_LOG_REGEX.search(line_str)
        if m_simple:
            gd = m_simple.groupdict()
            try:
                st = int(gd['status_code'])
            except Exception:
                st = 200
            entries.append(LogEntry(
                ip=gd['ip'],
                method=gd['method'],
                endpoint=redact_sensitive_data(gd['endpoint']),
                status_code=st,
                user_agent="Plain Text Log",
                raw_log=redact_sensitive_data(line_str),
                timestamp=datetime.now(timezone.utc).isoformat()
            ))
            valid += 1
            continue

        # General unformatted log line fallback
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line_str)
        ip_val = ip_match.group(0) if ip_match else "127.0.0.1"

        method_match = re.search(r'\b(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\b', line_str)
        method_val = method_match.group(0) if method_match else "GET"

        endpoint_match = re.search(r'(/[a-zA-Z0-9_\-\.\?%&=/]*)\b', line_str)
        endpoint_val = endpoint_match.group(0) if endpoint_match else "/"

        status_match = re.search(r'\b([1-5]\d{2})\b', line_str)
        status_val = int(status_match.group(0)) if status_match else 200

        entries.append(LogEntry(
            ip=ip_val,
            method=method_val,
            endpoint=redact_sensitive_data(endpoint_val),
            status_code=status_val,
            user_agent="Generic Log File",
            raw_log=redact_sensitive_data(line_str),
            timestamp=datetime.now(timezone.utc).isoformat()
        ))
        valid += 1

    return entries, valid, invalid

def parse_uploaded_file(filename: str, content_bytes: bytes, max_entries: int = 2000) -> Tuple[List[LogEntry], int, int]:
    """
    Parses uploaded log content from bytes into LogEntry items.
    Validates file extension, structure, and entry limits.
    """
    # Detect encoding
    try:
        content_str = content_bytes.decode('utf-8')
    except UnicodeDecodeError:
        content_str = content_bytes.decode('latin-1', errors='replace')

    ext = filename.lower().split('.')[-1] if '.' in filename else ''

    # Determine format by content & extension
    stripped = content_str.strip()
    if ext == 'csv' or (',' in stripped and '\n' in stripped and not stripped.startswith('{') and not stripped.startswith('[')):
        entries, valid, invalid = parse_csv_content(content_str)
    elif ext in ['jsonl', 'ndjson']:
        entries, valid, invalid = parse_jsonl_content(content_str)
    elif ext == 'json' or (stripped.startswith('{') or stripped.startswith('[')):
        entries, valid, invalid = parse_json_content(content_str)
    else:
        entries, valid, invalid = parse_text_log_content(content_str)

    # Limit max entries
    if len(entries) > max_entries:
        entries = entries[:max_entries]

    return entries, valid, invalid
