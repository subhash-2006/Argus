import math
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field

class LogEntry(BaseModel):
    ip: str
    method: str
    endpoint: str
    status_code: int
    user_agent: str
    raw_log: str
    timestamp: Optional[str] = None

def calculate_shannon_entropy(text: str) -> float:
    """Calculate the Shannon entropy of a text string."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)

# SQL Injection regex patterns
SQLI_PATTERNS = [
    r"(?i)\bUNION\b.*\bSELECT\b",
    r"(?i)\bSELECT\b.*\bFROM\b",
    r"(?i)CHAR\(\d+\)",
    r"(?i)--",
    r"(?i)\bOR\b\s+['\"]?1['\"]?\s*=\s*['\"]?1['\"]?",
    r"(?i)\bDROP\b\s+\bTABLE\b",
    r"(?i)\bINSERT\b\s+\bINTO\b",
    r"(?i)%27|%22|%20UNION%20|%20SELECT%20"
]

# Honeytoken endpoints
HONEYTOKEN_ENDPOINTS = [
    "/.env",
    "/wp-config.php",
    "/etc/passwd",
    "/.git",
    "/config.json",
    "/.aws/credentials",
    "/id_rsa"
]

# Cross-Site Scripting (XSS) regex patterns
XSS_PATTERNS = [
    r"(?i)<script\b",
    r"(?i)javascript:",
    r"(?i)onerror\s*=",
    r"(?i)onload\s*=",
    r"(?i)eval\(",
    r"(?i)alert\(",
    r"(?i)<iframe\b",
    r"(?i)%3Cscript",
    r"(?i)%3C%2Fscript"
]

from app.memory import episodic_memory
from app.ml_model import ml_classifier

def analyze_log_entry(entry: LogEntry) -> dict:
    ts = entry.timestamp or datetime.now(timezone.utc).isoformat()
    endpoint = entry.endpoint or ""
    raw_log = entry.raw_log or ""
    status_code = entry.status_code
    method = entry.method.upper()

    # 1. Calculate Shannon entropy
    endpoint_entropy = calculate_shannon_entropy(endpoint)

    # 2. Predict with CSIC 2010 Trained Machine Learning Model
    is_ml_anomaly, ml_confidence = ml_classifier.predict_anomaly(method, endpoint, raw_log)

    is_anomaly = False
    threat_type = "NORMAL"
    severity = "INFO"
    mitre_id = "N/A"
    rules_matched = []

    # Rule 1: Honeytoken Access
    for honeytoken in HONEYTOKEN_ENDPOINTS:
        if honeytoken in endpoint:
            is_anomaly = True
            threat_type = "HONEYTOKEN_ACCESS"
            severity = "CRITICAL" if honeytoken == "/.env" else "HIGH"
            mitre_id = "T1595"
            rules_matched.append(f"Honeytoken access detected: {honeytoken}")
            break

    # Rule 2: SQL Injection Detection
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, endpoint) or re.search(pattern, raw_log):
            is_anomaly = True
            if threat_type == "NORMAL":
                threat_type = "SQL_INJECTION"
                severity = "CRITICAL"
                mitre_id = "T1190"
            rules_matched.append(f"SQL Injection pattern matched: {pattern}")
            break

    # Rule 2.5: Cross-Site Scripting (XSS) Detection
    for pattern in XSS_PATTERNS:
        if re.search(pattern, endpoint) or re.search(pattern, raw_log):
            is_anomaly = True
            if threat_type == "NORMAL":
                threat_type = "XSS_ATTACK"
                severity = "HIGH"
                mitre_id = "T1059.007"
            rules_matched.append(f"XSS pattern matched: {pattern}")
            break

    # Rule 2.7: Privilege Escalation Detection
    priv_esc_patterns = [
        r"(?i)\bprivilege[-_ ]escalation\b",
        r"(?i)\bunauthorized\s+sudo\b",
        r"(?i)\bsudoers\b",
        r"(?i)\bpolkit\b",
        r"(?i)\bsetuid\b",
        r"(?i)\brole[-_ ]escalation\b",
        r"(?i)\bsu\s+root\b"
    ]
    for pattern in priv_esc_patterns:
        if re.search(pattern, raw_log) or re.search(pattern, endpoint):
            is_anomaly = True
            if threat_type == "NORMAL":
                threat_type = "PRIVILEGE_ESCALATION"
                severity = "CRITICAL"
                mitre_id = "T1548"
            rules_matched.append(f"Privilege escalation indicator matched: {pattern}")
            break

    # Rule 2.8: Rate Limit / High Request Rate Abuse
    rate_abuse_patterns = [
        r"(?i)\bhigh\s+request\s+rate\b",
        r"(?i)\brate\s+limit\b",
        r"(?i)\btoo\s+many\s+requests\b",
        r"(?i)\brequest\s+rate\s+exceeded\b"
    ]
    if status_code == 429:
        is_anomaly = True
        if threat_type == "NORMAL":
            threat_type = "RATE_LIMIT_ABUSE"
            severity = "HIGH"
            mitre_id = "T1499"
        rules_matched.append(f"HTTP 429 Rate limit / High request volume detected for {endpoint}")
    else:
        for pattern in rate_abuse_patterns:
            if re.search(pattern, raw_log) or re.search(pattern, endpoint):
                is_anomaly = True
                if threat_type == "NORMAL":
                    threat_type = "RATE_LIMIT_ABUSE"
                    severity = "HIGH"
                    mitre_id = "T1499"
                rules_matched.append(f"High request rate abuse indicator matched: {pattern}")
                break

    # Rule 3: Brute Force / Auth Failure / Invalid Token Detection
    auth_fail_patterns = [
        r"(?i)\bfailed\s+password\b",
        r"(?i)\bfailed\s+ssh\b",
        r"(?i)\bfailed\s+login\b",
        r"(?i)\blogin\s+failed\b",
        r"(?i)\bauthentication\s+failure\b",
        r"(?i)\bauth_failure\b",
        r"(?i)\binvalid\s+(?:api\s+)?token\b",
        r"(?i)\bunauthorized\s+token\b",
        r"(?i)\btoken_expired\b",
        r"(?i)\bjwt_invalid\b",
        r"(?i)\binvalid\s+user\b"
    ]
    is_auth_fail = any(re.search(pat, raw_log) or re.search(pat, endpoint) for pat in auth_fail_patterns)

    if status_code == 401 or "/api/v1/auth" in endpoint or is_auth_fail:
        is_anomaly = True
        if threat_type == "NORMAL":
            threat_type = "BRUTE_FORCE"
            severity = "HIGH" if ("/login" in endpoint or "/auth" in endpoint or "password" in raw_log.lower() or "token" in raw_log.lower()) else "MEDIUM"
            mitre_id = "T1110"
        rules_matched.append(f"Auth failure / Brute force / Invalid token detected for {endpoint}")
    elif "/admin" in endpoint and status_code in [403, 401, 500]:
        is_anomaly = True
        if threat_type == "NORMAL":
            threat_type = "UNAUTHORIZED_ADMIN_ACCESS"
            severity = "HIGH"
            mitre_id = "T1078"
        rules_matched.append(f"Suspicious access attempt to admin endpoint: {endpoint}")

    # Rule 3.5: Suspicious Input Indicator
    suspicious_input_patterns = [
        r"(?i)\bsuspicious\s+input\b",
        r"(?i)\bmalicious\s+payload\b",
        r"(?i)\binput\s+validation\s+failure\b"
    ]
    for pattern in suspicious_input_patterns:
        if re.search(pattern, raw_log) or re.search(pattern, endpoint):
            is_anomaly = True
            if threat_type == "NORMAL":
                threat_type = "SQL_INJECTION" if ("sqli" in raw_log.lower() or "select" in raw_log.lower()) else "SECURITY_ANOMALY"
                severity = "HIGH"
                mitre_id = "T1190"
            rules_matched.append(f"Suspicious input pattern matched: {pattern}")
            break

    # Rule 4: High Entropy Anomaly
    if endpoint_entropy > 4.5:
        is_anomaly = True
        if threat_type == "NORMAL":
            threat_type = "ANOMALOUS_ENTROPY"
            severity = "MEDIUM"
            mitre_id = "T1027"
        rules_matched.append(f"High Shannon entropy ({endpoint_entropy}) detected in URL endpoint")

    # Rule 5: ML Model Detection Trigger (only if no rule fired and ML probability >= 0.9)
    if not is_anomaly and ml_confidence >= 0.9:
        is_anomaly = True
        threat_type = "ML_CLASSIFIED_ANOMALY"
        severity = "CRITICAL" if ml_confidence > 0.97 else "MEDIUM"
        mitre_id = "T1083"
        rules_matched.append(f"CSIC 2010 Trained ML Model Flagged Anomaly (Confidence: {ml_confidence * 100:.1f}%)")

    # Ensure NORMAL when no rule fires and ML probability is below 0.9
    if not is_anomaly:
        threat_type = "NORMAL"
        severity = "INFO"
        mitre_id = "N/A"
        rules_matched = []

    final_rule_matched = rules_matched if rules_matched else ["None"]

    # Record event into Episodic Memory chain if anomalous
    if is_anomaly:
        episodic_memory.add_event(
            ip=entry.ip,
            endpoint=endpoint,
            threat_type=threat_type,
            severity=severity
        )

    import uuid
    inc_id = f"INC-{uuid.uuid4().hex[:8].upper()}"

    return {
        "incident_id": inc_id,
        "timestamp": ts,
        "ip": entry.ip,
        "method": method,
        "endpoint": endpoint,
        "status_code": status_code,
        "user_agent": entry.user_agent,
        "raw_log": raw_log,
        "shannon_entropy": endpoint_entropy,
        "ml_anomaly_prob": ml_confidence,
        "is_anomaly": is_anomaly,
        "threat_type": threat_type,
        "severity": severity,
        "mitre_id": mitre_id,
        "rule_matched": final_rule_matched,
    }
