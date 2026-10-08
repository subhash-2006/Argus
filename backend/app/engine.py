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
    rule_matched = "None"

    # Rule 1: Honeytoken Access
    for honeytoken in HONEYTOKEN_ENDPOINTS:
        if honeytoken in endpoint:
            is_anomaly = True
            threat_type = "HONEYTOKEN_ACCESS"
            severity = "CRITICAL" if honeytoken == "/.env" else "HIGH"
            mitre_id = "T1595"
            rule_matched = f"Honeytoken access detected: {honeytoken}"
            break

    # Rule 2: SQL Injection Detection
    if not is_anomaly:
        for pattern in SQLI_PATTERNS:
            if re.search(pattern, endpoint) or re.search(pattern, raw_log):
                is_anomaly = True
                threat_type = "SQL_INJECTION"
                severity = "CRITICAL"
                mitre_id = "T1190"
                rule_matched = f"SQL Injection pattern matched: {pattern}"
                break

    # Rule 3: Brute Force / Unauthorized Access
    if not is_anomaly:
        if status_code == 401 or "/api/v1/auth" in endpoint:
            is_anomaly = True
            threat_type = "BRUTE_FORCE"
            severity = "HIGH" if "/login" in endpoint or "/auth" in endpoint else "MEDIUM"
            mitre_id = "T1110"
            rule_matched = f"HTTP 401 / Auth brute force response for {endpoint}"
        elif "/admin" in endpoint and status_code in [403, 401, 500]:
            is_anomaly = True
            threat_type = "UNAUTHORIZED_ADMIN_ACCESS"
            severity = "HIGH"
            mitre_id = "T1078"
            rule_matched = f"Suspicious access attempt to admin endpoint: {endpoint}"

    # Rule 4: High Entropy Anomaly
    if not is_anomaly and endpoint_entropy > 4.5:
        is_anomaly = True
        threat_type = "ANOMALOUS_ENTROPY"
        severity = "MEDIUM"
        mitre_id = "T1027"
        rule_matched = f"High Shannon entropy ({endpoint_entropy}) detected in URL endpoint"

    # Rule 5: ML Model Detection Trigger (only if no rule fired and ML probability >= 0.9)
    if not is_anomaly and ml_confidence >= 0.9:
        is_anomaly = True
        threat_type = "ML_CLASSIFIED_ANOMALY"
        severity = "CRITICAL" if ml_confidence > 0.97 else "MEDIUM"
        mitre_id = "T1083"
        rule_matched = f"CSIC 2010 Trained ML Model Flagged Anomaly (Confidence: {ml_confidence * 100:.1f}%)"

    # Ensure NORMAL when no rule fires and ML probability is below 0.9
    if not is_anomaly:
        threat_type = "NORMAL"
        severity = "INFO"
        mitre_id = "N/A"
        rule_matched = "None"

    # Record event into Episodic Memory chain if anomalous
    if is_anomaly:
        episodic_memory.add_event(
            ip=entry.ip,
            endpoint=endpoint,
            threat_type=threat_type,
            severity=severity
        )

    return {
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
        "rule_matched": rule_matched,
    }
