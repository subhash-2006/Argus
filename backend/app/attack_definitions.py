"""
Log Sentinel — Attack Definitions and Plain-English Explanations
Maps detection rules and threat types to concise, easy-to-understand definitions.
"""

from typing import Dict, Any, List, Optional

# Maintainable registry of attack categories and their plain-English definitions
ATTACK_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    "BRUTE_FORCE": {
        "display_name": "Brute-Force Attack",
        "short_definition": "An attacker repeatedly tries different passwords or credentials to gain unauthorized access to an account.",
        "severity": "HIGH",
        "priority": 70,
        "is_confirmed_attack": True,
        "mitre_id": "T1110"
    },
    "SQL_INJECTION": {
        "display_name": "SQL Injection",
        "short_definition": "An attacker tries to insert malicious database commands through an application input to access or alter sensitive data.",
        "severity": "CRITICAL",
        "priority": 100,
        "is_confirmed_attack": True,
        "mitre_id": "T1190"
    },
    "XSS_ATTACK": {
        "display_name": "Cross-Site Scripting (XSS)",
        "short_definition": "An attacker attempts to inject malicious script into a web page that may run in another user's browser.",
        "severity": "HIGH",
        "priority": 80,
        "is_confirmed_attack": True,
        "mitre_id": "T1059.007"
    },
    "HONEYTOKEN_ACCESS": {
        "display_name": "Directory Traversal / Sensitive File Access",
        "short_definition": "An attacker attempts to access files, configuration secrets, or folders outside the application's permitted directory.",
        "severity": "CRITICAL",
        "priority": 90,
        "is_confirmed_attack": True,
        "mitre_id": "T1595"
    },
    "PRIVILEGE_ESCALATION": {
        "display_name": "Privilege Escalation",
        "short_definition": "An attacker attempts to gain elevated administrative rights or bypass access control permissions.",
        "severity": "CRITICAL",
        "priority": 95,
        "is_confirmed_attack": True,
        "mitre_id": "T1548"
    },
    "RATE_LIMIT_ABUSE": {
        "display_name": "Rate Limit Abuse / Request Flooding",
        "short_definition": "An unusually high volume of automated requests was sent to the server, potentially attempting to exhaust resources or bypass limits.",
        "severity": "HIGH",
        "priority": 60,
        "is_confirmed_attack": True,
        "mitre_id": "T1499"
    },
    "UNAUTHORIZED_ADMIN_ACCESS": {
        "display_name": "Unauthorized Admin Access",
        "short_definition": "Repeated or unauthorized access attempts to administrative interfaces were detected without valid credentials.",
        "severity": "HIGH",
        "priority": 75,
        "is_confirmed_attack": True,
        "mitre_id": "T1078"
    },
    "SUSPICIOUS_AUTH": {
        "display_name": "Suspicious Authentication Activity",
        "short_definition": "Repeated or unusual login attempts may indicate an attempt to access an account without permission.",
        "severity": "MEDIUM",
        "priority": 50,
        "is_confirmed_attack": False,
        "mitre_id": "T1110"
    },
    "ANOMALOUS_ENTROPY": {
        "display_name": "High-Entropy or Encoded Payload",
        "short_definition": "A string contains unusual or random-looking characters that may require further investigation. This pattern alone does not prove an attack.",
        "severity": "MEDIUM",
        "priority": 40,
        "is_confirmed_attack": False,
        "mitre_id": "T1027"
    },
    "ML_CLASSIFIED_ANOMALY": {
        "display_name": "Anomalous Traffic Pattern",
        "short_definition": "This activity differs from the normal traffic patterns learned by the detection system and should be reviewed.",
        "severity": "MEDIUM",
        "priority": 45,
        "is_confirmed_attack": False,
        "mitre_id": "T1083"
    },
    "SECURITY_ANOMALY": {
        "display_name": "Suspicious HTTP Requests",
        "short_definition": "One or more web requests contain patterns that may indicate probing or an attempt to exploit an application.",
        "severity": "MEDIUM",
        "priority": 30,
        "is_confirmed_attack": False,
        "mitre_id": "T1190"
    },
    "SUSPICIOUS_ACTIVITY": {
        "display_name": "Suspicious Activity",
        "short_definition": "Unusual activity was flagged by the detection rules that differs from expected system behavior and requires further investigation.",
        "severity": "MEDIUM",
        "priority": 20,
        "is_confirmed_attack": False,
        "mitre_id": "N/A"
    }
}

# Fallback definition for completely unknown attack types
DEFAULT_FALLBACK_DEFINITION = {
    "display_name": "Suspicious Activity",
    "short_definition": "Unusual activity was flagged by the security rules that differs from expected system behavior and requires further investigation.",
    "severity": "MEDIUM",
    "priority": 10,
    "is_confirmed_attack": False,
    "mitre_id": "N/A"
}


def normalize_threat_key(threat_type: Optional[str]) -> str:
    """Normalizes a threat key string to match ATTACK_DEFINITIONS keys."""
    if not threat_type:
        return "SUSPICIOUS_ACTIVITY"
    clean = str(threat_type).strip().upper().replace(" ", "_").replace("-", "_")

    # Map common aliases or substring matches
    if "SQL" in clean:
        return "SQL_INJECTION"
    if "BRUTE" in clean or "AUTH_FAIL" in clean or "CREDENTIAL" in clean:
        return "BRUTE_FORCE"
    if "XSS" in clean or "SCRIPT" in clean:
        return "XSS_ATTACK"
    if "HONEY" in clean or "TRAVERSAL" in clean or "PASSWD" in clean:
        return "HONEYTOKEN_ACCESS"
    if "PRIVILEGE" in clean or "SUDO" in clean:
        return "PRIVILEGE_ESCALATION"
    if "RATE" in clean or "FLOOD" in clean or "DOS" in clean:
        return "RATE_LIMIT_ABUSE"
    if "ADMIN" in clean:
        return "UNAUTHORIZED_ADMIN_ACCESS"
    if "ENTROPY" in clean:
        return "ANOMALOUS_ENTROPY"
    if "ML" in clean or "CLASSIFIER" in clean or "ISOLATION" in clean:
        return "ML_CLASSIFIED_ANOMALY"
    if clean in ATTACK_DEFINITIONS:
        return clean
    return "SUSPICIOUS_ACTIVITY"


def get_attack_definition(threat_type: Optional[str], rule_matched: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Returns the attack definition object for a given threat type.
    Falls back safely to 'Suspicious Activity' if the category is unknown.
    """
    key = normalize_threat_key(threat_type)
    if key in ATTACK_DEFINITIONS:
        return ATTACK_DEFINITIONS[key]

    # Check rule_matched for clues before using default fallback
    if rule_matched:
        rule_str = " ".join(rule_matched).upper()
        if "SQL" in rule_str:
            return ATTACK_DEFINITIONS["SQL_INJECTION"]
        if "BRUTE" in rule_str or "AUTH" in rule_str:
            return ATTACK_DEFINITIONS["BRUTE_FORCE"]
        if "XSS" in rule_str or "SCRIPT" in rule_str:
            return ATTACK_DEFINITIONS["XSS_ATTACK"]
        if "HONEYTOKEN" in rule_str or "TRAVERSAL" in rule_str:
            return ATTACK_DEFINITIONS["HONEYTOKEN_ACCESS"]
        if "PRIVILEGE" in rule_str or "SUDO" in rule_str:
            return ATTACK_DEFINITIONS["PRIVILEGE_ESCALATION"]
        if "RATE" in rule_str or "429" in rule_str:
            return ATTACK_DEFINITIONS["RATE_LIMIT_ABUSE"]

    return DEFAULT_FALLBACK_DEFINITION


SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0
}


def summarize_threats_for_alert(anomalies: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Consolidates a list of suspicious anomaly findings from an analysis run.
    Identifies the highest-severity attack category, overall severity, threat count,
    and a summary of additional categories.
    """
    if not anomalies:
        return {
            "has_threats": False,
            "threat_count": 0,
            "highest_attack_name": "None",
            "highest_threat_key": "NORMAL",
            "severity": "INFO",
            "short_definition": "No suspicious activity detected.",
            "other_categories_summary": ""
        }

    threat_count = len(anomalies)

    # Track categories and count
    category_counts: Dict[str, int] = {}
    highest_severity_val = -1
    overall_severity = "LOW"

    scored_threats = []

    for item in anomalies:
        raw_threat = item.get("threat_type") or "SUSPICIOUS_ACTIVITY"
        normalized_key = normalize_threat_key(raw_threat)
        definition = get_attack_definition(normalized_key, item.get("rule_matched"))

        category_name = definition["display_name"]
        category_counts[category_name] = category_counts.get(category_name, 0) + 1

        item_sev = (item.get("severity") or definition.get("severity") or "MEDIUM").upper()
        sev_val = SEVERITY_ORDER.get(item_sev, 2)
        if sev_val > highest_severity_val:
            highest_severity_val = sev_val
            overall_severity = item_sev

        priority = definition.get("priority", 20) + (sev_val * 20)
        scored_threats.append((priority, normalized_key, definition, item_sev))

    # Sort to find the highest-priority attack
    scored_threats.sort(key=lambda x: x[0], reverse=True)
    best_match = scored_threats[0]
    best_key = best_match[1]
    best_def = best_match[2]

    # Formulate summary of other categories if multiple
    other_categories = []
    for cat_name, cnt in category_counts.items():
        if cat_name != best_def["display_name"]:
            other_categories.append(f"{cat_name} ({cnt})")

    other_summary = ", ".join(other_categories) if other_categories else ""

    return {
        "has_threats": True,
        "threat_count": threat_count,
        "highest_attack_name": best_def["display_name"],
        "highest_threat_key": best_key,
        "severity": overall_severity,
        "short_definition": best_def["short_definition"],
        "other_categories_summary": other_summary,
        "category_counts": category_counts
    }


def format_whatsapp_message(
    attack_name: str,
    severity: str,
    short_definition: str,
    threat_count: int,
    other_summary: Optional[str] = None
) -> str:
    """
    Formats the WhatsApp alert message strictly adhering to the specified format:

    *Log Sentinel — Security Alert*

    A suspicious threat has been detected in your log file.

    *Attack:* {actual_attack_name}

    *Severity:* {actual_severity}

    *What it means:* {short_attack_definition}

    *Suspicious activities:* {actual_threat_count}

    Please check the attached PDF report for the complete analysis and recommended actions.

    — Log Sentinel
    """
    definition_text = short_definition
    if other_summary:
        definition_text = f"{short_definition} Also detected: {other_summary}."

    msg = (
        "*Log Sentinel — Security Alert*\n\n"
        "A suspicious threat has been detected in your log file.\n\n"
        f"*Attack:* {attack_name}\n\n"
        f"*Severity:* {severity}\n\n"
        f"*What it means:* {definition_text}\n\n"
        f"*Suspicious activities:* {threat_count}\n\n"
        "Please check the attached PDF report for the complete analysis and recommended actions.\n\n"
        "— Log Sentinel"
    )
    return msg
