import os
import random
import concurrent.futures
from typing import Optional
from google import genai
from google.genai import types
from pydantic import BaseModel, Field
from app.memory import get_semantic_threat_intel, get_procedural_playbook, episodic_memory

class MitreDetail(BaseModel):
    id: str = Field(description="MITRE ATT&CK Technique ID e.g. T1110")
    name: str = Field(description="Technique name e.g. Brute Force / Credential Stuffing")

class RemediationDetail(BaseModel):
    nginx_block: str = Field(description="Nginx/WAF rate limiting or blocking rule snippet")
    firewall: str = Field(description="Executable iptables or firewall drop rule")

class GeminiTriageResult(BaseModel):
    incident_id: str = Field(description="Unique incident ID string e.g. INC-8841")
    plain_summary: str = Field(description="Direct business impact summary with zero jargon")
    technical_details: str = Field(description="Technical analysis of the attack vector")
    mitre: MitreDetail = Field(description="MITRE ATT&CK technique mapping")
    confidence: float = Field(description="AI Confidence score between 0.00 and 1.00")
    remediation: RemediationDetail = Field(description="Ready-to-apply DevSecOps fix scripts")

    # Helper property accessors for legacy code compatibility
    @property
    def plain_english_summary(self) -> str:
        return self.plain_summary

    @property
    def remediation_snippet(self) -> str:
        return self.remediation.firewall

    @property
    def mitre_technique_id(self) -> str:
        return self.mitre.id

# Fixed MITRE mapping dictionary
FIXED_MITRE_MAP = {
    "HONEYTOKEN_ACCESS": {"id": "T1595", "name": "Active Scanning"},
    "SQL_INJECTION": {"id": "T1190", "name": "Exploit Public-Facing Application"},
    "BRUTE_FORCE": {"id": "T1110", "name": "Brute Force"},
    "UNAUTHORIZED_ADMIN_ACCESS": {"id": "T1078", "name": "Valid Accounts"},
    "ANOMALOUS_ENTROPY": {"id": "T1027", "name": "Obfuscated Files or Information"},
    "XSS_ATTACK": {"id": "T1059.007", "name": "Command and Scripting Interpreter: JavaScript"},
    "ML_CLASSIFIED_ANOMALY": {"id": "T1083", "name": "File and Directory Discovery"},
    "NORMAL": {"id": "N/A", "name": "Normal Traffic"}
}

def triage_incident_with_gemini(incident_data: dict) -> Optional[GeminiTriageResult]:
    api_key = os.getenv("GEMINI_API_KEY", "")
    ip = incident_data.get("ip", "127.0.0.1")
    endpoint = incident_data.get("endpoint", "/server")
    threat_type = incident_data.get("threat_type", "ANOMALY")
    
    # Use existing incident_id UUID from analyze_log_entry if available
    inc_id = incident_data.get("incident_id") or f"INC-{random.randint(1000, 9999)}"
    
    # Fixed MITRE Mapping lookup
    mitre_info = FIXED_MITRE_MAP.get(threat_type, {"id": incident_data.get("mitre_id", "T1190"), "name": "Security Anomaly"})
    mitre_id = mitre_info["id"]

    # Retrieve Episodic Memory timeline
    active_timeline = episodic_memory.get_active_chain_context(ip)
    
    # Retrieve Procedural Playbook Ground-Truth
    playbook = get_procedural_playbook(mitre_id, ip)

    prompt = (
        f"You are a SOC DevSecOps Engineer. Triage the following incident:\n"
        f"Incident Metadata: {incident_data}\n"
        f"Episodic Memory Attack Chain: {active_timeline}\n"
        f"MITRE Technique: {mitre_info}\n"
        f"Procedural Playbook Rules: {playbook}\n\n"
        f"Generate a dual-persona JSON triage report. Assign incident_id='{inc_id}'."
    )

    if api_key and "your_" not in api_key:
        def _call_gemini():
            try:
                client = genai.Client(api_key=api_key)
                primary_model = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")

                try:
                    response = client.models.generate_content(
                        model=primary_model,
                        contents=prompt,
                        config=types.GenerateContentConfig(
                            response_mime_type="application/json",
                            response_schema=GeminiTriageResult,
                        ),
                    )
                    if response and response.text:
                        parsed = GeminiTriageResult.model_validate_json(response.text)
                        parsed.incident_id = inc_id
                        return parsed
                except Exception as m_err:
                    err_msg = str(m_err)
                    print(f"Gemini API warning ({primary_model}): {err_msg}. Using deterministic triage fallback.")
                    return None
            except Exception as e:
                print(f"Gemini triage client exception: {e}")
            return None

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(_call_gemini)
                res = future.result(timeout=2.0)
                if res:
                    return res
        except concurrent.futures.TimeoutError:
            print("Gemini API call timed out after 2.0 seconds. Using deterministic triage fallback.")
        except Exception as e:
            print(f"Gemini triage API exception: {e}")

    # Template-based fallback summary and technical breakdown
    if threat_type == "HONEYTOKEN_ACCESS":
        fallback_summary = f"An unauthorized client from IP {ip} attempted to access decoy trap file '{endpoint}'. This indicates automated credential scraping."
        fallback_technical = f"HTTP request to decoy file '{endpoint}' from IP {ip}. Honeytokens trigger instant high-priority alerts with zero false-positives."
    elif threat_type == "SQL_INJECTION":
        raw_log = incident_data.get("raw_log", "")
        combined_text = f"{endpoint} {raw_log}".lower()
        if any(kw in combined_text for kw in ["password", "mysql.user", "user", "users", "credential", "auth"]):
            target_desc = "credential theft and sensitive user data extraction"
        elif any(kw in combined_text for kw in ["schema", "table", "column", "information_schema"]):
            target_desc = "database schema reconnaissance"
        elif any(kw in combined_text for kw in ["drop", "truncate", "delete"]):
            target_desc = "database destruction and table modification"
        else:
            target_desc = "database operations"

        fallback_summary = f"A malicious SQL injection attack query was detected targeting '{endpoint}'. The request attempted {target_desc}."
        fallback_technical = f"Input matching SQL injection signature (UNION/SELECT/CHAR/comments) received from IP {ip} targeting endpoint '{endpoint}'."
    elif threat_type == "BRUTE_FORCE":
        fallback_summary = f"Surge of unauthorized authentication requests detected targeting '{endpoint}'. Indicates password guessing or credential stuffing."
        fallback_technical = f"HTTP 401 Unauthorized / auth endpoint probe from IP {ip} targeting '{endpoint}'."
    elif threat_type == "XSS_ATTACK":
        fallback_summary = f"A Cross-Site Scripting (XSS) payload was detected targeting '{endpoint}'. The attacker attempted to inject malicious script tags."
        fallback_technical = f"HTML/JS script injection vector matched in request parameters from IP {ip} targeting '{endpoint}'."
    else:
        fallback_summary = f"High-risk anomalous traffic detected by CSIC 2010 ML Classifier & Shannon Entropy analysis on endpoint '{endpoint}'."
        fallback_technical = f"Request payload from IP {ip} on endpoint '{endpoint}' exceeded baseline anomaly threshold."

    return GeminiTriageResult(
        incident_id=inc_id,
        plain_summary=fallback_summary,
        technical_details=fallback_technical,
        mitre=MitreDetail(id=mitre_info["id"], name=mitre_info["name"]),
        confidence=0.95,
        remediation=RemediationDetail(
            nginx_block=playbook["nginx_block"],
            firewall=playbook["firewall"]
        )
    )
