import os
import random
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

def triage_incident_with_gemini(incident_data: dict) -> Optional[GeminiTriageResult]:
    api_key = os.getenv("GEMINI_API_KEY", "")
    ip = incident_data.get("ip", "127.0.0.1")
    mitre_id = incident_data.get("mitre_id", "T1190")
    
    # Retrieve Episodic Memory timeline
    active_timeline = episodic_memory.get_active_chain_context(ip)
    
    # Retrieve Semantic Threat Intel
    semantic_intel = get_semantic_threat_intel(mitre_id)
    
    # Retrieve Procedural Playbook Ground-Truth
    playbook = get_procedural_playbook(mitre_id, ip)

    # Generated incident ID
    inc_num = random.randint(1000, 9999)
    inc_id = f"INC-{inc_num}"

    prompt = (
        f"You are a SOC DevSecOps Engineer. Triage the following incident:\n"
        f"Incident Metadata: {incident_data}\n"
        f"Episodic Memory Attack Chain: {active_timeline}\n"
        f"Semantic Threat Knowledge: {semantic_intel}\n"
        f"Procedural Playbook Rules: {playbook}\n\n"
        f"Generate a dual-persona JSON triage report. Assign incident_id='{inc_id}'."
    )

    if api_key and "your_" not in api_key:
        try:
            client = genai.Client(api_key=api_key)
            models_to_try = [
                "gemini-2.5-flash",
                "gemini-3.8-flash",
                "gemini-3.5-flash",
                "gemini-2.0-flash",
                "gemini-1.5-flash"
            ]

            for model_name in models_to_try:
                try:
                    response = client.models.generate_content(
                        model=model_name,
                        contents=prompt,
                        config=types.GenerateContentConfig(
                            response_mime_type="application/json",
                            response_schema=GeminiTriageResult,
                        ),
                    )
                    if response and response.text:
                        parsed = GeminiTriageResult.model_validate_json(response.text)
                        return parsed
                except Exception as m_err:
                    print(f"Gemini model {model_name} warning: {m_err}")
                    continue
        except Exception as e:
            print(f"Gemini triage API exception: {e}")

    # Fallback deterministic structured response using Procedural Playbook & Semantic Intel
    return GeminiTriageResult(
        incident_id=inc_id,
        plain_summary=f"Detected suspicious {incident_data.get('threat_type', 'threat')} from IP {ip} targeting {incident_data.get('endpoint', 'server')}.",
        mitre=MitreDetail(id=mitre_id, name=semantic_intel.get("name", "Security Anomaly")),
        confidence=0.96,
        remediation=RemediationDetail(
            nginx_block=playbook["nginx_block"],
            firewall=playbook["firewall"]
        )
    )
