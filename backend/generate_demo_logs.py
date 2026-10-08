import time
import random
import requests

API_URL = "http://127.0.0.1:8000/api/ingest"

NORMAL_IPS = ["192.168.1.5", "10.0.0.4", "172.16.254.1"]
ATTACK_IPS = ["185.220.101.5", "45.146.164.2", "91.240.118.4"]

NORMAL_PAGES = ["/home", "/products", "/products?category=shoes", "/about", "/contact", "/blog/post-1"]

# Scenario 1: Credential Stuffing Attack
def run_scenario_1_credential_stuffing(count: int = 15):
    print(f"\n--- [RED-TEAM SIMULATION 1: CREDENTIAL STUFFING ({count} Events)] ---")
    ip = "198.51.100.45"
    for i in range(count):
        payload = {
            "ip": ip,
            "method": "POST",
            "endpoint": "/api/v1/auth",
            "status_code": 401,
            "user_agent": "python-requests/2.31.0 (Credential-Bot)",
            "raw_log": f"{ip} - - [{time.strftime('%d/%b/%Y:%H:%M:%S %z')}] \"POST /api/v1/auth HTTP/1.1\" 401 128"
        }
        try:
            r = requests.post(API_URL, json=payload)
            res = r.json().get("analysis", {})
            print(f"[{i+1}/{count}] Ingested Credential Burst -> HTTP 401 | Threat: {res.get('threat_type')} | MITRE: {res.get('mitre_id')}")
        except Exception as e:
            print(f"Connection error: {e}")
        time.sleep(0.05)

# Scenario 2: Obfuscated SQL Injection Attack
def run_scenario_2_obfuscated_sqli():
    print("\n--- [RED-TEAM SIMULATION 2: OBFUSCATED SQL INJECTION] ---")
    ip = "45.146.164.2"
    high_entropy_sqli = "/products?id=1%20UNION%20SELECT%20CHAR(39),CHAR(117),password%20FROM%20mysql.user--"
    payload = {
        "ip": ip,
        "method": "GET",
        "endpoint": high_entropy_sqli,
        "status_code": 500,
        "user_agent": "sqlmap/1.6.4#dev",
        "raw_log": f"{ip} - - [{time.strftime('%d/%b/%Y:%H:%M:%S %z')}] \"GET {high_entropy_sqli} HTTP/1.1\" 500 2450"
    }
    try:
        r = requests.post(API_URL, json=payload)
        res = r.json().get("analysis", {})
        print(f"Ingested Obfuscated SQLi -> Entropy: {res.get('shannon_entropy')} | Threat: {res.get('threat_type')}")
        if "gemini_triage" in res:
            triage = res["gemini_triage"]
            print(f"Gemini Triage Summary: {triage.get('plain_summary')}")
            print(f"Firewall Fix: {triage.get('remediation', {}).get('firewall')}")
    except Exception as e:
        print(f"Connection error: {e}")

# Scenario 3: Multi-Stage APT (Recon -> Honeytoken -> Escalation)
def run_scenario_3_multistage_apt():
    print("\n--- [RED-TEAM SIMULATION 3: MULTI-STAGE APT KILL CHAIN] ---")
    ip = "91.240.118.4"
    stages = [
        ("GET", "/about", 200, "Initial Recon"),
        ("GET", "/.env", 500, "Honeytoken Tripwire"),
        ("GET", "/admin.bak", 403, "Directory Discovery"),
        ("POST", "/admin/login", 401, "Privilege Escalation Attempt")
    ]
    for method, endpoint, status, stage_desc in stages:
        payload = {
            "ip": ip,
            "method": method,
            "endpoint": endpoint,
            "status_code": status,
            "user_agent": "Mozilla/5.0 (APT29 Probe)",
            "raw_log": f"{ip} - - [{time.strftime('%d/%b/%Y:%H:%M:%S %z')}] \"{method} {endpoint} HTTP/1.1\" {status} 1890"
        }
        try:
            r = requests.post(API_URL, json=payload)
            res = r.json().get("analysis", {})
            print(f"Stage: {stage_desc} -> {endpoint} ({status}) | Threat: {res.get('threat_type')}")
        except Exception as e:
            print(f"Connection error: {e}")
        time.sleep(0.3)

def make_normal_traffic():
    ip = random.choice(NORMAL_IPS)
    page = random.choice(NORMAL_PAGES)
    status = 200
    payload = {
        "ip": ip,
        "method": "GET",
        "endpoint": page,
        "status_code": status,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
        "raw_log": f"{ip} - - [{time.strftime('%d/%b/%Y:%H:%M:%S %z')}] \"GET {page} HTTP/1.1\" {status} {random.randint(400, 9000)}"
    }
    try:
        r = requests.post(API_URL, json=payload)
        print(f"Normal traffic: {page} -> HTTP {status}")
    except Exception as e:
        print(f"Connection failed: {e}")

if __name__ == "__main__":
    print("==================================================")
    print("LOG SENTINEL RED-TEAM SIMULATION ENGINE")
    print("Target API:", API_URL)
    print("==================================================")
    
    print("\nRunning All 3 Red-Team Attack Scenarios...\n")
    run_scenario_1_credential_stuffing(count=5)
    time.sleep(1)
    run_scenario_2_obfuscated_sqli()
    time.sleep(1)
    run_scenario_3_multistage_apt()
    
    print("\nSimulation completed cleanly.")