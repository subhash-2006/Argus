import os
import sys

# Ensure parent directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.pdf_generator import generate_incident_pdf
from app.log_parser import parse_uploaded_file, parse_csv_content, parse_json_content, parse_jsonl_content, parse_text_log_content

def test_pdf_generation():
    print("Testing PDF report generation...")
    test_incident = {
        "incident_id": "INC-TEST1234",
        "ip": "198.51.100.45",
        "method": "POST",
        "endpoint": "/api/v1/auth",
        "status_code": 401,
        "user_agent": "Credential-Stuffing-Bot/2.1",
        "raw_log": "198.51.100.45 - - POST /api/v1/auth HTTP/1.1 401 128",
        "threat_type": "BRUTE_FORCE",
        "severity": "HIGH",
        "mitre_id": "T1110",
        "rule_matched": ["HTTP 401 / Auth brute force response"],
        "ml_anomaly_prob": 0.96,
        "gemini_triage": {
            "plain_summary": "Surge of unauthorized authentication requests detected.",
            "technical_details": "HTTP 401 Unauthorized / auth endpoint probe from IP 198.51.100.45.",
            "mitre": {"id": "T1110", "name": "Brute Force"},
            "confidence": 0.96,
            "remediation": {
                "nginx_block": "location = /api/v1/auth {\n    deny 198.51.100.45;\n}",
                "firewall": "iptables -A INPUT -s 198.51.100.45 -j DROP"
            }
        }
    }
    pdf_bytes = generate_incident_pdf(test_incident)
    assert len(pdf_bytes) > 500, "PDF bytes should be greater than 500"
    assert pdf_bytes.startswith(b"%PDF"), "PDF header missing"
    print(f"PASS: Generated PDF report successfully ({len(pdf_bytes)} bytes)")

def test_log_parsers():
    print("Testing Log Parsers...")
    
    # 1. Text / CLF log
    clf_log = '192.168.1.100 - - [09/Oct/2026:07:00:00 +0000] "GET /.env HTTP/1.1" 500 123 "http://example.com" "Mozilla/5.0"'
    entries, valid, invalid = parse_uploaded_file("test.log", clf_log.encode('utf-8'))
    assert valid == 1, f"Expected 1 valid entry, got {valid}"
    assert entries[0].endpoint == "/.env"
    print("PASS: Text/CLF log parser")

    # 2. JSON log
    json_log = '[{"ip":"45.146.164.2","method":"GET","endpoint":"/products?id=1 UNION SELECT 1","status_code":500}]'
    entries, valid, invalid = parse_uploaded_file("test.json", json_log.encode('utf-8'))
    assert valid == 1, f"Expected 1 valid entry, got {valid}"
    assert entries[0].ip == "45.146.164.2"
    print("PASS: JSON log parser")

    # 3. JSONL log
    jsonl_log = '{"ip":"10.0.0.1","method":"POST","endpoint":"/login","status_code":401}\n{"ip":"10.0.0.2","method":"GET","endpoint":"/admin","status_code":403}\n'
    entries, valid, invalid = parse_uploaded_file("test.jsonl", jsonl_log.encode('utf-8'))
    assert valid == 2, f"Expected 2 valid entries, got {valid}"
    print("PASS: JSONL log parser")

    # 4. CSV log
    csv_log = "ip,method,endpoint,status_code,user_agent\n172.16.0.5,GET,/etc/passwd,500,Mozilla/5.0\n"
    entries, valid, invalid = parse_uploaded_file("test.csv", csv_log.encode('utf-8'))
    assert valid == 1, f"Expected 1 valid entry, got {valid}"
    assert entries[0].endpoint == "/etc/passwd"
    print("PASS: CSV log parser")

if __name__ == "__main__":
    test_pdf_generation()
    test_log_parsers()
    print("ALL BACKEND FEATURE TESTS PASSED!")
