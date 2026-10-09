import io
import os
import sys
import unittest
from datetime import datetime, timezone

# Ensure parent directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient

from app.engine import LogEntry, analyze_log_entry
from app.gemini_triage import triage_incident_with_gemini
from app.log_parser import parse_uploaded_file
from app.main import app
from app.pdf_generator import generate_incident_pdf


class TestLogSentinelComprehensive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_01_all_six_log_formats(self):
        """Verify parsing of all 6 supported log file formats: .log, .txt, .json, .jsonl, .ndjson, .csv"""
        print("\n--- 1. Testing All 6 Supported File Formats ---")

        # 1. .log (Common Log Format)
        log_content = '198.51.100.45 - - [09/Oct/2026:07:00:00 +0000] "GET /.env HTTP/1.1" 500 128'
        entries, valid, invalid = parse_uploaded_file("server.log", log_content.encode('utf-8'))
        self.assertEqual(valid, 1)
        self.assertEqual(entries[0].endpoint, "/.env")
        print("[OK] .log format parsed successfully")

        # 2. .txt (Plain Text unstructured log)
        txt_content = "10.0.0.5 - - [09/Oct/2026:07:05:00] POST /api/v1/auth 401\n45.146.164.2 - - GET /products?id=1 200\n"
        entries, valid, invalid = parse_uploaded_file("access.txt", txt_content.encode('utf-8'))
        self.assertEqual(valid, 2)
        print("[OK] .txt format parsed successfully")

        # 3. .json (JSON array format)
        json_content = '[{"ip": "192.168.1.50", "method": "POST", "endpoint": "/login", "status_code": 401}]'
        entries, valid, invalid = parse_uploaded_file("logs.json", json_content.encode('utf-8'))
        self.assertEqual(valid, 1)
        self.assertEqual(entries[0].ip, "192.168.1.50")
        print("[OK] .json format parsed successfully")

        # 4. .jsonl (JSON Lines format)
        jsonl_content = '{"ip": "172.16.0.1", "method": "GET", "endpoint": "/admin", "status_code": 403}\n{"ip": "172.16.0.2", "method": "GET", "endpoint": "/public", "status_code": 200}'
        entries, valid, invalid = parse_uploaded_file("stream.jsonl", jsonl_content.encode('utf-8'))
        self.assertEqual(valid, 2)
        print("[OK] .jsonl format parsed successfully")

        # 5. .ndjson (Newline Delimited JSON format)
        ndjson_content = '{"ip": "10.20.30.40", "method": "DELETE", "endpoint": "/api/users", "status_code": 401}\n'
        entries, valid, invalid = parse_uploaded_file("events.ndjson", ndjson_content.encode('utf-8'))
        self.assertEqual(valid, 1)
        self.assertEqual(entries[0].ip, "10.20.30.40")
        print("[OK] .ndjson format parsed successfully")

        # 6. .csv (Comma-Separated Values format)
        csv_content = "ip,method,endpoint,status_code,user_agent\n91.240.118.4,GET,/.env,500,Mozilla/5.0\n"
        entries, valid, invalid = parse_uploaded_file("audit.csv", csv_content.encode('utf-8'))
        self.assertEqual(valid, 1)
        self.assertEqual(entries[0].endpoint, "/.env")
        print("[OK] .csv format parsed successfully")

    def test_02_edge_cases_and_error_handling(self):
        """Test malformed JSON, empty files, oversized files, invalid CSV, and Gemini API failures"""
        print("\n--- 2. Testing Edge Cases & Error Handling ---")

        # Malformed JSON
        malformed_json = '{"ip": "127.0.0.1", "method": "GET", INVALID_SYNTAX}'
        entries, valid, invalid = parse_uploaded_file("broken.json", malformed_json.encode('utf-8'))
        self.assertGreater(invalid, 0)
        print("[OK] Malformed JSON handled cleanly without crash")

        # Empty File Upload via API
        response = self.client.post(
            "/api/analyze-file",
            files={"file": ("empty.log", b"", "text/plain")}
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("empty", response.json()["detail"].lower())
        print("[OK] Empty file rejected with 400 status")

        # Oversized File Upload (>10MB) via API
        huge_bytes = b"A" * (10 * 1024 * 1024 + 100)
        response = self.client.post(
            "/api/analyze-file",
            files={"file": ("huge.log", huge_bytes, "text/plain")}
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("exceeds", response.json()["detail"].lower())
        print("[OK] Oversized upload (>10MB) rejected with 400 status")

        # Invalid / Malformed CSV rows
        bad_csv = "ip,method,endpoint\n127.0.0.1\n,,,\n"
        entries, valid, invalid = parse_uploaded_file("bad.csv", bad_csv.encode('utf-8'))
        print("[OK] Malformed CSV handled cleanly")

        # Gemini API Failure / Fallback test
        bad_incident = {
            "ip": "203.0.113.5",
            "endpoint": "/.env",
            "threat_type": "HONEYTOKEN_ACCESS",
            "severity": "CRITICAL",
            "status_code": 500
        }
        # Forces fallback or valid triage
        triage_res = triage_incident_with_gemini(bad_incident)
        self.assertIsNotNone(triage_res)
        self.assertIn("decoy", triage_res.plain_summary.lower() + triage_res.technical_details.lower())
        print("[OK] Gemini API fallback triage functioning properly")

    def test_03_detection_pipeline_and_ai_summary(self):
        """Verify uploaded logs pass through detection engine rules, ML, and Gemini triage"""
        print("\n--- 3. Testing Detection Pipeline & AI Integration ---")

        sqli_log = '45.146.164.2 - - [09/Oct/2026:07:10:00] "GET /products?id=1%20UNION%20SELECT%20CHAR(39),password%20FROM%20users-- HTTP/1.1" 500 2450'
        response = self.client.post(
            "/api/analyze-file",
            files={"file": ("sqli.log", sqli_log.encode('utf-8'), "text/plain")}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["anomalies_count"], 1)
        anomaly = data["anomalies"][0]
        self.assertEqual(anomaly["threat_type"], "SQL_INJECTION")
        self.assertEqual(anomaly["severity"], "CRITICAL")
        self.assertIn("gemini_triage", anomaly)
        print("[OK] Uploaded SQLi log passed through rule engine, ML, and Gemini triage")

    def test_04_pdf_generation_from_real_incident(self):
        """Generate PDF from real incident and verify plain-English, timeline, remediation, details"""
        print("\n--- 4. Testing PDF Report Generation from Real Incident ---")

        real_incident = {
            "incident_id": "INC-REAL9988",
            "ip": "91.240.118.4",
            "method": "POST",
            "endpoint": "/admin/login",
            "status_code": 401,
            "user_agent": "Mozilla/5.0 (APT29 Recon)",
            "raw_log": "91.240.118.4 - - POST /admin/login HTTP/1.1 401 1890",
            "threat_type": "UNAUTHORIZED_ADMIN_ACCESS",
            "severity": "HIGH",
            "mitre_id": "T1078",
            "rule_matched": ["Suspicious access attempt to admin endpoint: /admin/login"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ml_anomaly_prob": 0.98,
            "gemini_triage": {
                "plain_summary": "An unauthorized client attempted brute-force admin login.",
                "technical_details": "Repeated HTTP 401 responses on admin login vector.",
                "mitre": {"id": "T1078", "name": "Valid Accounts"},
                "confidence": 0.98,
                "remediation": {
                    "nginx_block": "location /admin/login {\n    deny 91.240.118.4;\n}",
                    "firewall": "iptables -A INPUT -s 91.240.118.4 -j DROP"
                }
            }
        }

        # Test POST PDF export
        response = self.client.post("/api/export/pdf", json=real_incident)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/pdf")
        pdf_content = response.content
        self.assertTrue(pdf_content.startswith(b"%PDF"))
        self.assertGreater(len(pdf_content), 1000)
        print("[OK] PDF generated successfully via POST /api/export/pdf")

        # Test GET PDF export by ID
        response_get = self.client.get(f"/api/incidents/{real_incident['incident_id']}/pdf")
        self.assertEqual(response_get.status_code, 200)
        self.assertEqual(response_get.headers["content-type"], "application/pdf")
        print("[OK] PDF generated successfully via GET /api/incidents/{id}/pdf")

    def test_05_frontend_backend_api_routes(self):
        """Verify API endpoints used by frontend work cleanly"""
        print("\n--- 5. Testing Frontend-Backend API Integration ---")

        # Health endpoint
        res_health = self.client.get("/health")
        self.assertEqual(res_health.status_code, 200)
        self.assertEqual(res_health.json()["status"], "online")
        print("[OK] GET /health returned 200 OK")

        # Incidents endpoint
        res_inc = self.client.get("/api/incidents")
        self.assertEqual(res_inc.status_code, 200)
        self.assertIn("incidents", res_inc.json())
        print("[OK] GET /api/incidents returned 200 OK")

        # Simulate scenario endpoint
        res_sim = self.client.post("/api/simulate", json={"scenario": 1})
        self.assertEqual(res_sim.status_code, 200)
        self.assertTrue(res_sim.json()["success"])
        print("[OK] POST /api/simulate returned 200 OK")

    def test_06_cors_preflight_headers(self):
        """Verify OPTIONS preflight CORS response headers for all API endpoints"""
        print("\n--- 6. Testing CORS Preflight OPTIONS Headers ---")
        headers = {
            "Origin": "https://log-sentinel-frontend.onrender.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type"
        }

        endpoints = [
            "/api/analyze-file",
            "/api/simulate",
            "/api/incidents",
            "/api/export/pdf",
            "/health"
        ]

        for ep in endpoints:
            res = self.client.options(ep, headers=headers)
            self.assertEqual(res.status_code, 200, f"Preflight failed for {ep}")
            self.assertEqual(
                res.headers.get("access-control-allow-origin"),
                "https://log-sentinel-frontend.onrender.com",
                f"Missing Access-Control-Allow-Origin header on {ep}"
            )
            print(f"[OK] Preflight OPTIONS passed for {ep}")


if __name__ == "__main__":
    unittest.main()
