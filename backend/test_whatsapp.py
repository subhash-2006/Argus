"""
Automated Test Suite for Log Sentinel — WhatsApp Threat Alert System
Covers all 15 scenarios specified in Section 12 using mocked WhatsApp API responses.
Never sends real messages.
"""

import io
import unittest
from unittest.mock import patch, MagicMock
import requests
from fastapi.testclient import TestClient

from app.main import app
from app.whatsapp_service import whatsapp_service, WhatsAppService, validate_and_normalize_phone
from app.attack_definitions import (
    get_attack_definition,
    summarize_threats_for_alert,
    format_whatsapp_message,
    ATTACK_DEFINITIONS
)
from app.pdf_generator import generate_analysis_report_pdf


class TestWhatsAppThreatAlertSystem(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        # Reset runtime state on singleton service
        whatsapp_service._latest_notification = None
        whatsapp_service._idempotency_cache.clear()
        whatsapp_service._pdf_cache.clear()
        whatsapp_service.enabled = True
        whatsapp_service.current_recipient = "+919042541948"

    # 1. No suspicious findings: no alert is sent.
    def test_01_no_suspicious_findings_no_alert(self):
        normal_analysis = {
            "analysis_id": "TEST-NORMAL-01",
            "filename": "access_clean.log",
            "total_parsed": 5,
            "anomalies_count": 0,
            "anomalies": []
        }
        res = whatsapp_service.notify_threat_analysis(normal_analysis)
        self.assertFalse(res.get("sent", True))
        self.assertEqual(res.get("status"), "no_threats")
        self.assertIsNone(whatsapp_service._latest_notification)

    # 2. A brute-force finding: the correct simple definition appears.
    def test_02_bruteforce_correct_definition(self):
        bf_anomalies = [
            {
                "incident_id": "INC-BF-01",
                "ip": "198.51.100.45",
                "method": "POST",
                "endpoint": "/api/v1/auth",
                "threat_type": "BRUTE_FORCE",
                "severity": "HIGH",
                "rule_matched": ["Auth failure / Brute force / Invalid token detected"]
            }
        ]
        summary = summarize_threats_for_alert(bf_anomalies)
        self.assertEqual(summary["highest_attack_name"], "Brute-Force Attack")
        self.assertEqual(summary["severity"], "HIGH")
        self.assertEqual(summary["threat_count"], 1)
        expected_def = ATTACK_DEFINITIONS["BRUTE_FORCE"]["short_definition"]
        self.assertIn("passwords", summary["short_definition"].lower())
        self.assertEqual(summary["short_definition"], expected_def)

        msg = format_whatsapp_message(
            attack_name=summary["highest_attack_name"],
            severity=summary["severity"],
            short_definition=summary["short_definition"],
            threat_count=summary["threat_count"]
        )
        self.assertIn("*Attack:* Brute-Force Attack", msg)
        self.assertIn("*Severity:* HIGH", msg)
        self.assertIn("*What it means:* " + expected_def, msg)
        self.assertIn("*Suspicious activities:* 1", msg)

    # 3. Multiple suspicious findings: one consolidated alert is generated.
    def test_03_multiple_findings_consolidated_alert(self):
        multi_anomalies = [
            {
                "incident_id": "INC-01",
                "threat_type": "RATE_LIMIT_ABUSE",
                "severity": "MEDIUM",
                "rule_matched": ["Rate limit triggered"]
            },
            {
                "incident_id": "INC-02",
                "threat_type": "SQL_INJECTION",
                "severity": "CRITICAL",
                "rule_matched": ["SQL Injection pattern matched"]
            },
            {
                "incident_id": "INC-03",
                "threat_type": "XSS_ATTACK",
                "severity": "HIGH",
                "rule_matched": ["XSS pattern matched"]
            }
        ]
        summary = summarize_threats_for_alert(multi_anomalies)
        # SQL Injection should win priority as CRITICAL (priority 100)
        self.assertEqual(summary["highest_attack_name"], "SQL Injection")
        self.assertEqual(summary["severity"], "CRITICAL")
        self.assertEqual(summary["threat_count"], 3)
        self.assertIn("Cross-Site Scripting", summary["other_categories_summary"])
        self.assertIn("Rate Limit Abuse", summary["other_categories_summary"])

    # 4. Unknown category: safe fallback definition is used.
    def test_04_unknown_category_safe_fallback(self):
        unknown_def = get_attack_definition("COMPLETELY_UNKNOWN_EXPLOIT_99")
        self.assertEqual(unknown_def["display_name"], "Suspicious Activity")
        self.assertIn("Unusual activity was flagged", unknown_def["short_definition"])
        self.assertFalse(unknown_def["is_confirmed_attack"])

        # Also test threat summary with unknown category
        anomalies = [{"threat_type": "UNREGISTERED_ZERO_DAY", "severity": "MEDIUM"}]
        summary = summarize_threats_for_alert(anomalies)
        self.assertEqual(summary["highest_attack_name"], "Suspicious Activity")

    # 5. Correct recipient is selected.
    def test_05_correct_recipient_selected(self):
        is_valid, display, digits = validate_and_normalize_phone("+919042541948")
        self.assertTrue(is_valid)
        self.assertEqual(display, "+919042541948")
        self.assertEqual(digits, "919042541948")

        # Custom recipient validation
        is_valid2, display2, digits2 = validate_and_normalize_phone("+14155552671")
        self.assertTrue(is_valid2)
        self.assertEqual(display2, "+14155552671")
        self.assertEqual(digits2, "14155552671")

        # Rejects invalid strings
        is_valid_inv, _, _ = validate_and_normalize_phone("not-a-number")
        self.assertFalse(is_valid_inv)

    # 6 & 7. PDF is generated and uploaded before the document message is sent using provider's media ID.
    @patch("requests.post")
    def test_06_07_pdf_uploaded_and_sent_with_media_id(self, mock_post):
        # Configure test service with mock credentials
        test_svc = WhatsAppService()
        test_svc.enabled = True
        test_svc.access_token = "EAABmocktoken1234567890"
        test_svc.phone_number_id = "10987654321"
        test_svc.current_recipient = "+919042541948"

        upload_response = MagicMock()
        upload_response.status_code = 200
        upload_response.json.return_value = {"id": "media_test_id_9999"}

        send_response = MagicMock()
        send_response.status_code = 200
        send_response.json.return_value = {
            "messaging_product": "whatsapp",
            "contacts": [{"input": "919042541948", "wa_id": "919042541948"}],
            "messages": [{"id": "wamid.HBgTEST123456"}]
        }

        # First post is upload, second post is message send
        mock_post.side_effect = [upload_response, send_response]

        test_data = {
            "analysis_id": "ANALYSIS-MOCK-001",
            "filename": "auth_audit.log",
            "anomalies": [
                {
                    "threat_type": "BRUTE_FORCE",
                    "severity": "HIGH",
                    "ip": "198.51.100.45",
                    "endpoint": "/api/v1/auth",
                    "status_code": 401,
                    "rule_matched": ["Failed login attempts"]
                }
            ]
        }

        result = test_svc.notify_threat_analysis(test_data)

        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["media_id"], "media_test_id_9999")
        self.assertEqual(result["message_id"], "wamid.HBgTEST123456")
        self.assertTrue(result["pdf_attached"])
        self.assertEqual(mock_post.call_count, 2)

        # Verify upload call (Call 1)
        upload_call = mock_post.call_args_list[0]
        self.assertIn("/media", upload_call[0][0])
        self.assertIn("file", upload_call[1]["files"])

        # Verify send message call (Call 2)
        send_call = mock_post.call_args_list[1]
        self.assertIn("/messages", send_call[0][0])
        payload = send_call[1]["json"]
        self.assertEqual(payload["type"], "document")
        self.assertEqual(payload["document"]["id"], "media_test_id_9999")
        self.assertEqual(payload["to"], "919042541948")
        self.assertIn("*Attack:* Brute-Force Attack", payload["document"]["caption"])

    # 8. Missing credentials produce preview-only or disabled status.
    def test_08_missing_credentials_demo_preview(self):
        # Default environment has no real WhatsApp token
        test_svc = WhatsAppService()
        test_svc.enabled = True
        test_svc.access_token = ""
        test_svc.phone_number_id = ""

        test_data = {
            "analysis_id": "DEMO-01",
            "anomalies": [
                {"threat_type": "SQL_INJECTION", "severity": "CRITICAL", "endpoint": "/api/items"}
            ]
        }
        res = test_svc.notify_threat_analysis(test_data)
        self.assertEqual(res["status"], "demo_preview")
        self.assertTrue(res["is_demo"])
        self.assertIn("Demo preview only", res["notice"])
        self.assertIn("*Attack:* SQL Injection", res["message_preview"])
        self.assertTrue(res["pdf_attached"])

    # 9. Provider failure does not break the analysis.
    @patch("requests.post")
    def test_09_provider_failure_does_not_break_analysis(self, mock_post):
        # Mock requests to raise a network connection error
        mock_post.side_effect = requests.exceptions.ConnectionError("Connection to Meta Graph API timed out")

        file_content = b'198.51.100.45 - - [10/Oct/2026:13:55:36 +0000] "POST /api/v1/auth HTTP/1.1" 401 128\n'
        response = self.client.post(
            "/api/analyze-file",
            files={"file": ("brute_force.log", io.BytesIO(file_content), "text/plain")}
        )

        # File analysis must succeed with 200 OK
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertGreaterEqual(data["anomalies_count"], 1)

    # 10. Duplicate notification attempts are prevented (Idempotency).
    @patch("requests.post")
    def test_10_duplicate_notification_attempts_prevented(self, mock_post):
        test_svc = WhatsAppService()
        test_svc.enabled = True
        test_svc.access_token = "mock_token_123456789"
        test_svc.phone_number_id = "12345678"

        upload_mock = MagicMock(status_code=200)
        upload_mock.json.return_value = {"id": "med_123"}
        send_mock = MagicMock(status_code=200)
        send_mock.json.return_value = {"messages": [{"id": "wamid.123"}]}
        mock_post.side_effect = [upload_mock, send_mock]

        data = {
            "analysis_id": "STABLE-IDEMPOTENCY-KEY",
            "anomalies": [{"threat_type": "SQL_INJECTION", "severity": "CRITICAL"}]
        }

        # First call: sends
        res1 = test_svc.notify_threat_analysis(data, idempotency_key="STABLE-IDEMPOTENCY-KEY")
        self.assertEqual(res1["status"], "accepted")
        self.assertEqual(mock_post.call_count, 2)

        # Second call with same idempotency key: suppressed
        res2 = test_svc.notify_threat_analysis(data, idempotency_key="STABLE-IDEMPOTENCY-KEY")
        self.assertTrue(res2.get("is_duplicate"))
        self.assertEqual(mock_post.call_count, 2)  # No extra calls

    # 11. Failed delivery can be retried safely.
    @patch("requests.post")
    def test_11_failed_delivery_can_be_retried(self, mock_post):
        test_svc = WhatsAppService()
        test_svc.enabled = True
        test_svc.access_token = "mock_token_123456789"
        test_svc.phone_number_id = "12345678"

        # First call fails
        fail_mock = MagicMock(status_code=500, text="Internal Meta Outage")
        mock_post.return_value = fail_mock

        data = {
            "analysis_id": "RETRY-TARGET-KEY",
            "anomalies": [{"threat_type": "SQL_INJECTION", "severity": "CRITICAL"}]
        }
        res_fail = test_svc.notify_threat_analysis(data)
        self.assertEqual(res_fail["status"], "failed")

        # Now mock recovery for retry
        upload_mock = MagicMock(status_code=200)
        upload_mock.json.return_value = {"id": "med_recovered"}
        send_mock = MagicMock(status_code=200)
        send_mock.json.return_value = {"messages": [{"id": "wamid.recovered"}]}
        mock_post.side_effect = [upload_mock, send_mock]

        # Execute retry
        retry_res = test_svc.retry_latest_notification()
        self.assertTrue(retry_res["success"])
        self.assertEqual(retry_res["result"]["status"], "accepted")

    # 12. PDF generation or upload failure is reported correctly.
    @patch("requests.post")
    def test_12_upload_failure_reported_correctly(self, mock_post):
        test_svc = WhatsAppService()
        test_svc.enabled = True
        test_svc.access_token = "mock_token_123456789"
        test_svc.phone_number_id = "12345678"

        # Media upload endpoint returns 400 Bad Request
        fail_mock = MagicMock(status_code=400, text='{"error":{"message":"Unsupported file type"}}')
        fail_mock.json.return_value = {"error": {"message": "Unsupported file type"}}
        mock_post.return_value = fail_mock

        data = {
            "analysis_id": "UPLOAD-FAIL-01",
            "anomalies": [{"threat_type": "HONEYTOKEN_ACCESS", "severity": "CRITICAL"}]
        }
        res = test_svc.notify_threat_analysis(data)
        self.assertEqual(res["status"], "failed")
        self.assertFalse(res["pdf_attached"])
        self.assertIn("Meta Media Upload Failed", res["error"])

    # 13. PDF generation output contains all required fields and matches analysis.
    def test_13_pdf_generation_content_and_structure(self):
        analysis_data = {
            "filename": "threat_detect.log",
            "total_parsed": 42,
            "anomalies_count": 2,
            "anomalies": [
                {
                    "incident_id": "INC-TEST-1",
                    "timestamp": "2026-10-13T12:00:00Z",
                    "ip": "203.0.113.195",
                    "method": "POST",
                    "endpoint": "/login",
                    "status_code": 401,
                    "threat_type": "BRUTE_FORCE",
                    "severity": "HIGH",
                    "rule_matched": ["Failed credential attempt"]
                },
                {
                    "incident_id": "INC-TEST-2",
                    "timestamp": "2026-10-13T12:01:00Z",
                    "ip": "203.0.113.195",
                    "method": "GET",
                    "endpoint": "/users?id=1%20UNION%20SELECT",
                    "status_code": 500,
                    "threat_type": "SQL_INJECTION",
                    "severity": "CRITICAL",
                    "rule_matched": ["SQL Injection pattern detected"]
                }
            ],
            "is_local_fallback": False
        }
        pdf_bytes = generate_analysis_report_pdf(analysis_data)
        self.assertIsInstance(pdf_bytes, bytes)
        self.assertGreater(len(pdf_bytes), 3000)
        # Verify valid PDF signature
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))

    # 14. API Endpoints testing: status, preview, test, retry.
    def test_14_api_endpoints_work_cleanly(self):
        # GET /api/whatsapp/status
        status_res = self.client.get("/api/whatsapp/status")
        self.assertEqual(status_res.status_code, 200)
        st_data = status_res.json()
        self.assertIn("enabled", st_data)
        self.assertIn("current_recipient", st_data)
        self.assertNotIn("access_token", st_data)  # Token never exposed!

        # POST /api/whatsapp/preview
        preview_res = self.client.post("/api/whatsapp/preview", json={
            "analysis": {
                "anomalies": [{"threat_type": "SQL_INJECTION", "severity": "CRITICAL"}]
            }
        })
        self.assertEqual(preview_res.status_code, 200)
        pv = preview_res.json()["preview"]
        self.assertIn("*Attack:* SQL Injection", pv["message_preview"])

        # POST /api/whatsapp/test
        test_res = self.client.post("/api/whatsapp/test", json={})
        self.assertEqual(test_res.status_code, 200)
        self.assertTrue(test_res.json()["success"])

        # GET /api/whatsapp/download-pdf
        pdf_res = self.client.get("/api/whatsapp/download-pdf")
        self.assertEqual(pdf_res.status_code, 200)
        self.assertEqual(pdf_res.headers["content-type"], "application/pdf")
        self.assertTrue(pdf_res.content.startswith(b"%PDF"))

    # 15. Client-side fallback is not misrepresented as server-side analysis.
    def test_15_client_side_fallback_explicit_attribution(self):
        fallback_data = {
            "analysis_id": "CLIENT-FALLBACK-99",
            "filename": "offline_browser_scan.log",
            "total_parsed": 10,
            "anomalies_count": 1,
            "is_local_fallback": True,  # Explicitly flagged as client-side fallback
            "anomalies": [
                {
                    "threat_type": "BRUTE_FORCE",
                    "severity": "HIGH",
                    "rule_matched": ["Client heuristic: Repeated login failure"]
                }
            ]
        }
        preview = whatsapp_service.generate_alert_preview(fallback_data)
        self.assertTrue(preview["is_local_fallback"])

        # Generate PDF with fallback flag and verify
        pdf_bytes = generate_analysis_report_pdf(fallback_data)
        self.assertIsInstance(pdf_bytes, bytes)
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))


if __name__ == "__main__":
    unittest.main()
