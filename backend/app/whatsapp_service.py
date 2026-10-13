"""
Log Sentinel — WhatsApp Threat Alert System Service
Integrates with the official Meta WhatsApp Business Cloud API.
Provides automatic alerting, attack definitions, PDF document attachments,
preview/demo mode, phone number validation, idempotency, and retry capabilities.
"""

import os
import re
import time
import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple

import requests

from app.attack_definitions import (
    summarize_threats_for_alert,
    format_whatsapp_message,
    get_attack_definition,
    DEFAULT_FALLBACK_DEFINITION
)
from app.pdf_generator import generate_analysis_report_pdf, generate_incident_pdf

logger = logging.getLogger("whatsapp_service")

# E.164 phone number pattern
PHONE_CLEAN_REGEX = re.compile(r"[^\d+]")
DIGITS_ONLY_REGEX = re.compile(r"^\d{8,15}$")


def validate_and_normalize_phone(phone: Optional[str]) -> Tuple[bool, str, str]:
    """
    Validates and normalizes phone numbers for WhatsApp Cloud API.
    Returns: (is_valid, formatted_display, api_recipient)
    Example: '+919042541948' -> (True, '+919042541948', '919042541948')
    """
    if not phone or not isinstance(phone, str):
        return False, "", ""

    cleaned = PHONE_CLEAN_REGEX.sub("", phone.strip())
    if not cleaned:
        return False, "", ""

    # Extract digits for Meta API 'to' parameter
    digits = cleaned.lstrip("+")
    if not DIGITS_ONLY_REGEX.match(digits):
        return False, cleaned, ""

    display_format = f"+{digits}" if not cleaned.startswith("+") else cleaned
    return True, display_format, digits


class WhatsAppService:
    def __init__(self):
        self._load_config()
        self._latest_notification: Optional[Dict[str, Any]] = None
        self._idempotency_cache: Dict[str, Dict[str, Any]] = {}
        self._pdf_cache: Dict[str, bytes] = {}  # notification_id -> pdf_bytes

    def _load_config(self):
        """Loads configuration from environment variables with runtime override support."""
        raw_enabled = os.getenv("WHATSAPP_ENABLED", "false").lower()
        self.enabled = raw_enabled in ("true", "1", "yes", "on")
        self.access_token = os.getenv("WHATSAPP_ACCESS_TOKEN", "").strip()
        self.phone_number_id = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "").strip()
        self.default_recipient = os.getenv("WHATSAPP_DEFAULT_RECIPIENT", "+919042541948").strip()
        self.current_recipient = self.default_recipient
        self.api_version = os.getenv("WHATSAPP_API_VERSION", "v21.0").strip() or "v21.0"
        self.request_timeout = 12.0  # seconds

    def update_runtime_config(self, enabled: Optional[bool] = None, recipient: Optional[str] = None) -> Dict[str, Any]:
        """Allows toggling enabled state or changing demonstration recipient at runtime."""
        if enabled is not None:
            self.enabled = bool(enabled)
        if recipient is not None and recipient.strip():
            is_valid, display, _ = validate_and_normalize_phone(recipient)
            if not is_valid:
                raise ValueError("Invalid phone number format. Please provide a valid E.164 number with country code (e.g. +919042541948)")
            self.current_recipient = display
        return self.get_status_safe()

    def has_valid_credentials(self) -> bool:
        """Checks if genuine Meta Cloud API credentials are configured."""
        token_ok = bool(self.access_token) and "your_" not in self.access_token and len(self.access_token) > 15
        id_ok = bool(self.phone_number_id) and "your_" not in self.phone_number_id and self.phone_number_id.isdigit()
        return token_ok and id_ok

    def get_status_safe(self) -> Dict[str, Any]:
        """
        Returns public-safe WhatsApp configuration and notification status.
        Never exposes the access token.
        """
        has_creds = self.has_valid_credentials()

        if not self.enabled:
            mode = "disabled"
        elif not has_creds:
            mode = "demo_preview"
        else:
            mode = "live"

        masked_phone_id = (
            f"***{self.phone_number_id[-4:]}"
            if len(self.phone_number_id) > 4
            else ("configured" if self.phone_number_id else "missing")
        )

        return {
            "enabled": self.enabled,
            "mode": mode,
            "has_credentials": has_creds,
            "phone_number_id": masked_phone_id,
            "api_version": self.api_version,
            "current_recipient": self.current_recipient,
            "default_recipient": self.default_recipient,
            "latest_notification": self._latest_notification,
            "service": "Meta WhatsApp Business Cloud API"
        }

    def _upload_media(self, pdf_bytes: bytes, filename: str = "LogSentinel_Threat_Report.pdf") -> str:
        """
        Uploads PDF document to Meta WhatsApp Cloud Media endpoint.
        Returns: media_id string.
        """
        url = f"https://graph.facebook.com/{self.api_version}/{self.phone_number_id}/media"
        headers = {
            "Authorization": f"Bearer {self.access_token}"
        }
        files = {
            "file": (filename, pdf_bytes, "application/pdf")
        }
        data = {
            "messaging_product": "whatsapp",
            "type": "application/pdf"
        }

        response = requests.post(
            url,
            headers=headers,
            files=files,
            data=data,
            timeout=self.request_timeout
        )

        if response.status_code not in (200, 201):
            err_body = response.text
            try:
                err_json = response.json()
                msg = err_json.get("error", {}).get("message", err_body)
            except Exception:
                msg = err_body
            raise RuntimeError(f"Meta Media Upload Failed ({response.status_code}): {msg}")

        res_data = response.json()
        media_id = res_data.get("id")
        if not media_id:
            raise RuntimeError(f"Meta Media Upload returned no media id: {res_data}")

        return media_id

    def _send_document_message(
        self,
        to_digits: str,
        media_id: str,
        caption: str,
        filename: str = "LogSentinel_Threat_Report.pdf"
    ) -> Dict[str, Any]:
        """
        Sends WhatsApp document message referencing the uploaded media_id.
        """
        url = f"https://graph.facebook.com/{self.api_version}/{self.phone_number_id}/messages"
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }

        # WhatsApp Cloud API caption limit is 1024 chars
        safe_caption = caption[:1020]

        payload = {
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": to_digits,
            "type": "document",
            "document": {
                "id": media_id,
                "caption": safe_caption,
                "filename": filename
            }
        }

        response = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=self.request_timeout
        )

        if response.status_code not in (200, 201):
            err_body = response.text
            try:
                err_json = response.json()
                msg = err_json.get("error", {}).get("message", err_body)
            except Exception:
                msg = err_body
            raise RuntimeError(f"Meta Message Send Failed ({response.status_code}): {msg}")

        return response.json()

    def generate_alert_preview(
        self,
        analysis_data: Dict[str, Any],
        recipient: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Builds the message text and generates matching PDF without sending a message.
        """
        target_phone = recipient or self.current_recipient
        is_valid, formatted_phone, _ = validate_and_normalize_phone(target_phone)
        if not is_valid:
            formatted_phone = target_phone

        # Extract anomalies
        anomalies = analysis_data.get("anomalies")
        if anomalies is None:
            if analysis_data.get("is_anomaly"):
                anomalies = [analysis_data]
            else:
                anomalies = []

        threat_summary = summarize_threats_for_alert(anomalies)

        message_text = format_whatsapp_message(
            attack_name=threat_summary["highest_attack_name"],
            severity=threat_summary["severity"],
            short_definition=threat_summary["short_definition"],
            threat_count=threat_summary["threat_count"],
            other_summary=threat_summary["other_categories_summary"]
        )

        return {
            "recipient": formatted_phone,
            "has_threats": threat_summary["has_threats"],
            "attack_name": threat_summary["highest_attack_name"],
            "severity": threat_summary["severity"],
            "short_definition": threat_summary["short_definition"],
            "threat_count": threat_summary["threat_count"],
            "other_categories_summary": threat_summary["other_categories_summary"],
            "message_preview": message_text,
            "pdf_filename": "LogSentinel_Threat_Report.pdf",
            "is_local_fallback": bool(analysis_data.get("is_local_fallback", False))
        }

    def notify_threat_analysis(
        self,
        analysis_data: Dict[str, Any],
        recipient: Optional[str] = None,
        idempotency_key: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Primary automated workflow:
        1. Checks for suspicious findings. If none, does not send an alert.
        2. Idempotency check to prevent duplicate alerts.
        3. Identifies threat, severity, plain definition, and threat count.
        4. Generates matching PDF report.
        5. If live credentials and enabled, uploads PDF & sends document message.
           If credentials missing or disabled, creates demo preview record.
        6. Updates notification status.
        """
        anomalies = analysis_data.get("anomalies")
        if anomalies is None:
            if analysis_data.get("is_anomaly"):
                anomalies = [analysis_data]
            else:
                anomalies = []

        # 1. No suspicious findings: no alert is sent
        if not anomalies:
            logger.info("No suspicious findings in analysis run. Skipping WhatsApp alert.")
            return {
                "sent": False,
                "status": "no_threats",
                "message": "No qualifying suspicious threats detected. Alert skipped."
            }

        # 2. Idempotency check
        key = idempotency_key or analysis_data.get("analysis_id") or analysis_data.get("incident_id")
        if not key:
            key = f"RUN-{analysis_data.get('filename', 'log')}-{len(anomalies)}-{anomalies[0].get('timestamp', '')}"

        if key in self._idempotency_cache:
            existing = self._idempotency_cache[key]
            logger.info("Duplicate notification suppressed for key=%s", key)
            return {
                "sent": False,
                "is_duplicate": True,
                "status": existing.get("status", "accepted"),
                "notification_id": existing.get("notification_id"),
                "message": "Notification already processed for this analysis run.",
                "details": existing
            }

        # 3. Recipient determination
        target_phone = recipient or self.current_recipient
        is_valid, formatted_phone, api_recipient = validate_and_normalize_phone(target_phone)

        # 4. Generate alert text and attack definition
        preview = self.generate_alert_preview(analysis_data, recipient=target_phone)
        message_text = preview["message_preview"]

        # 5. Generate matching PDF
        pdf_bytes = generate_analysis_report_pdf(analysis_data)
        notification_id = f"NOTIF-{uuid.uuid4().hex[:8].upper()}"
        self._pdf_cache[notification_id] = pdf_bytes
        self._pdf_cache["latest"] = pdf_bytes

        attempt_time = datetime.now(timezone.utc).isoformat()

        # Handle invalid phone number
        if not is_valid:
            record = {
                "notification_id": notification_id,
                "analysis_id": key,
                "attempted_at": attempt_time,
                "recipient": target_phone,
                "status": "failed",
                "attack_name": preview["attack_name"],
                "severity": preview["severity"],
                "threat_count": preview["threat_count"],
                "short_definition": preview["short_definition"],
                "message_preview": message_text,
                "pdf_attached": False,
                "pdf_filename": "LogSentinel_Threat_Report.pdf",
                "is_demo": False,
                "error": f"Invalid recipient phone number format '{target_phone}'. Must be valid E.164."
            }
            self._latest_notification = record
            return record

        # 6. Check credentials & enabled mode
        has_creds = self.has_valid_credentials()

        if not self.enabled:
            record = {
                "notification_id": notification_id,
                "analysis_id": key,
                "attempted_at": attempt_time,
                "recipient": formatted_phone,
                "status": "disabled",
                "attack_name": preview["attack_name"],
                "severity": preview["severity"],
                "threat_count": preview["threat_count"],
                "short_definition": preview["short_definition"],
                "message_preview": message_text,
                "pdf_attached": True,
                "pdf_filename": "LogSentinel_Threat_Report.pdf",
                "is_demo": True,
                "notice": "WhatsApp integration is currently disabled in settings.",
                "error": None
            }
            self._latest_notification = record
            self._idempotency_cache[key] = record
            return record

        if not has_creds:
            record = {
                "notification_id": notification_id,
                "analysis_id": key,
                "attempted_at": attempt_time,
                "recipient": formatted_phone,
                "status": "demo_preview",
                "attack_name": preview["attack_name"],
                "severity": preview["severity"],
                "threat_count": preview["threat_count"],
                "short_definition": preview["short_definition"],
                "message_preview": message_text,
                "pdf_attached": True,
                "pdf_filename": "LogSentinel_Threat_Report.pdf",
                "is_demo": True,
                "notice": "Demo preview only — no WhatsApp message has been sent.",
                "error": None
            }
            self._latest_notification = record
            self._idempotency_cache[key] = record
            return record

        # 7. Real Sending via Meta Cloud API
        try:
            # Step A: Upload PDF to Media API
            media_id = self._upload_media(pdf_bytes, filename="LogSentinel_Threat_Report.pdf")

            # Step B: Send WhatsApp document message with caption
            send_res = self._send_document_message(
                to_digits=api_recipient,
                media_id=media_id,
                caption=message_text,
                filename="LogSentinel_Threat_Report.pdf"
            )

            messages = send_res.get("messages", [])
            msg_id = messages[0].get("id") if messages else f"wamid.{uuid.uuid4().hex}"

            record = {
                "notification_id": notification_id,
                "analysis_id": key,
                "attempted_at": attempt_time,
                "recipient": formatted_phone,
                "status": "accepted",  # Meta Cloud API accepted for delivery
                "attack_name": preview["attack_name"],
                "severity": preview["severity"],
                "threat_count": preview["threat_count"],
                "short_definition": preview["short_definition"],
                "message_preview": message_text,
                "pdf_attached": True,
                "pdf_filename": "LogSentinel_Threat_Report.pdf",
                "media_id": media_id,
                "message_id": msg_id,
                "is_demo": False,
                "error": None
            }
            self._latest_notification = record
            self._idempotency_cache[key] = record
            logger.info("WhatsApp document alert accepted by Meta API for %s. Message ID: %s", formatted_phone, msg_id)
            return record

        except Exception as exc:
            err_msg = str(exc)
            # Redact access token from any leaked error strings
            if self.access_token:
                err_msg = err_msg.replace(self.access_token, "[REDACTED_TOKEN]")

            logger.error("WhatsApp delivery failure: %s", err_msg)
            record = {
                "notification_id": notification_id,
                "analysis_id": key,
                "attempted_at": attempt_time,
                "recipient": formatted_phone,
                "status": "failed",
                "attack_name": preview["attack_name"],
                "severity": preview["severity"],
                "threat_count": preview["threat_count"],
                "short_definition": preview["short_definition"],
                "message_preview": message_text,
                "pdf_attached": False,
                "pdf_filename": "LogSentinel_Threat_Report.pdf",
                "is_demo": False,
                "raw_analysis_payload": analysis_data,  # Stored for retry
                "error": err_msg
            }
            self._latest_notification = record
            # Do not cache failed runs in idempotency cache so user can retry!
            return record

    def send_test_message(self, recipient: Optional[str] = None) -> Dict[str, Any]:
        """
        Sends a test WhatsApp notification (or generates a demo preview)
        demonstrating the complete workflow with attack definition and PDF attachment.
        """
        test_analysis = {
            "analysis_id": f"TEST-{uuid.uuid4().hex[:6].upper()}",
            "filename": "test_security_audit.log",
            "total_parsed": 12,
            "valid_entries": 12,
            "anomalies_count": 1,
            "is_anomaly": True,
            "anomalies": [
                {
                    "incident_id": "INC-TEST-8841",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "ip": "198.51.100.45",
                    "method": "POST",
                    "endpoint": "/api/v1/auth",
                    "status_code": 401,
                    "threat_type": "BRUTE_FORCE",
                    "severity": "HIGH",
                    "rule_matched": ["Auth failure / Brute force / Invalid token detected for /api/v1/auth"],
                    "raw_log": "198.51.100.45 - - POST /api/v1/auth HTTP/1.1 401 128 (Failed login attempt 5/5)"
                }
            ],
            "is_local_fallback": False
        }

        return self.notify_threat_analysis(
            analysis_data=test_analysis,
            recipient=recipient or self.current_recipient,
            idempotency_key=f"TEST-RUN-{uuid.uuid4().hex}"
        )

    def retry_latest_notification(self) -> Dict[str, Any]:
        """Retries sending the latest failed notification."""
        latest = self._latest_notification
        if not latest:
            return {"success": False, "message": "No previous notification found to retry."}

        if latest.get("status") not in ("failed", "disabled", "demo_preview"):
            return {
                "success": False,
                "message": f"Notification is currently in '{latest.get('status')}' status and does not require retry."
            }

        # Check if we have the original analysis payload or generate from latest
        payload = latest.get("raw_analysis_payload")
        if not payload:
            payload = {
                "analysis_id": latest.get("analysis_id", f"RETRY-{uuid.uuid4().hex[:6]}"),
                "filename": "retry_incident.log",
                "total_parsed": latest.get("threat_count", 1),
                "anomalies_count": latest.get("threat_count", 1),
                "anomalies": [
                    {
                        "incident_id": "INC-RETRY",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "ip": "127.0.0.1",
                        "method": "GET",
                        "endpoint": "/api/v1/resource",
                        "status_code": 401,
                        "threat_type": latest.get("attack_name", "SUSPICIOUS_ACTIVITY"),
                        "severity": latest.get("severity", "MEDIUM"),
                        "rule_matched": ["Retried security threat notification"]
                    }
                ]
            }

        # Clear idempotency lock for this key
        if latest.get("analysis_id") in self._idempotency_cache:
            del self._idempotency_cache[latest.get("analysis_id")]

        result = self.notify_threat_analysis(
            analysis_data=payload,
            recipient=latest.get("recipient"),
            idempotency_key=f"RETRY-{uuid.uuid4().hex[:8]}"
        )
        return {"success": True, "result": result}

    def get_cached_pdf(self, notification_id: Optional[str] = "latest") -> Optional[bytes]:
        """Returns raw PDF bytes for downloading/previewing the attached report."""
        if not notification_id or notification_id == "latest":
            return self._pdf_cache.get("latest")
        return self._pdf_cache.get(notification_id) or self._pdf_cache.get("latest")

    def handle_webhook_status_update(self, webhook_payload: Dict[str, Any]) -> None:
        """
        Processes Meta delivery status webhooks to update notification state
        from 'accepted' to 'sent', 'delivered', 'read', or 'failed'.
        """
        try:
            entry_list = webhook_payload.get("entry", [])
            for entry in entry_list:
                changes = entry.get("changes", [])
                for change in changes:
                    value = change.get("value", {})
                    statuses = value.get("statuses", [])
                    for s in statuses:
                        msg_id = s.get("id")
                        status_str = s.get("status")  # "sent", "delivered", "read", "failed"
                        if self._latest_notification and self._latest_notification.get("message_id") == msg_id:
                            self._latest_notification["status"] = status_str
                            self._latest_notification["webhook_updated_at"] = datetime.now(timezone.utc).isoformat()
                            logger.info("Notification %s status updated via webhook to: %s", msg_id, status_str)
        except Exception as e:
            logger.warning("Error processing WhatsApp status webhook: %s", e)


# Global singleton instance
whatsapp_service = WhatsAppService()
