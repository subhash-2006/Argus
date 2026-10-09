import io
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically compute and render total page count
    and running headers/footers.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))

        # Running Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(36, 11 * 72 - 28, "Log Sentinel | AI Security Operations Center — Incident Report")
            self.setStrokeColor(colors.HexColor("#E2E8F0"))
            self.setLineWidth(0.5)
            self.line(36, 11 * 72 - 32, 8.5 * 72 - 36, 11 * 72 - 32)

        # Running Footer
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(8.5 * 72 - 36, 25, page_text)
        self.drawString(36, 25, "CONFIDENTIAL & PROPRIETARY — FOR AUTHORIZED DEVELOPER / SOC USE ONLY")
        self.setStrokeColor(colors.HexColor("#E2E8F0"))
        self.setLineWidth(0.5)
        self.line(36, 35, 8.5 * 72 - 36, 35)

        self.restoreState()


def get_severity_color(severity: str) -> colors.Color:
    sev = (severity or "").upper()
    if sev == "CRITICAL":
        return colors.HexColor("#DC2626")  # Red
    elif sev == "HIGH":
        return colors.HexColor("#EA580C")  # Orange
    elif sev == "MEDIUM":
        return colors.HexColor("#D97706")  # Amber
    elif sev == "LOW":
        return colors.HexColor("#2563EB")  # Blue
    return colors.HexColor("#16A34A")  # Green / Info


def generate_incident_pdf(incident_data: Dict[str, Any]) -> bytes:
    """
    Generates a professional multi-page PDF Incident Report for the given incident dataset.
    Returns raw PDF bytes.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=40,
        bottomMargin=45
    )

    styles = getSampleStyleSheet()

    # Custom typography styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0F172A")
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#3B82F6")
    )
    section_heading = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#1E293B"),
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True
    )
    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['BodyText'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=14,
        textColor=colors.HexColor("#334155")
    )
    body_bold = ParagraphStyle(
        'BodyBold',
        parent=body_style,
        fontName='Helvetica-Bold'
    )
    code_style = ParagraphStyle(
        'CodeStyle',
        fontName='Courier',
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#0F172A"),
        backColor=colors.HexColor("#F1F5F9"),
        borderColor=colors.HexColor("#CBD5E1"),
        borderWidth=0.5,
        borderPadding=6,
        spaceBefore=4,
        spaceAfter=6
    )
    table_cell_style = ParagraphStyle(
        'TableCell',
        fontName='Helvetica',
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#1E293B")
    )
    table_cell_header = ParagraphStyle(
        'TableCellHeader',
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#FFFFFF")
    )

    story = []

    # Extract Data Fields
    inc_id = incident_data.get("incident_id") or "INC-UNKNOWN"
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    threat_type = incident_data.get("threat_type", "SECURITY_ANOMALY")
    severity = incident_data.get("severity", "MEDIUM")
    ip = incident_data.get("ip", "N/A")
    method = incident_data.get("method", "N/A")
    endpoint = incident_data.get("endpoint", "N/A")
    status_code = str(incident_data.get("status_code", "N/A"))
    timestamp = incident_data.get("timestamp", now_str)
    user_agent = incident_data.get("user_agent", "N/A")
    raw_log = incident_data.get("raw_log", "N/A")
    rules_matched = incident_data.get("rule_matched") or ["Rule-based anomaly threshold triggered"]
    if isinstance(rules_matched, list):
        rules_matched_str = "; ".join(rules_matched)
    else:
        rules_matched_str = str(rules_matched)

    gemini_triage = incident_data.get("gemini_triage") or {}
    plain_summary = gemini_triage.get("plain_summary") or gemini_triage.get("plain_english_summary") or (
        f"Anomalous web request detected from IP {ip} targeting endpoint '{endpoint}'. "
        f"The threat pattern matches {threat_type} with {severity} severity."
    )
    technical_details = gemini_triage.get("technical_details") or (
        f"HTTP {method} request to '{endpoint}' returned status {status_code}. "
        f"Matched detection rules: {rules_matched_str}."
    )

    mitre_obj = gemini_triage.get("mitre") or {}
    mitre_id = mitre_obj.get("id") or incident_data.get("mitre_id") or "T1190"
    mitre_name = mitre_obj.get("name") or "Exploit Public-Facing Application"

    confidence_score = incident_data.get("ml_anomaly_prob")
    if confidence_score is not None:
        confidence_str = f"{float(confidence_score) * 100:.1f}%"
    else:
        confidence_str = f"{float(gemini_triage.get('confidence', 0.95)) * 100:.1f}%"

    remediation_obj = gemini_triage.get("remediation") or {}
    nginx_rule = remediation_obj.get("nginx_block") or f"location = {endpoint} {{\n    deny {ip};\n}}"
    firewall_rule = remediation_obj.get("firewall") or f"iptables -A INPUT -s {ip} -j DROP"

    events_list = incident_data.get("related_events") or [incident_data]
    total_events = len(events_list)

    # HEADER BANNER
    story.append(Paragraph("LOG SENTINEL | SECURITY INCIDENT REPORT", subtitle_style))
    story.append(Spacer(1, 2))
    story.append(Paragraph(f"Incident Analysis & Mitigation Guide: {inc_id}", title_style))
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0F172A"), spaceBefore=2, spaceAfter=10))

    # SECTION 1: INCIDENT OVERVIEW
    story.append(Paragraph("1. Incident Overview", section_heading))

    sev_color = get_severity_color(severity)
    overview_data = [
        [
            Paragraph("<b>Incident ID:</b>", table_cell_style),
            Paragraph(inc_id, table_cell_style),
            Paragraph("<b>Generated At:</b>", table_cell_style),
            Paragraph(now_str, table_cell_style),
        ],
        [
            Paragraph("<b>Threat Category:</b>", table_cell_style),
            Paragraph(f"<b>{threat_type.replace('_', ' ')}</b>", table_cell_style),
            Paragraph("<b>Severity / Confidence:</b>", table_cell_style),
            Paragraph(f"<font color='{sev_color.hexval()}'><b>{severity}</b></font> ({confidence_str})", table_cell_style),
        ],
        [
            Paragraph("<b>Attacker IP:</b>", table_cell_style),
            Paragraph(ip, table_cell_style),
            Paragraph("<b>Status:</b>", table_cell_style),
            Paragraph("<font color='#DC2626'><b>ACTIVE / UNCONTAINED</b></font>", table_cell_style),
        ],
        [
            Paragraph("<b>Target Endpoint:</b>", table_cell_style),
            Paragraph(f"<code>{method} {endpoint}</code>", table_cell_style),
            Paragraph("<b>HTTP Status Code:</b>", table_cell_style),
            Paragraph(status_code, table_cell_style),
        ],
        [
            Paragraph("<b>MITRE ATT&CK:</b>", table_cell_style),
            Paragraph(f"<b>{mitre_id}</b> — {mitre_name}", table_cell_style),
            Paragraph("<b>Total Related Events:</b>", table_cell_style),
            Paragraph(str(total_events), table_cell_style),
        ],
    ]

    t_overview = Table(overview_data, colWidths=[110, 160, 110, 160])
    t_overview.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ('PADDING', (0, 0), (-1, -1), 5),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(t_overview)
    story.append(Spacer(1, 10))

    # SECTION 2: EXECUTIVE SUMMARY
    story.append(Paragraph("2. Executive Summary (Developer & Management Brief)", section_heading))
    exec_summary_text = (
        f"<b>What Happened:</b> {plain_summary}<br/><br/>"
        f"<b>Suspected Attack Vector:</b> The automated detection engine flagged traffic matching <b>{threat_type}</b> "
        f"patterns originating from IP <code>{ip}</code> targeting <code>{endpoint}</code>.<br/><br/>"
        f"<b>Why it is Suspicious:</b> The incoming request exhibited high-risk characteristics, including "
        f"matched security signatures ({rules_matched_str}) and abnormal request structure.<br/><br/>"
        f"<b>Potential Business & Technical Impact:</b> If left unmitigated, this vector could allow unauthorized "
        f"data access, system compromise, authentication bypass, or denial of service on application services.<br/><br/>"
        f"<b>Current Evidence Status:</b> Observed request telemetry has been verified against rule engines, Shannon entropy analysis, "
        f"and machine learning baselines."
    )
    story.append(Paragraph(exec_summary_text, body_style))
    story.append(Spacer(1, 10))

    # SECTION 3: EVIDENCE AND ATTACK TIMELINE
    story.append(Paragraph("3. Evidence & Attack Timeline", section_heading))
    story.append(Paragraph(
        "Chronological log telemetry collected for this incident. Events are grouped based on shared client IP, "
        "target endpoints, and temporal proximity.", body_style
    ))
    story.append(Spacer(1, 6))

    timeline_headers = [
        Paragraph("Timestamp", table_cell_header),
        Paragraph("Method", table_cell_header),
        Paragraph("Endpoint", table_cell_header),
        Paragraph("Status", table_cell_header),
        Paragraph("Matched Rule / Detection", table_cell_header),
    ]
    timeline_rows = [timeline_headers]

    for ev in events_list[:8]:  # Limit to top 8 events for space efficiency
        ev_ts = ev.get("timestamp") or timestamp
        ev_m = ev.get("method") or method
        ev_ep = ev.get("endpoint") or endpoint
        ev_st = str(ev.get("status_code") or status_code)
        ev_rule = ev.get("rule_matched") or rules_matched
        if isinstance(ev_rule, list):
            ev_rule_str = ev_rule[0] if ev_rule else "Rule match"
        else:
            ev_rule_str = str(ev_rule)

        timeline_rows.append([
            Paragraph(ev_ts.replace("T", " ")[:19], table_cell_style),
            Paragraph(ev_m, table_cell_style),
            Paragraph(f"<code>{ev_ep[:30]}</code>", table_cell_style),
            Paragraph(ev_st, table_cell_style),
            Paragraph(ev_rule_str[:40], table_cell_style),
        ])

    t_timeline = Table(timeline_rows, colWidths=[100, 45, 145, 45, 205])
    t_timeline.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1E293B")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor("#FFFFFF"), colors.HexColor("#F8FAFC")]),
        ('PADDING', (0, 0), (-1, -1), 4),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    story.append(t_timeline)
    story.append(Spacer(1, 10))

    # SECTION 4: TECHNICAL ANALYSIS
    story.append(Paragraph("4. Technical Analysis (Developer Perspective)", section_heading))
    tech_text = (
        f"<b>Attack Mechanism:</b> {technical_details}<br/><br/>"
        f"<b>Observed vs. Inferred Data:</b><br/>"
        f"• <i>Observed:</i> HTTP {method} request from IP <code>{ip}</code> to <code>{endpoint}</code> returning HTTP {status_code}. User Agent: <code>{user_agent}</code>.<br/>"
        f"• <i>Inferred:</i> Automated scan/exploit attempt matching MITRE ATT&CK <b>{mitre_id} ({mitre_name})</b>.<br/><br/>"
        f"<b>Detection Pipeline Engines Fired:</b><br/>"
        f"1. <b>Rule Matching:</b> {rules_matched_str}<br/>"
        f"2. <b>CSIC 2010 Isolation Forest ML Model:</b> Anomaly confidence {confidence_str}.<br/>"
        f"3. <b>Gemini AI Triage:</b> Automated contextual impact evaluation."
    )
    story.append(Paragraph(tech_text, body_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph("Raw Log Sample:", body_bold))
    story.append(Paragraph(raw_log.replace("<", "&lt;").replace(">", "&gt;"), code_style))
    story.append(Spacer(1, 10))

    # SECTION 5: REMEDIATION PLAN
    story.append(Paragraph("5. Prioritized Remediation Plan", section_heading))
    
    remed_text = (
        "<b>Priority 1 — Immediate Containment:</b><br/>"
        f"Block offending IP address at the firewall or reverse proxy immediately.<br/>"
        f"<b>Nginx Rule:</b><br/>"
    )
    story.append(Paragraph(remed_text, body_style))
    story.append(Paragraph(nginx_rule, code_style))

    story.append(Paragraph("<b>Linux iptables Command:</b>", body_style))
    story.append(Paragraph(firewall_rule, code_style))

    app_fixes_text = (
        "<b>Priority 2 — Application Code Fixes:</b><br/>"
        "• Validate and sanitize all incoming input parameters on server-side.<br/>"
        "• Use parameterized queries (ORM / Prepared Statements) to prevent SQL Injection.<br/>"
        "• Implement rate limiting middleware (e.g. max 10 requests/minute per IP on sensitive routes).<br/><br/>"
        "<b>Priority 3 — Infrastructure & Authentication Enhancements:</b><br/>"
        "• Enable WAF (Web Application Firewall) rules on Cloudflare or Render.<br/>"
        "• Require Multi-Factor Authentication (MFA) and account lockouts after consecutive failed attempts."
    )
    story.append(Paragraph(app_fixes_text, body_style))
    story.append(Spacer(1, 10))

    # SECTION 6: DEVELOPER ACTION CHECKLIST
    story.append(Paragraph("6. Developer Action Checklist", section_heading))
    checklist_items = [
        "<b>[ ] Step 1: Verification</b> — Inspect server access logs to confirm if IP <code>" + ip + "</code> reached internal resources.",
        "<b>[ ] Step 2: Containment</b> — Execute Nginx or iptables block rule to drop malicious traffic.",
        "<b>[ ] Step 3: Patch Codebase</b> — Review <code>" + endpoint + "</code> controller logic for input validation vulnerabilities.",
        "<b>[ ] Step 4: Test Fixes</b> — Perform unit and regression tests with security payloads (e.g., SQLi/XSS test suites).",
        "<b>[ ] Step 5: Post-Incident Review</b> — Verify log alerts in Log Sentinel dashboard and confirm zero recurring anomalies."
    ]
    for chk in checklist_items:
        story.append(Paragraph(chk, body_style))
        story.append(Spacer(1, 3))
    story.append(Spacer(1, 10))

    # SECTION 7: VALIDATION AND REFERENCES
    story.append(Paragraph("7. Validation & References", section_heading))
    refs_text = (
        f"• <b>MITRE ATT&CK Framework:</b> <font color='#2563EB'><u>https://attack.mitre.org/techniques/{mitre_id.replace('.', '/')}</u></font><br/>"
        f"• <b>OWASP Top 10 Web Application Security Risks</b> (A03:2021-Injection, A01:2021-Broken Access Control)<br/>"
        f"• <b>Log Sentinel Telemetry System:</b> Verified via Rules Engine, CSIC 2010 ML Model, and Gemini 2.5/3.5 Flash AI."
    )
    story.append(Paragraph(refs_text, body_style))

    # Build Document
    doc.build(story, canvasmaker=NumberedCanvas)
    buffer.seek(0)
    return buffer.getvalue()


def generate_summary_pdf(incidents: List[Dict[str, Any]]) -> bytes:
    """
    Generates a professional multi-incident summary PDF report.
    Returns raw PDF bytes.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=40,
        bottomMargin=45
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'SummaryDocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0F172A")
    )
    subtitle_style = ParagraphStyle(
        'SummaryDocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#3B82F6")
    )
    section_heading = ParagraphStyle(
        'SummarySectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#1E293B"),
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=True
    )
    body_style = ParagraphStyle(
        'SummaryBodyDark',
        parent=styles['BodyText'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155")
    )
    table_cell_style = ParagraphStyle(
        'SummaryTableCell',
        fontName='Helvetica',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#1E293B")
    )
    table_cell_header = ParagraphStyle(
        'SummaryTableCellHeader',
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#FFFFFF")
    )

    story = []
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    story.append(Paragraph("LOG SENTINEL | AI SECURITY OPERATIONS CENTER", subtitle_style))
    story.append(Spacer(1, 2))
    story.append(Paragraph("Executive Incident Summary Report", title_style))
    story.append(Spacer(1, 4))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0F172A"), spaceBefore=2, spaceAfter=8))

    incidents_list = incidents or []
    total_inc = len(incidents_list)

    # Severity Counts
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    threat_types = set()
    attacker_ips = set()

    for inc in incidents_list:
        sev = (inc.get("severity") or "MEDIUM").upper()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        if inc.get("threat_type"):
            threat_types.add(inc.get("threat_type"))
        if inc.get("ip"):
            attacker_ips.add(inc.get("ip"))

    # Overview Table
    summary_meta = [
        [
            Paragraph("<b>Generated At:</b>", table_cell_style),
            Paragraph(now_str, table_cell_style),
            Paragraph("<b>Total Incidents:</b>", table_cell_style),
            Paragraph(f"<b>{total_inc}</b>", table_cell_style),
        ],
        [
            Paragraph("<b>Critical Threats:</b>", table_cell_style),
            Paragraph(f"<font color='#DC2626'><b>{sev_counts['CRITICAL']}</b></font>", table_cell_style),
            Paragraph("<b>High Threats:</b>", table_cell_style),
            Paragraph(f"<font color='#EA580C'><b>{sev_counts['HIGH']}</b></font>", table_cell_style),
        ],
        [
            Paragraph("<b>Medium / Low Threats:</b>", table_cell_style),
            Paragraph(f"{sev_counts['MEDIUM']} Medium, {sev_counts['LOW']} Low", table_cell_style),
            Paragraph("<b>Unique Attacker IPs:</b>", table_cell_style),
            Paragraph(str(len(attacker_ips)), table_cell_style),
        ]
    ]

    t_meta = Table(summary_meta, colWidths=[120, 150, 120, 150])
    t_meta.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ('PADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 10))

    # Incident List Table
    story.append(Paragraph("Incident Telemetry Summary", section_heading))
    
    if not incidents_list:
        story.append(Paragraph("<i>No active security incidents recorded in this reporting window. All system telemetry operating normally.</i>", body_style))
    else:
        table_headers = [
            Paragraph("Incident ID", table_cell_header),
            Paragraph("Timestamp", table_cell_header),
            Paragraph("IP Address", table_cell_header),
            Paragraph("Threat Category", table_cell_header),
            Paragraph("Severity", table_cell_header),
            Paragraph("Target Endpoint", table_cell_header)
        ]
        inc_rows = [table_headers]

        for inc in incidents_list[:30]:  # Up to 30 incidents in summary report
            inc_id = inc.get("incident_id") or "INC-LOG"
            ts = inc.get("timestamp") or "N/A"
            ts_clean = ts.replace("T", " ")[:19]
            ip = inc.get("ip") or "127.0.0.1"
            threat = inc.get("threat_type") or "ANOMALY"
            sev = (inc.get("severity") or "MEDIUM").upper()
            ep = inc.get("endpoint") or "/"
            sev_c = get_severity_color(sev)

            inc_rows.append([
                Paragraph(inc_id, table_cell_style),
                Paragraph(ts_clean, table_cell_style),
                Paragraph(ip, table_cell_style),
                Paragraph(threat.replace("_", " "), table_cell_style),
                Paragraph(f"<font color='{sev_c.hexval()}'><b>{sev}</b></font>", table_cell_style),
                Paragraph(f"<code>{ep[:25]}</code>", table_cell_style)
            ])

        t_incidents = Table(inc_rows, colWidths=[80, 95, 80, 105, 55, 125])
        t_incidents.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1E293B")),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor("#FFFFFF"), colors.HexColor("#F8FAFC")]),
            ('PADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(t_incidents)

    story.append(Spacer(1, 12))
    story.append(Paragraph("Recommended Action Plan", section_heading))
    story.append(Paragraph(
        "1. Block persistent attacker IPs at reverse proxy and firewall layers.<br/>"
        "2. Review target endpoints flagged with SQL Injection or Honeytoken access.<br/>"
        "3. Deploy patched application builds and rate-limiting rules.", body_style
    ))

    doc.build(story, canvasmaker=NumberedCanvas)
    buffer.seek(0)
    return buffer.getvalue()

