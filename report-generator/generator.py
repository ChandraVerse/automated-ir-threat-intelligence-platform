"""
NIST 800-61 Incident Response Report Generator
Produces a professional PDF report using ReportLab.
"""
from __future__ import annotations
import os
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        HRFlowable,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

OUTPUT_DIR = Path(__file__).parent / "output"
OUTPUT_DIR.mkdir(exist_ok=True)

# ── Colour palette ────────────────────────────────────────────────────────────
DARK_BLUE = colors.HexColor("#0D2137")
ACCENT = colors.HexColor("#E63946")
LIGHT_GREY = colors.HexColor("#F4F6F9")
MID_GREY = colors.HexColor("#8896A7")
WHITE = colors.white
BLACK = colors.black


def _build_styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "title", parent=base["Title"],
            textColor=WHITE, fontSize=22, spaceAfter=6, alignment=TA_CENTER,
        ),
        "subtitle": ParagraphStyle(
            "subtitle", parent=base["Normal"],
            textColor=MID_GREY, fontSize=11, spaceAfter=4, alignment=TA_CENTER,
        ),
        "h1": ParagraphStyle(
            "h1", parent=base["Heading1"],
            textColor=DARK_BLUE, fontSize=14, spaceBefore=14, spaceAfter=6,
            borderPad=4,
        ),
        "h2": ParagraphStyle(
            "h2", parent=base["Heading2"],
            textColor=DARK_BLUE, fontSize=11, spaceBefore=10, spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "body", parent=base["Normal"],
            fontSize=9.5, leading=14, spaceAfter=4,
        ),
        "meta": ParagraphStyle(
            "meta", parent=base["Normal"],
            fontSize=9, textColor=MID_GREY, spaceAfter=2,
        ),
        "code": ParagraphStyle(
            "code", parent=base["Code"],
            fontSize=8, leading=12, backColor=LIGHT_GREY,
            leftIndent=12, rightIndent=12, spaceAfter=6,
        ),
    }


def _cover_page(elements: list, styles: dict, incident: dict) -> None:
    elements.append(Spacer(1, 3 * cm))
    # Dark header block
    header_data = [[Paragraph(f"INCIDENT RESPONSE REPORT", styles["title"])]]
    header_table = Table(header_data, colWidths=[17 * cm])
    header_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), DARK_BLUE),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [DARK_BLUE]),
        ("TOPPADDING", (0, 0), (-1, -1), 18),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 18),
        ("LEFTPADDING", (0, 0), (-1, -1), 20),
        ("RIGHTPADDING", (0, 0), (-1, -1), 20),
    ]))
    elements.append(header_table)
    elements.append(Spacer(1, 0.5 * cm))
    elements.append(Paragraph(incident.get("title", "Untitled Incident"), styles["subtitle"]))
    elements.append(Spacer(1, 1 * cm))

    meta_rows = [
        ["Incident ID", incident.get("id", "IR-0001")],
        ["Severity", incident.get("severity", "HIGH")],
        ["Classification", incident.get("classification", "CONFIDENTIAL")],
        ["Date Generated", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
        ["Analyst", incident.get("analyst", "SOC Analyst")],
        ["Organization", incident.get("org", "Security Operations Centre")],
    ]
    meta_table = Table(meta_rows, colWidths=[5 * cm, 12 * cm])
    meta_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9.5),
        ("TEXTCOLOR", (0, 0), (0, -1), DARK_BLUE),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [LIGHT_GREY, WHITE]),
        ("GRID", (0, 0), (-1, -1), 0.5, MID_GREY),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    elements.append(meta_table)
    elements.append(PageBreak())


def _section(elements: list, styles: dict, title: str, body: str) -> None:
    elements.append(Paragraph(title, styles["h1"]))
    elements.append(HRFlowable(width="100%", thickness=1, color=ACCENT, spaceAfter=6))
    for para in body.strip().split("\n\n"):
        elements.append(Paragraph(para.strip(), styles["body"]))
    elements.append(Spacer(1, 0.4 * cm))


def generate_report(incident: dict[str, Any], ioc_table: list[list] | None = None,
                    timeline: list[dict] | None = None, output_path: str | None = None) -> str:
    """
    Generate a NIST 800-61 PDF report.

    Parameters
    ----------
    incident : dict
        Keys: id, title, severity, classification, analyst, org,
              executive_summary, detection, containment, eradication,
              recovery, lessons_learned
    ioc_table : list of rows  [[IOC, Type, Score, Verdict], ...]
    timeline  : list of dicts [{timestamp, event, actor}, ...]
    output_path : override output file path
    """
    if not REPORTLAB_AVAILABLE:
        raise ImportError("reportlab is required: pip install reportlab")

    out = output_path or str(OUTPUT_DIR / f"{incident.get('id', 'IR-0001')}.pdf")
    doc = SimpleDocTemplate(
        out, pagesize=A4,
        leftMargin=2.5 * cm, rightMargin=2.5 * cm,
        topMargin=2 * cm, bottomMargin=2 * cm,
        title=incident.get("title", "IR Report"),
    )
    styles = _build_styles()
    elements: list = []

    # ── Cover ─────────────────────────────────────────────────────────────
    _cover_page(elements, styles, incident)

    # ── NIST 800-61 Phases ────────────────────────────────────────────────
    phases = [
        ("1. Executive Summary",           incident.get("executive_summary", "N/A")),
        ("2. Detection & Analysis",        incident.get("detection", "N/A")),
        ("3. Containment",                 incident.get("containment", "N/A")),
        ("4. Eradication",                 incident.get("eradication", "N/A")),
        ("5. Recovery",                    incident.get("recovery", "N/A")),
        ("6. Post-Incident / Lessons Learned", incident.get("lessons_learned", "N/A")),
    ]
    for title, body in phases:
        _section(elements, styles, title, body)

    # ── IOC Table ─────────────────────────────────────────────────────────
    if ioc_table:
        elements.append(Paragraph("7. Indicators of Compromise", styles["h1"]))
        elements.append(HRFlowable(width="100%", thickness=1, color=ACCENT, spaceAfter=6))
        headers = [["IOC Value", "Type", "Score", "Verdict"]]
        table_data = headers + ioc_table
        t = Table(table_data, colWidths=[8 * cm, 2.5 * cm, 2 * cm, 3 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), DARK_BLUE),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [LIGHT_GREY, WHITE]),
            ("GRID", (0, 0), (-1, -1), 0.4, MID_GREY),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 0.5 * cm))

    # ── Timeline ──────────────────────────────────────────────────────────
    if timeline:
        elements.append(Paragraph("8. Incident Timeline", styles["h1"]))
        elements.append(HRFlowable(width="100%", thickness=1, color=ACCENT, spaceAfter=6))
        tl_headers = [["Timestamp (UTC)", "Event", "Actor"]]
        tl_rows = [[e.get("timestamp", ""), e.get("event", ""), e.get("actor", "")] for e in timeline]
        tl_table = Table(tl_headers + tl_rows, colWidths=[4 * cm, 10 * cm, 3 * cm])
        tl_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), DARK_BLUE),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [LIGHT_GREY, WHITE]),
            ("GRID", (0, 0), (-1, -1), 0.4, MID_GREY),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(tl_table)

    doc.build(elements)
    return out


# ── CLI quick-test ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    sample = {
        "id": "IR-2024-001",
        "title": "Malicious IP Communication — Cobalt Strike C2",
        "severity": "CRITICAL",
        "classification": "CONFIDENTIAL — TLP:RED",
        "analyst": "SOC Tier-2 Analyst",
        "org": "ChandraVerse Security Operations",
        "executive_summary": (
            "At 14:32 UTC on 2024-03-15, Wazuh SIEM detected outbound C2 communication "
            "to 185.220.101.47 (Tor exit node). VirusTotal returned 52/73 detections. "
            "The host was isolated and the IP blocked at the perimeter firewall within 4 minutes "
            "of detection. No data exfiltration was confirmed."
        ),
        "detection": (
            "Wazuh rule 100510 (CUSTOM — Outbound C2 Beacon Pattern) fired at 14:32 UTC.\n\n"
            "IOC: 185.220.101.47 | AbuseIPDB confidence: 97% | Shodan tags: tor, scanner.\n\n"
            "MITRE ATT&CK: T1071.001 (Application Layer Protocol: Web Protocols), "
            "TA0010 (Command and Control)."
        ),
        "containment": (
            "Host WIN-WORKSTATION-07 isolated via CrowdStrike EDR at 14:34 UTC.\n\n"
            "Perimeter firewall rule added to block 185.220.101.47/32 (both directions) "
            "for 72 hours."
        ),
        "eradication": (
            "Full AV + EDR scan executed. Cobalt Strike beacon artifact found at "
            "C:\\Users\\jsmith\\AppData\\Roaming\\svchost32.exe (SHA256: d41d8cd98f00b204e9800998ecf8427e).\n\n"
            "Artifact quarantined and submitted for sandbox analysis."
        ),
        "recovery": (
            "Host reimaged from golden image. User credentials rotated. "
            "Monitoring enhanced for 14 days post-recovery."
        ),
        "lessons_learned": (
            "Detection gap: beacon used HTTPS on port 443 — SNI inspection rule added.\n\n"
            "Response time 4 min from detection to containment — meets SLA target of <15 min.\n\n"
            "Recommendation: Implement DNS-layer blocking (Umbrella) for all Tor exit nodes."
        ),
    }
    iocs = [
        ["185.220.101.47", "IP", "94", "MALICIOUS"],
        ["d41d8cd98f00b204e9800998ecf8427e", "MD5", "87", "MALICIOUS"],
        ["http://185.220.101.47/beacon", "URL", "91", "MALICIOUS"],
    ]
    tl = [
        {"timestamp": "2024-03-15 14:32:11", "event": "Wazuh alert fired — rule 100510", "actor": "Automated"},
        {"timestamp": "2024-03-15 14:33:05", "event": "IOC enrichment complete — score 94", "actor": "IR Platform"},
        {"timestamp": "2024-03-15 14:34:02", "event": "Host WIN-WORKSTATION-07 isolated", "actor": "SOC Analyst"},
        {"timestamp": "2024-03-15 14:34:58", "event": "Firewall block applied", "actor": "IR Platform"},
        {"timestamp": "2024-03-15 14:40:00", "event": "Jira ticket SEC-1447 created", "actor": "IR Platform"},
        {"timestamp": "2024-03-15 16:00:00", "event": "Host reimaged from golden image", "actor": "IT Ops"},
    ]
    out = generate_report(sample, iocs, tl)
    print(f"Report saved: {out}")
