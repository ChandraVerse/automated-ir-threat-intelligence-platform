"""
NIST 800-61 Incident Response Report Generator.
Author  : Chandra Sekhar Chakraborty
Project : Automated IR & Threat Intelligence Platform
"""
from __future__ import annotations
import os
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        HRFlowable, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
    )
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

OUTPUT_DIR = Path(__file__).parent / "output"
OUTPUT_DIR.mkdir(exist_ok=True)


def generate_report(incident: dict[str, Any], ioc_table: list | None = None,
                    timeline: list | None = None, output_path: str | None = None) -> str:
    if not REPORTLAB_AVAILABLE:
        raise ImportError("reportlab is required: pip install reportlab")
    out = output_path or str(OUTPUT_DIR / f"{incident.get('id', 'IR-0001')}.pdf")
    from reportlab.lib import colors as _c
    DARK_BLUE  = _c.HexColor("#0D2137")
    ACCENT     = _c.HexColor("#E63946")
    LIGHT_GREY = _c.HexColor("#F4F6F9")
    MID_GREY   = _c.HexColor("#8896A7")
    WHITE      = _c.white
    base = getSampleStyleSheet()
    styles = {
        "title":    ParagraphStyle("title",    parent=base["Title"],    textColor=WHITE,     fontSize=22, alignment=TA_CENTER),
        "subtitle": ParagraphStyle("subtitle", parent=base["Normal"],   textColor=MID_GREY,  fontSize=11, alignment=TA_CENTER),
        "h1":       ParagraphStyle("h1",       parent=base["Heading1"], textColor=DARK_BLUE, fontSize=14),
        "body":     ParagraphStyle("body",     parent=base["Normal"],   fontSize=9.5,        leading=14),
    }
    doc = SimpleDocTemplate(out, pagesize=A4, leftMargin=2.5*cm, rightMargin=2.5*cm,
                             topMargin=2*cm, bottomMargin=2*cm)
    elements: list = []
    elements.append(Spacer(1, 2*cm))
    elements.append(Paragraph("INCIDENT RESPONSE REPORT", styles["title"]))
    elements.append(Paragraph(incident.get("title", ""), styles["subtitle"]))
    elements.append(PageBreak())
    for title, key in [
        ("1. Executive Summary", "executive_summary"),
        ("2. Detection & Analysis", "detection"),
        ("3. Containment", "containment"),
        ("4. Eradication", "eradication"),
        ("5. Recovery", "recovery"),
        ("6. Lessons Learned", "lessons_learned"),
    ]:
        elements.append(Paragraph(title, styles["h1"]))
        elements.append(HRFlowable(width="100%", thickness=1, color=ACCENT, spaceAfter=6))
        elements.append(Paragraph(incident.get(key, "N/A"), styles["body"]))
        elements.append(Spacer(1, 0.4*cm))
    doc.build(elements)
    return out
