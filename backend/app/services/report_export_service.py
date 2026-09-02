"""Serialize the bounded SecurityReport model without repeating report queries."""

import csv
import io
from collections import Counter
from datetime import date
from html import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.schemas.report import SecurityReport


def _csv_cell(value) -> str | int | float:
    """Neutralize spreadsheet formulas while preserving ordinary CSV data."""
    if value is None:
        return ""
    if isinstance(value, (int, float)):
        return value
    text = str(value)
    return "'" + text if text.startswith(("=", "+", "-", "@")) else text


def export_report_csv(report: SecurityReport) -> bytes:
    """Return one safe structured row per attack finding."""
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow([
        "timestamp", "correlation_id", "request_id", "waf_event_id", "attack_type",
        "risk_score", "risk_level", "confidence", "action", "detection_method",
        "request_component", "mitigation",
    ])
    for entry in report.entries:
        writer.writerow([_csv_cell(value) for value in [
            entry.timestamp.isoformat(), entry.correlation_id or "", entry.request_id or "",
            entry.waf_event_id or "", entry.attack_type or "", entry.risk_score,
            entry.risk_level, entry.confidence, entry.action, entry.detection_method or "",
            entry.request_component or "", entry.mitigation or "",
        ]])
    return output.getvalue().encode("utf-8-sig")


def _page_number(canvas, document) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#52606d"))
    canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {document.page}")
    canvas.restoreState()


def export_report_pdf(
    report: SecurityReport,
    *,
    start_date: date | None = None,
    end_date: date | None = None,
) -> bytes:
    """Build a real, bounded PDF from the same report object used by JSON and CSV."""
    output = io.BytesIO()
    document = SimpleDocTemplate(
        output,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="SentinelWeb Security Report",
        author="SentinelWeb",
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "SentinelTitle", parent=styles["Title"], alignment=TA_CENTER,
        textColor=colors.HexColor("#102a43"), spaceAfter=8,
    )
    small = ParagraphStyle("SentinelSmall", parent=styles["BodyText"], fontSize=8, leading=10)
    story = [Paragraph("SentinelWeb Security Report", title_style)]
    range_text = (
        f"{start_date.isoformat() if start_date else 'Beginning'} to "
        f"{end_date.isoformat() if end_date else 'Present'}"
    )
    story.extend([
        Paragraph(
            f"Generated: {escape(report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC'))}",
            styles["BodyText"],
        ),
        Paragraph(f"Report range: {escape(range_text)}", styles["BodyText"]),
        Spacer(1, 8),
        Paragraph("Summary", styles["Heading2"]),
    ])
    summary = Table([
        ["Attack findings", "WAF requests", "Allowed", "Blocked"],
        [report.attack_findings, report.waf_request_count, report.allowed_count, report.blocked_count],
    ], colWidths=[40 * mm] * 4)
    summary.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#243b53")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#bcccdc")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.extend([summary, Spacer(1, 10), Paragraph("Attack distribution", styles["Heading2"])])
    distribution = Counter(entry.attack_type or "Unknown" for entry in report.entries if entry.attack_type)
    if distribution:
        dist_rows = [["Attack type", "Findings"]] + [[name, count] for name, count in sorted(distribution.items())]
        dist_table = Table(dist_rows, colWidths=[100 * mm, 35 * mm])
        dist_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#486581")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#bcccdc")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(dist_table)
    else:
        story.append(Paragraph("No attack findings in this period.", styles["BodyText"]))

    story.extend([Spacer(1, 10), Paragraph("Risk findings and mitigation", styles["Heading2"])])
    for entry in report.entries:
        identifier = entry.correlation_id or f"finding-{entry.id}"
        story.append(Paragraph(
            f"<b>{escape(entry.attack_type or 'Security finding')}</b> - "
            f"risk {entry.risk_score} ({escape(entry.risk_level)}), "
            f"confidence {entry.confidence:.2f}, action {escape(entry.action)}",
            small,
        ))
        story.append(Paragraph(
            f"Correlation: {escape(identifier)}; request ID: {entry.request_id or 'unavailable'}; "
            f"component: {escape(entry.request_component or 'unspecified')}; "
            f"method: {escape(entry.detection_method or 'unspecified')}",
            small,
        ))
        story.append(Paragraph(
            f"Mitigation: {escape(entry.mitigation or 'Review and validate the affected input.')}",
            small,
        ))
        story.append(Spacer(1, 5))
    if report.truncated:
        story.append(Paragraph(
            "This export is truncated at the configured bounded report-entry limit.",
            styles["Italic"],
        ))
    document.build(story, onFirstPage=_page_number, onLaterPages=_page_number)
    return output.getvalue()
