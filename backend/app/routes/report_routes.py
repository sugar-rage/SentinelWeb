"""
Report routes.

POST /api/reports/generate  — generate a security report for a date range.
GET  /api/reports/latest    — generate a report with no date filter (all data).
"""

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.schemas.report import SecurityReport, ReportRequest
from app.services.report_service import generate_report
from app.services.report_export_service import export_report_csv, export_report_pdf
from app.auth.dependencies import require_admin
from app.database.models.administrator import Administrator
from app.services.security_audit_service import record_security_event
from app.utils.helpers import get_client_ip

router = APIRouter(prefix="/api/reports", tags=["Reports"])


@router.post("/generate", response_model=SecurityReport)
def create_report(
    body: ReportRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin: Administrator = Depends(require_admin),
):
    """
    Generate a JSON security report. Requires admin.

    Optionally filter by start_date and end_date (YYYY-MM-DD).
    If omitted, all attack logs are included.
    """
    report = generate_report(
        db,
        start_date=body.start_date,
        end_date=body.end_date,
    )
    record_security_event(
        db,
        event_type="admin_report_generated",
        outcome="success",
        user_id=admin.id,
        session_id=getattr(request.state, "session_id", None),
        correlation_id=getattr(request.state, "correlation_id", None),
        ip_address=get_client_ip(request),
        details={"start_date": str(body.start_date) if body.start_date else None, "end_date": str(body.end_date) if body.end_date else None},
    )
    return report


@router.get("/latest", response_model=SecurityReport)
def latest_report(
    request: Request,
    db: Session = Depends(get_db),
    admin: Administrator = Depends(require_admin),
):
    """Generate a report containing all attack logs (no date filter). Requires admin."""
    report = generate_report(db)
    record_security_event(
        db,
        event_type="admin_report_generated",
        outcome="success",
        user_id=admin.id,
        session_id=getattr(request.state, "session_id", None),
        correlation_id=getattr(request.state, "correlation_id", None),
        ip_address=get_client_ip(request),
        details={"range": "all"},
    )
    return report


def _record_export(db, request, admin, export_format: str, body: ReportRequest) -> None:
    record_security_event(
        db,
        event_type="admin_report_exported",
        outcome="success",
        user_id=admin.id,
        session_id=getattr(request.state, "session_id", None),
        correlation_id=getattr(request.state, "correlation_id", None),
        ip_address=get_client_ip(request),
        details={
            "format": export_format,
            "start_date": str(body.start_date) if body.start_date else None,
            "end_date": str(body.end_date) if body.end_date else None,
        },
    )


@router.post("/export/csv")
def export_csv(
    body: ReportRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin: Administrator = Depends(require_admin),
):
    report = generate_report(db, start_date=body.start_date, end_date=body.end_date)
    content = export_report_csv(report)
    _record_export(db, request, admin, "csv", body)
    return Response(
        content=content,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="sentinelweb-security-report.csv"'},
    )


@router.post("/export/pdf")
def export_pdf(
    body: ReportRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin: Administrator = Depends(require_admin),
):
    report = generate_report(db, start_date=body.start_date, end_date=body.end_date)
    content = export_report_pdf(report, start_date=body.start_date, end_date=body.end_date)
    _record_export(db, request, admin, "pdf", body)
    return Response(
        content=content,
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="sentinelweb-security-report.pdf"'},
    )
