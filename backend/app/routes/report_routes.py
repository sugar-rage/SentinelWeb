"""
Report routes.

POST /api/reports/generate  — generate a security report for a date range.
GET  /api/reports/latest    — generate a report with no date filter (all data).
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.schemas.report import SecurityReport, ReportRequest
from app.services.report_service import generate_report
from app.auth.dependencies import require_admin
from app.database.models.administrator import Administrator

router = APIRouter(prefix="/api/reports", tags=["Reports"])


@router.post("/generate", response_model=SecurityReport)
def create_report(
    body: ReportRequest,
    db: Session = Depends(get_db),
    admin: Administrator = Depends(require_admin),
):
    """
    Generate a JSON security report. Requires admin.

    Optionally filter by start_date and end_date (YYYY-MM-DD).
    If omitted, all attack logs are included.
    """
    return generate_report(
        db,
        start_date=body.start_date,
        end_date=body.end_date,
    )


@router.get("/latest", response_model=SecurityReport)
def latest_report(
    db: Session = Depends(get_db),
    admin: Administrator = Depends(require_admin),
):
    """Generate a report containing all attack logs (no date filter). Requires admin."""
    return generate_report(db)

