"""
Report generator utility.

Thin wrapper around report_service that can be used from CLI
or background tasks.  For the API, the route calls report_service
directly.
"""

from datetime import date

from sqlalchemy.orm import Session
from app.services.report_service import generate_report
from app.schemas.report import SecurityReport


def build_security_report(
    db: Session,
    start_date: date | None = None,
    end_date: date | None = None,
) -> SecurityReport:
    """
    Generate a security report and return the Pydantic model.

    This is a convenience wrapper — useful if you later want to
    add file export, email, or PDF generation on top of the base
    report_service.
    """
    return generate_report(db, start_date=start_date, end_date=end_date)
