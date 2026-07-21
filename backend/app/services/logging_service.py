"""
Logging service — persists HTTP request metadata to request_logs.

Called by the request_logger middleware on every inbound request.
"""

from sqlalchemy.orm import Session
from app.database.models.request_log import RequestLog
from app.utils.helpers import utc_now


def log_request(
    db: Session,
    ip_address: str,
    method: str,
    path: str,
    status_code: int,
    process_time: float,
) -> None:
    """
    Insert one row into the request_logs table.

    Errors are silently swallowed so a logging failure
    never breaks the actual HTTP response.
    """
    try:
        entry = RequestLog(
            timestamp=utc_now(),
            ip_address=ip_address,
            method=method,
            path=path,
            status_code=status_code,
            process_time=process_time,
        )
        db.add(entry)
        db.commit()
    except Exception:
        db.rollback()
