"""
HTTP request logging middleware.

Logs every inbound request to the console AND persists it to the
request_logs table in PostgreSQL via the logging service.

The original console logging is preserved from the existing codebase.
"""

import time
from fastapi import Request
from app.database.database import SessionLocal
from app.services.logging_service import log_request
from app.utils.helpers import get_client_ip


async def log_requests(request: Request, call_next):
    """
    Middleware function registered via app.middleware("http").

    1. Records the start time.
    2. Forwards the request to the next handler.
    3. Calculates processing time.
    4. Prints to console (original behaviour).
    5. Persists a row to request_logs (new behaviour).
    """
    start_time = time.time()

    response = await call_next(request)

    process_time = time.time() - start_time

    # --- Original console logging (preserved) ---
    print(f"{request.method} {request.url.path} - {process_time:.4f} sec")

    # --- New: persist to database ---
    try:
        db = SessionLocal()
        log_request(
            db=db,
            ip_address=get_client_ip(request),
            method=request.method,
            path=str(request.url.path),
            status_code=response.status_code,
            process_time=round(process_time, 4),
        )
        db.close()
    except Exception:
        # Never let a logging failure break the response
        pass

    return response