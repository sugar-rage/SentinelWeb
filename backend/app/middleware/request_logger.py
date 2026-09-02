"""
HTTP request logging middleware.

Logs every inbound request to the console AND persists it to the
request_logs table in PostgreSQL via the logging service.

The original console logging is preserved from the existing codebase.
"""

import logging
import time
from uuid import UUID, uuid4
from fastapi import Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from app.services.logging_service import log_request
from app.utils.helpers import get_client_ip

logger = logging.getLogger("sentinelweb.request_logger")


def _persist_request(
    factory,
    *,
    correlation_id: str,
    session_id: int | None,
    ip_address: str,
    method: str,
    path: str,
    status_code: int,
    process_time: float,
) -> None:
    """Persist one request from a worker thread and always close its session."""
    db = factory()
    try:
        log_request(
            db=db,
            correlation_id=correlation_id,
            session_id=session_id,
            ip_address=ip_address,
            method=method,
            path=path,
            status_code=status_code,
            process_time=process_time,
        )
    finally:
        db.close()


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
    correlation_id = _correlation_id(request.headers.get("x-request-id"))
    request.state.correlation_id = correlation_id

    status_code = 500
    try:
        response = await call_next(request)
        status_code = response.status_code
        response.headers["X-Request-ID"] = correlation_id
        return response
    except Exception:
        logger.exception("Unhandled request error for %s %s", request.method, request.url.path)
        response = JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "request_id": correlation_id},
            headers={"X-Request-ID": correlation_id},
        )
        return response
    finally:
        process_time = time.time() - start_time
        logger.info("%s %s - %.4f sec", request.method, request.url.path, process_time)
        ip_address = get_client_ip(request)
        try:
            # Keep sync SQLAlchemy out of the event loop; no request body or
            # Authorization header is collected, so JWTs and secrets are not logged.
            await run_in_threadpool(
                _persist_request,
                request.app.state.session_factory,
                correlation_id=correlation_id,
                session_id=getattr(request.state, "session_id", None),
                ip_address=ip_address,
                method=request.method,
                path=str(request.url.path),
                status_code=status_code,
                process_time=round(process_time, 4),
            )
        except Exception:
            # Audit persistence must not replace the original security decision,
            # but it is never silently ignored.
            logger.exception("Request audit logging failed for %s %s", request.method, request.url.path)


def _correlation_id(provided: str | None) -> str:
    """Preserve valid UUID request IDs; replace untrusted values with UUID4."""
    if provided:
        try:
            return str(UUID(provided))
        except (ValueError, AttributeError):
            pass
    return str(uuid4())
