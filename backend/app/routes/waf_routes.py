"""Public fixed-upstream reverse-proxy WAF endpoints."""

import asyncio

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy.orm import Session

from app.core.config import settings
from app.database.database import get_db
from app.services.waf_logging_service import record_waf_event
from app.utils.helpers import get_client_ip
from app.waf.forwarder import (
    UpstreamForwarder,
    UpstreamResponseTooLarge,
    UpstreamTimeout,
    UpstreamUnavailable,
)
from app.waf.inspection import WAFRequestError, inspect_request
from app.waf.policy import inspect_components
from app.services.adaptive_risk_service import calculate_adaptive_risk
from app.services.risk_service import should_block

router = APIRouter(tags=["WAF"])


def get_waf_forwarder(request: Request) -> UpstreamForwarder:
    settings.validate_waf_configuration()
    if not hasattr(request.app.state, "waf_forwarder"):
        request.app.state.waf_forwarder = UpstreamForwarder(
            settings.WAF_UPSTREAM_URL,
            settings.WAF_UPSTREAM_TIMEOUT_SECONDS,
            max_response_bytes=settings.WAF_MAX_UPSTREAM_RESPONSE_BYTES,
        )
    return request.app.state.waf_forwarder


async def waf_concurrency_slot(request: Request):
    if not hasattr(request.app.state, "waf_semaphore"):
        request.app.state.waf_semaphore = asyncio.Semaphore(settings.WAF_MAX_CONCURRENT_REQUESTS)
    semaphore = request.app.state.waf_semaphore
    await semaphore.acquire()
    try:
        yield
    finally:
        semaphore.release()


def _error(status_code: int, detail: str, request_id: str, error_code: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"detail": detail, "request_id": request_id, "error": error_code},
        headers={"X-Request-ID": request_id},
    )


async def _read_limited_body(request: Request) -> bytes:
    configured_length = request.headers.get("content-length")
    if configured_length:
        try:
            lengths = {int(value.strip()) for value in configured_length.split(",")}
            if len(lengths) != 1:
                raise ValueError("conflicting content lengths")
        except ValueError as exc:
            raise WAFRequestError(400, "invalid_content_length", "Invalid Content-Length header") from exc
        if lengths.pop() > settings.WAF_MAX_REQUEST_BODY_BYTES:
            raise WAFRequestError(413, "request_too_large", "Request body exceeds WAF limit")
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > settings.WAF_MAX_REQUEST_BODY_BYTES:
            raise WAFRequestError(413, "request_too_large", "Request body exceeds WAF limit")
        chunks.append(chunk)
    return b"".join(chunks)


def _validate_request_envelope(request: Request) -> None:
    url_size = len(request.scope.get("raw_path", b"")) + len(request.scope.get("query_string", b""))
    if url_size > settings.WAF_MAX_URL_BYTES:
        raise WAFRequestError(414, "uri_too_long", "Request URL exceeds WAF limit")
    header_size = sum(len(name) + len(value) + 4 for name, value in request.scope.get("headers", []))
    if header_size > settings.WAF_MAX_HEADER_BYTES:
        raise WAFRequestError(431, "headers_too_large", "Request headers exceed WAF limit")


@router.get("/api/waf/health")
def waf_health():
    settings.validate_waf_configuration()
    return {
        "status": "healthy",
        "mode": "fixed_upstream_reverse_proxy",
        "block_threshold": settings.RISK_BLOCK_THRESHOLD,
    }


@router.api_route(
    "/waf/{upstream_path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
)
async def proxy_request(
    upstream_path: str,
    request: Request,
    db: Session = Depends(get_db),
    forwarder: UpstreamForwarder = Depends(get_waf_forwarder),
    _slot=Depends(waf_concurrency_slot),
):
    request_id = request.state.correlation_id
    source_ip = get_client_ip(request)
    path = "/" + upstream_path
    try:
        _validate_request_envelope(request)
        body = await _read_limited_body(request)
        components = inspect_request(request, body)
    except WAFRequestError as exc:
        record_waf_event(
            db,
            correlation_id=request_id,
            source_ip=source_ip,
            method=request.method,
            path=path,
            action="rejected",
            error_code=exc.error_code,
        )
        return _error(exc.status_code, exc.detail, request_id, exc.error_code)

    decision = inspect_components(components)
    dominant_finding = max(decision.findings, key=lambda finding: finding.result.risk_score, default=None)
    adaptive = calculate_adaptive_risk(
        db,
        base_score=decision.risk_score,
        attack_detected=bool(decision.findings),
        attack_type=dominant_finding.result.attack_type if dominant_finding else None,
        source_ip=source_ip,
        session_id=getattr(request.state, "session_id", None),
        endpoint=path,
    )
    decision = decision.__class__(
        findings=decision.findings,
        risk_score=adaptive.adaptive_score,
        risk_level=adaptive.risk_level,
        confidence=decision.confidence,
        blocked=should_block(adaptive.adaptive_score),
        base_risk_score=adaptive.base_score,
        adaptive_factors=adaptive.factors,
    )
    if decision.blocked:
        record_waf_event(
            db,
            correlation_id=request_id,
            source_ip=source_ip,
            method=request.method,
            path=path,
            action="blocked",
            decision=decision,
        )
        return JSONResponse(
            status_code=403,
            content={
                "blocked": True,
                "reason": "Malicious request detected",
                "request_id": request_id,
                "risk_score": decision.risk_score,
                "risk_level": decision.risk_level,
            },
            headers={"X-Request-ID": request_id},
        )

    try:
        upstream = await forwarder.forward(
            method=request.method,
            path=upstream_path,
            query_items=list(request.query_params.multi_items()),
            body=body,
            request_headers=request.headers,
            request_id=request_id,
        )
    except UpstreamTimeout:
        record_waf_event(
            db, correlation_id=request_id, source_ip=source_ip, method=request.method,
            path=path, action="error", decision=decision, error_code="upstream_timeout",
        )
        return _error(504, "Upstream service timed out", request_id, "upstream_timeout")
    except UpstreamUnavailable:
        record_waf_event(
            db, correlation_id=request_id, source_ip=source_ip, method=request.method,
            path=path, action="error", decision=decision, error_code="upstream_unavailable",
        )
        return _error(502, "Upstream service unavailable", request_id, "upstream_unavailable")
    except UpstreamResponseTooLarge:
        record_waf_event(
            db, correlation_id=request_id, source_ip=source_ip, method=request.method,
            path=path, action="error", decision=decision, error_code="upstream_response_too_large",
        )
        return _error(502, "Upstream response exceeded WAF limit", request_id, "upstream_response_too_large")

    record_waf_event(
        db,
        correlation_id=request_id,
        source_ip=source_ip,
        method=request.method,
        path=path,
        action="allowed",
        decision=decision,
        upstream_status=upstream.status_code,
    )
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=upstream.headers,
    )
