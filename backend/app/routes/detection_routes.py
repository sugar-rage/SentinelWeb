"""
Detection / scan routes.

POST /api/scan        — scan a single payload for attacks.
POST /api/scan/batch  — scan multiple payloads in one request.
"""

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from typing import List

from app.database.database import get_db
from app.schemas.detection import ScanRequest, ScanResponse
from app.services.detection_service import scan_payload
from app.utils.helpers import get_client_ip
from app.auth.dependencies import get_current_user
from app.database.models.administrator import Administrator

router = APIRouter(prefix="/api/scan", tags=["Detection"])


@router.post("", response_model=ScanResponse)
def scan(
    body: ScanRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: Administrator = Depends(get_current_user),
):
    """
    Scan a single payload for SQL Injection, XSS, or Prompt Injection.

    Requires authentication. Returns the detection result, risk score, and action taken.
    """
    ip = get_client_ip(request)
    return scan_payload(payload=body.payload, ip_address=ip, db=db)


@router.post("/batch", response_model=List[ScanResponse])
def scan_batch(
    payloads: List[ScanRequest],
    request: Request,
    db: Session = Depends(get_db),
    current_user: Administrator = Depends(get_current_user),
):
    """
    Scan multiple payloads in a single API call.

    Requires authentication. Each payload is processed independently and logged separately.
    """
    ip = get_client_ip(request)
    return [
        scan_payload(payload=item.payload, ip_address=ip, db=db)
        for item in payloads
    ]

