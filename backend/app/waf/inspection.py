"""Normalize real HTTP request data into bounded, attributable scan components."""

import json
from dataclasses import dataclass
from urllib.parse import parse_qsl

from fastapi import Request

from app.core.config import settings


SUPPORTED_BODY_TYPES = {
    "application/json",
    "application/x-www-form-urlencoded",
    "text/plain",
}
SAFE_INSPECTION_HEADERS = ("user-agent", "referer", "accept-language")


class WAFRequestError(ValueError):
    def __init__(self, status_code: int, error_code: str, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.error_code = error_code
        self.detail = detail


@dataclass(frozen=True)
class InspectionComponent:
    name: str
    value: str


def _json_components(value, prefix: str = "body", depth: int = 1) -> list[InspectionComponent]:
    if depth > settings.WAF_MAX_JSON_DEPTH:
        raise WAFRequestError(400, "json_too_deep", "JSON nesting exceeds WAF limit")
    components: list[InspectionComponent] = []
    if isinstance(value, dict):
        for key, item in value.items():
            components.extend(_json_components(item, f"{prefix}.{str(key)[:80]}", depth + 1))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            components.extend(_json_components(item, f"{prefix}[{index}]", depth + 1))
    elif value is not None:
        components.append(InspectionComponent(prefix, str(value)))
    return components


def inspect_request(request: Request, body: bytes) -> list[InspectionComponent]:
    """Return normalized path/query/header/body fields without credential headers."""
    components = [InspectionComponent("path", request.url.path)]
    components.extend(
        InspectionComponent(f"query.{key[:80]}", value)
        for key, value in request.query_params.multi_items()
    )
    components.extend(
        InspectionComponent(f"header.{name}", request.headers[name])
        for name in SAFE_INSPECTION_HEADERS
        if name in request.headers
    )

    if not body:
        return components

    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type not in SUPPORTED_BODY_TYPES:
        raise WAFRequestError(415, "unsupported_content_type", "Unsupported request content type")

    try:
        body_text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WAFRequestError(400, "invalid_body_encoding", "Request body must be UTF-8") from exc

    if content_type == "application/json":
        try:
            parsed = json.loads(body_text)
        except json.JSONDecodeError as exc:
            raise WAFRequestError(400, "malformed_json", "Malformed JSON request body") from exc
        components.extend(_json_components(parsed))
    elif content_type == "application/x-www-form-urlencoded":
        try:
            fields = parse_qsl(
                body_text,
                keep_blank_values=True,
                max_num_fields=settings.WAF_MAX_FORM_FIELDS,
            )
        except ValueError as exc:
            raise WAFRequestError(400, "too_many_form_fields", "Form field count exceeds WAF limit") from exc
        components.extend(InspectionComponent(f"form.{key[:80]}", value) for key, value in fields)
    else:
        components.append(InspectionComponent("body.text", body_text))
    return components
