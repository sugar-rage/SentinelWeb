"""
Shared utility helpers used across the backend.

Keeps small, reusable functions in one place.
"""

from datetime import datetime, timezone
import ipaddress
import re

from app.core.config import settings


_FORWARDED_FOR = re.compile(r'(?:^|[;,])\s*for=("[^\"]+"|[^;,]+)', re.IGNORECASE)


def _ip_address(value: str):
    value = value.strip().strip('"')
    if value.startswith("[") and "]" in value:
        value = value[1:value.index("]")]
    elif value.count(":") == 1 and "." in value:
        value = value.rsplit(":", 1)[0]
    if value.lower() == "unknown" or value.startswith("_"):
        raise ValueError("non-IP forwarding identifier")
    return ipaddress.ip_address(value)


def _is_trusted(address) -> bool:
    return any(address in network for network in settings.TRUSTED_PROXY_NETWORKS)


def get_client_ip(request) -> str:
    """Resolve source identity, trusting forwarding headers only from configured proxies."""
    if not request.client:
        return "unknown"
    peer_text = request.client.host
    try:
        peer = _ip_address(peer_text)
    except ValueError:
        return peer_text
    if not _is_trusted(peer):
        return str(peer)

    forwarded = request.headers.get("forwarded")
    x_forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded and x_forwarded_for:
        return str(peer)
    try:
        if forwarded:
            supplied = [_ip_address(match.group(1)) for match in _FORWARDED_FOR.finditer(forwarded)]
        elif x_forwarded_for:
            supplied = [_ip_address(value) for value in x_forwarded_for.split(",")]
        else:
            return str(peer)
    except ValueError:
        return str(peer)
    if not supplied:
        return str(peer)

    for address in reversed([*supplied, peer]):
        if not _is_trusted(address):
            return str(address)
    return str(supplied[0])


def utc_now() -> datetime:
    """Return an aware UTC timestamp."""
    return datetime.now(timezone.utc)
