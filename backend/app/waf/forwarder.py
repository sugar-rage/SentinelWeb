"""Fixed-destination HTTP forwarding with strict header and timeout boundaries."""

from dataclasses import dataclass

import httpx2 as httpx


FORWARDED_REQUEST_HEADERS = {"accept", "accept-language", "content-type", "user-agent"}
FORWARDED_RESPONSE_HEADERS = {"cache-control", "content-language", "content-type", "etag", "location"}


class UpstreamTimeout(RuntimeError):
    pass


class UpstreamUnavailable(RuntimeError):
    pass


class UpstreamResponseTooLarge(RuntimeError):
    pass


@dataclass(frozen=True)
class UpstreamResponse:
    status_code: int
    content: bytes
    headers: dict[str, str]


class UpstreamForwarder:
    """Forward only to the administrator-configured upstream URL."""

    def __init__(
        self,
        upstream_url: str,
        timeout_seconds: float,
        transport=None,
        max_response_bytes: int = 1024 * 1024,
    ):
        self.base_url = httpx.URL(upstream_url)
        self.timeout_seconds = timeout_seconds
        self.transport = transport
        self.max_response_bytes = max_response_bytes
        self._client = None

    def _client_instance(self):
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=self.timeout_seconds,
                follow_redirects=False,
                transport=self.transport,
                limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
            )
        return self._client

    async def close(self) -> None:
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()

    def _target(self, path: str) -> httpx.URL:
        base_path = self.base_url.path.rstrip("/")
        safe_path = "/" + path.lstrip("/")
        return self.base_url.copy_with(path=f"{base_path}{safe_path}", query=None, fragment=None)

    async def forward(
        self,
        *,
        method: str,
        path: str,
        query_items: list[tuple[str, str]],
        body: bytes,
        request_headers,
        request_id: str,
    ) -> UpstreamResponse:
        headers = {
            name: value
            for name, value in request_headers.items()
            if name.lower() in FORWARDED_REQUEST_HEADERS
        }
        headers["X-Request-ID"] = request_id
        try:
            client = self._client_instance()
            async with client.stream(
                    method,
                    self._target(path),
                    params=query_items,
                    content=body,
                    headers=headers,
            ) as response:
                content_length = response.headers.get("content-length")
                if content_length:
                    try:
                        if int(content_length) > self.max_response_bytes:
                            raise UpstreamResponseTooLarge("Configured upstream response limit exceeded")
                    except ValueError:
                        pass
                chunks: list[bytes] = []
                size = 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > self.max_response_bytes:
                        raise UpstreamResponseTooLarge("Configured upstream response limit exceeded")
                    chunks.append(chunk)
                content = b"".join(chunks)
                status_code = response.status_code
                response_headers = {
                    name: value
                    for name, value in response.headers.items()
                    if name.lower() in FORWARDED_RESPONSE_HEADERS
                }
        except httpx.TimeoutException as exc:
            raise UpstreamTimeout("The configured upstream timed out") from exc
        except (httpx.RequestError, ValueError) as exc:
            raise UpstreamUnavailable("The configured upstream is unavailable") from exc
        return UpstreamResponse(status_code, content, response_headers)
