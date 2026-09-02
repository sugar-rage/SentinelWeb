"""Small in-process authentication abuse limiter for a single backend instance."""

from collections import defaultdict, deque
from dataclasses import dataclass
from threading import Lock
from time import monotonic

from app.core.config import settings


@dataclass
class RateLimitDecision:
    allowed: bool
    retry_after: int = 0


class AuthRateLimiter:
    def __init__(self) -> None:
        self._attempts: dict[str, deque[float]] = defaultdict(deque)
        self._locked_until: dict[str, float] = {}
        self._lock = Lock()

    def check(self, key: str) -> RateLimitDecision:
        now = monotonic()
        with self._lock:
            locked_until = self._locked_until.get(key, 0)
            if locked_until > now:
                return RateLimitDecision(False, max(1, int(locked_until - now)))
            attempts = self._attempts[key]
            cutoff = now - settings.AUTH_RATE_LIMIT_WINDOW_SECONDS
            while attempts and attempts[0] < cutoff:
                attempts.popleft()
            if len(attempts) >= settings.AUTH_RATE_LIMIT_ATTEMPTS:
                self._locked_until[key] = now + settings.AUTH_LOCKOUT_SECONDS
                return RateLimitDecision(False, settings.AUTH_LOCKOUT_SECONDS)
            return RateLimitDecision(True)

    def record_failure(self, key: str) -> None:
        with self._lock:
            self._attempts[key].append(monotonic())

    def reset(self, key: str) -> None:
        with self._lock:
            self._attempts.pop(key, None)
            self._locked_until.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._attempts.clear()
            self._locked_until.clear()


auth_rate_limiter = AuthRateLimiter()
