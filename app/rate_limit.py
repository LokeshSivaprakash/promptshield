"""
Simple in-memory sliding-window rate limiter, keyed by client IP.

This is intentionally NOT Redis-backed for the MVP -- a single-instance
in-memory limiter is honest about what this project actually does today.
Multi-instance deployments need a shared store (Redis is the obvious
choice, and the interface below is small enough to swap in a Redis
implementation behind it without changing call sites) -- see README roadmap.
"""
import time
from collections import defaultdict, deque


class InMemoryRateLimiter:
    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: dict[str, deque] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        window_start = now - self.window_seconds
        hits = self._hits[key]

        while hits and hits[0] < window_start:
            hits.popleft()

        if len(hits) >= self.max_requests:
            return False

        hits.append(now)
        return True

    def reset(self):
        self._hits.clear()
