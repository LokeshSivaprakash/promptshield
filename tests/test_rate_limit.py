import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.rate_limit import InMemoryRateLimiter


def test_allows_up_to_the_limit():
    limiter = InMemoryRateLimiter(max_requests=3, window_seconds=60)
    assert limiter.allow("client-a") is True
    assert limiter.allow("client-a") is True
    assert limiter.allow("client-a") is True
    assert limiter.allow("client-a") is False


def test_separate_keys_have_independent_budgets():
    limiter = InMemoryRateLimiter(max_requests=1, window_seconds=60)
    assert limiter.allow("client-a") is True
    assert limiter.allow("client-b") is True
    assert limiter.allow("client-a") is False
    assert limiter.allow("client-b") is False


def test_window_expiry_allows_new_requests():
    limiter = InMemoryRateLimiter(max_requests=1, window_seconds=0)  # zero-width window -> always expires immediately
    assert limiter.allow("client-a") is True
    assert limiter.allow("client-a") is True  # previous hit already outside the (empty) window
