"""Layer 1 controls: who is calling, how often and a record of every decision.

Three building blocks live here:

- KeyRing checks an access key and returns the caller's role. It keeps only
  a fingerprint (SHA-256 hash) of each key, never the key itself. It
  compares fingerprints in constant time so response timing reveals nothing.
- RateLimiter allows each caller a fixed number of requests per minute,
  which protects the system and its model budget from floods.
- AuditLog writes one JSON line per security decision. The question text is
  never written, only its length and fingerprint (data minimisation).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
import time
import uuid
from collections import Counter, deque
from datetime import datetime, timezone
from enum import Enum


class Role(str, Enum):
    """What a caller is allowed to see."""

    ANALYST = "analyst"  # internal and public documents
    VIEWER = "viewer"  # public documents only


# Document classifications each role may read. The agent service applies
# this as a filter inside the vector store search (layer 4).
ROLE_CLEARANCE: dict[Role, list[str]] = {
    Role.ANALYST: ["public", "internal"],
    Role.VIEWER: ["public"],
}


def fingerprint(value: str) -> str:
    """Returns the SHA-256 hash of a value as hexadecimal text."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class KeyRing:
    """Maps access keys to roles without storing the keys themselves."""

    def __init__(self, keys: dict[Role, str]):
        self._entries = [(fingerprint(key), role) for role, key in keys.items() if key]
        if not self._entries:
            raise ValueError("At least one access key must be configured.")

    def identify(self, presented: str | None) -> Role | None:
        """Returns the role for a valid key, or None for a missing or wrong key."""
        if not presented:
            return None
        candidate = fingerprint(presented)
        match: Role | None = None
        # Every entry is compared, even after a match, so the time taken
        # does not depend on which key (if any) was presented.
        for stored, role in self._entries:
            if hmac.compare_digest(stored, candidate):
                match = role
        return match


class RateLimiter:
    """Allows at most `limit_per_minute` requests per caller in any 60 seconds."""

    def __init__(self, limit_per_minute: int, clock=time.monotonic):
        self._limit = limit_per_minute
        self._clock = clock
        self._calls: dict[str, deque] = {}
        self._lock = threading.Lock()

    def check(self, caller: str) -> tuple[bool, int]:
        """Records a call. Returns (allowed, calls remaining in this minute)."""
        now = self._clock()
        with self._lock:
            window = self._calls.setdefault(caller, deque())
            while window and now - window[0] >= 60:
                window.popleft()
            if len(window) >= self._limit:
                return False, 0
            window.append(now)
            return True, self._limit - len(window)


def new_request_id() -> str:
    """A unique ID for each request, returned to the caller and logged."""
    return uuid.uuid4().hex


class AuditLog:
    """One JSON line per security decision, plus running totals for the console."""

    def __init__(self, logger_name: str = "audit"):
        self._logger = logging.getLogger(logger_name)
        self.totals: Counter = Counter()

    def record(self, event: str, **fields) -> dict:
        entry = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, **fields}
        self.totals[event] += 1
        self._logger.info(json.dumps(entry, default=str))
        return entry
