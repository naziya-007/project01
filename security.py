"""Passwords, tokens, client identity and rate limiting."""
import base64
import hashlib
import hmac
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque

# scrypt (stdlib, memory-hard). ~32 MiB and ~100 ms per hash on a small instance.
# The test suite lowers N through TV_SCRYPT_N to stay fast; production never sets it.
SCRYPT_N, SCRYPT_R, SCRYPT_P = int(os.environ.get("TV_SCRYPT_N", 2 ** 15)), 8, 1
_MAXMEM = 64 * 1024 * 1024
MIN_PASSWORD_LENGTH = 12


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                            maxmem=_MAXMEM, dklen=32)
    return "scrypt${}${}${}${}${}".format(
        SCRYPT_N, SCRYPT_R, SCRYPT_P,
        base64.b64encode(salt).decode(), base64.b64encode(digest).decode())


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_b64, digest_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        expected = base64.b64decode(digest_b64)
        actual = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt_b64), n=int(n), r=int(r),
                                p=int(p), maxmem=_MAXMEM, dklen=len(expected))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


# Verified against when the e-mail does not exist, so "no such user" costs the
# same time as "wrong password" (no user enumeration by timing).
DUMMY_HASH = hash_password(secrets.token_urlsafe(24))


def password_problem(password: str) -> str | None:
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    if len(password) > 256:
        return "Password is too long."
    return None


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def tokens_equal(a: str | None, b: str | None) -> bool:
    if not a or not b:
        return False
    return hmac.compare_digest(a.encode(), b.encode())


_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def is_uuid(value) -> bool:
    return isinstance(value, str) and bool(_UUID_RE.match(value.lower()))


_EMAIL_RE = re.compile(r"^[^@\s\x00-\x1f\x7f]{1,64}@[^@\s\x00-\x1f\x7f]{1,189}\.[^@\s\x00-\x1f\x7f]{2,}$")


def normalise_email(value) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip().lower()
    return value if _EMAIL_RE.match(value) and len(value) <= 254 else None


def client_ip(request, trusted_hops: int) -> str:
    """Real client IP. With N trusted proxies, each proxy APPENDS the address it
    saw, so the Nth entry from the right is the one our own proxy observed;
    anything to its left was supplied by the client and may be forged."""
    if trusted_hops > 0:
        forwarded = request.headers.get("X-Forwarded-For", "")
        parts = [p.strip() for p in forwarded.split(",") if p.strip()]
        if len(parts) >= trusted_hops:
            return parts[-trusted_hops][:64]
    return (request.remote_addr or "unknown")[:64]


def user_agent(request) -> str:
    return (request.headers.get("User-Agent") or "")[:300]


class RateLimiter:
    """Sliding-window limiter, in process memory. With several gunicorn workers
    each keeps its own window (documented in THREATS.md); the DB-backed account
    lockout in services/users.py is the limit that holds across workers."""

    def __init__(self):
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window_seconds: int = 60) -> bool:
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > window_seconds:
                hits.popleft()
            if len(hits) >= limit:
                return False
            hits.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = RateLimiter()
