"""Configuration, read once from environment variables.

Nothing secret has a production default: if APP_ENV=production and a secret is
missing, the app refuses to start instead of running with a guessable key.
"""
import os


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw else default


class Config:
    def __init__(self, **overrides):
        self.APP_ENV = os.environ.get("APP_ENV", "development")
        production = self.APP_ENV == "production"

        self.DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://tv:tv@127.0.0.1:55432/trustvault")
        # Master key that wraps every per-file data key. Any string works; it is
        # stretched with HKDF. Changing it makes existing files unreadable.
        self.MASTER_KEY = os.environ.get("MASTER_KEY", "" if production else "dev-only-master-key-do-not-use")
        # Signs Flask's flash-message cookie only. Sessions are server-side.
        self.SECRET_KEY = os.environ.get("SECRET_KEY", "" if production else "dev-only-secret-key")

        self.COOKIE_SECURE = _bool("COOKIE_SECURE", production)
        self.SESSION_HOURS = _int("SESSION_HOURS", 8)
        self.IDLE_MINUTES = _int("IDLE_MINUTES", 30)
        self.MAX_UPLOAD_MB = _int("MAX_UPLOAD_MB", 10)
        self.SHARE_MAX_HOURS = _int("SHARE_MAX_HOURS", 168)
        self.TRASH_RETENTION_DAYS = _int("TRASH_RETENTION_DAYS", 30)
        # Number of reverse proxies in front of the app (Render = 1). Used to pick
        # the real client IP from X-Forwarded-For; 0 means use the socket address.
        self.TRUST_PROXY_HOPS = _int("TRUST_PROXY_HOPS", 1 if production else 0)

        self.STORAGE_BACKEND = os.environ.get("STORAGE_BACKEND", "db")  # "db" or "s3"
        self.S3_ENDPOINT = os.environ.get("S3_ENDPOINT", "")
        self.S3_BUCKET = os.environ.get("S3_BUCKET", "")
        self.S3_ACCESS_KEY_ID = os.environ.get("S3_ACCESS_KEY_ID", "")
        self.S3_SECRET_ACCESS_KEY = os.environ.get("S3_SECRET_ACCESS_KEY", "")

        # Optional LLM for access suggestions. Without a key a local heuristic is used.
        self.AI_API_KEY = os.environ.get("AI_API_KEY", "")
        self.AI_MODEL = os.environ.get("AI_MODEL", "claude-haiku-5-5")

        self.LOGIN_RATE_PER_MIN = _int("LOGIN_RATE_PER_MIN", 10)
        self.SHARE_RATE_PER_MIN = _int("SHARE_RATE_PER_MIN", 30)
        self.TESTING = False

        for key, value in overrides.items():
            setattr(self, key, value)

        if production:
            missing = [k for k in ("MASTER_KEY", "SECRET_KEY") if len(getattr(self, k)) < 16]
            if missing:
                raise RuntimeError(f"Refusing to start: set {', '.join(missing)} (16+ characters).")
