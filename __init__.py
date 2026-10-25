"""TrustVault application factory and request lifecycle.

Per request:
  1. load the session (if any) and publish the user to the DB context (RLS);
  2. reject unsafe methods without a valid CSRF token, and cross-site requests;
  3. run the view, which calls a service, which calls authorize() first;
  4. commit only if the response is a success (the audit row commits with the
     action, and if that commit fails the client gets a 500, not the file);
  5. otherwise roll back, then write any queued refusals in a fresh transaction.
"""
import logging
import uuid

from flask import Flask, g, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

from . import audit, crypto, security
from .config import Config
from .db import Database, DbError, sqlstate

SESSION_COOKIE = "tv_session"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
# Endpoints reachable without a session; they carry no ambient authority.
CSRF_EXEMPT = {"api.login", "ui.login", "api.share_info", "api.share_download", "ui.share_download", "ui.healthz"}


def create_app(config: Config | None = None) -> Flask:
    cfg = config or Config()
    app = Flask(__name__)
    app.config["TV"] = cfg
    app.config["SECRET_KEY"] = cfg.SECRET_KEY
    app.config["TESTING"] = cfg.TESTING
    app.config["TRUST_PROXY_HOPS"] = cfg.TRUST_PROXY_HOPS
    app.config["MASTER_KEY_BYTES"] = crypto.derive_master_key(cfg.MASTER_KEY)
    # Reject oversized bodies before they are read (upload limit + form overhead).
    app.config["MAX_CONTENT_LENGTH"] = cfg.MAX_UPLOAD_MB * 1024 * 1024 + 256 * 1024
    app.config["SESSION_COOKIE_NAME"] = "tv_flash"
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = cfg.COOKIE_SECURE
    logging.basicConfig(level=logging.INFO)

    from .web.api import bp as api_bp
    from .web.ui import bp as ui_bp

    app.register_blueprint(api_bp)
    app.register_blueprint(ui_bp)

    @app.before_request
    def _load_user():
        g.request_id = uuid.uuid4().hex[:12]
        g.user = None
        g.session = None
        g.force_commit = False
        if request.endpoint in ("static", "ui.healthz"):
            return None
        db = get_db()
        token = request.cookies.get(SESSION_COOKIE)
        if token:
            loaded = _users().load_session(db, token, cfg.IDLE_MINUTES)
            if loaded:
                g.user, g.session = loaded
                db.set_context(user_id=g.user["id"], role=g.user["role"])
            else:
                g.clear_cookie = True
        return _check_csrf()

    @app.after_request
    def _after(response):
        _finish_transaction(response)
        _security_headers(response, cfg)
        if g.get("clear_cookie"):
            response.delete_cookie(SESSION_COOKIE, path="/")
        return response

    @app.teardown_request
    def _close(exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    @app.errorhandler(HTTPException)
    def _http_error(exc: HTTPException):
        return _error_response(exc.code, exc.name, exc.description if exc.code in (400, 403, 413, 429) else None)

    @app.errorhandler(DbError)
    def _db_error(exc):
        if sqlstate(exc) == "42501":
            # Row-level security or a guard trigger refused the operation: the
            # second lock caught something the first did not. Audit and 404.
            if g.get("db") is not None:
                audit.deny(g.db, "access_denied", actor=g.get("user"),
                           details={"reason": "database_policy", "endpoint": request.endpoint})
            return _error_response(404, "Not Found", None)
        app.logger.exception("database error (request %s)", g.get("request_id"))
        return _error_response(500, "Internal Server Error", None)

    @app.errorhandler(Exception)
    def _unhandled(exc):
        if isinstance(exc, HTTPException):
            return _http_error(exc)
        app.logger.exception("unhandled error (request %s)", g.get("request_id"))
        return _error_response(500, "Internal Server Error", None)

    return app


def _users():
    from .services import users

    return users


def get_db() -> Database:
    if "db" not in g:
        from flask import current_app

        g.db = Database(current_app.config["TV"].DATABASE_URL)
    return g.db


def _check_csrf():
    if request.method in SAFE_METHODS:
        return None
    # Browsers label cross-site requests; refuse them outright for state changes.
    if request.headers.get("Sec-Fetch-Site") == "cross-site":
        return _error_response(403, "Forbidden", "Cross-site request refused.")
    if request.endpoint in CSRF_EXEMPT:
        return None
    if g.user is None:
        return None  # the view's login check answers 401 / redirect
    sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
    if not security.tokens_equal(sent, g.session["csrf_token"]):
        audit.deny(get_db(), "csrf_rejected", actor=g.user, details={"endpoint": request.endpoint})
        return _error_response(403, "Forbidden", "Missing or invalid CSRF token.")
    return None


def _finish_transaction(response) -> None:
    db = g.get("db")
    if db is None:
        return
    try:
        if response.status_code < 400 or g.get("force_commit"):
            db.commit()
        else:
            db.rollback()
        if g.get("pending_audit"):
            audit.flush_pending(db)
            db.commit()
    except Exception:
        db.rollback()
        logging.getLogger(__name__).exception("commit failed; refusing to send the response")
        raise


def _security_headers(response, cfg) -> None:
    h = response.headers
    h["Content-Security-Policy"] = ("default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
                                    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
    h["X-Content-Type-Options"] = "nosniff"
    h["X-Frame-Options"] = "DENY"
    h["Referrer-Policy"] = "no-referrer"
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    h["Cross-Origin-Resource-Policy"] = "same-origin"
    if request.endpoint != "static":
        h["Cache-Control"] = "no-store"
        h["Pragma"] = "no-cache"
    if cfg.COOKIE_SECURE:
        h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    h["X-Request-Id"] = g.get("request_id", "")


def _error_response(code: int, name: str, message: str | None):
    if request.path.startswith("/api/"):
        body = {"error": name.lower().replace(" ", "_"), "request_id": g.get("request_id")}
        if message:
            body["message"] = message
        return jsonify(body), code
    return render_template("error.html", code=code, name=name, message=message,
                           request_id=g.get("request_id")), code


def set_session_cookie(response, token: str) -> None:
    from flask import current_app

    cfg = current_app.config["TV"]
    response.set_cookie(SESSION_COOKIE, token, httponly=True, secure=cfg.COOKIE_SECURE, samesite="Lax",
                        path="/", max_age=cfg.SESSION_HOURS * 3600)

