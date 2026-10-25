"""Accounts, sign-in and server-side sessions."""
from datetime import datetime, timedelta, timezone

from werkzeug.exceptions import BadRequest, Forbidden, NotFound

from .. import audit, security
from ..db import DbError, sqlstate

ROLES = ("admin", "owner", "viewer")
LOCK_AFTER_FAILURES = 5
LOCK_MINUTES = 15
USER_COLUMNS = "id, email, full_name, role, is_active, created_at"


def _now():
    return datetime.now(timezone.utc)


# --------------------------------------------------------------- sign-in
def authenticate(db, email_raw, password) -> dict | None:
    """Returns the user on success. Same response and similar timing for unknown
    e-mail, wrong password, locked and deactivated accounts."""
    email = security.normalise_email(email_raw)
    if not isinstance(password, str):
        password = ""
    user = db.one("SELECT id, email, full_name, role, is_active, password_hash, failed_logins, locked_until "
                  "FROM users WHERE email = %s", (email,)) if email else None
    if user is None:
        security.verify_password(password, security.DUMMY_HASH)
        audit.record(db, "login_failed", details={"email": (email or str(email_raw))[:254], "reason": "unknown_user"},
                     outcome="failure")
        return None
    password_ok = security.verify_password(password, user["password_hash"])
    if user["locked_until"] is not None and user["locked_until"] > _now():
        audit.record(db, "login_failed", actor=user, target_user_id=user["id"],
                     details={"reason": "locked"}, outcome="failure")
        return None
    if not user["is_active"]:
        audit.record(db, "login_failed", actor=user, target_user_id=user["id"],
                     details={"reason": "deactivated"}, outcome="failure")
        return None
    if not password_ok:
        failures = user["failed_logins"] + 1
        locked_until = _now() + timedelta(minutes=LOCK_MINUTES) if failures >= LOCK_AFTER_FAILURES else None
        db.run("UPDATE users SET failed_logins = %s, locked_until = %s WHERE id = %s",
               (0 if locked_until else failures, locked_until, user["id"]))
        audit.record(db, "login_failed", actor=user, target_user_id=user["id"],
                     details={"reason": "bad_password", "locked": locked_until is not None}, outcome="failure")
        return None
    db.run("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = %s", (user["id"],))
    user.pop("password_hash", None)
    return user


def create_session(db, user: dict, ip: str, ua: str, hours: int) -> tuple[str, str]:
    """A brand-new random token on every sign-in (no session fixation)."""
    token = security.new_token()
    csrf = security.new_token()
    db.run("INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at, ip, user_agent) "
           "VALUES (%s, %s, %s, %s, %s, %s)",
           (security.sha256_hex(token), user["id"], csrf, _now() + timedelta(hours=hours), ip, ua))
    audit.record(db, "login_success", actor=user, target_user_id=user["id"])
    return token, csrf


def load_session(db, token: str | None, idle_minutes: int) -> tuple[dict, dict] | None:
    if not token or len(token) > 200:
        return None
    row = db.one(
        "SELECT s.token_hash, s.csrf_token, s.last_seen_at, s.expires_at, "
        "       u.id, u.email, u.full_name, u.role, u.is_active "
        "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = %s",
        (security.sha256_hex(token),))
    if row is None:
        return None
    now = _now()
    if not row["is_active"] or row["expires_at"] <= now or row["last_seen_at"] < now - timedelta(minutes=idle_minutes):
        db.run("DELETE FROM sessions WHERE token_hash = %s", (row["token_hash"],))
        return None
    if row["last_seen_at"] < now - timedelta(seconds=60):
        db.run("UPDATE sessions SET last_seen_at = now() WHERE token_hash = %s", (row["token_hash"],))
    user = {k: row[k] for k in ("id", "email", "full_name", "role", "is_active")}
    session = {"token_hash": row["token_hash"], "csrf_token": row["csrf_token"]}
    return user, session


def end_session(db, token_hash: str, user: dict) -> None:
    db.run("DELETE FROM sessions WHERE token_hash = %s", (token_hash,))
    audit.record(db, "logout", actor=user, target_user_id=user["id"])


def end_all_sessions(db, user_id: str, except_token_hash: str | None = None) -> int:
    if except_token_hash:
        return db.run("DELETE FROM sessions WHERE user_id = %s AND token_hash <> %s", (user_id, except_token_hash))
    return db.run("DELETE FROM sessions WHERE user_id = %s", (user_id,))


def change_own_password(db, user: dict, current_session_hash: str, current: str, new: str) -> None:
    row = db.one("SELECT password_hash FROM users WHERE id = %s", (user["id"],))
    if not row or not security.verify_password(current or "", row["password_hash"]):
        audit.record(db, "password_change_failed", actor=user, target_user_id=user["id"], outcome="failure")
        raise BadRequest("Current password is incorrect.")
    problem = security.password_problem(new)
    if problem:
        raise BadRequest(problem)
    db.run("UPDATE users SET password_hash = %s, password_changed_at = now() WHERE id = %s",
           (security.hash_password(new), user["id"]))
    ended = end_all_sessions(db, user["id"], except_token_hash=current_session_hash)
    audit.record(db, "password_changed", actor=user, target_user_id=user["id"], details={"other_sessions_ended": ended})


# ---------------------------------------------------------- administration
def require_admin(user: dict) -> None:
    if user is None or user.get("role") != "admin":
        raise Forbidden()


def list_users(db, admin: dict) -> list:
    require_admin(admin)
    return db.all(f"SELECT {USER_COLUMNS}, locked_until, "
                  "(SELECT count(*) FROM sessions s WHERE s.user_id = users.id) AS active_sessions "
                  "FROM users ORDER BY email")


def create_user(db, admin: dict, email_raw, full_name_raw, role, password) -> dict:
    require_admin(admin)
    from ..validation import clean_text

    email = security.normalise_email(email_raw)
    if not email:
        raise BadRequest("A valid e-mail address is required.")
    full_name = clean_text(full_name_raw, 120, "Full name")
    if role not in ROLES:
        raise BadRequest("Role must be admin, owner or viewer.")
    problem = security.password_problem(password)
    if problem:
        raise BadRequest(problem)
    try:
        user = db.one(f"INSERT INTO users (email, full_name, role, password_hash) VALUES (%s, %s, %s, %s) "
                      f"RETURNING {USER_COLUMNS}", (email, full_name, role, security.hash_password(password)))
    except DbError as exc:
        if sqlstate(exc) == "23505":
            raise BadRequest("A user with that e-mail already exists.") from exc
        raise
    audit.record(db, "user_created", actor=admin, target_user_id=user["id"], details={"email": email, "role": role})
    return user


def update_user(db, admin: dict, user_id, role=None, is_active=None) -> dict:
    require_admin(admin)
    if not security.is_uuid(user_id):
        raise NotFound()
    target = db.one(f"SELECT {USER_COLUMNS} FROM users WHERE id = %s", (user_id,))
    if target is None:
        raise NotFound()
    if target["id"] == admin["id"]:
        raise BadRequest("You cannot change your own role or deactivate yourself.")
    changes = {}
    if role is not None:
        if role not in ROLES:
            raise BadRequest("Role must be admin, owner or viewer.")
        if role != target["role"]:
            changes["role"] = [target["role"], role]
    if is_active is not None:
        if not isinstance(is_active, bool):
            raise BadRequest("is_active must be true or false.")
        if is_active != target["is_active"]:
            changes["is_active"] = [target["is_active"], is_active]
    if not changes:
        return target
    updated = db.one(f"UPDATE users SET role = %s, is_active = %s WHERE id = %s RETURNING {USER_COLUMNS}",
                     (changes.get("role", [None, target["role"]])[1],
                      changes.get("is_active", [None, target["is_active"]])[1], user_id))
    # Any change of privilege ends every session the user holds, immediately.
    ended = end_all_sessions(db, user_id)
    action = "user_deactivated" if changes.get("is_active") == [True, False] else "user_updated"
    audit.record(db, action, actor=admin, target_user_id=user_id,
                 details={"changes": changes, "sessions_ended": ended})
    return updated


def reset_password(db, admin: dict, user_id, new_password) -> None:
    require_admin(admin)
    if not security.is_uuid(user_id):
        raise NotFound()
    problem = security.password_problem(new_password)
    if problem:
        raise BadRequest(problem)
    count = db.run("UPDATE users SET password_hash = %s, password_changed_at = now(), failed_logins = 0, "
                   "locked_until = NULL WHERE id = %s", (security.hash_password(new_password), user_id))
    if count == 0:
        raise NotFound()
    ended = end_all_sessions(db, user_id)
    audit.record(db, "password_reset_by_admin", actor=admin, target_user_id=user_id, details={"sessions_ended": ended})
