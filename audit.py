"""Tamper-evident audit trail.

record()  writes an event inside the caller's transaction, so an action and its
          audit row commit together or not at all (a download whose audit row
          fails to commit is turned into an error before the bytes are sent).
deny()    queues a refused attempt. The request's main transaction is rolled back
          on refusal, so queued denials are written afterwards in a fresh
          transaction (app/__init__.py:_finish_transaction). Refusals are evidence
          too, and must survive the rollback of the thing that was refused.

Each row stores hash = sha256(canonical JSON of the row including prev_hash).
A transaction-scoped advisory lock serialises writers so two inserts can never
chain onto the same predecessor.
"""
import hashlib
import json
import re
from datetime import datetime, timezone

from flask import current_app, g, has_app_context, has_request_context, request

from . import security

GENESIS = "0" * 64
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_LOCK_KEY = 7_311_2026


def _context() -> tuple:
    if not has_request_context():
        return None, None
    return (security.client_ip(request, current_app.config["TRUST_PROXY_HOPS"]),
            security.user_agent(request))


def _iso(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).isoformat(timespec="microseconds")


def canonical(event: dict) -> str:
    payload = {
        "id": int(event["id"]),
        "at": _iso(event["at"]) if isinstance(event["at"], datetime) else event["at"],
        "actor_id": event.get("actor_id"),
        "actor_email": event.get("actor_email"),
        "action": event["action"],
        "document_id": event.get("document_id"),
        "target_user_id": event.get("target_user_id"),
        "outcome": event["outcome"],
        "ip": event.get("ip"),
        "user_agent": event.get("user_agent"),
        "details": event.get("details") or {},
        "prev_hash": event["prev_hash"],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def compute_hash(event: dict) -> str:
    return hashlib.sha256(canonical(event).encode()).hexdigest()


def _build(action, outcome, actor=None, document_id=None, target_user_id=None, details=None,
           ip=None, user_agent=None) -> dict:
    if ip is None and user_agent is None:
        ip, user_agent = _context()
    return {
        "action": action,
        "outcome": outcome,
        "actor_id": actor["id"] if actor else None,
        "actor_email": actor["email"] if actor else None,
        "document_id": document_id,
        "target_user_id": target_user_id,
        "details": _jsonable(details or {}),
        "ip": _clean(ip),
        "user_agent": _clean(user_agent),
    }


def _clean(value):
    # Attacker-supplied text (URL ids, user agents, file names) can contain NUL,
    # which PostgreSQL text/jsonb rejects. Failing to write a refusal would turn
    # it into an unlogged 500, so control characters are replaced, not trusted.
    if isinstance(value, str):
        return _CONTROL.sub("\ufffd", value)
    if isinstance(value, dict):
        return {_clean(k): _clean(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_clean(v) for v in value]
    return value


def _jsonable(details: dict) -> dict:
    # Round-trip so what we hash is exactly what jsonb will give back
    # (strings, ints, bools, nulls, lists, dicts; no floats by convention).
    return _clean(json.loads(json.dumps(details, default=str)))


def _insert(db, ev: dict) -> dict:
    db.scalar("SELECT pg_advisory_xact_lock(%s)", (_LOCK_KEY,))
    prev = db.scalar("SELECT hash FROM audit_events ORDER BY id DESC LIMIT 1") or GENESIS
    ev = dict(ev)
    ev["id"] = db.scalar("SELECT nextval(pg_get_serial_sequence('audit_events', 'id'))")
    ev["at"] = datetime.now(timezone.utc)
    ev["prev_hash"] = prev
    ev["hash"] = compute_hash(ev)
    db.run(
        "INSERT INTO audit_events (id, at, actor_id, actor_email, action, document_id, target_user_id, "
        "outcome, ip, user_agent, details, prev_hash, hash) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s)",
        (ev["id"], ev["at"], ev["actor_id"], ev["actor_email"], ev["action"], ev["document_id"],
         ev["target_user_id"], ev["outcome"], ev["ip"], ev["user_agent"],
         json.dumps(ev["details"], sort_keys=True), ev["prev_hash"], ev["hash"]),
    )
    return ev


def record(db, action, actor=None, document_id=None, target_user_id=None, details=None,
           outcome="success") -> dict:
    return _insert(db, _build(action, outcome, actor, document_id, target_user_id, details))


def deny(db, action, actor=None, document_id=None, target_user_id=None, details=None) -> None:
    """Queue a refused attempt; written after the request's transaction ends."""
    ev = _build(action, "denied", actor, document_id, target_user_id, details)
    if has_app_context() and has_request_context():
        g.setdefault("pending_audit", []).append(ev)
    else:  # scripts / seed: write straight away in the current transaction
        _insert(db, ev)


def flush_pending(db) -> None:
    pending = g.pop("pending_audit", []) if has_app_context() else []
    for ev in pending:
        _insert(db, ev)


def verify(db) -> dict:
    """Recompute the whole chain. Returns where (if anywhere) it breaks."""
    prev = GENESIS
    count = 0
    last = None
    rows = db.all("SELECT id, at, actor_id, actor_email, action, document_id, target_user_id, outcome, ip, "
                  "user_agent, details, prev_hash, hash FROM audit_events ORDER BY id")
    for row in rows:
        count += 1
        if row["prev_hash"] != prev:
            return {"ok": False, "count": count, "broken_at_id": row["id"],
                    "reason": "prev_hash does not match the previous row (a row was removed or inserted)"}
        if compute_hash(row) != row["hash"]:
            return {"ok": False, "count": count, "broken_at_id": row["id"],
                    "reason": "row contents do not match its hash (the row was altered)"}
        prev = row["hash"]
        last = row
    return {"ok": True, "count": count, "head_id": last["id"] if last else None, "head_hash": prev}


def head(db) -> dict:
    row = db.one("SELECT id, at, hash FROM audit_events ORDER BY id DESC LIMIT 1")
    if not row:
        return {"head_id": None, "head_hash": GENESIS, "at": None}
    return {"head_id": row["id"], "head_hash": row["hash"], "at": _iso(row["at"])}
