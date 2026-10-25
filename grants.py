"""Per-document grants to named people. Only the document's owner manages them."""
from werkzeug.exceptions import BadRequest, NotFound

from .. import audit, security
from ..authz import Action, authorize
from ..db import DbError, sqlstate

PERMISSIONS = ("read", "edit")


def list_grants(db, user: dict, doc_id) -> list:
    doc = authorize(db, user, doc_id, Action.MANAGE)
    return db.all("SELECT g.user_id, u.email, u.full_name, u.role, u.is_active, g.permission, g.granted_via, "
                  "g.created_at FROM grants g JOIN users u ON u.id = g.user_id WHERE g.document_id = %s "
                  "ORDER BY u.email", (doc["id"],))


def grant(db, user: dict, doc_id, email, permission, via="manual", suggestion_id=None) -> dict:
    doc = authorize(db, user, doc_id, Action.MANAGE)
    if permission not in PERMISSIONS:
        raise BadRequest("Permission must be 'read' or 'edit'.")
    email_n = security.normalise_email(email)
    target = db.one("SELECT id, email, role, is_active FROM users WHERE email = %s", (email_n,)) if email_n else None
    if target is None or not target["is_active"]:
        raise BadRequest("There is no active user with that e-mail address.")
    if target["id"] == doc["owner_id"]:
        raise BadRequest("The owner already has full access.")
    previous = db.scalar("SELECT permission FROM grants WHERE document_id = %s AND user_id = %s",
                         (doc["id"], target["id"]))
    try:
        row = db.one(
            "INSERT INTO grants (document_id, user_id, owner_id, permission, granted_by, granted_via) "
            "VALUES (%s, %s, %s, %s, %s, %s) "
            "ON CONFLICT (document_id, user_id) DO UPDATE SET permission = EXCLUDED.permission, "
            "granted_by = EXCLUDED.granted_by, granted_via = EXCLUDED.granted_via, created_at = now() "
            "RETURNING user_id, permission, granted_via, created_at",
            # owner_id is overwritten by the tv_fill_owner trigger from the documents row.
            (doc["id"], target["id"], doc["owner_id"], permission, user["id"], via))
    except DbError as exc:
        if sqlstate(exc) in ("42501", "23514"):
            # The database's own policy refused it (second lock). Record that too.
            audit.deny(db, "access_denied", actor=user, document_id=doc["id"],
                       details={"attempted": "manage", "reason": "database_policy", "sqlstate": sqlstate(exc)})
            raise NotFound() from exc
        raise
    audit.record(db, "grant_created" if previous is None else "grant_changed", actor=user,
                 document_id=doc["id"], target_user_id=target["id"],
                 details={"email": target["email"], "permission": permission, "previous": previous,
                          "via": via, **({"suggestion_id": suggestion_id} if suggestion_id else {})})
    row["email"] = target["email"]
    return row


def revoke(db, user: dict, doc_id, target_user_id) -> None:
    doc = authorize(db, user, doc_id, Action.MANAGE)
    if not security.is_uuid(target_user_id):
        raise NotFound()
    removed = db.one("DELETE FROM grants WHERE document_id = %s AND user_id = %s RETURNING permission",
                     (doc["id"], target_user_id))
    if removed is None:
        raise NotFound()
    target = db.one("SELECT email FROM users WHERE id = %s", (target_user_id,))
    # Nothing to invalidate: every request re-reads the grants table, nothing is cached,
    # and downloads stream through the server, so the next request is refused.
    audit.record(db, "grant_revoked", actor=user, document_id=doc["id"], target_user_id=target_user_id,
                 details={"email": target["email"] if target else None, "permission": removed["permission"]})
