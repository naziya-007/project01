"""Lock A: the application's authorization decision.

THIS IS THE ONLY PLACE THE APPLICATION DECIDES WHETHER A USER MAY TOUCH A DOCUMENT.

Every service function that receives a document id calls authorize() before it
does anything else (including validating the rest of the request), and
tests/test_route_coverage.py proves that for every route that takes a document id.

decide() is a pure function of (who, document facts, grant, action) so it can be
tested exhaustively without a database. authorize() fetches those facts and calls
it. The database's row-level security (migrations/002_rls.sql) is an independent
second lock: the facts are fetched through it, so a row the user may not see
arrives here as None and is refused even if decide() were wrong.

Refusals are 404, never 403, so a refused user cannot tell "exists but not
yours" from "does not exist". Every refusal is written to the audit trail.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from werkzeug.exceptions import NotFound

from . import audit
from .security import is_uuid


class Action(str, Enum):
    READ = "read"          # view metadata, list versions, download
    EDIT = "edit"          # rename, recategorise, upload a new version
    DELETE = "delete"      # move to trash
    RESTORE = "restore"    # bring back from trash
    MANAGE = "manage"      # grants, share links, AI suggestions


@dataclass(frozen=True)
class Subject:
    id: str
    role: str
    is_active: bool


def decide(subject: Optional[Subject], doc: Optional[dict], grant_permission: Optional[str],
           action: Action) -> bool:
    if subject is None or not subject.is_active:
        return False
    if doc is None:
        return False
    is_owner = doc["owner_id"] == subject.id
    deleted = doc.get("deleted_at") is not None

    if action is Action.RESTORE:
        return is_owner and deleted
    if deleted:
        return False
    if action is Action.READ:
        return is_owner or grant_permission in ("read", "edit")
    if action is Action.EDIT:
        return is_owner or grant_permission == "edit"
    if action in (Action.DELETE, Action.MANAGE):
        return is_owner
    return False
    # Note what is absent: the admin role grants nothing here. Administrators
    # manage people and read the audit trail; they do not read documents unless an
    # owner grants them access like anyone else.


def decide_share(link: Optional[dict], doc: Optional[dict], now: Optional[datetime] = None) -> bool:
    if link is None or doc is None:
        return False
    now = now or datetime.now(timezone.utc)
    if link["document_id"] != doc["id"]:
        return False
    if link.get("revoked_at") is not None:
        return False
    if link["expires_at"] <= now:
        return False
    if link.get("max_downloads") is not None and link["download_count"] >= link["max_downloads"]:
        return False
    if doc.get("deleted_at") is not None:
        return False
    return True


DOC_COLUMNS = ("id, owner_id, name, category, current_version, mime, size_bytes, deleted_at, deleted_by, "
               "created_at, updated_at")


def authorize(db, user: dict, document_id, action: Action) -> dict:
    """Return the document if `user` may perform `action` on it; otherwise audit
    the refusal and raise 404."""
    doc = None
    grant = None
    if is_uuid(document_id):
        doc = db.one(f"SELECT {DOC_COLUMNS} FROM documents WHERE id = %s", (document_id,))
        if doc is not None:
            grant = db.scalar("SELECT permission FROM grants WHERE document_id = %s AND user_id = %s",
                              (document_id, user["id"]))
    subject = Subject(id=user["id"], role=user["role"], is_active=bool(user.get("is_active")))
    if not decide(subject, doc, grant, action):
        audit.deny(db, "access_denied", actor=user,
                   document_id=document_id if is_uuid(document_id) else None,
                   details={"attempted": action.value,
                            "reason": "not_visible" if doc is None else "insufficient_permission",
                            **({} if is_uuid(document_id) else {"raw_id": str(document_id)[:80]})})
        raise NotFound()
    doc["my_permission"] = "owner" if doc["owner_id"] == user["id"] else grant
    return doc
