"""External share links, for people who have no account.

Design:
* The token is 256 bits of randomness, shown to the owner exactly once. Only its
  SHA-256 is stored, so a database dump does not yield working links.
* The link the owner copies is /share#<token>. Everything after '#' is never sent
  to a server, so the token does not land in Render's request logs, proxies or a
  Referer header. The page's own script posts it in a request body.
* Every link has an expiry (max SHARE_MAX_HOURS) and an optional download cap,
  is checked on every use, and dies when revoked or when the document is deleted.
* While serving a share request the database context carries ONLY the token
  hash: no user id, even if the visitor happens to be signed in.
"""
import re
from datetime import datetime, timedelta, timezone

from flask import current_app
from werkzeug.exceptions import BadRequest, NotFound

from .. import audit, security
from ..authz import DOC_COLUMNS, Action, authorize, decide_share
from ..validation import clean_text
from .documents import read_version_bytes

_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{40,64}$")
SHARE_COLUMNS = ("id, document_id, label, created_at, expires_at, max_downloads, download_count, revoked_at, "
                 "created_by")


def create(db, user: dict, doc_id, expires_hours=None, max_downloads=None, label=None) -> dict:
    doc = authorize(db, user, doc_id, Action.MANAGE)
    limit = current_app.config["TV"].SHARE_MAX_HOURS
    try:
        hours = int(expires_hours if expires_hours not in (None, "") else 24)
    except (TypeError, ValueError) as exc:
        raise BadRequest("Expiry must be a whole number of hours.") from exc
    if not 1 <= hours <= limit:
        raise BadRequest(f"Expiry must be between 1 and {limit} hours.")
    if max_downloads in (None, ""):
        cap = None
    else:
        try:
            cap = int(max_downloads)
        except (TypeError, ValueError) as exc:
            raise BadRequest("Download limit must be a whole number.") from exc
        if not 1 <= cap <= 1000:
            raise BadRequest("Download limit must be between 1 and 1000.")
    label = clean_text(label, 120, "Label") if label else None
    token = security.new_token(32)
    row = db.one(
        f"INSERT INTO share_links (document_id, owner_id, token_hash, label, created_by, expires_at, max_downloads) "
        f"VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING {SHARE_COLUMNS}",
        (doc["id"], doc["owner_id"], security.sha256_hex(token), label, user["id"],
         datetime.now(timezone.utc) + timedelta(hours=hours), cap))
    audit.record(db, "share_link_created", actor=user, document_id=doc["id"],
                 details={"share_id": row["id"], "expires_at": row["expires_at"].isoformat(),
                          "max_downloads": cap, "label": label})
    row["token"] = token  # returned once, never stored
    row["path"] = f"/share#{token}"
    return row


def list_links(db, user: dict, doc_id) -> list:
    doc = authorize(db, user, doc_id, Action.MANAGE)
    return db.all(f"SELECT {SHARE_COLUMNS} FROM share_links WHERE document_id = %s ORDER BY created_at DESC",
                  (doc["id"],))


def revoke(db, user: dict, doc_id, share_id) -> None:
    doc = authorize(db, user, doc_id, Action.MANAGE)
    if not security.is_uuid(share_id):
        raise NotFound()
    count = db.run("UPDATE share_links SET revoked_at = now(), revoked_by = %s "
                   "WHERE id = %s AND document_id = %s AND revoked_at IS NULL", (user["id"], share_id, doc["id"]))
    if count == 0:
        raise NotFound()
    audit.record(db, "share_link_revoked", actor=user, document_id=doc["id"], details={"share_id": share_id})


# ------------------------------------------------------- anonymous side
def _resolve(db, token) -> tuple[dict, dict]:
    if not isinstance(token, str) or not _TOKEN_RE.match(token):
        audit.deny(db, "share_access_denied", details={"reason": "malformed_token"})
        raise NotFound()
    token_hash = security.sha256_hex(token)
    db.set_context(share_hash=token_hash)  # no user identity on this path
    link = db.one("SELECT id, document_id, expires_at, max_downloads, download_count, revoked_at "
                  "FROM share_links WHERE token_hash = %s", (token_hash,))
    doc = db.one(f"SELECT {DOC_COLUMNS} FROM documents WHERE id = %s", (link["document_id"],)) if link else None
    if not decide_share(link, doc):
        audit.deny(db, "share_access_denied", document_id=link["document_id"] if link else None,
                   details={"share_id": link["id"] if link else None,
                            "reason": "unknown_token" if link is None else "inactive_link"})
        raise NotFound()
    return link, doc


def info(db, token) -> dict:
    link, doc = _resolve(db, token)
    remaining = None if link["max_downloads"] is None else link["max_downloads"] - link["download_count"]
    return {"name": doc["name"], "size_bytes": doc["size_bytes"], "expires_at": link["expires_at"],
            "downloads_remaining": remaining}


def download(db, token) -> tuple[str, bytes]:
    link, doc = _resolve(db, token)
    row, data = read_version_bytes(db, doc, doc["current_version"])
    # Compare-and-set on the counter: two simultaneous requests cannot both use
    # the last allowed download.
    counted = db.run("UPDATE share_links SET download_count = download_count + 1 "
                     "WHERE id = %s AND download_count = %s", (link["id"], link["download_count"]))
    if counted != 1:
        audit.deny(db, "share_access_denied", document_id=doc["id"],
                   details={"share_id": link["id"], "reason": "concurrent_use_of_last_download"})
        raise NotFound()
    audit.record(db, "share_download", document_id=doc["id"],
                 details={"share_id": link["id"], "version": row["version"], "sha256": row["sha256"],
                          "filename": row["filename"], "download_number": link["download_count"] + 1})
    return row["filename"], data
