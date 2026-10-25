"""Documents: upload, search, metadata, versions, download, trash."""
import uuid
from datetime import date, datetime, timedelta, timezone

from flask import current_app
from werkzeug.exceptions import BadRequest, Forbidden, NotFound

from .. import audit, crypto, storage
from ..authz import DOC_COLUMNS, Action, authorize
from ..validation import clean_text, validate_upload

CATEGORIES = ("HR", "Legal", "Finance", "Engineering", "Audit", "Other")
EDITABLE_FIELDS = {"name", "category"}
PAGE_SIZE = 50


def _master_key() -> bytes:
    return current_app.config["MASTER_KEY_BYTES"]


def _max_bytes() -> int:
    return current_app.config["TV"].MAX_UPLOAD_MB * 1024 * 1024


def _category(value) -> str:
    if value not in CATEGORIES:
        raise BadRequest("Category must be one of: " + ", ".join(CATEGORIES) + ".")
    return value


def _store_version(db, user, doc_id: str, version: int, vf, data: bytes) -> dict:
    blob, wrapped = crypto.encrypt_file(_master_key(), doc_id, version, data)
    key = storage.new_key()
    storage.backend().put(db, key, blob)
    return db.one(
        "INSERT INTO document_versions (document_id, version, filename, mime, size_bytes, sha256, storage_key, "
        "wrapped_key, created_by) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) "
        "RETURNING id, version, filename, mime, size_bytes, sha256, created_at",
        (doc_id, version, vf.filename, vf.mime, vf.size, vf.sha256, key, wrapped, user["id"]))


# ------------------------------------------------------------------ create
def create(db, user: dict, filename, data: bytes, name=None, category="Other") -> dict:
    if user["role"] != "owner":
        audit.deny(db, "upload_denied", actor=user, details={"reason": "role_not_owner", "role": user["role"]})
        raise Forbidden("Only document owners can upload new documents.")
    category = _category(category)
    vf = validate_upload(filename, data, _max_bytes())
    display = clean_text(name, 200, "Name") if name not in (None, "") else vf.filename
    doc_id = str(uuid.uuid4())
    doc = db.one(
        f"INSERT INTO documents (id, owner_id, name, category, current_version, mime, size_bytes) "
        f"VALUES (%s, %s, %s, %s, 1, %s, %s) RETURNING {DOC_COLUMNS}",
        (doc_id, user["id"], display, category, vf.mime, vf.size))
    version = _store_version(db, user, doc_id, 1, vf, data)
    audit.record(db, "upload", actor=user, document_id=doc_id,
                 details={"name": display, "category": category, "filename": vf.filename, "mime": vf.mime,
                          "size": vf.size, "sha256": vf.sha256, "version": 1})
    doc["my_permission"] = "owner"
    doc["versions"] = [version]
    return doc


# ------------------------------------------------------------------ search
def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _parse_date(value, field):
    if value in (None, ""):
        return None
    try:
        return date.fromisoformat(str(value)).isoformat()
    except ValueError as exc:
        raise BadRequest(f"{field} must be a date in YYYY-MM-DD format.") from exc


def search(db, user: dict, q=None, owner=None, category=None, date_from=None, date_to=None,
           scope="all", page=1) -> dict:
    """Documents the user owns or holds a grant on, filtered. The visibility
    condition is written here explicitly AND enforced by RLS underneath."""
    select_params = [user["id"], user["id"]]
    where = ["d.deleted_at IS NULL"]
    params = []
    if scope == "mine":
        where.append("d.owner_id = %s")
        params.append(user["id"])
    elif scope == "shared":
        where.append("EXISTS (SELECT 1 FROM grants g WHERE g.document_id = d.id AND g.user_id = %s)")
        params.append(user["id"])
    else:
        where.append("(d.owner_id = %s OR EXISTS (SELECT 1 FROM grants g WHERE g.document_id = d.id "
                     "AND g.user_id = %s))")
        params += [user["id"], user["id"]]
    if q:
        q = clean_text(q, 200, "Search text")
        where.append("d.name ILIKE %s ESCAPE '\\'")
        params.append(f"%{_escape_like(q)}%")
    if owner:
        owner = clean_text(owner, 200, "Owner")
        where.append("(u.email ILIKE %s ESCAPE '\\' OR u.full_name ILIKE %s ESCAPE '\\')")
        params += [f"%{_escape_like(owner)}%"] * 2
    if category:
        where.append("d.category = %s")
        params.append(_category(category))
    df = _parse_date(date_from, "From date")
    dt = _parse_date(date_to, "To date")
    if df:
        where.append("d.created_at >= %s::date")
        params.append(df)
    if dt:
        where.append("d.created_at < %s::date + 1")
        params.append(dt)
    try:
        page = max(1, min(int(page), 1000))
    except (TypeError, ValueError):
        page = 1
    sql = (
        "SELECT d.id, d.name, d.category, d.current_version, d.mime, d.size_bytes, d.created_at, d.updated_at, "
        "       u.email AS owner_email, u.full_name AS owner_name, "
        "       CASE WHEN d.owner_id = %s THEN 'owner' "
        "            ELSE (SELECT g.permission FROM grants g WHERE g.document_id = d.id AND g.user_id = %s) "
        "       END AS my_permission "
        "FROM documents d JOIN users u ON u.id = d.owner_id "
        f"WHERE {' AND '.join(where)} ORDER BY d.updated_at DESC, d.id LIMIT %s OFFSET %s")
    rows = db.all(sql, select_params + params + [PAGE_SIZE + 1, (page - 1) * PAGE_SIZE])
    return {"items": rows[:PAGE_SIZE], "page": page, "has_more": len(rows) > PAGE_SIZE}


# ------------------------------------------------------------- read paths
def get(db, user: dict, doc_id) -> dict:
    doc = authorize(db, user, doc_id, Action.READ)
    doc["owner"] = db.one("SELECT id, email, full_name FROM users WHERE id = %s", (doc["owner_id"],))
    doc["versions"] = list_versions_unchecked(db, doc["id"])
    return doc


def list_versions_unchecked(db, doc_id: str) -> list:
    """Caller must already hold an authorize() result for doc_id."""
    return db.all("SELECT v.version, v.filename, v.mime, v.size_bytes, v.sha256, v.created_at, "
                  "u.email AS created_by_email FROM document_versions v JOIN users u ON u.id = v.created_by "
                  "WHERE v.document_id = %s ORDER BY v.version DESC", (doc_id,))


def versions(db, user: dict, doc_id) -> list:
    doc = authorize(db, user, doc_id, Action.READ)
    return list_versions_unchecked(db, doc["id"])


def read_version_bytes(db, doc: dict, version: int) -> tuple[dict, bytes]:
    """Decrypt one version. Caller must already hold an authorize() (or share)
    result for doc. The SELECTs below still pass through RLS (second lock)."""
    row = db.one("SELECT version, filename, mime, size_bytes, sha256, storage_key, wrapped_key "
                 "FROM document_versions WHERE document_id = %s AND version = %s", (doc["id"], version))
    if row is None:
        raise NotFound()
    blob = storage.backend().get(db, row["storage_key"])
    if blob is None:
        raise NotFound()
    data = crypto.decrypt_file(_master_key(), doc["id"], row["version"], blob, row["wrapped_key"])
    return row, data


def download(db, user: dict, doc_id, version=None) -> tuple[str, bytes, dict]:
    doc = authorize(db, user, doc_id, Action.READ)
    if version is None:
        version = doc["current_version"]
    try:
        version = int(version)
    except (TypeError, ValueError) as exc:
        raise NotFound() from exc
    row, data = read_version_bytes(db, doc, version)
    audit.record(db, "download", actor=user, document_id=doc["id"],
                 details={"version": row["version"], "filename": row["filename"], "sha256": row["sha256"],
                          "size": row["size_bytes"], "via": doc["my_permission"]})
    return row["filename"], data, doc


# ------------------------------------------------------------ write paths
def update_metadata(db, user: dict, doc_id, payload) -> dict:
    doc = authorize(db, user, doc_id, Action.EDIT)
    if not isinstance(payload, dict) or not payload:
        raise BadRequest("Nothing to update.")
    unknown = set(payload) - EDITABLE_FIELDS
    if unknown:
        # Mass-assignment guard: owner_id, deleted_at, version etc. are never accepted.
        raise BadRequest("These fields cannot be changed: " + ", ".join(sorted(unknown)) + ".")
    new_name = clean_text(payload["name"], 200, "Name") if "name" in payload else doc["name"]
    new_category = _category(payload["category"]) if "category" in payload else doc["category"]
    changes = {}
    if new_name != doc["name"]:
        changes["name"] = [doc["name"], new_name]
    if new_category != doc["category"]:
        changes["category"] = [doc["category"], new_category]
    if not changes:
        return doc
    updated = db.one(f"UPDATE documents SET name = %s, category = %s, updated_at = now() WHERE id = %s "
                     f"RETURNING {DOC_COLUMNS}", (new_name, new_category, doc["id"]))
    if updated is None:
        raise NotFound()
    audit.record(db, "document_updated", actor=user, document_id=doc["id"], details={"changes": changes})
    updated["my_permission"] = doc["my_permission"]
    return updated


def add_version(db, user: dict, doc_id, get_file) -> dict:
    """get_file() returns (filename, bytes). It is called only after authorization,
    so an unauthorised caller learns nothing from upload validation errors."""
    doc = authorize(db, user, doc_id, Action.EDIT)
    filename, data = get_file()
    vf = validate_upload(filename, data, _max_bytes())
    # The UPDATE takes a row lock, so two concurrent uploads get consecutive numbers.
    bumped = db.one("UPDATE documents SET current_version = current_version + 1, mime = %s, size_bytes = %s, "
                    "updated_at = now() WHERE id = %s RETURNING current_version", (vf.mime, vf.size, doc["id"]))
    if bumped is None:
        raise NotFound()
    version = _store_version(db, user, doc["id"], bumped["current_version"], vf, data)
    audit.record(db, "version_uploaded", actor=user, document_id=doc["id"],
                 details={"version": version["version"], "filename": vf.filename, "sha256": vf.sha256,
                          "size": vf.size, "via": doc["my_permission"]})
    return version


def soft_delete(db, user: dict, doc_id) -> None:
    doc = authorize(db, user, doc_id, Action.DELETE)
    changed = db.run("UPDATE documents SET deleted_at = now(), deleted_by = %s, updated_at = now() WHERE id = %s",
                     (user["id"], doc["id"]))
    if changed != 1:  # row-level security matched nothing: refuse rather than report success
        raise NotFound()
    # Share links die with the document and do NOT come back on restore.
    revoked = db.run("UPDATE share_links SET revoked_at = now(), revoked_by = %s "
                     "WHERE document_id = %s AND revoked_at IS NULL", (user["id"], doc["id"]))
    audit.record(db, "document_deleted", actor=user, document_id=doc["id"],
                 details={"name": doc["name"], "share_links_revoked": revoked,
                          "restorable_days": current_app.config["TV"].TRASH_RETENTION_DAYS})


def restore(db, user: dict, doc_id) -> dict:
    doc = authorize(db, user, doc_id, Action.RESTORE)
    if doc["deleted_at"] is None:
        raise NotFound()
    limit = timedelta(days=current_app.config["TV"].TRASH_RETENTION_DAYS)
    if doc["deleted_at"] < datetime.now(timezone.utc) - limit:
        raise BadRequest("This document is past its retention window and can no longer be restored.")
    restored = db.one(f"UPDATE documents SET deleted_at = NULL, deleted_by = NULL, updated_at = now() "
                      f"WHERE id = %s RETURNING {DOC_COLUMNS}", (doc["id"],))
    if restored is None:
        raise NotFound()
    audit.record(db, "document_restored", actor=user, document_id=doc["id"], details={"name": doc["name"]})
    return restored


def trash(db, user: dict) -> list:
    return db.all("SELECT id, name, category, deleted_at, size_bytes FROM documents "
                  "WHERE owner_id = %s AND deleted_at IS NOT NULL ORDER BY deleted_at DESC", (user["id"],))
