"""Administrator views: document activity, permission changes, alerts, transfers.

The administrator sees metadata (names, owners, who holds which grant, every audit
event) but has no path to file contents: authz.decide() gives the admin role
nothing, and the document_versions/blobs policies have no admin clause.
"""
import csv
import io

from werkzeug.exceptions import BadRequest, NotFound

from .. import audit, security
from .users import require_admin

PERMISSION_ACTIONS = ("grant_created", "grant_changed", "grant_revoked", "share_link_created",
                      "share_link_revoked", "ownership_transferred", "ai_suggestion_accepted",
                      "ai_suggestion_rejected")


def documents_overview(db, admin: dict, q=None) -> list:
    require_admin(admin)
    params = []
    where = ""
    if q:
        where = "WHERE d.name ILIKE %s ESCAPE '\\' OR u.email ILIKE %s ESCAPE '\\'"
        like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")[:200] + "%"
        params = [like, like]
    return db.all(
        "SELECT d.id, d.name, d.category, d.current_version, d.size_bytes, d.created_at, d.updated_at, "
        "       u.email AS owner_email, "
        "       (SELECT count(*) FROM grants g WHERE g.document_id = d.id) AS grant_count, "
        "       (SELECT count(*) FROM share_links s WHERE s.document_id = d.id AND s.revoked_at IS NULL "
        "          AND s.expires_at > now()) AS active_share_links "
        f"FROM documents d JOIN users u ON u.id = d.owner_id {where} ORDER BY d.updated_at DESC LIMIT 500",
        params)


def document_access(db, admin: dict, doc_id) -> dict:
    """Who can reach this document right now (for an investigation)."""
    require_admin(admin)
    if not security.is_uuid(doc_id):
        raise NotFound()
    doc = db.one("SELECT d.id, d.name, d.category, u.email AS owner_email FROM documents d "
                 "JOIN users u ON u.id = d.owner_id WHERE d.id = %s", (doc_id,))
    if doc is None:
        raise NotFound()
    doc["grants"] = db.all("SELECT u.email, u.role, u.is_active, g.permission, g.granted_via, g.created_at "
                           "FROM grants g JOIN users u ON u.id = g.user_id WHERE g.document_id = %s", (doc_id,))
    doc["share_links"] = db.all("SELECT id, label, expires_at, max_downloads, download_count, revoked_at "
                                "FROM share_links WHERE document_id = %s ORDER BY created_at DESC", (doc_id,))
    doc["recent_events"] = db.all("SELECT id, at, actor_email, action, outcome, ip FROM audit_events "
                                  "WHERE document_id = %s ORDER BY id DESC LIMIT 100", (doc_id,))
    return doc


def transfer_ownership(db, admin: dict, doc_id, new_owner_email) -> dict:
    """Offboarding: hand a leaver's document to another owner. Runs in the
    database's system context because ownership is deliberately not changeable
    by any normal policy. The old owner keeps no access; their share links die."""
    require_admin(admin)
    if not security.is_uuid(doc_id):
        raise NotFound()
    email = security.normalise_email(new_owner_email)
    target = db.one("SELECT id, email, role, is_active FROM users WHERE email = %s", (email,)) if email else None
    if target is None or not target["is_active"] or target["role"] != "owner":
        raise BadRequest("The new owner must be an active user with the owner role.")
    ctx = db.context()
    db.set_context(system=True)
    try:
        doc = db.one("SELECT id, owner_id, name, deleted_at FROM documents WHERE id = %s FOR UPDATE", (doc_id,))
        if doc is None or doc["deleted_at"] is not None:
            raise NotFound()
        if doc["owner_id"] == target["id"]:
            raise BadRequest("That user already owns the document.")
        old_owner = doc["owner_id"]
        db.run("DELETE FROM grants WHERE document_id = %s AND user_id = %s", (doc_id, target["id"]))
        db.run("UPDATE documents SET owner_id = %s, updated_at = now() WHERE id = %s", (target["id"], doc_id))
        db.run("UPDATE grants SET owner_id = %s WHERE document_id = %s", (target["id"], doc_id))
        revoked = db.run("UPDATE share_links SET owner_id = %s, revoked_at = coalesce(revoked_at, now()), "
                         "revoked_by = coalesce(revoked_by, %s) WHERE document_id = %s",
                         (target["id"], admin["id"], doc_id))
        db.run("UPDATE ai_suggestions SET owner_id = %s, status = CASE WHEN status = 'pending' THEN 'rejected' "
               "ELSE status END WHERE document_id = %s", (target["id"], doc_id))
        audit.record(db, "ownership_transferred", actor=admin, document_id=doc_id, target_user_id=target["id"],
                     details={"from_user_id": old_owner, "to_email": target["email"], "share_links_revoked": revoked})
    finally:
        db.set_context(user_id=ctx["user_id"] or None, role=ctx["role"] or None)
    return {"document_id": doc_id, "new_owner": target["email"]}


def audit_events(db, admin: dict, action=None, actor=None, document_id=None, outcome=None,
                 permission_only=False, limit=200) -> list:
    require_admin(admin)
    where, params = [], []
    if action:
        where.append("action = %s")
        params.append(str(action)[:64])
    if permission_only:
        where.append("action = ANY(%s::text[])")
        params.append(list(PERMISSION_ACTIONS))
    if actor:
        where.append("actor_email ILIKE %s ESCAPE '\\'")
        params.append("%" + str(actor).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")[:200] + "%")
    if document_id:
        if not security.is_uuid(document_id):
            raise BadRequest("Document id must be a UUID.")
        where.append("document_id = %s")
        params.append(document_id)
    if outcome in ("success", "denied", "failure"):
        where.append("outcome = %s")
        params.append(outcome)
    try:
        limit = max(1, min(int(limit), 1000))
    except (TypeError, ValueError):
        limit = 200
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    return db.all("SELECT id, at, actor_id, actor_email, action, document_id, target_user_id, outcome, ip, "
                  f"user_agent, details, hash FROM audit_events {clause} ORDER BY id DESC LIMIT %s",
                  params + [limit])


def _csv_safe(value) -> str:
    text = "" if value is None else str(value)
    # Spreadsheet formula injection: a filename like "=HYPERLINK(...)" must not
    # execute when an auditor opens the export in Excel.
    if text[:1] in ("=", "+", "-", "@", "\t", "\r"):
        text = "'" + text
    return text


def audit_csv(db, admin: dict, **filters) -> str:
    rows = audit_events(db, admin, limit=1000, **filters)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "at", "actor_email", "action", "outcome", "document_id", "target_user_id", "ip",
                     "user_agent", "details", "hash"])
    for r in rows:
        writer.writerow([_csv_safe(r["id"]), _csv_safe(r["at"].isoformat()), _csv_safe(r["actor_email"]),
                         _csv_safe(r["action"]), _csv_safe(r["outcome"]), _csv_safe(r["document_id"]),
                         _csv_safe(r["target_user_id"]), _csv_safe(r["ip"]), _csv_safe(r["user_agent"]),
                         _csv_safe(r["details"]), _csv_safe(r["hash"])])
    audit.record(db, "audit_exported", actor=admin, details={"rows": len(rows), "filters": filters})
    return buf.getvalue()


def alerts(db, admin: dict) -> list:
    """Things an administrator should look at. Each rule is a query over the
    audit trail, so anything flagged here can be traced to the exact events."""
    require_admin(admin)
    found = []

    for r in db.all("SELECT actor_email, count(*) AS n, count(DISTINCT document_id) AS docs FROM audit_events "
                    "WHERE action IN ('access_denied', 'upload_denied') AND at > now() - interval '1 hour' "
                    "AND actor_email IS NOT NULL GROUP BY actor_email HAVING count(*) >= 5 ORDER BY n DESC"):
        found.append({"severity": "high", "kind": "probing",
                      "message": f"{r['actor_email']} was refused {r['n']} times in the last hour "
                                 f"across {r['docs']} document id(s): possible ID guessing.",
                      "actor": r["actor_email"]})

    for r in db.all("SELECT count(*) AS n, count(DISTINCT ip) AS ips FROM audit_events "
                    "WHERE action = 'share_access_denied' AND at > now() - interval '1 hour'"):
        if r["n"] >= 10:
            found.append({"severity": "high", "kind": "share_token_guessing",
                          "message": f"{r['n']} invalid share-link attempts from {r['ips']} IP(s) in the last hour."})

    for r in db.all("SELECT actor_email, count(*) AS n FROM audit_events WHERE action = 'download' "
                    "AND at > now() - interval '1 hour' GROUP BY actor_email HAVING count(*) >= 20"):
        found.append({"severity": "medium", "kind": "bulk_download",
                      "message": f"{r['actor_email']} downloaded {r['n']} files in the last hour.",
                      "actor": r["actor_email"]})

    for r in db.all("SELECT details->>'email' AS email, actor_email, count(*) AS n FROM audit_events "
                    "WHERE action = 'login_failed' AND at > now() - interval '1 hour' "
                    "GROUP BY details->>'email', actor_email HAVING count(*) >= 5"):
        who = r["actor_email"] or r["email"]
        found.append({"severity": "medium", "kind": "password_guessing",
                      "message": f"{r['n']} failed sign-ins for {who} in the last hour."})

    for r in db.all("SELECT actor_email, document_id, count(*) AS n FROM audit_events "
                    "WHERE action IN ('grant_created', 'grant_changed') AND at > now() - interval '10 minutes' "
                    "GROUP BY actor_email, document_id HAVING count(*) >= 5"):
        found.append({"severity": "medium", "kind": "mass_grant",
                      "message": f"{r['actor_email']} granted {r['n']} people access to one document within "
                                 f"10 minutes.", "document_id": r["document_id"]})

    for r in db.all("SELECT a.actor_email, a.ip, a.at FROM audit_events a WHERE a.action = 'login_success' "
                    "AND a.at > now() - interval '24 hours' AND NOT EXISTS (SELECT 1 FROM audit_events b "
                    "WHERE b.action = 'login_success' AND b.actor_id = a.actor_id AND b.ip = a.ip AND b.id < a.id "
                    "AND b.at > now() - interval '30 days') AND EXISTS (SELECT 1 FROM audit_events c "
                    "WHERE c.action = 'login_success' AND c.actor_id = a.actor_id AND c.id < a.id) "
                    "ORDER BY a.id DESC LIMIT 20"):
        found.append({"severity": "low", "kind": "new_ip",
                      "message": f"{r['actor_email']} signed in from a new IP address ({r['ip']})."})

    for r in db.all("SELECT actor_email, document_id, at FROM audit_events WHERE action = 'ownership_transferred' "
                    "AND at > now() - interval '7 days' ORDER BY id DESC LIMIT 20"):
        found.append({"severity": "low", "kind": "ownership_transfer",
                      "message": f"{r['actor_email']} transferred ownership of a document.",
                      "document_id": r["document_id"]})

    chain = audit.verify(db)
    if not chain["ok"]:
        found.insert(0, {"severity": "critical", "kind": "audit_chain_broken",
                         "message": f"Audit chain verification failed at event {chain['broken_at_id']}: "
                                    f"{chain['reason']}."})
    return found
