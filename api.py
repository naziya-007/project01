"""JSON API. Each route's docstring states who may call it; docs/API.md is the
reference. Routes stay thin: they parse input and call a service. Every service
that takes a document id calls authz.authorize() before anything else."""
from flask import Blueprint, current_app, g, jsonify, request
from werkzeug.exceptions import BadRequest

from .. import audit, get_db, security, set_session_cookie
from ..services import admin as admin_service
from ..services import ai as ai_service
from ..services import documents as doc_service
from ..services import grants as grant_service
from ..services import shares as share_service
from ..services import users as user_service
from .common import admin_required, file_response, json_body, login_required, serialise, uploaded_file

bp = Blueprint("api", __name__, url_prefix="/api")


def ok(payload=None, status=200):
    return jsonify(serialise(payload if payload is not None else {"ok": True})), status


def _rate_limited(key: str, limit: int) -> bool:
    return not security.limiter.allow(key, limit)


# ---------------------------------------------------------------- auth
@bp.post("/auth/login")
def login():
    """Anyone. Body {email, password}. Sets the session cookie; returns the CSRF token."""
    body = json_body()
    cfg = current_app.config["TV"]
    ip = security.client_ip(request, cfg.TRUST_PROXY_HOPS)
    email = str(body.get("email", ""))[:254].lower()
    if _rate_limited(f"login-ip:{ip}", cfg.LOGIN_RATE_PER_MIN) or _rate_limited(f"login-email:{email}", cfg.LOGIN_RATE_PER_MIN):
        audit.deny(get_db(), "login_rate_limited", details={"email": email})
        return jsonify({"error": "too_many_requests"}), 429
    db = get_db()
    user = user_service.authenticate(db, body.get("email"), body.get("password"))
    if user is None:
        g.force_commit = True  # keep the failure counter and the audit row
        return jsonify({"error": "invalid_credentials", "message": "Invalid e-mail or password."}), 401
    token, csrf = user_service.create_session(db, user, ip, security.user_agent(request), cfg.SESSION_HOURS)
    resp, status = ok({"user": {k: user[k] for k in ("id", "email", "full_name", "role")}, "csrf_token": csrf})
    set_session_cookie(resp, token)
    return resp, status


@bp.post("/auth/logout")
@login_required
def logout():
    """Any signed-in user. Ends this session immediately."""
    user_service.end_session(get_db(), g.session["token_hash"], g.user)
    resp, status = ok()
    resp.delete_cookie("tv_session", path="/")
    return resp, status


@bp.get("/me")
@login_required
def me():
    """Any signed-in user."""
    return ok({"user": g.user, "csrf_token": g.session["csrf_token"]})


@bp.post("/me/password")
@login_required
def change_password():
    """Any signed-in user. Body {current_password, new_password}. Ends all other sessions."""
    body = json_body()
    try:
        user_service.change_own_password(get_db(), g.user, g.session["token_hash"],
                                         body.get("current_password"), body.get("new_password"))
    except BadRequest:
        g.force_commit = True  # keep the audit row for the failed attempt
        raise
    return ok()


# ----------------------------------------------------------- documents
@bp.get("/documents")
@login_required
def list_documents():
    """Any signed-in user. Only documents they own or hold a grant on.
    Query: q, owner, category, from, to (YYYY-MM-DD), scope=all|mine|shared, page."""
    a = request.args
    return ok(doc_service.search(get_db(), g.user, q=a.get("q"), owner=a.get("owner"), category=a.get("category"),
                                 date_from=a.get("from"), date_to=a.get("to"), scope=a.get("scope", "all"),
                                 page=a.get("page", 1)))


@bp.post("/documents")
@login_required
def upload_document():
    """Users with role 'owner'. Multipart: file, name (optional), category."""
    filename, data = uploaded_file()
    doc = doc_service.create(get_db(), g.user, filename, data, request.form.get("name"),
                             request.form.get("category", "Other"))
    return ok(doc, 201)


@bp.get("/documents/<doc_id>")
@login_required
def get_document(doc_id):
    """Owner, or a user with a read/edit grant."""
    return ok(doc_service.get(get_db(), g.user, doc_id))


@bp.patch("/documents/<doc_id>")
@login_required
def update_document(doc_id):
    """Owner, or a user with an edit grant. Body: {name?, category?}; any other field is refused."""
    return ok(doc_service.update_metadata(get_db(), g.user, doc_id, json_body()))


@bp.delete("/documents/<doc_id>")
@login_required
def delete_document(doc_id):
    """Owner only. Moves to trash; revokes all share links."""
    doc_service.soft_delete(get_db(), g.user, doc_id)
    return ok()


@bp.post("/documents/<doc_id>/restore")
@login_required
def restore_document(doc_id):
    """Owner only, within the retention window."""
    return ok(doc_service.restore(get_db(), g.user, doc_id))


@bp.post("/documents/<doc_id>/download")
@login_required
def download_document(doc_id):
    """Owner, or a user with a read/edit grant. POST + CSRF token, so a third-party
    page cannot make a victim's browser download (and be audited as reading) a file."""
    filename, data, _ = doc_service.download(get_db(), g.user, doc_id)
    return file_response(filename, data)


@bp.get("/documents/<doc_id>/versions")
@login_required
def list_versions(doc_id):
    """Owner, or a user with a read/edit grant."""
    return ok({"versions": doc_service.versions(get_db(), g.user, doc_id)})


@bp.post("/documents/<doc_id>/versions")
@login_required
def add_version(doc_id):
    """Owner, or a user with an edit grant. Multipart: file."""
    return ok(doc_service.add_version(get_db(), g.user, doc_id, uploaded_file), 201)


@bp.post("/documents/<doc_id>/versions/<int:version>/download")
@login_required
def download_version(doc_id, version):
    """Owner, or a user with a read/edit grant (checked against the grant held now)."""
    filename, data, _ = doc_service.download(get_db(), g.user, doc_id, version)
    return file_response(filename, data)


@bp.get("/trash")
@login_required
def trash():
    """Any signed-in user: their own deleted documents."""
    return ok({"items": doc_service.trash(get_db(), g.user)})


# --------------------------------------------------------------- grants
@bp.get("/documents/<doc_id>/grants")
@login_required
def list_grants(doc_id):
    """Owner only."""
    return ok({"grants": grant_service.list_grants(get_db(), g.user, doc_id)})


@bp.post("/documents/<doc_id>/grants")
@login_required
def create_grant(doc_id):
    """Owner only. Body {email, permission: read|edit}. Creates or changes a grant."""
    body = json_body()
    return ok(grant_service.grant(get_db(), g.user, doc_id, body.get("email"), body.get("permission")), 201)


@bp.delete("/documents/<doc_id>/grants/<user_id>")
@login_required
def delete_grant(doc_id, user_id):
    """Owner only. Takes effect on the grantee's very next request."""
    grant_service.revoke(get_db(), g.user, doc_id, user_id)
    return ok()


# ---------------------------------------------------------- share links
@bp.get("/documents/<doc_id>/shares")
@login_required
def list_shares(doc_id):
    """Owner only."""
    return ok({"shares": share_service.list_links(get_db(), g.user, doc_id)})


@bp.post("/documents/<doc_id>/shares")
@login_required
def create_share(doc_id):
    """Owner only. Body {expires_hours (1-168), max_downloads?, label?}. Token returned once."""
    body = json_body()
    return ok(share_service.create(get_db(), g.user, doc_id, body.get("expires_hours"), body.get("max_downloads"),
                                   body.get("label")), 201)


@bp.delete("/documents/<doc_id>/shares/<share_id>")
@login_required
def revoke_share(doc_id, share_id):
    """Owner only."""
    share_service.revoke(get_db(), g.user, doc_id, share_id)
    return ok()


@bp.post("/share/info")
def share_info():
    """Anyone holding a live share token. Body {token}."""
    cfg = current_app.config["TV"]
    if _rate_limited(f"share:{security.client_ip(request, cfg.TRUST_PROXY_HOPS)}", cfg.SHARE_RATE_PER_MIN):
        return jsonify({"error": "too_many_requests"}), 429
    return ok(share_service.info(get_db(), json_body().get("token")))


@bp.post("/share/download")
def share_download():
    """Anyone holding a live share token. Body {token} (JSON or form field)."""
    cfg = current_app.config["TV"]
    if _rate_limited(f"share:{security.client_ip(request, cfg.TRUST_PROXY_HOPS)}", cfg.SHARE_RATE_PER_MIN):
        return jsonify({"error": "too_many_requests"}), 429
    token = request.form.get("token") if not request.is_json else json_body().get("token")
    filename, data = share_service.download(get_db(), token)
    return file_response(filename, data)


# --------------------------------------------------------- AI suggestions
@bp.post("/documents/<doc_id>/suggestions")
@login_required
def generate_suggestions(doc_id):
    """Owner only. Generates suggestions; grants nothing."""
    return ok({"suggestions": ai_service.suggest(get_db(), g.user, doc_id)}, 201)


@bp.get("/documents/<doc_id>/suggestions")
@login_required
def list_suggestions(doc_id):
    """Owner only."""
    return ok({"suggestions": ai_service.list_pending(get_db(), g.user, doc_id)})


@bp.post("/documents/<doc_id>/suggestions/<suggestion_id>/accept")
@login_required
def accept_suggestion(doc_id, suggestion_id):
    """Owner only. Body {permission?}. The owner's confirmation is what creates the grant."""
    body = json_body()
    return ok(ai_service.decide(get_db(), g.user, doc_id, suggestion_id, True, body.get("permission")), 201)


@bp.post("/documents/<doc_id>/suggestions/<suggestion_id>/reject")
@login_required
def reject_suggestion(doc_id, suggestion_id):
    """Owner only."""
    ai_service.decide(get_db(), g.user, doc_id, suggestion_id, False)
    return ok()


# ---------------------------------------------------------------- admin
@bp.get("/admin/users")
@admin_required
def admin_users():
    """Admin only."""
    return ok({"users": user_service.list_users(get_db(), g.user)})


@bp.post("/admin/users")
@admin_required
def admin_create_user():
    """Admin only. Body {email, full_name, role, password}."""
    b = json_body()
    return ok(user_service.create_user(get_db(), g.user, b.get("email"), b.get("full_name"), b.get("role"),
                                       b.get("password")), 201)


@bp.patch("/admin/users/<user_id>")
@admin_required
def admin_update_user(user_id):
    """Admin only. Body {role?, is_active?}. Ends all of that user's sessions."""
    b = json_body()
    return ok(user_service.update_user(get_db(), g.user, user_id, b.get("role"), b.get("is_active")))


@bp.post("/admin/users/<user_id>/reset-password")
@admin_required
def admin_reset_password(user_id):
    """Admin only. Body {password}. Ends all of that user's sessions."""
    user_service.reset_password(get_db(), g.user, user_id, json_body().get("password"))
    return ok()


@bp.get("/admin/documents")
@admin_required
def admin_documents():
    """Admin only. Metadata of every document; never contents."""
    return ok({"documents": admin_service.documents_overview(get_db(), g.user, request.args.get("q"))})


@bp.get("/admin/documents/<doc_id>/access")
@admin_required
def admin_document_access(doc_id):
    """Admin only. Who can reach this document now, and its recent audit events."""
    return ok(admin_service.document_access(get_db(), g.user, doc_id))


@bp.post("/admin/documents/<doc_id>/transfer")
@admin_required
def admin_transfer(doc_id):
    """Admin only. Body {new_owner_email}. For offboarding a leaver."""
    return ok(admin_service.transfer_ownership(get_db(), g.user, doc_id, json_body().get("new_owner_email")))


@bp.get("/admin/audit")
@admin_required
def admin_audit():
    """Admin only. Query: action, actor, document_id, outcome, permission_only=1, limit."""
    a = request.args
    return ok({"events": admin_service.audit_events(get_db(), g.user, a.get("action"), a.get("actor"),
                                                    a.get("document_id"), a.get("outcome"),
                                                    a.get("permission_only") == "1", a.get("limit", 200))})


@bp.get("/admin/audit/verify")
@admin_required
def admin_verify():
    """Admin only. Recomputes the hash chain over every event."""
    db = get_db()
    result = audit.verify(db)
    audit.record(db, "audit_verified", actor=g.user, details={"ok": result["ok"], "count": result["count"]})
    return ok(result)


@bp.get("/admin/audit/head")
@admin_required
def admin_head():
    """Admin only. Latest event id and hash, for anchoring outside the database."""
    return ok(audit.head(get_db()))


@bp.get("/admin/audit/export.csv")
@admin_required
def admin_export():
    """Admin only. CSV of the latest 1000 events (formula-injection safe)."""
    from flask import Response

    body = admin_service.audit_csv(get_db(), g.user)
    return Response(body, mimetype="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="trustvault-audit.csv"'})


@bp.get("/admin/alerts")
@admin_required
def admin_alerts():
    """Admin only."""
    return ok({"alerts": admin_service.alerts(get_db(), g.user)})
