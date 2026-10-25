"""Server-rendered pages. Same services, same authorize() calls as the API; the
pages add nothing to authorization (a hidden button is never the protection)."""
from flask import (Blueprint, current_app, flash, g, redirect, render_template, request, url_for)
from werkzeug.exceptions import BadRequest, Forbidden

from .. import audit, get_db, security, set_session_cookie
from ..services import admin as admin_service
from ..services import ai as ai_service
from ..services import documents as doc_service
from ..services import grants as grant_service
from ..services import shares as share_service
from ..services import users as user_service
from .common import admin_required, file_response, login_required, uploaded_file

bp = Blueprint("ui", __name__)


def _back_with_error(exc: BadRequest, endpoint: str, **kwargs):
    get_db().rollback()  # nothing half-done survives a validation error
    flash(exc.description or "That request was not valid.", "error")
    return redirect(url_for(endpoint, **kwargs))


@bp.get("/healthz")
def healthz():
    return {"status": "ok"}


@bp.app_context_processor
def _inject():
    return {"current_user": g.get("user"), "csrf_token": g.session["csrf_token"] if g.get("session") else "",
            "categories": doc_service.CATEGORIES}


# ---------------------------------------------------------------- auth
@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    cfg = current_app.config["TV"]
    ip = security.client_ip(request, cfg.TRUST_PROXY_HOPS)
    email = request.form.get("email", "")[:254].lower()
    db = get_db()
    if not security.limiter.allow(f"login-ip:{ip}", cfg.LOGIN_RATE_PER_MIN) or \
            not security.limiter.allow(f"login-email:{email}", cfg.LOGIN_RATE_PER_MIN):
        audit.deny(db, "login_rate_limited", details={"email": email})
        return render_template("login.html", error="Too many attempts. Wait a minute and try again."), 429
    user = user_service.authenticate(db, request.form.get("email"), request.form.get("password"))
    if user is None:
        g.force_commit = True
        return render_template("login.html", error="Invalid e-mail or password."), 401
    token, _ = user_service.create_session(db, user, ip, security.user_agent(request), cfg.SESSION_HOURS)
    resp = redirect(url_for("ui.admin_dashboard" if user["role"] == "admin" else "ui.documents"))
    set_session_cookie(resp, token)
    return resp


@bp.post("/logout")
@login_required
def logout():
    user_service.end_session(get_db(), g.session["token_hash"], g.user)
    resp = redirect(url_for("ui.login"))
    resp.delete_cookie("tv_session", path="/")
    return resp


@bp.route("/account", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "POST":
        try:
            user_service.change_own_password(get_db(), g.user, g.session["token_hash"],
                                             request.form.get("current_password"), request.form.get("new_password"))
        except BadRequest as exc:
            g.force_commit = True  # keep the failed-attempt audit row
            flash(exc.description, "error")
            return redirect(url_for("ui.account"))
        flash("Password changed. Your other sessions were signed out.", "ok")
        return redirect(url_for("ui.account"))
    return render_template("account.html")


# ----------------------------------------------------------- documents
@bp.get("/")
@login_required
def documents():
    if g.user["role"] == "admin" and not request.args:
        return redirect(url_for("ui.admin_dashboard"))
    a = request.args
    try:
        result = doc_service.search(get_db(), g.user, q=a.get("q"), owner=a.get("owner"),
                                    category=a.get("category") or None, date_from=a.get("from"),
                                    date_to=a.get("to"), scope=a.get("scope", "all"), page=a.get("page", 1))
    except BadRequest as exc:
        flash(exc.description, "error")
        result = {"items": [], "page": 1, "has_more": False}
    return render_template("documents.html", result=result, args=a)


@bp.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if g.user["role"] != "owner":
        raise Forbidden("Only document owners can upload.")
    if request.method == "GET":
        return render_template("upload.html")
    try:
        filename, data = uploaded_file()
        doc = doc_service.create(get_db(), g.user, filename, data, request.form.get("name"),
                                 request.form.get("category", "Other"))
    except BadRequest as exc:
        return _back_with_error(exc, "ui.upload")
    flash("Uploaded and encrypted.", "ok")
    return redirect(url_for("ui.document", doc_id=doc["id"]))


def _render_document(doc_id, new_share=None):
    db = get_db()
    doc = doc_service.get(db, g.user, doc_id)
    extra = {}
    if doc["my_permission"] == "owner":
        extra = {"grants": grant_service.list_grants(db, g.user, doc_id),
                 "shares": share_service.list_links(db, g.user, doc_id),
                 "suggestions": ai_service.list_pending(db, g.user, doc_id)}
    return render_template("document.html", doc=doc, new_share=new_share, **extra)


@bp.get("/documents/<doc_id>")
@login_required
def document(doc_id):
    return _render_document(doc_id)


@bp.post("/documents/<doc_id>/edit")
@login_required
def edit_document(doc_id):
    try:
        doc_service.update_metadata(get_db(), g.user, doc_id,
                                    {"name": request.form.get("name"), "category": request.form.get("category")})
    except BadRequest as exc:
        return _back_with_error(exc, "ui.document", doc_id=doc_id)
    flash("Saved.", "ok")
    return redirect(url_for("ui.document", doc_id=doc_id))


@bp.post("/documents/<doc_id>/download")
@login_required
def download(doc_id):
    filename, data, _ = doc_service.download(get_db(), g.user, doc_id)
    return file_response(filename, data)


@bp.post("/documents/<doc_id>/versions/<int:version>/download")
@login_required
def download_version(doc_id, version):
    filename, data, _ = doc_service.download(get_db(), g.user, doc_id, version)
    return file_response(filename, data)


@bp.post("/documents/<doc_id>/versions")
@login_required
def add_version(doc_id):
    try:
        doc_service.add_version(get_db(), g.user, doc_id, uploaded_file)
    except BadRequest as exc:
        return _back_with_error(exc, "ui.document", doc_id=doc_id)
    flash("New version uploaded.", "ok")
    return redirect(url_for("ui.document", doc_id=doc_id))


@bp.post("/documents/<doc_id>/delete")
@login_required
def delete(doc_id):
    doc_service.soft_delete(get_db(), g.user, doc_id)
    flash("Moved to trash. Share links were revoked.", "ok")
    return redirect(url_for("ui.trash"))


@bp.post("/documents/<doc_id>/restore")
@login_required
def restore(doc_id):
    try:
        doc_service.restore(get_db(), g.user, doc_id)
    except BadRequest as exc:
        return _back_with_error(exc, "ui.trash")
    flash("Restored.", "ok")
    return redirect(url_for("ui.document", doc_id=doc_id))


@bp.get("/trash")
@login_required
def trash():
    return render_template("trash.html", items=doc_service.trash(get_db(), g.user))


# --------------------------------------------------------------- sharing
@bp.post("/documents/<doc_id>/grants")
@login_required
def add_grant(doc_id):
    try:
        grant_service.grant(get_db(), g.user, doc_id, request.form.get("email"), request.form.get("permission"))
    except BadRequest as exc:
        return _back_with_error(exc, "ui.document", doc_id=doc_id)
    flash("Access granted.", "ok")
    return redirect(url_for("ui.document", doc_id=doc_id))


@bp.post("/documents/<doc_id>/grants/<user_id>/revoke")
@login_required
def revoke_grant(doc_id, user_id):
    grant_service.revoke(get_db(), g.user, doc_id, user_id)
    flash("Access revoked. It stopped working immediately.", "ok")
    return redirect(url_for("ui.document", doc_id=doc_id))


@bp.post("/documents/<doc_id>/shares")
@login_required
def add_share(doc_id):
    try:
        link = share_service.create(get_db(), g.user, doc_id, request.form.get("expires_hours"),
                                    request.form.get("max_downloads"), request.form.get("label"))
    except BadRequest as exc:
        return _back_with_error(exc, "ui.document", doc_id=doc_id)
    # Rendered directly (not redirected) so the one-time token never sits in a cookie.
    return _render_document(doc_id, new_share=request.host_url.rstrip("/") + link["path"])


@bp.post("/documents/<doc_id>/shares/<share_id>/revoke")
@login_required
def revoke_share(doc_id, share_id):
    share_service.revoke(get_db(), g.user, doc_id, share_id)
    flash("Share link revoked.", "ok")
    return redirect(url_for("ui.document", doc_id=doc_id))


@bp.post("/documents/<doc_id>/suggestions")
@login_required
def suggest(doc_id):
    picks = ai_service.suggest(get_db(), g.user, doc_id)
    flash(f"{len(picks)} suggestion(s). Nothing is shared until you accept one." if picks
          else "No suggestions: you have not shared similar documents before.", "ok")
    return redirect(url_for("ui.document", doc_id=doc_id))


@bp.post("/documents/<doc_id>/suggestions/<suggestion_id>/accept")
@login_required
def accept_suggestion(doc_id, suggestion_id):
    try:
        ai_service.decide(get_db(), g.user, doc_id, suggestion_id, True, request.form.get("permission"))
    except BadRequest as exc:
        return _back_with_error(exc, "ui.document", doc_id=doc_id)
    flash("Suggestion accepted: access granted by you.", "ok")
    return redirect(url_for("ui.document", doc_id=doc_id))


@bp.post("/documents/<doc_id>/suggestions/<suggestion_id>/reject")
@login_required
def reject_suggestion(doc_id, suggestion_id):
    ai_service.decide(get_db(), g.user, doc_id, suggestion_id, False)
    flash("Suggestion dismissed.", "ok")
    return redirect(url_for("ui.document", doc_id=doc_id))


@bp.get("/share")
def share_page():
    return render_template("share.html")


@bp.post("/share/download")
def share_download():
    cfg = current_app.config["TV"]
    if not security.limiter.allow(f"share:{security.client_ip(request, cfg.TRUST_PROXY_HOPS)}", cfg.SHARE_RATE_PER_MIN):
        return render_template("error.html", code=429, name="Too Many Requests", message="Slow down."), 429
    filename, data = share_service.download(get_db(), request.form.get("token"))
    return file_response(filename, data)


# ---------------------------------------------------------------- admin
@bp.get("/admin")
@admin_required
def admin_dashboard():
    db = get_db()
    return render_template("admin/dashboard.html",
                           alerts=admin_service.alerts(db, g.user),
                           recent=admin_service.audit_events(db, g.user, limit=25),
                           permission_changes=admin_service.audit_events(db, g.user, permission_only=True, limit=15),
                           denied=admin_service.audit_events(db, g.user, outcome="denied", limit=15),
                           head=audit.head(db))


@bp.get("/admin/users")
@admin_required
def admin_users():
    return render_template("admin/users.html", users=user_service.list_users(get_db(), g.user))


@bp.post("/admin/users")
@admin_required
def admin_create_user():
    f = request.form
    try:
        user_service.create_user(get_db(), g.user, f.get("email"), f.get("full_name"), f.get("role"), f.get("password"))
    except BadRequest as exc:
        return _back_with_error(exc, "ui.admin_users")
    flash("User created.", "ok")
    return redirect(url_for("ui.admin_users"))


@bp.post("/admin/users/<user_id>")
@admin_required
def admin_update_user(user_id):
    f = request.form
    active = {"true": True, "false": False}.get(f.get("is_active"))
    try:
        user_service.update_user(get_db(), g.user, user_id, f.get("role") or None, active)
    except BadRequest as exc:
        return _back_with_error(exc, "ui.admin_users")
    flash("User updated; their sessions were ended.", "ok")
    return redirect(url_for("ui.admin_users"))


@bp.post("/admin/users/<user_id>/reset-password")
@admin_required
def admin_reset_password(user_id):
    try:
        user_service.reset_password(get_db(), g.user, user_id, request.form.get("password"))
    except BadRequest as exc:
        return _back_with_error(exc, "ui.admin_users")
    flash("Password reset; their sessions were ended.", "ok")
    return redirect(url_for("ui.admin_users"))


@bp.get("/admin/documents")
@admin_required
def admin_documents():
    return render_template("admin/documents.html",
                           documents=admin_service.documents_overview(get_db(), g.user, request.args.get("q")))


@bp.get("/admin/documents/<doc_id>")
@admin_required
def admin_document(doc_id):
    return render_template("admin/document.html", doc=admin_service.document_access(get_db(), g.user, doc_id))


@bp.post("/admin/documents/<doc_id>/transfer")
@admin_required
def admin_transfer(doc_id):
    try:
        admin_service.transfer_ownership(get_db(), g.user, doc_id, request.form.get("new_owner_email"))
    except BadRequest as exc:
        return _back_with_error(exc, "ui.admin_document", doc_id=doc_id)
    flash("Ownership transferred. The previous owner's share links were revoked.", "ok")
    return redirect(url_for("ui.admin_document", doc_id=doc_id))


@bp.get("/admin/audit")
@admin_required
def admin_audit():
    a = request.args
    try:
        events = admin_service.audit_events(get_db(), g.user, a.get("action") or None, a.get("actor") or None,
                                            a.get("document_id") or None, a.get("outcome") or None,
                                            a.get("permission_only") == "1", a.get("limit", 200))
    except BadRequest as exc:
        flash(exc.description, "error")
        events = []
    return render_template("admin/audit.html", events=events, args=a)


@bp.post("/admin/audit/verify")
@admin_required
def admin_verify():
    db = get_db()
    result = audit.verify(db)
    audit.record(db, "audit_verified", actor=g.user, details={"ok": result["ok"], "count": result["count"]})
    if result["ok"]:
        flash(f"Chain intact: {result['count']} events verified. Head {result['head_hash'][:16]}…", "ok")
    else:
        flash(f"CHAIN BROKEN at event {result['broken_at_id']}: {result['reason']}", "error")
    return redirect(url_for("ui.admin_dashboard"))
