"""Helpers shared by the JSON API and the HTML pages."""
import re
import urllib.parse
from functools import wraps

from flask import Response, current_app, g, jsonify, redirect, request, url_for
from werkzeug.exceptions import BadRequest, Forbidden


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if g.get("user") is None:
            if request.path.startswith("/api/"):
                return jsonify({"error": "unauthorized"}), 401
            return redirect(url_for("ui.login"))
        return view(*args, **kwargs)

    return wrapper


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapper(*args, **kwargs):
        if g.user["role"] != "admin":
            raise Forbidden()
        return view(*args, **kwargs)

    return wrapper


def json_body() -> dict:
    # Only genuine application/json is accepted: a cross-site HTML form cannot
    # send it without a CORS preflight, which this app never approves.
    if not request.is_json:
        raise BadRequest("Expected an application/json body.")
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise BadRequest("Expected a JSON object.")
    return data


def uploaded_file():
    f = request.files.get("file")
    if f is None:
        raise BadRequest("Attach a file in the 'file' field.")
    limit = current_app.config["TV"].MAX_UPLOAD_MB * 1024 * 1024
    data = f.stream.read(limit + 1)  # one byte over the limit is enough to reject
    return f.filename, data


def file_response(filename: str, data: bytes) -> Response:
    """Always a download, never rendered: generic type, attachment disposition and
    nosniff (set globally), so even an HTML file that slipped past validation
    would be saved to disk, not run as script in our origin."""
    ascii_name = re.sub(r"[^A-Za-z0-9._-]", "_", filename)[:120] or "download"
    encoded = urllib.parse.quote(filename, safe="")
    resp = Response(data, mimetype="application/octet-stream")
    resp.headers["Content-Disposition"] = f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{encoded}"
    resp.headers["Content-Length"] = str(len(data))
    resp.headers["X-Download-Options"] = "noopen"
    return resp


def serialise(value):
    """JSON-safe copy (datetimes to ISO strings, bytes dropped)."""
    from datetime import date, datetime

    if isinstance(value, dict):
        return {k: serialise(v) for k, v in value.items() if not isinstance(v, (bytes, bytearray))}
    if isinstance(value, list):
        return [serialise(v) for v in value]
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value
