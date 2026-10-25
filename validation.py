"""Upload validation.

The browser-supplied Content-Type and the file extension are both attacker
controlled, so the type is decided from the bytes, and the extension must agree
with what the bytes are. Anything that a browser could render as active content
(HTML, SVG, XML, scripts) is not on the list. Office files are zip archives and are
inspected for zip bombs and macros before being accepted.
"""
import hashlib
import io
import re
import unicodedata
import zipfile
from dataclasses import dataclass

from werkzeug.exceptions import BadRequest

ALLOWED = {
    "pdf": "application/pdf",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "txt": "text/plain",
    "csv": "text/csv",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}

ZIP_MAX_ENTRIES = 2000
ZIP_MAX_TOTAL_UNCOMPRESSED = 200 * 1024 * 1024
ZIP_MAX_RATIO = 150


class UploadRejected(BadRequest):
    pass


@dataclass(frozen=True)
class ValidatedFile:
    filename: str
    extension: str
    mime: str
    size: int
    sha256: str


_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def clean_text(value, max_len: int, field: str) -> str:
    if not isinstance(value, str):
        raise BadRequest(f"{field} is required.")
    value = unicodedata.normalize("NFKC", value)
    value = _CONTROL.sub("", value).strip()
    # Bidirectional overrides let "evil‮fdp.exe" display as "evilexe.pdf".
    value = re.sub(r"[‪-‮⁦-⁩‎‏]", "", value)
    if not value:
        raise BadRequest(f"{field} is required.")
    if len(value) > max_len:
        raise BadRequest(f"{field} must be at most {max_len} characters.")
    return value


def clean_filename(raw) -> tuple[str, str]:
    if not isinstance(raw, str) or not raw:
        raise UploadRejected("A file name is required.")
    # Keep only the last path component, whichever separator the client used.
    name = re.split(r"[\\/]", raw)[-1]
    name = clean_text(name, 255, "File name")
    name = name.lstrip(".")  # no hidden files / "..": the name is display-only anyway
    if "." not in name:
        raise UploadRejected("The file needs an extension.")
    stem, ext = name.rsplit(".", 1)
    ext = ext.lower()
    stem = re.sub(r"[^\w\-. ()\[\]]", "_", stem)[:120] or "file"
    return f"{stem}.{ext}", ext


def detect_type(data: bytes, ext: str) -> str | None:
    """Return the extension the bytes really are, or None if unrecognised."""
    if data.startswith(b"%PDF-"):
        return "pdf"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if data.startswith(b"PK\x03\x04"):
        return _detect_office(data)
    if ext in ("txt", "csv") and _is_plain_text(data):
        return ext
    return None


def _is_plain_text(data: bytes) -> bool:
    if b"\x00" in data:
        return False
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    head = text[:1024].lstrip().lower()
    # Refuse text that a browser or viewer would treat as markup.
    return not head.startswith(("<!doctype", "<html", "<svg", "<?xml", "<script"))


def _detect_office(data: bytes) -> str | None:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return None
    infos = archive.infolist()
    if len(infos) > ZIP_MAX_ENTRIES:
        raise UploadRejected("Archive has too many entries.")
    total = 0
    names = set()
    for info in infos:
        total += info.file_size
        if info.compress_size and info.file_size / info.compress_size > ZIP_MAX_RATIO:
            raise UploadRejected("Archive compression ratio is suspicious (possible zip bomb).")
        if total > ZIP_MAX_TOTAL_UNCOMPRESSED:
            raise UploadRejected("Archive expands to more than the allowed size.")
        if info.filename.startswith("/") or ".." in info.filename.split("/"):
            raise UploadRejected("Archive contains unsafe paths.")
        names.add(info.filename)
    if "[Content_Types].xml" not in names:
        return None
    if any(n.lower().endswith("vbaproject.bin") for n in names):
        raise UploadRejected("Documents containing macros are not accepted.")
    if "word/document.xml" in names:
        return "docx"
    if "xl/workbook.xml" in names:
        return "xlsx"
    return None


# Byte-pattern check only: an obfuscated PDF (compressed object streams) can hide
# these. Accepted and documented in THREATS.md; downloads are always forced to
# attachment so the browser's PDF viewer never runs them in our origin.
_PDF_ACTIVE = (b"/JavaScript", b"/JS ", b"/JS(", b"/JS<", b"/Launch", b"/EmbeddedFile")


def validate_upload(raw_filename, data: bytes, max_bytes: int) -> ValidatedFile:
    if not data:
        raise UploadRejected("The file is empty.")
    if len(data) > max_bytes:
        raise UploadRejected(f"The file is larger than {max_bytes // (1024 * 1024)} MB.")
    filename, ext = clean_filename(raw_filename)
    if ext not in ALLOWED:
        raise UploadRejected("This file type is not allowed. Allowed: " + ", ".join(sorted(ALLOWED)) + ".")
    actual = detect_type(data, ext)
    expected = "jpg" if ext == "jpeg" else ext
    if actual != expected:
        raise UploadRejected("The file contents do not match its extension.")
    if actual == "pdf":
        if b"%%EOF" not in data[-2048:]:
            raise UploadRejected("The PDF is truncated or malformed.")
        if any(marker in data for marker in _PDF_ACTIVE):
            raise UploadRejected("PDFs with scripts, launch actions or embedded files are not accepted.")
    return ValidatedFile(filename=filename, extension=ext, mime=ALLOWED[ext], size=len(data),
                         sha256=hashlib.sha256(data).hexdigest())
