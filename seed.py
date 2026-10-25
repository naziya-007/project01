"""Demo data, created only when the users table is empty (safe on every boot).

Accounts (passwords can be overridden with SEED_PASSWORD_<NAME> env vars):
  admin@trustvault.demo   admin   manages users, sees all activity, cannot read files
  alice@trustvault.demo   owner   HR; owns salary letters
  bob@trustvault.demo     owner   Legal; owns a contract, granted Alice edit
  victor@trustvault.demo  viewer  granted read on ONE of Alice's documents
  eve@trustvault.demo     viewer  granted nothing: the account to attack with
"""
import os

from . import create_app, get_db, security
from .services import documents, grants

USERS = [
    ("admin@trustvault.demo", "Ada Admin", "admin", "Admin#Vault2026"),
    ("alice@trustvault.demo", "Alice Owner (HR)", "owner", "Alice#Vault2026"),
    ("bob@trustvault.demo", "Bob Owner (Legal)", "owner", "Bob#Vault2026!"),
    ("victor@trustvault.demo", "Victor Viewer", "viewer", "Victor#Vault2026"),
    ("eve@trustvault.demo", "Eve Outsider", "viewer", "Eve#Vault2026!"),
]


def _pdf(text: str) -> bytes:
    """A minimal, valid single-page PDF (no scripts)."""
    stream = f"BT /F1 14 Tf 72 720 Td ({text}) Tj ET".encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


def seed(app) -> bool:
    with app.test_request_context("/seed"):
        db = get_db()
        if db.scalar("SELECT count(*) FROM users"):
            return False
        db.set_context(system=True)
        users = {}
        for email, name, role, default_pw in USERS:
            key = "SEED_PASSWORD_" + email.split("@")[0].upper()
            pw = os.environ.get(key, default_pw)
            users[email.split("@")[0]] = db.one(
                "INSERT INTO users (email, full_name, role, password_hash) VALUES (%s, %s, %s, %s) "
                "RETURNING id, email, full_name, role, is_active", (email, name, role, security.hash_password(pw)))
        db.commit()

        def as_user(u):
            db.set_context(user_id=u["id"], role=u["role"])

        alice, bob = users["alice"], users["bob"]
        as_user(alice)
        letter = documents.create(db, alice, "salary-letter-victor.pdf",
                                  _pdf("Salary letter for Victor Viewer - CONFIDENTIAL"), "Salary letter - Victor", "HR")
        bands = documents.create(db, alice, "comp-bands-2026.csv",
                                 b"level,min,max\nL1,40000,55000\nL2,55000,72000\nL3,72000,95000\n",
                                 "Compensation bands 2026", "HR")
        documents.create(db, alice, "audit-notes-q3.txt", b"Q3 internal audit notes. Restricted to HR.\n",
                         "Q3 audit notes", "Audit")
        grants.grant(db, alice, letter["id"], "victor@trustvault.demo", "read")
        db.commit()

        as_user(bob)
        msa = documents.create(db, bob, "acme-msa.pdf", _pdf("Master Services Agreement - Acme Corp"),
                               "Acme MSA contract", "Legal")
        documents.create(db, bob, "nda-template.txt", b"Mutual NDA template v3\n", "NDA template", "Legal")
        grants.grant(db, bob, msa["id"], "alice@trustvault.demo", "edit")
        db.commit()
        _ = bands
        return True


if __name__ == "__main__":
    created = seed(create_app())
    print("Seeded demo data." if created else "Users exist; seed skipped.")
