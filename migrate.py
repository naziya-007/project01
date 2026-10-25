"""Apply migrations/*.sql in order, once each. Safe to run on every boot:
an advisory lock stops two instances migrating at the same time.

    python -m app.migrate            apply pending migrations
    python -m app.migrate --reset    DROP EVERYTHING and re-apply (tests / local only)
"""
import os
import pathlib
import sys

import psycopg

from .config import Config

MIGRATIONS = pathlib.Path(__file__).resolve().parent.parent / "migrations"


def migrate(url: str, reset: bool = False) -> list:
    applied = []
    with psycopg.connect(url, autocommit=False) as conn:
        conn.execute("SELECT pg_advisory_lock(424242)")
        try:
            if reset:
                conn.execute("DROP SCHEMA public CASCADE")
                conn.execute("CREATE SCHEMA public")
                conn.commit()
            conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations "
                         "(version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())")
            conn.commit()
            done = {r[0] for r in conn.execute("SELECT version FROM schema_migrations").fetchall()}
            for path in sorted(MIGRATIONS.glob("*.sql")):
                if path.name in done:
                    continue
                conn.execute(path.read_text())
                conn.execute("INSERT INTO schema_migrations (version) VALUES (%s)", (path.name,))
                conn.commit()
                applied.append(path.name)
        finally:
            conn.execute("SELECT pg_advisory_unlock(424242)")
            conn.commit()
    return applied


if __name__ == "__main__":
    reset = "--reset" in sys.argv
    if reset and os.environ.get("APP_ENV") == "production":
        sys.exit("Refusing to --reset a production database.")
    names = migrate(Config().DATABASE_URL, reset=reset)
    print("Applied:", ", ".join(names) if names else "nothing (up to date)")
