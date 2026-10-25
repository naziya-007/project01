"""Hard-delete documents that have been in the trash longer than the retention
window, including their encrypted bytes. Runs at boot (render.yaml) and can be run
by hand. Each purge is written to the audit trail, which outlives the document."""
from . import audit, create_app, get_db, storage


def purge(app) -> int:
    days = app.config["TV"].TRASH_RETENTION_DAYS
    with app.test_request_context("/purge"):
        db = get_db()
        db.set_context(system=True)
        doomed = db.all("SELECT id, name, owner_id FROM documents WHERE deleted_at < now() - make_interval(days => %s)",
                        (days,))
        for doc in doomed:
            keys = [r["storage_key"] for r in db.all("SELECT storage_key FROM document_versions WHERE document_id = %s",
                                                      (doc["id"],))]
            db.run("DELETE FROM documents WHERE id = %s", (doc["id"],))  # cascades versions, grants, links
            for key in keys:
                storage.backend().delete(db, key)
            audit.record(db, "document_purged", document_id=doc["id"],
                         details={"name": doc["name"], "owner_id": doc["owner_id"], "versions": len(keys),
                                  "retention_days": days})
        db.commit()
        return len(doomed)


if __name__ == "__main__":
    print(f"Purged {purge(create_app())} document(s).")
