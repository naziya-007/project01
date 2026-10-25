"""Where ciphertext lives.

"db" (default): the `blobs` table. Reads go through row-level security chained to
document_versions, so the database itself refuses to hand a blob to a user who
cannot see the version that points at it. Suits Render's free tier, whose local
disk is wiped on every restart. Limit: the free database is 1 GB.

"s3": any S3-compatible private bucket (Cloudflare R2, AWS S3, Backblaze B2).
Objects are only ever fetched by the server after authorization; no pre-signed
URLs are issued, because a pre-signed URL keeps working after access is revoked.
"""
import secrets

from flask import current_app


def new_key() -> str:
    return secrets.token_hex(16)


class DbStorage:
    def put(self, db, key: str, data: bytes) -> None:
        db.run("INSERT INTO blobs (storage_key, data) VALUES (%s, %s)", (key, data))

    def get(self, db, key: str) -> bytes | None:
        return db.scalar("SELECT data FROM blobs WHERE storage_key = %s", (key,))

    def delete(self, db, key: str) -> None:
        db.run("DELETE FROM blobs WHERE storage_key = %s", (key,))


class S3Storage:
    def __init__(self, cfg):
        import boto3  # optional dependency, only needed for this backend

        self.bucket = cfg.S3_BUCKET
        self.client = boto3.client("s3", endpoint_url=cfg.S3_ENDPOINT or None,
                                   aws_access_key_id=cfg.S3_ACCESS_KEY_ID,
                                   aws_secret_access_key=cfg.S3_SECRET_ACCESS_KEY)

    def put(self, db, key: str, data: bytes) -> None:
        self.client.put_object(Bucket=self.bucket, Key=f"blobs/{key}", Body=data)

    def get(self, db, key: str) -> bytes | None:
        try:
            return self.client.get_object(Bucket=self.bucket, Key=f"blobs/{key}")["Body"].read()
        except self.client.exceptions.NoSuchKey:
            return None

    def delete(self, db, key: str) -> None:
        self.client.delete_object(Bucket=self.bucket, Key=f"blobs/{key}")


_db_storage = DbStorage()


def backend():
    cfg = current_app.config["TV"]
    if cfg.STORAGE_BACKEND == "s3":
        store = current_app.extensions.get("tv_s3")
        if store is None:
            store = S3Storage(cfg)
            current_app.extensions["tv_s3"] = store
        return store
    return _db_storage
