"""Envelope encryption for stored files.

Each version of each file gets its own random 256-bit data key (DEK). The file is
encrypted with AES-256-GCM under that DEK, with the document id and version as
associated data, so a ciphertext copied onto another document refuses to decrypt.
The DEK is itself encrypted ("wrapped") under a master key derived from the
MASTER_KEY environment variable and stored in document_versions.wrapped_key.

Consequence: the blob store alone (a leaked bucket, a stolen `blobs` dump) is
useless without both the database row and the master key.
"""
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

NONCE = 12


class DecryptionError(Exception):
    pass


def derive_master_key(secret: str) -> bytes:
    if not secret:
        raise RuntimeError("MASTER_KEY is not set")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"trustvault-master-v1",
                info=b"wrap-data-keys").derive(secret.encode())


def _aad(document_id: str, version: int, purpose: str) -> bytes:
    return f"{purpose}:{document_id}:{version}".encode()


def encrypt_file(master_key: bytes, document_id: str, version: int, plaintext: bytes) -> tuple[bytes, bytes]:
    """Returns (ciphertext_blob, wrapped_key)."""
    dek = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(NONCE)
    blob = nonce + AESGCM(dek).encrypt(nonce, plaintext, _aad(document_id, version, "file"))
    wnonce = os.urandom(NONCE)
    wrapped = wnonce + AESGCM(master_key).encrypt(wnonce, dek, _aad(document_id, version, "dek"))
    return blob, wrapped


def decrypt_file(master_key: bytes, document_id: str, version: int, blob: bytes, wrapped: bytes) -> bytes:
    try:
        dek = AESGCM(master_key).decrypt(wrapped[:NONCE], wrapped[NONCE:], _aad(document_id, version, "dek"))
        return AESGCM(dek).decrypt(blob[:NONCE], blob[NONCE:], _aad(document_id, version, "file"))
    except Exception as exc:  # InvalidTag, ValueError
        raise DecryptionError("stored file failed integrity check") from exc
