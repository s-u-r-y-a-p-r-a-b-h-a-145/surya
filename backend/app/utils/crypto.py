import base64
import hashlib
from cryptography.fernet import Fernet
from ..config import settings


def _derive_fernet_key(secret: str) -> bytes:
    # Derive a 32-byte key from app secret, urlsafe-base64 encoded for Fernet
    digest = hashlib.sha256(secret.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def get_fernet() -> Fernet:
    return Fernet(_derive_fernet_key(settings.secret_key))


def encrypt_bytes(data: bytes) -> bytes:
    return get_fernet().encrypt(data)


def decrypt_bytes(token: bytes) -> bytes:
    return get_fernet().decrypt(token)
