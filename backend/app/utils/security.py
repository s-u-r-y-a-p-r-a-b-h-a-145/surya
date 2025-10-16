from datetime import datetime, timedelta, timezone
from typing import Optional
import jwt
from passlib.context import CryptContext
from ..config import settings

password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(plain_password: str) -> str:
    return password_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return password_context.verify(plain_password, hashed_password)


def create_access_token(subject: str, expires_delta: Optional[timedelta] = None) -> str:
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=30))
    to_encode = {
        "sub": subject,
        "iss": settings.issuer,
        "aud": settings.audience,
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "exp": int(expire.timestamp()),
    }
    token = jwt.encode(to_encode, settings.secret_key, algorithm="HS256")
    return token


def decode_token(token: str) -> dict:
    return jwt.decode(token, settings.secret_key, algorithms=["HS256"], audience=settings.audience, issuer=settings.issuer)
