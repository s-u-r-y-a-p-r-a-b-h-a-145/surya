from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
import pyotp
import qrcode
import io
import base64
from ..services.database import SessionLocal
from ..services.models import User
from ..config import settings
from ..utils.crypto import encrypt_bytes, decrypt_bytes

router = APIRouter(prefix="/totp", tags=["totp"])

class SetupResponse(BaseModel):
    secret: str
    provisioning_uri: str
    qr_base64_png: str

class VerifyRequest(BaseModel):
    user_id: int
    code: str


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/setup", response_model=SetupResponse)
def setup_totp(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    secret = pyotp.random_base32()
    user.totp_secret_enc = encrypt_bytes(secret.encode())
    db.commit()
    issuer = settings.issuer
    name = user.email
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=name, issuer_name=issuer)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()
    return SetupResponse(secret=secret, provisioning_uri=uri, qr_base64_png=qr_b64)

@router.post("/verify")
def verify_totp(payload: VerifyRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == payload.user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if not user.totp_secret_enc:
        raise HTTPException(status_code=400, detail="TOTP not initialized")
    secret = decrypt_bytes(user.totp_secret_enc).decode()
    totp = pyotp.TOTP(secret)
    if not totp.verify(payload.code, valid_window=1):
        raise HTTPException(status_code=401, detail="Invalid TOTP")
    user.is_totp_enabled = True
    db.commit()
    return {"status": "verified"}
