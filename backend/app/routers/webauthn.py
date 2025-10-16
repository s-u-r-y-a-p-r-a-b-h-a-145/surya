from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from webauthn import (
    generate_registration_options,
    options_to_json,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
)
from webauthn.helpers.structs import (
    PublicKeyCredentialRpEntity,
    UserVerificationRequirement,
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
)
from ..services.database import SessionLocal
from ..services.models import User, WebAuthnCredential
from ..config import settings

router = APIRouter(prefix="/webauthn", tags=["webauthn"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class BeginRegResponse(BaseModel):
    publicKey: dict

@router.post("/register/begin", response_model=BeginRegResponse)
def begin_registration(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    options = generate_registration_options(
        rp=PublicKeyCredentialRpEntity(id="localhost", name=settings.app_name),
        user_id=str(user.id).encode(),
        user_name=user.email,
        authenticator_selection=AuthenticatorSelectionCriteria(
            require_resident_key=False,
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )
    return {"publicKey": options_to_json(options)}

class FinishRegRequest(BaseModel):
    user_id: int
    response: dict

@router.post("/register/finish")
def finish_registration(payload: FinishRegRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == payload.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    verification = verify_registration_response(
        credential=payload.response,
        expected_rp_id="localhost",
        expected_origin="http://localhost:8000",
        expected_challenge=None,  # For demo only; in production store and check challenge
    )

    cred = WebAuthnCredential(
        user_id=user.id,
        credential_id=verification.credential_id,
        public_key=verification.credential_public_key,
        sign_count=verification.sign_count,
        transports=None,
    )
    db.add(cred)
    db.commit()
    return {"status": "registered"}

class BeginAuthResponse(BaseModel):
    publicKey: dict

@router.post("/authenticate/begin", response_model=BeginAuthResponse)
def begin_authentication(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    options = generate_authentication_options(
        rp_id="localhost",
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    return {"publicKey": options_to_json(options)}

class FinishAuthRequest(BaseModel):
    user_id: int
    response: dict

@router.post("/authenticate/finish")
def finish_authentication(payload: FinishAuthRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == payload.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    verification = verify_authentication_response(
        credential=payload.response,
        expected_rp_id="localhost",
        expected_origin="http://localhost:8000",
        expected_challenge=None,  # demo only
        credential_public_key=None,  # would look up by credential_id
        credential_current_sign_count=0,
        require_user_verification=False,
    )

    # Would update sign count
    return {"status": "authenticated"}
