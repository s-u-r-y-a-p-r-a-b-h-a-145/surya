from sqlalchemy import String, Integer, Boolean, LargeBinary, ForeignKey, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .database import Base
from datetime import datetime

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    totp_secret_enc: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    webauthn_credentials: Mapped[list["WebAuthnCredential"]] = relationship(back_populates="user", cascade="all, delete-orphan")

class WebAuthnCredential(Base):
    __tablename__ = "webauthn_credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    credential_id: Mapped[bytes] = mapped_column(LargeBinary, unique=True, nullable=False)
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    sign_count: Mapped[int] = mapped_column(Integer, default=0)
    transports: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    user: Mapped[User] = relationship(back_populates="webauthn_credentials")
