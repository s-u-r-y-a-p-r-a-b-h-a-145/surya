from pydantic import BaseModel, Field
import os
from datetime import timedelta

class Settings(BaseModel):
    app_name: str = Field(default="Secure MFA Framework")
    secret_key: str = Field(default=os.getenv("SECRET_KEY", "dev-secret-change"))
    access_token_expire_minutes: int = 30
    db_url: str = Field(default=os.getenv("DATABASE_URL", "sqlite:///./app.db"))
    issuer: str = "secure-mfa"
    audience: str = "secure-mfa-clients"

    class Config:
        arbitrary_types_allowed = True

settings = Settings()
access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
