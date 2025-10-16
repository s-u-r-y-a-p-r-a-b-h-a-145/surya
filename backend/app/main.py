from fastapi import FastAPI
from .routers import auth, totp, webauthn

app = FastAPI(title="Secure MFA Framework")

@app.get("/health")
def health():
    return {"status": "ok"}

app.include_router(auth.router)
app.include_router(totp.router)
app.include_router(webauthn.router)
