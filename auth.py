from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from settings import JWT_SECRET, JWT_ALG, JWT_EXPIRE_MIN, ADMIN_USER, ADMIN_PASS_HASH

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer = HTTPBearer(auto_error=False)

def create_password_hash(plain: str) -> str:
    return pwd_context.hash(plain)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def authenticate_user(username: str, password: str) -> bool:
    if not ADMIN_PASS_HASH:
        # Evita rodar "sem senha" em produção por acidente
        return False
    if username != ADMIN_USER:
        return False
    return verify_password(password, ADMIN_PASS_HASH)

def create_access_token(subject: str) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=JWT_EXPIRE_MIN)
    payload = {"sub": subject, "iat": int(now.timestamp()), "exp": exp}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def require_auth(creds: HTTPAuthorizationCredentials = Depends(bearer)) -> str:
    if not creds or creds.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Token ausente")

    token = creds.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        sub = payload.get("sub")
        if not sub:
            raise HTTPException(status_code=401, detail="Token inválido")
        return sub
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido ou expirado")
