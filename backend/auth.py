from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from backend.config import ACCESS_TOKEN_EXPIRE_MINUTES, JWT_ALGORITHM, JWT_SECRET, SUPPORTED_ROLES
from backend.database import get_db
from backend.models import SessionToken, User
from backend.schemas import UserPublic


pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=False)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def authenticate_user(db: Session, username: str, password: str) -> User | None:
    user = (
        db.query(User)
        .filter((User.username == username) | (User.email == username))
        .first()
    )
    if not user or not user.is_active:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_access_token(db: Session, user: User) -> str:
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    jti = uuid4().hex
    payload = {
        "sub": str(user.id),
        "jti": jti,
        "role": user.role,
        "exp": expires_at,
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    token_record = SessionToken(
        user_id=user.id,
        jti=jti,
        token_hash=_hash_token(token),
        expires_at=expires_at.replace(tzinfo=None),
    )
    db.add(token_record)
    user.last_login_at = datetime.utcnow()
    db.commit()
    return token


def revoke_token(db: Session, token: str) -> None:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        jti = payload.get("jti")
    except JWTError:
        return

    record = db.query(SessionToken).filter(SessionToken.jti == jti).first()
    if record and not record.revoked_at:
        record.revoked_at = datetime.utcnow()
        db.commit()


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    return get_user_from_token(db, credentials.credentials)


def require_roles(*allowed_roles: str):
    invalid_roles = [role for role in allowed_roles if role not in SUPPORTED_ROLES]
    if invalid_roles:
        raise ValueError(f"Unsupported roles configured: {invalid_roles}")

    def dependency(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to access this resource",
            )
        return current_user

    return dependency


def to_user_public(user: User) -> UserPublic:
    return UserPublic.model_validate(user)


def get_user_from_token(db: Session, token: str) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
    )

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = int(payload.get("sub"))
        jti = payload.get("jti")
    except (JWTError, TypeError, ValueError):
        raise credentials_exception from None

    session_token = db.query(SessionToken).filter(SessionToken.jti == jti).first()
    if not session_token or session_token.revoked_at or session_token.token_hash != _hash_token(token):
        raise credentials_exception
    if session_token.expires_at < datetime.utcnow():
        raise credentials_exception

    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active:
        raise credentials_exception
    return user
