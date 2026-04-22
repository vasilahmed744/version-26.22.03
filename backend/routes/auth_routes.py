from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from backend.auth import (
    authenticate_user,
    bearer_scheme,
    create_access_token,
    get_current_user,
    revoke_token,
    to_user_public,
)
from backend.database import get_db
from backend.models import User
from backend.schemas import LoginRequest, TokenResponse


router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    user = authenticate_user(db, payload.username, payload.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
    token = create_access_token(db, user)
    return TokenResponse(access_token=token, user=to_user_public(user))


@router.post("/logout")
def logout(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    revoke_token(db, credentials.credentials)
    return {"message": f"Logged out {current_user.username}"}


@router.get("/me")
def me(current_user: User = Depends(get_current_user)) -> dict:
    return {"user": to_user_public(current_user)}
