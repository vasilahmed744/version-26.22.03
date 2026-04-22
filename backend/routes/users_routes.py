from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.auth import hash_password, require_roles, to_user_public
from backend.database import get_db
from backend.models import User
from backend.schemas import UserCreate, UserUpdate


router = APIRouter(prefix="/users", tags=["users"])


@router.get("")
def list_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
) -> dict:
    users = db.query(User).order_by(User.created_at.asc()).all()
    return {"items": [to_user_public(user).model_dump(mode="json") for user in users]}


@router.post("")
def create_user(
    payload: UserCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
) -> dict:
    existing = (
        db.query(User)
        .filter((User.username == payload.username) | (User.email == payload.email))
        .first()
    )
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username or email already exists")

    user = User(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
        role=payload.role,
        is_active=payload.is_active,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"message": "User created", "user": to_user_public(user)}


@router.patch("/{user_id}")
def update_user(
    user_id: int,
    payload: UserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
) -> dict:
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if payload.email is not None:
        user.email = payload.email
    if payload.role is not None:
        user.role = payload.role
    if payload.is_active is not None:
        user.is_active = payload.is_active
    if payload.password:
        user.password_hash = hash_password(payload.password)
    db.commit()
    db.refresh(user)
    return {"message": "User updated", "user": to_user_public(user)}
