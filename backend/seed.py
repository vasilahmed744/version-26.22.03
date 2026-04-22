from __future__ import annotations

from sqlalchemy.orm import Session

from backend.auth import hash_password
from backend.config import DEFAULT_SETTINGS
from backend.database import Base, engine
from backend.models import Setting, User


def initialize_database() -> None:
    Base.metadata.create_all(bind=engine)


def seed_defaults(db: Session) -> None:
    if not db.query(Setting).first():
        db.add(Setting(**DEFAULT_SETTINGS))

    default_users = [
        {
            "username": "admin",
            "email": "admin@sentinel.local",
            "password": "Admin@123",
            "role": "admin",
        },
        {
            "username": "analyst",
            "email": "analyst@sentinel.local",
            "password": "Analyst@123",
            "role": "analyst",
        },
        {
            "username": "viewer",
            "email": "viewer@sentinel.local",
            "password": "Viewer@123",
            "role": "viewer",
        },
    ]
    for user_data in default_users:
        exists = db.query(User).filter(User.username == user_data["username"]).first()
        if exists:
            continue
        db.add(
            User(
                username=user_data["username"],
                email=user_data["email"],
                password_hash=hash_password(user_data["password"]),
                role=user_data["role"],
                is_active=True,
            )
        )

    db.commit()
