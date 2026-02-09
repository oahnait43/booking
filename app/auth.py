from __future__ import annotations

from typing import Iterable, Optional, Set

from fastapi import Depends, HTTPException, Request
from passlib.context import CryptContext
from sqlmodel import Session, select

from app.db import get_session
from app.models import User, UserRole

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def authenticate_user(session: Session, username: str, password: str) -> Optional[User]:
    user = session.exec(select(User).where(User.username == username)).first()
    if not user:
        return None
    if not user.is_active:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


def ensure_bootstrap_admin(session: Session, username: str, password: str) -> None:
    existing = session.exec(
        select(User).where(User.username == username).where(User.role == UserRole.admin)
    ).first()
    if existing:
        return
    admin = User(username=username, password_hash=hash_password(password), role=UserRole.admin)
    session.add(admin)
    session.commit()


def get_current_user(
    request: Request,
    session: Session = Depends(get_session),
) -> User:
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user = session.get(User, int(user_id))
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


def require_roles(roles: Iterable[UserRole]):
    role_set: Set[UserRole] = set(roles)

    def dependency(user: User = Depends(get_current_user)) -> User:
        if user.role not in role_set:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user

    return dependency
