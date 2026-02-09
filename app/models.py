from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from sqlalchemy import UniqueConstraint
from sqlmodel import Field, SQLModel


class UserRole(str, Enum):
    member = "member"
    coach = "coach"
    admin = "admin"
    frontdesk = "frontdesk"


class BookingStatus(str, Enum):
    pending = "pending"
    confirmed = "confirmed"
    rejected = "rejected"
    cancelled = "cancelled"


class User(SQLModel, table=True):
    __table_args__ = (UniqueConstraint("username"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True)
    password_hash: str
    role: UserRole = Field(index=True)
    is_active: bool = Field(default=True, index=True)
    created_at: datetime = Field(default_factory=datetime.utcnow, index=True)


class Coach(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", index=True)
    display_name: str = Field(index=True)
    notes: Optional[str] = None


class Member(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", index=True)
    display_name: str = Field(index=True)
    phone: Optional[str] = None


class AvailabilityRule(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    coach_id: int = Field(foreign_key="coach.id", index=True)
    weekday: int = Field(index=True)
    start_minute: int
    end_minute: int
    slot_minutes: int
    capacity: int = 1
    enabled: bool = Field(default=True, index=True)


class AvailabilityException(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    coach_id: int = Field(foreign_key="coach.id", index=True)
    date: str = Field(index=True)
    start_minute: int
    end_minute: int
    capacity: int = 1
    enabled: bool = Field(default=True, index=True)


class Booking(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    coach_id: int = Field(foreign_key="coach.id", index=True)
    member_id: int = Field(foreign_key="member.id", index=True)
    date: str = Field(index=True)
    start_minute: int = Field(index=True)
    end_minute: int
    status: BookingStatus = Field(default=BookingStatus.pending, index=True)
    decision_note: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow, index=True)
    updated_at: datetime = Field(default_factory=datetime.utcnow, index=True)
