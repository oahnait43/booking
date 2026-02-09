from __future__ import annotations

from datetime import datetime
from typing import Optional, Tuple

from sqlalchemy import func
from sqlmodel import Session, select

from app.models import Booking, BookingStatus, Coach, Member
from app.services.availability import build_slots_for_coach
from app.settings import settings


class BookingError(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


def get_member_by_user_id(session: Session, user_id: int) -> Optional[Member]:
    return session.exec(select(Member).where(Member.user_id == user_id)).first()


def get_coach_by_user_id(session: Session, user_id: int) -> Optional[Coach]:
    return session.exec(select(Coach).where(Coach.user_id == user_id)).first()


def _find_slot(
    session: Session, coach_id: int, date: str, start_minute: int
) -> Optional[Tuple[int, int, int]]:
    slots = build_slots_for_coach(
        session=session,
        coach_id=coach_id,
        date=date,
        default_slot_minutes=settings.default_slot_minutes,
    )
    for slot in slots:
        if slot.start_minute == start_minute:
            return (slot.start_minute, slot.end_minute, slot.capacity)
    return None


def create_booking(
    session: Session,
    member_id: int,
    coach_id: int,
    date: str,
    start_minute: int,
) -> Booking:
    try:
        slot = _find_slot(
            session=session, coach_id=coach_id, date=date, start_minute=start_minute
        )
    except ValueError:
        raise BookingError("日期格式错误")
    if not slot:
        raise BookingError("该时间段不可预约")
    slot_start, slot_end, capacity = slot

    active_statuses = {BookingStatus.pending, BookingStatus.confirmed}

    existing_member = session.exec(
        select(Booking).where(
            Booking.member_id == member_id,
            Booking.date == date,
            Booking.start_minute == slot_start,
            Booking.status.in_(active_statuses),
        )
    ).first()
    if existing_member:
        raise BookingError("你已预约过该时间段")

    coach_count = session.exec(
        select(func.count())
        .select_from(Booking)
        .where(
            Booking.coach_id == coach_id,
            Booking.date == date,
            Booking.start_minute == slot_start,
            Booking.status.in_(active_statuses),
        )
    ).one()
    if coach_count >= capacity:
        raise BookingError("该时间段已约满")

    booking = Booking(
        coach_id=coach_id,
        member_id=member_id,
        date=date,
        start_minute=slot_start,
        end_minute=slot_end,
        status=BookingStatus.pending,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    session.add(booking)
    session.commit()
    session.refresh(booking)
    return booking


def cancel_booking(session: Session, booking_id: int, member_id: int) -> Booking:
    booking = session.get(Booking, booking_id)
    if not booking or booking.member_id != member_id:
        raise BookingError("预约不存在")
    if booking.status not in {BookingStatus.pending, BookingStatus.confirmed}:
        raise BookingError("当前状态不可取消")
    booking.status = BookingStatus.cancelled
    booking.updated_at = datetime.utcnow()
    session.add(booking)
    session.commit()
    session.refresh(booking)
    return booking


def confirm_booking(session: Session, booking_id: int, coach_id: int) -> Booking:
    booking = session.get(Booking, booking_id)
    if not booking or booking.coach_id != coach_id:
        raise BookingError("预约不存在")
    if booking.status != BookingStatus.pending:
        raise BookingError("当前状态不可确认")
    booking.status = BookingStatus.confirmed
    booking.updated_at = datetime.utcnow()
    session.add(booking)
    session.commit()
    session.refresh(booking)
    return booking


def reject_booking(
    session: Session, booking_id: int, coach_id: int, decision_note: Optional[str] = None
) -> Booking:
    booking = session.get(Booking, booking_id)
    if not booking or booking.coach_id != coach_id:
        raise BookingError("预约不存在")
    if booking.status != BookingStatus.pending:
        raise BookingError("当前状态不可拒绝")
    booking.status = BookingStatus.rejected
    booking.decision_note = decision_note
    booking.updated_at = datetime.utcnow()
    session.add(booking)
    session.commit()
    session.refresh(booking)
    return booking
