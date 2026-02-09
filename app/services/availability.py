from __future__ import annotations

from dataclasses import dataclass
from datetime import date as date_type
from typing import Dict, List

from sqlalchemy import func
from sqlmodel import Session, select

from app.models import AvailabilityException, AvailabilityRule, Booking, BookingStatus
from app.time_utils import parse_ymd


@dataclass(frozen=True)
class Slot:
    date: str
    start_minute: int
    end_minute: int
    capacity: int
    booked: int
    available: bool


def build_slots_for_coach(
    session: Session,
    coach_id: int,
    date: str,
    default_slot_minutes: int = 60,
) -> List[Slot]:
    day: date_type = parse_ymd(date)

    exceptions = session.exec(
        select(AvailabilityException).where(
            AvailabilityException.coach_id == coach_id,
            AvailabilityException.date == date,
        )
    ).all()

    if exceptions:
        segments = [
            (ex.start_minute, ex.end_minute, default_slot_minutes, ex.capacity, ex.enabled)
            for ex in exceptions
        ]
    else:
        weekday = day.weekday()
        rules = session.exec(
            select(AvailabilityRule).where(
                AvailabilityRule.coach_id == coach_id,
                AvailabilityRule.weekday == weekday,
            )
        ).all()
        segments = [
            (r.start_minute, r.end_minute, r.slot_minutes, r.capacity, r.enabled) for r in rules
        ]

    slots: List[Slot] = []
    desired_starts: List[int] = []
    for start_minute, end_minute, slot_minutes, capacity, enabled in segments:
        if not enabled:
            continue
        if slot_minutes <= 0 or capacity <= 0:
            continue
        last_start = end_minute - slot_minutes
        for s in range(start_minute, last_start + 1, slot_minutes):
            desired_starts.append(s)

    if not desired_starts:
        return []

    active_statuses = {BookingStatus.pending, BookingStatus.confirmed}
    rows = session.exec(
        select(Booking.start_minute, func.count(Booking.id))
        .where(
            Booking.coach_id == coach_id,
            Booking.date == date,
            Booking.start_minute.in_(desired_starts),
            Booking.status.in_(active_statuses),
        )
        .group_by(Booking.start_minute)
    ).all()
    booked_map: Dict[int, int] = {int(start): int(cnt) for start, cnt in rows}

    for start_minute, end_minute, slot_minutes, capacity, enabled in segments:
        if not enabled:
            continue
        if slot_minutes <= 0 or capacity <= 0:
            continue
        last_start = end_minute - slot_minutes
        for s in range(start_minute, last_start + 1, slot_minutes):
            booked = booked_map.get(s, 0)
            slots.append(
                Slot(
                    date=date,
                    start_minute=s,
                    end_minute=s + slot_minutes,
                    capacity=capacity,
                    booked=booked,
                    available=booked < capacity,
                )
            )

    slots.sort(key=lambda x: x.start_minute)
    return slots
