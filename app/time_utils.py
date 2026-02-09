from __future__ import annotations

from datetime import date as date_type
from datetime import datetime


def parse_ymd(value: str) -> date_type:
    return datetime.strptime(value, "%Y-%m-%d").date()


def hm_to_minute(value: str) -> int:
    hour_str, minute_str = value.split(":")
    return int(hour_str) * 60 + int(minute_str)


def minute_to_hm(value: int) -> str:
    hour = value // 60
    minute = value % 60
    return f"{hour:02d}:{minute:02d}"


WEEKDAY_LABELS = ["周一", "周二", "周三", "周四", "周五", "周六", "周日"]


def weekday_label(weekday: int) -> str:
    if 0 <= weekday <= 6:
        return WEEKDAY_LABELS[weekday]
    return str(weekday)
