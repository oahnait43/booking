from datetime import date as date_type
from typing import Optional
from urllib.parse import quote

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.responses import JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from app.auth import (
    authenticate_user,
    ensure_bootstrap_admin,
    get_current_user,
    hash_password,
    require_roles,
)
from app.db import create_db_and_tables, engine, get_session
from app.models import (
    AvailabilityException,
    AvailabilityRule,
    Booking,
    BookingStatus,
    Coach,
    Member,
    User,
    UserRole,
)
from app.settings import settings
from app.services.availability import build_slots_for_coach
from app.services.bookings import (
    BookingError,
    cancel_booking,
    confirm_booking,
    create_booking,
    get_coach_by_user_id,
    get_member_by_user_id,
    reject_booking,
)
from app.time_utils import hm_to_minute, minute_to_hm, parse_ymd, weekday_label


app = FastAPI()
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key,
    same_site="lax",
    https_only=settings.cookie_secure,
)

app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

@app.exception_handler(HTTPException)
def http_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code == 401 and request.method == "GET":
        return RedirectResponse(url="/login", status_code=302)
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.on_event("startup")
def on_startup() -> None:
    create_db_and_tables()
    with Session(engine) as session:
        ensure_bootstrap_admin(
            session=session,
            username=settings.bootstrap_admin_username,
            password=settings.bootstrap_admin_password,
        )


@app.get("/")
def root(request: Request):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    return RedirectResponse(url="/me", status_code=302)


@app.get("/health")
def health():
    return {"ok": True}

@app.get("/api/coaches")
def api_list_coaches(
    user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    coaches = session.exec(select(Coach).order_by(Coach.display_name)).all()
    return [{"id": c.id, "display_name": c.display_name} for c in coaches]


@app.get("/api/coaches/{coach_id}/availability")
def api_coach_availability(
    coach_id: int,
    date: str,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    try:
        parse_ymd(date)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format")
    slots = build_slots_for_coach(
        session=session,
        coach_id=coach_id,
        date=date,
        default_slot_minutes=settings.default_slot_minutes,
    )
    return [
        {
            "date": s.date,
            "start_minute": s.start_minute,
            "end_minute": s.end_minute,
            "start_hm": minute_to_hm(s.start_minute),
            "end_hm": minute_to_hm(s.end_minute),
            "capacity": s.capacity,
            "booked": s.booked,
            "available": s.available,
        }
        for s in slots
    ]

@app.post("/api/bookings")
def api_create_booking(
    request: Request,
    coach_id: int = Form(...),
    date: str = Form(...),
    start_minute: int = Form(...),
    user: User = Depends(require_roles([UserRole.member])),
    session: Session = Depends(get_session),
):
    member = get_member_by_user_id(session=session, user_id=user.id)
    if not member:
        raise HTTPException(status_code=400, detail="Member profile not found")
    try:
        booking = create_booking(
            session=session,
            member_id=member.id,
            coach_id=coach_id,
            date=date,
            start_minute=start_minute,
        )
    except BookingError as e:
        raise HTTPException(status_code=400, detail=e.message)
    return {
        "id": booking.id,
        "coach_id": booking.coach_id,
        "member_id": booking.member_id,
        "date": booking.date,
        "start_minute": booking.start_minute,
        "end_minute": booking.end_minute,
        "status": booking.status,
    }


@app.post("/api/bookings/{booking_id}/cancel")
def api_cancel_booking(
    booking_id: int,
    user: User = Depends(require_roles([UserRole.member])),
    session: Session = Depends(get_session),
):
    member = get_member_by_user_id(session=session, user_id=user.id)
    if not member:
        raise HTTPException(status_code=400, detail="Member profile not found")
    try:
        booking = cancel_booking(session=session, booking_id=booking_id, member_id=member.id)
    except BookingError as e:
        raise HTTPException(status_code=400, detail=e.message)
    return {"id": booking.id, "status": booking.status}


@app.get("/login")
def login_page(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse(url="/me", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    session: Session = Depends(get_session),
):
    user = authenticate_user(session=session, username=username, password=password)
    if not user:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "用户名或密码错误"},
            status_code=400,
        )
    request.session["user_id"] = user.id
    return RedirectResponse(url="/me", status_code=302)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)


@app.get("/me")
def me(user: User = Depends(get_current_user)):
    if user.role == UserRole.member:
        return RedirectResponse(url="/member", status_code=302)
    if user.role == UserRole.coach:
        return RedirectResponse(url="/coach", status_code=302)
    if user.role in {UserRole.admin, UserRole.frontdesk}:
        return RedirectResponse(url="/admin", status_code=302)
    return RedirectResponse(url="/login", status_code=302)


@app.get("/member")
def member_home(
    request: Request,
    user: User = Depends(require_roles([UserRole.member])),
    session: Session = Depends(get_session),
    coach_id: Optional[int] = None,
    date: Optional[str] = None,
    msg: Optional[str] = None,
):
    member = get_member_by_user_id(session=session, user_id=user.id)
    if not member:
        raise HTTPException(status_code=400, detail="Member profile not found")

    coaches = session.exec(select(Coach).order_by(Coach.display_name)).all()
    selected_date = date or date_type.today().strftime("%Y-%m-%d")
    selected_coach_id = coach_id or (coaches[0].id if coaches else None)

    slots = (
        build_slots_for_coach(
            session=session,
            coach_id=selected_coach_id,
            date=selected_date,
            default_slot_minutes=settings.default_slot_minutes,
        )
        if selected_coach_id
        else []
    )

    return templates.TemplateResponse(
        "member_home.html",
        {
            "request": request,
            "user": user,
            "coaches": coaches,
            "selected_date": selected_date,
            "selected_coach_id": selected_coach_id,
            "slots": slots,
            "minute_to_hm": minute_to_hm,
            "msg": msg,
        },
    )


@app.post("/member/book")
def member_book(
    request: Request,
    coach_id: int = Form(...),
    date: str = Form(...),
    start_minute: int = Form(...),
    user: User = Depends(require_roles([UserRole.member])),
    session: Session = Depends(get_session),
):
    member = get_member_by_user_id(session=session, user_id=user.id)
    if not member:
        raise HTTPException(status_code=400, detail="Member profile not found")
    try:
        create_booking(
            session=session,
            member_id=member.id,
            coach_id=coach_id,
            date=date,
            start_minute=start_minute,
        )
    except BookingError as e:
        return RedirectResponse(
            url=f"/member?coach_id={coach_id}&date={date}&msg={quote(e.message)}",
            status_code=302,
        )
    return RedirectResponse(
        url=f"/member/bookings?msg={quote('预约已提交，等待教练确认')}",
        status_code=302,
    )


@app.get("/member/bookings")
def member_bookings(
    request: Request,
    user: User = Depends(require_roles([UserRole.member])),
    session: Session = Depends(get_session),
    msg: Optional[str] = None,
):
    member = get_member_by_user_id(session=session, user_id=user.id)
    if not member:
        raise HTTPException(status_code=400, detail="Member profile not found")

    rows = session.exec(
        select(Booking, Coach)
        .join(Coach, Coach.id == Booking.coach_id)
        .where(Booking.member_id == member.id)
        .order_by(Booking.date.desc(), Booking.start_minute.desc())
    ).all()
    items = [
        {
            "booking": booking,
            "coach": coach,
            "start_hm": minute_to_hm(booking.start_minute),
            "end_hm": minute_to_hm(booking.end_minute),
        }
        for booking, coach in rows
    ]

    return templates.TemplateResponse(
        "member_bookings.html",
        {"request": request, "user": user, "items": items, "msg": msg},
    )


@app.post("/member/bookings/{booking_id}/cancel")
def member_cancel_booking(
    booking_id: int,
    user: User = Depends(require_roles([UserRole.member])),
    session: Session = Depends(get_session),
):
    member = get_member_by_user_id(session=session, user_id=user.id)
    if not member:
        raise HTTPException(status_code=400, detail="Member profile not found")
    try:
        cancel_booking(session=session, booking_id=booking_id, member_id=member.id)
    except BookingError as e:
        return RedirectResponse(url=f"/member/bookings?msg={quote(e.message)}", status_code=302)
    return RedirectResponse(
        url=f"/member/bookings?msg={quote('已取消预约')}",
        status_code=302,
    )


@app.get("/coach")
def coach_home(
    request: Request,
    user: User = Depends(require_roles([UserRole.coach])),
    session: Session = Depends(get_session),
    date: Optional[str] = None,
    msg: Optional[str] = None,
):
    coach = get_coach_by_user_id(session=session, user_id=user.id)
    if not coach:
        raise HTTPException(status_code=400, detail="Coach profile not found")

    selected_date = date or date_type.today().strftime("%Y-%m-%d")

    rows = session.exec(
        select(Booking, Member)
        .join(Member, Member.id == Booking.member_id)
        .where(Booking.coach_id == coach.id, Booking.date == selected_date)
        .order_by(Booking.start_minute.asc())
    ).all()

    items = [
        {
            "booking": booking,
            "member": member,
            "start_hm": minute_to_hm(booking.start_minute),
            "end_hm": minute_to_hm(booking.end_minute),
        }
        for booking, member in rows
    ]

    return templates.TemplateResponse(
        "coach_home.html",
        {
            "request": request,
            "user": user,
            "coach": coach,
            "selected_date": selected_date,
            "items": items,
            "msg": msg,
            "BookingStatus": BookingStatus,
        },
    )


@app.post("/coach/bookings/{booking_id}/confirm")
def coach_confirm(
    booking_id: int,
    user: User = Depends(require_roles([UserRole.coach])),
    session: Session = Depends(get_session),
):
    coach = get_coach_by_user_id(session=session, user_id=user.id)
    if not coach:
        raise HTTPException(status_code=400, detail="Coach profile not found")
    try:
        confirm_booking(session=session, booking_id=booking_id, coach_id=coach.id)
    except BookingError as e:
        return RedirectResponse(url=f"/coach?msg={quote(e.message)}", status_code=302)
    return RedirectResponse(url=f"/coach?msg={quote('已确认预约')}", status_code=302)


@app.post("/coach/bookings/{booking_id}/reject")
def coach_reject(
    booking_id: int,
    decision_note: str = Form(""),
    user: User = Depends(require_roles([UserRole.coach])),
    session: Session = Depends(get_session),
):
    coach = get_coach_by_user_id(session=session, user_id=user.id)
    if not coach:
        raise HTTPException(status_code=400, detail="Coach profile not found")
    try:
        reject_booking(
            session=session,
            booking_id=booking_id,
            coach_id=coach.id,
            decision_note=decision_note.strip() or None,
        )
    except BookingError as e:
        return RedirectResponse(url=f"/coach?msg={quote(e.message)}", status_code=302)
    return RedirectResponse(url=f"/coach?msg={quote('已拒绝预约')}", status_code=302)


@app.get("/admin")
def admin_home(
    request: Request,
    user: User = Depends(require_roles([UserRole.admin, UserRole.frontdesk])),
    msg: Optional[str] = None,
):
    return templates.TemplateResponse(
        "admin_home.html",
        {"request": request, "user": user, "msg": msg},
    )


@app.get("/admin/users")
def admin_users(
    request: Request,
    user: User = Depends(require_roles([UserRole.admin, UserRole.frontdesk])),
    session: Session = Depends(get_session),
    msg: Optional[str] = None,
):
    users = session.exec(select(User).order_by(User.created_at.desc())).all()
    return templates.TemplateResponse(
        "admin_users.html",
        {"request": request, "user": user, "users": users, "msg": msg, "UserRole": UserRole},
    )


@app.post("/admin/users/create")
def admin_create_user(
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    display_name: str = Form(""),
    user: User = Depends(require_roles([UserRole.admin, UserRole.frontdesk])),
    session: Session = Depends(get_session),
):
    try:
        role_enum = UserRole(role)
    except ValueError:
        return RedirectResponse(url=f"/admin/users?msg={quote('角色无效')}", status_code=302)

    new_user = User(
        username=username.strip(),
        password_hash=hash_password(password),
        role=role_enum,
        is_active=True,
    )
    session.add(new_user)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        return RedirectResponse(url=f"/admin/users?msg={quote('用户名已存在')}", status_code=302)
    session.refresh(new_user)

    if role_enum == UserRole.member:
        profile = Member(user_id=new_user.id, display_name=display_name.strip() or username.strip())
        session.add(profile)
        session.commit()
    if role_enum == UserRole.coach:
        profile = Coach(user_id=new_user.id, display_name=display_name.strip() or username.strip())
        session.add(profile)
        session.commit()

    return RedirectResponse(url=f"/admin/users?msg={quote('已创建用户')}", status_code=302)


@app.post("/admin/users/{target_user_id}/toggle")
def admin_toggle_user(
    target_user_id: int,
    user: User = Depends(require_roles([UserRole.admin, UserRole.frontdesk])),
    session: Session = Depends(get_session),
):
    target = session.get(User, target_user_id)
    if not target:
        return RedirectResponse(url=f"/admin/users?msg={quote('用户不存在')}", status_code=302)
    target.is_active = not target.is_active
    session.add(target)
    session.commit()
    return RedirectResponse(url=f"/admin/users?msg={quote('已更新状态')}", status_code=302)


@app.post("/admin/users/{target_user_id}/reset_password")
def admin_reset_password(
    target_user_id: int,
    new_password: str = Form(...),
    user: User = Depends(require_roles([UserRole.admin, UserRole.frontdesk])),
    session: Session = Depends(get_session),
):
    target = session.get(User, target_user_id)
    if not target:
        return RedirectResponse(url=f"/admin/users?msg={quote('用户不存在')}", status_code=302)
    target.password_hash = hash_password(new_password)
    session.add(target)
    session.commit()
    return RedirectResponse(url=f"/admin/users?msg={quote('已重置密码')}", status_code=302)


@app.get("/admin/schedule")
def admin_schedule(
    request: Request,
    user: User = Depends(require_roles([UserRole.admin, UserRole.frontdesk])),
    session: Session = Depends(get_session),
    coach_id: Optional[int] = None,
    msg: Optional[str] = None,
):
    coaches = session.exec(select(Coach).order_by(Coach.display_name)).all()
    selected_coach_id = coach_id or (coaches[0].id if coaches else None)

    rules = (
        session.exec(
            select(AvailabilityRule)
            .where(AvailabilityRule.coach_id == selected_coach_id)
            .order_by(AvailabilityRule.weekday.asc(), AvailabilityRule.start_minute.asc())
        ).all()
        if selected_coach_id
        else []
    )
    exceptions = (
        session.exec(
            select(AvailabilityException)
            .where(AvailabilityException.coach_id == selected_coach_id)
            .order_by(AvailabilityException.date.desc(), AvailabilityException.start_minute.asc())
        ).all()
        if selected_coach_id
        else []
    )

    return templates.TemplateResponse(
        "admin_schedule.html",
        {
            "request": request,
            "user": user,
            "coaches": coaches,
            "selected_coach_id": selected_coach_id,
            "rules": rules,
            "exceptions": exceptions,
            "minute_to_hm": minute_to_hm,
            "weekday_label": weekday_label,
            "msg": msg,
        },
    )


@app.post("/admin/schedule/rules/create")
def admin_create_rule(
    coach_id: int = Form(...),
    weekday: int = Form(...),
    start_hm: str = Form(...),
    end_hm: str = Form(...),
    slot_minutes: int = Form(...),
    capacity: int = Form(1),
    enabled: bool = Form(False),
    user: User = Depends(require_roles([UserRole.admin, UserRole.frontdesk])),
    session: Session = Depends(get_session),
):
    rule = AvailabilityRule(
        coach_id=coach_id,
        weekday=weekday,
        start_minute=hm_to_minute(start_hm),
        end_minute=hm_to_minute(end_hm),
        slot_minutes=slot_minutes,
        capacity=capacity,
        enabled=enabled,
    )
    session.add(rule)
    session.commit()
    return RedirectResponse(
        url=f"/admin/schedule?coach_id={coach_id}&msg={quote('已添加规则')}", status_code=302
    )


@app.post("/admin/schedule/rules/{rule_id}/toggle")
def admin_toggle_rule(
    rule_id: int,
    coach_id: int = Form(...),
    user: User = Depends(require_roles([UserRole.admin, UserRole.frontdesk])),
    session: Session = Depends(get_session),
):
    rule = session.get(AvailabilityRule, rule_id)
    if not rule:
        return RedirectResponse(
            url=f"/admin/schedule?coach_id={coach_id}&msg={quote('规则不存在')}",
            status_code=302,
        )
    rule.enabled = not rule.enabled
    session.add(rule)
    session.commit()
    return RedirectResponse(
        url=f"/admin/schedule?coach_id={coach_id}&msg={quote('已更新规则')}",
        status_code=302,
    )


@app.post("/admin/schedule/rules/{rule_id}/delete")
def admin_delete_rule(
    rule_id: int,
    coach_id: int = Form(...),
    user: User = Depends(require_roles([UserRole.admin, UserRole.frontdesk])),
    session: Session = Depends(get_session),
):
    rule = session.get(AvailabilityRule, rule_id)
    if rule:
        session.delete(rule)
        session.commit()
    return RedirectResponse(
        url=f"/admin/schedule?coach_id={coach_id}&msg={quote('已删除规则')}",
        status_code=302,
    )


@app.post("/admin/schedule/exceptions/create")
def admin_create_exception(
    coach_id: int = Form(...),
    date: str = Form(...),
    start_hm: str = Form(...),
    end_hm: str = Form(...),
    capacity: int = Form(1),
    enabled: bool = Form(False),
    user: User = Depends(require_roles([UserRole.admin, UserRole.frontdesk])),
    session: Session = Depends(get_session),
):
    ex = AvailabilityException(
        coach_id=coach_id,
        date=date,
        start_minute=hm_to_minute(start_hm),
        end_minute=hm_to_minute(end_hm),
        capacity=capacity,
        enabled=enabled,
    )
    session.add(ex)
    session.commit()
    return RedirectResponse(
        url=f"/admin/schedule?coach_id={coach_id}&msg={quote('已添加例外')}", status_code=302
    )


@app.post("/admin/schedule/exceptions/{exception_id}/toggle")
def admin_toggle_exception(
    exception_id: int,
    coach_id: int = Form(...),
    user: User = Depends(require_roles([UserRole.admin, UserRole.frontdesk])),
    session: Session = Depends(get_session),
):
    ex = session.get(AvailabilityException, exception_id)
    if not ex:
        return RedirectResponse(
            url=f"/admin/schedule?coach_id={coach_id}&msg={quote('例外不存在')}",
            status_code=302,
        )
    ex.enabled = not ex.enabled
    session.add(ex)
    session.commit()
    return RedirectResponse(
        url=f"/admin/schedule?coach_id={coach_id}&msg={quote('已更新例外')}",
        status_code=302,
    )


@app.post("/admin/schedule/exceptions/{exception_id}/delete")
def admin_delete_exception(
    exception_id: int,
    coach_id: int = Form(...),
    user: User = Depends(require_roles([UserRole.admin, UserRole.frontdesk])),
    session: Session = Depends(get_session),
):
    ex = session.get(AvailabilityException, exception_id)
    if ex:
        session.delete(ex)
        session.commit()
    return RedirectResponse(
        url=f"/admin/schedule?coach_id={coach_id}&msg={quote('已删除例外')}",
        status_code=302,
    )


@app.get("/admin/bookings")
def admin_bookings(
    request: Request,
    user: User = Depends(require_roles([UserRole.admin, UserRole.frontdesk])),
    session: Session = Depends(get_session),
    date: Optional[str] = None,
    status: Optional[str] = None,
    coach_id: Optional[int] = None,
):
    coaches = session.exec(select(Coach).order_by(Coach.display_name)).all()

    stmt = (
        select(Booking, Coach, Member)
        .join(Coach, Coach.id == Booking.coach_id)
        .join(Member, Member.id == Booking.member_id)
        .order_by(Booking.created_at.desc())
    )
    if date:
        stmt = stmt.where(Booking.date == date)
    if status:
        try:
            status_enum = BookingStatus(status)
        except ValueError:
            status_enum = None
        if status_enum:
            stmt = stmt.where(Booking.status == status_enum)
    if coach_id:
        stmt = stmt.where(Booking.coach_id == coach_id)

    rows = session.exec(stmt).all()
    items = [
        {
            "booking": booking,
            "coach": coach,
            "member": member,
            "start_hm": minute_to_hm(booking.start_minute),
            "end_hm": minute_to_hm(booking.end_minute),
        }
        for booking, coach, member in rows
    ]

    return templates.TemplateResponse(
        "admin_bookings.html",
        {
            "request": request,
            "user": user,
            "coaches": coaches,
            "items": items,
            "date": date,
            "status": status,
            "coach_id": coach_id,
            "BookingStatus": BookingStatus,
        },
    )
