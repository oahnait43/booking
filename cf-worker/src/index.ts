import type { AvailabilityException, AvailabilityRule, Booking, Coach, Env, Member, User, UserRole } from "./types";
import { buildSlotsForCoach } from "./availability";
import { BookingError, cancelBooking, confirmBooking, createBooking, rejectBooking } from "./bookings";
import { hashPassword, signSession, verifyPassword, verifySession } from "./crypto";
import { badRequest, clearCookie, getCookie, html, json, readForm, redirect, setCookie } from "./http";
import {
  kvAppendIdToList,
  kvGetCoachByUserId,
  kvGetJson,
  kvGetMemberByUserId,
  kvGetUserByUsername,
  kvListAvailabilityExceptions,
  kvListAvailabilityRules,
  kvListBookingsByIds,
  kvListCoaches,
  kvListByPrefix,
  kvPutCoach,
  kvPutJson,
  kvPutMember,
  kvPutUser,
  keys,
} from "./kv";
import { hmToMinute, minuteToHm, parseYmd, weekdayLabel, weekdayForYmd } from "./time";
import { Router } from "./router";

type SessionPayload = { user_id: string; exp: number };

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function layout(params: { title: string; body: string }): string {
  const { title, body } = params;
  return `<!doctype html>
<html lang="zh-CN">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <script src="https://cdn.tailwindcss.com"></script>
    <title>${escapeHtml(title)}</title>
  </head>
  <body class="bg-slate-50 text-slate-900">
    <div class="mx-auto max-w-md px-4 py-6">
      ${body}
    </div>
  </body>
</html>`;
}

function infoBox(msg: string): string {
  return `<div class="mt-3 rounded-lg border bg-white p-3 text-sm text-slate-700">${escapeHtml(msg)}</div>`;
}

function cookieSecure(env: Env): boolean {
  return (env.COOKIE_SECURE ?? "false").toLowerCase() === "true";
}

function defaultSlotMinutes(env: Env): number {
  const v = Number(env.DEFAULT_SLOT_MINUTES ?? "60");
  return Number.isFinite(v) && v > 0 ? v : 60;
}

async function getCurrentUser(req: Request, env: Env): Promise<User | null> {
  const token = getCookie(req, "session");
  if (!token) return null;
  const payload = await verifySession<SessionPayload>(env, token);
  if (!payload) return null;
  if (Date.now() > payload.exp * 1000) return null;
  const user = await kvGetJson<User>(env.BOOKING_KV, keys.user(payload.user_id));
  if (!user || !user.is_active) return null;
  return user;
}

function hasRole(user: User, roles: UserRole[]): boolean {
  return roles.includes(user.role);
}

async function requireUser(req: Request, env: Env): Promise<User | Response> {
  const user = await getCurrentUser(req, env);
  if (!user) return redirect("/login", 302);
  return user;
}

async function requireRoles(req: Request, env: Env, roles: UserRole[]): Promise<User | Response> {
  const userOr = await requireUser(req, env);
  if (userOr instanceof Response) return userOr;
  if (!hasRole(userOr, roles)) return html(layout({ title: "无权限", body: infoBox("无权限") }), 403);
  return userOr;
}

let bootstrapPromise: Promise<void> | null = null;

async function ensureBootstrapAdmin(env: Env): Promise<void> {
  const username = env.BOOTSTRAP_ADMIN_USERNAME ?? "admin";
  const password = env.BOOTSTRAP_ADMIN_PASSWORD ?? "admin123";
  const existing = await kvGetUserByUsername(env.BOOKING_KV, username);
  if (existing) return;
  const user: User = {
    id: crypto.randomUUID(),
    username,
    password_hash: await hashPassword(password),
    role: "admin",
    is_active: true,
    created_at: new Date().toISOString(),
  };
  await kvPutUser(env.BOOKING_KV, user);
}

async function ensureBootstrapped(env: Env): Promise<void> {
  if (!bootstrapPromise) bootstrapPromise = ensureBootstrapAdmin(env);
  await bootstrapPromise;
}

async function renderLogin(req: Request, env: Env): Promise<Response> {
  const user = await getCurrentUser(req, env);
  if (user) return redirect("/me", 302);
  const url = new URL(req.url);
  const msg = url.searchParams.get("msg");
  const body = `
    <h1 class="text-xl font-semibold">登录</h1>
    ${msg ? infoBox(msg) : ""}
    <form method="post" action="/login" class="mt-4 space-y-3">
      <div>
        <label class="text-sm text-slate-600">用户名</label>
        <input name="username" class="mt-1 w-full rounded-lg border bg-white px-3 py-2" required />
      </div>
      <div>
        <label class="text-sm text-slate-600">密码</label>
        <input name="password" type="password" class="mt-1 w-full rounded-lg border bg-white px-3 py-2" required />
      </div>
      <button class="w-full rounded-lg bg-slate-900 px-3 py-2 text-white">登录</button>
    </form>
  `;
  return html(layout({ title: "登录", body }));
}

async function handleLogin(req: Request, env: Env): Promise<Response> {
  const form = await readForm(req);
  const username = (form.username ?? "").trim();
  const password = form.password ?? "";
  if (!username || !password) return redirect(`/login?msg=${encodeURIComponent("请输入用户名和密码")}`, 302);
  const user = await kvGetUserByUsername(env.BOOKING_KV, username);
  if (!user) return redirect(`/login?msg=${encodeURIComponent("用户名或密码错误")}`, 302);
  const ok = await verifyPassword(password, user.password_hash);
  if (!ok || !user.is_active) return redirect(`/login?msg=${encodeURIComponent("用户名或密码错误")}`, 302);

  const payload: SessionPayload = { user_id: user.id, exp: Math.floor(Date.now() / 1000) + 7 * 24 * 3600 };
  const token = await signSession(env, payload);
  const headers = new Headers({ location: "/me" });
  setCookie(headers, "session", token, { secure: cookieSecure(env), httpOnly: true, sameSite: "Lax", maxAge: 7 * 24 * 3600 });
  return new Response(null, { status: 302, headers });
}

async function handleLogout(env: Env): Promise<Response> {
  const headers = new Headers({ location: "/login" });
  clearCookie(headers, "session");
  return new Response(null, { status: 302, headers });
}

async function handleMe(req: Request, env: Env): Promise<Response> {
  const user = await getCurrentUser(req, env);
  if (!user) return redirect("/login", 302);
  if (user.role === "member") return redirect("/member", 302);
  if (user.role === "coach") return redirect("/coach", 302);
  if (user.role === "admin" || user.role === "frontdesk") return redirect("/admin", 302);
  return redirect("/login", 302);
}

async function renderMember(req: Request, env: Env): Promise<Response> {
  const userOr = await requireRoles(req, env, ["member"]);
  if (userOr instanceof Response) return userOr;
  const member = await kvGetMemberByUserId(env.BOOKING_KV, userOr.id);
  if (!member) return html(layout({ title: "会员", body: infoBox("Member profile not found") }), 400);

  const url = new URL(req.url);
  const msg = url.searchParams.get("msg");
  const date = url.searchParams.get("date") ?? new Date().toISOString().slice(0, 10);
  const coaches = await kvListCoaches(env.BOOKING_KV);
  const selectedCoachId = url.searchParams.get("coach_id") ?? coaches[0]?.id ?? "";

  const slots = selectedCoachId
    ? await buildSlotsForCoach(env.BOOKING_KV, selectedCoachId, date, defaultSlotMinutes(env))
    : [];

  const coachOptions = coaches
    .map(
      (c) =>
        `<option value="${escapeHtml(c.id)}" ${c.id === selectedCoachId ? "selected" : ""}>${escapeHtml(c.display_name)}</option>`,
    )
    .join("");

  const slotList =
    slots.length === 0
      ? `<div class="rounded-xl border bg-white p-4 text-sm text-slate-700">当天暂无可预约时间</div>`
      : slots
          .map((s) => {
            const right = s.available
              ? `<form method="post" action="/member/book">
                  <input type="hidden" name="coach_id" value="${escapeHtml(selectedCoachId)}" />
                  <input type="hidden" name="date" value="${escapeHtml(date)}" />
                  <input type="hidden" name="start_minute" value="${s.start_minute}" />
                  <button class="rounded-lg bg-emerald-600 px-3 py-2 text-sm text-white">预约</button>
                </form>`
              : `<span class="text-sm text-slate-400">已满</span>`;
            return `<div class="flex items-center justify-between rounded-xl border bg-white p-4">
              <div>
                <div class="text-sm font-medium">${minuteToHm(s.start_minute)} - ${minuteToHm(s.end_minute)}</div>
                <div class="mt-1 text-xs text-slate-500">容量 ${s.capacity} · 已约 ${s.booked}</div>
              </div>
              ${right}
            </div>`;
          })
          .join("");

  const body = `
    <div class="flex items-center justify-between">
      <h1 class="text-xl font-semibold">会员预约</h1>
      <a href="/logout" class="text-sm text-slate-600 underline">退出</a>
    </div>
    ${msg ? infoBox(msg) : ""}
    <a href="/member/bookings" class="mt-3 inline-block text-sm text-slate-600 underline">我的预约</a>
    <form method="get" action="/member" class="mt-4 space-y-3 rounded-xl border bg-white p-4">
      <div>
        <label class="text-sm text-slate-600">选择教练</label>
        <select name="coach_id" class="mt-1 w-full rounded-lg border bg-white px-3 py-2">${coachOptions}</select>
      </div>
      <div>
        <label class="text-sm text-slate-600">日期</label>
        <input name="date" type="date" value="${escapeHtml(date)}" class="mt-1 w-full rounded-lg border bg-white px-3 py-2" />
      </div>
      <button class="w-full rounded-lg bg-slate-900 px-3 py-2 text-white">查看可预约时间</button>
    </form>
    <div class="mt-4 space-y-2">${slotList}</div>
  `;
  return html(layout({ title: "会员预约", body }));
}

async function handleMemberBook(req: Request, env: Env): Promise<Response> {
  const userOr = await requireRoles(req, env, ["member"]);
  if (userOr instanceof Response) return userOr;
  const member = await kvGetMemberByUserId(env.BOOKING_KV, userOr.id);
  if (!member) return redirect(`/member?msg=${encodeURIComponent("Member profile not found")}`, 302);

  const form = await readForm(req);
  const coachId = form.coach_id ?? "";
  const date = form.date ?? "";
  const startMinute = Number(form.start_minute ?? "");
  try {
    await createBooking({
      kv: env.BOOKING_KV,
      memberId: member.id,
      coachId,
      date,
      startMinute,
      defaultSlotMinutes: defaultSlotMinutes(env),
    });
  } catch (e) {
    const msg = e instanceof BookingError ? e.message : "预约失败";
    return redirect(`/member?coach_id=${encodeURIComponent(coachId)}&date=${encodeURIComponent(date)}&msg=${encodeURIComponent(msg)}`, 302);
  }
  return redirect(`/member/bookings?msg=${encodeURIComponent("预约已提交，等待教练确认")}`, 302);
}

async function renderMemberBookings(req: Request, env: Env): Promise<Response> {
  const userOr = await requireRoles(req, env, ["member"]);
  if (userOr instanceof Response) return userOr;
  const member = await kvGetMemberByUserId(env.BOOKING_KV, userOr.id);
  if (!member) return html(layout({ title: "我的预约", body: infoBox("Member profile not found") }), 400);

  const url = new URL(req.url);
  const msg = url.searchParams.get("msg");
  const ids = ((await env.BOOKING_KV.get(keys.bookingIdsByMember(member.id), "json")) as string[] | null) ?? [];
  const bookings = await kvListBookingsByIds(env.BOOKING_KV, ids);
  bookings.sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : b.start_minute - a.start_minute));

  const coachCache = new Map<string, Coach>();
  const rows = await Promise.all(
    bookings.map(async (b) => {
      const cached = coachCache.get(b.coach_id);
      const coach = cached ?? (await kvGetJson<Coach>(env.BOOKING_KV, keys.coach(b.coach_id)));
      if (coach) coachCache.set(b.coach_id, coach);
      return { booking: b, coach };
    }),
  );

  const list =
    rows.length === 0
      ? `<div class="rounded-xl border bg-white p-4 text-sm text-slate-700">暂无预约记录</div>`
      : rows
          .map(({ booking, coach }) => {
            const canCancel = booking.status === "pending" || booking.status === "confirmed";
            const cancelForm = canCancel
              ? `<form method="post" action="/member/bookings/${escapeHtml(booking.id)}/cancel" class="mt-3">
                  <button class="rounded-lg border px-3 py-2 text-sm">取消预约</button>
                </form>`
              : "";
            const note = booking.decision_note ? `<div class="mt-2 text-xs text-slate-500">备注：${escapeHtml(booking.decision_note)}</div>` : "";
            return `<div class="rounded-xl border bg-white p-4">
              <div class="flex items-center justify-between">
                <div>
                  <div class="text-sm font-medium">${escapeHtml(booking.date)} · ${minuteToHm(booking.start_minute)} - ${minuteToHm(booking.end_minute)}</div>
                  <div class="mt-1 text-xs text-slate-500">教练：${escapeHtml(coach?.display_name ?? booking.coach_id)}</div>
                </div>
                <div class="text-xs text-slate-600">${escapeHtml(booking.status)}</div>
              </div>
              ${note}
              ${cancelForm}
            </div>`;
          })
          .join("");

  const body = `
    <div class="flex items-center justify-between">
      <h1 class="text-xl font-semibold">我的预约</h1>
      <a href="/logout" class="text-sm text-slate-600 underline">退出</a>
    </div>
    ${msg ? infoBox(msg) : ""}
    <a href="/member" class="mt-3 inline-block text-sm text-slate-600 underline">返回预约</a>
    <div class="mt-4 space-y-2">${list}</div>
  `;
  return html(layout({ title: "我的预约", body }));
}

async function handleMemberCancel(req: Request, env: Env, bookingId: string): Promise<Response> {
  const userOr = await requireRoles(req, env, ["member"]);
  if (userOr instanceof Response) return userOr;
  const member = await kvGetMemberByUserId(env.BOOKING_KV, userOr.id);
  if (!member) return redirect(`/member/bookings?msg=${encodeURIComponent("Member profile not found")}`, 302);
  try {
    await cancelBooking(env.BOOKING_KV, bookingId, member.id);
  } catch (e) {
    const msg = e instanceof BookingError ? e.message : "取消失败";
    return redirect(`/member/bookings?msg=${encodeURIComponent(msg)}`, 302);
  }
  return redirect(`/member/bookings?msg=${encodeURIComponent("已取消预约")}`, 302);
}

async function renderCoach(req: Request, env: Env): Promise<Response> {
  const userOr = await requireRoles(req, env, ["coach"]);
  if (userOr instanceof Response) return userOr;
  const coach = await kvGetCoachByUserId(env.BOOKING_KV, userOr.id);
  if (!coach) return html(layout({ title: "教练", body: infoBox("Coach profile not found") }), 400);

  const url = new URL(req.url);
  const msg = url.searchParams.get("msg");
  const date = url.searchParams.get("date") ?? new Date().toISOString().slice(0, 10);

  const bookingIds = ((await env.BOOKING_KV.get(keys.bookingIdsByCoachDate(coach.id, date), "json")) as string[] | null) ?? [];
  const bookings = await kvListBookingsByIds(env.BOOKING_KV, bookingIds);
  bookings.sort((a, b) => a.start_minute - b.start_minute);

  const memberCache = new Map<string, Member>();
  const items = await Promise.all(
    bookings.map(async (b) => {
      const cached = memberCache.get(b.member_id);
      const member = cached ?? (await kvGetJson<Member>(env.BOOKING_KV, keys.member(b.member_id)));
      if (member) memberCache.set(b.member_id, member);
      return { booking: b, member };
    }),
  );

  const list =
    items.length === 0
      ? `<div class="rounded-xl border bg-white p-4 text-sm text-slate-700">当天暂无预约</div>`
      : items
          .map(({ booking, member }) => {
            const note = booking.decision_note ? `<div class="mt-2 text-xs text-slate-500">备注：${escapeHtml(booking.decision_note)}</div>` : "";
            const actions =
              booking.status === "pending"
                ? `<div class="mt-3 flex gap-2">
                    <form method="post" action="/coach/bookings/${escapeHtml(booking.id)}/confirm" class="flex-1">
                      <button class="w-full rounded-lg bg-emerald-600 px-3 py-2 text-sm text-white">确认</button>
                    </form>
                    <form method="post" action="/coach/bookings/${escapeHtml(booking.id)}/reject" class="flex-1">
                      <input name="decision_note" placeholder="拒绝原因（可选）" class="mb-2 w-full rounded-lg border bg-white px-3 py-2 text-sm" />
                      <button class="w-full rounded-lg bg-rose-600 px-3 py-2 text-sm text-white">拒绝</button>
                    </form>
                  </div>`
                : "";
            return `<div class="rounded-xl border bg-white p-4">
              <div class="flex items-center justify-between">
                <div>
                  <div class="text-sm font-medium">${minuteToHm(booking.start_minute)} - ${minuteToHm(booking.end_minute)}</div>
                  <div class="mt-1 text-xs text-slate-500">会员：${escapeHtml(member?.display_name ?? booking.member_id)}</div>
                </div>
                <div class="text-xs text-slate-600">${escapeHtml(booking.status)}</div>
              </div>
              ${actions}
              ${note}
            </div>`;
          })
          .join("");

  const body = `
    <div class="flex items-center justify-between">
      <h1 class="text-xl font-semibold">教练确认</h1>
      <a href="/logout" class="text-sm text-slate-600 underline">退出</a>
    </div>
    ${msg ? infoBox(msg) : ""}
    <form method="get" action="/coach" class="mt-4 space-y-3 rounded-xl border bg-white p-4">
      <div>
        <label class="text-sm text-slate-600">日期</label>
        <input name="date" type="date" value="${escapeHtml(date)}" class="mt-1 w-full rounded-lg border bg-white px-3 py-2" />
      </div>
      <button class="w-full rounded-lg bg-slate-900 px-3 py-2 text-white">查看预约</button>
    </form>
    <div class="mt-4 space-y-2">${list}</div>
  `;
  return html(layout({ title: "教练确认", body }));
}

async function handleCoachConfirm(req: Request, env: Env, bookingId: string): Promise<Response> {
  const userOr = await requireRoles(req, env, ["coach"]);
  if (userOr instanceof Response) return userOr;
  const coach = await kvGetCoachByUserId(env.BOOKING_KV, userOr.id);
  if (!coach) return redirect(`/coach?msg=${encodeURIComponent("Coach profile not found")}`, 302);
  try {
    await confirmBooking(env.BOOKING_KV, bookingId, coach.id);
  } catch (e) {
    const msg = e instanceof BookingError ? e.message : "操作失败";
    return redirect(`/coach?msg=${encodeURIComponent(msg)}`, 302);
  }
  return redirect(`/coach?msg=${encodeURIComponent("已确认预约")}`, 302);
}

async function handleCoachReject(req: Request, env: Env, bookingId: string): Promise<Response> {
  const userOr = await requireRoles(req, env, ["coach"]);
  if (userOr instanceof Response) return userOr;
  const coach = await kvGetCoachByUserId(env.BOOKING_KV, userOr.id);
  if (!coach) return redirect(`/coach?msg=${encodeURIComponent("Coach profile not found")}`, 302);
  const form = await readForm(req);
  const note = form.decision_note ?? "";
  try {
    await rejectBooking(env.BOOKING_KV, bookingId, coach.id, note);
  } catch (e) {
    const msg = e instanceof BookingError ? e.message : "操作失败";
    return redirect(`/coach?msg=${encodeURIComponent(msg)}`, 302);
  }
  return redirect(`/coach?msg=${encodeURIComponent("已拒绝预约")}`, 302);
}

async function renderAdmin(req: Request, env: Env): Promise<Response> {
  const userOr = await requireRoles(req, env, ["admin", "frontdesk"]);
  if (userOr instanceof Response) return userOr;
  const url = new URL(req.url);
  const msg = url.searchParams.get("msg");
  const body = `
    <div class="flex items-center justify-between">
      <h1 class="text-xl font-semibold">管理端</h1>
      <a href="/logout" class="text-sm text-slate-600 underline">退出</a>
    </div>
    ${msg ? infoBox(msg) : ""}
    <div class="mt-4 space-y-2">
      <a class="block rounded-xl border bg-white p-4" href="/admin/users">
        <div class="text-sm font-medium">用户管理</div>
        <div class="mt-1 text-xs text-slate-500">创建账号、重置密码、启用/禁用</div>
      </a>
      <a class="block rounded-xl border bg-white p-4" href="/admin/schedule">
        <div class="text-sm font-medium">时间配置</div>
        <div class="mt-1 text-xs text-slate-500">设置教练每周规则与日期例外、开关预约</div>
      </a>
      <a class="block rounded-xl border bg-white p-4" href="/admin/bookings">
        <div class="text-sm font-medium">预约查询</div>
        <div class="mt-1 text-xs text-slate-500">按日期/教练/状态筛选预约</div>
      </a>
    </div>
  `;
  return html(layout({ title: "管理端", body }));
}

async function renderAdminUsers(req: Request, env: Env): Promise<Response> {
  const userOr = await requireRoles(req, env, ["admin", "frontdesk"]);
  if (userOr instanceof Response) return userOr;
  const url = new URL(req.url);
  const msg = url.searchParams.get("msg");

  const userKeys = await kvListByPrefix(env.BOOKING_KV, "user:");
  const users: User[] = [];
  for (const k of userKeys) {
    const u = await kvGetJson<User>(env.BOOKING_KV, k);
    if (u) users.push(u);
  }
  users.sort((a, b) => (a.created_at < b.created_at ? 1 : -1));

  const rows = users
    .map(
      (u) => `<div class="rounded-xl border bg-white p-4">
        <div class="flex items-center justify-between">
          <div>
            <div class="text-sm font-medium">${escapeHtml(u.username)}</div>
            <div class="mt-1 text-xs text-slate-500">角色：${escapeHtml(u.role)} · 状态：${u.is_active ? "启用" : "禁用"}</div>
          </div>
          <form method="post" action="/admin/users/${escapeHtml(u.id)}/toggle">
            <button class="rounded-lg border px-3 py-2 text-sm">${u.is_active ? "禁用" : "启用"}</button>
          </form>
        </div>
        <form method="post" action="/admin/users/${escapeHtml(u.id)}/reset_password" class="mt-3 flex gap-2">
          <input name="new_password" type="password" placeholder="新密码" class="flex-1 rounded-lg border bg-white px-3 py-2 text-sm" required />
          <button class="rounded-lg bg-slate-900 px-3 py-2 text-sm text-white">重置</button>
        </form>
      </div>`,
    )
    .join("");

  const body = `
    <div class="flex items-center justify-between">
      <h1 class="text-xl font-semibold">用户管理</h1>
      <a href="/admin" class="text-sm text-slate-600 underline">返回</a>
    </div>
    ${msg ? infoBox(msg) : ""}
    <div class="mt-4 rounded-xl border bg-white p-4">
      <div class="text-sm font-medium">创建用户</div>
      <form method="post" action="/admin/users/create" class="mt-3 space-y-3">
        <div>
          <label class="text-sm text-slate-600">用户名</label>
          <input name="username" class="mt-1 w-full rounded-lg border bg-white px-3 py-2" required />
        </div>
        <div>
          <label class="text-sm text-slate-600">密码</label>
          <input name="password" type="password" class="mt-1 w-full rounded-lg border bg-white px-3 py-2" required />
        </div>
        <div>
          <label class="text-sm text-slate-600">角色</label>
          <select name="role" class="mt-1 w-full rounded-lg border bg-white px-3 py-2">
            <option value="member">member（会员）</option>
            <option value="coach">coach（教练）</option>
            <option value="frontdesk">frontdesk（前台）</option>
            <option value="admin">admin（管理员）</option>
          </select>
        </div>
        <div>
          <label class="text-sm text-slate-600">显示名（会员/教练可选）</label>
          <input name="display_name" class="mt-1 w-full rounded-lg border bg-white px-3 py-2" />
        </div>
        <button class="w-full rounded-lg bg-slate-900 px-3 py-2 text-white">创建</button>
      </form>
    </div>
    <div class="mt-4 space-y-2">${rows || `<div class="rounded-xl border bg-white p-4 text-sm text-slate-700">暂无用户</div>`}</div>
  `;
  return html(layout({ title: "用户管理", body }));
}

async function handleAdminCreateUser(req: Request, env: Env): Promise<Response> {
  const userOr = await requireRoles(req, env, ["admin", "frontdesk"]);
  if (userOr instanceof Response) return userOr;
  const form = await readForm(req);
  const username = (form.username ?? "").trim();
  const password = form.password ?? "";
  const role = (form.role ?? "").trim() as UserRole;
  const displayName = (form.display_name ?? "").trim();

  if (!username || !password) return redirect(`/admin/users?msg=${encodeURIComponent("用户名或密码不能为空")}`, 302);
  if (!["member", "coach", "frontdesk", "admin"].includes(role)) return redirect(`/admin/users?msg=${encodeURIComponent("角色无效")}`, 302);

  const exists = await kvGetUserByUsername(env.BOOKING_KV, username);
  if (exists) return redirect(`/admin/users?msg=${encodeURIComponent("用户名已存在")}`, 302);

  const newUser: User = {
    id: crypto.randomUUID(),
    username,
    password_hash: await hashPassword(password),
    role,
    is_active: true,
    created_at: new Date().toISOString(),
  };
  await kvPutUser(env.BOOKING_KV, newUser);

  if (role === "member") {
    const member: Member = { id: crypto.randomUUID(), user_id: newUser.id, display_name: displayName || username };
    await kvPutMember(env.BOOKING_KV, member);
  }
  if (role === "coach") {
    const coach: Coach = { id: crypto.randomUUID(), user_id: newUser.id, display_name: displayName || username };
    await kvPutCoach(env.BOOKING_KV, coach);
  }

  return redirect(`/admin/users?msg=${encodeURIComponent("已创建用户")}`, 302);
}

async function handleAdminToggleUser(req: Request, env: Env, targetUserId: string): Promise<Response> {
  const userOr = await requireRoles(req, env, ["admin", "frontdesk"]);
  if (userOr instanceof Response) return userOr;
  const target = await kvGetJson<User>(env.BOOKING_KV, keys.user(targetUserId));
  if (!target) return redirect(`/admin/users?msg=${encodeURIComponent("用户不存在")}`, 302);
  target.is_active = !target.is_active;
  await kvPutJson(env.BOOKING_KV, keys.user(target.id), target);
  return redirect(`/admin/users?msg=${encodeURIComponent("已更新状态")}`, 302);
}

async function handleAdminResetPassword(req: Request, env: Env, targetUserId: string): Promise<Response> {
  const userOr = await requireRoles(req, env, ["admin", "frontdesk"]);
  if (userOr instanceof Response) return userOr;
  const form = await readForm(req);
  const newPassword = form.new_password ?? "";
  if (!newPassword) return redirect(`/admin/users?msg=${encodeURIComponent("新密码不能为空")}`, 302);
  const target = await kvGetJson<User>(env.BOOKING_KV, keys.user(targetUserId));
  if (!target) return redirect(`/admin/users?msg=${encodeURIComponent("用户不存在")}`, 302);
  target.password_hash = await hashPassword(newPassword);
  await kvPutJson(env.BOOKING_KV, keys.user(target.id), target);
  return redirect(`/admin/users?msg=${encodeURIComponent("已重置密码")}`, 302);
}

async function renderAdminSchedule(req: Request, env: Env): Promise<Response> {
  const userOr = await requireRoles(req, env, ["admin", "frontdesk"]);
  if (userOr instanceof Response) return userOr;
  const url = new URL(req.url);
  const msg = url.searchParams.get("msg");
  const coachId = url.searchParams.get("coach_id") ?? "";

  const coaches = await kvListCoaches(env.BOOKING_KV);
  const selectedCoachId = coachId || coaches[0]?.id || "";
  const rulesAll = selectedCoachId ? await kvListAvailabilityRules(env.BOOKING_KV, selectedCoachId) : [];

  const today = new Date().toISOString().slice(0, 10);
  const exceptionDates = await kvListByPrefix(env.BOOKING_KV, `availEx:${selectedCoachId}:`);
  const dateSet = new Set<string>();
  for (const k of exceptionDates) {
    const parts = k.split(":");
    if (parts.length >= 3) dateSet.add(parts[2]);
  }
  const exDates = Array.from(dateSet).sort((a, b) => (a < b ? 1 : -1)).slice(0, 14);
  const exceptionsByDate: Record<string, AvailabilityException[]> = {};
  for (const d of exDates) {
    exceptionsByDate[d] = await kvListAvailabilityExceptions(env.BOOKING_KV, selectedCoachId, d);
  }

  const coachOptions = coaches
    .map(
      (c) =>
        `<option value="${escapeHtml(c.id)}" ${c.id === selectedCoachId ? "selected" : ""}>${escapeHtml(c.display_name)}</option>`,
    )
    .join("");

  const ruleRows =
    rulesAll.length === 0
      ? `<div class="rounded-xl border bg-white p-4 text-sm text-slate-700">暂无规则</div>`
      : rulesAll
          .map((r) => {
            return `<div class="rounded-xl border bg-white p-4">
              <div class="flex items-center justify-between">
                <div>
                  <div class="text-sm font-medium">${escapeHtml(weekdayLabel(r.weekday))} · ${minuteToHm(r.start_minute)} - ${minuteToHm(r.end_minute)}</div>
                  <div class="mt-1 text-xs text-slate-500">单节 ${r.slot_minutes} 分钟 · 容量 ${r.capacity} · ${r.enabled ? "启用" : "关闭"}</div>
                </div>
                <div class="flex gap-2">
                  <form method="post" action="/admin/schedule/rules/${escapeHtml(r.id)}/toggle">
                    <input type="hidden" name="coach_id" value="${escapeHtml(selectedCoachId)}" />
                    <button class="rounded-lg border px-3 py-2 text-sm">${r.enabled ? "关闭" : "开启"}</button>
                  </form>
                  <form method="post" action="/admin/schedule/rules/${escapeHtml(r.id)}/delete">
                    <input type="hidden" name="coach_id" value="${escapeHtml(selectedCoachId)}" />
                    <button class="rounded-lg border px-3 py-2 text-sm">删除</button>
                  </form>
                </div>
              </div>
            </div>`;
          })
          .join("");

  const exRows = exDates
    .flatMap((d) => exceptionsByDate[d].map((ex) => ({ d, ex })))
    .map(({ ex }) => {
      return `<div class="rounded-xl border bg-white p-4">
        <div class="flex items-center justify-between">
          <div>
            <div class="text-sm font-medium">${escapeHtml(ex.date)} · ${minuteToHm(ex.start_minute)} - ${minuteToHm(ex.end_minute)}</div>
            <div class="mt-1 text-xs text-slate-500">容量 ${ex.capacity} · ${ex.enabled ? "启用" : "关闭"}</div>
          </div>
          <div class="flex gap-2">
            <form method="post" action="/admin/schedule/exceptions/${escapeHtml(ex.id)}/toggle">
              <input type="hidden" name="coach_id" value="${escapeHtml(selectedCoachId)}" />
              <button class="rounded-lg border px-3 py-2 text-sm">${ex.enabled ? "关闭" : "开启"}</button>
            </form>
            <form method="post" action="/admin/schedule/exceptions/${escapeHtml(ex.id)}/delete">
              <input type="hidden" name="coach_id" value="${escapeHtml(selectedCoachId)}" />
              <button class="rounded-lg border px-3 py-2 text-sm">删除</button>
            </form>
          </div>
        </div>
      </div>`;
    })
    .join("");

  const body = `
    <div class="flex items-center justify-between">
      <h1 class="text-xl font-semibold">时间配置</h1>
      <a href="/admin" class="text-sm text-slate-600 underline">返回</a>
    </div>
    ${msg ? infoBox(msg) : ""}
    <form method="get" action="/admin/schedule" class="mt-4 space-y-3 rounded-xl border bg-white p-4">
      <div>
        <label class="text-sm text-slate-600">选择教练</label>
        <select name="coach_id" class="mt-1 w-full rounded-lg border bg-white px-3 py-2">${coachOptions}</select>
      </div>
      <button class="w-full rounded-lg bg-slate-900 px-3 py-2 text-white">切换</button>
    </form>
    ${!selectedCoachId ? infoBox("请先创建教练账号") : ""}
    ${
      selectedCoachId
        ? `<div class="mt-4 rounded-xl border bg-white p-4">
            <div class="text-sm font-medium">添加每周规则</div>
            <form method="post" action="/admin/schedule/rules/create" class="mt-3 space-y-3">
              <input type="hidden" name="coach_id" value="${escapeHtml(selectedCoachId)}" />
              <div>
                <label class="text-sm text-slate-600">星期</label>
                <select name="weekday" class="mt-1 w-full rounded-lg border bg-white px-3 py-2">
                  ${Array.from({ length: 7 })
                    .map((_, i) => `<option value="${i}">${escapeHtml(weekdayLabel(i))}</option>`)
                    .join("")}
                </select>
              </div>
              <div class="grid grid-cols-2 gap-2">
                <div>
                  <label class="text-sm text-slate-600">开始</label>
                  <input name="start_hm" value="08:00" class="mt-1 w-full rounded-lg border bg-white px-3 py-2" required />
                </div>
                <div>
                  <label class="text-sm text-slate-600">结束</label>
                  <input name="end_hm" value="20:00" class="mt-1 w-full rounded-lg border bg-white px-3 py-2" required />
                </div>
              </div>
              <div class="grid grid-cols-2 gap-2">
                <div>
                  <label class="text-sm text-slate-600">单节分钟</label>
                  <input name="slot_minutes" type="number" value="60" class="mt-1 w-full rounded-lg border bg-white px-3 py-2" required />
                </div>
                <div>
                  <label class="text-sm text-slate-600">容量</label>
                  <input name="capacity" type="number" value="1" class="mt-1 w-full rounded-lg border bg-white px-3 py-2" required />
                </div>
              </div>
              <label class="flex items-center gap-2 text-sm text-slate-700">
                <input type="checkbox" name="enabled" />
                启用
              </label>
              <button class="w-full rounded-lg bg-slate-900 px-3 py-2 text-white">添加规则</button>
            </form>
          </div>
          <div class="mt-4 space-y-2">${ruleRows}</div>
          <div class="mt-6 rounded-xl border bg-white p-4">
            <div class="text-sm font-medium">添加日期例外</div>
            <form method="post" action="/admin/schedule/exceptions/create" class="mt-3 space-y-3">
              <input type="hidden" name="coach_id" value="${escapeHtml(selectedCoachId)}" />
              <div>
                <label class="text-sm text-slate-600">日期</label>
                <input name="date" type="date" value="${escapeHtml(today)}" class="mt-1 w-full rounded-lg border bg-white px-3 py-2" required />
              </div>
              <div class="grid grid-cols-2 gap-2">
                <div>
                  <label class="text-sm text-slate-600">开始</label>
                  <input name="start_hm" value="08:00" class="mt-1 w-full rounded-lg border bg-white px-3 py-2" required />
                </div>
                <div>
                  <label class="text-sm text-slate-600">结束</label>
                  <input name="end_hm" value="20:00" class="mt-1 w-full rounded-lg border bg-white px-3 py-2" required />
                </div>
              </div>
              <div>
                <label class="text-sm text-slate-600">容量</label>
                <input name="capacity" type="number" value="1" class="mt-1 w-full rounded-lg border bg-white px-3 py-2" required />
              </div>
              <label class="flex items-center gap-2 text-sm text-slate-700">
                <input type="checkbox" name="enabled" />
                启用
              </label>
              <button class="w-full rounded-lg bg-slate-900 px-3 py-2 text-white">添加例外</button>
            </form>
          </div>
          <div class="mt-4 space-y-2">${exRows || `<div class="rounded-xl border bg-white p-4 text-sm text-slate-700">暂无例外</div>`}</div>`
        : ""
    }
  `;
  return html(layout({ title: "时间配置", body }));
}

async function handleAdminCreateRule(req: Request, env: Env): Promise<Response> {
  const userOr = await requireRoles(req, env, ["admin", "frontdesk"]);
  if (userOr instanceof Response) return userOr;
  const form = await readForm(req);
  const coachId = form.coach_id ?? "";
  const weekday = Number(form.weekday ?? "");
  const start = hmToMinute(form.start_hm ?? "");
  const end = hmToMinute(form.end_hm ?? "");
  const slotMinutes = Number(form.slot_minutes ?? "");
  const capacity = Number(form.capacity ?? "");
  const enabled = form.enabled === "on";
  if (!coachId || !Number.isFinite(weekday) || start === null || end === null) return redirect(`/admin/schedule?msg=${encodeURIComponent("参数错误")}`, 302);
  const rule: AvailabilityRule = {
    id: crypto.randomUUID(),
    coach_id: coachId,
    weekday,
    start_minute: start,
    end_minute: end,
    slot_minutes: slotMinutes,
    capacity,
    enabled,
  };
  await kvPutJson(env.BOOKING_KV, keys.availRule(coachId, rule.id), rule);
  return redirect(`/admin/schedule?coach_id=${encodeURIComponent(coachId)}&msg=${encodeURIComponent("已添加规则")}`, 302);
}

async function handleAdminToggleRule(req: Request, env: Env, ruleId: string): Promise<Response> {
  const userOr = await requireRoles(req, env, ["admin", "frontdesk"]);
  if (userOr instanceof Response) return userOr;
  const form = await readForm(req);
  const coachId = form.coach_id ?? "";
  if (!coachId) return redirect(`/admin/schedule?msg=${encodeURIComponent("参数错误")}`, 302);
  const key = keys.availRule(coachId, ruleId);
  const rule = await kvGetJson<AvailabilityRule>(env.BOOKING_KV, key);
  if (!rule) return redirect(`/admin/schedule?coach_id=${encodeURIComponent(coachId)}&msg=${encodeURIComponent("规则不存在")}`, 302);
  rule.enabled = !rule.enabled;
  await kvPutJson(env.BOOKING_KV, key, rule);
  return redirect(`/admin/schedule?coach_id=${encodeURIComponent(coachId)}&msg=${encodeURIComponent("已更新规则")}`, 302);
}

async function handleAdminDeleteRule(req: Request, env: Env, ruleId: string): Promise<Response> {
  const userOr = await requireRoles(req, env, ["admin", "frontdesk"]);
  if (userOr instanceof Response) return userOr;
  const form = await readForm(req);
  const coachId = form.coach_id ?? "";
  if (!coachId) return redirect(`/admin/schedule?msg=${encodeURIComponent("参数错误")}`, 302);
  await env.BOOKING_KV.delete(keys.availRule(coachId, ruleId));
  return redirect(`/admin/schedule?coach_id=${encodeURIComponent(coachId)}&msg=${encodeURIComponent("已删除规则")}`, 302);
}

async function handleAdminCreateException(req: Request, env: Env): Promise<Response> {
  const userOr = await requireRoles(req, env, ["admin", "frontdesk"]);
  if (userOr instanceof Response) return userOr;
  const form = await readForm(req);
  const coachId = form.coach_id ?? "";
  const date = form.date ?? "";
  const start = hmToMinute(form.start_hm ?? "");
  const end = hmToMinute(form.end_hm ?? "");
  const capacity = Number(form.capacity ?? "");
  const enabled = form.enabled === "on";
  if (!coachId || !parseYmd(date) || start === null || end === null) return redirect(`/admin/schedule?msg=${encodeURIComponent("参数错误")}`, 302);
  const ex: AvailabilityException = {
    id: crypto.randomUUID(),
    coach_id: coachId,
    date,
    start_minute: start,
    end_minute: end,
    capacity,
    enabled,
  };
  await kvPutJson(env.BOOKING_KV, keys.availEx(coachId, date, ex.id), ex);
  return redirect(`/admin/schedule?coach_id=${encodeURIComponent(coachId)}&msg=${encodeURIComponent("已添加例外")}`, 302);
}

async function handleAdminToggleException(req: Request, env: Env, exId: string): Promise<Response> {
  const userOr = await requireRoles(req, env, ["admin", "frontdesk"]);
  if (userOr instanceof Response) return userOr;
  const form = await readForm(req);
  const coachId = form.coach_id ?? "";
  if (!coachId) return redirect(`/admin/schedule?msg=${encodeURIComponent("参数错误")}`, 302);

  const keyMatches = (await kvListByPrefix(env.BOOKING_KV, `availEx:${coachId}:`)).filter((k) => k.endsWith(`:${exId}`));
  const key = keyMatches[0];
  if (!key) return redirect(`/admin/schedule?coach_id=${encodeURIComponent(coachId)}&msg=${encodeURIComponent("例外不存在")}`, 302);
  const ex = await kvGetJson<AvailabilityException>(env.BOOKING_KV, key);
  if (!ex) return redirect(`/admin/schedule?coach_id=${encodeURIComponent(coachId)}&msg=${encodeURIComponent("例外不存在")}`, 302);
  ex.enabled = !ex.enabled;
  await kvPutJson(env.BOOKING_KV, key, ex);
  return redirect(`/admin/schedule?coach_id=${encodeURIComponent(coachId)}&msg=${encodeURIComponent("已更新例外")}`, 302);
}

async function handleAdminDeleteException(req: Request, env: Env, exId: string): Promise<Response> {
  const userOr = await requireRoles(req, env, ["admin", "frontdesk"]);
  if (userOr instanceof Response) return userOr;
  const form = await readForm(req);
  const coachId = form.coach_id ?? "";
  if (!coachId) return redirect(`/admin/schedule?msg=${encodeURIComponent("参数错误")}`, 302);
  const keyMatches = (await kvListByPrefix(env.BOOKING_KV, `availEx:${coachId}:`)).filter((k) => k.endsWith(`:${exId}`));
  const key = keyMatches[0];
  if (key) await env.BOOKING_KV.delete(key);
  return redirect(`/admin/schedule?coach_id=${encodeURIComponent(coachId)}&msg=${encodeURIComponent("已删除例外")}`, 302);
}

async function renderAdminBookings(req: Request, env: Env): Promise<Response> {
  const userOr = await requireRoles(req, env, ["admin", "frontdesk"]);
  if (userOr instanceof Response) return userOr;
  const url = new URL(req.url);
  const date = url.searchParams.get("date") || undefined;
  const status = url.searchParams.get("status") || undefined;
  const coachId = url.searchParams.get("coach_id") || undefined;

  const coaches = await kvListCoaches(env.BOOKING_KV);
  const coachMap = new Map<string, Coach>(coaches.map((c) => [c.id, c]));

  const bookingKeys = await kvListByPrefix(env.BOOKING_KV, "booking:");
  const bookings: Booking[] = [];
  for (const k of bookingKeys) {
    const b = await kvGetJson<Booking>(env.BOOKING_KV, k);
    if (!b) continue;
    if (date && b.date !== date) continue;
    if (status && b.status !== status) continue;
    if (coachId && b.coach_id !== coachId) continue;
    bookings.push(b);
  }
  bookings.sort((a, b) => (a.created_at < b.created_at ? 1 : -1));

  const memberKeys = await kvListByPrefix(env.BOOKING_KV, "member:");
  const members: Member[] = [];
  for (const k of memberKeys) {
    const m = await kvGetJson<Member>(env.BOOKING_KV, k);
    if (m) members.push(m);
  }
  const memberMap = new Map<string, Member>(members.map((m) => [m.id, m]));

  const coachOptions = coaches
    .map(
      (c) =>
        `<option value="${escapeHtml(c.id)}" ${coachId && c.id === coachId ? "selected" : ""}>${escapeHtml(c.display_name)}</option>`,
    )
    .join("");

  const statusOptions = ["pending", "confirmed", "rejected", "cancelled"]
    .map((st) => `<option value="${st}" ${status && status === st ? "selected" : ""}>${st}</option>`)
    .join("");

  const list =
    bookings.length === 0
      ? `<div class="rounded-xl border bg-white p-4 text-sm text-slate-700">暂无符合条件的预约</div>`
      : bookings
          .map((b) => {
            const coach = coachMap.get(b.coach_id);
            const member = memberMap.get(b.member_id);
            const note = b.decision_note ? `<div class="mt-2 text-xs text-slate-500">备注：${escapeHtml(b.decision_note)}</div>` : "";
            return `<div class="rounded-xl border bg-white p-4">
              <div class="flex items-center justify-between">
                <div>
                  <div class="text-sm font-medium">${escapeHtml(b.date)} · ${minuteToHm(b.start_minute)} - ${minuteToHm(b.end_minute)}</div>
                  <div class="mt-1 text-xs text-slate-500">教练：${escapeHtml(coach?.display_name ?? b.coach_id)} · 会员：${escapeHtml(member?.display_name ?? b.member_id)}</div>
                </div>
                <div class="text-xs text-slate-600">${escapeHtml(b.status)}</div>
              </div>
              ${note}
            </div>`;
          })
          .join("");

  const body = `
    <div class="flex items-center justify-between">
      <h1 class="text-xl font-semibold">预约查询</h1>
      <a href="/admin" class="text-sm text-slate-600 underline">返回</a>
    </div>
    <form method="get" action="/admin/bookings" class="mt-4 space-y-3 rounded-xl border bg-white p-4">
      <div>
        <label class="text-sm text-slate-600">日期（可选）</label>
        <input name="date" type="date" value="${escapeHtml(date ?? "")}" class="mt-1 w-full rounded-lg border bg-white px-3 py-2" />
      </div>
      <div>
        <label class="text-sm text-slate-600">教练（可选）</label>
        <select name="coach_id" class="mt-1 w-full rounded-lg border bg-white px-3 py-2">
          <option value="">全部</option>
          ${coachOptions}
        </select>
      </div>
      <div>
        <label class="text-sm text-slate-600">状态（可选）</label>
        <select name="status" class="mt-1 w-full rounded-lg border bg-white px-3 py-2">
          <option value="">全部</option>
          ${statusOptions}
        </select>
      </div>
      <button class="w-full rounded-lg bg-slate-900 px-3 py-2 text-white">筛选</button>
    </form>
    <div class="mt-4 space-y-2">${list}</div>
  `;
  return html(layout({ title: "预约查询", body }));
}

async function apiCoaches(req: Request, env: Env): Promise<Response> {
  const user = await getCurrentUser(req, env);
  if (!user) return json({ detail: "Not authenticated" }, 401);
  const coaches = await kvListCoaches(env.BOOKING_KV);
  return json(coaches.map((c) => ({ id: c.id, display_name: c.display_name })));
}

async function apiCoachAvailability(req: Request, env: Env, coachId: string): Promise<Response> {
  const user = await getCurrentUser(req, env);
  if (!user) return json({ detail: "Not authenticated" }, 401);
  const url = new URL(req.url);
  const date = url.searchParams.get("date") ?? "";
  if (!parseYmd(date)) return badRequest("Invalid date format");
  const slots = await buildSlotsForCoach(env.BOOKING_KV, coachId, date, defaultSlotMinutes(env));
  return json(
    slots.map((s) => ({
      ...s,
      start_hm: minuteToHm(s.start_minute),
      end_hm: minuteToHm(s.end_minute),
    })),
  );
}

const router = new Router();

router.on("GET", "/health", async () => json({ ok: true }));
router.on("GET", "/", async (req) => redirect("/me", 302));
router.on("GET", "/me", async (req, ctx) => {
  const env = (ctx as unknown as { env: Env }).env;
  return handleMe(req, env);
});

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    await ensureBootstrapped(env);

    const url = new URL(req.url);
    const r = new Router();

    r.on("GET", "/", async () => {
      const user = await getCurrentUser(req, env);
      return user ? redirect("/me", 302) : redirect("/login", 302);
    });
    r.on("GET", "/health", async () => json({ ok: true }));
    r.on("GET", "/login", async () => renderLogin(req, env));
    r.on("POST", "/login", async () => handleLogin(req, env));
    r.on("GET", "/logout", async () => handleLogout(env));
    r.on("GET", "/me", async () => handleMe(req, env));

    r.on("GET", "/member", async () => renderMember(req, env));
    r.on("POST", "/member/book", async () => handleMemberBook(req, env));
    r.on("GET", "/member/bookings", async () => renderMemberBookings(req, env));
    r.on("POST", "/member/bookings/:bookingId/cancel", async (_req, ctx) =>
      handleMemberCancel(req, env, ctx.params.bookingId),
    );

    r.on("GET", "/coach", async () => renderCoach(req, env));
    r.on("POST", "/coach/bookings/:bookingId/confirm", async (_req, ctx) =>
      handleCoachConfirm(req, env, ctx.params.bookingId),
    );
    r.on("POST", "/coach/bookings/:bookingId/reject", async (_req, ctx) =>
      handleCoachReject(req, env, ctx.params.bookingId),
    );

    r.on("GET", "/admin", async () => renderAdmin(req, env));
    r.on("GET", "/admin/users", async () => renderAdminUsers(req, env));
    r.on("POST", "/admin/users/create", async () => handleAdminCreateUser(req, env));
    r.on("POST", "/admin/users/:userId/toggle", async (_req, ctx) => handleAdminToggleUser(req, env, ctx.params.userId));
    r.on("POST", "/admin/users/:userId/reset_password", async (_req, ctx) =>
      handleAdminResetPassword(req, env, ctx.params.userId),
    );
    r.on("GET", "/admin/schedule", async () => renderAdminSchedule(req, env));
    r.on("POST", "/admin/schedule/rules/create", async () => handleAdminCreateRule(req, env));
    r.on("POST", "/admin/schedule/rules/:ruleId/toggle", async (_req, ctx) => handleAdminToggleRule(req, env, ctx.params.ruleId));
    r.on("POST", "/admin/schedule/rules/:ruleId/delete", async (_req, ctx) => handleAdminDeleteRule(req, env, ctx.params.ruleId));
    r.on("POST", "/admin/schedule/exceptions/create", async () => handleAdminCreateException(req, env));
    r.on("POST", "/admin/schedule/exceptions/:exId/toggle", async (_req, ctx) =>
      handleAdminToggleException(req, env, ctx.params.exId),
    );
    r.on("POST", "/admin/schedule/exceptions/:exId/delete", async (_req, ctx) =>
      handleAdminDeleteException(req, env, ctx.params.exId),
    );
    r.on("GET", "/admin/bookings", async () => renderAdminBookings(req, env));

    r.on("GET", "/api/coaches", async () => apiCoaches(req, env));
    r.on("GET", "/api/coaches/:coachId/availability", async (_req, ctx) => apiCoachAvailability(req, env, ctx.params.coachId));

    return r.handle(req);
  },
};
