import type { Booking, BookingStatus } from "./types";
import { kvAppendIdToList, kvGetBooking, kvGetJson, kvPutBooking, keys } from "./kv";
import { readSlotDefinition } from "./availability";
import { parseYmd } from "./time";

export class BookingError extends Error {
  message: string;
  constructor(message: string) {
    super(message);
    this.message = message;
  }
}

function nowIso(): string {
  return new Date().toISOString();
}

function isActiveStatus(status: BookingStatus): boolean {
  return status === "pending" || status === "confirmed";
}

export async function createBooking(params: {
  kv: KVNamespace;
  memberId: string;
  coachId: string;
  date: string;
  startMinute: number;
  defaultSlotMinutes: number;
}): Promise<Booking> {
  const { kv, memberId, coachId, date, startMinute, defaultSlotMinutes } = params;

  if (!parseYmd(date)) throw new BookingError("日期格式错误");
  const slot = await readSlotDefinition(kv, coachId, date, startMinute, defaultSlotMinutes);
  if (!slot) throw new BookingError("该时间段不可预约");

  const memberIdsKey = keys.bookingIdsByMember(memberId);
  const memberBookingIds = (await kv.get(memberIdsKey, "json")) as string[] | null;
  if (memberBookingIds) {
    for (const id of memberBookingIds) {
      const b = await kvGetBooking(kv, id);
      if (!b) continue;
      if (!isActiveStatus(b.status)) continue;
      if (b.date === date && b.start_minute === slot.start) throw new BookingError("你已预约过该时间段");
    }
  }

  const coachDateKey = keys.bookingIdsByCoachDate(coachId, date);
  const coachBookingIds = (await kv.get(coachDateKey, "json")) as string[] | null;
  let activeCount = 0;
  if (coachBookingIds) {
    for (const id of coachBookingIds) {
      const b = await kvGetJson<Booking>(kv, keys.booking(id));
      if (!b) continue;
      if (!isActiveStatus(b.status)) continue;
      if (b.start_minute === slot.start) activeCount += 1;
    }
  }
  if (activeCount >= slot.capacity) throw new BookingError("该时间段已约满");

  const booking: Booking = {
    id: crypto.randomUUID(),
    coach_id: coachId,
    member_id: memberId,
    date,
    start_minute: slot.start,
    end_minute: slot.end,
    status: "pending",
    created_at: nowIso(),
    updated_at: nowIso(),
  };

  await kvPutBooking(kv, booking);
  await kvAppendIdToList(kv, memberIdsKey, booking.id);
  await kvAppendIdToList(kv, coachDateKey, booking.id);

  return booking;
}

export async function cancelBooking(kv: KVNamespace, bookingId: string, memberId: string): Promise<Booking> {
  const booking = await kvGetBooking(kv, bookingId);
  if (!booking || booking.member_id !== memberId) throw new BookingError("预约不存在");
  if (!isActiveStatus(booking.status)) throw new BookingError("当前状态不可取消");
  booking.status = "cancelled";
  booking.updated_at = nowIso();
  await kvPutBooking(kv, booking);
  return booking;
}

export async function confirmBooking(kv: KVNamespace, bookingId: string, coachId: string): Promise<Booking> {
  const booking = await kvGetBooking(kv, bookingId);
  if (!booking || booking.coach_id !== coachId) throw new BookingError("预约不存在");
  if (booking.status !== "pending") throw new BookingError("当前状态不可确认");
  booking.status = "confirmed";
  booking.updated_at = nowIso();
  await kvPutBooking(kv, booking);
  return booking;
}

export async function rejectBooking(
  kv: KVNamespace,
  bookingId: string,
  coachId: string,
  decisionNote?: string,
): Promise<Booking> {
  const booking = await kvGetBooking(kv, bookingId);
  if (!booking || booking.coach_id !== coachId) throw new BookingError("预约不存在");
  if (booking.status !== "pending") throw new BookingError("当前状态不可拒绝");
  booking.status = "rejected";
  booking.decision_note = decisionNote?.trim() || undefined;
  booking.updated_at = nowIso();
  await kvPutBooking(kv, booking);
  return booking;
}
