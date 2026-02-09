import type { AvailabilityException, AvailabilityRule, Booking, BookingStatus, Slot } from "./types";
import { kvGetJson, kvListAvailabilityExceptions, kvListAvailabilityRules, keys } from "./kv";
import { weekdayForYmd } from "./time";

function isActiveBookingStatus(status: BookingStatus): boolean {
  return status === "pending" || status === "confirmed";
}

export async function buildSlotsForCoach(
  kv: KVNamespace,
  coachId: string,
  date: string,
  defaultSlotMinutes: number,
): Promise<Slot[]> {
  const weekday = weekdayForYmd(date);
  if (weekday === null) return [];

  const exceptions = await kvListAvailabilityExceptions(kv, coachId, date);
  let segments:
    | Array<{ start: number; end: number; slot: number; cap: number; enabled: boolean }>
    | null = null;

  if (exceptions.length > 0) {
    segments = exceptions.map((ex) => ({
      start: ex.start_minute,
      end: ex.end_minute,
      slot: defaultSlotMinutes,
      cap: ex.capacity,
      enabled: ex.enabled,
    }));
  } else {
    const rules = await kvListAvailabilityRules(kv, coachId);
    segments = rules
      .filter((r) => r.weekday === weekday)
      .map((r) => ({
        start: r.start_minute,
        end: r.end_minute,
        slot: r.slot_minutes,
        cap: r.capacity,
        enabled: r.enabled,
      }));
  }

  const starts: number[] = [];
  for (const seg of segments) {
    if (!seg.enabled) continue;
    if (seg.slot <= 0 || seg.cap <= 0) continue;
    const last = seg.end - seg.slot;
    for (let s = seg.start; s <= last; s += seg.slot) starts.push(s);
  }
  if (starts.length === 0) return [];

  const bookingIds = (await kv.get(keys.bookingIdsByCoachDate(coachId, date), "json")) as string[] | null;
  const activeByStart = new Map<number, number>();
  if (bookingIds && bookingIds.length > 0) {
    for (const id of bookingIds) {
      const b = await kvGetJson<Booking>(kv, keys.booking(id));
      if (!b) continue;
      if (!isActiveBookingStatus(b.status)) continue;
      activeByStart.set(b.start_minute, (activeByStart.get(b.start_minute) ?? 0) + 1);
    }
  }

  const slots: Slot[] = [];
  for (const seg of segments) {
    if (!seg.enabled) continue;
    if (seg.slot <= 0 || seg.cap <= 0) continue;
    const last = seg.end - seg.slot;
    for (let s = seg.start; s <= last; s += seg.slot) {
      const booked = activeByStart.get(s) ?? 0;
      slots.push({
        date,
        start_minute: s,
        end_minute: s + seg.slot,
        capacity: seg.cap,
        booked,
        available: booked < seg.cap,
      });
    }
  }
  slots.sort((a, b) => a.start_minute - b.start_minute);
  return slots;
}

export async function readSlotDefinition(
  kv: KVNamespace,
  coachId: string,
  date: string,
  startMinute: number,
  defaultSlotMinutes: number,
): Promise<{ start: number; end: number; capacity: number } | null> {
  const slots = await buildSlotsForCoach(kv, coachId, date, defaultSlotMinutes);
  const slot = slots.find((s) => s.start_minute === startMinute);
  if (!slot) return null;
  return { start: slot.start_minute, end: slot.end_minute, capacity: slot.capacity };
}
