import type {
  AvailabilityException,
  AvailabilityRule,
  Booking,
  Coach,
  Member,
  User,
} from "./types";

export const keys = {
  user: (id: string) => `user:${id}`,
  userByUsername: (username: string) => `userByUsername:${username}`,
  coach: (id: string) => `coach:${id}`,
  coachByUserId: (userId: string) => `coachByUserId:${userId}`,
  member: (id: string) => `member:${id}`,
  memberByUserId: (userId: string) => `memberByUserId:${userId}`,
  availRule: (coachId: string, ruleId: string) => `availRule:${coachId}:${ruleId}`,
  availEx: (coachId: string, date: string, exId: string) => `availEx:${coachId}:${date}:${exId}`,
  booking: (id: string) => `booking:${id}`,
  bookingIdsByMember: (memberId: string) => `bookingIdsByMember:${memberId}`,
  bookingIdsByCoachDate: (coachId: string, date: string) => `bookingIdsByCoachDate:${coachId}:${date}`,
};

export async function kvGetJson<T>(kv: KVNamespace, key: string): Promise<T | null> {
  const value = await kv.get(key, "json");
  return (value as T | null) ?? null;
}

export async function kvPutJson(kv: KVNamespace, key: string, value: unknown): Promise<void> {
  await kv.put(key, JSON.stringify(value));
}

export async function kvDelete(kv: KVNamespace, key: string): Promise<void> {
  await kv.delete(key);
}

export async function kvListByPrefix(
  kv: KVNamespace,
  prefix: string,
): Promise<string[]> {
  const keysOut: string[] = [];
  let cursor: string | undefined = undefined;
  for (;;) {
    const result: Awaited<ReturnType<KVNamespace["list"]>> = await kv.list({ prefix, cursor });
    for (const k of result.keys) keysOut.push(k.name);
    if (result.list_complete) break;
    cursor = result.cursor;
  }
  return keysOut;
}

export async function kvGetUserByUsername(kv: KVNamespace, username: string): Promise<User | null> {
  const userId = await kv.get(keys.userByUsername(username));
  if (!userId) return null;
  return kvGetJson<User>(kv, keys.user(userId));
}

export async function kvPutUser(kv: KVNamespace, user: User): Promise<void> {
  await kvPutJson(kv, keys.user(user.id), user);
  await kv.put(keys.userByUsername(user.username), user.id);
}

export async function kvPutCoach(kv: KVNamespace, coach: Coach): Promise<void> {
  await kvPutJson(kv, keys.coach(coach.id), coach);
  await kv.put(keys.coachByUserId(coach.user_id), coach.id);
}

export async function kvPutMember(kv: KVNamespace, member: Member): Promise<void> {
  await kvPutJson(kv, keys.member(member.id), member);
  await kv.put(keys.memberByUserId(member.user_id), member.id);
}

export async function kvGetCoachByUserId(kv: KVNamespace, userId: string): Promise<Coach | null> {
  const coachId = await kv.get(keys.coachByUserId(userId));
  if (!coachId) return null;
  return kvGetJson<Coach>(kv, keys.coach(coachId));
}

export async function kvGetMemberByUserId(kv: KVNamespace, userId: string): Promise<Member | null> {
  const memberId = await kv.get(keys.memberByUserId(userId));
  if (!memberId) return null;
  return kvGetJson<Member>(kv, keys.member(memberId));
}

export async function kvListCoaches(kv: KVNamespace): Promise<Coach[]> {
  const coachKeys = await kvListByPrefix(kv, "coach:");
  const coaches: Coach[] = [];
  for (const k of coachKeys) {
    const coach = await kvGetJson<Coach>(kv, k);
    if (coach) coaches.push(coach);
  }
  coaches.sort((a, b) => a.display_name.localeCompare(b.display_name, "zh"));
  return coaches;
}

export async function kvListAvailabilityRules(kv: KVNamespace, coachId: string): Promise<AvailabilityRule[]> {
  const ruleKeys = await kvListByPrefix(kv, `availRule:${coachId}:`);
  const rules: AvailabilityRule[] = [];
  for (const k of ruleKeys) {
    const r = await kvGetJson<AvailabilityRule>(kv, k);
    if (r) rules.push(r);
  }
  rules.sort((a, b) => a.weekday - b.weekday || a.start_minute - b.start_minute);
  return rules;
}

export async function kvListAvailabilityExceptions(
  kv: KVNamespace,
  coachId: string,
  date: string,
): Promise<AvailabilityException[]> {
  const exKeys = await kvListByPrefix(kv, `availEx:${coachId}:${date}:`);
  const out: AvailabilityException[] = [];
  for (const k of exKeys) {
    const ex = await kvGetJson<AvailabilityException>(kv, k);
    if (ex) out.push(ex);
  }
  out.sort((a, b) => a.start_minute - b.start_minute);
  return out;
}

export async function kvGetBooking(kv: KVNamespace, bookingId: string): Promise<Booking | null> {
  return kvGetJson<Booking>(kv, keys.booking(bookingId));
}

export async function kvPutBooking(kv: KVNamespace, booking: Booking): Promise<void> {
  await kvPutJson(kv, keys.booking(booking.id), booking);
}

export async function kvAppendIdToList(kv: KVNamespace, listKey: string, id: string): Promise<void> {
  const existing = (await kv.get(listKey, "json")) as string[] | null;
  const next = existing ? [...existing, id] : [id];
  await kvPutJson(kv, listKey, next);
}

export async function kvListBookingsByIds(kv: KVNamespace, ids: string[]): Promise<Booking[]> {
  const out: Booking[] = [];
  for (const id of ids) {
    const b = await kvGetBooking(kv, id);
    if (b) out.push(b);
  }
  return out;
}
