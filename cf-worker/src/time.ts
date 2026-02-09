export function parseYmd(value: string): { y: number; m: number; d: number } | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (!m) return null;
  const y = Number(m[1]);
  const mo = Number(m[2]);
  const d = Number(m[3]);
  if (!Number.isFinite(y) || !Number.isFinite(mo) || !Number.isFinite(d)) return null;
  if (mo < 1 || mo > 12) return null;
  if (d < 1 || d > 31) return null;
  return { y, m: mo, d };
}

export function weekdayForYmd(value: string): number | null {
  const parsed = parseYmd(value);
  if (!parsed) return null;
  const dt = new Date(`${value}T00:00:00Z`);
  const js = dt.getUTCDay();
  return (js + 6) % 7;
}

export function hmToMinute(value: string): number | null {
  const m = /^(\d{2}):(\d{2})$/.exec(value);
  if (!m) return null;
  const h = Number(m[1]);
  const mi = Number(m[2]);
  if (h < 0 || h > 23) return null;
  if (mi < 0 || mi > 59) return null;
  return h * 60 + mi;
}

export function minuteToHm(value: number): string {
  const h = Math.floor(value / 60);
  const m = value % 60;
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}`;
}

export const weekdayLabels = ["周一", "周二", "周三", "周四", "周五", "周六", "周日"];

export function weekdayLabel(weekday: number): string {
  return weekdayLabels[weekday] ?? String(weekday);
}
