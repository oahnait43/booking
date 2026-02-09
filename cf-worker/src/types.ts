export type UserRole = "member" | "coach" | "frontdesk" | "admin";

export type BookingStatus = "pending" | "confirmed" | "rejected" | "cancelled";

export type User = {
  id: string;
  username: string;
  password_hash: string;
  role: UserRole;
  is_active: boolean;
  created_at: string;
};

export type Member = {
  id: string;
  user_id: string;
  display_name: string;
};

export type Coach = {
  id: string;
  user_id: string;
  display_name: string;
};

export type AvailabilityRule = {
  id: string;
  coach_id: string;
  weekday: number;
  start_minute: number;
  end_minute: number;
  slot_minutes: number;
  capacity: number;
  enabled: boolean;
};

export type AvailabilityException = {
  id: string;
  coach_id: string;
  date: string;
  start_minute: number;
  end_minute: number;
  capacity: number;
  enabled: boolean;
};

export type Booking = {
  id: string;
  coach_id: string;
  member_id: string;
  date: string;
  start_minute: number;
  end_minute: number;
  status: BookingStatus;
  decision_note?: string;
  created_at: string;
  updated_at: string;
};

export type Slot = {
  date: string;
  start_minute: number;
  end_minute: number;
  capacity: number;
  booked: number;
  available: boolean;
};

export type Env = {
  BOOKING_KV: KVNamespace;
  SECRET_KEY: string;
  COOKIE_SECURE: string;
  BOOTSTRAP_ADMIN_USERNAME?: string;
  BOOTSTRAP_ADMIN_PASSWORD?: string;
  DEFAULT_SLOT_MINUTES?: string;
};
