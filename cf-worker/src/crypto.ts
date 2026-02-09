import type { Env } from "./types";

function b64uEncode(input: ArrayBuffer | Uint8Array): string {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  const bin = String.fromCharCode(...bytes);
  const b64 = btoa(bin);
  return b64.replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function b64uDecodeToBytes(value: string): Uint8Array {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const padLen = (4 - (normalized.length % 4)) % 4;
  const b64 = normalized + "=".repeat(padLen);
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function hmacKey(secret: string): Promise<CryptoKey> {
  const raw = new TextEncoder().encode(secret);
  return crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

export async function signSession(env: Env, payload: unknown): Promise<string> {
  const body = b64uEncode(new TextEncoder().encode(JSON.stringify(payload)));
  const key = await hmacKey(env.SECRET_KEY);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body));
  return `${body}.${b64uEncode(sig)}`;
}

export async function verifySession<T>(env: Env, token: string): Promise<T | null> {
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [body, signature] = parts;
  const key = await hmacKey(env.SECRET_KEY);
  const ok = await crypto.subtle.verify(
    "HMAC",
    key,
    b64uDecodeToBytes(signature),
    new TextEncoder().encode(body),
  );
  if (!ok) return null;
  const json = new TextDecoder().decode(b64uDecodeToBytes(body));
  return JSON.parse(json) as T;
}

async function pbkdf2Key(password: string): Promise<CryptoKey> {
  const raw = new TextEncoder().encode(password);
  return crypto.subtle.importKey("raw", raw, "PBKDF2", false, ["deriveBits"]);
}

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await pbkdf2Key(password);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: 210000 },
    key,
    256,
  );
  return `pbkdf2_sha256$210000$${b64uEncode(salt)}$${b64uEncode(bits)}`;
}

export async function verifyPassword(password: string, passwordHash: string): Promise<boolean> {
  const parts = passwordHash.split("$");
  if (parts.length !== 4) return false;
  const [alg, iterStr, saltB64, digestB64] = parts;
  if (alg !== "pbkdf2_sha256") return false;
  const iterations = Number(iterStr);
  if (!Number.isFinite(iterations) || iterations <= 0) return false;
  const salt = b64uDecodeToBytes(saltB64);
  const key = await pbkdf2Key(password);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    key,
    256,
  );
  const expected = b64uEncode(bits);
  return expected === digestB64;
}
