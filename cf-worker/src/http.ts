export function html(body: string, status = 200, headers?: HeadersInit): Response {
  return new Response(body, {
    status,
    headers: { "content-type": "text/html; charset=utf-8", ...(headers ?? {}) },
  });
}

export function json(data: unknown, status = 200, headers?: HeadersInit): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...(headers ?? {}) },
  });
}

export function redirect(url: string, status: 302): Response {
  return new Response(null, { status, headers: { location: url } });
}

export function badRequest(message: string): Response {
  return json({ detail: message }, 400);
}

export function forbidden(): Response {
  return json({ detail: "Forbidden" }, 403);
}

export function unauthorized(): Response {
  return json({ detail: "Not authenticated" }, 401);
}

export function getCookie(req: Request, name: string): string | null {
  const raw = req.headers.get("cookie");
  if (!raw) return null;
  const parts = raw.split(";").map((p) => p.trim());
  for (const p of parts) {
    const idx = p.indexOf("=");
    if (idx <= 0) continue;
    const k = p.slice(0, idx);
    if (k !== name) continue;
    return decodeURIComponent(p.slice(idx + 1));
  }
  return null;
}

export function setCookie(
  headers: Headers,
  name: string,
  value: string,
  opts: {
    httpOnly?: boolean;
    secure?: boolean;
    sameSite?: "Lax" | "Strict" | "None";
    path?: string;
    maxAge?: number;
  } = {},
): void {
  const parts: string[] = [];
  parts.push(`${name}=${encodeURIComponent(value)}`);
  parts.push(`Path=${opts.path ?? "/"}`);
  if (opts.httpOnly ?? true) parts.push("HttpOnly");
  if (opts.secure) parts.push("Secure");
  parts.push(`SameSite=${opts.sameSite ?? "Lax"}`);
  if (opts.maxAge !== undefined) parts.push(`Max-Age=${opts.maxAge}`);
  headers.append("Set-Cookie", parts.join("; "));
}

export function clearCookie(headers: Headers, name: string): void {
  headers.append("Set-Cookie", `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax`);
}

export async function readForm(req: Request): Promise<Record<string, string>> {
  const contentType = req.headers.get("content-type") ?? "";
  if (!contentType.includes("application/x-www-form-urlencoded") && !contentType.includes("multipart/form-data")) {
    return {};
  }
  const data = await req.formData();
  const out: Record<string, string> = {};
  data.forEach((v, k) => {
    out[k] = String(v);
  });
  return out;
}
