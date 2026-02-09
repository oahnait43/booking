export type Handler = (req: Request, ctx: { params: Record<string, string> }) => Promise<Response> | Response;

type Route = { method: string; parts: string[]; handler: Handler };

export class Router {
  private routes: Route[] = [];

  on(method: string, path: string, handler: Handler): void {
    const parts = path.split("/").filter(Boolean);
    this.routes.push({ method: method.toUpperCase(), parts, handler });
  }

  async handle(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const parts = url.pathname.split("/").filter(Boolean);
    const method = req.method.toUpperCase();
    for (const r of this.routes) {
      if (r.method !== method) continue;
      if (r.parts.length !== parts.length) continue;
      const params: Record<string, string> = {};
      let ok = true;
      for (let i = 0; i < r.parts.length; i++) {
        const rp = r.parts[i];
        const pp = parts[i];
        if (rp.startsWith(":")) {
          params[rp.slice(1)] = decodeURIComponent(pp);
        } else if (rp !== pp) {
          ok = false;
          break;
        }
      }
      if (!ok) continue;
      return await r.handler(req, { params });
    }
    return new Response("Not Found", { status: 404 });
  }
}
