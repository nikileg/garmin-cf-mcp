// Access guard: only Garmin accounts listed in ALLOWED_EMAILS (comma-separated)
// may sign in. Wraps the original Worker from ./index.ts.
// - POST /authorize/login is rejected unless the submitted email is allowed
//   (Garmin then verifies the password/MFA for that email).
// - POST /authorize/tokens (paste garmin_tokens.json) is disabled, since the
//   email can't be verified on that path.
// Fails closed: an empty ALLOWED_EMAILS blocks every sign-in.
import inner from "./index.js";
import type { Env } from "./env.js";

type GuardEnv = Env & { ALLOWED_EMAILS?: string };

function deny(message: string): Response {
  const body = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Access denied</title><body style="font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem"><h1>Access denied</h1><p>${message}</p></body>`;
  return new Response(body, { status: 403, headers: { "content-type": "text/html; charset=utf-8" } });
}

export default {
  async fetch(request: Request, env: GuardEnv, ctx: ExecutionContext): Promise<Response> {
    if (request.method === "POST") {
      const path = new URL(request.url).pathname;
      if (path === "/authorize/tokens") return deny("Token import is disabled on this server.");
      if (path === "/authorize/login") {
        const allowed = (env.ALLOWED_EMAILS ?? "")
          .split(",")
          .map((s) => s.trim().toLowerCase())
          .filter(Boolean);
        const form = await request.clone().formData().catch(() => null);
        const email = String(form?.get("email") ?? "").trim().toLowerCase();
        if (!email || !allowed.includes(email)) return deny("This Garmin account is not allowed on this server.");
      }
    }
    return (inner as unknown as ExportedHandler<GuardEnv>).fetch!(request as any, env, ctx);
  },
};
