// Lightweight optional protection for the admin API/dashboard. If
// GATEWAY_ADMIN_TOKEN is set in the environment, admin routes require it
// (as a Bearer token or `x-admin-token` header). If it's not set, the admin
// API is open - convenient for local/dev use of this starter project.
export function requireAdmin(req: Request): Response | null {
  const token = process.env.GATEWAY_ADMIN_TOKEN;
  if (!token) return null;

  const header = req.headers.get("x-admin-token") ?? req.headers.get("authorization")?.replace(/^Bearer\s+/i, "");
  if (header === token) return null;

  return Response.json({ error: "Missing or invalid admin token." }, { status: 401 });
}
