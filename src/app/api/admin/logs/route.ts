import { desc, eq } from "drizzle-orm";
import { db } from "@/db";
import { gatewayRequestLogs } from "@/db/schema";
import { requireAdmin } from "@/lib/gateway/admin-auth";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const unauthorized = requireAdmin(req);
  if (unauthorized) return unauthorized;

  const url = new URL(req.url);
  const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit")) || 50));
  const apiKeyId = url.searchParams.get("apiKeyId");

  const rows = await db
    .select()
    .from(gatewayRequestLogs)
    .where(apiKeyId ? eq(gatewayRequestLogs.apiKeyId, apiKeyId) : undefined)
    .orderBy(desc(gatewayRequestLogs.createdAt))
    .limit(limit);

  return Response.json({ logs: rows });
}
