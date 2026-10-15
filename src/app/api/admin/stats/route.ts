import { gte, sql } from "drizzle-orm";
import { db } from "@/db";
import { gatewayRequestLogs } from "@/db/schema";
import { requireAdmin } from "@/lib/gateway/admin-auth";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const unauthorized = requireAdmin(req);
  if (unauthorized) return unauthorized;

  const dayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);

  const [totals] = await db
    .select({
      requests: sql<number>`count(*)::int`,
      successes: sql<number>`count(*) filter (where ${gatewayRequestLogs.status} = 'success')::int`,
      tokens: sql<number>`coalesce(sum(${gatewayRequestLogs.totalTokens}), 0)::int`,
      costUsd: sql<string>`coalesce(sum(${gatewayRequestLogs.costUsd}), 0)::text`,
      avgLatencyMs: sql<number>`coalesce(avg(${gatewayRequestLogs.latencyMs}) filter (where ${gatewayRequestLogs.status} = 'success'), 0)::int`,
    })
    .from(gatewayRequestLogs);

  const [last24h] = await db
    .select({
      requests: sql<number>`count(*)::int`,
      tokens: sql<number>`coalesce(sum(${gatewayRequestLogs.totalTokens}), 0)::int`,
      costUsd: sql<string>`coalesce(sum(${gatewayRequestLogs.costUsd}), 0)::text`,
    })
    .from(gatewayRequestLogs)
    .where(gte(gatewayRequestLogs.createdAt, dayAgo));

  const byModel = await db
    .select({
      provider: gatewayRequestLogs.resolvedProvider,
      model: gatewayRequestLogs.resolvedModel,
      requests: sql<number>`count(*)::int`,
      tokens: sql<number>`coalesce(sum(${gatewayRequestLogs.totalTokens}), 0)::int`,
      costUsd: sql<string>`coalesce(sum(${gatewayRequestLogs.costUsd}), 0)::text`,
    })
    .from(gatewayRequestLogs)
    .where(sql`${gatewayRequestLogs.resolvedProvider} is not null`)
    .groupBy(gatewayRequestLogs.resolvedProvider, gatewayRequestLogs.resolvedModel)
    .orderBy(sql`count(*) desc`);

  const byStatus = await db
    .select({
      status: gatewayRequestLogs.status,
      count: sql<number>`count(*)::int`,
    })
    .from(gatewayRequestLogs)
    .groupBy(gatewayRequestLogs.status);

  return Response.json({ totals, last24h, byModel, byStatus });
}
