import { and, desc, eq, gte, sql } from "drizzle-orm";
import { db } from "@/db";
import { gatewayApiKeys, gatewayRequestLogs, type GatewayAttempt } from "@/db/schema";
import { hashApiKey } from "./keys";

export type ApiKeyRow = typeof gatewayApiKeys.$inferSelect;

export async function authenticateKey(rawKey: string | null): Promise<ApiKeyRow | null> {
  if (!rawKey) return null;
  const hash = hashApiKey(rawKey);
  const [row] = await db.select().from(gatewayApiKeys).where(eq(gatewayApiKeys.keyHash, hash)).limit(1);
  return row ?? null;
}

export type LimitCheck =
  | { ok: true }
  | { ok: false; status: number; message: string; reason: string };

export async function checkLimits(key: ApiKeyRow, requestedModel: string): Promise<LimitCheck> {
  if (!key.isActive) {
    return { ok: false, status: 401, message: "This API key has been revoked.", reason: "key_revoked" };
  }

  if (key.allowedModels.length > 0 && !key.allowedModels.includes(requestedModel)) {
    return {
      ok: false,
      status: 403,
      message: `This key is not allowed to use model "${requestedModel}". Allowed: ${key.allowedModels.join(", ")}`,
      reason: "model_not_allowed",
    };
  }

  const oneMinuteAgo = new Date(Date.now() - 60_000);
  const [{ count: recentCount }] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(gatewayRequestLogs)
    .where(and(eq(gatewayRequestLogs.apiKeyId, key.id), gte(gatewayRequestLogs.createdAt, oneMinuteAgo)));

  if (recentCount >= key.rpmLimit) {
    return {
      ok: false,
      status: 429,
      message: `Rate limit exceeded: ${key.rpmLimit} requests/minute for this key.`,
      reason: "rate_limited",
    };
  }

  if (key.dailyTokenLimit != null) {
    const startOfDay = new Date();
    startOfDay.setUTCHours(0, 0, 0, 0);
    const [{ total }] = await db
      .select({ total: sql<number>`coalesce(sum(${gatewayRequestLogs.totalTokens}), 0)::int` })
      .from(gatewayRequestLogs)
      .where(and(eq(gatewayRequestLogs.apiKeyId, key.id), gte(gatewayRequestLogs.createdAt, startOfDay)));

    if (total >= key.dailyTokenLimit) {
      return {
        ok: false,
        status: 429,
        message: `Daily token limit of ${key.dailyTokenLimit} reached for this key.`,
        reason: "daily_token_limit",
      };
    }
  }

  if (key.budgetUsd != null && Number(key.spentUsd) >= Number(key.budgetUsd)) {
    return {
      ok: false,
      status: 429,
      message: `Budget of $${key.budgetUsd} reached for this key.`,
      reason: "budget_exceeded",
    };
  }

  return { ok: true };
}

export async function logRejected(params: {
  key: ApiKeyRow | null;
  requestedModel: string;
  status: string;
  message: string;
  stream: boolean;
}) {
  await db.insert(gatewayRequestLogs).values({
    apiKeyId: params.key?.id ?? null,
    apiKeyName: params.key?.name ?? null,
    requestedModel: params.requestedModel,
    status: params.status,
    attempts: [],
    errorMessage: params.message,
    stream: params.stream,
  });
}

export async function logCompletion(params: {
  key: ApiKeyRow;
  requestedModel: string;
  resolvedProvider: string | null;
  resolvedModel: string | null;
  status: string;
  attempts: GatewayAttempt[];
  promptTokens: number;
  completionTokens: number;
  costUsd: number;
  latencyMs: number;
  stream: boolean;
  errorMessage?: string;
}) {
  await db.insert(gatewayRequestLogs).values({
    apiKeyId: params.key.id,
    apiKeyName: params.key.name,
    requestedModel: params.requestedModel,
    resolvedProvider: params.resolvedProvider,
    resolvedModel: params.resolvedModel,
    status: params.status,
    attempts: params.attempts,
    promptTokens: params.promptTokens,
    completionTokens: params.completionTokens,
    totalTokens: params.promptTokens + params.completionTokens,
    costUsd: params.costUsd.toFixed(6),
    latencyMs: params.latencyMs,
    stream: params.stream,
    errorMessage: params.errorMessage,
  });

  await db
    .update(gatewayApiKeys)
    .set({
      lastUsedAt: new Date(),
      spentUsd: sql`${gatewayApiKeys.spentUsd} + ${params.costUsd.toFixed(6)}::numeric`,
    })
    .where(eq(gatewayApiKeys.id, params.key.id));
}

export async function listKeysWithUsage() {
  const keys = await db.select().from(gatewayApiKeys).orderBy(desc(gatewayApiKeys.createdAt));
  const dayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);

  const usageRows = await db
    .select({
      apiKeyId: gatewayRequestLogs.apiKeyId,
      requests: sql<number>`count(*)::int`,
      tokens: sql<number>`coalesce(sum(${gatewayRequestLogs.totalTokens}), 0)::int`,
    })
    .from(gatewayRequestLogs)
    .where(gte(gatewayRequestLogs.createdAt, dayAgo))
    .groupBy(gatewayRequestLogs.apiKeyId);

  const usageByKey = new Map(usageRows.map((r) => [r.apiKeyId, r]));

  return keys.map((k) => ({
    ...k,
    requestsLast24h: usageByKey.get(k.id)?.requests ?? 0,
    tokensLast24h: usageByKey.get(k.id)?.tokens ?? 0,
  }));
}
