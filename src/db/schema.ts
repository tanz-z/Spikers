import {
  boolean,
  index,
  integer,
  jsonb,
  numeric,
  pgTable,
  text,
  timestamp,
  uuid,
} from "drizzle-orm/pg-core";

/**
 * Virtual API keys issued by the gateway. End users / client apps call the
 * gateway with one of these keys instead of ever touching a real provider
 * key (OpenAI / Anthropic / Google / Groq / ...).
 */
export const gatewayApiKeys = pgTable("gateway_api_keys", {
  id: uuid("id").defaultRandom().primaryKey(),
  name: text("name").notNull(),
  // Short, non-secret prefix shown in the UI, e.g. "sk-gw-ab12cd34"
  keyPrefix: text("key_prefix").notNull(),
  // sha256 hex digest of the real key - the plaintext key is never stored
  keyHash: text("key_hash").notNull().unique(),
  // Empty array = all models allowed
  allowedModels: jsonb("allowed_models").$type<string[]>().notNull().default([]),
  rpmLimit: integer("rpm_limit").notNull().default(30),
  dailyTokenLimit: integer("daily_token_limit"),
  budgetUsd: numeric("budget_usd", { precision: 10, scale: 4 }),
  spentUsd: numeric("spent_usd", { precision: 10, scale: 4 }).notNull().default("0"),
  isActive: boolean("is_active").notNull().default(true),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
});

export type GatewayAttempt = {
  provider: string;
  model: string;
  ok: boolean;
  skipped?: boolean;
  reason?: string;
  error?: string;
  latencyMs?: number;
};

/**
 * One row per request that passes through the gateway. This is what powers
 * rate limiting, budget enforcement, and the admin analytics dashboard.
 */
export const gatewayRequestLogs = pgTable(
  "gateway_request_logs",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    apiKeyId: uuid("api_key_id").references(() => gatewayApiKeys.id, {
      onDelete: "set null",
    }),
    apiKeyName: text("api_key_name"),
    requestedModel: text("requested_model").notNull(),
    resolvedProvider: text("resolved_provider"),
    resolvedModel: text("resolved_model"),
    status: text("status").notNull(),
    attempts: jsonb("attempts").$type<GatewayAttempt[]>().notNull().default([]),
    promptTokens: integer("prompt_tokens").notNull().default(0),
    completionTokens: integer("completion_tokens").notNull().default(0),
    totalTokens: integer("total_tokens").notNull().default(0),
    costUsd: numeric("cost_usd", { precision: 12, scale: 6 }).notNull().default("0"),
    latencyMs: integer("latency_ms").notNull().default(0),
    stream: boolean("stream").notNull().default(false),
    errorMessage: text("error_message"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index("gateway_request_logs_api_key_created_idx").on(table.apiKeyId, table.createdAt),
    index("gateway_request_logs_created_idx").on(table.createdAt),
  ],
);
