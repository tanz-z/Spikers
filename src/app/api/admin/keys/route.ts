import { db } from "@/db";
import { gatewayApiKeys } from "@/db/schema";
import { generateApiKey } from "@/lib/gateway/keys";
import { listKeysWithUsage } from "@/lib/gateway/service";
import { requireAdmin } from "@/lib/gateway/admin-auth";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const unauthorized = requireAdmin(req);
  if (unauthorized) return unauthorized;

  const keys = await listKeysWithUsage();
  return Response.json({ keys });
}

type CreateBody = {
  name?: string;
  allowedModels?: string[];
  rpmLimit?: number;
  dailyTokenLimit?: number | null;
  budgetUsd?: number | null;
};

export async function POST(req: Request) {
  const unauthorized = requireAdmin(req);
  if (unauthorized) return unauthorized;

  let body: CreateBody;
  try {
    body = await req.json();
  } catch {
    return Response.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  const name = body.name?.trim() || "Untitled key";
  const { plaintext, prefix, hash } = generateApiKey();

  const [row] = await db
    .insert(gatewayApiKeys)
    .values({
      name,
      keyPrefix: prefix,
      keyHash: hash,
      allowedModels: Array.isArray(body.allowedModels) ? body.allowedModels : [],
      rpmLimit: body.rpmLimit && body.rpmLimit > 0 ? Math.floor(body.rpmLimit) : 30,
      dailyTokenLimit: body.dailyTokenLimit ?? null,
      budgetUsd: body.budgetUsd != null ? String(body.budgetUsd) : null,
    })
    .returning();

  return Response.json({ key: plaintext, record: row }, { status: 201 });
}
