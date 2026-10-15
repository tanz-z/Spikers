import { eq } from "drizzle-orm";
import { db } from "@/db";
import { gatewayApiKeys } from "@/db/schema";
import { requireAdmin } from "@/lib/gateway/admin-auth";

type Params = { params: Promise<{ id: string }> };

type PatchBody = {
  name?: string;
  isActive?: boolean;
  allowedModels?: string[];
  rpmLimit?: number;
  dailyTokenLimit?: number | null;
  budgetUsd?: number | null;
};

export async function PATCH(req: Request, { params }: Params) {
  const unauthorized = requireAdmin(req);
  if (unauthorized) return unauthorized;
  const { id } = await params;

  let body: PatchBody;
  try {
    body = await req.json();
  } catch {
    return Response.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  const updates: Partial<typeof gatewayApiKeys.$inferInsert> = {};
  if (typeof body.name === "string") updates.name = body.name;
  if (typeof body.isActive === "boolean") updates.isActive = body.isActive;
  if (Array.isArray(body.allowedModels)) updates.allowedModels = body.allowedModels;
  if (typeof body.rpmLimit === "number" && body.rpmLimit > 0) updates.rpmLimit = Math.floor(body.rpmLimit);
  if ("dailyTokenLimit" in body) updates.dailyTokenLimit = body.dailyTokenLimit ?? null;
  if ("budgetUsd" in body) updates.budgetUsd = body.budgetUsd != null ? String(body.budgetUsd) : null;

  if (Object.keys(updates).length === 0) {
    return Response.json({ error: "No valid fields to update." }, { status: 400 });
  }

  const [row] = await db.update(gatewayApiKeys).set(updates).where(eq(gatewayApiKeys.id, id)).returning();
  if (!row) return Response.json({ error: "Key not found." }, { status: 404 });
  return Response.json({ record: row });
}

export async function DELETE(req: Request, { params }: Params) {
  const unauthorized = requireAdmin(req);
  if (unauthorized) return unauthorized;
  const { id } = await params;

  const [row] = await db.delete(gatewayApiKeys).where(eq(gatewayApiKeys.id, id)).returning();
  if (!row) return Response.json({ error: "Key not found." }, { status: 404 });
  return Response.json({ ok: true });
}
