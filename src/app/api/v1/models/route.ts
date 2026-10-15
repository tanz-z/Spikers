import { listModelCatalog } from "@/lib/gateway/models";
import { authenticateKey } from "@/lib/gateway/service";
import { extractBearerToken } from "@/lib/gateway/keys";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const rawKey = extractBearerToken(req.headers.get("authorization"));
  const key = await authenticateKey(rawKey);
  if (!key || !key.isActive) {
    return Response.json({ error: { message: "Invalid or missing API key.", type: "authentication_error" } }, { status: 401 });
  }

  const catalog = listModelCatalog().filter(
    (alias) => key.allowedModels.length === 0 || key.allowedModels.includes(alias.id),
  );

  return Response.json({
    object: "list",
    data: catalog.map((alias) => ({
      id: alias.id,
      object: "model",
      label: alias.label,
      description: alias.description,
      fallback_chain: alias.candidates.map((c) => ({
        provider: c.provider,
        model: c.model,
        configured: c.configured,
      })),
    })),
  });
}
