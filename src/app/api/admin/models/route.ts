import { listModelCatalog } from "@/lib/gateway/models";
import { requireAdmin } from "@/lib/gateway/admin-auth";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const unauthorized = requireAdmin(req);
  if (unauthorized) return unauthorized;

  return Response.json({ aliases: listModelCatalog() });
}
