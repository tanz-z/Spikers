import { randomBytes, createHash } from "crypto";

export const KEY_PREFIX = "sk-gw-";

export function generateApiKey(): { plaintext: string; prefix: string; hash: string } {
  const secret = randomBytes(24).toString("base64url");
  const plaintext = `${KEY_PREFIX}${secret}`;
  const prefix = plaintext.slice(0, KEY_PREFIX.length + 8);
  const hash = hashApiKey(plaintext);
  return { plaintext, prefix, hash };
}

export function hashApiKey(plaintext: string): string {
  return createHash("sha256").update(plaintext).digest("hex");
}

export function extractBearerToken(authHeader: string | null): string | null {
  if (!authHeader) return null;
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : authHeader.trim();
}
