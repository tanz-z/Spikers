// ---------------------------------------------------------------------------
// Model registry & routing config for the LLM Gateway.
//
// This is the single place that defines:
//   - which upstream providers exist and how to reach them
//   - which "gateway model aliases" clients can request
//   - the ordered fallback chain behind each alias
//   - approximate pricing used for cost tracking in the admin dashboard
//
// Add/remove providers or change fallback order here - nothing else in the
// gateway needs to change.
// ---------------------------------------------------------------------------

export type Provider =
  | "openai"
  | "anthropic"
  | "google"
  | "groq"
  | "mistral"
  | "openrouter"
  | "mock";

export type ModelCandidate = {
  provider: Provider;
  model: string;
};

export type ProviderInfo = {
  envVar: string | null; // null = never needs a key (mock)
  baseUrl?: string;
  label: string;
};

export const PROVIDERS: Record<Provider, ProviderInfo> = {
  openai: { envVar: "OPENAI_API_KEY", baseUrl: "https://api.openai.com/v1", label: "OpenAI" },
  anthropic: { envVar: "ANTHROPIC_API_KEY", label: "Anthropic" },
  google: { envVar: "GOOGLE_API_KEY", label: "Google Gemini" },
  groq: { envVar: "GROQ_API_KEY", baseUrl: "https://api.groq.com/openai/v1", label: "Groq" },
  mistral: { envVar: "MISTRAL_API_KEY", baseUrl: "https://api.mistral.ai/v1", label: "Mistral" },
  openrouter: {
    envVar: "OPENROUTER_API_KEY",
    baseUrl: "https://openrouter.ai/api/v1",
    label: "OpenRouter",
  },
  mock: { envVar: null, label: "Gateway Sandbox Model" },
};

export function providerApiKey(provider: Provider): string | undefined {
  const info = PROVIDERS[provider];
  if (!info.envVar) return undefined;
  if (provider === "google") {
    return process.env.GOOGLE_API_KEY || process.env.GEMINI_API_KEY;
  }
  return process.env[info.envVar];
}

export function isProviderConfigured(provider: Provider): boolean {
  if (provider === "mock") return true;
  return Boolean(providerApiKey(provider));
}

// USD per 1,000,000 tokens. Approximate list pricing - update to taste.
export const PRICING: Record<string, { input: number; output: number }> = {
  "openai:gpt-4o": { input: 2.5, output: 10 },
  "openai:gpt-4o-mini": { input: 0.15, output: 0.6 },
  "openai:gpt-4.1-mini": { input: 0.4, output: 1.6 },
  "anthropic:claude-3-5-sonnet-latest": { input: 3, output: 15 },
  "anthropic:claude-3-5-haiku-latest": { input: 0.8, output: 4 },
  "google:gemini-1.5-pro": { input: 1.25, output: 5 },
  "google:gemini-2.0-flash": { input: 0.1, output: 0.4 },
  "groq:llama-3.3-70b-versatile": { input: 0.59, output: 0.79 },
  "groq:llama-3.1-8b-instant": { input: 0.05, output: 0.08 },
  "mistral:mistral-large-latest": { input: 2, output: 6 },
  "mistral:mistral-small-latest": { input: 0.2, output: 0.6 },
  "openrouter:meta-llama/llama-3.3-70b-instruct": { input: 0.35, output: 0.4 },
  "mock:gateway-sandbox": { input: 0, output: 0 },
};

export function priceOf(provider: Provider, model: string) {
  return PRICING[`${provider}:${model}`] ?? { input: 0, output: 0 };
}

export type Alias = {
  id: string;
  label: string;
  description: string;
  candidates: ModelCandidate[];
};

// Ordered fallback chains. The gateway tries each candidate in order and
// moves on if the provider has no key configured, errors, or times out.
// Every alias ends in `mock` so the gateway always returns *something*,
// even before you add any provider keys.
export const ALIASES: Alias[] = [
  {
    id: "gateway-fast",
    label: "Fast / cheap",
    description: "Lowest latency & cost. Good for autocomplete, classification, simple chat.",
    candidates: [
      { provider: "groq", model: "llama-3.1-8b-instant" },
      { provider: "openai", model: "gpt-4o-mini" },
      { provider: "google", model: "gemini-2.0-flash" },
      { provider: "mock", model: "gateway-sandbox" },
    ],
  },
  {
    id: "gateway-balanced",
    label: "Balanced (default)",
    description: "Good quality/cost tradeoff for general purpose chat.",
    candidates: [
      { provider: "openai", model: "gpt-4o-mini" },
      { provider: "anthropic", model: "claude-3-5-haiku-latest" },
      { provider: "groq", model: "llama-3.3-70b-versatile" },
      { provider: "mock", model: "gateway-sandbox" },
    ],
  },
  {
    id: "gateway-smart",
    label: "Smart / reasoning",
    description: "Highest quality for complex reasoning, writing, and analysis.",
    candidates: [
      { provider: "anthropic", model: "claude-3-5-sonnet-latest" },
      { provider: "openai", model: "gpt-4o" },
      { provider: "google", model: "gemini-1.5-pro" },
      { provider: "mock", model: "gateway-sandbox" },
    ],
  },
  {
    id: "gateway-coder",
    label: "Code",
    description: "Tuned routing order for coding tasks.",
    candidates: [
      { provider: "openai", model: "gpt-4.1-mini" },
      { provider: "anthropic", model: "claude-3-5-sonnet-latest" },
      { provider: "groq", model: "llama-3.3-70b-versatile" },
      { provider: "mock", model: "gateway-sandbox" },
    ],
  },
];

export function findAlias(id: string): Alias | undefined {
  return ALIASES.find((a) => a.id === id);
}

const KNOWN_PROVIDERS = new Set<string>(Object.keys(PROVIDERS));

/**
 * Resolve a client-requested "model" string into an ordered candidate chain.
 *
 *  - a gateway alias, e.g. "gateway-balanced"
 *  - a direct "provider:model" or "provider/model" pin, e.g. "openai:gpt-4o"
 *    (no fallback - used for testing a specific upstream model)
 */
export function resolveModelChain(
  requested: string,
): { alias: string; candidates: ModelCandidate[] } | null {
  const alias = findAlias(requested);
  if (alias) return { alias: alias.id, candidates: alias.candidates };

  const sep = requested.includes(":") ? ":" : requested.includes("/") ? "/" : null;
  if (sep) {
    const [provider, ...rest] = requested.split(sep);
    const model = rest.join(sep);
    if (provider && model && KNOWN_PROVIDERS.has(provider)) {
      return {
        alias: requested,
        candidates: [{ provider: provider as Provider, model }],
      };
    }
  }

  return null;
}

export function listModelCatalog() {
  return ALIASES.map((alias) => ({
    ...alias,
    candidates: alias.candidates.map((c) => ({
      ...c,
      configured: isProviderConfigured(c.provider),
      envVar: PROVIDERS[c.provider].envVar,
    })),
  }));
}
