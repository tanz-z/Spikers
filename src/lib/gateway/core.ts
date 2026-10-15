import { isProviderConfigured, priceOf, PROVIDERS, type ModelCandidate } from "./models";
import { getProviderStream } from "./providers";
import type { ChatMessage, ChatOptions, StreamChunk } from "./types";
import type { GatewayAttempt } from "@/db/schema";

export type GatewayRunResult = {
  provider: string;
  model: string;
  attempts: GatewayAttempt[];
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
  costUsd: number;
};

export type GatewayStreamEvent =
  | { type: "delta"; text: string }
  | { type: "done"; result: GatewayRunResult }
  | { type: "failed"; attempts: GatewayAttempt[] };

const DEFAULT_TIMEOUT_MS = 45_000;

/**
 * Tries each candidate in order. A candidate "commits" (and fallback stops)
 * as soon as its upstream connection is accepted - auth errors, missing
 * keys, 404 model errors, and timeouts all fail over to the next candidate
 * with no partial output ever reaching the caller.
 */
export async function* runGateway(
  candidates: ModelCandidate[],
  messages: ChatMessage[],
  opts: ChatOptions,
): AsyncGenerator<GatewayStreamEvent> {
  const attempts: GatewayAttempt[] = [];

  for (const candidate of candidates) {
    const { provider, model } = candidate;

    if (!isProviderConfigured(provider)) {
      attempts.push({
        provider,
        model,
        ok: false,
        skipped: true,
        reason: `${PROVIDERS[provider].envVar ?? "API key"} not configured`,
      });
      continue;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);
    const started = Date.now();

    let committed = false;
    let promptTokens = 0;
    let completionTokens = 0;
    let textLength = 0;

    try {
      const gen = getProviderStream(candidate, messages, { ...opts, signal: controller.signal });
      const first = await gen.next();

      // Connection + headers succeeded - commit to this candidate. From this
      // point on, any error is surfaced as a (possibly truncated) finished
      // response instead of falling back, since the caller may already be
      // seeing streamed text from this provider.
      committed = true;

      let item = first;
      while (!item.done) {
        const chunk: StreamChunk = item.value;
        if (chunk.type === "delta") {
          textLength += chunk.text.length;
          yield { type: "delta", text: chunk.text };
        } else if (chunk.type === "usage") {
          promptTokens = chunk.usage.promptTokens || promptTokens;
          completionTokens = chunk.usage.completionTokens || completionTokens;
        }
        item = await gen.next();
      }

      clearTimeout(timer);
      if (completionTokens === 0 && textLength > 0) {
        completionTokens = Math.max(1, Math.ceil(textLength / 4));
      }
      const pricing = priceOf(provider, model);
      const costUsd =
        (promptTokens / 1_000_000) * pricing.input + (completionTokens / 1_000_000) * pricing.output;

      attempts.push({ provider, model, ok: true, latencyMs: Date.now() - started });
      yield {
        type: "done",
        result: {
          provider,
          model,
          attempts,
          promptTokens,
          completionTokens,
          totalTokens: promptTokens + completionTokens,
          costUsd,
        },
      };
      return;
    } catch (err) {
      clearTimeout(timer);
      const message = err instanceof Error ? err.message : String(err);
      attempts.push({ provider, model, ok: false, error: message, latencyMs: Date.now() - started });

      if (committed) {
        // Already streamed partial content to the caller - finish here
        // rather than silently mixing in a second model's output.
        if (completionTokens === 0 && textLength > 0) {
          completionTokens = Math.max(1, Math.ceil(textLength / 4));
        }
        const pricing = priceOf(provider, model);
        const costUsd =
          (promptTokens / 1_000_000) * pricing.input + (completionTokens / 1_000_000) * pricing.output;
        yield {
          type: "done",
          result: {
            provider,
            model,
            attempts,
            promptTokens,
            completionTokens,
            totalTokens: promptTokens + completionTokens,
            costUsd,
          },
        };
        return;
      }
      continue;
    }
  }

  yield { type: "failed", attempts };
}
