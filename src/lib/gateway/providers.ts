// Upstream provider adapters. Each adapter is an async generator that:
//   1. Opens the request to the upstream provider (this is where auth /
//      model-not-found / rate-limit errors surface - *before* anything is
//      yielded, so the gateway can fail over to the next candidate safely).
//   2. Yields `{ type: "delta", text }` chunks as they arrive.
//   3. Yields a final `{ type: "usage", usage }` chunk once known.
//
// This single shape powers both streaming and non-streaming gateway
// responses - non-streaming requests just drain the generator server-side.

import { PROVIDERS, providerApiKey, type ModelCandidate, type Provider } from "./models";
import { parseSse } from "./sse";
import type { ChatMessage, ChatOptions, StreamChunk } from "./types";

function estimateTokens(text: string): number {
  // ~4 chars/token heuristic, used only when a provider doesn't report usage.
  return Math.max(1, Math.ceil(text.length / 4));
}

async function readErrorBody(res: Response): Promise<string> {
  try {
    const text = await res.text();
    return text.slice(0, 500);
  } catch {
    return res.statusText;
  }
}

/** OpenAI-compatible Chat Completions API (OpenAI, Groq, Mistral, OpenRouter). */
async function* openAiCompatibleStream(
  baseUrl: string,
  apiKey: string,
  model: string,
  messages: ChatMessage[],
  opts: ChatOptions,
): AsyncGenerator<StreamChunk> {
  const res = await fetch(`${baseUrl}/chat/completions`, {
    method: "POST",
    signal: opts.signal,
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model,
      messages,
      temperature: opts.temperature,
      max_tokens: opts.maxTokens,
      stream: true,
      stream_options: { include_usage: true },
    }),
  });

  if (!res.ok || !res.body) {
    throw new Error(`HTTP ${res.status}: ${await readErrorBody(res)}`);
  }

  let usage: StreamChunk | null = null;
  for await (const evt of parseSse(res.body)) {
    if (evt.data === "[DONE]") break;
    let obj: {
      choices?: { delta?: { content?: string } }[];
      usage?: { prompt_tokens?: number; completion_tokens?: number };
    };
    try {
      obj = JSON.parse(evt.data);
    } catch {
      continue;
    }
    const delta = obj.choices?.[0]?.delta?.content;
    if (delta) yield { type: "delta", text: delta };
    if (obj.usage) {
      usage = {
        type: "usage",
        usage: {
          promptTokens: obj.usage.prompt_tokens ?? 0,
          completionTokens: obj.usage.completion_tokens ?? 0,
        },
      };
    }
  }
  if (usage) yield usage;
}

/** Anthropic Messages API. */
async function* anthropicStream(
  apiKey: string,
  model: string,
  messages: ChatMessage[],
  opts: ChatOptions,
): AsyncGenerator<StreamChunk> {
  const system = messages
    .filter((m) => m.role === "system")
    .map((m) => m.content)
    .join("\n\n");
  const turns = messages
    .filter((m) => m.role !== "system")
    .map((m) => ({ role: m.role === "assistant" ? "assistant" : "user", content: m.content }));

  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    signal: opts.signal,
    headers: {
      "content-type": "application/json",
      "x-api-key": apiKey,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model,
      system: system || undefined,
      messages: turns,
      max_tokens: opts.maxTokens ?? 1024,
      temperature: opts.temperature,
      stream: true,
    }),
  });

  if (!res.ok || !res.body) {
    throw new Error(`HTTP ${res.status}: ${await readErrorBody(res)}`);
  }

  let promptTokens = 0;
  let completionTokens = 0;
  for await (const evt of parseSse(res.body)) {
    let obj: {
      type?: string;
      message?: { usage?: { input_tokens?: number; output_tokens?: number } };
      usage?: { input_tokens?: number; output_tokens?: number };
      delta?: { type?: string; text?: string; output_tokens?: number };
    };
    try {
      obj = JSON.parse(evt.data);
    } catch {
      continue;
    }
    if (obj.type === "message_start" && obj.message?.usage) {
      promptTokens = obj.message.usage.input_tokens ?? 0;
      completionTokens = obj.message.usage.output_tokens ?? completionTokens;
    } else if (obj.type === "content_block_delta" && obj.delta?.type === "text_delta" && obj.delta.text) {
      yield { type: "delta", text: obj.delta.text };
    } else if (obj.type === "message_delta" && obj.usage?.output_tokens != null) {
      completionTokens = obj.usage.output_tokens;
    }
  }
  yield { type: "usage", usage: { promptTokens, completionTokens } };
}

/** Google Gemini REST API. */
async function* googleStream(
  apiKey: string,
  model: string,
  messages: ChatMessage[],
  opts: ChatOptions,
): AsyncGenerator<StreamChunk> {
  const systemInstruction = messages
    .filter((m) => m.role === "system")
    .map((m) => m.content)
    .join("\n\n");
  const contents = messages
    .filter((m) => m.role !== "system")
    .map((m) => ({
      role: m.role === "assistant" ? "model" : "user",
      parts: [{ text: m.content }],
    }));

  const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(
    model,
  )}:streamGenerateContent?alt=sse&key=${apiKey}`;

  const res = await fetch(url, {
    method: "POST",
    signal: opts.signal,
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      contents,
      systemInstruction: systemInstruction ? { parts: [{ text: systemInstruction }] } : undefined,
      generationConfig: {
        temperature: opts.temperature,
        maxOutputTokens: opts.maxTokens,
      },
    }),
  });

  if (!res.ok || !res.body) {
    throw new Error(`HTTP ${res.status}: ${await readErrorBody(res)}`);
  }

  let promptTokens = 0;
  let completionTokens = 0;
  for await (const evt of parseSse(res.body)) {
    let obj: {
      candidates?: { content?: { parts?: { text?: string }[] } }[];
      usageMetadata?: { promptTokenCount?: number; candidatesTokenCount?: number };
    };
    try {
      obj = JSON.parse(evt.data);
    } catch {
      continue;
    }
    const text = obj.candidates?.[0]?.content?.parts?.map((p) => p.text ?? "").join("");
    if (text) yield { type: "delta", text };
    if (obj.usageMetadata) {
      promptTokens = obj.usageMetadata.promptTokenCount ?? promptTokens;
      completionTokens = obj.usageMetadata.candidatesTokenCount ?? completionTokens;
    }
  }
  yield { type: "usage", usage: { promptTokens, completionTokens } };
}

/** Always-available sandbox provider. Lets the gateway (auth, rate limiting,
 * fallback, logging, cost tracking) be fully demoed before any real provider
 * API key is configured. */
async function* mockStream(messages: ChatMessage[], opts: ChatOptions): AsyncGenerator<StreamChunk> {
  const lastUser = [...messages].reverse().find((m) => m.role === "user")?.content ?? "";
  const reply =
    `This is the gateway's built-in sandbox model - no upstream provider API key is configured yet, ` +
    `so this request was routed here as the final fallback. ` +
    `Add OPENAI_API_KEY, ANTHROPIC_API_KEY, GOOGLE_API_KEY, GROQ_API_KEY, MISTRAL_API_KEY and/or ` +
    `OPENROUTER_API_KEY to the environment to start getting real completions. ` +
    `Echo of your message: "${lastUser.slice(0, 200)}"`;

  const words = reply.split(" ");
  for (const word of words) {
    if (opts.signal?.aborted) break;
    await new Promise((r) => setTimeout(r, 12));
    yield { type: "delta", text: word + " " };
  }
  yield {
    type: "usage",
    usage: { promptTokens: estimateTokens(lastUser), completionTokens: estimateTokens(reply) },
  };
}

export function getProviderStream(
  candidate: ModelCandidate,
  messages: ChatMessage[],
  opts: ChatOptions,
): AsyncGenerator<StreamChunk> {
  const { provider, model } = candidate;
  if (provider === "mock") return mockStream(messages, opts);

  const apiKey = providerApiKey(provider);
  if (!apiKey) {
    throw Object.assign(new Error(`${PROVIDERS[provider].envVar} is not configured`), {
      code: "NO_API_KEY",
    });
  }

  switch (provider) {
    case "anthropic":
      return anthropicStream(apiKey, model, messages, opts);
    case "google":
      return googleStream(apiKey, model, messages, opts);
    case "openai":
    case "groq":
    case "mistral":
    case "openrouter": {
      const baseUrl = PROVIDERS[provider].baseUrl!;
      return openAiCompatibleStream(baseUrl, apiKey, model, messages, opts);
    }
    default: {
      const _exhaustive: never = provider;
      throw new Error(`Unsupported provider: ${_exhaustive}`);
    }
  }
}

export type { Provider };
