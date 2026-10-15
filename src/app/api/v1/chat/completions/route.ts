import { randomUUID } from "crypto";
import { resolveModelChain } from "@/lib/gateway/models";
import { runGateway, type GatewayRunResult } from "@/lib/gateway/core";
import { authenticateKey, checkLimits, logCompletion, logRejected } from "@/lib/gateway/service";
import { extractBearerToken } from "@/lib/gateway/keys";
import type { ChatMessage } from "@/lib/gateway/types";
import type { GatewayAttempt } from "@/db/schema";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

type Body = {
  model?: string;
  messages?: { role?: string; content?: string }[];
  stream?: boolean;
  temperature?: number;
  max_tokens?: number;
};

function errorResponse(status: number, message: string, type = "invalid_request_error") {
  return Response.json({ error: { message, type } }, { status });
}

export async function POST(req: Request) {
  const rawKey = extractBearerToken(req.headers.get("authorization"));
  const key = await authenticateKey(rawKey);

  if (!key) {
    return errorResponse(401, "Invalid or missing API key. Create one from the admin dashboard.", "authentication_error");
  }

  let body: Body;
  try {
    body = await req.json();
  } catch {
    return errorResponse(400, "Request body must be valid JSON.");
  }

  const requestedModel = body.model?.trim();
  if (!requestedModel) {
    return errorResponse(400, "`model` is required.");
  }

  const rawMessages = body.messages;
  if (!Array.isArray(rawMessages) || rawMessages.length === 0) {
    return errorResponse(400, "`messages` must be a non-empty array.");
  }
  for (const m of rawMessages) {
    if (!m || typeof m.content !== "string" || !["system", "user", "assistant"].includes(m.role ?? "")) {
      return errorResponse(400, 'Each message needs a role of "system" | "user" | "assistant" and string content.');
    }
  }
  const messages = rawMessages as ChatMessage[];
  const stream = Boolean(body.stream);

  const limitCheck = await checkLimits(key, requestedModel);
  if (!limitCheck.ok) {
    await logRejected({ key, requestedModel, status: limitCheck.reason, message: limitCheck.message, stream });
    return errorResponse(limitCheck.status, limitCheck.message, limitCheck.reason);
  }

  const resolved = resolveModelChain(requestedModel);
  if (!resolved) {
    await logRejected({
      key,
      requestedModel,
      status: "unknown_model",
      message: `Unknown model "${requestedModel}".`,
      stream,
    });
    return errorResponse(
      404,
      `Unknown model "${requestedModel}". Use a gateway alias (gateway-fast, gateway-balanced, gateway-smart, gateway-coder) or "provider:model" to pin a specific upstream model.`,
      "model_not_found",
    );
  }

  const opts = { temperature: body.temperature, maxTokens: body.max_tokens };
  const startedAt = Date.now();
  const completionId = `chatcmpl-${randomUUID()}`;
  const createdTs = Math.floor(Date.now() / 1000);

  if (!stream) {
    let content = "";
    const gen = runGateway(resolved.candidates, messages, opts);
    let doneEvent: GatewayRunResult | null = null;
    let failedAttempts: GatewayAttempt[] | null = null;

    for await (const evt of gen) {
      if (evt.type === "delta") content += evt.text;
      else if (evt.type === "done") doneEvent = evt.result;
      else if (evt.type === "failed") failedAttempts = evt.attempts;
    }

    const latencyMs = Date.now() - startedAt;

    if (!doneEvent) {
      await logCompletion({
        key,
        requestedModel,
        resolvedProvider: null,
        resolvedModel: null,
        status: "error",
        attempts: failedAttempts ?? [],
        promptTokens: 0,
        completionTokens: 0,
        costUsd: 0,
        latencyMs,
        stream: false,
        errorMessage: "All providers in the fallback chain failed.",
      });
      return errorResponse(502, "All providers in the fallback chain failed.", "upstream_error");
    }

    await logCompletion({
      key,
      requestedModel,
      resolvedProvider: doneEvent.provider,
      resolvedModel: doneEvent.model,
      status: "success",
      attempts: doneEvent.attempts,
      promptTokens: doneEvent.promptTokens,
      completionTokens: doneEvent.completionTokens,
      costUsd: doneEvent.costUsd,
      latencyMs,
      stream: false,
    });

    return Response.json({
      id: completionId,
      object: "chat.completion",
      created: createdTs,
      model: `${doneEvent.provider}:${doneEvent.model}`,
      choices: [{ index: 0, message: { role: "assistant", content }, finish_reason: "stop" }],
      usage: {
        prompt_tokens: doneEvent.promptTokens,
        completion_tokens: doneEvent.completionTokens,
        total_tokens: doneEvent.totalTokens,
      },
      gateway: {
        requestedModel,
        alias: resolved.alias,
        provider: doneEvent.provider,
        resolvedModel: doneEvent.model,
        fallbackUsed: doneEvent.attempts.length > 1,
        attempts: doneEvent.attempts,
        costUsd: doneEvent.costUsd,
        latencyMs,
      },
    });
  }

  const encoder = new TextEncoder();
  const gen = runGateway(resolved.candidates, messages, opts);

  const readable = new ReadableStream<Uint8Array>({
    async start(controller) {
      const send = (obj: unknown) => controller.enqueue(encoder.encode(`data: ${JSON.stringify(obj)}\n\n`));
      let doneEvent: GatewayRunResult | null = null;
      let failedAttempts: GatewayAttempt[] | null = null;

      try {
        for await (const evt of gen) {
          if (evt.type === "delta") {
            send({
              id: completionId,
              object: "chat.completion.chunk",
              created: createdTs,
              model: requestedModel,
              choices: [{ index: 0, delta: { content: evt.text }, finish_reason: null }],
            });
          } else if (evt.type === "done") {
            doneEvent = evt.result;
          } else if (evt.type === "failed") {
            failedAttempts = evt.attempts;
          }
        }
      } catch {
        // fall through to logging below with whatever state we have
      }

      const latencyMs = Date.now() - startedAt;

      if (doneEvent) {
        send({
          id: completionId,
          object: "chat.completion.chunk",
          created: createdTs,
          model: `${doneEvent.provider}:${doneEvent.model}`,
          choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
          usage: {
            prompt_tokens: doneEvent.promptTokens,
            completion_tokens: doneEvent.completionTokens,
            total_tokens: doneEvent.totalTokens,
          },
          gateway: {
            requestedModel,
            alias: resolved.alias,
            provider: doneEvent.provider,
            resolvedModel: doneEvent.model,
            fallbackUsed: doneEvent.attempts.length > 1,
            attempts: doneEvent.attempts,
            costUsd: doneEvent.costUsd,
            latencyMs,
          },
        });
        await logCompletion({
          key,
          requestedModel,
          resolvedProvider: doneEvent.provider,
          resolvedModel: doneEvent.model,
          status: "success",
          attempts: doneEvent.attempts,
          promptTokens: doneEvent.promptTokens,
          completionTokens: doneEvent.completionTokens,
          costUsd: doneEvent.costUsd,
          latencyMs,
          stream: true,
        });
      } else {
        send({ error: { message: "All providers in the fallback chain failed.", type: "upstream_error" } });
        await logCompletion({
          key,
          requestedModel,
          resolvedProvider: null,
          resolvedModel: null,
          status: "error",
          attempts: failedAttempts ?? [],
          promptTokens: 0,
          completionTokens: 0,
          costUsd: 0,
          latencyMs,
          stream: true,
          errorMessage: "All providers in the fallback chain failed.",
        });
      }

      controller.enqueue(encoder.encode("data: [DONE]\n\n"));
      controller.close();
    },
    cancel() {
      gen.return?.(undefined as never);
    },
  });

  return new Response(readable, {
    headers: {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-cache, no-transform",
      connection: "keep-alive",
      "x-gateway-alias": resolved.alias,
    },
  });
}
