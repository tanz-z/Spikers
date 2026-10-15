"use client";

import { useEffect, useMemo, useRef, useState } from "react";

type AliasOption = {
  id: string;
  label: string;
  description: string;
  candidates: { provider: string; model: string; configured: boolean; envVar: string | null }[];
};

type ChatMsg = {
  role: "user" | "assistant" | "system";
  content: string;
  meta?: {
    provider?: string;
    model?: string;
    costUsd?: number;
    latencyMs?: number;
    fallbackUsed?: boolean;
    totalTokens?: number;
  };
  error?: boolean;
};

const STORAGE_KEY = "gateway_demo_api_key";

export function ChatPlayground({ aliases }: { aliases: AliasOption[] }) {
  const [apiKey, setApiKey] = useState<string | null>(null);
  const [creatingKey, setCreatingKey] = useState(false);
  const [model, setModel] = useState(aliases.find((a) => a.id === "gateway-balanced")?.id ?? aliases[0]?.id ?? "");
  const [messages, setMessages] = useState<ChatMsg[]>([]);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const [streamMode, setStreamMode] = useState(true);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const stored = typeof window !== "undefined" ? window.localStorage.getItem(STORAGE_KEY) : null;
    if (stored) setApiKey(stored);
  }, []);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const activeAlias = useMemo(() => aliases.find((a) => a.id === model), [aliases, model]);

  async function createPlaygroundKey() {
    setCreatingKey(true);
    try {
      const res = await fetch("/api/admin/keys", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: "Playground key", rpmLimit: 60 }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data?.error ?? "Failed to create key");
      window.localStorage.setItem(STORAGE_KEY, data.key);
      setApiKey(data.key);
    } catch (err) {
      setMessages((m) => [
        ...m,
        { role: "system", content: `Could not create a playground key: ${(err as Error).message}`, error: true },
      ]);
    } finally {
      setCreatingKey(false);
    }
  }

  function resetKey() {
    window.localStorage.removeItem(STORAGE_KEY);
    setApiKey(null);
  }

  async function sendMessage() {
    const text = input.trim();
    if (!text || sending || !apiKey) return;
    setInput("");
    const history = [...messages.filter((m) => m.role !== "system"), { role: "user" as const, content: text }];
    setMessages((m) => [...m, { role: "user", content: text }]);
    setSending(true);

    const assistantIndex = history.length; // position after pushing user msg
    setMessages((m) => [...m, { role: "assistant", content: "" }]);

    try {
      const res = await fetch("/api/v1/chat/completions", {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` },
        body: JSON.stringify({
          model,
          stream: streamMode,
          messages: history.map(({ role, content }) => ({ role, content })),
        }),
      });

      if (!streamMode) {
        const data = await res.json();
        if (!res.ok) throw new Error(data?.error?.message ?? "Request failed");
        updateAssistant(assistantIndex, data.choices[0].message.content, {
          provider: data.gateway?.provider,
          model: data.gateway?.resolvedModel,
          costUsd: data.gateway?.costUsd,
          latencyMs: data.gateway?.latencyMs,
          fallbackUsed: data.gateway?.fallbackUsed,
          totalTokens: data.usage?.total_tokens,
        });
        return;
      }

      if (!res.ok || !res.body) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data?.error?.message ?? `Request failed (${res.status})`);
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let content = "";
      let meta: ChatMsg["meta"] = {};

      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let idx: number;
        while ((idx = buffer.indexOf("\n\n")) !== -1) {
          const record = buffer.slice(0, idx);
          buffer = buffer.slice(idx + 2);
          const line = record.trim();
          if (!line.startsWith("data:")) continue;
          const payload = line.slice("data:".length).trim();
          if (payload === "[DONE]") continue;
          let obj: {
            choices?: { delta?: { content?: string } }[];
            error?: { message?: string };
            gateway?: { provider?: string; resolvedModel?: string; costUsd?: number; latencyMs?: number; fallbackUsed?: boolean };
            usage?: { total_tokens?: number };
          };
          try {
            obj = JSON.parse(payload);
          } catch {
            continue;
          }
          if (obj.error) throw new Error(obj.error.message ?? "Upstream error");
          const delta = obj.choices?.[0]?.delta?.content;
          if (delta) {
            content += delta;
            updateAssistant(assistantIndex, content);
          }
          if (obj.gateway) {
            meta = {
              provider: obj.gateway.provider,
              model: obj.gateway.resolvedModel,
              costUsd: obj.gateway.costUsd,
              latencyMs: obj.gateway.latencyMs,
              fallbackUsed: obj.gateway.fallbackUsed,
              totalTokens: obj.usage?.total_tokens,
            };
            updateAssistant(assistantIndex, content, meta);
          }
        }
      }
    } catch (err) {
      updateAssistant(assistantIndex, `⚠️ ${(err as Error).message}`, undefined, true);
    } finally {
      setSending(false);
    }
  }

  function updateAssistant(index: number, content: string, meta?: ChatMsg["meta"], error?: boolean) {
    setMessages((m) => {
      const copy = [...m];
      const target = copy[index];
      if (!target) return m;
      copy[index] = { ...target, content, meta: meta ?? target.meta, error: error ?? target.error };
      return copy;
    });
  }

  if (!apiKey) {
    return (
      <div className="mx-auto max-w-xl rounded-3xl border border-slate-200 bg-white p-10 text-center shadow-sm">
        <p className="text-sm font-medium uppercase tracking-wide text-slate-500">Gateway Playground</p>
        <h2 className="mt-2 text-2xl font-semibold text-slate-950">Create a playground API key</h2>
        <p className="mt-3 text-sm text-slate-600">
          The playground talks to your app the same way any client would: through the gateway&apos;s own virtual API
          key, never directly to an upstream provider.
        </p>
        <button
          onClick={createPlaygroundKey}
          disabled={creatingKey}
          className="mt-6 rounded-xl bg-slate-950 px-5 py-2.5 text-sm font-semibold text-white hover:bg-slate-800 disabled:opacity-60"
        >
          {creatingKey ? "Creating…" : "Generate playground key"}
        </button>
      </div>
    );
  }

  return (
    <div className="mx-auto grid max-w-3xl gap-4">
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-slate-200 bg-white px-4 py-3 shadow-sm">
        <div className="flex items-center gap-2 text-xs text-slate-500">
          <span className="rounded-full bg-emerald-50 px-2 py-1 font-medium text-emerald-700">key active</span>
          <code className="rounded bg-slate-100 px-2 py-1">{apiKey.slice(0, 14)}…</code>
          <button onClick={resetKey} className="underline hover:text-slate-800">
            reset
          </button>
        </div>
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-1.5 text-xs text-slate-600">
            <input type="checkbox" checked={streamMode} onChange={(e) => setStreamMode(e.target.checked)} />
            stream
          </label>
          <select
            value={model}
            onChange={(e) => setModel(e.target.value)}
            className="rounded-lg border border-slate-200 bg-white px-2 py-1.5 text-sm"
          >
            {aliases.map((a) => (
              <option key={a.id} value={a.id}>
                {a.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      {activeAlias && (
        <p className="rounded-xl bg-slate-900/5 px-4 py-2 text-xs text-slate-600">
          <strong>{activeAlias.label}</strong> routing order:{" "}
          {activeAlias.candidates.map((c, i) => (
            <span key={`${c.provider}-${c.model}`}>
              {i > 0 && " → "}
              <span className={c.configured ? "text-slate-800" : "text-slate-400"}>
                {c.provider}:{c.model}
              </span>
            </span>
          ))}
        </p>
      )}

      <div className="flex h-[520px] flex-col rounded-2xl border border-slate-200 bg-white shadow-sm">
        <div className="flex-1 space-y-4 overflow-y-auto p-5">
          {messages.length === 0 && (
            <p className="text-sm text-slate-400">
              Say hello. Your message is sent to <code>/api/v1/chat/completions</code> with your gateway key - the
              gateway resolves the model alias, applies rate limits, and routes to the first healthy provider.
            </p>
          )}
          {messages.map((m, i) => (
            <div key={i} className={m.role === "user" ? "flex justify-end" : "flex justify-start"}>
              {m.role === "system" ? (
                <p className="w-full text-center text-xs text-rose-500">{m.content}</p>
              ) : (
                <div
                  className={`max-w-[80%] rounded-2xl px-4 py-2.5 text-sm whitespace-pre-wrap ${
                    m.role === "user"
                      ? "bg-slate-950 text-white"
                      : m.error
                        ? "bg-rose-50 text-rose-700"
                        : "bg-slate-100 text-slate-900"
                  }`}
                >
                  {m.content || (sending && i === messages.length - 1 ? "…" : "")}
                  {m.meta?.provider && (
                    <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 border-t border-slate-200/70 pt-1.5 text-[11px] font-medium text-slate-500">
                      <span>{m.meta.provider}:{m.meta.model}</span>
                      {m.meta.totalTokens != null && <span>{m.meta.totalTokens} tok</span>}
                      {m.meta.costUsd != null && <span>${m.meta.costUsd.toFixed(6)}</span>}
                      {m.meta.latencyMs != null && <span>{m.meta.latencyMs}ms</span>}
                      {m.meta.fallbackUsed && <span className="text-amber-600">fallback used</span>}
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
          <div ref={bottomRef} />
        </div>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            sendMessage();
          }}
          className="flex items-end gap-2 border-t border-slate-200 p-3"
        >
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
              }
            }}
            rows={1}
            placeholder="Message the gateway…"
            className="max-h-32 flex-1 resize-none rounded-xl border border-slate-200 px-3 py-2 text-sm outline-none focus:border-slate-400"
          />
          <button
            type="submit"
            disabled={sending || !input.trim()}
            className="rounded-xl bg-slate-950 px-4 py-2 text-sm font-semibold text-white disabled:opacity-50"
          >
            Send
          </button>
        </form>
      </div>
    </div>
  );
}
