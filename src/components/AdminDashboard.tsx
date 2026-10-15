"use client";

import { useEffect, useState } from "react";

type ApiKeyRecord = {
  id: string;
  name: string;
  keyPrefix: string;
  allowedModels: string[];
  rpmLimit: number;
  dailyTokenLimit: number | null;
  budgetUsd: string | null;
  spentUsd: string;
  isActive: boolean;
  createdAt: string;
  lastUsedAt: string | null;
  requestsLast24h: number;
  tokensLast24h: number;
};

type LogRecord = {
  id: string;
  apiKeyName: string | null;
  requestedModel: string;
  resolvedProvider: string | null;
  resolvedModel: string | null;
  status: string;
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
  costUsd: string;
  latencyMs: number;
  stream: boolean;
  errorMessage: string | null;
  createdAt: string;
};

type Stats = {
  totals: { requests: number; successes: number; tokens: number; costUsd: string; avgLatencyMs: number };
  last24h: { requests: number; tokens: number; costUsd: string };
  byModel: { provider: string | null; model: string | null; requests: number; tokens: number; costUsd: string }[];
  byStatus: { status: string; count: number }[];
};

type AliasCatalog = {
  id: string;
  label: string;
  description: string;
  candidates: { provider: string; model: string; configured: boolean; envVar: string | null }[];
};

const TABS = ["Keys", "Logs", "Routing"] as const;

function adminHeaders(adminToken: string) {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (adminToken) headers["x-admin-token"] = adminToken;
  return headers;
}

export function AdminDashboard() {
  const [tab, setTab] = useState<(typeof TABS)[number]>("Keys");
  const [adminToken, setAdminToken] = useState("");
  const [keys, setKeys] = useState<ApiKeyRecord[] | null>(null);
  const [logs, setLogs] = useState<LogRecord[] | null>(null);
  const [stats, setStats] = useState<Stats | null>(null);
  const [catalog, setCatalog] = useState<AliasCatalog[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [newKeyBanner, setNewKeyBanner] = useState<string | null>(null);
  const [form, setForm] = useState({ name: "", rpmLimit: 30, dailyTokenLimit: "", budgetUsd: "" });
  const [busy, setBusy] = useState(false);

  async function loadAll() {
    setError(null);
    try {
      const [keysRes, statsRes, catalogRes] = await Promise.all([
        fetch("/api/admin/keys", { headers: adminHeaders(adminToken) }),
        fetch("/api/admin/stats", { headers: adminHeaders(adminToken) }),
        fetch("/api/admin/models", { headers: adminHeaders(adminToken) }),
      ]);
      if (keysRes.status === 401 || statsRes.status === 401) {
        setError("Admin token required (set GATEWAY_ADMIN_TOKEN and enter it below, or leave both blank in dev).");
        return;
      }
      setKeys((await keysRes.json()).keys);
      setStats(await statsRes.json());
      setCatalog((await catalogRes.json()).aliases);
      const logsRes = await fetch("/api/admin/logs?limit=100", { headers: adminHeaders(adminToken) });
      setLogs((await logsRes.json()).logs);
    } catch {
      setError("Failed to load admin data.");
    }
  }

  useEffect(() => {
    loadAll();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function createKey(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/admin/keys", {
        method: "POST",
        headers: adminHeaders(adminToken),
        body: JSON.stringify({
          name: form.name || "Untitled key",
          rpmLimit: Number(form.rpmLimit) || 30,
          dailyTokenLimit: form.dailyTokenLimit ? Number(form.dailyTokenLimit) : null,
          budgetUsd: form.budgetUsd ? Number(form.budgetUsd) : null,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data?.error ?? "Failed to create key");
      setNewKeyBanner(data.key);
      setForm({ name: "", rpmLimit: 30, dailyTokenLimit: "", budgetUsd: "" });
      await loadAll();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function toggleActive(key: ApiKeyRecord) {
    await fetch(`/api/admin/keys/${key.id}`, {
      method: "PATCH",
      headers: adminHeaders(adminToken),
      body: JSON.stringify({ isActive: !key.isActive }),
    });
    await loadAll();
  }

  async function deleteKey(key: ApiKeyRecord) {
    if (!confirm(`Revoke and delete "${key.name}"? This cannot be undone.`)) return;
    await fetch(`/api/admin/keys/${key.id}`, { method: "DELETE", headers: adminHeaders(adminToken) });
    await loadAll();
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-3 rounded-2xl border border-slate-200 bg-white p-3 text-sm">
        <span className="text-slate-500">Admin token (optional, matches GATEWAY_ADMIN_TOKEN):</span>
        <input
          value={adminToken}
          onChange={(e) => setAdminToken(e.target.value)}
          placeholder="leave blank if unset"
          className="w-56 rounded-lg border border-slate-200 px-2 py-1"
        />
        <button onClick={loadAll} className="rounded-lg bg-slate-950 px-3 py-1.5 text-white">
          Refresh
        </button>
        {error && <span className="text-rose-600">{error}</span>}
      </div>

      {stats && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <StatCard label="Total requests" value={stats.totals.requests.toLocaleString()} />
          <StatCard
            label="Success rate"
            value={
              stats.totals.requests > 0
                ? `${Math.round((stats.totals.successes / stats.totals.requests) * 100)}%`
                : "—"
            }
          />
          <StatCard label="Total tokens" value={stats.totals.tokens.toLocaleString()} />
          <StatCard label="Total cost" value={`$${Number(stats.totals.costUsd).toFixed(4)}`} />
        </div>
      )}

      {newKeyBanner && (
        <div className="rounded-2xl border border-emerald-200 bg-emerald-50 p-4 text-sm">
          <p className="font-medium text-emerald-800">Save this key now - it won&apos;t be shown again:</p>
          <div className="mt-2 flex items-center gap-2">
            <code className="flex-1 overflow-x-auto rounded-lg bg-white px-3 py-2">{newKeyBanner}</code>
            <button
              onClick={() => navigator.clipboard.writeText(newKeyBanner)}
              className="rounded-lg bg-emerald-700 px-3 py-2 text-white"
            >
              Copy
            </button>
            <button onClick={() => setNewKeyBanner(null)} className="rounded-lg px-3 py-2 text-emerald-800">
              Dismiss
            </button>
          </div>
        </div>
      )}

      <div className="flex gap-1 border-b border-slate-200">
        {TABS.map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`rounded-t-lg px-4 py-2 text-sm font-medium ${
              tab === t ? "border-b-2 border-slate-950 text-slate-950" : "text-slate-500 hover:text-slate-800"
            }`}
          >
            {t}
          </button>
        ))}
      </div>

      {tab === "Keys" && (
        <div className="space-y-6">
          <form onSubmit={createKey} className="grid gap-3 rounded-2xl border border-slate-200 bg-white p-4 sm:grid-cols-5">
            <input
              placeholder="Key name"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              className="rounded-lg border border-slate-200 px-3 py-2 text-sm sm:col-span-2"
            />
            <input
              type="number"
              placeholder="RPM limit"
              value={form.rpmLimit}
              onChange={(e) => setForm({ ...form, rpmLimit: Number(e.target.value) })}
              className="rounded-lg border border-slate-200 px-3 py-2 text-sm"
            />
            <input
              type="number"
              placeholder="Daily token limit"
              value={form.dailyTokenLimit}
              onChange={(e) => setForm({ ...form, dailyTokenLimit: e.target.value })}
              className="rounded-lg border border-slate-200 px-3 py-2 text-sm"
            />
            <input
              type="number"
              step="0.01"
              placeholder="Budget USD"
              value={form.budgetUsd}
              onChange={(e) => setForm({ ...form, budgetUsd: e.target.value })}
              className="rounded-lg border border-slate-200 px-3 py-2 text-sm"
            />
            <button
              type="submit"
              disabled={busy}
              className="rounded-lg bg-slate-950 px-3 py-2 text-sm font-semibold text-white sm:col-span-5"
            >
              {busy ? "Creating…" : "Create API key"}
            </button>
          </form>

          <div className="overflow-x-auto rounded-2xl border border-slate-200 bg-white">
            <table className="w-full min-w-[720px] text-left text-sm">
              <thead className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="px-4 py-3">Name</th>
                  <th className="px-4 py-3">Key</th>
                  <th className="px-4 py-3">RPM</th>
                  <th className="px-4 py-3">Today</th>
                  <th className="px-4 py-3">Spent</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Actions</th>
                </tr>
              </thead>
              <tbody>
                {keys?.map((k) => (
                  <tr key={k.id} className="border-b border-slate-100 last:border-0">
                    <td className="px-4 py-3 font-medium">{k.name}</td>
                    <td className="px-4 py-3">
                      <code className="text-xs text-slate-500">{k.keyPrefix}…</code>
                    </td>
                    <td className="px-4 py-3">{k.rpmLimit}/min</td>
                    <td className="px-4 py-3">
                      {k.requestsLast24h} reqs · {k.tokensLast24h} tok
                    </td>
                    <td className="px-4 py-3">
                      ${Number(k.spentUsd).toFixed(4)}
                      {k.budgetUsd ? ` / $${Number(k.budgetUsd).toFixed(2)}` : ""}
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`rounded-full px-2 py-1 text-xs font-medium ${
                          k.isActive ? "bg-emerald-50 text-emerald-700" : "bg-slate-100 text-slate-500"
                        }`}
                      >
                        {k.isActive ? "active" : "revoked"}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex gap-2">
                        <button onClick={() => toggleActive(k)} className="text-xs underline">
                          {k.isActive ? "revoke" : "reactivate"}
                        </button>
                        <button onClick={() => deleteKey(k)} className="text-xs text-rose-600 underline">
                          delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
                {keys?.length === 0 && (
                  <tr>
                    <td colSpan={7} className="px-4 py-6 text-center text-slate-400">
                      No keys yet - create one above.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab === "Logs" && (
        <div className="overflow-x-auto rounded-2xl border border-slate-200 bg-white">
          <table className="w-full min-w-[920px] text-left text-sm">
            <thead className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="px-4 py-3">Time</th>
                <th className="px-4 py-3">Key</th>
                <th className="px-4 py-3">Requested</th>
                <th className="px-4 py-3">Resolved</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Tokens</th>
                <th className="px-4 py-3">Cost</th>
                <th className="px-4 py-3">Latency</th>
              </tr>
            </thead>
            <tbody>
              {logs?.map((l) => (
                <tr key={l.id} className="border-b border-slate-100 last:border-0 align-top">
                  <td className="px-4 py-3 whitespace-nowrap text-xs text-slate-500">
                    {new Date(l.createdAt).toLocaleString()}
                  </td>
                  <td className="px-4 py-3">{l.apiKeyName ?? "—"}</td>
                  <td className="px-4 py-3">{l.requestedModel}</td>
                  <td className="px-4 py-3">
                    {l.resolvedProvider ? `${l.resolvedProvider}:${l.resolvedModel}` : "—"}
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`rounded-full px-2 py-1 text-xs font-medium ${
                        l.status === "success" ? "bg-emerald-50 text-emerald-700" : "bg-rose-50 text-rose-700"
                      }`}
                      title={l.errorMessage ?? undefined}
                    >
                      {l.status}
                    </span>
                  </td>
                  <td className="px-4 py-3">{l.totalTokens}</td>
                  <td className="px-4 py-3">${Number(l.costUsd).toFixed(6)}</td>
                  <td className="px-4 py-3">{l.latencyMs}ms</td>
                </tr>
              ))}
              {logs?.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-4 py-6 text-center text-slate-400">
                    No requests logged yet - send a message from the Playground.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {tab === "Routing" && (
        <div className="grid gap-4 sm:grid-cols-2">
          {catalog?.map((alias) => (
            <div key={alias.id} className="rounded-2xl border border-slate-200 bg-white p-4">
              <p className="font-semibold text-slate-950">{alias.label}</p>
              <p className="mt-0.5 text-xs text-slate-500">{alias.id}</p>
              <p className="mt-2 text-sm text-slate-600">{alias.description}</p>
              <ol className="mt-3 space-y-1.5 text-sm">
                {alias.candidates.map((c, i) => (
                  <li key={`${c.provider}-${c.model}`} className="flex items-center gap-2">
                    <span className="text-xs text-slate-400">{i + 1}.</span>
                    <span
                      className={`h-2 w-2 rounded-full ${c.configured ? "bg-emerald-500" : "bg-slate-300"}`}
                      title={c.configured ? "configured" : `set ${c.envVar} to enable`}
                    />
                    <code className="text-xs">
                      {c.provider}:{c.model}
                    </code>
                    {!c.configured && c.envVar && (
                      <span className="text-xs text-slate-400">needs {c.envVar}</span>
                    )}
                  </li>
                ))}
              </ol>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function StatCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-4">
      <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
      <p className="mt-1 text-2xl font-semibold text-slate-950">{value}</p>
    </div>
  );
}
