import { AdminDashboard } from "@/components/AdminDashboard";

export const dynamic = "force-dynamic";

export default function AdminPage() {
  return (
    <main className="mx-auto max-w-6xl px-6 py-10">
      <div className="mb-8">
        <p className="text-sm font-medium uppercase tracking-[0.1em] text-slate-500">Gateway Admin</p>
        <h1 className="mt-2 text-3xl font-semibold text-slate-950">Keys, usage & routing</h1>
        <p className="mt-2 max-w-2xl text-sm text-slate-600">
          Issue virtual API keys for client apps, watch every request the gateway proxies, and see which upstream
          providers are wired up.
        </p>
      </div>
      <AdminDashboard />
    </main>
  );
}
