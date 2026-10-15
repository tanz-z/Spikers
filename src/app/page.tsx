import { ChatPlayground } from "@/components/ChatPlayground";
import { listModelCatalog } from "@/lib/gateway/models";

export const dynamic = "force-dynamic";

export default function HomePage() {
  const aliases = listModelCatalog();

  return (
    <main className="mx-auto max-w-5xl px-6 py-10">
      <div className="mx-auto mb-8 max-w-3xl text-center">
        <p className="text-sm font-medium uppercase tracking-[0.1em] text-slate-500">Gateway Playground</p>
        <h1 className="mt-2 text-3xl font-semibold text-slate-950 sm:text-4xl">
          One endpoint. Every model. Built-in fallback.
        </h1>
        <p className="mt-3 text-sm text-slate-600 sm:text-base">
          This chat talks to <code className="rounded bg-white px-1.5 py-0.5">/api/v1/chat/completions</code> - the
          same gateway endpoint your own apps would call - instead of hitting any LLM provider directly.
        </p>
      </div>
      <ChatPlayground aliases={aliases} />
    </main>
  );
}
