import Link from "next/link";

export function Nav() {
  return (
    <header className="border-b border-slate-200 bg-white/80 backdrop-blur">
      <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
        <Link href="/" className="flex items-center gap-2 font-semibold text-slate-950">
          <span className="grid h-8 w-8 place-items-center rounded-lg bg-slate-950 text-sm text-white">⌁</span>
          <span>LLM Gateway</span>
        </Link>
        <nav className="flex items-center gap-1 text-sm font-medium text-slate-600">
          <Link href="/" className="rounded-lg px-3 py-2 hover:bg-slate-100 hover:text-slate-950">
            Playground
          </Link>
          <Link href="/admin" className="rounded-lg px-3 py-2 hover:bg-slate-100 hover:text-slate-950">
            Admin Dashboard
          </Link>
          <a
            href="/api/v1/chat/completions"
            className="ml-2 rounded-lg border border-slate-200 px-3 py-2 text-slate-500"
            title="POST endpoint - call it with your API key"
          >
            /api/v1/chat/completions
          </a>
        </nav>
      </div>
    </header>
  );
}
