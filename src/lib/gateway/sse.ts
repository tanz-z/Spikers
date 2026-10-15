// Minimal Server-Sent-Events line parser shared by every upstream provider
// adapter. Handles both "data-only" SSE (OpenAI-compatible, Google) and
// "named event" SSE (Anthropic).

export type SseEvent = { event?: string; data: string };

export async function* parseSse(body: ReadableStream<Uint8Array>): AsyncGenerator<SseEvent> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });

      let sepIndex: number;
      // SSE records are separated by a blank line (\n\n). Handle \r\n too.
      while ((sepIndex = buffer.indexOf("\n\n")) !== -1 || (sepIndex = buffer.indexOf("\r\n\r\n")) !== -1) {
        const record = buffer.slice(0, sepIndex);
        buffer = buffer.slice(sepIndex + (buffer[sepIndex] === "\r" ? 4 : 2));
        const evt = parseRecord(record);
        if (evt) yield evt;
      }
    }
    if (buffer.trim()) {
      const evt = parseRecord(buffer);
      if (evt) yield evt;
    }
  } finally {
    reader.releaseLock();
  }
}

function parseRecord(record: string): SseEvent | null {
  let event: string | undefined;
  const dataLines: string[] = [];
  for (const rawLine of record.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith(":")) continue;
    if (line.startsWith("event:")) {
      event = line.slice("event:".length).trim();
    } else if (line.startsWith("data:")) {
      dataLines.push(line.slice("data:".length).trim());
    }
  }
  if (dataLines.length === 0) return null;
  return { event, data: dataLines.join("\n") };
}
