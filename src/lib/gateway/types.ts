export type ChatRole = "system" | "user" | "assistant";

export type ChatMessage = {
  role: ChatRole;
  content: string;
};

export type ChatOptions = {
  temperature?: number;
  maxTokens?: number;
  signal?: AbortSignal;
};

export type UsageTokens = {
  promptTokens: number;
  completionTokens: number;
};

export type StreamChunk = { type: "delta"; text: string } | { type: "usage"; usage: UsageTokens };
