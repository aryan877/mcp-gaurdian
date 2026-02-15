// Types for the Archestra platform API responses.
// These map directly to what the API returns.

export interface McpServer {
  id: string;
  name: string;
  catalogName?: string;
  description?: string;
  status?: string;
  localInstallationStatus?: string;
  createdAt?: string;
  updatedAt?: string;
  config?: Record<string, unknown>;
}

export interface McpTool {
  id: string;
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  serverId?: string;
  serverName?: string;
}

export interface ToolInvocationPolicy {
  id?: string;
  toolId: string;
  toolName?: string;
  serverName?: string;
  action: "allow_when_context_is_untrusted" | "block_when_context_is_untrusted" | "block_always";
}

export interface TrustedDataPolicy {
  id?: string;
  toolId: string;
  toolName?: string;
  serverName?: string;
  action: "mark_as_trusted" | "mark_as_untrusted" | "block_always" | "sanitize_with_dual_llm";
}

export interface McpToolCall {
  id: string;
  toolName: string;
  serverName: string;
  arguments: Record<string, unknown>;
  result?: unknown;
  error?: string;
  duration?: number;
  timestamp: string;
}

export interface LlmChatMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface LlmChatResponse {
  choices: Array<{
    message: {
      role: string;
      content: string;
    };
  }>;
}
