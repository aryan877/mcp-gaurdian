// Archestra API client. All Guardian tools go through this to talk to the
// platform — listing servers, reading tool definitions, creating policies,
// proxying LLM calls, and pulling tool call logs for monitoring.
// Uses the ARCHESTRA_API_URL and ARCHESTRA_API_KEY env vars.

import axios, { AxiosInstance } from "axios";
import { log, LogLevel } from "../common/logger.js";
import { ArchestraApiError, ServerNotFoundError } from "../common/errors.js";
import type {
  McpServer,
  McpTool,
  ToolInvocationPolicy,
  TrustedDataPolicy,
  McpToolCall,
  LlmChatMessage,
  LlmChatResponse,
} from "./types.js";

export class ArchestraClient {
  private http: AxiosInstance;

  constructor(
    baseUrl: string = process.env.ARCHESTRA_API_URL || "http://localhost:9000",
    token?: string
  ) {
    const apiKey = token || process.env.ARCHESTRA_API_KEY;
    this.http = axios.create({
      baseURL: baseUrl,
      timeout: 30000,
      headers: {
        "Content-Type": "application/json",
        ...(apiKey ? { Authorization: apiKey } : {}),
      },
    });

    this.http.interceptors.response.use(
      (res) => res,
      (err) => {
        const status = err.response?.status ?? 0;
        const message = err.response?.data?.message ?? err.message;
        log(LogLevel.ERROR, `Archestra API error: ${status} ${message}`);
        throw new ArchestraApiError(message, status);
      }
    );
  }

  // --- servers ---

  async listServers(): Promise<McpServer[]> {
    log(LogLevel.DEBUG, "Listing MCP servers");
    const { data } = await this.http.get("/api/mcp_server");
    return data;
  }

  async findServer(serverName: string): Promise<McpServer> {
    const servers = await this.listServers();
    const server = servers.find(
      (s) =>
        s.catalogName?.toLowerCase() === serverName.toLowerCase() ||
        s.name.toLowerCase() === serverName.toLowerCase()
    );
    if (!server) throw new ServerNotFoundError(serverName);
    return server;
  }

  async getServerTools(serverId: string): Promise<McpTool[]> {
    const { data } = await this.http.get(`/api/mcp_server/${serverId}/tools`);
    return data;
  }

  // --- tool invocation policies (block/allow rules) ---

  async listToolInvocationPolicies(): Promise<ToolInvocationPolicy[]> {
    const { data } = await this.http.get("/api/tool-invocation");
    return data;
  }

  async createToolInvocationPolicy(
    policy: ToolInvocationPolicy
  ): Promise<ToolInvocationPolicy> {
    log(LogLevel.INFO, `Creating tool invocation policy`, {
      toolId: policy.toolId,
      action: policy.action,
    });
    const { data } = await this.http.post("/api/tool-invocation", policy);
    return data;
  }

  async updateToolInvocationPolicy(
    id: string,
    policy: Partial<ToolInvocationPolicy>
  ): Promise<ToolInvocationPolicy> {
    const { data } = await this.http.put(`/api/tool-invocation/${id}`, policy);
    return data;
  }

  async deleteToolInvocationPolicy(id: string): Promise<void> {
    await this.http.delete(`/api/tool-invocation/${id}`);
  }

  // --- trusted data policies (sanitize/quarantine rules) ---

  async listTrustedDataPolicies(): Promise<TrustedDataPolicy[]> {
    const { data } = await this.http.get("/api/trusted-data-policies");
    return data;
  }

  async createTrustedDataPolicy(
    policy: TrustedDataPolicy
  ): Promise<TrustedDataPolicy> {
    log(LogLevel.INFO, `Creating trusted data policy`, {
      toolId: policy.toolId,
      action: policy.action,
    });
    const { data } = await this.http.post(
      "/api/trusted-data-policies",
      policy
    );
    return data;
  }

  async updateTrustedDataPolicy(
    id: string,
    policy: Partial<TrustedDataPolicy>
  ): Promise<TrustedDataPolicy> {
    const { data } = await this.http.put(
      `/api/trusted-data-policies/${id}`,
      policy
    );
    return data;
  }

  async deleteTrustedDataPolicy(id: string): Promise<void> {
    await this.http.delete(`/api/trusted-data-policies/${id}`);
  }

  // --- bulk ops ---

  async bulkSetToolInvocationDefault(
    toolIds: string[],
    action: ToolInvocationPolicy["action"]
  ): Promise<void> {
    log(LogLevel.INFO, `Bulk setting tool invocation default`, { count: toolIds.length, action });
    await this.http.post("/api/tool-invocation/bulk-default", { toolIds, action });
  }

  async bulkSetTrustedDataDefault(
    toolIds: string[],
    action: TrustedDataPolicy["action"]
  ): Promise<void> {
    log(LogLevel.INFO, `Bulk setting trusted data default`, { count: toolIds.length, action });
    await this.http.post("/api/trusted-data-policies/bulk-default", { toolIds, action });
  }

  // --- monitoring ---

  async getToolCalls(): Promise<McpToolCall[]> {
    const { data } = await this.http.get("/api/mcp-tool-calls");
    return data;
  }

  // --- LLM proxy (used for deep scan + test evaluation) ---

  async chatCompletion(
    messages: LlmChatMessage[],
    model: string = "gpt-5-mini"
  ): Promise<LlmChatResponse> {
    log(LogLevel.DEBUG, `LLM chat completion via Archestra proxy`, { model });
    const { data } = await this.http.post("/v1/openai/chat/completions", {
      model,
      messages,
      temperature: 0.1,
    });
    return data;
  }
}

// Singleton instance
let _client: ArchestraClient | null = null;

export function getClient(): ArchestraClient {
  if (!_client) {
    _client = new ArchestraClient();
  }
  return _client;
}
