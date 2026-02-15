#!/usr/bin/env node
// MCP Guardian server entry point. Supports two transports:
// - stdio (default): used when deployed inside Archestra's K8s cluster
// - streamable-http: used for standalone mode + the dashboard talks to this

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { tools, executeTool } from "./tools/index.js";
import { formatError } from "./common/errors.js";
import { VERSION } from "./common/version.js";
import { log, LogLevel } from "./common/logger.js";
import express from "express";
import cors from "cors";

function createServer() {
  const server = new Server(
    { name: "mcp-guardian", version: VERSION },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: tools.map((t) => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema,
    })),
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const toolName = request.params.name;
    const startTime = Date.now();

    try {
      if (!request.params.arguments) {
        return {
          content: [{ type: "text", text: "Error: Arguments are required" }],
          isError: true,
        };
      }

      log(LogLevel.INFO, `Executing tool: ${toolName}`);
      const result = await executeTool(toolName, request.params.arguments);
      log(LogLevel.INFO, `Tool completed: ${toolName}`, { duration: `${Date.now() - startTime}ms` });

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    } catch (error) {
      log(LogLevel.ERROR, `Tool failed: ${toolName}`, {
        duration: `${Date.now() - startTime}ms`,
        error: error instanceof Error ? error.message : String(error),
      });

      if (error instanceof z.ZodError) {
        return {
          content: [{ type: "text", text: `Invalid input: ${JSON.stringify(error.errors)}` }],
          isError: true,
        };
      }

      return {
        content: [{ type: "text", text: formatError(error) }],
        isError: true,
      };
    }
  });

  return server;
}

const transportMode = process.env.TRANSPORT || "stdio";

async function runServer() {
  log(LogLevel.INFO, `MCP Guardian v${VERSION} — ${tools.length} tools`);

  if (transportMode === "sse") {
    const app = express();
    const port = parseInt(process.env.PORT || "8080", 10);

    app.use(cors({
      origin: process.env.CORS_ORIGIN || "*",
      methods: "GET, POST, OPTIONS",
      allowedHeaders: "Content-Type, Authorization",
    }));
    app.use(express.json({ limit: "1mb" }));

    app.get("/health", (_req, res) => {
      res.json({ status: "ok", version: VERSION, transport: "streamable-http", tools: tools.length });
    });

    app.post("/mcp", async (req, res) => {
      const server = createServer();
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    });

    app.get("/mcp", async (req, res) => {
      const server = createServer();
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
      await server.connect(transport);
      await transport.handleRequest(req, res);
    });

    app.listen(port, () => {
      log(LogLevel.INFO, `Streamable HTTP on port ${port}`);
    });
  } else {
    const server = createServer();
    const transport = new StdioServerTransport();
    await server.connect(transport);
    log(LogLevel.INFO, "Running on stdio");
  }
}

runServer().catch((error) => {
  log(LogLevel.ERROR, `Fatal: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});
