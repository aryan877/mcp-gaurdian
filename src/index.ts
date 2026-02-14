#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { tools, executeTool } from "./tools/index.js";
import { z } from "zod";
import { isGuardianError, formatError } from "./common/errors.js";
import { VERSION } from "./common/version.js";
import { log, LogLevel } from "./common/logger.js";
import express from "express";
import cors from "cors";

function createServer() {
  const server = new Server(
    { name: "mcp-guardian", version: VERSION },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    log(LogLevel.DEBUG, "Handling ListToolsRequest");
    return {
      tools: tools.map((t) => ({
        name: t.name,
        description: t.description,
        inputSchema: t.inputSchema,
      })),
    };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const toolName = request.params.name;
    const startTime = Date.now();

    try {
      log(LogLevel.INFO, `Executing tool: ${toolName}`);

      if (!request.params.arguments) {
        return {
          content: [{ type: "text", text: "Error: Arguments are required" }],
          isError: true,
        };
      }

      const result = await executeTool(toolName, request.params.arguments);
      const duration = Date.now() - startTime;

      log(LogLevel.INFO, `Tool completed: ${toolName}`, {
        duration: `${duration}ms`,
      });

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    } catch (error) {
      const duration = Date.now() - startTime;
      log(LogLevel.ERROR, `Tool failed: ${toolName}`, {
        duration: `${duration}ms`,
        error: error instanceof Error ? error.message : String(error),
      });

      if (error instanceof z.ZodError) {
        return {
          content: [
            {
              type: "text",
              text: `Invalid input: ${JSON.stringify(error.errors)}`,
            },
          ],
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

// Transport selection
const transportMode = process.env.TRANSPORT || "stdio";

log(LogLevel.INFO, `Registering ${tools.length} Guardian tools`);

async function runServer() {
  if (transportMode === "sse") {
    log(LogLevel.INFO, "Starting Guardian in Streamable HTTP mode");

    const app = express();
    const port = parseInt(process.env.PORT || "8080", 10);

    app.use(
      cors({
        origin: process.env.CORS_ORIGIN || "*",
        methods: "GET, POST, OPTIONS",
        allowedHeaders: "Content-Type, Authorization",
      })
    );
    app.use(express.json({ limit: "1mb" }));

    // Health check
    app.get("/health", (_req, res) => {
      res.status(200).json({
        status: "ok",
        version: VERSION,
        transport: "streamable-http",
        tools: tools.length,
      });
    });

    // Streamable HTTP transport (stateless - new server per request)
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
      log(
        LogLevel.INFO,
        `MCP Guardian running in Streamable HTTP mode on port ${port}`
      );
    });
  } else {
    log(LogLevel.INFO, "Starting Guardian in stdio mode");
    const server = createServer();
    const transport = new StdioServerTransport();
    await server.connect(transport);
    log(LogLevel.INFO, "MCP Guardian running on stdio");
  }
}

runServer().catch((error) => {
  log(LogLevel.ERROR, `Fatal error: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});
