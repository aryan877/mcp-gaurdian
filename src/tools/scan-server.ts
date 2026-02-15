// scan_server: the main entry point for vulnerability scanning.
// Pulls the server's tool list from Archestra, runs every tool through
// the pattern matcher, checks for the Lethal Trifecta across all tools,
// and optionally runs deep LLM analysis on each tool definition.

import { zodToJsonSchema } from "zod-to-json-schema";
import { ScanServerInput } from "../schemas/inputs.js";
import type { ScanResult } from "../schemas/outputs.js";
import { getClient } from "../archestra/client.js";
import { log, LogLevel } from "../common/logger.js";
import {
  analyzeToolVulnerabilities,
  calculateBasicTrustScore,
  detectLethalTrifecta,
} from "../analysis/vulnerability-patterns.js";
import { analyzeWithLlm } from "../analysis/prompt-injection.js";

export async function scanServer(
  args: unknown
): Promise<ScanResult> {
  const { serverName, deep } = ScanServerInput.parse(args);
  log(LogLevel.INFO, `Scanning server: ${serverName}`, { deep });

  const client = getClient();
  const server = await client.findServer(serverName);
  const tools = (await client.getServerTools(server.id)).map((t) => ({
    ...t,
    serverName,
  }));

  log(LogLevel.INFO, `Found ${tools.length} tools on server "${serverName}"`);

  const allVulnerabilities = [];

  for (const tool of tools) {
    allVulnerabilities.push(...analyzeToolVulnerabilities(tool, tools));
  }

  allVulnerabilities.push(...detectLethalTrifecta(tools));

  if (deep) {
    log(LogLevel.INFO, "Running deep LLM-based analysis...");
    for (const tool of tools) {
      allVulnerabilities.push(...(await analyzeWithLlm(tool)));
    }
  }

  const trustScore = calculateBasicTrustScore(allVulnerabilities);

  const result: ScanResult = {
    serverName,
    toolCount: tools.length,
    vulnerabilities: allVulnerabilities,
    trustScore,
    scannedAt: new Date().toISOString(),
  };

  log(LogLevel.INFO, `Scan complete: ${serverName}`, {
    vulnerabilities: allVulnerabilities.length,
    trustScore,
  });

  return result;
}

export const scanServerTool = {
  name: "scan_server",
  description:
    "Analyze an MCP server's tools for security vulnerabilities including prompt injection, excessive permissions, data exfiltration risks, command injection, PII exposure, and missing input validation. Returns a vulnerability report with trust score.",
  inputSchema: zodToJsonSchema(ScanServerInput),
  handler: scanServer,
};
