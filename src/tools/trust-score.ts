import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";
import { TrustScoreInput } from "../schemas/inputs.js";
import type { TrustScoreResult } from "../schemas/outputs.js";
import { getClient } from "../archestra/client.js";
import { log, LogLevel } from "../common/logger.js";
import { scanServer } from "./scan-server.js";
import { calculateTrustScore } from "../analysis/scoring.js";
import type { McpTool } from "../archestra/types.js";
import { ServerNotFoundError } from "../common/errors.js";

export async function trustScore(
  args: z.infer<typeof TrustScoreInput>
): Promise<TrustScoreResult> {
  const { serverName } = TrustScoreInput.parse(args);
  log(LogLevel.INFO, `Calculating trust score for ${serverName}`);

  const client = getClient();

  // Get scan results
  const scanResult = await scanServer({ serverName, deep: false });

  // Get server tools
  const servers = await client.listServers();
  const server = servers.find(
    (s) => s.name.toLowerCase() === serverName.toLowerCase()
  );
  if (!server) throw new ServerNotFoundError(serverName);

  // Collect tools
  const agents = await client.listAgents();
  const tools: McpTool[] = [];
  for (const agent of agents) {
    try {
      const agentTools = await client.getAgentTools(agent.id);
      tools.push(
        ...agentTools
          .filter((t) => t.serverId === server.id || t.serverName === serverName)
          .map((t) => ({ ...t, serverName }))
      );
    } catch {
      // skip
    }
  }

  // Get existing policies
  const [toolInvocationPolicies, trustedDataPolicies] = await Promise.all([
    client.listToolInvocationPolicies(),
    client.listTrustedDataPolicies(),
  ]);

  const result = calculateTrustScore({
    tools,
    vulnerabilities: scanResult.vulnerabilities,
    toolInvocationPolicies,
    trustedDataPolicies,
  });

  log(LogLevel.INFO, `Trust score for ${serverName}: ${result.overallScore} (${result.grade})`);

  return result;
}

export const trustScoreTool = {
  name: "trust_score",
  description:
    "Calculate a comprehensive trust score (0-100) for an MCP server with detailed breakdown across 6 dimensions: tool description safety, input validation, permission scope, data handling, error handling, and policy compliance. Returns a letter grade (A+ to F) with recommendations.",
  inputSchema: zodToJsonSchema(TrustScoreInput),
  handler: async (args: unknown) => {
    const parsed = TrustScoreInput.parse(args);
    return await trustScore(parsed);
  },
};
