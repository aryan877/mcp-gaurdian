// trust_score: runs a scan, then feeds the vulnerabilities + existing policies
// into the 6-dimension scoring engine. Returns A+ through F with a full
// breakdown of what's strong and what's weak.

import { zodToJsonSchema } from "zod-to-json-schema";
import { TrustScoreInput } from "../schemas/inputs.js";
import type { TrustScoreResult } from "../schemas/outputs.js";
import { getClient } from "../archestra/client.js";
import { log, LogLevel } from "../common/logger.js";
import { scanServer } from "./scan-server.js";
import { calculateTrustScore } from "../analysis/scoring.js";

export async function trustScore(
  args: unknown
): Promise<TrustScoreResult> {
  const { serverName } = TrustScoreInput.parse(args);
  log(LogLevel.INFO, `Calculating trust score for ${serverName}`);

  const client = getClient();
  const scanResult = await scanServer({ serverName, deep: false });

  const server = await client.findServer(serverName);
  const tools = (await client.getServerTools(server.id)).map((t) => ({
    ...t,
    serverName,
  }));

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
  handler: trustScore,
};
