// tool registry — all 6 Guardian tools registered here

import { scanServerTool } from "./scan-server.js";
import { testServerTool } from "./test-server.js";
import { generatePolicyTool } from "./generate-policy.js";
import { trustScoreTool } from "./trust-score.js";
import { monitorTool } from "./monitor.js";
import { auditReportTool } from "./audit-report.js";

export const tools = [
  scanServerTool,
  testServerTool,
  generatePolicyTool,
  trustScoreTool,
  monitorTool,
  auditReportTool,
];

const toolMap = new Map(tools.map((t) => [t.name, t]));

export async function executeTool(toolName: string, args: unknown) {
  const tool = toolMap.get(toolName);
  if (!tool) throw new Error(`Tool "${toolName}" not found`);
  return await tool.handler(args);
}
