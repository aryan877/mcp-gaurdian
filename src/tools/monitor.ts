// monitor: pulls recent tool call logs from Archestra and checks for
// anomalies — high error rates, unusual call volumes, and suspicious
// input patterns (like SQL injection or prompt injection attempts in
// the actual runtime arguments).

import { zodToJsonSchema } from "zod-to-json-schema";
import { MonitorInput } from "../schemas/inputs.js";
import type { MonitorResult } from "../schemas/outputs.js";
import { getClient } from "../archestra/client.js";
import { log, LogLevel } from "../common/logger.js";

export async function monitor(
  args: unknown
): Promise<MonitorResult> {
  const parsed = MonitorInput.parse(args);
  const { serverName, lookbackMinutes } = parsed;
  // default thresholds: flag if >10% errors, >100 calls/min, or known attack patterns
  const thresholds = parsed.alertThresholds ?? {
    errorRate: 0.1,
    callsPerMinute: 100,
    suspiciousPatterns: true,
  };

  log(LogLevel.INFO, `Monitoring tool calls`, {
    serverName: serverName || "all",
    lookbackMinutes,
  });

  const client = getClient();
  const toolCalls = await client.getToolCalls();

  const cutoff = new Date(
    Date.now() - lookbackMinutes * 60 * 1000
  ).toISOString();
  const recentCalls = toolCalls.filter((tc) => tc.timestamp >= cutoff);

  const filteredCalls = serverName
    ? recentCalls.filter(
        (tc) => tc.serverName?.toLowerCase() === serverName.toLowerCase()
      )
    : recentCalls;

  const serverGroups = new Map<string, typeof filteredCalls>();
  for (const call of filteredCalls) {
    const name = call.serverName || "unknown";
    if (!serverGroups.has(name)) serverGroups.set(name, []);
    serverGroups.get(name)!.push(call);
  }

  const servers: MonitorResult["servers"] = [];

  for (const [srvName, calls] of serverGroups) {
    const errorCount = calls.filter((c) => c.error).length;
    const errorRate = calls.length > 0 ? errorCount / calls.length : 0;

    const toolCallCounts = new Map<string, number>();
    for (const c of calls) {
      toolCallCounts.set(c.toolName, (toolCallCounts.get(c.toolName) || 0) + 1);
    }

    const topTools = Array.from(toolCallCounts.entries())
      .map(([name, count]) => ({ name, calls: count }))
      .sort((a, b) => b.calls - a.calls)
      .slice(0, 5);

    const alerts: MonitorResult["servers"][0]["alerts"] = [];

    if (errorRate > thresholds.errorRate) {
      alerts.push({
        type: "high_error_rate",
        severity: errorRate > 0.5 ? "critical" : "warning",
        description: `Error rate ${(errorRate * 100).toFixed(1)}% exceeds threshold ${(thresholds.errorRate * 100).toFixed(1)}%`,
        timestamp: new Date().toISOString(),
      });
    }

    const callsPerMinute = calls.length / lookbackMinutes;
    if (callsPerMinute > thresholds.callsPerMinute) {
      alerts.push({
        type: "unusual_volume",
        severity: callsPerMinute > thresholds.callsPerMinute * 5 ? "critical" : "warning",
        description: `${callsPerMinute.toFixed(1)} calls/min exceeds threshold ${thresholds.callsPerMinute}/min`,
        timestamp: new Date().toISOString(),
      });
    }

    if (thresholds.suspiciousPatterns) {
      const suspiciousPatterns = [
        /ignore\s+previous/i,
        /drop\s+table/i,
        /\.\.\/\.\.\//,
        /<script>/i,
        /exec\s*\(/i,
      ];

      for (const call of calls) {
        const argsStr = JSON.stringify(call.arguments || {});
        for (const pattern of suspiciousPatterns) {
          if (pattern.test(argsStr)) {
            alerts.push({
              type: "suspicious_input",
              severity: "critical",
              description: `Suspicious pattern "${pattern.source}" detected in call to ${call.toolName}`,
              timestamp: call.timestamp,
            });
            break;
          }
        }
      }
    }

    servers.push({
      serverName: srvName,
      totalCalls: calls.length,
      errorCount,
      errorRate: Math.round(errorRate * 1000) / 1000,
      topTools,
      alerts,
    });
  }

  return { timeRange: `Last ${lookbackMinutes} minutes`, servers };
}

export const monitorTool = {
  name: "monitor",
  description:
    "Monitor MCP tool calls in real-time for suspicious patterns, high error rates, unusual call volumes, and security anomalies. Analyzes recent tool call history from Archestra and generates alerts.",
  inputSchema: zodToJsonSchema(MonitorInput),
  handler: monitor,
};
