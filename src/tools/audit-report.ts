// audit_report: the "run everything" tool. Scans all servers, calculates
// trust scores, pulls monitoring data, and assembles it into a single
// markdown or JSON report with an executive summary.

import { zodToJsonSchema } from "zod-to-json-schema";
import { AuditReportInput } from "../schemas/inputs.js";
import type { AuditReportResult, ScanResult, Vulnerability } from "../schemas/outputs.js";
import { getClient } from "../archestra/client.js";
import { log, LogLevel } from "../common/logger.js";
import { scanServer } from "./scan-server.js";
import { trustScore } from "./trust-score.js";
import { monitor } from "./monitor.js";

function countBySeverity(vulns: Vulnerability[]) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const v of vulns) {
    if (v.severity in counts) counts[v.severity as keyof typeof counts]++;
  }
  return counts;
}

function generateMarkdownReport(
  scans: ScanResult[],
  trustScores: Array<{ serverName: string; score: number; grade: string }>,
  monitorData: { servers: Array<{ serverName: string; totalCalls: number; errorRate: number; alerts: unknown[] }> },
  policiesConfigured: number,
  policiesMissing: number
): string {
  const allVulns = scans.flatMap((s) => s.vulnerabilities);
  const severity = countBySeverity(allVulns);

  const avgScore =
    trustScores.length > 0
      ? Math.round(trustScores.reduce((sum, ts) => sum + ts.score, 0) / trustScores.length)
      : 0;

  let md = `# MCP Guardian Security Audit Report\n\n`;
  md += `**Generated**: ${new Date().toISOString()}\n\n---\n\n`;

  md += `## Executive Summary\n\n`;
  md += `- **Servers Audited**: ${scans.length}\n`;
  md += `- **Total Vulnerabilities**: ${allVulns.length}\n`;
  md += `- **Critical Issues**: ${severity.critical}\n`;
  md += `- **Average Trust Score**: ${avgScore}/100\n`;
  md += `- **Policies Configured**: ${policiesConfigured}\n`;
  md += `- **Policies Missing**: ${policiesMissing}\n\n`;

  md += `## Server Breakdown\n\n`;
  for (const scan of scans) {
    const ts = trustScores.find((t) => t.serverName === scan.serverName);
    md += `### ${scan.serverName}\n\n`;
    md += `- **Trust Score**: ${ts?.score ?? "N/A"}/100 (${ts?.grade ?? "N/A"})\n`;
    md += `- **Tools**: ${scan.toolCount}\n`;
    md += `- **Vulnerabilities**: ${scan.vulnerabilities.length}\n\n`;

    if (scan.vulnerabilities.length > 0) {
      md += `| Severity | Category | Tool | Description |\n`;
      md += `|----------|----------|------|-------------|\n`;
      for (const v of scan.vulnerabilities) {
        md += `| ${v.severity.toUpperCase()} | ${v.category} | ${v.tool} | ${v.description.substring(0, 80)}... |\n`;
      }
      md += `\n`;
    }
  }

  if (monitorData.servers.length > 0) {
    md += `## Recent Activity\n\n`;
    for (const srv of monitorData.servers) {
      md += `- **${srv.serverName}**: ${srv.totalCalls} calls, ${(srv.errorRate * 100).toFixed(1)}% error rate, ${srv.alerts.length} alerts\n`;
    }
    md += `\n`;
  }

  md += `## Recommendations\n\n`;
  if (severity.critical > 0) {
    md += `1. **URGENT**: Address ${severity.critical} critical vulnerabilities immediately\n`;
  }
  if (policiesMissing > 0) {
    md += `${severity.critical > 0 ? "2" : "1"}. Configure Archestra security policies for ${policiesMissing} uncovered tools (use \`generate_policy\`)\n`;
  }
  md += `- Run periodic scans to detect new vulnerabilities\n`;
  md += `- Monitor tool call patterns for anomalies\n`;
  md += `- Apply Dual LLM sanitization for tools handling sensitive data\n`;

  return md;
}

export async function auditReport(
  args: unknown
): Promise<AuditReportResult> {
  const { serverName, format } = AuditReportInput.parse(args);
  log(LogLevel.INFO, `Generating audit report`, { serverName, format });

  const client = getClient();

  let serverNames: string[];
  if (serverName) {
    serverNames = [serverName];
  } else {
    const servers = await client.listServers();
    serverNames = servers.map((s) => s.catalogName || s.name);
  }

  const scans: ScanResult[] = [];
  for (const name of serverNames) {
    try {
      scans.push(await scanServer({ serverName: name, deep: false }));
    } catch (error) {
      log(LogLevel.WARN, `Failed to scan ${name}`, {
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  const trustScores: Array<{ serverName: string; score: number; grade: string }> = [];
  for (const name of serverNames) {
    try {
      const result = await trustScore({ serverName: name });
      trustScores.push({
        serverName: name,
        score: result.overallScore,
        grade: result.grade,
      });
    } catch {
      // skip servers that fail trust scoring
    }
  }

  let monitorData: Awaited<ReturnType<typeof monitor>> = {
    timeRange: "Last 60 minutes",
    servers: [],
  };
  try {
    monitorData = await monitor({ lookbackMinutes: 60 });
  } catch {
    // monitoring is optional
  }

  const [invocationPolicies, dataPolicies] = await Promise.all([
    client.listToolInvocationPolicies(),
    client.listTrustedDataPolicies(),
  ]);
  const policiesConfigured = invocationPolicies.length + dataPolicies.length;
  const totalTools = scans.reduce((sum, s) => sum + s.toolCount, 0);
  const policiesMissing = Math.max(0, totalTools - policiesConfigured);

  const allVulns = scans.flatMap((s) => s.vulnerabilities);
  const severity = countBySeverity(allVulns);

  const avgTrustScore =
    trustScores.length > 0
      ? Math.round(trustScores.reduce((sum, ts) => sum + ts.score, 0) / trustScores.length)
      : 0;

  let report: string;
  if (format === "json") {
    report = JSON.stringify({ scans, trustScores, monitoring: monitorData, policiesConfigured, policiesMissing }, null, 2);
  } else {
    report = generateMarkdownReport(scans, trustScores, monitorData, policiesConfigured, policiesMissing);
  }

  return {
    generatedAt: new Date().toISOString(),
    summary: {
      totalServers: scans.length,
      totalTools,
      totalVulnerabilities: allVulns.length,
      criticalCount: severity.critical,
      highCount: severity.high,
      mediumCount: severity.medium,
      lowCount: severity.low,
      averageTrustScore: avgTrustScore,
      policiesConfigured,
      policiesMissing,
    },
    report,
  };
}

export const auditReportTool = {
  name: "audit_report",
  description:
    "Generate a comprehensive security audit report for all (or a specific) MCP servers. Combines vulnerability scans, trust scores, monitoring data, and policy compliance into a formatted report (markdown or JSON).",
  inputSchema: zodToJsonSchema(AuditReportInput),
  handler: auditReport,
};
