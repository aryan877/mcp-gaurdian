// generate_policy: this is the "closed loop" — we take scan results and
// translate each vulnerability into an Archestra security policy. In strict
// mode, critical things get block_always. In recommended mode, we use
// block_when_context_is_untrusted so the tool still works in safe contexts.
// Supports dry-run (preview) or live application via the Archestra API.

import { zodToJsonSchema } from "zod-to-json-schema";
import { GeneratePolicyInput } from "../schemas/inputs.js";
import type { PolicyResult } from "../schemas/outputs.js";
import { getClient } from "../archestra/client.js";
import { log, LogLevel } from "../common/logger.js";
import { scanServer } from "./scan-server.js";
import type { Vulnerability } from "../schemas/outputs.js";

interface PolicyRecommendation {
  type: "tool_invocation" | "trusted_data";
  toolName: string;
  toolId: string;
  action: string;
  reason: string;
}

function mapVulnerabilityToPolicy(
  vuln: Vulnerability,
  toolId: string,
  mode: "recommended" | "strict" | "permissive"
): PolicyRecommendation[] {
  const policies: PolicyRecommendation[] = [];

  switch (vuln.category) {
    case "Prompt Injection":
    case "Prompt Injection (LLM-detected)":
      if (mode === "strict" || vuln.severity === "critical") {
        policies.push({
          type: "tool_invocation",
          toolName: vuln.tool,
          toolId,
          action: "block_always",
          reason: `Critical prompt injection detected: ${vuln.description}`,
        });
      } else if (mode === "recommended") {
        policies.push({
          type: "tool_invocation",
          toolName: vuln.tool,
          toolId,
          action: "block_when_context_is_untrusted",
          reason: `Prompt injection risk: ${vuln.description}`,
        });
      }
      break;

    case "Data Exfiltration Risk":
      policies.push({
        type: "trusted_data",
        toolName: vuln.tool,
        toolId,
        action:
          mode === "permissive"
            ? "mark_as_untrusted"
            : "sanitize_with_dual_llm",
        reason: `Data exfiltration risk: ${vuln.description}`,
      });
      break;

    case "PII Exposure":
      policies.push({
        type: "trusted_data",
        toolName: vuln.tool,
        toolId,
        action:
          mode === "strict"
            ? "sanitize_with_dual_llm"
            : "mark_as_untrusted",
        reason: `PII exposure risk: ${vuln.description}`,
      });
      break;

    case "Excessive Permissions":
    case "Command Injection":
      if (mode !== "permissive") {
        policies.push({
          type: "tool_invocation",
          toolName: vuln.tool,
          toolId,
          action:
            mode === "strict"
              ? "block_always"
              : "block_when_context_is_untrusted",
          reason: `Security risk: ${vuln.description}`,
        });
      }
      break;

    case "Missing Input Validation":
      if (mode === "strict") {
        policies.push({
          type: "tool_invocation",
          toolName: vuln.tool,
          toolId,
          action: "block_when_context_is_untrusted",
          reason: `Missing input validation: ${vuln.description}`,
        });
      }
      break;

    case "ANSI/Steganography Attack":
      policies.push({
        type: "tool_invocation",
        toolName: vuln.tool,
        toolId,
        action: "block_always",
        reason: `Hidden content attack: ${vuln.description}`,
      });
      break;

    case "Path Traversal":
      policies.push({
        type: "tool_invocation",
        toolName: vuln.tool,
        toolId,
        action: mode === "permissive" ? "block_when_context_is_untrusted" : "block_always",
        reason: `Path traversal risk: ${vuln.description}`,
      });
      break;

    case "Tool Shadowing":
      if (mode !== "permissive") {
        policies.push({
          type: "tool_invocation",
          toolName: vuln.tool,
          toolId,
          action: "block_when_context_is_untrusted",
          reason: `Tool shadowing risk: ${vuln.description}`,
        });
      }
      break;

    case "Lethal Trifecta":
      policies.push({
        type: "tool_invocation",
        toolName: vuln.tool,
        toolId,
        action: "block_when_context_is_untrusted",
        reason: `Lethal Trifecta: ${vuln.description}`,
      });
      break;
  }

  return policies;
}

export async function generatePolicy(
  args: unknown
): Promise<PolicyResult> {
  const { serverName, mode, dryRun } = GeneratePolicyInput.parse(args);
  log(LogLevel.INFO, `Generating policies for ${serverName}`, { mode, dryRun });

  const scanResult = await scanServer({ serverName, deep: false });

  const client = getClient();
  const server = await client.findServer(serverName);
  const tools = await client.getServerTools(server.id);

  const toolIdMap = new Map<string, string>();
  for (const tool of tools) {
    toolIdMap.set(tool.name, tool.id);
  }

  const recommendations: PolicyRecommendation[] = [];
  const seen = new Set<string>();

  for (const vuln of scanResult.vulnerabilities) {
    const toolId = toolIdMap.get(vuln.tool) || vuln.tool;
    for (const p of mapVulnerabilityToPolicy(vuln, toolId, mode)) {
      const key = `${p.toolName}:${p.type}:${p.action}`;
      if (!seen.has(key)) {
        seen.add(key);
        recommendations.push(p);
      }
    }
  }

  const appliedPolicies = [];
  for (const rec of recommendations) {
    let applied = false;

    if (!dryRun) {
      try {
        if (rec.type === "tool_invocation") {
          await client.createToolInvocationPolicy({
            toolId: rec.toolId,
            action: rec.action as any,
          });
        } else {
          await client.createTrustedDataPolicy({
            toolId: rec.toolId,
            action: rec.action as any,
          });
        }
        applied = true;
        log(LogLevel.INFO, `Applied policy: ${rec.type} ${rec.action} on ${rec.toolName}`);
      } catch (error) {
        log(LogLevel.ERROR, `Failed to apply policy for ${rec.toolName}`, {
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }

    appliedPolicies.push({
      type: rec.type,
      toolName: rec.toolName,
      action: rec.action,
      reason: rec.reason,
      applied,
    });
  }

  return {
    serverName,
    policiesGenerated: appliedPolicies.length,
    policies: appliedPolicies,
  };
}

export const generatePolicyTool = {
  name: "generate_policy",
  description:
    "Auto-generate and optionally apply Archestra security policies (tool invocation + trusted data) based on vulnerability scan results. Supports recommended, strict, and permissive modes. Defaults to dry-run (preview only).",
  inputSchema: zodToJsonSchema(GeneratePolicyInput),
  handler: generatePolicy,
};
