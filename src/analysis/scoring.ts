import type { Vulnerability } from "../schemas/outputs.js";
import type { TrustScoreResult } from "../schemas/outputs.js";
import type { McpTool, ToolInvocationPolicy, TrustedDataPolicy } from "../archestra/types.js";

interface ScoringContext {
  tools: McpTool[];
  vulnerabilities: Vulnerability[];
  toolInvocationPolicies: ToolInvocationPolicy[];
  trustedDataPolicies: TrustedDataPolicy[];
}

function scoreToolDescriptionSafety(ctx: ScoringContext): number {
  let score = 100;
  const descVulns = ctx.vulnerabilities.filter(
    (v) =>
      v.category === "Prompt Injection" ||
      v.category === "Prompt Injection (LLM-detected)"
  );
  for (const v of descVulns) {
    switch (v.severity) {
      case "critical":
        score -= 40;
        break;
      case "high":
        score -= 25;
        break;
      case "medium":
        score -= 15;
        break;
      default:
        score -= 5;
    }
  }
  return Math.max(0, score);
}

function scoreInputValidation(ctx: ScoringContext): number {
  let score = 100;
  const validationVulns = ctx.vulnerabilities.filter(
    (v) => v.category === "Missing Input Validation"
  );
  const deduction = validationVulns.length * 10;
  score -= Math.min(deduction, 60);

  // Bonus: tools that have well-defined schemas
  const toolsWithSchemas = ctx.tools.filter(
    (t) =>
      t.inputSchema?.properties &&
      Object.keys(t.inputSchema.properties as object).length > 0
  );
  if (ctx.tools.length > 0) {
    const ratio = toolsWithSchemas.length / ctx.tools.length;
    if (ratio === 1) score = Math.min(score + 10, 100);
  }

  return Math.max(0, score);
}

function scorePermissionScope(ctx: ScoringContext): number {
  let score = 100;
  const permVulns = ctx.vulnerabilities.filter(
    (v) =>
      v.category === "Excessive Permissions" ||
      v.category === "Command Injection"
  );
  for (const v of permVulns) {
    switch (v.severity) {
      case "critical":
        score -= 35;
        break;
      case "high":
        score -= 20;
        break;
      default:
        score -= 10;
    }
  }
  return Math.max(0, score);
}

function scoreDataHandling(ctx: ScoringContext): number {
  let score = 100;
  const dataVulns = ctx.vulnerabilities.filter(
    (v) =>
      v.category === "Data Exfiltration Risk" ||
      v.category === "PII Exposure"
  );
  for (const v of dataVulns) {
    switch (v.severity) {
      case "critical":
        score -= 35;
        break;
      case "high":
        score -= 20;
        break;
      case "medium":
        score -= 12;
        break;
      default:
        score -= 5;
    }
  }
  return Math.max(0, score);
}

function scoreErrorHandling(ctx: ScoringContext): number {
  // Without actually calling tools, we estimate based on schema quality
  let score = 80; // default good since we can't easily test this statically
  const hasAnyVuln = ctx.vulnerabilities.length > 0;
  if (!hasAnyVuln) score = 100;
  return score;
}

function scorePolicyCompliance(ctx: ScoringContext): number {
  if (ctx.tools.length === 0) return 100;

  const toolIds = new Set(ctx.tools.map((t) => t.id));
  const coveredByInvocation = new Set(
    ctx.toolInvocationPolicies
      .filter((p) => toolIds.has(p.toolId))
      .map((p) => p.toolId)
  );
  const coveredByData = new Set(
    ctx.trustedDataPolicies
      .filter((p) => toolIds.has(p.toolId))
      .map((p) => p.toolId)
  );

  const coveredTools = new Set([...coveredByInvocation, ...coveredByData]);
  const ratio = coveredTools.size / ctx.tools.length;

  return Math.round(ratio * 100);
}

function computeGrade(score: number): TrustScoreResult["grade"] {
  if (score >= 95) return "A+";
  if (score >= 85) return "A";
  if (score >= 70) return "B";
  if (score >= 55) return "C";
  if (score >= 40) return "D";
  return "F";
}

function generateRecommendations(
  ctx: ScoringContext,
  breakdown: TrustScoreResult["breakdown"]
): string[] {
  const recs: string[] = [];

  if (breakdown.toolDescriptionSafety < 70) {
    recs.push(
      "CRITICAL: Review all tool descriptions for hidden instructions or prompt injection patterns"
    );
  }
  if (breakdown.inputValidation < 70) {
    recs.push(
      "Add proper input validation with type constraints, maxLength, and patterns to all tool schemas"
    );
  }
  if (breakdown.permissionScope < 70) {
    recs.push(
      "Apply least-privilege principle: restrict tool access to only necessary resources"
    );
  }
  if (breakdown.dataHandling < 70) {
    recs.push(
      "Apply trusted data policies (sanitize_with_dual_llm) to tools that handle sensitive data"
    );
  }
  if (breakdown.policyCompliance < 50) {
    recs.push(
      "Configure Archestra security policies for all tools. Use generate_policy to auto-create recommended policies."
    );
  }
  if (ctx.vulnerabilities.some((v) => v.category === "Tool Poisoning")) {
    recs.push(
      "Resolve tool naming conflicts to prevent tool shadowing attacks"
    );
  }

  if (recs.length === 0) {
    recs.push("Server is well-configured. Continue monitoring for changes.");
  }

  return recs;
}

export function calculateTrustScore(ctx: ScoringContext): TrustScoreResult {
  const breakdown = {
    toolDescriptionSafety: scoreToolDescriptionSafety(ctx),
    inputValidation: scoreInputValidation(ctx),
    permissionScope: scorePermissionScope(ctx),
    dataHandling: scoreDataHandling(ctx),
    errorHandling: scoreErrorHandling(ctx),
    policyCompliance: scorePolicyCompliance(ctx),
  };

  // Weighted average
  const overallScore = Math.round(
    breakdown.toolDescriptionSafety * 0.25 +
      breakdown.inputValidation * 0.2 +
      breakdown.permissionScope * 0.2 +
      breakdown.dataHandling * 0.15 +
      breakdown.errorHandling * 0.1 +
      breakdown.policyCompliance * 0.1
  );

  const serverName =
    ctx.tools[0]?.serverName ?? "unknown";

  return {
    serverName,
    overallScore,
    breakdown,
    grade: computeGrade(overallScore),
    recommendations: generateRecommendations(ctx, breakdown),
  };
}
