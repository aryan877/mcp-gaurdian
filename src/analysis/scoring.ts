// Full trust score calculation across 6 dimensions. Each dimension is scored
// 0-100 independently, then we weight them and combine into an overall score.
// If there's any critical vulnerability, the score gets capped at 40 (grade D).
// The idea is: you can't be "mostly safe" if you have a critical hole.

import type { Vulnerability } from "../schemas/outputs.js";
import type { TrustScoreResult } from "../schemas/outputs.js";
import type {
  McpTool,
  ToolInvocationPolicy,
  TrustedDataPolicy,
} from "../archestra/types.js";

interface ScoringContext {
  tools: McpTool[];
  vulnerabilities: Vulnerability[];
  toolInvocationPolicies: ToolInvocationPolicy[];
  trustedDataPolicies: TrustedDataPolicy[];
}

// each function below scores one dimension out of 100
function scoreToolDescriptionSafety(ctx: ScoringContext): number {
  let score = 100;
  const descVulns = ctx.vulnerabilities.filter(
    (v) =>
      v.category === "Prompt Injection" ||
      v.category === "Prompt Injection (LLM-detected)" ||
      v.category === "ANSI/Steganography Attack"
  );
  for (const v of descVulns) {
    score -= v.severity === "critical" ? 40 : v.severity === "high" ? 25 : 15;
  }
  return Math.max(0, score);
}

function scoreInputValidation(ctx: ScoringContext): number {
  let score = 100;
  const validationVulns = ctx.vulnerabilities.filter(
    (v) => v.category === "Missing Input Validation"
  );
  score -= Math.min(validationVulns.length * 10, 60);

  // give a small bonus if all tools actually define their schemas properly
  if (ctx.tools.length > 0) {
    const withSchemas = ctx.tools.filter(
      (t) =>
        t.inputSchema?.properties &&
        Object.keys(t.inputSchema.properties as object).length > 0
    );
    if (withSchemas.length === ctx.tools.length) score = Math.min(score + 10, 100);
  }

  return Math.max(0, score);
}

function scorePermissionScope(ctx: ScoringContext): number {
  let score = 100;
  const permVulns = ctx.vulnerabilities.filter(
    (v) =>
      v.category === "Excessive Permissions" ||
      v.category === "Command Injection" ||
      v.category === "Path Traversal"
  );
  for (const v of permVulns) {
    score -= v.severity === "critical" ? 35 : v.severity === "high" ? 20 : 10;
  }
  return Math.max(0, score);
}

function scoreDataHandling(ctx: ScoringContext): number {
  let score = 100;
  const dataVulns = ctx.vulnerabilities.filter(
    (v) =>
      v.category === "Data Exfiltration Risk" ||
      v.category === "PII Exposure" ||
      v.category === "Lethal Trifecta"
  );
  for (const v of dataVulns) {
    score -= v.severity === "critical" ? 40 : v.severity === "high" ? 20 : 12;
  }
  return Math.max(0, score);
}

function scoreToolIntegrity(ctx: ScoringContext): number {
  let score = 100;
  const integrityVulns = ctx.vulnerabilities.filter(
    (v) => v.category === "Tool Shadowing"
  );
  for (const v of integrityVulns) {
    score -= v.severity === "high" ? 25 : v.severity === "medium" ? 15 : 10;
  }
  return Math.max(0, score);
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
  return Math.round((coveredTools.size / ctx.tools.length) * 100);
}

function computeGrade(score: number): TrustScoreResult["grade"] {
  if (score >= 95) return "A+";
  if (score >= 85) return "A";
  if (score >= 70) return "B";
  if (score >= 55) return "C";
  if (score >= 40) return "D";
  return "F";
}

// plain English recommendations based on which dimensions are weak
function generateRecommendations(
  ctx: ScoringContext,
  breakdown: TrustScoreResult["breakdown"]
): string[] {
  const recs: string[] = [];

  if (ctx.vulnerabilities.some((v) => v.category === "Lethal Trifecta")) {
    recs.push(
      "CRITICAL: Lethal Trifecta detected — apply 'block_when_context_is_untrusted' on external comms tools and 'sanitize_with_dual_llm' on untrusted content tools to break the exfiltration chain"
    );
  }
  if (breakdown.toolDescriptionSafety < 70) {
    recs.push(
      "Review all tool descriptions and schemas for prompt injection, ANSI escapes, and hidden instructions"
    );
  }
  if (breakdown.inputValidation < 70) {
    recs.push(
      "Add type constraints, maxLength, and pattern validation to all tool input schemas"
    );
  }
  if (breakdown.permissionScope < 70) {
    recs.push(
      "Restrict tool access to only necessary resources — apply least-privilege via Archestra policies"
    );
  }
  if (breakdown.dataHandling < 70) {
    recs.push(
      "Apply 'sanitize_with_dual_llm' trusted data policies on tools that handle sensitive data or untrusted content"
    );
  }
  if (breakdown.toolIntegrity < 80) {
    recs.push(
      "Resolve tool naming conflicts — use server-namespaced names to prevent tool shadowing"
    );
  }
  if (breakdown.policyCompliance < 50) {
    recs.push(
      "Configure Archestra security policies for all tools — use generate_policy to auto-create them"
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
    toolIntegrity: scoreToolIntegrity(ctx),
    policyCompliance: scorePolicyCompliance(ctx),
  };

  // weighted by how dangerous each dimension is if it's bad
  let overallScore = Math.round(
    breakdown.toolDescriptionSafety * 0.25 +
      breakdown.inputValidation * 0.15 +
      breakdown.permissionScope * 0.2 +
      breakdown.dataHandling * 0.15 +
      breakdown.toolIntegrity * 0.1 +
      breakdown.policyCompliance * 0.15
  );

  // any critical vuln caps the grade at D — you don't get a B with a critical hole
  const hasCritical = ctx.vulnerabilities.some(
    (v) => v.severity === "critical"
  );
  if (hasCritical) {
    overallScore = Math.min(overallScore, 40);
  }

  const serverName = ctx.tools[0]?.serverName ?? "unknown";

  return {
    serverName,
    overallScore,
    breakdown,
    grade: computeGrade(overallScore),
    recommendations: generateRecommendations(ctx, breakdown),
  };
}
