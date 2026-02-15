import { z } from "zod";

export const ScanServerInput = z.object({
  serverName: z
    .string()
    .describe("Name of the installed MCP server to scan"),
  deep: z
    .boolean()
    .optional()
    .default(false)
    .describe("Run deep analysis with LLM-based prompt injection detection"),
});

export const TestServerInput = z.object({
  serverName: z.string().describe("Name of the MCP server to test"),
  toolName: z
    .string()
    .optional()
    .describe("Specific tool to test (all if omitted)"),
  testTypes: z
    .array(
      z.enum([
        "valid_input",
        "edge_cases",
        "malformed_input",
        "injection",
        "overflow",
      ])
    )
    .optional()
    .default(["valid_input", "malformed_input"]),
});

export const GeneratePolicyInput = z.object({
  serverName: z.string().describe("Name of the MCP server"),
  mode: z
    .enum(["recommended", "strict", "permissive"])
    .default("recommended")
    .describe("Policy strictness mode"),
  dryRun: z
    .boolean()
    .optional()
    .default(true)
    .describe("If true, show policies without applying"),
});

export const TrustScoreInput = z.object({
  serverName: z
    .string()
    .describe("Name of the MCP server to score"),
});

export const MonitorInput = z.object({
  serverName: z
    .string()
    .optional()
    .describe("Specific server to monitor (all if omitted)"),
  lookbackMinutes: z
    .number()
    .optional()
    .default(60)
    .describe("How far back to check"),
  alertThresholds: z
    .object({
      errorRate: z.number().optional().default(0.1),
      callsPerMinute: z.number().optional().default(100),
      suspiciousPatterns: z.boolean().optional().default(true),
    })
    .optional(),
});

export const AuditReportInput = z.object({
  serverName: z
    .string()
    .optional()
    .describe("Specific server (all servers if omitted)"),
  format: z
    .enum(["markdown", "json"])
    .optional()
    .default("markdown"),
  includeRecommendations: z.boolean().optional().default(true),
});
