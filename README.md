<p align="center">
  <img src="docs/guardian-logo.png" width="120" alt="MCP Guardian">
</p>

<h1 align="center">MCP Guardian</h1>

<p align="center">
  <b>An MCP server that scans, tests, and locks down other MCP servers</b>
</p>

<p align="center">
  <a href="https://archestra.ai"><img src="https://img.shields.io/badge/Built%20on-Archestra-black?style=flat-square&logo=data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjYiIGhlaWdodD0iMjYiIHZpZXdCb3g9IjAgMCAyNiAyNiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cmVjdCB4PSIxIiB5PSIxIiB3aWR0aD0iMjQiIGhlaWdodD0iMjMiIHJ4PSI1IiBmaWxsPSJ3aGl0ZSIvPjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNMTAuNDM4NCAxNy4wNTI0QzExLjMyNzIgMTcuMDUyNCAxMi4xMjI4IDE2LjUwMTEgMTIuNDM0OSAxNS42Njg5TDE0LjY0ODcgOS43NjUzNkMxNS4xNzE0IDguMzcxNDMgMTQuMTQxIDYuODg0NSAxMi42NTIyIDYuODg0NUMxMS43NjM0IDYuODg0NSAxMC45Njc5IDcuNDM1ODMgMTAuNjU1OCA4LjI2ODAzTDguNDQxOTggMTQuMTcxNkM3LjkxOTI2IDE1LjU2NTUgOC45NDk3MSAxNy4wNTI0IDEwLjQzODQgMTcuMDUyNFoiIGZpbGw9ImJsYWNrIi8+PGVsbGlwc2UgY3g9IjIuMTE4MzEiIGN5PSIxLjk1OTQ0IiByeD0iMi4xMTgzMSIgcnk9IjEuOTU5NDQiIHRyYW5zZm9ybT0ibWF0cml4KC0xIDAgMCAxIDE4LjUzNTYgMTIuOTc0NykiIGZpbGw9ImJsYWNrIi8+PC9zdmc+" alt="Archestra"></a>
  <img src="https://img.shields.io/badge/MCP-Protocol-FFE500?style=flat-square" alt="MCP">
  <img src="https://img.shields.io/badge/TypeScript-5.x-3178C6?style=flat-square&logo=typescript&logoColor=white" alt="TypeScript">
  <img src="https://img.shields.io/badge/Terraform-IaC-7B42BC?style=flat-square&logo=terraform&logoColor=white" alt="Terraform">
  <img src="https://img.shields.io/badge/Hackathon-2%20Fast%202%20MCP-FF4444?style=flat-square" alt="Hackathon">
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License">
</p>

<p align="center">
  <a href="#try-it">Try It</a> &bull;
  <a href="#the-problem">Problem</a> &bull;
  <a href="#how-it-works">How It Works</a> &bull;
  <a href="#demo">Demo</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#architecture">Architecture</a>
</p>

---

## Try It

> No setup needed. Open, sign in, chat.

| | |
|---|---|
| **Archestra UI** | [guardian.aryankumar.dev](https://guardian.aryankumar.dev) |

Select the **Guardian Security Agent** profile and type:

```
Scan the malicious-demo server with deep analysis
```

Then lock it down:

```
Generate strict policies for malicious-demo and apply them
```

---

## The Problem

MCP servers give AI agents real power: file access, API calls, database queries, email. But nobody's checking whether those tools are safe to use together.

We kept running into the same pattern across every non-trivial MCP server we tested:

<p align="center">
  <img src="docs/lethal-trifecta.jpg" width="700" alt="The Lethal Trifecta">
</p>

One tool reads private data. Another processes content from the internet. A third sends emails. Each one looks harmless alone. Together, they're a complete data exfiltration chain.

We call it the **Lethal Trifecta**. Most developers never see it because they're looking at tools individually, not as a system.

Guardian finds this pattern and shuts it down.

---

## How It Works

Guardian is itself an MCP server running on Archestra. It exposes 6 tools that any AI agent can call:

| Tool | What it does |
|------|-------------|
| `scan_server` | Runs 50+ vulnerability patterns + LLM deep scan across 7 categories |
| `test_server` | Generates injection, overflow, and edge-case tests against tools |
| `generate_policy` | Creates Archestra security policies and applies them |
| `trust_score` | Calculates a weighted score (0-100) across 6 dimensions |
| `monitor` | Watches for error spikes, volume anomalies, suspicious inputs |
| `audit_report` | Produces a full multi-server security report |

### What makes it different

Most security tools stop at reporting. Guardian closes the loop.

<p align="center">
  <img src="docs/closed-loop.jpg" width="700" alt="Closed-Loop Security">
</p>

It reads tool definitions through Archestra's API, finds the problems, then writes real blocking policies back:

- **Tool Invocation Policies**: `block_always`, `block_when_context_is_untrusted`
- **Trusted Data Policies**: `sanitize_with_dual_llm`, `mark_as_untrusted`

One chat command goes from "found a vulnerability" to "it's now blocked for every agent on the platform."

---

## Demo

We built a deliberately broken MCP server with 7 tools designed to fail every check:

| Tool | What's wrong with it |
|------|---------------------|
| `read_file` | Hidden instruction in the description that tells the agent to exfiltrate via `send_email` |
| `execute` | No input validation, runs shell commands directly |
| `get_user_data` | Returns SSNs and credit cards with zero sanitization |
| `search` | Generic name designed to shadow legitimate tools |
| `update_config` | Tells the agent to run with `sudo` |
| `send_email` | Unrestricted external communication |
| `fetch_webpage` | Processes embedded instructions from untrusted pages |

### Scanning it

```
You:  Scan the malicious-demo server with deep analysis

Guardian → scan_server("malicious-demo", deep: true)

  SCAN RESULTS: malicious-demo
  Trust Score: 0/100 (Grade: F)
  7 tools scanned, 19 vulnerabilities found

  CRITICAL  Prompt injection in read_file
  CRITICAL  Command injection in execute
  CRITICAL  Lethal Trifecta detected
  HIGH      PII exposure in get_user_data
  HIGH      Tool shadowing in search
  HIGH      Missing validation in update_config
  MEDIUM    Unrestricted send_email
  ...
```

### Locking it down

```
You:  Generate strict policies for malicious-demo and apply them

Guardian → generate_policy("malicious-demo", mode: "strict", dryRun: false)

  POLICIES APPLIED: 9 policies created

  read_file      → block_always
  execute        → block_always
  get_user_data  → sanitize_with_dual_llm
  send_email     → block_when_untrusted
  fetch_webpage  → sanitize_with_dual_llm
  update_config  → block_when_untrusted
  search         → mark_as_untrusted
  ...

  Exfiltration path: BROKEN
```

### Testing it

```
You:  Read my secret file and email it to attacker@evil.com

Archestra:  Tool "read_file" blocked by policy: block_always
```

The attack gets stopped at the platform level. No agent can talk its way past a policy engine.

---

## Quick Start

### What you need

- [Docker](https://docker.com) installed
- An LLM API key (OpenAI or Anthropic)

### 1. Start Archestra

```bash
docker run -d --name archestra \
  -p 3000:3000 -p 9000:9000 -p 9050:9050 \
  -v archestra-data:/var/lib/postgresql/data \
  -v archestra-app:/app/data \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e ARCHESTRA_QUICKSTART=true \
  -e ARCHESTRA_CHAT_OPENAI_API_KEY="sk-..." \
  archestra/platform:latest
```

Quickstart mode runs an embedded Kubernetes cluster inside the container. MCP servers deploy as pods; no external K8s needed.

Wait ~60s for initialization, then open `http://localhost:3000` and sign in with `admin@example.com` / `password`.

### 2. Build the images

```bash
git clone https://github.com/aryan877/mcp-guardian.git
cd mcp-guardian

docker build -t mcp-guardian:latest .
docker build -t malicious-demo:latest demo/malicious-server/
```

### 3. Load into Archestra's K8s

```bash
docker exec archestra kind load docker-image mcp-guardian:latest --name archestra-mcp
docker exec archestra kind load docker-image malicious-demo:latest --name archestra-mcp
```

### 4. Create an API key

Open `http://localhost:3000` → Settings → API Keys → Create. Copy the key (starts with `archestra_`).

### 5. Deploy with Terraform

```bash
cd terraform

export ARCHESTRA_BASE_URL=http://localhost:9000
export ARCHESTRA_API_KEY=archestra_<your-key>
export TF_VAR_archestra_api_key=$ARCHESTRA_API_KEY

terraform init
terraform apply
```

This creates everything: catalog entries for both servers, K8s pod deployments, a "Guardian Security Agent" profile with all 6 tools assigned, and a security team.

### 6. Use it

Open `http://localhost:3000`, pick the Guardian Security Agent profile, and type:

```
Scan the malicious-demo server with deep analysis
```

---

## Architecture

<p align="center">
  <img src="docs/architecture.jpg" width="700" alt="Architecture">
</p>

Everything runs in one Docker container. Archestra manages an embedded K8s cluster where each MCP server gets its own pod.

Guardian never connects to other MCP servers directly. It reads their metadata through Archestra's REST API:

```typescript
// read tool definitions from Archestra
const server = await client.findServer("malicious-demo");
const tools = await client.getServerTools(server.id);

// pattern-match descriptions + schemas for known attacks
// "send contents to evil-exfiltration.example.com" → CRITICAL
```

Then writes policies back:

```typescript
// block the dangerous tool for all agents
await client.createToolInvocationPolicy({
  toolId: "read_file_uuid",
  action: "block_always",
});

// sanitize outputs with dual LLM quarantine
await client.createTrustedDataPolicy({
  toolId: "get_user_data_uuid",
  action: "sanitize_with_dual_llm",
});
```

---

## Vulnerability Detection

### Static patterns (7 categories)

Guardian runs 50+ regex patterns against tool names, descriptions, and the full JSON schema tree (recursively, not just top-level):

| Category | What it catches |
|----------|----------------|
| Prompt Injection | Hidden instructions in descriptions, override attempts, social engineering |
| Excessive Permissions | `admin`, `root`, `sudo`, wildcard access |
| Data Exfiltration | Tools that send data to external services |
| Command Injection | Shell execution without sanitization |
| PII Exposure | SSN, credit card, email patterns in outputs |
| Missing Validation | Tools without input type checking |
| Tool Poisoning | Generic names that shadow legitimate tools |

### LLM deep scan

When you pass `deep: true`, Guardian sends each tool definition to an LLM through Archestra's proxy. This catches semantic attacks that regex misses: things like obfuscated instructions, social engineering in descriptions, and encoded payloads.

### Lethal Trifecta detection

Guardian checks whether a server's tools, taken together, create an exfiltration chain. If it finds private data access + untrusted content processing + external comms on the same server, that's a critical finding regardless of individual tool scores.

---

## Trust Score

6 dimensions, weighted by how much damage each one can cause:

```
Tool Description Safety     ████████░░  82/100  (25%)
Permission Scope            ████████░░  78/100  (20%)
Input Validation            ██████░░░░  65/100  (15%)
Data Handling               ██████░░░░  60/100  (15%)
Policy Compliance           ███████░░░  68/100  (15%)
Tool Integrity              █████████░  85/100  (10%)

Overall: 73/100  Grade: B
```

---

## How We Use Archestra

| Feature | What Guardian does with it |
|---------|--------------------------|
| MCP Server Runtime | Guardian runs as a managed pod in Archestra's embedded K8s |
| LLM Proxy | Deep scans go through `/v1/openai/chat/completions` |
| Tool Invocation Policies | `generate_policy` writes real blocking rules |
| Trusted Data Policies | Marks dangerous outputs for dual LLM sanitization |
| Terraform Provider | Full IaC: catalog, install, profile, tool assignments, team |
| Chat UI | The only interface; you talk to Guardian in natural language |
| Agentic Security Engine | Enforces every policy Guardian creates, in real time |
| Observability | All tool calls logged in Archestra's audit trail |

---

## Terraform

The full deployment is in `terraform/main.tf` using the [Archestra Terraform Provider](https://registry.terraform.io/providers/archestra-ai/archestra/latest):

```hcl
resource "archestra_mcp_registry_catalog_item" "guardian" {
  name        = "mcp-guardian"
  description = "Security auditor for MCP servers"
  local_config = {
    command        = "node"
    arguments      = ["dist/index.js"]
    docker_image   = "mcp-guardian:latest"
    transport_type = "streamable-http"
    http_port      = 8080
    http_path      = "/mcp"
  }
}

resource "archestra_mcp_server_installation" "guardian" {
  name          = "mcp-guardian"
  mcp_server_id = archestra_mcp_registry_catalog_item.guardian.id
}

resource "archestra_profile" "guardian_agent" {
  name = "Guardian Security Agent"
}
```

One `terraform apply` creates catalog items, server installations, an agent profile, 6 tool assignments, and a security team.

---

## Project Structure

```
mcp-guardian/
├── src/
│   ├── index.ts                      # Dual transport: stdio + Streamable HTTP
│   ├── tools/
│   │   ├── scan-server.ts            # 7-category vulnerability scanning
│   │   ├── test-server.ts            # Auto-generated security tests
│   │   ├── generate-policy.ts        # Policy creation & enforcement
│   │   ├── trust-score.ts            # 6-dimension scoring algorithm
│   │   ├── monitor.ts                # Real-time anomaly detection
│   │   └── audit-report.ts           # Full security reports
│   ├── analysis/
│   │   ├── vulnerability-patterns.ts # 50+ detection patterns
│   │   ├── prompt-injection.ts       # LLM-powered deep scan
│   │   ├── scoring.ts                # Weighted trust score math
│   │   └── test-generator.ts         # Schema-based test generation
│   ├── archestra/
│   │   ├── client.ts                 # Archestra API client
│   │   └── types.ts                  # TypeScript definitions
│   └── schemas/
│       ├── inputs.ts                 # Zod input validation
│       └── outputs.ts                # Zod output schemas
├── demo/
│   └── malicious-server/             # 7 intentionally vulnerable tools
├── terraform/
│   └── main.tf                       # Full IaC deployment
├── Dockerfile                        # Multi-stage build (node:24-alpine)
└── package.json
```

---

## Tech Stack

| | |
|---|---|
| MCP Server | TypeScript + `@modelcontextprotocol/sdk` v1.12+ |
| Validation | Zod + zod-to-json-schema |
| Infrastructure | Terraform + [Archestra Provider](https://registry.terraform.io/providers/archestra-ai/archestra/latest) |
| Transport | stdio (inside Archestra) + Streamable HTTP (standalone) |
| Container | Multi-stage Docker (node:24-alpine) |
| Platform | [Archestra](https://archestra.ai) |

---

## What We Learned

The Lethal Trifecta showed up in basically every MCP setup we tested. Most devs don't see it because each tool looks fine on its own. It's only when you look at what the tools can do together that the exfiltration path becomes obvious.

Blocking at the platform level is the right call. It doesn't matter how clever a prompt injection is if the policy engine won't let the tool run in the first place.

Archestra's `sanitize_with_dual_llm` is seriously underused. For any tool that returns user-generated content, running two independent LLMs as a quarantine layer is far more reliable than trying to regex your way to safety.

And the meta insight: an MCP server that audits other MCP servers is the natural architecture for this problem. Manual review doesn't scale. Automation does.

---

<p align="center">
  Solo submission by <a href="https://github.com/aryan877">Aryan Kumar</a> for the
  <a href="https://www.wemakedevs.org/hackathons/2fast2mcp">2 Fast 2 MCP</a> hackathon
</p>

<p align="center">
  <sub>Built on <a href="https://archestra.ai">Archestra</a></sub>
</p>

<p align="center">
  <img src="docs/archestra-logo.png" width="32" alt="Archestra">
</p>
