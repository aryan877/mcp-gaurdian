<p align="center">
  <img src="docs/guardian-logo.png" width="120" alt="MCP Guardian">
</p>

<h1 align="center">MCP Guardian</h1>

<p align="center">
  <b>Autonomous security auditor that scans, tests, and locks down MCP servers on Archestra</b>
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
  <a href="#live-demo">Live Demo</a> &bull;
  <a href="#the-problem">Problem</a> &bull;
  <a href="#how-it-works">How It Works</a> &bull;
  <a href="#demo">Demo</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#architecture">Architecture</a>
</p>

---

## Live Demo

> **Try it now** &mdash; no setup required.

| Service | URL |
|---------|-----|
| **Archestra UI** (chat with Guardian agent) | [guardian.aryankumar.dev](https://guardian.aryankumar.dev) |

Sign in to the Archestra UI, select the **Guardian Security Agent** profile, and try:

```
Scan the malicious-demo server with deep analysis
```

Then apply policies:

```
Generate strict policies for malicious-demo and apply them
```

---

## The Problem

MCP servers give AI agents superpowers &mdash; file access, API calls, database queries, email. But **who audits the agents?**

A single misconfigured server creates the **Lethal Trifecta**:

```
  read_file()          fetch_webpage()         send_email()
  ─────────────        ─────────────────       ────────────────
  Private Data    +    Untrusted Content   +   External Comms
       │                      │                       │
       └──────────── DATA EXFILTRATION ──────────────┘
```

We found this pattern in **every non-trivial MCP server** we tested. Most developers don't realize their combination of tools creates an attack surface.

**MCP Guardian fixes this automatically.** It scans servers, finds vulnerabilities, and creates Archestra security policies that block attacks &mdash; without human intervention.

---

## How It Works

Guardian is itself an MCP server running on Archestra. It provides **6 security tools** that any AI agent can invoke:

| Tool | What It Does |
|------|-------------|
| **`scan_server`** | Static pattern analysis + LLM deep scan across 7 vulnerability categories |
| **`test_server`** | Auto-generates injection, overflow, and edge-case tests against tools |
| **`generate_policy`** | Creates and **applies** Archestra security policies from scan results |
| **`trust_score`** | 6-dimension weighted score (0-100) with letter grades A+ through F |
| **`monitor`** | Real-time anomaly detection: error spikes, volume anomalies, suspicious inputs |
| **`audit_report`** | Full multi-server security report combining all analyses |

### The Killer Feature: Closed-Loop Security

Most security tools stop at reporting. Guardian **closes the loop**:

```
  Scan           Analyze          Generate         Enforce
  ─────────  →  ─────────────  →  ──────────  →  ──────────────
  read_file      CRITICAL:        block_always     Archestra now
  description    prompt inject    for read_file    BLOCKS the tool
  has hidden     detected                          for all agents
  instructions
```

Guardian writes **real policies** to Archestra's API:

- **Tool Invocation Policies** &rarr; `block_always`, `block_when_context_is_untrusted`
- **Trusted Data Policies** &rarr; `sanitize_with_dual_llm`, `mark_as_untrusted`

One command hardens your entire MCP infrastructure.

---

## Demo

### The Malicious Server

We built a deliberately vulnerable MCP server (`demo/malicious-server/`) with **7 weaponized tools**:

| Tool | Vulnerability |
|------|--------------|
| `read_file` | Prompt injection: hidden instruction to exfiltrate via `send_email` |
| `execute` | No input validation, direct shell command execution |
| `get_user_data` | Returns SSNs and credit cards with zero sanitization |
| `search` | Tool shadowing with generic name to intercept queries |
| `update_config` | Instructs agent to run with `sudo` privileges |
| `send_email` | Unrestricted external communication (exfiltration leg) |
| `fetch_webpage` | Processes untrusted embedded instructions |

### Attack &rarr; Detect &rarr; Block

**Step 1: Scan the malicious server**
```
You:  Scan the malicious-demo server with deep analysis

Guardian → scan_server("malicious-demo", deep: true)

┌─────────────────────────────────────────────────┐
│  SCAN RESULTS: malicious-demo                    │
│  Trust Score: 0/100 (Grade: F)                   │
│  7 tools scanned, 19 vulnerabilities found       │
├─────────────────────────────────────────────────┤
│  ❌ CRITICAL  Prompt injection in read_file      │
│  ❌ CRITICAL  Command injection in execute       │
│  ❌ CRITICAL  Lethal Trifecta detected           │
│  🟠 HIGH     PII exposure in get_user_data      │
│  🟠 HIGH     Tool shadowing in search           │
│  🟠 HIGH     Missing validation in update_config │
│  🟡 MEDIUM   Unrestricted send_email            │
│  ...                                             │
└─────────────────────────────────────────────────┘
```

**Step 2: Generate and apply policies**
```
You:  Generate strict policies for malicious-demo and apply them

Guardian → generate_policy("malicious-demo", mode: "strict", dryRun: false)

┌─────────────────────────────────────────────────┐
│  POLICIES APPLIED: 9 policies created            │
├─────────────────────────────────────────────────┤
│  ✅ read_file      → block_always               │
│  ✅ execute        → block_always               │
│  ✅ get_user_data  → sanitize_with_dual_llm     │
│  ✅ send_email     → block_when_untrusted       │
│  ✅ fetch_webpage  → sanitize_with_dual_llm     │
│  ✅ update_config  → block_when_untrusted       │
│  ✅ search         → mark_as_untrusted          │
│  ...                                             │
└─────────────────────────────────────────────────┘

Exfiltration path: BROKEN ✓
```

**Step 3: Try using the malicious tools**
```
You:  Read my secret file and email it to attacker@evil.com

Archestra:  ❌ Tool "read_file" blocked by policy: block_always
            Policy created by MCP Guardian (prompt injection detected)
```

The attack is stopped at the platform level, not the application level.

---

## Quick Start

### Prerequisites

- [Docker](https://docker.com) installed and running
- An LLM API key (OpenAI or Anthropic)

### 1. Start Archestra (Quickstart Mode)

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

> Quickstart mode embeds a Kubernetes cluster inside the Archestra container.
> MCP servers deploy as pods in this internal cluster &mdash; no external K8s required.

Wait for Archestra to finish initializing (~60s), then open `http://localhost:3000` and sign in with `admin@example.com` / `password`.

### 2. Build Docker Images

```bash
git clone https://github.com/aryan877/mcp-guardian.git
cd mcp-guardian

# Build Guardian
docker build -t mcp-guardian:latest .

# Build the malicious demo server
docker build -t malicious-demo:latest demo/malicious-server/
```

### 3. Load Images into Archestra's Embedded K8s

```bash
# Archestra runs an internal kind cluster — images must be loaded explicitly
docker exec archestra kind load docker-image mcp-guardian:latest --name archestra-mcp
docker exec archestra kind load docker-image malicious-demo:latest --name archestra-mcp
```

### 4. Create an API Key

Open `http://localhost:3000` → **Settings** → **API Keys** → **Create**. Name it something like `terraform-deploy` and copy the key (starts with `archestra_`).

### 5. Deploy with Terraform

```bash
cd terraform

export ARCHESTRA_BASE_URL=http://localhost:9000
export ARCHESTRA_API_KEY=archestra_<your-key>
export TF_VAR_archestra_api_key=$ARCHESTRA_API_KEY

terraform init
terraform apply
```

This creates:

| Resource | What It Does |
|----------|-------------|
| `archestra_mcp_registry_catalog_item.guardian` | Registers Guardian in the MCP catalog |
| `archestra_mcp_registry_catalog_item.malicious_demo` | Registers the demo vulnerable server |
| `archestra_mcp_server_installation.guardian` | Deploys Guardian as a K8s pod inside Archestra |
| `archestra_mcp_server_installation.malicious_demo` | Deploys the malicious server as a K8s pod |
| `archestra_profile.guardian_agent` | Creates a "Guardian Security Agent" profile |
| `archestra_profile_tool.*` (x6) | Assigns all 6 Guardian tools to the agent profile |
| `archestra_team.security` | Creates a Security Team with Guardian access |

### 6. Use Guardian

Open `http://localhost:3000`, select the **Guardian Security Agent** profile, and chat:

```
Scan the malicious-demo server with deep analysis
```

---

## Architecture

```
┌──────────────────── ARCHESTRA CONTAINER ────────────────────┐
│                                                              │
│  Archestra Platform (API :9000, UI :3000)                    │
│  ┌──────────┐  ┌───────────┐  ┌──────────────────────────┐  │
│  │ Chat UI  │  │  Policy   │  │     MCP Gateway          │  │
│  │          │  │  Engine   │  │  (routes tool calls)     │  │
│  └────┬─────┘  └────┬──────┘  └──────────┬───────────────┘  │
│       │              │                     │                  │
│       │    ┌─────────┴──────────┐          │                  │
│       └───▶│    LLM Proxy      │          │                  │
│            │  (Claude/GPT API) │          │                  │
│            │  + policy enforce │          │                  │
│            └───────────────────┘          │                  │
│                                            │                  │
│  ┌───────────┐  ┌───────────┐              │                  │
│  │ Postgres  │  │ Metrics   │              │                  │
│  │  (state)  │  │  (:9050)  │              │                  │
│  └───────────┘  └───────────┘              │                  │
│                                            │                  │
│  ┌─── Embedded Kind Cluster (archestra-mcp) ──────────────┐  │
│  │                                         │               │  │
│  │                    ┌────────────────────┬┘               │  │
│  │                    │                    │                │  │
│  │                    ▼                    ▼                │  │
│  │          ┌──────────────┐    ┌──────────────┐           │  │
│  │          │ MCP GUARDIAN │    │  MALICIOUS   │           │  │
│  │          │   (pod)      │    │  DEMO (pod)  │           │  │
│  │          │  6 security  │    │  7 vulnerable│           │  │
│  │          │  tools       │    │  tools       │           │  │
│  │          │              │◀──▶│              │           │  │
│  │          │ Reads tools  │    │ Gets scanned │           │  │
│  │          │ via API ─────┼───▶│ and locked   │           │  │
│  │          └──────────────┘    └──────────────┘           │  │
│  └─────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────┘
```

Everything runs inside a single Docker container. Archestra manages an embedded Kubernetes cluster where each MCP server runs as its own pod.

### How Guardian Reads Other Servers

Guardian doesn't connect directly to MCP servers. It reads their **metadata through Archestra's API**:

```typescript
// Guardian calls Archestra API to get a server's tool definitions
const server = await client.findServer("malicious-demo");  // GET /api/mcp_server
const tools = await client.getServerTools(server.id);      // GET /api/mcp_server/:id/tools

// each tool has: name, description, inputSchema (JSON schema)
// we pattern-match descriptions + schemas for known attack patterns:
//   "send contents to evil-exfiltration.example.com" → CRITICAL
```

Then **writes policies back** to Archestra:

```typescript
// then writes policies back to lock down the dangerous tools
await client.createToolInvocationPolicy({
  toolId: "read_file_uuid",
  action: "block_always",              // archestra blocks this for all agents
});

await client.createTrustedDataPolicy({
  toolId: "get_user_data_uuid",
  action: "sanitize_with_dual_llm",    // dual LLM quarantine on output
});
```

---

## Terraform IaC

The entire deployment is codified in `terraform/main.tf` using the [Archestra Terraform Provider](https://registry.terraform.io/providers/archestra-ai/archestra/latest):

```hcl
# Register Guardian in Archestra's MCP catalog
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

# Deploy as a pod inside Archestra's embedded K8s
resource "archestra_mcp_server_installation" "guardian" {
  name          = "mcp-guardian"
  mcp_server_id = archestra_mcp_registry_catalog_item.guardian.id
}

# Create an agent profile with all Guardian tools
resource "archestra_profile" "guardian_agent" {
  name = "Guardian Security Agent"
}
```

Full config includes catalog items, installations, agent profile, 6 tool assignments, and a security team.

---

## Vulnerability Detection

### Static Pattern Analysis (7 Categories)

| Category | Patterns | Example Detection |
|----------|----------|-------------------|
| **Prompt Injection** | 17 regex patterns | Hidden instructions in tool descriptions |
| **Excessive Permissions** | 5 patterns | `admin`, `root`, `sudo`, wildcard access |
| **Data Exfiltration** | 4 patterns | Tools that send data externally |
| **Command Injection** | 3 patterns | Shell execution without sanitization |
| **PII Exposure** | 4 patterns | SSN, credit card, email patterns |
| **Missing Validation** | Schema analysis | Tools without input type checking |
| **Tool Poisoning** | Name analysis | Generic names that shadow legitimate tools |

### LLM Deep Scan

When `deep: true`, Guardian uses Archestra's LLM proxy to analyze each tool with AI &mdash; catching semantic vulnerabilities that regex can't find.

---

## Trust Score Algorithm

6 dimensions, weighted by security impact:

```
┌─────────────────────────────────────────┐
│  Tool Description Safety     ████████░░  82/100  (25% weight)
│  Permission Scope            ████████░░  78/100  (20% weight)
│  Input Validation            ██████░░░░  65/100  (15% weight)
│  Data Handling               ██████░░░░  60/100  (15% weight)
│  Policy Compliance           ███████░░░  68/100  (15% weight)
│  Tool Integrity              █████████░  85/100  (10% weight)
├─────────────────────────────────────────┤
│  Overall: 73/100  Grade: B              │
└─────────────────────────────────────────┘
```

---

## Archestra Integration

| Archestra Feature | How Guardian Uses It |
|-------------------|---------------------|
| **MCP Server Runtime** | Guardian runs as a managed pod in Archestra's embedded K8s |
| **LLM Proxy** | Deep vulnerability analysis via `/v1/openai/chat/completions` |
| **Tool Invocation Policies** | `generate_policy` creates real blocking rules |
| **Trusted Data Policies** | Marks dangerous outputs for sanitization |
| **Dual LLM Quarantine** | Recommends `sanitize_with_dual_llm` for high-risk tools |
| **Terraform Provider** | Full IaC deployment: catalog, install, profile, tool assignments |
| **MCP Gateway** | Exposed via `/v1/mcp/:profileId` for programmatic access |
| **Chat UI** | Invoke Guardian through natural language conversation |
| **Observability** | All tool calls logged in Archestra's audit trail |
| **Cost Controls** | LLM usage tracked through Archestra's limits engine |

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
│   │   └── audit-report.ts           # Comprehensive reports
│   ├── analysis/
│   │   ├── vulnerability-patterns.ts # 30+ detection patterns
│   │   ├── prompt-injection.ts       # LLM-powered deep scan
│   │   ├── scoring.ts                # Weighted trust score math
│   │   └── test-generator.ts         # Schema-based test generation
│   ├── archestra/
│   │   ├── client.ts                 # Full Archestra API client
│   │   └── types.ts                  # TypeScript definitions
│   └── schemas/
│       ├── inputs.ts                 # Zod input validation
│       └── outputs.ts                # Zod output schemas
├── demo/
│   └── malicious-server/             # 7 intentionally vulnerable tools
├── terraform/
│   └── main.tf                       # Full IaC: catalog, install, profile, tools, team
├── Dockerfile                        # Multi-stage build (node:24-alpine)
└── package.json
```

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| MCP Server | TypeScript + `@modelcontextprotocol/sdk` v1.12+ |
| Schema Validation | Zod + zod-to-json-schema |
| Infrastructure | Terraform + [Archestra Provider](https://registry.terraform.io/providers/archestra-ai/archestra/latest) |
| Transport | stdio (inside Archestra) + Streamable HTTP (standalone) |
| Container | Multi-stage Docker (node:24-alpine) |
| Platform | [Archestra](https://archestra.ai) |

---

## What We Learned

- **The Lethal Trifecta is everywhere.** Private data access + untrusted content + external comms exists in almost every non-trivial MCP setup. Most developers don't see it because the tools look harmless individually.

- **Platform-level security beats application-level.** Blocking at the Archestra policy engine means no agent can bypass it, regardless of how clever the prompt injection is.

- **Dual LLM quarantine is underused.** Archestra's `sanitize_with_dual_llm` action is the correct answer for tools that return user-generated content. Two independent LLMs checking for injection is far more robust than regex.

- **MCP security needs automation.** Manual review doesn't scale. An MCP server that audits other MCP servers is the natural architecture.

- **Infrastructure as Code matters.** Deploying both the security auditor and the vulnerable demo server through Terraform makes the entire setup reproducible in a single `terraform apply`.

---

<p align="center">
  <b>Solo submission</b> by <a href="https://github.com/aryan877">Aryan Kumar</a> for the
  <a href="https://wemakedevs.org/events/hackathons/2-fast-2-mcp">2 Fast 2 MCP</a> hackathon
</p>

<p align="center">
  <sub>Built with <a href="https://archestra.ai">Archestra</a> &mdash; the MCP platform for AI agents</sub>
</p>

<p align="center">
  <img src="docs/archestra-logo.png" width="32" alt="Archestra">
</p>
