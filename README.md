# yivpn-agent-cli (v2.0.0 — Unified AI Agent MCP Server, Proxy Daemon & VPN API CLI)

Official zero-dependency **Model Context Protocol (MCP)** server, built-in **rootless `sing-box` proxy daemon**, Node.js CLI, Python `ed25519-v1` reference signer, and AI Agent `SKILL.md` for **[YIVPN AI Agent & Developer Hub](https://yivpn.net/en/vpn-api/)**.

### One Command, Two Environments (Automatic Environment Routing)

Run a single MCP command everywhere — `npx --yes github:yivpn-official/yivpn-agent-cli mcp`:

1. **Zero-App Cloud, Docker & Local Sandbox Mode (Default when no Desktop Token is passed)**:
   - Zero email registration, zero GUI app, zero `root` privileges, and **zero dropped SSH sessions**.
   - Built-in **rootless proxy daemon** (`connect_vpn` / `disconnect_vpn` / `yivpn-agent connect`) manages `sing-box` on `127.0.0.1:10808` (HTTP + SOCKS5) automatically.
   - Instant **`$0` 90-minute / 1 GiB Free Trial** (`trial` / `claim_free_trial` on residential/local ISPs) or multi-region `US/JP/SG/HK` & cloud VMs via Hosted Checkout (`$2.99` / `¥19.90`) or `x402` Base USDC.
2. **Desktop App Bridge Mode (Auto-selected when `YIVPN_MCP_TOKEN` is set on Windows / macOS)**:
   - Auto-discovers the active loopback port (`mcp-config.json`, `38410`, or `38419`) of **YIVPN Desktop (`v1.0.4+`)**.
   - Controls live OS `TUN` / `Proxy` split-tunneling with **Preview → Apply → Kernel Log Verification → Automatic Local Rollback**.

- **Unified Human Docs**: [`https://yivpn.net/en/vpn-api/`](https://yivpn.net/en/vpn-api/) ([简体中文](https://yivpn.net/vpn-api/))
- **Unified Agent Quickstart (`llms.txt`)**: [`https://yivpn.net/vpn-api/llms.txt`](https://yivpn.net/vpn-api/llms.txt)
- **OpenAPI 3.1 Specification**: [`https://yivpn.net/vpn-api/openapi.yaml`](https://yivpn.net/vpn-api/openapi.yaml)
- **Live Discovery API**: [`https://yivpn.net/api/v1/vpn`](https://yivpn.net/api/v1/vpn)

---

## One-Line Prompt for Your AI Agent

Copy & paste into **Claude Code**, **OpenAI Codex**, **Cursor**, **Windsurf**, or **OpenClaw**:

```text
Read https://yivpn.net/vpn-api/llms.txt and connect YIVPN via yivpn-agent-cli MCP (use my local Desktop MCP if configured, otherwise claim the $0 trial and start the rootless 127.0.0.1:10808 proxy).
```

---

## Unified MCP Registration (Auto-Detects Cloud vs Desktop)

### 1. Zero-App / Cloud VM / Docker / Local Sandbox
```bash
claude mcp add yivpn -- npx --yes github:yivpn-official/yivpn-agent-cli mcp
```
Exposes **11 MCP tools** with core names unified across environments:
- **Core Tunnel & Diagnostics (6)**: `get_capabilities`, `get_vpn_status`, `list_servers`, `connect_vpn`, `disconnect_vpn`, `diagnose_connection` (probing both direct ISP & live proxy tunnel)
- **Zero-Account Provisioning & Billing (5)**: `claim_free_trial`, `purchase_vpn_entitlement`, `configure_vpn_guardrails`, `export_singbox_config`, `rotate_or_revoke_key`

### 2. YIVPN Desktop App (Windows & macOS `v1.0.4+`)
Enable **Settings → Connection Strategy → Local MCP Service (AI Agent)** in YIVPN Desktop, issue a per-agent token (`yivpn_mcp_...`), and register:
```bash
# Universal Zero-Install Auto-Discovery Bridge (Claude Code / Codex / Cursor)
claude mcp add yivpn -e YIVPN_MCP_TOKEN=yivpn_mcp_<YOUR_TOKEN> -- npx --yes github:yivpn-official/yivpn-agent-cli mcp
```
Exposes **8 live kernel tools**: `get_capabilities`, `get_vpn_status`, `list_servers`, `connect_vpn`, `disconnect_vpn`, `diagnose_connection`, `preview_routing_rules`, `apply_routing_rules` (with automatic local rollback), and `rollback_routing_rules`.

---

## One-Shot CLI Quickstart (Node.js 20+)

```bash
# 1a. One-command Free Trial + Start Rootless Proxy Daemon on 127.0.0.1:10808 (residential/local ISPs)
npx --yes github:yivpn-official/yivpn-agent-cli connect --auto-trial

# 1b. OR Paid Multi-Region Plan ($2.99 / ¥19.90 1mo — unlocks AWS/GCP/VPS IPs + US/JP/SG/HK)
npx --yes github:yivpn-official/yivpn-agent-cli buy --months 1 --rail checkout
npx --yes github:yivpn-official/yivpn-agent-cli status --wait
npx --yes github:yivpn-official/yivpn-agent-cli connect --region JP

# 2. Route any curl, Python script, or Playwright browser through 127.0.0.1:10808 (SSH stays untouched)
HTTPS_PROXY=http://127.0.0.1:10808 curl -fsSL https://api.ipify.org?format=json

# 3. Inspect live daemon + entitlement status, or stop cleanly
npx --yes github:yivpn-official/yivpn-agent-cli status
npx --yes github:yivpn-official/yivpn-agent-cli disconnect
```

---

## Direct REST API & `ed25519-v1` Signing Specification

Every authenticated API request (including `rail: "trial"`) includes three headers:

- `X-YIVPN-Pubkey`: 64-character hex (or Base64) raw 32-byte Ed25519 public key
- `X-YIVPN-Timestamp`: Unix epoch seconds (`10` digits, within `±300s`)
- `X-YIVPN-Signature`: Base64 (or 128-char hex) 64-byte Ed25519 signature over UTF-8:

```text
yivpn-ed25519-v1
<HTTP_METHOD_UPPERCASE>
<CANONICAL_PATH_INCLUDING_QUERY>
<UNIX_TIMESTAMP_SECONDS>
<LOWERCASE_SHA256_HEX_OF_RAW_REQUEST_BODY>
```

See [`bin/yivpn-agent.mjs`](./bin/yivpn-agent.mjs) (zero-dependency Node.js) and [`python/sign_request.py`](./python/sign_request.py) (Python 3) for reference implementations.

---

## License

[MIT](./LICENSE) © YIVPN
