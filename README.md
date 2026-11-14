# yivpn-agent-cli (v1.2.0 — Unified MCP Server & Zero-Account Agent VPN CLI)

Official zero-dependency **Model Context Protocol (MCP)** server/bridge, Node.js CLI, Python `ed25519-v1` reference signer, and AI Agent `SKILL.md` for **[YIVPN Local MCP](https://yivpn.net/en/vpn-mcp/)** & **[YIVPN Agent VPN API](https://yivpn.net/en/vpn-api/)**.

Works seamlessly across **two environments**:
1. **Desktop Local MCP Mode (Windows & macOS `YIVPN v1.0.4+`)**: Connect Claude Code, OpenAI Codex, or Cursor directly to your local YIVPN Desktop App (`http://127.0.0.1:38419/mcp` or via `npx --yes github:yivpn-official/yivpn-agent-cli mcp`) to inspect real VPN status, diagnose routes, preview split-tunneling rules, reload the live `sing-box` kernel, and roll back safely.
2. **Zero-App / Headless Agent Mode (Local Dev Machines, Linux VMs, Docker, Sandboxes)**: Zero email registration, zero GUI app, zero `root` privileges, and zero dropped SSH sessions — claim an instant **`$0` 90-minute / 1 GiB Free Trial** (`trial` / `claim_free_trial` on residential/local ISPs) or unlock multi-region `US/JP/SG/HK` & cloud VMs via Hosted Checkout (`$2.99` / `¥19.90`) or `x402` Base USDC, and run a rootless `127.0.0.1:10808` (HTTP + SOCKS5) proxy.

- **Desktop Local MCP Docs**: [`https://yivpn.net/en/vpn-mcp/`](https://yivpn.net/en/vpn-mcp/) ([简体中文](https://yivpn.net/vpn-mcp/)) · [`llms.txt`](https://yivpn.net/vpn-mcp/llms.txt)
- **Headless Agent API Docs**: [`https://yivpn.net/en/vpn-api/`](https://yivpn.net/en/vpn-api/) ([简体中文](https://yivpn.net/vpn-api/)) · [`llms.txt`](https://yivpn.net/vpn-api/llms.txt) · [`openapi.yaml`](https://yivpn.net/vpn-api/openapi.yaml)
- **Live Discovery API**: [`https://yivpn.net/api/v1/vpn`](https://yivpn.net/api/v1/vpn)

---

## One-Line Prompts for Your AI Agent

### A. Desktop App Local MCP (Windows / macOS with Claude Code, Codex, or Cursor)
```text
Read https://yivpn.net/vpn-mcp/llms.txt , connect to my local YIVPN MCP server, check my current VPN status, and diagnose my network routes.
```

### B. Zero-App / Headless Sandbox (Free Trial + Zero-Account API + MCP)
```text
Read https://yivpn.net/vpn-api/llms.txt and set up a rootless YIVPN proxy on 127.0.0.1:10808 (claim the free trial if eligible, or register the yivpn-agent-cli MCP server) for this environment.
```

---

## Mode 1: Desktop App Local MCP Setup (Windows & macOS)

1. Open **YIVPN Desktop (`v1.0.4+`)** → **Settings → Local MCP Service (AI Agent)** → toggle **ON** and issue a per-agent token (`yivpn_mcp_...`).
2. Add to **Claude Code** or **OpenAI Codex**:

```bash
# Claude Code (Direct Streamable HTTP)
claude mcp add --transport http yivpn http://127.0.0.1:38419/mcp --header "Authorization: Bearer yivpn_mcp_<YOUR_TOKEN>"

# Or Universal Zero-Install Stdio Bridge (Claude Code / Codex / Cursor)
claude mcp add yivpn -e YIVPN_MCP_TOKEN=yivpn_mcp_<YOUR_TOKEN> -- npx --yes github:yivpn-official/yivpn-agent-cli mcp
```

OpenAI Codex (`~/.codex/config.toml`):
```toml
[mcp_servers.yivpn]
url = "http://127.0.0.1:38419/mcp"
http_headers = { "Authorization" = "Bearer yivpn_mcp_<YOUR_TOKEN>" }
```

**8 Live Kernel Tools Exposed**: `get_capabilities`, `get_vpn_status`, `list_servers`, `connect_vpn`, `disconnect_vpn`, `diagnose_connection`, `preview_routing_rules`, `apply_routing_rules` (with automatic local rollback on failure), and `rollback_routing_rules`.

---

## Mode 2: Zero-App / Headless Cloud MCP & CLI Quickstart (Node.js 20+)

### Register as a Headless MCP Server (`9` Tools Including `claim_free_trial`)
```bash
claude mcp add yivpn-cloud -- npx --yes github:yivpn-official/yivpn-agent-cli mcp --headless
```

### Or Run Directly from the CLI
```bash
# Option 1: Claim instant $0 90-minute / 1 GiB Free Trial on US-Ohio (residential/local ISPs, zero card)
#           Automatically generates ~/.yivpn-agent/key.json if none exists.
npx --yes github:yivpn-official/yivpn-agent-cli trial

# Option 2: Multi-Region Cloud/VPS Access ($2.99 / ¥19.90 1mo — unlocks US, JP, SG, HK & datacenter IPs)
npx --yes github:yivpn-official/yivpn-agent-cli keygen
npx --yes github:yivpn-official/yivpn-agent-cli buy --months 1 --rail checkout
npx --yes github:yivpn-official/yivpn-agent-cli status --wait

# Optional: configure tunnel DNS guardrails & preferred exit region
npx --yes github:yivpn-official/yivpn-agent-cli settings --guardrails malware,ads --region auto

# Export ready-to-run rootless sing-box config (127.0.0.1:10808 HTTP + SOCKS5)
npx --yes github:yivpn-official/yivpn-agent-cli config --mode proxy --out yivpn-agent.json

# Start tunnel without root and without touching host SSH routes
sing-box run -c yivpn-agent.json &
HTTPS_PROXY=http://127.0.0.1:10808 curl -fsSL https://api.ipify.org?format=json
```

---

## `ed25519-v1` Signing Specification

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
