# yivpn-agent-cli (v2.1.0 — Unified AI Agent MCP Server, Proxy Daemon & VPN API CLI)

Official zero-dependency **Model Context Protocol (MCP)** server, built-in **rootless `sing-box 1.12+ / 1.14+` proxy daemon**, optional **safe Windows/macOS system proxy manager**, Node.js CLI, Python `ed25519-v1` reference signer, and AI Agent `SKILL.md` for **[YIVPN AI Agent & Developer Hub](https://yivpn.net/en/vpn-api/)**.

### Environment-Aware Routing (Cloud VM vs Personal Desktop)

1. **Zero-App Cloud, Docker & Headless Sandbox (`127.0.0.1:10808` Only — Zero SSH Drop)**:
   - Zero email registration, zero GUI app, zero `root` privileges, and **never touches Linux host routes**.
   - Instant **`$0` 90-minute / 1 GiB Free Trial** (`connect --auto-trial` — works directly on domestic ISPs AND behind existing proxies/cloud sandboxes) or multi-region `US/JP/SG/HK` via Hosted Checkout (`$2.99` / `¥19.90`) or `x402` Base USDC.
2. **Personal Windows / macOS Workstation (`--system-proxy` or Desktop GUI Bridge)**:
   - Detects installed **YIVPN Desktop (`v1.0.4+`)** automatically (which includes **90 min/day free global OS TUN** with zero account required, plus Local MCP live split-tunneling when `YIVPN_MCP_TOKEN` is set).
   - When running without the Desktop GUI, pass `--system-proxy` (`connect --auto-trial --system-proxy`) to route Chrome/Edge/Safari through `127.0.0.1:10808` and automatically restore OS proxy settings on `disconnect`.
3. **Mainland China Zero-Proxy Bootstrap (GFW-Safe First-Party Mirror)**:
   - If `github.com` is unreachable before connecting, download the single-file CLI directly from `https://yivpn.net/vpn-api/yivpn-agent.mjs` (checksum at `https://yivpn.net/vpn-api/yivpn-agent.mjs.sha256`).

- **Unified Human Docs**: [`https://yivpn.net/en/vpn-api/`](https://yivpn.net/en/vpn-api/) ([简体中文](https://yivpn.net/vpn-api/))
- **Unified Agent Quickstart (`llms.txt`)**: [`https://yivpn.net/vpn-api/llms.txt`](https://yivpn.net/vpn-api/llms.txt)
- **First-Party CLI Mirror (No-Proxy China Safe)**: [`https://yivpn.net/vpn-api/yivpn-agent.mjs`](https://yivpn.net/vpn-api/yivpn-agent.mjs)
- **OpenAPI 3.1 Specification**: [`https://yivpn.net/vpn-api/openapi.yaml`](https://yivpn.net/vpn-api/openapi.yaml)
- **Live Discovery API**: [`https://yivpn.net/api/v1/vpn`](https://yivpn.net/api/v1/vpn)

---

## One-Line Prompt for Your AI Agent

Copy & paste into **Claude Code**, **OpenAI Codex**, **Cursor**, **Doubao**, **Windsurf**, or **OpenClaw**:

```text
Read https://yivpn.net/vpn-api/llms.txt and auto-connect this environment to YIVPN (claim the free 90-min trial if needed).
```

---

## Quickstart Commands (Node.js 20+)

### A. Mainland China (Zero Proxy Enabled — Bypass GitHub Timeout)
```bash
curl -fsSL https://yivpn.net/vpn-api/yivpn-agent.mjs -o yivpn-agent.mjs

# Linux / Cloud VM / Terminal-only proxy (127.0.0.1:10808, SSH-safe):
node yivpn-agent.mjs connect --auto-trial

# Personal Windows / macOS PC (also enables browser system proxy, restored on disconnect):
node yivpn-agent.mjs connect --auto-trial --system-proxy

# Stop daemon & restore OS system proxy cleanly:
node yivpn-agent.mjs disconnect
```

### B. Standard `npx` CLI & Unified MCP Server
```bash
# Register MCP (Cloud / Docker / Zero-App Sandbox — exposes 11 tools)
claude mcp add yivpn -- npx --yes github:yivpn-official/yivpn-agent-cli mcp

# Register MCP (YIVPN Desktop App v1.0.4+ Local Split-Tunneling Bridge — exposes 8 live kernel tools)
claude mcp add yivpn -e YIVPN_MCP_TOKEN=yivpn_mcp_<YOUR_TOKEN> -- npx --yes github:yivpn-official/yivpn-agent-cli mcp

# Paid Multi-Region Plan ($2.99 / ¥19.90 1mo — unlocks US/JP/SG/HK across 5 concurrent devices)
npx --yes github:yivpn-official/yivpn-agent-cli buy --months 1 --rail checkout
npx --yes github:yivpn-official/yivpn-agent-cli status --wait
npx --yes github:yivpn-official/yivpn-agent-cli connect --region JP

# Fast large file download once 127.0.0.1:10808 is active:
curl -fL --proxy http://127.0.0.1:10808 https://yivpn.net/downloads/YIVPN_1.0.4_x64.msi -o YIVPN_1.0.4_x64.msi
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
