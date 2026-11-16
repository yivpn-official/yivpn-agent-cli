# yivpn-agent-cli (v2.2.0 — Unified AI Agent MCP Server, Proxy Daemon & VPN API CLI)

Official zero-dependency **Model Context Protocol (MCP)** server, built-in **rootless `sing-box 1.12+ / 1.14+` proxy daemon**, **conflict-safe Windows/macOS system proxy manager with automatic trial-expiry restore watchdog**, Node.js CLI, Python `ed25519-v1` reference signer, and AI Agent `SKILL.md` for **[YIVPN AI Agent & Developer Hub](https://yivpn.net/en/vpn-api/)**.

### Environment-Aware Routing & Safety Guardrails (`v2.2.0`)

1. **Zero-App Cloud, Docker & Headless Sandbox (`127.0.0.1:10808` Only — Zero SSH Drop)**:
   - Zero email registration, zero GUI app, zero `root` privileges, and **never touches Linux host routes**.
   - Instant **`$0` 90-minute / 1 GiB Free Trial** (`connect --auto-trial` — works directly on domestic ISPs AND behind existing proxies/cloud sandboxes) or multi-region `US/JP/SG/HK` via Hosted Checkout (`$2.99` / `¥19.90`) or `x402` Base USDC.
2. **Personal Windows / macOS Workstation (Desktop GUI Priority + Conflict-Safe `--system-proxy`)**:
   - Detects installed **YIVPN Desktop (`v1.0.5+`)** (`status` → `desktop_app.installed` / `launch-desktop`), which provides **90 min/day free global OS TUN** with zero login, no `1 GiB` cap, and zero WinINET registry conflicts.
   - Detects active third-party proxies (`Karing`, `Clash`, `Mihomo`, `v2rayN` via `osSystemProxy.portListening` + `ownerProcess`) and refuses to clobber their OS system proxy unless `--force-system-proxy` is passed.
   - When `--system-proxy` is applied, spawns an **`autoRestoreWatchdog`** that automatically restores previous OS proxy settings on `disconnect`, if `sing-box` exits, or when the 90-minute trial expires (browsers never hang on a dead port).
3. **Mainland China Zero-Proxy Bootstrap (GFW-Safe First-Party Mirror)**:
   - Download `bin/yivpn-agent.mjs` directly from `https://yivpn.net/vpn-api/yivpn-agent.mjs` into `~/.yivpn-agent/yivpn-agent.mjs` (SHA-256: `0129bc9b459494ed779d7574dc962c22a190afa08c0228a70cf46e22553ee76b`, checksum endpoint: `https://yivpn.net/vpn-api/yivpn-agent.mjs.sha256`).

- **Unified Human Docs**: [`https://yivpn.net/en/vpn-api/`](https://yivpn.net/en/vpn-api/) ([简体中文](https://yivpn.net/vpn-api/))
- **Unified Agent Quickstart (`llms.txt v2.2`)**: [`https://yivpn.net/vpn-api/llms.txt?v=2.2`](https://yivpn.net/vpn-api/llms.txt?v=2.2)
- **First-Party CLI Mirror (No-Proxy China Safe)**: [`https://yivpn.net/vpn-api/yivpn-agent.mjs`](https://yivpn.net/vpn-api/yivpn-agent.mjs)
- **OpenAPI 3.1 Specification**: [`https://yivpn.net/vpn-api/openapi.yaml`](https://yivpn.net/vpn-api/openapi.yaml)
- **Live Discovery API**: [`https://yivpn.net/api/v1/vpn`](https://yivpn.net/api/v1/vpn)

---

## One-Line Prompt for Your AI Agent

Copy & paste into **Claude Code**, **OpenAI Codex**, **Cursor**, **Doubao**, **Windsurf**, or **OpenClaw**:

```text
Read the latest guide at https://yivpn.net/vpn-api/llms.txt?v=2.2 and auto-connect this environment to YIVPN (claim the free 90-min trial if needed).
```

---

## Quickstart Commands (Node.js 20+)

### A. Recommended Persistent Single-File Setup (Mainland China & Global Safe)
```bash
mkdir -p ~/.yivpn-agent
curl -fsSL https://yivpn.net/vpn-api/yivpn-agent.mjs -o ~/.yivpn-agent/yivpn-agent.mjs

# Pre-check installed Desktop App & any active external proxy:
node ~/.yivpn-agent/yivpn-agent.mjs status

# Linux / Cloud VM / Terminal-only proxy (127.0.0.1:10808, SSH-safe):
node ~/.yivpn-agent/yivpn-agent.mjs connect --auto-trial

# Personal Windows / macOS PC (conflict-safe browser system proxy + expiry auto-restore watchdog):
node ~/.yivpn-agent/yivpn-agent.mjs connect --auto-trial --system-proxy

# Verify direct ISP vs tunnel exit (--noproxy "*" bypasses existing env proxies):
curl -fsSL --noproxy "*" https://cloudflare.com/cdn-cgi/trace
curl -fsSL -x http://127.0.0.1:10808 https://cloudflare.com/cdn-cgi/trace

# Stop daemon & restore OS system proxy cleanly:
node ~/.yivpn-agent/yivpn-agent.mjs disconnect
```

### B. Unified MCP Server Registration (`stdio`)
```bash
# Register MCP (Zero-App Cloud / Docker / Sandbox — exposes 11 tools)
claude mcp add yivpn -- node ~/.yivpn-agent/yivpn-agent.mjs mcp

# Register MCP (YIVPN Desktop App v1.0.5+ Local Split-Tunneling Bridge — exposes 8 live kernel tools)
claude mcp add yivpn -e YIVPN_MCP_TOKEN=yivpn_mcp_<YOUR_TOKEN> -- node ~/.yivpn-agent/yivpn-agent.mjs mcp

# Paid Multi-Region Plan ($2.99 / ¥19.90 1mo — unlocks US/JP/SG/HK across 5 concurrent devices)
node ~/.yivpn-agent/yivpn-agent.mjs buy --months 1 --rail checkout
node ~/.yivpn-agent/yivpn-agent.mjs status --wait
node ~/.yivpn-agent/yivpn-agent.mjs connect --region JP

# Fast large file download once 127.0.0.1:10808 is active:
curl -fL --proxy http://127.0.0.1:10808 https://yivpn.net/downloads/YIVPN_1.0.5_x64.msi -o YIVPN_1.0.5_x64.msi
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

See [`bin/yivpn-agent.mjs`](./bin/yivpn-agent.mjs) (zero-dependency Node.js, SHA-256 `0129bc9b459494ed779d7574dc962c22a190afa08c0228a70cf46e22553ee76b`) and [`python/sign_request.py`](./python/sign_request.py) (Python 3) for reference implementations.

---

## License

[MIT](./LICENSE) © YIVPN
