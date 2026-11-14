---
name: yivpn-agent-vpn
description: Unified YIVPN AI Agent network tool (v2.1.0). Automatically bridges to a local YIVPN Desktop App MCP server (Windows/macOS live split-tunneling & rollback) OR runs a zero-account, rootless 127.0.0.1:10808 sing-box 1.12+/1.14+ VPN proxy daemon in cloud VMs, Docker containers, and personal workstations ($0 90m/1GiB Trial + Checkout/x402 + optional safe OS system proxy).
---

# YIVPN Unified AI Agent MCP & VPN Skill (`v2.1.0`)

## Step 1: Environment Decision Tree (Choose the Right Mode First)

1. **Linux Cloud VM / SSH Host / Docker / Headless Sandbox**
   - Goal: Route CLI/Python/Node/Playwright traffic without dropping SSH.
   - **NEVER** modify host routes or global OS proxy. Start only `127.0.0.1:10808` (`connect --auto-trial` or MCP `connect_vpn` with `systemProxy: false`).
2. **Personal Windows / macOS Computer (Human Using Chrome / Edge / Safari / Apps)**
   - First check `status` (or `get_capabilities`) → `desktop_app.installed`:
     - **If YIVPN Desktop GUI (`v1.0.4+`) is already installed**: YIVPN Desktop includes **90 min/day free global OS TUN** with zero account required! Launch the Desktop App for full-system VPN, OR connect to its Local MCP (`YIVPN_MCP_TOKEN=yivpn_mcp_...`) for live split-tunneling.
     - **If YIVPN Desktop is NOT installed** and the user asks to "connect my computer/browser to VPN": pass `--system-proxy` (`connect --auto-trial --system-proxy` or MCP `connect_vpn` with `systemProxy: true`) so Chrome/Edge/Safari use `127.0.0.1:10808` immediately. Run `disconnect` when finished to restore OS proxy settings automatically.

## Step 2: Mainland China Zero-Proxy Bootstrap (GFW-Safe)

When running inside Mainland China **with no existing proxy enabled**, `github.com` and `raw.githubusercontent.com` may time out. Fetch the official zero-dependency single-file CLI directly from `yivpn.net` first-party CDN:

```bash
curl -fsSL https://yivpn.net/vpn-api/yivpn-agent.mjs -o yivpn-agent.mjs
# Optional SHA-256 verification: curl -fsSL https://yivpn.net/vpn-api/yivpn-agent.mjs.sha256
node yivpn-agent.mjs connect --auto-trial
# On personal Windows/macOS where browsers also need VPN:
node yivpn-agent.mjs connect --auto-trial --system-proxy
```

Outside restricted networks (or once `127.0.0.1:10808` is active), you can also run via `npx`:

```bash
# Zero-App Cloud / Docker / Local Sandbox
claude mcp add yivpn -- npx --yes github:yivpn-official/yivpn-agent-cli mcp

# Desktop Workstation Bridge (auto-discovers YIVPN Desktop App port 38410 / 38419)
claude mcp add yivpn -e YIVPN_MCP_TOKEN=yivpn_mcp_<TOKEN> -- npx --yes github:yivpn-official/yivpn-agent-cli mcp
```

## Step 3: Operational Rules & Windows PowerShell Guardrails

- **Fast Large Downloads via Tunnel**: Once `127.0.0.1:10808` is up, **always** pass `--proxy http://127.0.0.1:10808` when downloading installers (`https://yivpn.net/downloads/*`) or GitHub releases (avoids slow ~20 KB/s direct cross-border links).
- **Trial Works Behind Existing Proxies Too**: The `$0` 90-minute / 1 GiB trial (`rail: "trial"`) works on direct residential/mobile ISPs AND behind shared proxies/cloud sandboxes (24h cooldown keyed per hardware hash).
- **Windows PowerShell 5.1 Do & Don't**:
  - Do **NOT** hand-write `.ps1` wrappers to edit `~/.yivpn-agent/daemon.json` or `sing-box-proxy.json` (`Set-Content -Encoding utf8` writes UTF-8 BOM in PowerShell 5.1). Use built-in subcommands: `connect`, `disconnect`, `status`, `trial`, `buy`, `locations`, `settings`, `config`, `version`.
  - If `connect` fails, inspect `~/.yivpn-agent/sing-box.log` directly.
- **Desktop MCP Safety**: When controlling YIVPN Desktop via `YIVPN_MCP_TOKEN`, always call `preview_routing_rules` before `apply_routing_rules`, and ask the user to click **Approve** in the app if `status: "requires_user_confirmation"` is returned.

## References

- Unified Agent Quickstart (`llms.txt`): `https://yivpn.net/vpn-api/llms.txt`
- First-Party Single-File CLI Mirror: `https://yivpn.net/vpn-api/yivpn-agent.mjs`
- OpenAPI 3.1 Specification: `https://yivpn.net/vpn-api/openapi.yaml`
- Live Discovery Endpoint: `https://yivpn.net/api/v1/vpn`
