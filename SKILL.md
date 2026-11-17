---
name: yivpn-agent-vpn
description: Unified YIVPN AI Agent network tool (v2.2.1). Automatically bridges to a local YIVPN Desktop App MCP server (Windows/macOS live split-tunneling & rollback) OR runs a zero-account, rootless 127.0.0.1:10808 sing-box 1.12+/1.14+ VPN proxy daemon in cloud VMs, Docker containers, and personal workstations ($0 90m/1GiB Trial + Checkout/x402 + conflict-safe OS system proxy with automatic expiry restore watchdog).
---

# YIVPN Unified AI Agent MCP & VPN Skill (`v2.2.1`)

## Step 1: Persistent First-Party Bootstrap & Pre-Check (`status`)

Save the zero-dependency CLI to `~/.yivpn-agent/yivpn-agent.mjs` (never volatile `%TEMP%`, and avoid `npx github:...` before connecting in Mainland China) and inspect host state first:

```bash
mkdir -p ~/.yivpn-agent
curl -fsSL https://yivpn.net/vpn-api/yivpn-agent.mjs -o ~/.yivpn-agent/yivpn-agent.mjs
node ~/.yivpn-agent/yivpn-agent.mjs status
```

## Step 2: Environment & Proxy Conflict Decision Tree

1. **Personal Windows / macOS Computer with `desktop_app.installed == true`**
   - **YIVPN Desktop (`v1.0.6+`)** already includes **90 min/day of `$0` free global OS TUN** with zero login, no `1 GiB` cap, and zero WinINET system-proxy conflicts!
   - Prefer launching Desktop GUI (`node ~/.yivpn-agent/yivpn-agent.mjs launch-desktop`) or connect to its Local MCP (`YIVPN_MCP_TOKEN=yivpn_mcp_...`) for YiPro split-tunneling.
2. **Existing Third-Party Proxy Active (`local_proxy.osSystemProxy.externalConflict == true`)**
   - When `status` shows `portListening: true` on another port (e.g. `karingService.exe` on `3067` or `verge-mihomo` on `7890`), **DO NOT overwrite OS system proxy** (background daemons will fight over WinINET/`networksetup`).
   - Run `node ~/.yivpn-agent/yivpn-agent.mjs connect --auto-trial` (local `127.0.0.1:10808` only) and ask the user to toggle off System Proxy inside their existing client first if they want all browser traffic switched to YIVPN.
3. **Personal Windows / macOS Computer without Desktop App or Conflicting Proxy**
   - Run `node ~/.yivpn-agent/yivpn-agent.mjs connect --auto-trial --system-proxy`.
   - Built-in `autoRestoreWatchdog` automatically restores OS proxy settings on `disconnect`, if `sing-box` exits, or when the 90-minute trial expires.
4. **Linux Cloud VM / SSH Host / Docker / Headless Sandbox**
   - **NEVER** pass `--system-proxy` or modify host routes. Start only `127.0.0.1:10808` (`connect --auto-trial`) and pass `HTTPS_PROXY=http://127.0.0.1:10808`.

## Step 3: Verification & PowerShell Guardrails

- **Accurate Direct vs Tunnel Probe**: Always pass `--noproxy "*"` when testing direct ISP connectivity (`curl -fsSL --noproxy "*" https://cloudflare.com/cdn-cgi/trace`) vs tunnel (`curl -fsSL -x http://127.0.0.1:10808 https://cloudflare.com/cdn-cgi/trace`).
- **Fast Large Downloads via Tunnel**: Once `127.0.0.1:10808` is up, pass `-x http://127.0.0.1:10808` when downloading installers (`https://yivpn.net/downloads/*`) or GitHub releases.
- **Windows PowerShell Rules**: Invoke `curl.exe` (not PowerShell's `curl` alias) and `node "$HOME\.yivpn-agent\yivpn-agent.mjs"`. Do NOT edit `~/.yivpn-agent/*.json` with PowerShell 5.1 `Set-Content -Encoding utf8`.

## References

- Unified Agent Quickstart (`llms.txt v2.2`): `https://yivpn.net/vpn-api/llms.txt`
- First-Party Single-File CLI Mirror (SHA-256 `6dc9cab1175e626726c56eb63e4af15473aee8eefb6c396f53a8b7930badef63`): `https://yivpn.net/vpn-api/yivpn-agent.mjs`
- OpenAPI 3.1 Specification: `https://yivpn.net/vpn-api/openapi.yaml`
- Live Discovery Endpoint: `https://yivpn.net/api/v1/vpn`
