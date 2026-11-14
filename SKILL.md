---
name: yivpn-agent-vpn
description: Unified YIVPN AI Agent network tool (v2.0.0). Automatically bridges to a local YIVPN Desktop App MCP server (Windows/macOS live split-tunneling & rollback) OR runs a zero-account, rootless 127.0.0.1:10808 VPN proxy daemon in cloud VMs, Docker containers, and local sandboxes ($0 90m/1GiB Trial + Checkout/x402).
---

# YIVPN Unified AI Agent MCP & VPN Skill (`v2.0.0`)

Register once with a single command — `yivpn-agent-cli` automatically selects the right runtime:

```bash
# Zero-App Cloud / Docker / Local Sandbox (auto-selected when no YIVPN_MCP_TOKEN is set)
claude mcp add yivpn -- npx --yes github:yivpn-official/yivpn-agent-cli mcp

# Desktop Workstation Bridge (auto-discovers YIVPN Desktop App port when YIVPN_MCP_TOKEN is set)
claude mcp add yivpn -e YIVPN_MCP_TOKEN=yivpn_mcp_<TOKEN> -- npx --yes github:yivpn-official/yivpn-agent-cli mcp
```

## Scenario A: Zero-App Cloud, Docker & Sandbox Mode (`127.0.0.1:10808` Daemon)

- **One-Call Connect (`connect_vpn` MCP tool or `connect --auto-trial` CLI)**:
  - On residential, office, or mobile ISPs, calling `connect_vpn` (with `autoClaimTrial: true`, default) automatically generates `~/.yivpn-agent/key.json`, claims the **`$0` 90-minute / 1 GiB** `US-Ohio` free trial, validates and starts a rootless background `sing-box` proxy on `127.0.0.1:10808`, verifies exit IP, and never touches host routes or SSH.
  - On cloud/datacenter/VPS ASNs (`AWS`, `GCP`, `Azure`, `DigitalOcean`, `Hetzner`, etc.), call `purchase_vpn_entitlement` (`$2.99` / `¥19.90` for 1 month via `checkout` or `x402` Base USDC) to unlock `US`, `JP`, `SG`, and `HK` across up to 5 concurrent sandboxes, then call `connect_vpn`.
- **Clean Teardown**: Call `disconnect_vpn` (or `npx --yes github:yivpn-official/yivpn-agent-cli disconnect`) to stop the managed `sing-box` daemon.

## Scenario B: Desktop Workstation Mode (Windows / macOS `YIVPN v1.0.4+`)

Workflow rules when `YIVPN_MCP_TOKEN` connects to the YIVPN Desktop App:
- Call `get_capabilities` and `get_vpn_status` first.
- Always call `preview_routing_rules` before `apply_routing_rules` and inspect conflicts.
- Prefer verified `service_preset` IDs (`openai`, `anthropic`, `github`, `google`, `telegram`, `xiaohongshu`, `baidu`, `wechat`, `amap`, `alibaba`, `bilibili`, `qichacha`).
- If a call returns `status: "requires_user_confirmation"`, ask the user to click **Approve** in the YIVPN Desktop App before retrying with `confirmationId`.

## References

- Unified Agent Quickstart (`llms.txt`): `https://yivpn.net/vpn-api/llms.txt`
- OpenAPI 3.1 Specification: `https://yivpn.net/vpn-api/openapi.yaml`
- Live Discovery Endpoint: `https://yivpn.net/api/v1/vpn`
