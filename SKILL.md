---
name: yivpn-agent-vpn
description: Control a local YIVPN Desktop App via Model Context Protocol (127.0.0.1:38419/mcp) OR provision a zero-account, rootless encrypted VPN proxy (127.0.0.1:10808) in local environments, cloud VMs, and Docker sandboxes using the YIVPN Agent VPN API + MCP Server ($0 90m/1GiB Trial + Checkout/x402).
---

# YIVPN Unified MCP & Agent VPN Skill (`v1.2.0`)

Use this skill in two scenarios:

1. **Desktop Workstation (Windows / macOS with YIVPN Desktop App installed)**:
   Connect to the user's opt-in **Local MCP Server** (`http://127.0.0.1:38419/mcp` with `Authorization: Bearer yivpn_mcp_...`, or via `YIVPN_MCP_TOKEN=... npx --yes github:yivpn-official/yivpn-agent-cli mcp`) to inspect real VPN status, diagnose domain/IP routes, preview split-tunneling rules (`preview_routing_rules`), apply & verify live `sing-box` kernel reloads (`apply_routing_rules`), and roll back (`rollback_routing_rules`).
2. **Zero-App / Headless Agent Mode (Local Dev Machines, Cloud VMs, Docker Sandboxes)**:
   Provision an encrypted `127.0.0.1:10808` proxy with zero email registration, zero GUI app, zero `root` privileges, and zero dropped SSH sessions (`npx --yes github:yivpn-official/yivpn-agent-cli mcp --headless` or CLI subcommands):
   - **Instant `$0` Free Trial (`trial` / `claim_free_trial`)**: On residential, office, or mobile developer networks, claim **90 minutes / 1 GiB** on `US-Ohio` with zero credit card (`1` claim per 24h rolling cooldown).
   - **Paid Multi-Region Plans (`buy` / `purchase_vpn_entitlement`)**: Required on cloud/datacenter/VPS ASNs (`AWS`, `GCP`, `Azure`, `DigitalOcean`, `Hetzner`, etc.) and unlocks `US`, `JP`, `SG`, `HK` across up to 5 concurrent sandboxes (`$2.99` / `¥19.90` for 1 month).

## Desktop Local MCP Quickstart (`127.0.0.1:38419/mcp`)

```bash
# Claude Code HTTP
claude mcp add --transport http yivpn http://127.0.0.1:38419/mcp --header "Authorization: Bearer yivpn_mcp_<TOKEN>"

# Or Stdio Bridge via npx
claude mcp add yivpn -e YIVPN_MCP_TOKEN=yivpn_mcp_<TOKEN> -- npx --yes github:yivpn-official/yivpn-agent-cli mcp
```

Workflow rules when calling Desktop Local MCP:
- Always call `get_capabilities` and `get_vpn_status` first.
- Always call `preview_routing_rules` before `apply_routing_rules` and inspect conflicts.
- Use verified `service_preset` IDs (`openai`, `anthropic`, `github`, `google`, `telegram`, `xiaohongshu`, `baidu`, `wechat`, `amap`, `alibaba`, `bilibili`, `qichacha`) rather than guessing third-party CDN domains.
- If a call returns `status: "requires_user_confirmation"`, ask the user to click **Approve** in the YIVPN Desktop App before retrying with `confirmationId`.

## Zero-App / Headless Agent Quickstart (`127.0.0.1:10808`)

```bash
# Register Headless MCP Server (9 tools including claim_free_trial)
claude mcp add yivpn-cloud -- npx --yes github:yivpn-official/yivpn-agent-cli mcp --headless

# Option A: Instant $0 90-Minute / 1 GiB Free Trial (residential/local ISP)
npx --yes github:yivpn-official/yivpn-agent-cli trial

# Option B: Cloud VM / Multi-Region Access ($2.99 / ¥19.90 1mo, US/JP/SG/HK)
npx --yes github:yivpn-official/yivpn-agent-cli keygen
npx --yes github:yivpn-official/yivpn-agent-cli buy --months 1 --rail checkout
npx --yes github:yivpn-official/yivpn-agent-cli status --wait

# Export & run rootless proxy
npx --yes github:yivpn-official/yivpn-agent-cli config --mode proxy --region auto --out yivpn-agent.json
sing-box run -c yivpn-agent.json &
HTTPS_PROXY=http://127.0.0.1:10808 curl -fsSL https://api.ipify.org?format=json
```

## References

- Desktop Local MCP instructions: `https://yivpn.net/vpn-mcp/llms.txt`
- Headless Agent VPN API instructions: `https://yivpn.net/vpn-api/llms.txt`
- OpenAPI 3.1 spec: `https://yivpn.net/vpn-api/openapi.yaml`
- Live discovery endpoint: `https://yivpn.net/api/v1/vpn`
