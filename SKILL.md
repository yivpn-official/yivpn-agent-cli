---
name: yivpn-agent-vpn
description: Control a local YIVPN Desktop App via Model Context Protocol (127.0.0.1:38419/mcp) OR provision a zero-account, rootless encrypted VPN proxy (127.0.0.1:10808) in cloud VMs and Docker sandboxes using the YIVPN Agent VPN API + MCP Server.
---

# YIVPN Unified MCP & Agent VPN Skill

Use this skill in two scenarios:

1. **Desktop Workstation (Windows / macOS with YIVPN Desktop App installed)**:
   Connect to the user's opt-in **Local MCP Server** (`http://127.0.0.1:38419/mcp` with `Authorization: Bearer yivpn_mcp_...`, or via `YIVPN_MCP_TOKEN=... npx --yes github:yivpn-official/yivpn-agent-cli mcp`) to inspect real VPN status, diagnose domain/IP routes, preview split-tunneling rules (`preview_routing_rules`), apply & verify live `sing-box` kernel reloads (`apply_routing_rules`), and roll back (`rollback_routing_rules`).
2. **Headless Cloud VM / Docker Container / Autonomous Sandbox**:
   Provision an encrypted multi-region (`US`, `JP`, `SG`, `HK`) `127.0.0.1:10808` proxy with zero email registration, zero GUI app, zero `root` privileges, and zero dropped SSH sessions (`npx --yes github:yivpn-official/yivpn-agent-cli mcp --headless` or CLI subcommands).

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

## Headless Cloud / Sandbox Quickstart (`127.0.0.1:10808`)

```bash
# Register Headless MCP Server
claude mcp add yivpn-cloud -- npx --yes github:yivpn-official/yivpn-agent-cli mcp --headless

# Or one-shot CLI setup
npx --yes github:yivpn-official/yivpn-agent-cli keygen
npx --yes github:yivpn-official/yivpn-agent-cli buy --months 1 --rail checkout
npx --yes github:yivpn-official/yivpn-agent-cli status --wait
npx --yes github:yivpn-official/yivpn-agent-cli config --mode proxy --region auto --out yivpn-agent.json
sing-box run -c yivpn-agent.json &
HTTPS_PROXY=http://127.0.0.1:10808 curl -fsSL https://api.ipify.org?format=json
```

## References

- Desktop Local MCP instructions: `https://yivpn.net/vpn-mcp/llms.txt`
- Headless Agent VPN API instructions: `https://yivpn.net/vpn-api/llms.txt`
- OpenAPI 3.1 spec: `https://yivpn.net/vpn-api/openapi.yaml`
- Live discovery endpoint: `https://yivpn.net/api/v1/vpn`
