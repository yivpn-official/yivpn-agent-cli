# yivpn-agent-cli

Official zero-dependency Node.js CLI, Python `ed25519-v1` reference signer, and AI Agent `SKILL.md` for the **[YIVPN Agent & Developer VPN API](https://yivpn.net/en/vpn-api/)**.

Provision censorship-resistant `Hysteria2` (QUIC/UDP 443) + `VLESS+REALITY` (TLS 1.3/TCP 443) tunnels across **`US`, `JP`, `SG`, and `HK`** for AI agents, Playwright/Puppeteer browsers, unprivileged Docker containers, and cloud VMs — with **zero email registration, zero GUI app, zero `root` privileges, and zero dropped SSH sessions**.

- **Live Discovery API**: [`https://yivpn.net/api/v1/vpn`](https://yivpn.net/api/v1/vpn)
- **Machine Instructions (`llms.txt`)**: [`https://yivpn.net/vpn-api/llms.txt`](https://yivpn.net/vpn-api/llms.txt)
- **OpenAPI 3.1 Spec**: [`https://yivpn.net/vpn-api/openapi.yaml`](https://yivpn.net/vpn-api/openapi.yaml)
- **12-Language Docs**: [English](https://yivpn.net/en/vpn-api/) · [简体中文](https://yivpn.net/vpn-api/) · [繁體中文](https://yivpn.net/zh-tw/vpn-api/) · [日本語](https://yivpn.net/ja/vpn-api/) · [한국어](https://yivpn.net/ko/vpn-api/) · [Русский](https://yivpn.net/ru/vpn-api/) · [Deutsch](https://yivpn.net/de/vpn-api/) · [Français](https://yivpn.net/fr/vpn-api/) · [Español](https://yivpn.net/es/vpn-api/)

---

## Prompt for Your AI Agent

Paste this into Claude Code, Cursor, Codex, Antigravity, or OpenClaw:

```text
Read https://yivpn.net/vpn-api/llms.txt and set up a rootless YIVPN proxy on 127.0.0.1:10808 for this environment.
```

---

## Quickstart (Zero-Install via `npx`, Node.js 20+)

```bash
# 1. Mint a local Ed25519 keypair (~/.yivpn-agent/key.json, chmod 600)
npx --yes github:yivpn-official/yivpn-agent-cli keygen

# 2. Purchase time bound directly to your Ed25519 public key ($2.99 / 1 mo)
npx --yes github:yivpn-official/yivpn-agent-cli buy --months 1 --rail checkout

# 3. Poll until payment settles & multi-region nodes are provisioned
npx --yes github:yivpn-official/yivpn-agent-cli status --wait

# 4. Optional: configure tunnel DNS guardrails & preferred exit region
npx --yes github:yivpn-official/yivpn-agent-cli settings --guardrails malware,ads --region auto

# 5. Export ready-to-run rootless sing-box config (127.0.0.1:10808 HTTP + SOCKS5)
npx --yes github:yivpn-official/yivpn-agent-cli config --mode proxy --out yivpn-agent.json

# 6. Start tunnel without root and without touching host SSH routes
sing-box run -c yivpn-agent.json &
HTTPS_PROXY=http://127.0.0.1:10808 curl -fsSL https://api.ipify.org?format=json
```

---

## Why Rootless `mode=proxy` Beats Bare WireGuard Scripts in Cloud VMs

| Feature | YIVPN Agent API (`mode=proxy`) | Bare WireGuard APIs |
| :--- | :--- | :--- |
| **Container & Cloud SSH Safety** | Listens on `127.0.0.1:10808` (HTTP + SOCKS5); requires **no `root` / `CAP_NET_ADMIN`** and **never drops SSH** (optional `mode=tun` also supported) | Requires `root` kernel interface; overwrites default route and severs SSH |
| **DPI & Censorship Resistance** | `Hysteria2` (QUIC/UDP 443) + `VLESS+REALITY` (TLS 1.3/TCP 443) | Plain UDP WireGuard handshakes easily throttled or blocked |
| **Exit Regions** | Multi-region failover across `US`, `JP`, `SG`, `HK` | Single static peer per config |
| **Tunnel DNS Guardrails** | `malware` (default `1.1.1.2` Security DoH + phishing block), `ads`, `adult`, `smart_split` | Basic DNS |
| **Key Lifecycle** | Stateless `ed25519-v1` request signing, atomic `/rotate`, and instant `DELETE` revocation | Static keys without request replay protection |

---

## `ed25519-v1` Signing Specification

Every authenticated request includes three headers:

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
