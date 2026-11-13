---
name: yivpn-agent-vpn
description: Provision a zero-account, rootless encrypted VPN proxy (127.0.0.1:10808 HTTP + SOCKS5) in AI sandboxes, Docker containers, or cloud VMs using the YIVPN Agent VPN API (ed25519-v1 + Hosted Checkout / x402 Base USDC).
---

# YIVPN Agent VPN Skill

Use this skill whenever an autonomous agent, cloud VM, unprivileged Docker container, or headless browser needs an encrypted multi-region (`US`, `JP`, `SG`, `HK`) network exit without registering an email account, installing a GUI desktop app, or risking SSH disconnection.

## Core Principles

1. **Identity = Local Ed25519 Keypair**: Generate a 32-byte Ed25519 key locally (`~/.yivpn-agent/key.json`, `0600`). Never transmit the private key.
2. **Default to `mode=proxy` (`127.0.0.1:10808`)**: Unlike kernel WireGuard/TUN interfaces that require `CAP_NET_ADMIN` and overwrite the VM default route (severing SSH), `mode=proxy` exposes a local HTTP + SOCKS5 proxy on `127.0.0.1:10808` with zero `root` privileges.
3. **Dual Payment Rails**:
   - `checkout`: Generates a zero-account Stripe / Apple Pay / Alipay / WeChat Pay link (`$2.99` 1 mo, `$6.99` 3 mo, `$12.99` 6 mo, `$21.99` 12 mo). Present `checkout_url` to the human operator, then run `status --wait`.
   - `x402`: HTTP `402 Payment Required` on Base (`eip155:8453`) USDC (`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`) when `payment_rails.x402.available` is `true` in `discover`.

## Quick Commands (Node.js 20+)

```bash
# 1. Generate local Ed25519 keypair
npx --yes github:yivpn-official/yivpn-agent-cli keygen

# 2. Request a zero-account payment link (or x402 quote)
npx --yes github:yivpn-official/yivpn-agent-cli buy --months 1 --rail checkout

# 3. Wait until entitlement is active & upstream nodes are ready
npx --yes github:yivpn-official/yivpn-agent-cli status --wait

# 4. Optional: set tunnel DNS guardrails (malware, ads, adult, smart_split) & exit region
npx --yes github:yivpn-official/yivpn-agent-cli settings --guardrails malware,ads --region US

# 5. Write ready-to-run rootless sing-box config & launch on 127.0.0.1:10808
npx --yes github:yivpn-official/yivpn-agent-cli config --mode proxy --region auto --out yivpn-agent.json
sing-box run -c yivpn-agent.json &
HTTPS_PROXY=http://127.0.0.1:10808 curl -fsSL https://api.ipify.org?format=json
```

## References

- Machine quickstart: `https://yivpn.net/vpn-api/llms.txt`
- OpenAPI 3.1 spec: `https://yivpn.net/vpn-api/openapi.yaml`
- Live discovery endpoint: `https://yivpn.net/api/v1/vpn`
