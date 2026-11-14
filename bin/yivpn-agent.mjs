#!/usr/bin/env node
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';

const DEFAULT_BASE_URL = process.env.YIVPN_API_BASE || 'https://yivpn.net/api/v1/vpn';
const DEFAULT_KEY_PATH = process.env.YIVPN_KEY_FILE || path.join(os.homedir(), '.yivpn-agent', 'key.json');
const DEFAULT_DESKTOP_MCP_URL = process.env.YIVPN_MCP_URL || 'http://127.0.0.1:38419/mcp';
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function parseArgs(argv) {
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token.startsWith('--')) {
      const eq = token.indexOf('=');
      if (eq > 0) {
        flags[token.slice(2, eq)] = token.slice(eq + 1);
      } else {
        const next = argv[i + 1];
        if (next && !next.startsWith('--')) {
          flags[token.slice(2)] = next;
          i += 1;
        } else {
          flags[token.slice(2)] = true;
        }
      }
    } else if (token === '-h') {
      flags.help = true;
    } else {
      positional.push(token);
    }
  }
  return { command: positional[0] || 'help', positional: positional.slice(1), flags };
}

function generateKeyRecord() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pubkeyHex = publicKey.export({ type: 'spki', format: 'der' }).subarray(12).toString('hex');
  const pkcs8Pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  return {
    profile: 'ed25519-v1',
    pubkey: pubkeyHex,
    private_key_pem: pkcs8Pem,
    created_at: new Date().toISOString(),
  };
}

function loadKeyRecord(keyFile) {
  if (!fs.existsSync(keyFile)) {
    throw new Error(`No Ed25519 key found at ${keyFile}. Run "yivpn-agent keygen" first.`);
  }
  const parsed = JSON.parse(fs.readFileSync(keyFile, 'utf8'));
  if (!parsed?.pubkey || !parsed?.private_key_pem) {
    throw new Error(`Malformed key file at ${keyFile}.`);
  }
  return parsed;
}

function loadOrCreateKeyRecord(keyFile) {
  if (fs.existsSync(keyFile)) {
    return { record: loadKeyRecord(keyFile), created: false };
  }
  const record = generateKeyRecord();
  saveKeyRecord(keyFile, record);
  return { record, created: true };
}

function saveKeyRecord(keyFile, record) {
  fs.mkdirSync(path.dirname(keyFile), { recursive: true, mode: 0o700 });
  fs.writeFileSync(keyFile, JSON.stringify(record, null, 2) + '\n', { encoding: 'utf8', mode: 0o600 });
}

export function buildSigningPayload(method, canonicalPath, timestamp, rawBody = '') {
  const bodySha = crypto.createHash('sha256').update(rawBody, 'utf8').digest('hex');
  return `yivpn-ed25519-v1\n${method.toUpperCase()}\n${canonicalPath}\n${timestamp}\n${bodySha}`;
}

export function signHeaders(keyRecord, method, canonicalPath, rawBody = '') {
  const ts = String(Math.floor(Date.now() / 1000));
  const payload = buildSigningPayload(method, canonicalPath, ts, rawBody);
  const privKey = crypto.createPrivateKey(keyRecord.private_key_pem);
  const sig = crypto.sign(null, Buffer.from(payload, 'utf8'), privKey).toString('base64');
  return {
    'X-YIVPN-Pubkey': keyRecord.pubkey,
    'X-YIVPN-Timestamp': ts,
    'X-YIVPN-Signature': sig,
  };
}

function resolveEndpoint(baseUrl, subPath = '') {
  const base = baseUrl.replace(/\/+$/, '');
  const fullUrl = new URL(subPath ? `${base}${subPath}` : base);
  const idx = fullUrl.pathname.indexOf('/api/v1/vpn');
  const canonicalPath = (idx >= 0 ? fullUrl.pathname.slice(idx) : fullUrl.pathname) + fullUrl.search;
  return { url: fullUrl.toString(), canonicalPath };
}

async function apiRequest({ baseUrl, method = 'GET', subPath = '', bodyObj = null, keyRecord = null, extraHeaders = {} }) {
  const { url, canonicalPath } = resolveEndpoint(baseUrl, subPath);
  const rawBody = bodyObj !== null ? JSON.stringify(bodyObj) : '';
  const headers = {
    Accept: 'application/json, text/plain;q=0.9',
    ...(bodyObj !== null ? { 'Content-Type': 'application/json' } : {}),
    ...(keyRecord ? signHeaders(keyRecord, method, canonicalPath, rawBody) : {}),
    ...extraHeaders,
  };

  const res = await fetch(url, {
    method,
    headers,
    body: bodyObj !== null ? rawBody : undefined,
  });

  const contentType = res.headers.get('content-type') || '';
  const data = contentType.includes('application/json') ? await res.json() : await res.text();
  return { status: res.status, headers: res.headers, data };
}

export function computeDeviceHash() {
  try {
    let raw = '';
    if (process.platform === 'win32') {
      const out = execFileSync('reg.exe', ['query', 'HKLM\\SOFTWARE\\Microsoft\\Cryptography', '/v', 'MachineGuid'], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 2500,
      });
      const m = out.match(/MachineGuid\s+REG_SZ\s+([^\r\n]+)/i);
      if (m) raw = m[1].trim().toLowerCase();
    } else if (process.platform === 'darwin') {
      const out = execFileSync('ioreg', ['-rd1', '-c', 'IOPlatformExpertDevice'], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 2500,
      });
      const m = out.match(/"IOPlatformUUID"\s*=\s*"([^"]+)"/i);
      if (m) raw = m[1].trim().toLowerCase();
    } else {
      for (const p of ['/etc/machine-id', '/var/lib/dbus/machine-id']) {
        if (fs.existsSync(p)) {
          raw = fs.readFileSync(p, 'utf8').trim().toLowerCase();
          if (raw) break;
        }
      }
    }
    if (!raw) return '';
    return crypto.createHash('sha256').update(`yivpn-agent-device-v1:${process.platform}:${raw}`, 'utf8').digest('hex');
  } catch {
    return '';
  }
}

async function claimFreeTrial({ baseUrl, keyFile }) {
  const { record, created } = loadOrCreateKeyRecord(keyFile);
  const deviceHash = computeDeviceHash();
  const res = await apiRequest({
    baseUrl,
    method: 'POST',
    subPath: '/entitlements',
    bodyObj: { pubkey: record.pubkey, rail: 'trial' },
    keyRecord: record,
    extraHeaders: deviceHash ? { 'X-YIVPN-Device-Hash': deviceHash } : {},
  });
  const payload =
    typeof res.data === 'object' && res.data !== null
      ? { status_code: res.status, key_created: created, key_file: keyFile, pubkey: record.pubkey, ...res.data }
      : { status_code: res.status, key_created: created, key_file: keyFile, pubkey: record.pubkey, body: res.data };
  if (res.status === 403 && payload.error === 'trial_datacenter_ip_not_eligible') {
    payload.upgrade_hint =
      'Cloud/VPS datacenter IPs are not eligible for the $0 residential trial. Run "npx --yes github:yivpn-official/yivpn-agent-cli buy --months 1 --rail checkout" ($2.99 / ¥19.90) to unlock cloud sandboxes and US/JP/SG/HK nodes.';
  }
  return { status: res.status, payload };
}

// =============================================================================
// MCP Server (Desktop Local MCP Bridge + Headless Cloud Ed25519 MCP Server)
// =============================================================================

export const HEADLESS_MCP_TOOLS = [
  {
    name: 'get_capabilities',
    description:
      'Return YIVPN Headless Agent VPN API capabilities, supported protocols (Hysteria2 + VLESS+REALITY), guardrail presets, payment rails, and local Ed25519 key status.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'get_vpn_status',
    description:
      'Inspect the signed Ed25519 VPN entitlement status (active, ready, expires_at, remaining_seconds, guardrails) and local keypair metadata.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'list_servers',
    description:
      'List authorized multi-region Hysteria2 and VLESS exit nodes provisioned for this Ed25519 key.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'claim_free_trial',
    description:
      'Mint a local Ed25519 keypair (if none exists) and claim an instant $0 90-minute / 1 GiB free trial on US-Ohio (residential/office/mobile ISPs, 1 claim per 24h, zero credit card).',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'purchase_vpn_entitlement',
    description:
      'Mint a local Ed25519 keypair (if none exists) and request a zero-account VPN entitlement via Hosted Checkout (Stripe/Apple Pay/Alipay/WeChat) or x402 Base USDC.',
    inputSchema: {
      type: 'object',
      properties: {
        months: { type: 'integer', enum: [1, 3, 6, 12], description: 'Subscription duration in months (default: 1).' },
        rail: { type: 'string', enum: ['checkout', 'x402'], description: 'Payment rail (default: checkout).' },
        currency: { type: 'string', enum: ['usd', 'cny'], description: 'Currency for checkout rail (default: usd).' },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'configure_vpn_guardrails',
    description:
      'Read or update tunnel DNS guardrails (malware, ads, adult, smart_split) and preferred exit region (auto, US, JP, SG, HK).',
    inputSchema: {
      type: 'object',
      properties: {
        guardrails: {
          type: 'array',
          items: { type: 'string', enum: ['malware', 'ads', 'adult', 'smart_split'] },
          description: 'Active DNS/routing guardrails to enforce inside the tunnel.',
        },
        preferredRegion: {
          type: 'string',
          enum: ['auto', 'US', 'JP', 'SG', 'HK'],
          description: 'Preferred exit region.',
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'export_singbox_config',
    description:
      'Fetch a ready-to-run rootless sing-box JSON configuration (default 127.0.0.1:10808 mixed HTTP/SOCKS5 proxy that never drops SSH) and optionally save it to outPath.',
    inputSchema: {
      type: 'object',
      properties: {
        mode: { type: 'string', enum: ['proxy', 'tun'], description: 'proxy (rootless 127.0.0.1:port, default) or tun.' },
        region: { type: 'string', enum: ['auto', 'US', 'JP', 'SG', 'HK'], description: 'Target exit region (default: auto).' },
        port: { type: 'integer', description: 'Local mixed proxy port when mode=proxy (default: 10808).' },
        outPath: { type: 'string', description: 'Optional file path to write the sing-box JSON configuration (mode 0600).' },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'diagnose_connection',
    description:
      'Diagnose DNS A/AAAA records and direct HTTPS reachability/latency to a public domain or URL (blocks private/loopback targets).',
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string', description: 'Public domain or HTTPS URL (e.g. api.ipify.org or https://cloudflare.com/cdn-cgi/trace).' },
      },
      required: ['target'],
      additionalProperties: false,
    },
  },
  {
    name: 'rotate_or_revoke_key',
    description:
      'Atomically rotate remaining subscription time to a brand-new local Ed25519 keypair, or immediately revoke the entitlement.',
    inputSchema: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['rotate', 'revoke'], description: 'rotate or revoke.' },
      },
      required: ['action'],
      additionalProperties: false,
    },
  },
];

function isPrivateOrLoopbackHost(host) {
  const h = host.trim().toLowerCase();
  if (
    h === 'localhost' ||
    h.endsWith('.local') ||
    h.endsWith('.internal') ||
    h === '127.0.0.1' ||
    h === '::1' ||
    h.startsWith('10.') ||
    h.startsWith('192.168.') ||
    h.startsWith('169.254.') ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(h)
  ) {
    return true;
  }
  return false;
}

async function executeHeadlessMcpTool(name, args = {}, { baseUrl, keyFile }) {
  if (name === 'get_capabilities') {
    const disc = await apiRequest({ baseUrl, method: 'GET' });
    const hasKey = fs.existsSync(keyFile);
    const pubkey = hasKey ? loadKeyRecord(keyFile).pubkey : null;
    return {
      mode: 'headless-ed25519-api',
      platform: os.platform(),
      keyFile,
      hasLocalKeypair: hasKey,
      pubkey,
      desktopMcpNote:
        'Running in Headless Cloud/Container API mode. To control a local YIVPN Windows/macOS Desktop App instead, pass YIVPN_MCP_TOKEN=<yivpn_mcp_...> from YIVPN Settings -> Local MCP.',
      serviceDiscovery: disc.data,
    };
  }

  if (name === 'claim_free_trial') {
    const { status, payload } = await claimFreeTrial({ baseUrl, keyFile });
    if (status >= 400) {
      throw new Error(JSON.stringify(payload));
    }
    return payload;
  }

  if (name === 'purchase_vpn_entitlement') {
    const { record, created } = loadOrCreateKeyRecord(keyFile);
    const months = Number(args.months || 1);
    const rail = String(args.rail || 'checkout');
    const currency = String(args.currency || 'usd');
    const res = await apiRequest({
      baseUrl,
      method: 'POST',
      subPath: '/entitlements',
      bodyObj: { pubkey: record.pubkey, months, rail, payment_method: 'card', currency },
    });
    const out = typeof res.data === 'object' ? { statusCode: res.status, keyCreated: created, pubkey: record.pubkey, ...res.data } : { statusCode: res.status, body: res.data };
    const payHeader = res.headers.get('payment-required');
    if (payHeader) out.paymentRequiredHeader = payHeader;
    return out;
  }

  if (name === 'diagnose_connection') {
    const rawTarget = String(args.target || '').trim();
    if (!rawTarget) throw new Error('MISSING_TARGET: target is required.');
    const urlObj = rawTarget.includes('://') ? new URL(rawTarget) : new URL(`https://${rawTarget}`);
    if (isPrivateOrLoopbackHost(urlObj.hostname)) {
      throw new Error(`FORBIDDEN_TARGET: Refusing to probe private or loopback host "${urlObj.hostname}".`);
    }
    const [v4, v6] = await Promise.all([
      dns.resolve4(urlObj.hostname).catch(() => []),
      dns.resolve6(urlObj.hostname).catch(() => []),
    ]);
    const started = Date.now();
    let directProbe;
    try {
      const resp = await fetch(urlObj.toString(), { signal: AbortSignal.timeout(5000) });
      directProbe = { reachable: true, httpStatus: resp.status, latencyMs: Date.now() - started };
    } catch (e) {
      directProbe = { reachable: false, error: e?.message || String(e), latencyMs: Date.now() - started };
    }
    return {
      target: rawTarget,
      host: urlObj.hostname,
      dns: { ipv4: v4, ipv6: v6 },
      directProbe,
    };
  }

  const keyRecord = loadKeyRecord(keyFile);

  if (name === 'get_vpn_status') {
    const res = await apiRequest({ baseUrl, method: 'GET', subPath: '/status', keyRecord });
    if (res.status >= 400) throw new Error(JSON.stringify(res.data));
    return res.data;
  }

  if (name === 'list_servers') {
    const res = await apiRequest({ baseUrl, method: 'GET', subPath: '/locations', keyRecord });
    if (res.status >= 400) throw new Error(JSON.stringify(res.data));
    const safeLocations = Array.isArray(res.data?.locations)
      ? res.data.locations.map((loc) => ({
          id: loc.id,
          name: loc.name,
          region: loc.region,
          protocols: loc.protocols,
        }))
      : res.data;
    return { pubkey: keyRecord.pubkey, locations: safeLocations };
  }

  if (name === 'configure_vpn_guardrails') {
    const hasUpdates = Array.isArray(args.guardrails) || typeof args.preferredRegion === 'string';
    if (!hasUpdates) {
      const res = await apiRequest({ baseUrl, method: 'GET', subPath: '/settings', keyRecord });
      if (res.status >= 400) throw new Error(JSON.stringify(res.data));
      return res.data;
    }
    const bodyObj = {};
    if (Array.isArray(args.guardrails)) bodyObj.guardrails = args.guardrails;
    if (typeof args.preferredRegion === 'string') bodyObj.preferred_region = args.preferredRegion;
    const res = await apiRequest({ baseUrl, method: 'PUT', subPath: '/settings', bodyObj, keyRecord });
    if (res.status >= 400) throw new Error(JSON.stringify(res.data));
    return res.data;
  }

  if (name === 'export_singbox_config') {
    const mode = String(args.mode || 'proxy');
    const region = String(args.region || 'auto');
    const port = Number(args.port || 10808);
    const qs = new URLSearchParams({ format: 'singbox', mode, region, port: String(port), raw: '1' });
    const res = await apiRequest({ baseUrl, method: 'GET', subPath: `/config?${qs.toString()}`, keyRecord });
    if (res.status >= 400) throw new Error(typeof res.data === 'string' ? res.data : JSON.stringify(res.data));
    const text = typeof res.data === 'string' ? res.data : JSON.stringify(res.data, null, 2) + '\n';
    if (args.outPath) {
      const outPath = path.resolve(String(args.outPath));
      fs.writeFileSync(outPath, text, { encoding: 'utf8', mode: 0o600 });
      return {
        ok: true,
        outFile: outPath,
        mode,
        region,
        ...(mode === 'proxy' ? { httpProxy: `http://127.0.0.1:${port}`, socks5Proxy: `socks5://127.0.0.1:${port}` } : {}),
        launchCommand: `sing-box run -c ${outPath}`,
      };
    }
    return {
      ok: true,
      mode,
      region,
      ...(mode === 'proxy' ? { httpProxy: `http://127.0.0.1:${port}`, socks5Proxy: `socks5://127.0.0.1:${port}` } : {}),
      singboxConfig: typeof res.data === 'string' ? JSON.parse(res.data) : res.data,
    };
  }

  if (name === 'rotate_or_revoke_key') {
    if (args.action === 'rotate') {
      const nextRecord = generateKeyRecord();
      const res = await apiRequest({
        baseUrl,
        method: 'POST',
        subPath: '/rotate',
        bodyObj: { new_pubkey: nextRecord.pubkey },
        keyRecord,
      });
      if (res.status >= 400) throw new Error(JSON.stringify(res.data));
      const backupPath = `${keyFile}.prev`;
      fs.copyFileSync(keyFile, backupPath);
      saveKeyRecord(keyFile, nextRecord);
      return { ...res.data, keyFile, backupKeyFile: backupPath };
    }
    if (args.action === 'revoke') {
      const res = await apiRequest({ baseUrl, method: 'DELETE', subPath: '/entitlements', keyRecord });
      if (res.status >= 400) throw new Error(JSON.stringify(res.data));
      return res.data;
    }
    throw new Error(`Unsupported action "${args.action}".`);
  }

  throw new Error(`UNKNOWN_TOOL: "${name}"`);
}

export async function handleHeadlessMcpJsonRpc(msg, ctx) {
  if (!msg || typeof msg !== 'object') {
    return { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } };
  }
  const { id, method, params } = msg;
  if (id === undefined || id === null) {
    return null;
  }
  if (method === 'initialize') {
    const requestedVersion = params?.protocolVersion || '2024-11-05';
    return {
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: requestedVersion === '2025-03-26' ? '2025-03-26' : '2024-11-05',
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'yivpn-agent-mcp', version: '1.2.0' },
      },
    };
  }
  if (method === 'ping') {
    return { jsonrpc: '2.0', id, result: {} };
  }
  if (method === 'tools/list') {
    return { jsonrpc: '2.0', id, result: { tools: HEADLESS_MCP_TOOLS } };
  }
  if (method === 'resources/list') {
    return { jsonrpc: '2.0', id, result: { resources: [] } };
  }
  if (method === 'prompts/list') {
    return { jsonrpc: '2.0', id, result: { prompts: [] } };
  }
  if (method === 'tools/call') {
    const toolName = params?.name;
    const toolArgs = params?.arguments || {};
    try {
      const result = await executeHeadlessMcpTool(toolName, toolArgs, ctx);
      return {
        jsonrpc: '2.0',
        id,
        result: {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
          structuredContent: result,
          isError: false,
        },
      };
    } catch (err) {
      const errObj = { error: err?.message || String(err) };
      return {
        jsonrpc: '2.0',
        id,
        result: {
          content: [{ type: 'text', text: JSON.stringify(errObj, null, 2) }],
          structuredContent: errObj,
          isError: true,
        },
      };
    }
  }
  return { jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } };
}

async function runDesktopMcpStdioBridge(mcpUrl, mcpToken) {
  const parsed = new URL(mcpUrl);
  if (parsed.hostname !== '127.0.0.1' && parsed.hostname !== 'localhost') {
    throw new Error(`Refusing non-loopback Desktop MCP endpoint: ${mcpUrl}`);
  }
  const rl = readline.createInterface({ input: process.stdin, terminal: false });
  for await (const line of rl) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let msg;
    try {
      msg = JSON.parse(trimmed);
    } catch {
      process.stdout.write(
        JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }) + '\n'
      );
      continue;
    }
    const isNotification = msg.id === undefined || msg.id === null;
    try {
      const resp = await fetch(mcpUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(mcpToken ? { Authorization: `Bearer ${mcpToken}` } : {}),
        },
        body: JSON.stringify(msg),
      });
      if (resp.status === 202 || isNotification) continue;
      const text = await resp.text();
      if (!text.trim()) continue;
      const out = JSON.parse(text);
      process.stdout.write(JSON.stringify(out) + '\n');
    } catch (err) {
      if (!isNotification) {
        process.stdout.write(
          JSON.stringify({
            jsonrpc: '2.0',
            id: msg.id ?? null,
            error: {
              code: -32000,
              message: `Cannot reach YIVPN Desktop Local MCP at ${mcpUrl} (${err?.message || err}). Ensure YIVPN Desktop App is open and Local MCP is enabled in Settings.`,
            },
          }) + '\n'
        );
      }
    }
  }
}

async function runHeadlessMcpStdioServer(ctx) {
  const rl = readline.createInterface({ input: process.stdin, terminal: false });
  for await (const line of rl) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let msg;
    try {
      msg = JSON.parse(trimmed);
    } catch {
      process.stdout.write(
        JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }) + '\n'
      );
      continue;
    }
    const out = await handleHeadlessMcpJsonRpc(msg, ctx);
    if (out) {
      process.stdout.write(JSON.stringify(out) + '\n');
    }
  }
}

function printHelp() {
  console.log(`yivpn-agent-cli v1.2.0 — Official YIVPN MCP Server & Zero-Account Agent VPN CLI

Usage:
  yivpn-agent <command> [options]

Commands:
  mcp         Start Model Context Protocol (MCP) stdio server:
                • Desktop Bridge Mode (when YIVPN_MCP_TOKEN / --mcp-token is set):
                  Bridges stdio to YIVPN Desktop App Local MCP (127.0.0.1:38419/mcp) with live sing-box routing & rollback.
                • Headless Cloud Mode (default in VMs/Docker without Desktop App):
                  Exposes zero-account Ed25519 + $0 Trial / Checkout / x402 Agent VPN API tools over MCP.
  trial       Claim an instant $0 90-minute / 1 GiB free trial on US-Ohio (mints keypair automatically; residential/local ISPs)
  keygen      Generate a local Ed25519 keypair (~/.yivpn-agent/key.json)
  discover    Query unauthenticated service capabilities, terms & payment rails
  buy         Purchase/extend multi-region VPN time (--months 1|3|6|12 --rail checkout|x402)
  status      Inspect signed key status (--wait to poll until active=true)
  locations   List provisioned Hysteria2 & VLESS+REALITY exit nodes
  settings    Read or update DNS guardrails (--guardrails malware,ads --region US)
  config      Fetch ready-to-run rootless sing-box config (--mode proxy|tun --out file.json)
  rotate      Atomically migrate remaining time to a newly generated Ed25519 keypair
  revoke      Immediately revoke entitlement and disable upstream credentials
  selftest    Verify local Ed25519 signing and MCP JSON-RPC protocol round-trip

Options:
  --mcp-url <url>     Desktop Local MCP URL (default: http://127.0.0.1:38419/mcp or $YIVPN_MCP_URL)
  --mcp-token <tok>   Desktop Local MCP token ($YIVPN_MCP_TOKEN)
  --headless          Force Headless Ed25519 API MCP mode even if YIVPN_MCP_TOKEN is set
  --desktop           Force Desktop App MCP bridge mode
  --key-file <path>   Path to Ed25519 key JSON (default: ~/.yivpn-agent/key.json)
  --api-base <url>    API base URL (default: https://yivpn.net/api/v1/vpn)
`);
}

async function run() {
  const { command, flags } = parseArgs(process.argv.slice(2));
  if (flags.help || command === 'help') {
    printHelp();
    return;
  }

  const baseUrl = String(flags['api-base'] || DEFAULT_BASE_URL);
  const keyFile = path.resolve(String(flags['key-file'] || DEFAULT_KEY_PATH));

  if (command === 'mcp') {
    const mcpUrl = String(flags['mcp-url'] || DEFAULT_DESKTOP_MCP_URL);
    const mcpToken = flags['mcp-token'] ? String(flags['mcp-token']) : process.env.YIVPN_MCP_TOKEN || '';
    const useDesktop = Boolean(flags.desktop || (!flags.headless && mcpToken));
    if (useDesktop) {
      await runDesktopMcpStdioBridge(mcpUrl, mcpToken);
    } else {
      await runHeadlessMcpStdioServer({ baseUrl, keyFile });
    }
    return;
  }

  if (command === 'selftest') {
    const rec = generateKeyRecord();
    assert.match(rec.pubkey, /^[0-9a-f]{64}$/);
    const hdrs = signHeaders(rec, 'GET', '/api/v1/vpn/status', '');
    const payload = buildSigningPayload('GET', '/api/v1/vpn/status', hdrs['X-YIVPN-Timestamp'], '');
    const pubObj = crypto.createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(rec.pubkey, 'hex')]),
      format: 'der',
      type: 'spki',
    });
    const ok = crypto.verify(null, Buffer.from(payload, 'utf8'), pubObj, Buffer.from(hdrs['X-YIVPN-Signature'], 'base64'));
    assert.equal(ok, true, 'ed25519-v1 self-test verification failed');

    const initRes = await handleHeadlessMcpJsonRpc(
      { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05' } },
      { baseUrl, keyFile }
    );
    assert.equal(initRes.result.serverInfo.name, 'yivpn-agent-mcp');
    const toolsRes = await handleHeadlessMcpJsonRpc(
      { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} },
      { baseUrl, keyFile }
    );
    assert.equal(toolsRes.result.tools.length, 9);
    const devHash = computeDeviceHash();
    if (devHash) {
      assert.match(devHash, /^[0-9a-f]{64}$/);
    }

    console.log(
      JSON.stringify(
        {
          ok: true,
          version: '1.2.0',
          profile: 'ed25519-v1',
          mcpTools: toolsRes.result.tools.length,
          deviceHashAvailable: Boolean(devHash),
          pubkey_sample: rec.pubkey,
        },
        null,
        2
      )
    );
    return;
  }

  if (command === 'trial') {
    const { status, payload } = await claimFreeTrial({ baseUrl, keyFile });
    console.log(JSON.stringify(payload, null, 2));
    if (status >= 400) process.exitCode = 1;
    return;
  }

  if (command === 'keygen') {
    if (fs.existsSync(keyFile) && !flags.force) {
      const existing = loadKeyRecord(keyFile);
      console.log(JSON.stringify({ ok: true, existing: true, key_file: keyFile, pubkey: existing.pubkey }, null, 2));
      return;
    }
    const record = generateKeyRecord();
    saveKeyRecord(keyFile, record);
    console.log(JSON.stringify({ ok: true, created: true, key_file: keyFile, pubkey: record.pubkey }, null, 2));
    return;
  }

  if (command === 'discover') {
    const res = await apiRequest({ baseUrl, method: 'GET' });
    console.log(JSON.stringify(res.data, null, 2));
    if (res.status >= 400) process.exitCode = 1;
    return;
  }

  if (command === 'buy') {
    const { record: keyRecord } = loadOrCreateKeyRecord(keyFile);
    const months = Number(flags.months || 1);
    const rail = String(flags.rail || 'checkout');
    const paymentMethod = String(flags.method || 'card');
    const currency = String(flags.currency || 'usd');
    const extraHeaders = flags['payment-signature']
      ? { 'PAYMENT-SIGNATURE': String(flags['payment-signature']) }
      : {};

    const res = await apiRequest({
      baseUrl,
      method: 'POST',
      subPath: '/entitlements',
      bodyObj: { pubkey: keyRecord.pubkey, months, rail, payment_method: paymentMethod, currency },
      extraHeaders,
    });

    const paymentReq = res.headers.get('payment-required');
    const out = typeof res.data === 'object' ? { status_code: res.status, ...res.data } : { status_code: res.status, body: res.data };
    if (paymentReq) out.payment_required_header = paymentReq;
    console.log(JSON.stringify(out, null, 2));
    if (res.status >= 400 && res.status !== 402) process.exitCode = 1;
    return;
  }

  const keyRecord = loadKeyRecord(keyFile);

  if (command === 'status') {
    const wait = Boolean(flags.wait);
    const timeoutMs = Number(flags['timeout-sec'] || 300) * 1000;
    const deadline = Date.now() + timeoutMs;
    while (true) {
      const res = await apiRequest({ baseUrl, method: 'GET', subPath: '/status', keyRecord });
      if (!wait || (res.data?.active && res.data?.ready) || Date.now() >= deadline) {
        console.log(JSON.stringify(res.data, null, 2));
        if (res.status >= 400) process.exitCode = 1;
        return;
      }
      await new Promise((r) => setTimeout(r, 3000));
    }
  }

  if (command === 'locations') {
    const res = await apiRequest({ baseUrl, method: 'GET', subPath: '/locations', keyRecord });
    console.log(JSON.stringify(res.data, null, 2));
    if (res.status >= 400) process.exitCode = 1;
    return;
  }

  if (command === 'settings') {
    const hasUpdates = flags.guardrails !== undefined || flags.region !== undefined;
    if (!hasUpdates) {
      const res = await apiRequest({ baseUrl, method: 'GET', subPath: '/settings', keyRecord });
      console.log(JSON.stringify(res.data, null, 2));
      if (res.status >= 400) process.exitCode = 1;
      return;
    }
    const bodyObj = {};
    if (flags.guardrails !== undefined) {
      const raw = String(flags.guardrails).trim();
      bodyObj.guardrails = raw === 'none' || raw === '' ? [] : raw.split(',').map((s) => s.trim()).filter(Boolean);
    }
    if (flags.region !== undefined) {
      bodyObj.preferred_region = String(flags.region).trim();
    }
    const res = await apiRequest({ baseUrl, method: 'PUT', subPath: '/settings', bodyObj, keyRecord });
    console.log(JSON.stringify(res.data, null, 2));
    if (res.status >= 400) process.exitCode = 1;
    return;
  }

  if (command === 'config') {
    const format = String(flags.format || 'singbox');
    const mode = String(flags.mode || 'proxy');
    const region = String(flags.region || 'auto');
    const port = Number(flags.port || 10808);
    const qs = new URLSearchParams({ format, mode, region, port: String(port) });
    if (flags.out && format === 'singbox') qs.set('raw', '1');

    const res = await apiRequest({ baseUrl, method: 'GET', subPath: `/config?${qs.toString()}`, keyRecord });
    if (res.status >= 400) {
      console.error(typeof res.data === 'string' ? res.data : JSON.stringify(res.data, null, 2));
      process.exitCode = 1;
      return;
    }
    if (flags.out) {
      const outPath = path.resolve(String(flags.out));
      const text = typeof res.data === 'string' ? res.data : JSON.stringify(res.data, null, 2) + '\n';
      fs.writeFileSync(outPath, text, { encoding: 'utf8', mode: 0o600 });
      console.log(
        JSON.stringify(
          {
            ok: true,
            out_file: outPath,
            mode,
            region,
            ...(mode === 'proxy' ? { local_proxy: `http://127.0.0.1:${port}`, socks5_proxy: `socks5://127.0.0.1:${port}` } : {}),
            run_hint: `sing-box run -c ${outPath}`,
          },
          null,
          2
        )
      );
      return;
    }
    if (typeof res.data === 'string') {
      process.stdout.write(res.data);
    } else {
      console.log(JSON.stringify(res.data, null, 2));
    }
    return;
  }

  if (command === 'rotate') {
    const nextRecord = generateKeyRecord();
    const res = await apiRequest({
      baseUrl,
      method: 'POST',
      subPath: '/rotate',
      bodyObj: { new_pubkey: nextRecord.pubkey },
      keyRecord,
    });
    if (res.status >= 400) {
      console.error(JSON.stringify(res.data, null, 2));
      process.exitCode = 1;
      return;
    }
    const backupPath = `${keyFile}.prev`;
    fs.copyFileSync(keyFile, backupPath);
    saveKeyRecord(keyFile, nextRecord);
    console.log(JSON.stringify({ ...res.data, key_file: keyFile, backup_key_file: backupPath }, null, 2));
    return;
  }

  if (command === 'revoke') {
    const res = await apiRequest({ baseUrl, method: 'DELETE', subPath: '/entitlements', keyRecord });
    console.log(JSON.stringify(res.data, null, 2));
    if (res.status >= 400) process.exitCode = 1;
    return;
  }

  throw new Error(`Unknown command "${command}". Run "yivpn-agent --help" for usage.`);
}

run().catch((err) => {
  console.error(JSON.stringify({ ok: false, error: err?.message || String(err) }, null, 2));
  process.exitCode = 1;
});
