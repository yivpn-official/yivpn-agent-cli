#!/usr/bin/env node
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const DEFAULT_BASE_URL = process.env.YIVPN_API_BASE || 'https://yivpn.net/api/v1/vpn';
const DEFAULT_KEY_PATH = process.env.YIVPN_KEY_FILE || path.join(os.homedir(), '.yivpn-agent', 'key.json');
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

function printHelp() {
  console.log(`yivpn-agent-cli v1.0.0 — Zero-Account VPN API CLI for AI Agents & Cloud Sandboxes

Usage:
  yivpn-agent <command> [options]

Commands:
  keygen      Generate a local Ed25519 keypair (~/.yivpn-agent/key.json)
  discover    Query unauthenticated service capabilities, terms & payment rails
  buy         Purchase/extend VPN time (--months 1|3|6|12 --rail checkout|x402)
  status      Inspect signed key status (--wait to poll until active=true)
  locations   List provisioned Hysteria2 & VLESS+REALITY exit nodes
  settings    Read or update DNS guardrails (--guardrails malware,ads --region US)
  config      Fetch ready-to-run rootless sing-box config (--mode proxy|tun --out file.json)
  rotate      Atomically migrate remaining time to a newly generated Ed25519 keypair
  revoke      Immediately revoke entitlement and disable upstream credentials
  selftest    Verify local Ed25519 keygen and ed25519-v1 signature round-trip

Global Options:
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
    console.log(JSON.stringify({ ok: true, profile: 'ed25519-v1', pubkey_sample: rec.pubkey }, null, 2));
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
    const keyRecord = fs.existsSync(keyFile) ? loadKeyRecord(keyFile) : (() => {
      const r = generateKeyRecord();
      saveKeyRecord(keyFile, r);
      return r;
    })();
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
