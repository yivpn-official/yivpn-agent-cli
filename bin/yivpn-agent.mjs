#!/usr/bin/env node
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import tls from 'node:tls';
import { fileURLToPath } from 'node:url';

export const CLI_VERSION = '2.2.1';
const DEFAULT_BASE_URL = process.env.YIVPN_API_BASE || 'https://yivpn.net/api/v1/vpn';
const ALLOW_CUSTOM_API_BASE_ENV = process.env.YIVPN_ALLOW_CUSTOM_API_BASE === '1';

export function validateTrustedApiBase(rawBase, allowCustom = false) {
  let parsed;
  try {
    parsed = new URL(String(rawBase || '').trim());
  } catch {
    throw new Error(`INVALID_API_BASE: "${rawBase}" is not a valid URL.`);
  }
  if (parsed.username || parsed.password) {
    throw new Error('INVALID_API_BASE: Credentials in API base URL are forbidden.');
  }
  const host = parsed.hostname.toLowerCase();
  const isOfficial =
    parsed.protocol === 'https:' &&
    (host === 'yivpn.net' || host === 'www.yivpn.net') &&
    (parsed.pathname === '/api/v1/vpn' || parsed.pathname.startsWith('/api/v1/vpn/'));
  if (isOfficial) {
    return parsed.toString().replace(/\/+$/, '');
  }
  if (!allowCustom && !ALLOW_CUSTOM_API_BASE_ENV) {
    throw new Error(
      `UNTRUSTED_API_BASE: Refusing non-official API base "${parsed.origin}" without --allow-custom-api-base (or YIVPN_ALLOW_CUSTOM_API_BASE=1).`
    );
  }
  const isLocalLoopback =
    parsed.protocol === 'http:' && (host === '127.0.0.1' || host === 'localhost' || host === '::1' || host === '[::1]');
  if (parsed.protocol !== 'https:' && !isLocalLoopback) {
    throw new Error('INSECURE_API_BASE: Custom API base must use https:// (or loopback http://127.0.0.1 for local testing).');
  }
  return parsed.toString().replace(/\/+$/, '');
}
const DEFAULT_AGENT_DIR = process.env.YIVPN_AGENT_DIR || path.join(os.homedir(), '.yivpn-agent');
const DEFAULT_KEY_PATH = process.env.YIVPN_KEY_FILE || path.join(DEFAULT_AGENT_DIR, 'key.json');
const DESKTOP_DEFAULT_PORTS = [38410, 38419];
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const WIN_INET_REG_KEY = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';
const WIN_PROXY_OVERRIDE =
  'localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>';

function readJsonTextStripBom(filePath) {
  const raw = fs.readFileSync(filePath, 'utf8').replace(/^\uFEFF/, '');
  return JSON.parse(raw);
}

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
        if (next && !next.startsWith('-')) {
          flags[token.slice(2)] = next;
          i += 1;
        } else {
          flags[token.slice(2)] = true;
        }
      }
    } else if (token === '-h') {
      flags.help = true;
    } else if (token === '-v') {
      flags.version = true;
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
    throw new Error(
      `No Ed25519 key found at ${keyFile}. Run "yivpn-agent connect --auto-trial", "yivpn-agent trial" (free 90m/1GiB), or "yivpn-agent keygen" first.`
    );
  }
  const parsed = readJsonTextStripBom(keyFile);
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
  const dir = path.dirname(keyFile);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  try {
    fs.chmodSync(dir, 0o700);
  } catch {}
  fs.writeFileSync(keyFile, JSON.stringify(record, null, 2) + '\n', { encoding: 'utf8', mode: 0o600 });
  try {
    fs.chmodSync(keyFile, 0o600);
  } catch {}
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
  return { status: res.status, payload };
}

function isDesktopGuiRunning() {
  try {
    if (process.platform === 'win32') {
      const out = execFileSync('tasklist.exe', ['/FI', 'IMAGENAME eq YIVPN.exe', '/NH', '/FO', 'CSV'], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 2000,
      });
      return out.toLowerCase().includes('"yivpn.exe"');
    }
    if (process.platform === 'darwin') {
      const out = execFileSync('pgrep', ['-x', 'YIVPN'], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 2000,
      });
      return Boolean(out.trim());
    }
  } catch {}
  return false;
}

export function detectInstalledDesktopApp() {
  const home = os.homedir();
  const candidates = [];
  if (process.platform === 'win32') {
    const localAppData = process.env.LOCALAPPDATA || path.join(home, 'AppData', 'Local');
    const programFiles = process.env.ProgramFiles || 'C:\\Program Files';
    candidates.push(
      path.join(localAppData, 'YIVPN', 'YIVPN.exe'),
      path.join(localAppData, 'Programs', 'YIVPN', 'YIVPN.exe'),
      path.join(programFiles, 'YIVPN', 'YIVPN.exe')
    );
  } else if (process.platform === 'darwin') {
    candidates.push('/Applications/YIVPN.app');
  }
  for (const p of candidates) {
    try {
      if (fs.existsSync(p)) {
        const running = isDesktopGuiRunning();
        return {
          installed: true,
          running,
          path: p,
          freeDailyTunMinutes: 90,
          launchHint: 'node ~/.yivpn-agent/yivpn-agent.mjs launch-desktop',
          note: 'YIVPN Desktop GUI is installed on this computer (includes built-in 90 min/day free global OS TUN without account registration, no 1 GiB cap, and zero WinINET proxy conflicts).',
        };
      }
    } catch {}
  }
  return { installed: false, running: false, path: null };
}

export function launchInstalledDesktopApp() {
  const app = detectInstalledDesktopApp();
  if (!app.installed || !app.path) {
    throw new Error(
      'DESKTOP_APP_NOT_INSTALLED: YIVPN Desktop GUI is not installed on this computer. Download from https://yivpn.net/download/ or use "connect --auto-trial --system-proxy".'
    );
  }
  if (process.platform === 'win32') {
    const child = spawn(app.path, [], {
      detached: true,
      stdio: 'ignore',
      windowsHide: false,
    });
    child.unref();
    return { ok: true, launched: true, alreadyRunning: app.running, platform: 'win32', path: app.path, pid: child.pid || null };
  }
  if (process.platform === 'darwin') {
    const child = spawn('open', ['-a', app.path], {
      detached: true,
      stdio: 'ignore',
    });
    child.unref();
    return { ok: true, launched: true, alreadyRunning: app.running, platform: 'darwin', path: app.path };
  }
  throw new Error(`UNSUPPORTED_DESKTOP_LAUNCH: Platform "${process.platform}" does not have a Desktop GUI launcher.`);
}

// =============================================================================
// Desktop App Auto-Discovery & Loopback TCP Probing
// =============================================================================

export function probeLoopbackPort(port, timeoutMs = 250) {
  return new Promise((resolve) => {
    const sock = net.createConnection({ host: '127.0.0.1', port });
    let settled = false;
    const finish = (ok) => {
      if (settled) return;
      settled = true;
      sock.destroy();
      resolve(ok);
    };
    sock.setTimeout(timeoutMs);
    sock.once('connect', () => finish(true));
    sock.once('timeout', () => finish(false));
    sock.once('error', () => finish(false));
  });
}

function getDesktopAppDataCandidates() {
  const dirs = [];
  if (process.env.YIVPN_APP_DATA_DIR) {
    dirs.push(process.env.YIVPN_APP_DATA_DIR);
  }
  const home = os.homedir();
  if (process.platform === 'win32') {
    const appData = process.env.APPDATA || path.join(home, 'AppData', 'Roaming');
    dirs.push(path.join(appData, 'com.aicross.wawa.accelerator'));
  } else if (process.platform === 'darwin') {
    dirs.push(path.join(home, 'Library', 'Application Support', 'com.aicross.wawa.accelerator'));
  } else {
    const xdgData = process.env.XDG_DATA_HOME || path.join(home, '.local', 'share');
    dirs.push(path.join(xdgData, 'com.aicross.wawa.accelerator'));
  }
  return dirs;
}

export async function detectDesktopMcpEnvironment(explicitUrl = '') {
  if (explicitUrl) {
    const parsed = new URL(explicitUrl);
    const port = Number(parsed.port || (parsed.protocol === 'https:' ? 443 : 80));
    const listening = (parsed.hostname === '127.0.0.1' || parsed.hostname === 'localhost')
      ? await probeLoopbackPort(port)
      : false;
    return {
      endpoint: explicitUrl,
      port,
      listening,
      configuredEnabled: null,
      source: 'explicit',
    };
  }

  let configuredPort = null;
  let configuredEnabled = null;
  for (const dir of getDesktopAppDataCandidates()) {
    const cfgPath = path.join(dir, 'mcp-config.json');
    if (fs.existsSync(cfgPath)) {
      try {
        const cfg = readJsonTextStripBom(cfgPath);
        if (typeof cfg?.port === 'number' && cfg.port > 0 && cfg.port < 65536) {
          configuredPort = cfg.port;
        }
        if (typeof cfg?.enabled === 'boolean') {
          configuredEnabled = cfg.enabled;
        }
        break;
      } catch {
        // Ignore malformed local desktop config
      }
    }
  }

  const candidatePorts = [...new Set([configuredPort, ...DESKTOP_DEFAULT_PORTS].filter(Boolean))];
  for (const p of candidatePorts) {
    if (await probeLoopbackPort(p)) {
      return {
        endpoint: `http://127.0.0.1:${p}/mcp`,
        port: p,
        listening: true,
        configuredEnabled,
        source: p === configuredPort ? 'desktop-config' : 'port-probe',
      };
    }
  }

  const fallbackPort = configuredPort || DESKTOP_DEFAULT_PORTS[0];
  return {
    endpoint: `http://127.0.0.1:${fallbackPort}/mcp`,
    port: fallbackPort,
    listening: false,
    configuredEnabled,
    source: configuredPort ? 'desktop-config-offline' : 'default',
  };
}

// =============================================================================
// Built-in Rootless Local Proxy Daemon (sing-box 127.0.0.1:10808 lifecycle)
// =============================================================================

function getDaemonStatePaths(keyFile) {
  const dir = path.dirname(keyFile);
  return {
    dir,
    daemonFile: path.join(dir, 'daemon.json'),
    configFile: path.join(dir, 'sing-box-proxy.json'),
    logFile: path.join(dir, 'sing-box.log'),
  };
}

function parseSingboxMajorMinor(binPath) {
  try {
    const out = execFileSync(binPath, ['version'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 2500,
    });
    const m = out.match(/sing-box version\s+(\d+)\.(\d+)/i);
    if (m) {
      return { major: Number(m[1]), minor: Number(m[2]), raw: m[0] };
    }
  } catch {}
  return null;
}

export function resolveSingboxBinary(explicitBin = '') {
  const candidates = [];
  if (explicitBin) candidates.push(explicitBin);
  if (process.env.YIVPN_SINGBOX_BIN) candidates.push(process.env.YIVPN_SINGBOX_BIN);

  const exeName = process.platform === 'win32' ? 'sing-box.exe' : 'sing-box';
  const home = os.homedir();
  candidates.push(path.join(DEFAULT_AGENT_DIR, 'bin', exeName));

  if (process.platform === 'win32') {
    const localAppData = process.env.LOCALAPPDATA || path.join(home, 'AppData', 'Local');
    const programFiles = process.env.ProgramFiles || 'C:\\Program Files';
    candidates.push(
      path.join(localAppData, 'YIVPN', 'sing-box', 'sing-box.exe'),
      path.join(localAppData, 'Programs', 'YIVPN', 'sing-box', 'sing-box.exe'),
      path.join(programFiles, 'YIVPN', 'sing-box', 'sing-box.exe'),
      path.join(localAppData, 'YIVPN', 'resources', 'sing-box', 'sing-box.exe'),
      path.join(programFiles, 'YIVPN', 'resources', 'sing-box', 'sing-box.exe'),
      path.join(home, 'Desktop', 'YIVPN', 'sing-box', 'sing-box.exe')
    );
  } else if (process.platform === 'darwin') {
    candidates.push(
      '/Applications/YIVPN.app/Contents/MacOS/sing-box',
      '/Applications/YIVPN.app/Contents/Resources/sing-box/sing-box',
      '/opt/homebrew/bin/sing-box',
      '/usr/local/bin/sing-box'
    );
  } else {
    candidates.push('/usr/local/bin/sing-box', '/usr/bin/sing-box', path.join(home, '.local', 'bin', 'sing-box'));
  }

  const pathDirs = (process.env.PATH || '').split(path.delimiter).filter(Boolean);
  for (const d of pathDirs) {
    candidates.push(path.join(d, exeName));
  }

  const seen = new Set();
  let fallbackBin = null;
  for (const c of candidates) {
    if (!c) continue;
    const normKey = process.platform === 'win32' ? path.resolve(c).toLowerCase() : path.resolve(c);
    if (seen.has(normKey)) continue;
    seen.add(normKey);
    try {
      if (fs.existsSync(c) && fs.statSync(c).isFile()) {
        if (!fallbackBin) fallbackBin = c;
        const ver = parseSingboxMajorMinor(c);
        if (ver && (ver.major > 1 || (ver.major === 1 && ver.minor >= 12))) {
          return c;
        }
      }
    } catch {
      // ignore inaccessible path
    }
  }
  return fallbackBin;
}

// =============================================================================
// Optional Safe Workstation System Proxy (Windows WinINET / macOS networksetup)
// =============================================================================

export function readOsSystemProxyState() {
  if (process.platform === 'win32') {
    try {
      const out = execFileSync('reg.exe', ['query', WIN_INET_REG_KEY], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 2500,
      });
      const enableMatch = out.match(/ProxyEnable\s+REG_DWORD\s+0x([0-9a-f]+)/i);
      const serverMatch = out.match(/ProxyServer\s+REG_SZ\s+([^\r\n]*)/i);
      const overrideMatch = out.match(/ProxyOverride\s+REG_SZ\s+([^\r\n]*)/i);
      return {
        supported: true,
        platform: 'win32',
        enabled: enableMatch ? parseInt(enableMatch[1], 16) !== 0 : false,
        server: serverMatch ? serverMatch[1].trim() : '',
        override: overrideMatch ? overrideMatch[1].trim() : '',
      };
    } catch {
      return { supported: false, platform: 'win32' };
    }
  }
  if (process.platform === 'darwin') {
    try {
      const servicesOut = execFileSync('networksetup', ['-listallnetworkservices'], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 2500,
      });
      const services = servicesOut
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter((s) => s && !s.startsWith('*') && !s.toLowerCase().includes('asterisk'));
      const preferred = services.find((s) => /^wi-?fi$/i.test(s)) || services[0];
      if (!preferred) return { supported: false, platform: 'darwin' };
      const webOut = execFileSync('networksetup', ['-getwebproxy', preferred], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 2500,
      });
      const enabled = /^Enabled:\s*Yes/im.test(webOut);
      const srv = (webOut.match(/^Server:\s*(.*)$/im)?.[1] || '').trim();
      const prt = (webOut.match(/^Port:\s*(.*)$/im)?.[1] || '').trim();
      return {
        supported: true,
        platform: 'darwin',
        service: preferred,
        enabled,
        server: srv && prt && prt !== '0' ? `${srv}:${prt}` : '',
      };
    } catch {
      return { supported: false, platform: 'darwin' };
    }
  }
  return { supported: false, platform: process.platform };
}

function notifyWindowsWinInetRefresh() {
  if (process.platform !== 'win32') return;
  try {
    const psCode =
      '$sig=\'[DllImport("wininet.dll",SetLastError=true)]public static extern bool InternetSetOption(IntPtr h,int o,IntPtr b,int l);\';' +
      '$t=Add-Type -MemberDefinition $sig -Name W -Namespace YivpnWinInet -PassThru;' +
      '[void]$t::InternetSetOption([IntPtr]::Zero,39,[IntPtr]::Zero,0);' +
      '[void]$t::InternetSetOption([IntPtr]::Zero,37,[IntPtr]::Zero,0)';
    execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', psCode], {
      stdio: ['ignore', 'ignore', 'ignore'],
      timeout: 3500,
      windowsHide: true,
    });
  } catch {
    // Registry write already succeeded; apps polling registry still pick up ProxyEnable
  }
}

export function enableOsSystemProxy(port) {
  const proxyHostPort = `127.0.0.1:${port}`;
  if (process.platform === 'win32') {
    const prev = readOsSystemProxyState();
    execFileSync('reg.exe', ['add', WIN_INET_REG_KEY, '/v', 'ProxyServer', '/t', 'REG_SZ', '/d', proxyHostPort, '/f'], {
      stdio: ['ignore', 'ignore', 'ignore'],
      timeout: 2500,
    });
    execFileSync(
      'reg.exe',
      ['add', WIN_INET_REG_KEY, '/v', 'ProxyOverride', '/t', 'REG_SZ', '/d', WIN_PROXY_OVERRIDE, '/f'],
      { stdio: ['ignore', 'ignore', 'ignore'], timeout: 2500 }
    );
    execFileSync('reg.exe', ['add', WIN_INET_REG_KEY, '/v', 'ProxyEnable', '/t', 'REG_DWORD', '/d', '1', '/f'], {
      stdio: ['ignore', 'ignore', 'ignore'],
      timeout: 2500,
    });
    notifyWindowsWinInetRefresh();
    return {
      applied: true,
      platform: 'win32',
      proxyServer: proxyHostPort,
      previous: prev,
    };
  }
  if (process.platform === 'darwin') {
    const prev = readOsSystemProxyState();
    if (!prev.supported || !prev.service) {
      return { applied: false, platform: 'darwin', reason: 'Could not detect active macOS network service.' };
    }
    const svc = prev.service;
    execFileSync('networksetup', ['-setwebproxy', svc, '127.0.0.1', String(port)], {
      stdio: ['ignore', 'ignore', 'ignore'],
      timeout: 2500,
    });
    execFileSync('networksetup', ['-setsecurewebproxy', svc, '127.0.0.1', String(port)], {
      stdio: ['ignore', 'ignore', 'ignore'],
      timeout: 2500,
    });
    execFileSync('networksetup', ['-setsocksfirewallproxy', svc, '127.0.0.1', String(port)], {
      stdio: ['ignore', 'ignore', 'ignore'],
      timeout: 2500,
    });
    execFileSync('networksetup', ['-setwebproxystate', svc, 'on'], { stdio: ['ignore', 'ignore', 'ignore'], timeout: 2500 });
    execFileSync('networksetup', ['-setsecurewebproxystate', svc, 'on'], {
      stdio: ['ignore', 'ignore', 'ignore'],
      timeout: 2500,
    });
    execFileSync('networksetup', ['-setsocksfirewallproxystate', svc, 'on'], {
      stdio: ['ignore', 'ignore', 'ignore'],
      timeout: 2500,
    });
    return {
      applied: true,
      platform: 'darwin',
      service: svc,
      proxyServer: proxyHostPort,
      previous: prev,
    };
  }
  return {
    applied: false,
    platform: process.platform,
    reason: 'System-wide proxy is skipped on Linux/SSH hosts to protect remote sessions; use HTTP_PROXY/HTTPS_PROXY.',
  };
}

export function restoreOsSystemProxy(savedSystemProxy = null, managedPort = 10808) {
  const managedTarget = `127.0.0.1:${managedPort}`;
  if (process.platform === 'win32') {
    try {
      const cur = readOsSystemProxyState();
      const pointingToUs = cur.enabled && (cur.server === managedTarget || cur.server.includes(`=${managedTarget}`));
      if (!savedSystemProxy?.applied && !pointingToUs) {
        return { restored: false, platform: 'win32', enabled: cur.enabled };
      }
      const prev = savedSystemProxy?.previous;
      const shouldReEnablePrev = Boolean(prev?.enabled && prev.server && prev.server !== managedTarget);
      if (shouldReEnablePrev) {
        execFileSync(
          'reg.exe',
          ['add', WIN_INET_REG_KEY, '/v', 'ProxyServer', '/t', 'REG_SZ', '/d', prev.server, '/f'],
          { stdio: ['ignore', 'ignore', 'ignore'], timeout: 2500 }
        );
        execFileSync('reg.exe', ['add', WIN_INET_REG_KEY, '/v', 'ProxyEnable', '/t', 'REG_DWORD', '/d', '1', '/f'], {
          stdio: ['ignore', 'ignore', 'ignore'],
          timeout: 2500,
        });
      } else {
        execFileSync('reg.exe', ['add', WIN_INET_REG_KEY, '/v', 'ProxyEnable', '/t', 'REG_DWORD', '/d', '0', '/f'], {
          stdio: ['ignore', 'ignore', 'ignore'],
          timeout: 2500,
        });
      }
      notifyWindowsWinInetRefresh();
      return { restored: true, platform: 'win32', enabled: shouldReEnablePrev };
    } catch {
      return { restored: false, platform: 'win32' };
    }
  }
  if (process.platform === 'darwin') {
    try {
      const cur = readOsSystemProxyState();
      const svc = savedSystemProxy?.service || cur.service;
      if (!svc) return { restored: false, platform: 'darwin' };
      const pointingToUs = cur.enabled && cur.server === managedTarget;
      if (!savedSystemProxy?.applied && !pointingToUs) {
        return { restored: false, platform: 'darwin', enabled: cur.enabled };
      }
      execFileSync('networksetup', ['-setwebproxystate', svc, 'off'], {
        stdio: ['ignore', 'ignore', 'ignore'],
        timeout: 2500,
      });
      execFileSync('networksetup', ['-setsecurewebproxystate', svc, 'off'], {
        stdio: ['ignore', 'ignore', 'ignore'],
        timeout: 2500,
      });
      execFileSync('networksetup', ['-setsocksfirewallproxystate', svc, 'off'], {
        stdio: ['ignore', 'ignore', 'ignore'],
        timeout: 2500,
      });
      return { restored: true, platform: 'darwin', service: svc, enabled: false };
    } catch {
      return { restored: false, platform: 'darwin' };
    }
  }
  return { restored: false, platform: process.platform };
}

export function parseLoopbackProxyPort(serverStr) {
  if (!serverStr || typeof serverStr !== 'string') return null;
  const m = serverStr.match(/(?:^|[=;,\s]|https?:\/\/|socks5?:\/\/)(?:127\.0\.0\.1|localhost):(\d{1,5})\b/i);
  if (!m) return null;
  const p = Number(m[1]);
  return Number.isInteger(p) && p > 0 && p < 65536 ? p : null;
}

function detectPortListeningOwner(port) {
  if (!Number.isInteger(port) || port <= 0 || port >= 65536) {
    return { pid: null, processName: null };
  }
  try {
    if (process.platform === 'win32') {
      const out = execFileSync('netstat.exe', ['-ano', '-p', 'tcp'], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 2000,
      });
      const portSuffix = `:${port}`;
      let ownerPid = null;
      for (const rawLine of out.split(/\r?\n/)) {
        const line = rawLine.trim();
        if (!line.startsWith('TCP')) continue;
        const parts = line.split(/\s+/);
        if (parts.length < 5) continue;
        const localAddr = parts[1] || '';
        const state = (parts[3] || '').toUpperCase();
        const pidNum = Number(parts[4]);
        if (state === 'LISTENING' && localAddr.endsWith(portSuffix) && Number.isInteger(pidNum) && pidNum > 0) {
          ownerPid = pidNum;
          break;
        }
      }
      if (!ownerPid) return { pid: null, processName: null };
      const tOut = execFileSync('tasklist.exe', ['/FI', `PID eq ${ownerPid}`, '/NH', '/FO', 'CSV'], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 2000,
      });
      const csvMatch = tOut.match(/"([^"]+)"/);
      return { pid: ownerPid, processName: csvMatch ? csvMatch[1] : null };
    }
    const lsofOut = execFileSync('lsof', ['-nP', `-iTCP:${port}`, '-sTCP:LISTEN', '-F', 'pc'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 2000,
    });
    const pidMatch = lsofOut.match(/^p(\d+)/m);
    const cmdMatch = lsofOut.match(/^c([^\r\n]+)/m);
    return {
      pid: pidMatch ? Number(pidMatch[1]) : null,
      processName: cmdMatch ? cmdMatch[1].trim() : null,
    };
  } catch {
    return { pid: null, processName: null };
  }
}

export async function inspectOsSystemProxyState(managedPort = 10808) {
  const base = readOsSystemProxyState();
  if (!base.supported) return base;
  const parsedPort = parseLoopbackProxyPort(base.server);
  if (!parsedPort) {
    return { ...base, parsedPort: null, portListening: null, externalConflict: false };
  }
  const portListening = await probeLoopbackPort(parsedPort, 250);
  const owner = portListening ? detectPortListeningOwner(parsedPort) : { pid: null, processName: null };
  const isExternalPort = parsedPort !== Number(managedPort || 10808);
  return {
    ...base,
    parsedPort,
    portListening,
    ...(owner.processName ? { ownerProcess: owner.processName } : {}),
    ...(owner.pid ? { ownerPid: owner.pid } : {}),
    externalConflict: Boolean(base.enabled && portListening && isExternalPort),
  };
}

function isPidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 1) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err?.code === 'EPERM';
  }
}

function isVerifiedProcessByName(pid, keyword) {
  if (!isPidAlive(pid)) return false;
  try {
    if (process.platform === 'win32') {
      const out = execFileSync('tasklist.exe', ['/FI', `PID eq ${pid}`, '/NH', '/FO', 'CSV'], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 2500,
      });
      return out.toLowerCase().includes(keyword);
    }
    const out = execFileSync('ps', ['-p', String(pid), '-o', 'comm='], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 2500,
    });
    return out.toLowerCase().includes(keyword);
  } catch {
    return false;
  }
}

function isVerifiedSingboxProcess(pid) {
  return isVerifiedProcessByName(pid, 'sing-box');
}

function isVerifiedNodeProcess(pid) {
  return isVerifiedProcessByName(pid, 'node');
}

export async function inspectLocalProxyDaemon(keyFile) {
  const { daemonFile, logFile } = getDaemonStatePaths(keyFile);
  if (!fs.existsSync(daemonFile)) {
    return { running: false, osSystemProxy: await inspectOsSystemProxyState(10808) };
  }
  try {
    const info = readJsonTextStripBom(daemonFile);
    const pid = Number(info?.pid || 0);
    const port = Number(info?.port || 10808);
    const procAlive = isVerifiedSingboxProcess(pid);
    const portOpen = procAlive ? await probeLoopbackPort(port, 300) : false;
    if (!procAlive) {
      if (info?.systemProxy?.applied) {
        restoreOsSystemProxy(info.systemProxy, port);
      }
      const wdPid = Number(info?.watchdogPid || 0);
      if (wdPid > 1 && isVerifiedNodeProcess(wdPid)) {
        try {
          process.kill(wdPid, 'SIGTERM');
        } catch {}
      }
      try {
        fs.unlinkSync(daemonFile);
      } catch {
        // ignore
      }
      return { running: false, osSystemProxy: await inspectOsSystemProxyState(port) };
    }
    const wdPid = Number(info?.watchdogPid || 0);
    return {
      running: true,
      portReady: portOpen,
      pid,
      port,
      region: info.region || 'auto',
      httpProxy: `http://127.0.0.1:${port}`,
      socks5Proxy: `socks5://127.0.0.1:${port}`,
      systemProxyEnabled: Boolean(info?.systemProxy?.applied),
      autoRestoreWatchdog: {
        enabled: Boolean(wdPid > 1 && isVerifiedNodeProcess(wdPid)),
        watchdogPid: wdPid > 1 ? wdPid : null,
        expiresAt: info.expiresAt || null,
      },
      osSystemProxy: await inspectOsSystemProxyState(port),
      startedAt: info.startedAt || null,
      singboxBin: info.singboxBin || null,
      logFile,
    };
  } catch {
    return { running: false, osSystemProxy: await inspectOsSystemProxyState(10808) };
  }
}

export async function stopLocalProxyDaemon(keyFile, fallbackPort = 10808, { allowBlindProxyRestore = true } = {}) {
  const { daemonFile } = getDaemonStatePaths(keyFile);
  if (!fs.existsSync(daemonFile)) {
    const sysProxyRestore = allowBlindProxyRestore
      ? restoreOsSystemProxy(null, fallbackPort)
      : { restored: false, platform: process.platform };
    return { ok: true, wasRunning: false, disconnected: true, systemProxy: sysProxyRestore };
  }
  let info = null;
  try {
    info = readJsonTextStripBom(daemonFile);
  } catch {
    // ignore
  }
  const pid = Number(info?.pid || 0);
  const wdPid = Number(info?.watchdogPid || 0);
  const port = Number(info?.port || fallbackPort || 10808);
  const sysProxyRestore = restoreOsSystemProxy(info?.systemProxy || null, port);
  let terminated = false;

  if (isVerifiedSingboxProcess(pid)) {
    try {
      if (process.platform === 'win32') {
        execFileSync('taskkill.exe', ['/PID', String(pid), '/T', '/F'], {
          stdio: ['ignore', 'ignore', 'ignore'],
          timeout: 4000,
        });
      } else {
        process.kill(pid, 'SIGTERM');
      }
      terminated = true;
    } catch {
      // ignore if exited concurrently
    }
    const deadline = Date.now() + 3000;
    while (Date.now() < deadline && (isPidAlive(pid) || (await probeLoopbackPort(port, 120)))) {
      await new Promise((r) => setTimeout(r, 80));
    }
  }

  try {
    if (fs.existsSync(daemonFile)) fs.unlinkSync(daemonFile);
  } catch {
    // ignore
  }

  if (wdPid > 1 && wdPid !== process.pid && isVerifiedNodeProcess(wdPid)) {
    try {
      process.kill(wdPid, 'SIGTERM');
    } catch {
      // ignore
    }
  }

  const portStillOpen = await probeLoopbackPort(port, 200);
  return {
    ok: true,
    wasRunning: terminated,
    disconnected: !portStillOpen,
    stoppedPid: terminated ? pid : null,
    port,
    systemProxy: sysProxyRestore,
  };
}

export function probeHttpsViaHttpProxy({ proxyHost = '127.0.0.1', proxyPort, targetUrl, timeoutMs = 6500 }) {
  return new Promise((resolve) => {
    const started = Date.now();
    const parsed = new URL(targetUrl);
    const targetHost = parsed.hostname;
    const targetPort = Number(parsed.port || (parsed.protocol === 'http:' ? 80 : 443));
    const reqPath = (parsed.pathname || '/') + (parsed.search || '');

    let settled = false;
    let rawSock = null;
    let tlsSock = null;

    const finish = (resObj) => {
      if (settled) return;
      settled = true;
      try {
        if (tlsSock) tlsSock.destroy();
      } catch {}
      try {
        if (rawSock) rawSock.destroy();
      } catch {}
      resolve({ ...resObj, latencyMs: Date.now() - started });
    };

    const timer = setTimeout(() => {
      finish({ reachable: false, error: `Proxy probe timed out after ${timeoutMs}ms` });
    }, timeoutMs);

    rawSock = net.createConnection({ host: proxyHost, port: proxyPort }, () => {
      rawSock.write(
        `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\nProxy-Connection: keep-alive\r\n\r\n`
      );
    });

    rawSock.once('error', (err) => {
      clearTimeout(timer);
      finish({ reachable: false, error: err?.message || String(err) });
    });

    let connectBuf = Buffer.alloc(0);
    const onConnectData = (chunk) => {
      connectBuf = Buffer.concat([connectBuf, chunk]);
      const headerEnd = connectBuf.indexOf('\r\n\r\n');
      if (headerEnd < 0) {
        if (connectBuf.length > 8192) {
          clearTimeout(timer);
          finish({ reachable: false, error: 'Oversized proxy CONNECT header' });
        }
        return;
      }
      rawSock.removeListener('data', onConnectData);
      const statusLine = connectBuf.subarray(0, connectBuf.indexOf('\r\n')).toString('utf8');
      if (!/^HTTP\/1\.[01]\s+200\b/i.test(statusLine)) {
        clearTimeout(timer);
        finish({ reachable: false, error: `Proxy CONNECT rejected: ${statusLine}` });
        return;
      }

      if (parsed.protocol === 'http:') {
        rawSock.write(
          `GET ${reqPath} HTTP/1.1\r\nHost: ${targetHost}\r\nUser-Agent: yivpn-agent-cli/${CLI_VERSION}\r\nAccept: application/json,text/plain,*/*\r\nConnection: close\r\n\r\n`
        );
        collectHttpResponse(rawSock);
        return;
      }

      tlsSock = tls.connect(
        {
          socket: rawSock,
          servername: net.isIP(targetHost) ? undefined : targetHost,
        },
        () => {
          tlsSock.write(
            `GET ${reqPath} HTTP/1.1\r\nHost: ${targetHost}\r\nUser-Agent: yivpn-agent-cli/${CLI_VERSION}\r\nAccept: application/json,text/plain,*/*\r\nConnection: close\r\n\r\n`
          );
        }
      );
      tlsSock.once('error', (err) => {
        clearTimeout(timer);
        finish({ reachable: false, error: err?.message || String(err) });
      });
      collectHttpResponse(tlsSock);
    };

    function collectHttpResponse(stream) {
      const chunks = [];
      let total = 0;
      stream.on('data', (c) => {
        if (total < 16384) {
          chunks.push(c);
          total += c.length;
        }
      });
      stream.once('end', () => {
        clearTimeout(timer);
        const raw = Buffer.concat(chunks).toString('utf8');
        const splitIdx = raw.indexOf('\r\n\r\n');
        const head = splitIdx >= 0 ? raw.slice(0, splitIdx) : raw;
        const body = splitIdx >= 0 ? raw.slice(splitIdx + 4).trim() : '';
        const statusMatch = head.match(/^HTTP\/1\.[01]\s+(\d{3})/i);
        const httpStatus = statusMatch ? Number(statusMatch[1]) : null;
        let parsedJson = null;
        try {
          parsedJson = JSON.parse(body);
        } catch {
          // non-JSON body is fine
        }
        finish({
          reachable: Boolean(httpStatus),
          httpStatus,
          ...(parsedJson && targetHost === 'api.ipify.org' ? { data: parsedJson } : {}),
        });
      });
    }

    rawSock.on('data', onConnectData);
  });
}

async function runSystemProxyWatchdog({ baseUrl, keyFile }) {
  const { daemonFile } = getDaemonStatePaths(keyFile);
  await new Promise((r) => setTimeout(r, 2500));
  const maxTicks = 17280; // up to 24h at 5s intervals
  for (let tick = 0; tick < maxTicks; tick += 1) {
    if (!fs.existsSync(daemonFile)) return;
    let info = null;
    try {
      info = readJsonTextStripBom(daemonFile);
    } catch {
      return;
    }
    if (!info || !info.systemProxy?.applied) return;
    if (info.watchdogPid && Number(info.watchdogPid) !== process.pid) return;

    const pid = Number(info.pid || 0);
    const port = Number(info.port || 10808);
    if (!isVerifiedSingboxProcess(pid)) {
      restoreOsSystemProxy(info.systemProxy, port);
      try {
        if (fs.existsSync(daemonFile)) fs.unlinkSync(daemonFile);
      } catch {}
      return;
    }

    if (info.expiresAt) {
      const expMs = Date.parse(info.expiresAt);
      if (Number.isFinite(expMs) && Date.now() >= expMs + 3000) {
        let renewed = false;
        try {
          if (fs.existsSync(keyFile)) {
            const keyRecord = loadKeyRecord(keyFile);
            const res = await apiRequest({ baseUrl, method: 'GET', subPath: '/status', keyRecord });
            if (res.status === 200 && res.data?.active && Number(res.data?.remaining_seconds || 0) > 5) {
              renewed = true;
              info.expiresAt = res.data.expires_at || null;
              fs.writeFileSync(daemonFile, JSON.stringify(info, null, 2) + '\n', { encoding: 'utf8', mode: 0o600 });
            }
          }
        } catch {
          // treat unreachable/expired status after deadline as expired so browser does not hang on dead port
        }
        if (!renewed) {
          await stopLocalProxyDaemon(keyFile, port);
          return;
        }
      }
    }

    await new Promise((r) => setTimeout(r, 5000));
  }
}

async function startLocalProxyDaemon({
  baseUrl,
  keyFile,
  region = 'auto',
  port = 10808,
  autoTrial = false,
  systemProxy = false,
  forceSystemProxy = false,
  singboxBin = '',
}) {
  const resolvedBin = resolveSingboxBinary(singboxBin);
  if (!resolvedBin) {
    throw new Error(
      'SINGBOX_NOT_FOUND: Could not find "sing-box" (v1.12+) in PATH, YIVPN_SINGBOX_BIN, or YIVPN Desktop bundle. Install via "winget install SagerNet.sing-box" (Windows), "brew install sing-box" (macOS), "apt install sing-box" (Linux), or install YIVPN Desktop from https://yivpn.net/download/ (bundles sing-box 1.14).'
    );
  }

  let trialClaimed = null;
  if (!fs.existsSync(keyFile)) {
    if (!autoTrial) {
      throw new Error(
        `NO_KEYPAIR: No Ed25519 key found at ${keyFile}. Pass autoClaimTrial=true / --auto-trial, run claim_free_trial, or purchase an entitlement first.`
      );
    }
    const trialRes = await claimFreeTrial({ baseUrl, keyFile });
    if (trialRes.status >= 400) {
      throw new Error(`AUTO_TRIAL_FAILED: ${JSON.stringify(trialRes.payload)}`);
    }
    trialClaimed = trialRes.payload;
  }

  let keyRecord = loadKeyRecord(keyFile);
  const qs = new URLSearchParams({
    format: 'singbox',
    mode: 'proxy',
    region: String(region || 'auto'),
    port: String(port),
    raw: '1',
  });
  let cfgRes = await apiRequest({ baseUrl, method: 'GET', subPath: `/config?${qs.toString()}`, keyRecord });

  if ((cfgRes.status === 402 || cfgRes.status === 403 || cfgRes.status === 404) && autoTrial && !trialClaimed) {
    const trialRes = await claimFreeTrial({ baseUrl, keyFile });
    if (trialRes.status < 400) {
      trialClaimed = trialRes.payload;
      keyRecord = loadKeyRecord(keyFile);
      cfgRes = await apiRequest({ baseUrl, method: 'GET', subPath: `/config?${qs.toString()}`, keyRecord });
    }
  }

  if (cfgRes.status >= 400) {
    throw new Error(typeof cfgRes.data === 'string' ? cfgRes.data : JSON.stringify(cfgRes.data));
  }

  const cfgText = validateRemoteSingboxConfig(cfgRes.data, 'proxy', port);

  await stopLocalProxyDaemon(keyFile, port);

  const { dir, daemonFile, configFile, logFile } = getDaemonStatePaths(keyFile);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  try {
    fs.chmodSync(dir, 0o700);
  } catch {}
  fs.writeFileSync(configFile, cfgText, { encoding: 'utf8', mode: 0o600 });
  try {
    fs.chmodSync(configFile, 0o600);
  } catch {}

  try {
    execFileSync(resolvedBin, ['check', '-c', configFile], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 5000,
    });
  } catch (checkErr) {
    const stderrStr = String(checkErr?.stderr || checkErr?.message || checkErr).trim();
    throw new Error(`SINGBOX_CONFIG_CHECK_FAILED (${resolvedBin}): ${stderrStr}`);
  }

  // Truncate per-run log so error diagnostics only reflect the current launch
  const logFd = fs.openSync(logFile, 'w', 0o600);
  const child = spawn(resolvedBin, ['run', '-c', configFile], {
    detached: true,
    stdio: ['ignore', logFd, logFd],
    windowsHide: true,
  });
  child.unref();
  fs.closeSync(logFd);

  const deadline = Date.now() + 8000;
  let ready = false;
  while (Date.now() < deadline) {
    if (!isPidAlive(child.pid)) {
      break;
    }
    if (await probeLoopbackPort(port, 200)) {
      ready = true;
      break;
    }
    await new Promise((r) => setTimeout(r, 120));
  }

  if (!ready) {
    let fullLog = '';
    try {
      fullLog = fs.readFileSync(logFile, 'utf8').trim();
    } catch {}
    const fatalLines = fullLog
      .split(/\r?\n/)
      .filter((l) => /fatal|error|panic/i.test(l))
      .slice(-6)
      .join(' | ');
    const diag = fatalLines || fullLog.slice(-1200);
    try {
      if (isPidAlive(child.pid)) process.kill(child.pid, 'SIGTERM');
    } catch {}
    throw new Error(`DAEMON_START_FAILED: sing-box did not bind 127.0.0.1:${port}. Diagnostics: ${diag}`);
  }

  const osProxyNow = await inspectOsSystemProxyState(port);
  let systemProxyResult;
  if (systemProxy) {
    if (osProxyNow.externalConflict && !forceSystemProxy) {
      const ownerLabel = osProxyNow.ownerProcess || 'another proxy app';
      systemProxyResult = {
        applied: false,
        skippedReason: 'EXTERNAL_PROXY_ACTIVE',
        platform: process.platform,
        activeExternalServer: osProxyNow.server,
        activeExternalPort: osProxyNow.parsedPort,
        ownerProcess: osProxyNow.ownerProcess || null,
        ownerPid: osProxyNow.ownerPid || null,
        hint: `Active external proxy (${ownerLabel}) is already listening on ${osProxyNow.server} with OS System Proxy enabled and will overwrite registry changes if clobbered. YIVPN tunnel is live on 127.0.0.1:${port} for CLI/Agent traffic; ask the user to disable System Proxy inside ${ownerLabel} first, then re-run "connect --system-proxy" (or pass --force-system-proxy).`,
      };
    } else {
      systemProxyResult = enableOsSystemProxy(port);
    }
  } else {
    systemProxyResult = {
      applied: false,
      platform: process.platform,
      ...(osProxyNow.externalConflict
        ? {
            activeExternalServer: osProxyNow.server,
            ownerProcess: osProxyNow.ownerProcess || null,
          }
        : {}),
      hint:
        process.platform === 'win32' || process.platform === 'darwin'
          ? osProxyNow.externalConflict
            ? `Local port 127.0.0.1:${port} is active. Existing proxy (${osProxyNow.ownerProcess || osProxyNow.server}) currently owns OS System Proxy on ${osProxyNow.server}; keep it as-is or ask the user to turn off System Proxy in ${osProxyNow.ownerProcess || 'that client'} before passing --system-proxy.`
            : `Local port 127.0.0.1:${port} is active. Pass --system-proxy (or systemProxy=true) if the user wants Chrome/Edge/Safari/desktop apps to route through YIVPN automatically.`
          : `Local port 127.0.0.1:${port} is active (SSH-safe; host routes untouched).`,
    };
  }

  let expiresAt = trialClaimed?.expires_at || null;
  if (!expiresAt && systemProxyResult.applied) {
    try {
      const stRes = await apiRequest({ baseUrl, method: 'GET', subPath: '/status', keyRecord });
      if (stRes.status === 200 && stRes.data?.expires_at) {
        expiresAt = stRes.data.expires_at;
      }
    } catch {}
  }

  const startedAt = new Date().toISOString();
  const stateObj = {
    pid: child.pid,
    port,
    region: String(region || 'auto'),
    singboxBin: resolvedBin,
    configFile,
    logFile,
    startedAt,
    expiresAt,
    watchdogPid: null,
    systemProxy: systemProxyResult,
  };
  fs.writeFileSync(daemonFile, JSON.stringify(stateObj, null, 2) + '\n', { encoding: 'utf8', mode: 0o600 });

  let watchdogPid = null;
  if (systemProxyResult.applied) {
    try {
      const selfPath = fileURLToPath(import.meta.url);
      const wdArgs = [selfPath, '__watchdog', '--key-file', keyFile, '--api-base', baseUrl];
      if (baseUrl !== 'https://yivpn.net/api/v1/vpn') {
        wdArgs.push('--allow-custom-api-base');
      }
      const wd = spawn(
        process.execPath,
        wdArgs,
        {
          detached: true,
          stdio: 'ignore',
          windowsHide: true,
        }
      );
      wd.unref();
      watchdogPid = wd.pid || null;
      if (watchdogPid) {
        stateObj.watchdogPid = watchdogPid;
        fs.writeFileSync(daemonFile, JSON.stringify(stateObj, null, 2) + '\n', { encoding: 'utf8', mode: 0o600 });
      }
    } catch {
      watchdogPid = null;
    }
  }

  const exitProbe = await probeHttpsViaHttpProxy({
    proxyPort: port,
    targetUrl: 'https://api.ipify.org?format=json',
    timeoutMs: 7500,
  });

  return {
    ok: true,
    connected: true,
    mode: systemProxyResult.applied ? 'rootless-proxy+system-proxy' : 'rootless-proxy',
    pid: child.pid,
    region: String(region || 'auto'),
    port,
    httpProxy: `http://127.0.0.1:${port}`,
    socks5Proxy: `socks5://127.0.0.1:${port}`,
    systemProxy: systemProxyResult,
    ...(systemProxyResult.applied
      ? {
          autoRestoreWatchdog: {
            enabled: Boolean(watchdogPid),
            watchdogPid,
            expiresAt,
            note: 'Automatically restores OS system proxy when sing-box exits or trial/entitlement expires so browsers never lose connectivity.',
          },
        }
      : {}),
    desktopApp: detectInstalledDesktopApp(),
    envHint: `HTTPS_PROXY=http://127.0.0.1:${port} HTTP_PROXY=http://127.0.0.1:${port} ALL_PROXY=socks5://127.0.0.1:${port}`,
    fastDownloadHint: `For large downloads (e.g. .msi/.dmg/.apk), pass --proxy http://127.0.0.1:${port} to curl.`,
    exitIp: exitProbe.data?.ip || null,
    exitProbe,
    ...(trialClaimed ? { trialClaimed } : {}),
  };
}

// =============================================================================
// Unified MCP Server (Auto-Detects Desktop App Bridge vs Zero-App Cloud + Daemon)
// =============================================================================

export const HEADLESS_MCP_TOOLS = [
  {
    name: 'get_capabilities',
    description:
      'Return YIVPN Agent capabilities, active runtime mode (Desktop Bridge vs Zero-App Cloud/Daemon), detected sing-box binary, desktop MCP probe state, supported protocols (Hysteria2 + VLESS+REALITY), guardrail presets, and payment rails.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'get_vpn_status',
    description:
      'Inspect BOTH the live local rootless proxy daemon state (127.0.0.1:10808 running/pid/proxy URLs) AND the signed Ed25519 VPN entitlement status (active, ready, expires_at, remaining_seconds, guardrails).',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'list_servers',
    description:
      'List authorized multi-region Hysteria2 and VLESS exit nodes provisioned for this Ed25519 key.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'connect_vpn',
    description:
      'Start or switch the rootless local sing-box VPN proxy daemon (default 127.0.0.1:10808 mixed HTTP+SOCKS5 — zero root required, never drops Linux SSH). Automatically claims the $0 90m/1GiB free trial if no active key exists and autoClaimTrial is true. Set systemProxy=true ONLY on personal Windows/macOS workstations when the user wants browsers/desktop apps routed through YIVPN.',
    inputSchema: {
      type: 'object',
      properties: {
        region: {
          type: 'string',
          enum: ['auto', 'US', 'JP', 'SG', 'HK'],
          description: 'Target exit region (default: auto).',
        },
        port: {
          type: 'integer',
          description: 'Local loopback mixed HTTP/SOCKS5 port (default: 10808).',
        },
        autoClaimTrial: {
          type: 'boolean',
          description: 'Automatically mint a keypair and claim the $0 90m/1GiB free trial if no active entitlement exists (default: true).',
        },
        systemProxy: {
          type: 'boolean',
          description:
            'On personal Windows/macOS desktops, configure OS system proxy to 127.0.0.1:port so Chrome/Edge/Safari use YIVPN (automatically skipped if another active local proxy owns OS system proxy, and auto-restored on disconnect_vpn or trial expiry). Ignored on Linux/SSH.',
        },
        forceSystemProxy: {
          type: 'boolean',
          description:
            'Override an active third-party OS system proxy even if another proxy client is currently listening on another loopback port (default: false).',
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'disconnect_vpn',
    description:
      'Cleanly stop the managed local rootless sing-box VPN proxy daemon and automatically restore OS system proxy if it was enabled by YIVPN.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'diagnose_connection',
    description:
      'Diagnose DNS A/AAAA records, direct ISP reachability, and (when local proxy is running) encrypted VPN tunnel reachability/latency to a public domain or URL.',
    inputSchema: {
      type: 'object',
      properties: {
        target: {
          type: 'string',
          description: 'Public domain or HTTPS URL (e.g. api.ipify.org or https://cloudflare.com/cdn-cgi/trace).',
        },
      },
      required: ['target'],
      additionalProperties: false,
    },
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
      'Fetch a ready-to-run sing-box JSON configuration (mode=proxy or mode=tun) and optionally write it to outPath.',
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

const PRIVATE_IP_BLOCKLIST = (() => {
  const bl = new net.BlockList();
  bl.addSubnet('0.0.0.0', 8, 'ipv4');
  bl.addSubnet('10.0.0.0', 8, 'ipv4');
  bl.addSubnet('100.64.0.0', 10, 'ipv4');
  bl.addSubnet('127.0.0.0', 8, 'ipv4');
  bl.addSubnet('169.254.0.0', 16, 'ipv4');
  bl.addSubnet('172.16.0.0', 12, 'ipv4');
  bl.addSubnet('192.0.0.0', 24, 'ipv4');
  bl.addSubnet('192.0.2.0', 24, 'ipv4');
  bl.addSubnet('192.88.99.0', 24, 'ipv4');
  bl.addSubnet('192.168.0.0', 16, 'ipv4');
  bl.addSubnet('198.18.0.0', 15, 'ipv4');
  bl.addSubnet('198.51.100.0', 24, 'ipv4');
  bl.addSubnet('203.0.113.0', 24, 'ipv4');
  bl.addSubnet('224.0.0.0', 4, 'ipv4');
  bl.addSubnet('240.0.0.0', 4, 'ipv4');
  bl.addAddress('::', 'ipv6');
  bl.addAddress('::1', 'ipv6');
  bl.addSubnet('fc00::', 7, 'ipv6');
  bl.addSubnet('fe80::', 10, 'ipv6');
  bl.addSubnet('ff00::', 8, 'ipv6');
  return bl;
})();

export function isBlockedIpAddress(rawIp) {
  const clean = String(rawIp || '').trim().replace(/^\[|\]$/g, '').toLowerCase();
  const ver = net.isIP(clean);
  if (ver === 4) {
    return PRIVATE_IP_BLOCKLIST.check(clean, 'ipv4');
  }
  if (ver === 6) {
    if (clean.startsWith('::ffff:')) {
      const mapped = clean.slice(7);
      if (net.isIP(mapped) === 4) return PRIVATE_IP_BLOCKLIST.check(mapped, 'ipv4');
      const hexMatch = mapped.match(/^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
      if (hexMatch) {
        const hi = Number.parseInt(hexMatch[1], 16);
        const lo = Number.parseInt(hexMatch[2], 16);
        const v4 = `${(hi >> 8) & 255}.${hi & 255}.${(lo >> 8) & 255}.${lo & 255}`;
        return PRIVATE_IP_BLOCKLIST.check(v4, 'ipv4');
      }
      return true;
    }
    return PRIVATE_IP_BLOCKLIST.check(clean, 'ipv6');
  }
  return true;
}

export function isPrivateOrLoopbackHost(host) {
  const h = String(host || '').trim().replace(/^\[|\]$/g, '').toLowerCase();
  if (!h || h.length > 253) return true;
  if (h.startsWith('\\') || h.startsWith('/') || /[\s/\\?#@%]/.test(h)) return true;
  if (
    h === 'localhost' ||
    h.endsWith('.localhost') ||
    h.endsWith('.local') ||
    h.endsWith('.internal')
  ) {
    return true;
  }
  // Reject integer / hex / octal single-token or non-standard numeric IPv4 notations
  if (/^(?:0x[0-9a-f]+|\d+)$/i.test(h)) return true;
  if (/^[0-9x.]+$/i.test(h) && net.isIP(h) !== 4) return true;
  if (net.isIP(h)) {
    return isBlockedIpAddress(h);
  }
  return false;
}

const FORBIDDEN_SINGBOX_CONFIG_KEYS = new Set([
  'output',
  'cache_file',
  'clash_api',
  'v2ray_api',
  'pprof',
  'acme',
  'ech',
  'external_ui',
  'external_ui_download_url',
]);

function assertNoDangerousSingboxKeys(node, pathTrace = 'root') {
  if (!node || typeof node !== 'object') return;
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i += 1) {
      assertNoDangerousSingboxKeys(node[i], `${pathTrace}[${i}]`);
    }
    return;
  }
  for (const [k, v] of Object.entries(node)) {
    const lk = k.toLowerCase();
    if (
      FORBIDDEN_SINGBOX_CONFIG_KEYS.has(lk) ||
      lk.endsWith('_path') ||
      lk.endsWith('_directory')
    ) {
      throw new Error(`UNSAFE_REMOTE_CONFIG: Forbidden sing-box key "${k}" at ${pathTrace}.${k}`);
    }
    assertNoDangerousSingboxKeys(v, `${pathTrace}.${k}`);
  }
}

export function validateRemoteSingboxConfig(rawData, expectedMode = 'proxy', expectedPort = 10808) {
  let cfg;
  try {
    cfg = typeof rawData === 'string' ? JSON.parse(rawData) : structuredClone(rawData);
  } catch {
    throw new Error('UNSAFE_REMOTE_CONFIG: Response is not valid JSON.');
  }
  if (!cfg || typeof cfg !== 'object' || Array.isArray(cfg)) {
    throw new Error('UNSAFE_REMOTE_CONFIG: Root configuration must be a JSON object.');
  }
  assertNoDangerousSingboxKeys(cfg);

  if (!Array.isArray(cfg.inbounds) || cfg.inbounds.length === 0 || cfg.inbounds.length > 4) {
    throw new Error('UNSAFE_REMOTE_CONFIG: Configuration must define 1..4 inbounds.');
  }
  for (const inb of cfg.inbounds) {
    if (!inb || typeof inb !== 'object') {
      throw new Error('UNSAFE_REMOTE_CONFIG: Malformed inbound entry.');
    }
    const t = String(inb.type || '').toLowerCase();
    if (expectedMode === 'proxy') {
      if (!['mixed', 'socks', 'http'].includes(t)) {
        throw new Error(`UNSAFE_REMOTE_CONFIG: Disallowed inbound type "${t}" in proxy mode.`);
      }
      if (inb.listen !== '127.0.0.1') {
        throw new Error(`UNSAFE_REMOTE_CONFIG: Proxy inbound must bind strictly to 127.0.0.1 (got "${inb.listen}").`);
      }
      const lp = Number(inb.listen_port);
      if (!Number.isInteger(lp) || lp < 1024 || lp > 65535 || (expectedPort && lp !== Number(expectedPort))) {
        throw new Error(`UNSAFE_REMOTE_CONFIG: Unexpected inbound listen_port "${inb.listen_port}".`);
      }
    } else if (!['tun', 'mixed', 'socks', 'http'].includes(t)) {
      throw new Error(`UNSAFE_REMOTE_CONFIG: Disallowed inbound type "${t}".`);
    }
  }

  if (!Array.isArray(cfg.outbounds) || cfg.outbounds.length === 0 || cfg.outbounds.length > 16) {
    throw new Error('UNSAFE_REMOTE_CONFIG: Configuration must define 1..16 outbounds.');
  }
  const ALLOWED_PROXY_TYPES = new Set([
    'vless', 'vmess', 'trojan', 'shadowsocks', 'anytls', 'hysteria', 'hysteria2', 'tuic', 'socks', 'http',
  ]);
  for (const ob of cfg.outbounds) {
    if (!ob || typeof ob !== 'object') {
      throw new Error('UNSAFE_REMOTE_CONFIG: Malformed outbound entry.');
    }
    const t = String(ob.type || '').toLowerCase();
    if (t === 'direct' || t === 'block' || t === 'dns') continue;
    if (!ALLOWED_PROXY_TYPES.has(t)) {
      throw new Error(`UNSAFE_REMOTE_CONFIG: Unsupported outbound type "${t}".`);
    }
    const srv = String(ob.server || '').trim();
    const sp = Number(ob.server_port);
    if (!srv || isPrivateOrLoopbackHost(srv) || !Number.isInteger(sp) || sp < 1 || sp > 65535) {
      throw new Error(`UNSAFE_REMOTE_CONFIG: Outbound server "${srv}:${ob.server_port}" must be a public endpoint.`);
    }
  }
  return JSON.stringify(cfg, null, 2) + '\n';
}

export function validateSafeConfigOutputPath(rawOutPath, keyFile = DEFAULT_KEY_PATH, { confineToAgentDirs = true } = {}) {
  const candidate = path.resolve(String(rawOutPath || '').trim());
  if (!candidate.toLowerCase().endsWith('.json')) {
    throw new Error('UNSAFE_OUTPUT_PATH: Output file must have a .json extension.');
  }
  const parentDir = path.dirname(candidate);
  fs.mkdirSync(parentDir, { recursive: true, mode: 0o700 });
  const realParent = fs.realpathSync(parentDir);
  const finalTarget = path.join(realParent, path.basename(candidate));

  if (fs.existsSync(finalTarget) && fs.lstatSync(finalTarget).isSymbolicLink()) {
    throw new Error('UNSAFE_OUTPUT_PATH: Refusing to overwrite a symbolic link.');
  }

  if (confineToAgentDirs) {
    const allowedRoots = [
      DEFAULT_AGENT_DIR,
      path.dirname(path.resolve(keyFile)),
      os.tmpdir(),
    ].map((root) => {
      try {
        fs.mkdirSync(root, { recursive: true, mode: 0o700 });
        return fs.realpathSync(root);
      } catch {
        return path.resolve(root);
      }
    });
    const isInsideRoot = allowedRoots.some((root) => {
      const rel = path.relative(root, finalTarget);
      return rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel);
    });
    if (!isInsideRoot) {
      throw new Error(
        `UNSAFE_OUTPUT_PATH: MCP export outPath must be inside ${DEFAULT_AGENT_DIR} or system temp directory.`
      );
    }
  }
  return finalTarget;
}

async function executeHeadlessMcpTool(name, args = {}, { baseUrl, keyFile }) {
  if (name === 'get_capabilities') {
    const [disc, desktopProbe, localProxy] = await Promise.all([
      apiRequest({ baseUrl, method: 'GET' }).catch((e) => ({ status: 0, data: { error: e?.message || String(e) } })),
      detectDesktopMcpEnvironment(),
      inspectLocalProxyDaemon(keyFile),
    ]);
    const hasKey = fs.existsSync(keyFile);
    const pubkey = hasKey ? loadKeyRecord(keyFile).pubkey : null;
    const singboxBin = resolveSingboxBinary();
    return {
      mode: 'unified-headless-ed25519',
      version: CLI_VERSION,
      platform: os.platform(),
      keyFile,
      hasLocalKeypair: hasKey,
      pubkey,
      singboxAvailable: Boolean(singboxBin),
      singboxBin,
      desktopAppInstalled: detectInstalledDesktopApp(),
      localProxy,
      desktopMcpDetected: {
        listening: desktopProbe.listening,
        endpoint: desktopProbe.endpoint,
        note: desktopProbe.listening
          ? `YIVPN Desktop App Local MCP is listening at ${desktopProbe.endpoint}. Set YIVPN_MCP_TOKEN=<yivpn_mcp_...> to control live Desktop App split-tunneling instead.`
          : 'No running YIVPN Desktop App Local MCP detected; operating in Zero-Account Cloud + Rootless Proxy Daemon mode.',
      },
      serviceDiscovery: disc.data,
    };
  }

  if (name === 'get_vpn_status') {
    const localProxy = await inspectLocalProxyDaemon(keyFile);
    if (!fs.existsSync(keyFile)) {
      return {
        connected: localProxy.running,
        localProxy,
        desktopAppInstalled: detectInstalledDesktopApp(),
        hasLocalKeypair: false,
        entitlement: null,
        nextStepHint:
          'Call connect_vpn (auto-claims the $0 90m/1GiB free trial and starts 127.0.0.1:10808; pass systemProxy=true on personal Windows/macOS desktops if browsers should also use YIVPN).',
      };
    }
    const keyRecord = loadKeyRecord(keyFile);
    const res = await apiRequest({ baseUrl, method: 'GET', subPath: '/status', keyRecord });
    if (res.status >= 400) throw new Error(JSON.stringify(res.data));
    return {
      connected: localProxy.running,
      localProxy,
      desktopAppInstalled: detectInstalledDesktopApp(),
      hasLocalKeypair: true,
      ...res.data,
    };
  }

  if (name === 'connect_vpn') {
    const region = String(args.region || 'auto');
    const port = Number(args.port || 10808);
    const autoTrial = args.autoClaimTrial !== undefined ? Boolean(args.autoClaimTrial) : true;
    const systemProxy = Boolean(args.systemProxy);
    const forceSystemProxy = Boolean(args.forceSystemProxy);
    return await startLocalProxyDaemon({ baseUrl, keyFile, region, port, autoTrial, systemProxy, forceSystemProxy });
  }

  if (name === 'disconnect_vpn') {
    const isDefaultKey = path.resolve(keyFile) === path.resolve(DEFAULT_KEY_PATH);
    return await stopLocalProxyDaemon(keyFile, 10808, { allowBlindProxyRestore: isDefaultKey });
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
    const out =
      typeof res.data === 'object'
        ? { statusCode: res.status, keyCreated: created, pubkey: record.pubkey, ...res.data }
        : { statusCode: res.status, body: res.data };
    const payHeader = res.headers.get('payment-required');
    if (payHeader) out.paymentRequiredHeader = payHeader;
    return out;
  }

  if (name === 'diagnose_connection') {
    const rawTarget = String(args.target || '').trim();
    if (!rawTarget) throw new Error('MISSING_TARGET: target is required.');
    const urlObj = rawTarget.includes('://') ? new URL(rawTarget) : new URL(`https://${rawTarget}`);
    if (!['https:', 'http:'].includes(urlObj.protocol) || urlObj.username || urlObj.password) {
      throw new Error('FORBIDDEN_TARGET: Only http:// and https:// public targets without credentials are allowed.');
    }
    if (isPrivateOrLoopbackHost(urlObj.hostname)) {
      throw new Error(`FORBIDDEN_TARGET: Refusing to probe private or loopback host "${urlObj.hostname}".`);
    }
    const lookedUp = await dns.lookup(urlObj.hostname, { all: true, verbatim: true }).catch(() => []);
    if (!lookedUp.length || lookedUp.some((entry) => isBlockedIpAddress(entry.address))) {
      throw new Error(`FORBIDDEN_TARGET: Host "${urlObj.hostname}" did not resolve to a public IP address.`);
    }
    const [v4, v6, localProxy] = await Promise.all([
      dns.resolve4(urlObj.hostname).catch(() => []),
      dns.resolve6(urlObj.hostname).catch(() => []),
      inspectLocalProxyDaemon(keyFile),
    ]);
    const started = Date.now();
    let directProbe;
    try {
      const resp = await fetch(urlObj.toString(), {
        redirect: 'manual',
        signal: AbortSignal.timeout(5000),
      });
      directProbe = { reachable: true, httpStatus: resp.status, latencyMs: Date.now() - started };
    } catch (e) {
      directProbe = { reachable: false, error: e?.message || String(e), latencyMs: Date.now() - started };
    }

    const tunnelProbe = localProxy.running
      ? await probeHttpsViaHttpProxy({
          proxyPort: localProxy.port,
          targetUrl: urlObj.toString(),
          timeoutMs: 6000,
        })
      : null;

    return {
      target: rawTarget,
      host: urlObj.hostname,
      dns: { ipv4: v4, ipv6: v6 },
      directProbe,
      localProxyRunning: localProxy.running,
      tunnelProbe,
    };
  }

  const keyRecord = loadKeyRecord(keyFile);

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
    const text = validateRemoteSingboxConfig(res.data, mode, port);
    if (args.outPath) {
      const outPath = validateSafeConfigOutputPath(args.outPath, keyFile, { confineToAgentDirs: true });
      fs.writeFileSync(outPath, text, { encoding: 'utf8', mode: 0o600 });
      try {
        fs.chmodSync(outPath, 0o600);
      } catch {}
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
      singboxConfig: JSON.parse(text),
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
      try {
        fs.chmodSync(backupPath, 0o600);
      } catch {}
      saveKeyRecord(keyFile, nextRecord);
      return { ...res.data, keyFile, backupKeyFile: backupPath };
    }
    if (args.action === 'revoke') {
      await stopLocalProxyDaemon(keyFile);
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
        serverInfo: { name: 'yivpn-agent-mcp', version: CLI_VERSION },
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
          Host: parsed.host,
          ...(mcpToken ? { Authorization: `Bearer ${mcpToken}` } : {}),
        },
        body: JSON.stringify(msg),
      });
      if (resp.status === 202 || resp.status === 204 || isNotification) continue;
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
  console.log(`yivpn-agent-cli v${CLI_VERSION} — Unified YIVPN AI Agent MCP Server, Proxy Daemon & API CLI

Usage:
  yivpn-agent <command> [options]

Commands:
  mcp         Start unified Model Context Protocol (MCP) stdio server (auto-detects environment):
                • Desktop App Bridge (auto-selected when YIVPN_MCP_TOKEN / --desktop is provided):
                  Auto-discovers YIVPN Desktop App Local MCP port (mcp-config.json / 38410 / 38419) for live sing-box routing & rollback.
                • Zero-App Cloud + Rootless Daemon Mode (auto-selected in VMs, Docker & keyless setups):
                  Exposes 11 MCP tools including connect_vpn, disconnect_vpn, claim_free_trial ($0 90m/1GiB), guardrails & x402/Checkout.
  connect         Start or switch the managed rootless sing-box proxy on 127.0.0.1:10808 (--auto-trial [--system-proxy])
  disconnect      Stop the managed rootless sing-box proxy daemon and restore OS system proxy if enabled
  launch-desktop  Launch installed YIVPN Desktop GUI app (Windows/macOS, 90m/day free OS-wide Global TUN)
  trial           Claim an instant $0 90-minute / 1 GiB free trial on US-Ohio (works directly or behind proxies/cloud IPs)
  keygen          Generate a local Ed25519 keypair (~/.yivpn-agent/key.json)
  discover        Query unauthenticated service capabilities, terms & payment rails
  buy             Purchase/extend multi-region VPN time (--months 1|3|6|12 --rail checkout|x402 --currency usd|cny)
  status          Inspect live local proxy daemon, active external proxies, Desktop GUI & Ed25519 entitlement (--wait)
  locations       List provisioned Hysteria2 & VLESS+REALITY exit nodes
  settings        Read or update DNS guardrails (--guardrails malware,ads,smart_split --region US)
  config          Export raw sing-box 1.12+ / 1.14+ config (--mode proxy|tun --out file.json)
  rotate          Atomically migrate remaining time to a newly generated Ed25519 keypair
  revoke          Stop local daemon and immediately revoke entitlement
  version         Print CLI version JSON
  selftest        Verify Ed25519 signing, BOM tolerance, environment auto-detection, and MCP JSON-RPC round-trip

Options:
  --mcp-url <url>        Desktop Local MCP URL ($YIVPN_MCP_URL; auto-discovers 38410 / 38419 when omitted)
  --mcp-token <tok>      Desktop Local MCP token ($YIVPN_MCP_TOKEN)
  --headless             Force Zero-App Cloud/Daemon MCP mode even if YIVPN_MCP_TOKEN is set
  --desktop              Force Desktop App MCP bridge mode
  --region <code>        Target region for connect / config / settings (auto|US|JP|SG|HK)
  --port <num>           Local proxy port for connect / config (default: 10808)
  --auto-trial           Auto-claim $0 90m/1GiB free trial during "connect" if no active key exists
  --system-proxy         Configure Windows/macOS OS system proxy to 127.0.0.1:<port> (skips active external proxies; auto-restores on disconnect/expiry)
  --force-system-proxy   Force-overwrite OS system proxy even when another local proxy app is actively listening
  --singbox-bin <path>   Explicit path to sing-box binary ($YIVPN_SINGBOX_BIN)
  --key-file <path>      Path to Ed25519 key JSON (default: ~/.yivpn-agent/key.json)
  --api-base <url>       API base URL (default: https://yivpn.net/api/v1/vpn)
  -v, --version          Print CLI version
  -h, --help             Show this help message
`);
}

async function run() {
  const { command, flags } = parseArgs(process.argv.slice(2));
  if (flags.version || command === 'version') {
    console.log(JSON.stringify({ ok: true, name: 'yivpn-agent-cli', version: CLI_VERSION }));
    return;
  }
  if (flags.help || command === 'help') {
    printHelp();
    return;
  }

  const allowCustomApiBase = Boolean(flags['allow-custom-api-base']);
  const baseUrl = validateTrustedApiBase(String(flags['api-base'] || DEFAULT_BASE_URL), allowCustomApiBase);
  const keyFile = path.resolve(String(flags['key-file'] || DEFAULT_KEY_PATH));

  if (command === '__watchdog') {
    await runSystemProxyWatchdog({ baseUrl, keyFile });
    return;
  }

  if (command === 'launch-desktop') {
    const out = launchInstalledDesktopApp();
    console.log(JSON.stringify(out, null, 2));
    return;
  }

  if (command === 'mcp') {
    const explicitMcpUrl = flags['mcp-url'] ? String(flags['mcp-url']) : process.env.YIVPN_MCP_URL || '';
    const mcpToken = flags['mcp-token'] ? String(flags['mcp-token']) : process.env.YIVPN_MCP_TOKEN || '';
    const useDesktop = Boolean(flags.desktop || (!flags.headless && mcpToken));
    if (useDesktop) {
      const detected = await detectDesktopMcpEnvironment(explicitMcpUrl);
      await runDesktopMcpStdioBridge(detected.endpoint, mcpToken);
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

    const tmpDir = path.join(os.tmpdir(), `yivpn-selftest-${process.pid}-${Date.now()}`);
    const tmpKeyFile = path.join(tmpDir, 'key.json');
    fs.mkdirSync(tmpDir, { recursive: true });
    // Verify Windows PowerShell 5.1 UTF-8 BOM tolerance on JSON files
    const bomFile = path.join(tmpDir, 'bom-test.json');
    fs.writeFileSync(bomFile, '\uFEFF' + JSON.stringify({ hello: 'world' }), 'utf8');
    assert.equal(readJsonTextStripBom(bomFile).hello, 'world', 'UTF-8 BOM stripping failed');
    fs.rmSync(bomFile, { force: true });
    const initRes = await handleHeadlessMcpJsonRpc(
      { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26' } },
      { baseUrl, keyFile: tmpKeyFile }
    );
    assert.equal(initRes.result.serverInfo.name, 'yivpn-agent-mcp');
    assert.equal(initRes.result.serverInfo.version, CLI_VERSION);

    const toolsRes = await handleHeadlessMcpJsonRpc(
      { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} },
      { baseUrl, keyFile: tmpKeyFile }
    );
    assert.equal(toolsRes.result.tools.length, 11);
    const toolNames = toolsRes.result.tools.map((t) => t.name);
    for (const coreTool of [
      'get_capabilities',
      'get_vpn_status',
      'list_servers',
      'connect_vpn',
      'disconnect_vpn',
      'diagnose_connection',
    ]) {
      assert.ok(toolNames.includes(coreTool), `Missing unified MCP tool: ${coreTool}`);
    }

    // Keyless get_vpn_status & disconnect_vpn must succeed cleanly without throwing
    const statusRes = await handleHeadlessMcpJsonRpc(
      { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'get_vpn_status', arguments: {} } },
      { baseUrl, keyFile: tmpKeyFile }
    );
    assert.equal(statusRes.result.isError, false);
    assert.equal(statusRes.result.structuredContent.hasLocalKeypair, false);
    assert.equal(statusRes.result.structuredContent.connected, false);

    const discRes = await handleHeadlessMcpJsonRpc(
      { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'disconnect_vpn', arguments: {} } },
      { baseUrl, keyFile: tmpKeyFile }
    );
    assert.equal(discRes.result.isError, false);
    assert.equal(discRes.result.structuredContent.disconnected, true);

    const desktopProbe = await detectDesktopMcpEnvironment();
    assert.ok(desktopProbe.endpoint.startsWith('http://127.0.0.1:'));

    assert.equal(parseLoopbackProxyPort('127.0.0.1:3067'), 3067);
    assert.equal(parseLoopbackProxyPort('http=127.0.0.1:7890;https=127.0.0.1:7890'), 7890);
    assert.equal(parseLoopbackProxyPort('10.0.0.1:8080'), null);
    const osProxyCheck = await inspectOsSystemProxyState(10808);
    assert.equal(typeof osProxyCheck.supported, 'boolean');

    // Security self-tests: IP blocklist, API base trust boundary, remote sing-box config sanitizer, outPath confinement
    assert.equal(isPrivateOrLoopbackHost('::ffff:127.0.0.1'), true);
    assert.equal(isPrivateOrLoopbackHost('2130706433'), true);
    assert.equal(isPrivateOrLoopbackHost('0x7f000001'), true);
    assert.equal(isPrivateOrLoopbackHost('100.64.0.1'), true);
    assert.equal(isPrivateOrLoopbackHost('1.1.1.1'), false);
    assert.throws(() => validateTrustedApiBase('https://evil.example.com/api/v1/vpn', false), /UNTRUSTED_API_BASE/);
    assert.equal(validateTrustedApiBase('https://yivpn.net/api/v1/vpn', false), 'https://yivpn.net/api/v1/vpn');
    assert.throws(
      () =>
        validateRemoteSingboxConfig(
          {
            log: { output: '/etc/cron.d/pwn' },
            inbounds: [{ type: 'mixed', listen: '127.0.0.1', listen_port: 10808 }],
            outbounds: [{ type: 'vless', server: '57.180.66.66', server_port: 443 }],
          },
          'proxy',
          10808
        ),
      /UNSAFE_REMOTE_CONFIG/
    );
    assert.throws(
      () =>
        validateRemoteSingboxConfig(
          {
            inbounds: [{ type: 'mixed', listen: '0.0.0.0', listen_port: 10808 }],
            outbounds: [{ type: 'vless', server: '57.180.66.66', server_port: 443 }],
          },
          'proxy',
          10808
        ),
      /UNSAFE_REMOTE_CONFIG/
    );
    assert.throws(() => validateSafeConfigOutputPath('/etc/pwn.conf', tmpKeyFile), /UNSAFE_OUTPUT_PATH/);

    const devHash = computeDeviceHash();
    if (devHash) {
      assert.match(devHash, /^[0-9a-f]{64}$/);
    }

    fs.rmSync(tmpDir, { recursive: true, force: true });

    console.log(
      JSON.stringify(
        {
          ok: true,
          version: CLI_VERSION,
          profile: 'ed25519-v1',
          mcpTools: toolsRes.result.tools.length,
          singboxDetected: Boolean(resolveSingboxBinary()),
          desktopMcpListening: desktopProbe.listening,
          deviceHashAvailable: Boolean(devHash),
          pubkey_sample: rec.pubkey,
        },
        null,
        2
      )
    );
    return;
  }

  if (command === 'connect') {
    const region = String(flags.region || 'auto');
    const port = Number(flags.port || 10808);
    const autoTrial = Boolean(flags['auto-trial'] || flags.trial);
    const systemProxy = Boolean(flags['system-proxy']);
    const forceSystemProxy = Boolean(flags['force-system-proxy']);
    const singboxBin = flags['singbox-bin'] ? String(flags['singbox-bin']) : '';
    const out = await startLocalProxyDaemon({
      baseUrl,
      keyFile,
      region,
      port,
      autoTrial,
      systemProxy,
      forceSystemProxy,
      singboxBin,
    });
    console.log(JSON.stringify(out, null, 2));
    return;
  }

  if (command === 'disconnect') {
    const port = Number(flags.port || 10808);
    const out = await stopLocalProxyDaemon(keyFile, port);
    console.log(JSON.stringify(out, null, 2));
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

  if (command === 'status') {
    const localProxy = await inspectLocalProxyDaemon(keyFile);
    const desktopApp = detectInstalledDesktopApp();
    if (!fs.existsSync(keyFile)) {
      console.log(
        JSON.stringify({ ok: true, has_local_keypair: false, desktop_app: desktopApp, local_proxy: localProxy }, null, 2)
      );
      return;
    }
    const keyRecord = loadKeyRecord(keyFile);
    const wait = Boolean(flags.wait);
    const timeoutMs = Number(flags['timeout-sec'] || 300) * 1000;
    const deadline = Date.now() + timeoutMs;
    while (true) {
      const res = await apiRequest({ baseUrl, method: 'GET', subPath: '/status', keyRecord });
      if (!wait || (res.data?.active && res.data?.ready) || Date.now() >= deadline) {
        const merged =
          typeof res.data === 'object' && res.data !== null
            ? { ...res.data, desktop_app: desktopApp, local_proxy: localProxy }
            : { body: res.data, desktop_app: desktopApp, local_proxy: localProxy };
        console.log(JSON.stringify(merged, null, 2));
        if (res.status >= 400) process.exitCode = 1;
        return;
      }
      await new Promise((r) => setTimeout(r, 3000));
    }
  }

  const keyRecord = loadKeyRecord(keyFile);

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
      const outPath = validateSafeConfigOutputPath(flags.out, keyFile, { confineToAgentDirs: false });
      const text =
        format === 'singbox'
          ? validateRemoteSingboxConfig(res.data, mode, port)
          : typeof res.data === 'string'
            ? res.data
            : JSON.stringify(res.data, null, 2) + '\n';
      fs.writeFileSync(outPath, text, { encoding: 'utf8', mode: 0o600 });
      try {
        fs.chmodSync(outPath, 0o600);
      } catch {}
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
    try {
      fs.chmodSync(backupPath, 0o600);
    } catch {}
    saveKeyRecord(keyFile, nextRecord);
    console.log(JSON.stringify({ ...res.data, key_file: keyFile, backup_key_file: backupPath }, null, 2));
    return;
  }

  if (command === 'revoke') {
    await stopLocalProxyDaemon(keyFile);
    const res = await apiRequest({ baseUrl, method: 'DELETE', subPath: '/entitlements', keyRecord });
    console.log(JSON.stringify(res.data, null, 2));
    if (res.status >= 400) process.exitCode = 1;
    return;
  }

  throw new Error(`Unknown command "${command}". Run "yivpn-agent --help" for usage.`);
}

const isMainModule = (() => {
  try {
    if (!process.argv[1]) return false;
    const a = fs.realpathSync(process.argv[1]);
    const b = fs.realpathSync(fileURLToPath(import.meta.url));
    return process.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b;
  } catch {
    return true;
  }
})();

if (isMainModule) {
  run().catch((err) => {
    console.error(JSON.stringify({ ok: false, error: err?.message || String(err) }, null, 2));
    process.exitCode = 1;
  });
}
