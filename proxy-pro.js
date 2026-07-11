const fs = require('fs');
const crypto = require('crypto');
const net = require('net');
const path = require('path');
const readline = require('readline');
const axios = require('axios');
const chalk = require('chalk');
const cliProgress = require('cli-progress');
const boxen = require('boxen');
const figlet = require('figlet');
const gradient = require('gradient-string');
const { HttpProxyAgent } = require('http-proxy-agent');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');

// --- Safety net: proxy handshakes (esp. HTTP-CONNECT tried against SOCKS
// servers) often emit socket errors AFTER axios has already resolved/rejected.
// Those bubble up as uncaught exceptions and crash the whole test run.
// Swallow the known-benign network noise so the tester keeps going.
const _SWALLOW_CODES = new Set([
  'ECONNRESET','EPIPE','ECONNABORTED','ECONNREFUSED','ETIMEDOUT','EHOSTUNREACH',
  'ENETUNREACH','EPROTO','EAI_AGAIN','ERR_SOCKET_CLOSED','ERR_STREAM_PREMATURE_CLOSE',
  'ERR_TLS_CERT_ALTNAME_INVALID','ERR_SSL_WRONG_VERSION_NUMBER','ERR_SSL_PACKET_LENGTH_TOO_LONG','ERR_BAD_RESPONSE'
]);
function _isBenign(e) {
  return !!(e && (_SWALLOW_CODES.has(e.code) || /socket hang up|Client network socket|aborted/i.test(e.message || '')));
}
process.on('uncaughtException', (e) => {
  if (_isBenign(e)) return;
  console.error('[fatal]', e);
  try { require('fs').appendFileSync(require('path').join(__dirname, 'output', 'run.log'),
        `[${new Date().toISOString()}] uncaughtException: ${e && (e.stack || e.message || e)}\n`); } catch {}
});
process.on('unhandledRejection', (e) => {
  if (_isBenign(e)) return;
  // v7.6: no longer silently swallowed — log real bugs to run.log for later inspection
  try { require('fs').appendFileSync(require('path').join(__dirname, 'output', 'run.log'),
        `[${new Date().toISOString()}] unhandledRejection: ${e && (e.stack || e.message || e)}\n`); } catch {}
});



const ROOT = __dirname;
const OUTPUT = path.join(ROOT, 'output');
// v7.7.7: numbered history folders instead of archive/ snapshots.
// Each collect run writes to output/All_proxy/All_proxy_<N>/
// Each test    run writes to output/Result_test/results_<N>/
const BASE_COLLECT_DIR = path.join(OUTPUT, 'All_proxy');
const BASE_TEST_DIR    = path.join(OUTPUT, 'Result_test');
let COLLECT_DIR = BASE_COLLECT_DIR;   // current run dir (recomputed on write)
let TEST_DIR    = BASE_TEST_DIR;
let BY_TYPE_DIR = path.join(TEST_DIR, 'by_type');
let BY_COUNTRY_DIR = path.join(TEST_DIR, 'by_country');
const LINKS_FILE = path.join(ROOT, 'links.txt');
const FILES_FILE = path.join(ROOT, 'files.txt');          // list of local proxy files
const FILE_TYPES_FILE = path.join(ROOT, 'files_types.json'); // v7.7.5: per-file forced type ({ "<path>": "socks5" })
const CONFIG_FILE = path.join(ROOT, 'config.json');
const HISTORY_FILE = path.join(ROOT, 'history.json');
const PRIVATE_FILE = path.join(ROOT, 'private_sources.json');
const PASTED_FILE  = path.join(ROOT, 'pasted_proxies.txt'); // v7.9.0: Smart Paste inline proxies
const PASTED_SOURCES_FILE = path.join(ROOT, 'pasted_sources.json'); // v1.0.1: track which URLs/files came via Smart Paste
const AUTOCOLLECT_SEEN_FILE = path.join(ROOT, '.autocollect_seen.json'); // v7.7.1: remember which built-in URLs were already used
let LAST_COLLECTED = path.join(COLLECT_DIR, 'all_proxies_with_auth.txt');
let RESULT_JSON = path.join(TEST_DIR, 'tested_results.json');
const LOG_FILE = path.join(OUTPUT, 'run.log');
// v7.8.0: profiles + resume-state
const PROFILES_DIR = path.join(ROOT, 'profiles');
const RESUME_FILE = path.join(OUTPUT, '.resume.json');

// Return path to next numbered run dir: <base>/<prefix>_<N>. Ensures parent exists.
function nextRunDir(baseDir, prefix) {
  try { if (!fs.existsSync(baseDir)) fs.mkdirSync(baseDir, { recursive: true }); } catch {}
  let max = 0;
  try {
    for (const entry of fs.readdirSync(baseDir)) {
      const m = entry.match(new RegExp('^' + prefix + '_(\\d+)$', 'i'));
      if (m) { const n = parseInt(m[1], 10); if (n > max) max = n; }
    }
  } catch {}
  return path.join(baseDir, `${prefix}_${max + 1}`);
}
function latestRunDir(baseDir, prefix) {
  let max = 0, found = null;
  try {
    for (const entry of fs.readdirSync(baseDir)) {
      const m = entry.match(new RegExp('^' + prefix + '_(\\d+)$', 'i'));
      if (m) { const n = parseInt(m[1], 10); if (n > max) { max = n; found = path.join(baseDir, entry); } }
    }
  } catch {}
  return found;
}

// v7.8.0: hash of a proxy set — used by the Resume feature to know that the
// resume file belongs to the SAME list we're about to test (no accidental merges).
function hashProxyList(proxies) {
  const h = crypto.createHash('sha1');
  const keys = proxies.map(p => `${p.type}://${p.username||''}:${p.password||''}@${p.host}:${p.port}`).sort();
  for (const k of keys) h.update(k + '\n');
  return h.digest('hex');
}
function saveResume(state) {
  try { ensureDir(OUTPUT); fs.writeFileSync(RESUME_FILE, JSON.stringify(state)); } catch {}
}
function loadResume() {
  try { return JSON.parse(fs.readFileSync(RESUME_FILE, 'utf8')); } catch { return null; }
}
function clearResume() { try { fs.unlinkSync(RESUME_FILE); } catch {} }

// v7.8.0: named settings profiles. Users can save/load whole configs by name.
function listProfiles() {
  try { return fs.readdirSync(PROFILES_DIR).filter(f => f.endsWith('.json')).map(f => f.replace(/\.json$/, '')); }
  catch { return []; }
}
function saveProfile(name, config) {
  const safe = String(name).replace(/[^a-zA-Z0-9_.-]/g, '_');
  if (!safe) return null;
  try { if (!fs.existsSync(PROFILES_DIR)) fs.mkdirSync(PROFILES_DIR, { recursive: true }); } catch {}
  const fp = path.join(PROFILES_DIR, safe + '.json');
  fs.writeFileSync(fp, JSON.stringify(config, null, 2));
  return fp;
}
function loadProfile(name) {
  const safe = String(name).replace(/[^a-zA-Z0-9_.-]/g, '_');
  const fp = path.join(PROFILES_DIR, safe + '.json');
  try { return JSON.parse(fs.readFileSync(fp, 'utf8')); } catch { return null; }
}
function deleteProfile(name) {
  const safe = String(name).replace(/[^a-zA-Z0-9_.-]/g, '_');
  try { fs.unlinkSync(path.join(PROFILES_DIR, safe + '.json')); return true; } catch { return false; }
}

const APP_VERSION = '1.0.7';


const DEFAULT_SOURCE_URLS = [
  'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt',
  'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt',
  'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt',
  'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt',
  'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt',
  'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt',
  'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt',
  'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt',
  'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt',
  'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt',
  'https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt',
  'https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt',
  'https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt',
  'https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt',
  'https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all',
  'https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks4&timeout=10000&country=all',
  'https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all'
];

// v7.7.7: legacy no-op — archive/ was replaced by numbered run folders
// (output/All_proxy/All_proxy_N/ and output/Result_test/results_N/).
function resetSessionArchive() { /* kept for backward compatibility */ }
function archivePrevious() { return false; }

// ============================================================
// MODES - one-click bundles: each mode sets ALL speed/accuracy/depth knobs at once.
// User picks one mode; no need to touch conc/timeout/retries by hand.
// ============================================================
// Fields per mode:
//   speed/accuracy/depth knobs: timeoutMs, concurrency, retries, twoPhase, tcpTimeoutMs,
//   requiredSuccesses (how many endpoints must succeed to be Alive), coverage (max endpoints tried),
//   maxToTest, excellentScore, goodScore, maxExcellentLatencyMs, veryBestLimit,
//   smartProtocolFallback, checkAnonymity, checkGeo, doubleCheck (second confirmation probe),
//   testTypes.
// ============================================================
const TEST_MODES = {
  ultra:    { name: 'Ultra Speed',     description: 'Max speed. Built for 100k+ lists. 1 endpoint hit, no anon/geo.',
              timeoutMs: 6000,  concurrency: 400, retries: 2, twoPhase: true,  tcpTimeoutMs: 2500,
              requiredSuccesses: 1, coverage: 1, maxToTest: 0,
              excellentScore: 80, goodScore: 65, maxExcellentLatencyMs: 3500, veryBestLimit: 1000,
              smartProtocolFallback: false, checkAnonymity: false, checkGeo: false, doubleCheck: false,
              testTypes: ['http','https','socks4','socks5'] },
  fast:     { name: 'Fast Scan',       description: 'Fast + geo. 1 endpoint hit. Recommended for large lists.',
              timeoutMs: 8000,  concurrency: 250, retries: 3, twoPhase: true,  tcpTimeoutMs: 3000,
              requiredSuccesses: 1, coverage: 2, maxToTest: 0,
              excellentScore: 82, goodScore: 68, maxExcellentLatencyMs: 3200, veryBestLimit: 700,
              smartProtocolFallback: true, checkAnonymity: false, checkGeo: true, doubleCheck: false,
              testTypes: ['http','https','socks4','socks5'] },
  balanced: { name: 'Balanced (recommended)', description: 'Balanced speed / accuracy. 2 endpoint hits + anon + geo.',
              timeoutMs: 10000, concurrency: 150, retries: 5, twoPhase: true,  tcpTimeoutMs: 3500,
              requiredSuccesses: 2, coverage: 3, maxToTest: 0,
              excellentScore: 85, goodScore: 70, maxExcellentLatencyMs: 3000, veryBestLimit: 500,
              smartProtocolFallback: true, checkAnonymity: true, checkGeo: true, doubleCheck: false,
              testTypes: ['http','https','socks4','socks5'] },
  accurate: { name: 'Accurate',        description: 'High accuracy. 3 endpoint hits, no two-phase, double-check.',
              timeoutMs: 14000, concurrency: 80,  retries: 7, twoPhase: false, tcpTimeoutMs: 5000,
              requiredSuccesses: 3, coverage: 5, maxToTest: 0,
              excellentScore: 88, goodScore: 72, maxExcellentLatencyMs: 3500, veryBestLimit: 400,
              smartProtocolFallback: true, checkAnonymity: true, checkGeo: true, doubleCheck: true,
              testTypes: ['http','https','socks4','socks5'] },
  deep:     { name: 'Deep Inspect',    description: 'Deep. All endpoints tested, judge revalidated, lowest false-dead rate.',
              timeoutMs: 18000, concurrency: 50,  retries: 10, twoPhase: false, tcpTimeoutMs: 6000,
              requiredSuccesses: 4, coverage: 8, maxToTest: 0,
              excellentScore: 90, goodScore: 75, maxExcellentLatencyMs: 4000, veryBestLimit: 300,
              smartProtocolFallback: true, checkAnonymity: true, checkGeo: true, doubleCheck: true,
              testTypes: ['http','https','socks4','socks5'] },
  strict:   { name: 'Strict Very Best', description: 'Only the strongest survive. For picking top-tier proxies.',
              timeoutMs: 14000, concurrency: 60,  retries: 8, twoPhase: false, tcpTimeoutMs: 5000,
              requiredSuccesses: 4, coverage: 6, maxToTest: 0,
              excellentScore: 92, goodScore: 80, maxExcellentLatencyMs: 2000, veryBestLimit: 150,
              smartProtocolFallback: true, checkAnonymity: true, checkGeo: true, doubleCheck: true,
              testTypes: ['http','https','socks4','socks5'] },
  lowpc:    { name: 'Low PC / Weak Net', description: 'Light-weight for weak PC or slow internet.',
              timeoutMs: 12000, concurrency: 30,  retries: 5, twoPhase: true,  tcpTimeoutMs: 4500,
              requiredSuccesses: 1, coverage: 2, maxToTest: 0,
              excellentScore: 85, goodScore: 70, maxExcellentLatencyMs: 4500, veryBestLimit: 300,
              smartProtocolFallback: true, checkAnonymity: false, checkGeo: true, doubleCheck: false,
              testTypes: ['http','https','socks4','socks5'] },
  sample:   { name: 'Sample 1000',     description: 'First 1000 only (quick sanity check on a big list).',
              timeoutMs: 9000,  concurrency: 120, retries: 4, twoPhase: true,  tcpTimeoutMs: 3500,
              requiredSuccesses: 2, coverage: 3, maxToTest: 1000,
              excellentScore: 85, goodScore: 70, maxExcellentLatencyMs: 3500, veryBestLimit: 200,
              smartProtocolFallback: true, checkAnonymity: true, checkGeo: true, doubleCheck: false,
              testTypes: ['http','https','socks4','socks5'] }
};
// Backwards-compat alias for older code paths
const TEST_PRESETS = TEST_MODES;

const DEFAULT_CONFIG = {
  activeMode: 'balanced',
  activePreset: 'balanced', // legacy alias, kept in sync by applyMode()
  // v7.5.4: mixed pool — 204 endpoints + IP echo + simple sites
  testUrls: [
    'http://cp.cloudflare.com/generate_204',
    'http://www.gstatic.com/generate_204',
    'http://api.ipify.org?format=json',
    'http://httpbin.org/ip',
    'http://example.com/',
    'http://neverssl.com/',
    'https://cp.cloudflare.com/generate_204',
    'https://www.gstatic.com/generate_204',
    'https://api.ipify.org?format=json',
    'https://httpbin.org/ip'
  ],
  ipEchoUrl: 'https://api.ipify.org?format=json',
  ipEchoUrlHttp: 'http://api.ipify.org?format=json',
  judgeUrl: 'https://httpbin.org/get',
  timeoutMs: 10000, concurrency: 150, retries: 5, maxToTest: 0,
  twoPhase: true, tcpTimeoutMs: 3500,
  // v7.6: accuracy knobs (set by mode; can be overridden manually)
  requiredSuccesses: 2, coverage: 3, doubleCheck: false, perProxyMaxMs: 30000,
  veryBestLimit: 500, excellentScore: 85, goodScore: 70, maxExcellentLatencyMs: 3000,
  saveDead: true,
  testTypes: ['http', 'https', 'socks4', 'socks5'],
  smartProtocolFallback: true,
  sortBy: 'score', keepAuth: true, outputWithScheme: true,
  checkAnonymity: true, checkGeo: true, geoProvider: 'ip-api',
  countryFilter: [], excludeCountries: [],
  maskCredentialsInLogs: true, useHistory: false,
  // v7.6: high-volume checking is the norm -> rate-limit defaults to 0
  collectRateLimitMs: 0,
  proxyAuth: { enabled: false, username: '', password: '', applyToMissingOnly: true },
  schedule: { enabled: false, everyHours: 6, runCollect: true, runTest: true }
};

const store = { http: new Map(), https: new Map(), socks4: new Map(), socks5: new Map(), unknown: new Map() };
let PUBLIC_IP = null;

// ============================================================
// STOP CONTROLLER — global cancel flag (Ctrl+C or 'q')
// aborts in-flight axios + destroys sockets so workers unblock instantly
// ============================================================
const STOP = { requested: false, reason: '' };
let STOP_CONTROLLER = new AbortController();
function stopSignal() { return STOP_CONTROLLER.signal; }
function resetStop() {
  STOP.requested = false; STOP.reason = '';
  STOP_CONTROLLER = new AbortController();
}
function requestStop(reason) {
  if (STOP.requested) return;
  STOP.requested = true;
  STOP.reason = reason || 'user';
  try { STOP_CONTROLLER.abort(); } catch {}
  process.stdout.write('\n' + chalk.yellow.bold('⏸  Stop requested — aborting in-flight probes...\n'));
}

// ============================================================
// UI THEME
// ============================================================
const theme = {
  brand: gradient(['#00e5ff', '#00b0ff', '#7c4dff']),
  ok: chalk.hex('#00e676'),
  warn: chalk.hex('#ffb300'),
  err: chalk.hex('#ff5252'),
  info: chalk.hex('#40c4ff'),
  dim: chalk.hex('#78909c'),
  accent: chalk.hex('#7c4dff'),
  label: chalk.hex('#b0bec5'),
  value: chalk.hex('#eceff1').bold,
  key: chalk.hex('#00e5ff').bold
};

function banner() {
  const art = figlet.textSync('PROXY  PRO', { font: 'ANSI Shadow', horizontalLayout: 'fitted' });
  return theme.brand.multiline(art);
}

function panel(content, opts = {}) {
  return boxen(content, {
    padding: { top: 0, bottom: 0, left: 2, right: 2 },
    margin: 0,
    borderStyle: 'round',
    borderColor: 'cyan',
    ...opts
  });
}

function hardClear() {
  // \x1Bc = full reset (works on modern CMD/Windows Terminal), then wipe scrollback + move home
  try { process.stdout.write('\x1Bc\x1B[2J\x1B[3J\x1B[H'); } catch { console.clear(); }
}

function header() {
  hardClear();
  console.log(banner());
  console.log(theme.dim(`  - Collect - Two-Phase Test - Smart Protocol - Anonymity - Geo - Live Stop & Save -   v${APP_VERSION}`));
  console.log('');
}

// ============================================================
// UTILS
// ============================================================
function ensureDir(dir) { if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true }); }
function loadConfig() {
  try {
    if (!fs.existsSync(CONFIG_FILE)) { fs.writeFileSync(CONFIG_FILE, JSON.stringify(DEFAULT_CONFIG, null, 2)); return { ...DEFAULT_CONFIG, proxyAuth: { ...DEFAULT_CONFIG.proxyAuth }, schedule: { ...DEFAULT_CONFIG.schedule } }; }
    const loaded = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
    // v7.6 migration: old configs only had activePreset — mirror it into activeMode.
    if (loaded.activePreset && !loaded.activeMode) loaded.activeMode = loaded.activePreset;
    if (loaded.activeMode && !loaded.activePreset) loaded.activePreset = loaded.activeMode;
    // legacy modes that no longer exist → map to nearest v7.6 equivalent
    const legacyMap = { turbo: 'fast', quick: 'fast' };
    if (loaded.activeMode && legacyMap[loaded.activeMode]) { loaded.activeMode = legacyMap[loaded.activeMode]; loaded.activePreset = loaded.activeMode; }
    return { ...DEFAULT_CONFIG, ...loaded, proxyAuth: { ...DEFAULT_CONFIG.proxyAuth, ...(loaded.proxyAuth || {}) }, schedule: { ...DEFAULT_CONFIG.schedule, ...(loaded.schedule || {}) } };
  } catch { return { ...DEFAULT_CONFIG }; }
}
function saveConfig(c) { fs.writeFileSync(CONFIG_FILE, JSON.stringify(c, null, 2)); }
function loadHistory() { try { return fs.existsSync(HISTORY_FILE) ? JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf8')) : {}; } catch { return {}; } }
function saveHistory(h) { fs.writeFileSync(HISTORY_FILE, JSON.stringify(h, null, 2)); }
function ask(q) {
  return new Promise(resolve => {
    // v1.0.7: reset only Proxy Pro's stop-key handler before a menu prompt.
    // Do NOT remove all stdin "data" listeners: on Windows terminals that can
    // break readline's internal input handling and make number choices look stuck.
    try { if (typeof disableStopKey === 'function') disableStopKey({ keepOpen: true }); } catch {}
    try { process.stdin.removeListener('keypress', onKey); } catch {}
    try { if (process.stdin.isTTY && process.stdin.setRawMode) process.stdin.setRawMode(false); } catch {}
    try { process.stdin.resume(); } catch {}
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: !!process.stdin.isTTY });
    let done = false;
    const finish = (a) => { if (done) return; done = true; try { rl.close(); } catch {} resolve(a); };
    rl.on('close', () => finish(''));
    rl.question(q, a => finish(a));
  });
}
// v7.6: log rotation — keep run.log under 5 MB so long runs don't fill the disk.
function log(msg) {
  try {
    ensureDir(OUTPUT);
    try {
      const st = fs.statSync(LOG_FILE);
      if (st && st.size > 5 * 1024 * 1024) {
        const rotated = LOG_FILE + '.' + Date.now() + '.old';
        fs.renameSync(LOG_FILE, rotated);
      }
    } catch {}
    fs.appendFileSync(LOG_FILE, `[${new Date().toISOString()}] ${msg}\n`);
  } catch {}
}
function mask(s) { return String(s || '').replace(/([a-zA-Z0-9._%-]+):([^@\s]+)@/g, '****:****@'); }
function fmtDuration(ms) { const s = Math.round(ms / 1000); if (s < 60) return `${s}s`; const m = Math.floor(s / 60); const sr = s % 60; if (m < 60) return `${m}m${sr}s`; const h = Math.floor(m / 60); const mr = m % 60; return `${h}h${mr}m`; }

function normalizeHost(h) { return String(h || '').trim().replace(/^\[/, '').replace(/\]$/, '').toLowerCase(); }
function isValidIPv4(h) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(h) && h.split('.').every(x => +x >= 0 && +x <= 255); }
function isValidDomain(h) {
  if (h === 'localhost') return true;
  if (h.length > 253 || !h.includes('.') || h.includes('..')) return false;
  if (!/^[a-zA-Z0-9.-]+$/.test(h)) return false;
  return h.split('.').every(p => p.length && p.length <= 63 && !p.startsWith('-') && !p.endsWith('-'));
}
function isValidHost(h) { h = normalizeHost(h); if (!h) return false; return /^\d{1,3}(\.\d{1,3}){3}$/.test(h) ? isValidIPv4(h) : isValidDomain(h); }
function isValidPort(p) { return /^\d{1,5}$/.test(String(p)) && +p >= 1 && +p <= 65535; }
function cleanType(t, fb = 'unknown') { t = String(t || '').toLowerCase().trim(); return ['http','https','socks4','socks5'].includes(t) ? t : fb; }
function guessTypeFromUrl(u) {
  u = String(u || '').toLowerCase();
  if (u.includes('socks5')) return 'socks5';
  if (u.includes('socks4')) return 'socks4';
  if (u.includes('/https') || u.includes('https.txt') || u.includes('protocols/https')) return 'https';
  if (u.includes('/http') || u.includes('http.txt') || u.includes('protocols/http') || u.includes('proxy-list')) return 'http';
  return 'unknown';
}
function decodeSafe(v) { try { return decodeURIComponent(v); } catch { return v; } }
function proxyKey(i) { const a = i.username || i.password ? `${i.username}:${i.password}@` : ''; return `${i.type}://${a}${i.host}:${i.port}`; }
function authForProxy(i, config = null) {
  const user = i.username || '';
  const pass = i.password || '';
  if (user || pass) return { username: user, password: pass, source: 'line' };
  const pa = config && config.proxyAuth;
  if (pa && pa.enabled && (!pa.applyToMissingOnly || !(user || pass))) {
    return { username: pa.username || '', password: pa.password || '', source: 'global' };
  }
  return { username: '', password: '', source: '' };
}

function proxyToUrl(i, withAuth = true, config = null) {
  const t = cleanType(i.type, 'http');
  const au = withAuth ? authForProxy(i, config) : { username: '', password: '' };
  const a = withAuth && (au.username || au.password) ? `${encodeURIComponent(au.username)}:${encodeURIComponent(au.password)}@` : '';
  return `${t}://${a}${i.host}:${i.port}`;
}

function proxyToAgentUrl(i, config = null, schemeOverride = '') {
  // In public proxy lists, "HTTPS" usually means an HTTP proxy that supports
  // CONNECT to HTTPS targets, NOT a proxy server that itself speaks TLS.
  // Therefore https-list entries are tested with http://host:port first.
  const originalType = cleanType(i.type, 'http');
  const t = schemeOverride || (originalType === 'https' ? 'http' : originalType);
  const au = authForProxy(i, config);
  const a = (au.username || au.password) ? `${encodeURIComponent(au.username)}:${encodeURIComponent(au.password)}@` : '';
  return `${t}://${a}${i.host}:${i.port}`;
}

function addProxy(item, stats, defaults) {
  stats.rawFound++;
  const type = cleanType(item.type, 'unknown');
  const host = normalizeHost(item.host);
  const port = String(item.port || '').trim();
  let username = item.username ? String(item.username).trim() : '';
  let password = item.password ? String(item.password).trim() : '';
  // v7.7: per-source credentials for PRIVATE sources — applied only when line has no auth.
  if (defaults && (defaults.username || defaults.password) && !username && !password) {
    username = String(defaults.username || '').trim();
    password = String(defaults.password || '').trim();
  }
  // v7.7.4: honour the forced type from a PRIVATE source whenever the raw line
  // did NOT carry an explicit scheme. Previously we only overrode 'unknown',
  // so a private SOCKS5 file whose name/URL didn't contain "socks5" got
  // stored as 'http' (because fallbackType guessed http) and every SOCKS5
  // handshake later failed. User intent from the private-source form ALWAYS
  // wins over URL-guessing.
  let effectiveType = type;
  if (defaults && defaults.type && ['http','https','socks4','socks5'].includes(defaults.type)) {
    if (!item.__explicitScheme) effectiveType = defaults.type;
  }
  if (!isValidHost(host) || !isValidPort(port)) { stats.invalid++; return false; }
  const targetType = store[effectiveType] ? effectiveType : 'unknown';
  const clean = { type: targetType, host, port, username, password };
  const key = proxyKey(clean);
  if (store[targetType].has(key)) { stats.duplicates++; return false; }
  store[targetType].set(key, clean);
  stats.added++;
  return true;
}

function readUrlsFromText(text) {
  const found = String(text || '').match(/https?:\/\/[^\s'"<>]+/gi) || [];
  const urls = [];
  for (let u of found) { u = u.trim().replace(/[)\].,]+$/g, ''); if (!urls.includes(u)) urls.push(u); }
  return urls;
}
function normalizeText(t) { return String(t || '').replace(/\r/g, '\n').replace(/[;,]/g, '\n').replace(/[<>]/g, '').trim(); }

function extractProxies(text, sourceUrl, stats, defaults) {
  const fallbackType = guessTypeFromUrl(sourceUrl);
  const normalized = normalizeText(text);
  const lines = normalized.split(/\n+/);
  for (let line of lines) {
    line = String(line || '').trim().replace(/^:+/, '');
    if (!line) continue;
    let m;
    const urlRe = /\b(https?|socks4|socks5):\/\/(?:(.*?):(.*?)@)?(\[[0-9a-fA-F:]+\]|(?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|localhost):(\d{1,5})\b/gi;
    // v7.7.4: mark URL-scheme lines as explicit so PRIVATE defaults.type does NOT overwrite them.
    while ((m = urlRe.exec(line)) !== null) addProxy({ type: m[1], username: m[2] ? decodeSafe(m[2]) : '', password: m[3] ? decodeSafe(m[3]) : '', host: m[4], port: m[5], __explicitScheme: true }, stats, defaults);
    const noUrls = line.replace(/\b(https?|socks4|socks5):\/\/[^\s]+/gi, ' ');
    const authAtRe = /\b([^:\s@\/]+):([^@\s\/]+)@((?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|localhost):(\d{1,5})\b/gi;
    while ((m = authAtRe.exec(noUrls)) !== null) addProxy({ type: fallbackType, username: decodeSafe(m[1]), password: decodeSafe(m[2]), host: m[3], port: m[4] }, stats, defaults);
    const colonRe = /\b((?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|localhost):(\d{1,5})(?::([^:\s]+):([^:\s]+))?\b/g;
    while ((m = colonRe.exec(noUrls)) !== null) addProxy({ type: fallbackType, host: m[1], port: m[2], username: m[3] || '', password: m[4] || '' }, stats, defaults);
  }
  const objects = normalized.match(/\{[^{}]{10,600}\}/g) || [];
  for (const obj of objects) {
    const tm = obj.match(/"(?:type|protocol|scheme)"\s*:\s*"(https?|socks4|socks5)"/i);
    const hm = obj.match(/"(?:ip|host|addr|address)"\s*:\s*"([^"]+)"/i);
    const pm = obj.match(/"port"\s*:\s*"?(\d{1,5})"?/i);
    const um = obj.match(/"(?:user|username|login)"\s*:\s*"([^"]*)"/i);
    const ppm = obj.match(/"(?:pass|password)"\s*:\s*"([^"]*)"/i);
    if (hm && pm) addProxy({ type: tm ? tm[1] : fallbackType, host: hm[1], port: pm[1], username: um ? um[1] : '', password: ppm ? ppm[1] : '', __explicitScheme: !!tm }, stats, defaults);
  }
}

async function fetchText(url, timeoutMs = 30000) {
  const res = await axios.get(url, {
    timeout: timeoutMs, maxRedirects: 5, responseType: 'text',
    validateStatus: s => s >= 200 && s < 400,
    headers: { 'User-Agent': `Mozilla/5.0 ProxyProAdvanced/${APP_VERSION}`, 'Accept': 'text/plain,text/html,application/json,*/*' }
  });
  return typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
}

async function detectPublicIp() {
  if (PUBLIC_IP) return PUBLIC_IP;
  try {
    const r = await axios.get('https://api.ipify.org?format=json', { timeout: 8000 });
    PUBLIC_IP = r.data && r.data.ip ? r.data.ip : null;
  } catch { PUBLIC_IP = null; }
  return PUBLIC_IP;
}

// ============================================================
// COLLECT
// ============================================================
// Read local file paths saved in files.txt (one per line, blank/# ignored)
function readSavedLinks() {
  if (!fs.existsSync(LINKS_FILE)) return [];
  const all = readUrlsFromText(fs.readFileSync(LINKS_FILE, 'utf8'));
  // v7.7.1: never treat the built-in DEFAULT_SOURCE_URLS as "user sources".
  // Option 4 (Collect from MY sources) must ONLY use links the user added themselves.
  const defaults = new Set(DEFAULT_SOURCE_URLS);
  return all.filter(u => !defaults.has(u));
}

function writeSavedLinks(urls) {
  const defaults = new Set(DEFAULT_SOURCE_URLS);
  const unique = [...new Set(urls)].filter(u => !defaults.has(u));
  fs.writeFileSync(LINKS_FILE, unique.join('\n') + (unique.length ? '\n' : ''), 'utf8');
}

// v7.7.1: track which built-in URLs were already auto-collected so users can
// ask for "only NEW built-in sources" on the next Option 5 run.
function readAutocollectSeen() {
  try { if (!fs.existsSync(AUTOCOLLECT_SEEN_FILE)) return []; const a = JSON.parse(fs.readFileSync(AUTOCOLLECT_SEEN_FILE, 'utf8')); return Array.isArray(a) ? a : []; } catch { return []; }
}
function writeAutocollectSeen(list) {
  try { fs.writeFileSync(AUTOCOLLECT_SEEN_FILE, JSON.stringify([...new Set(list)], null, 2), 'utf8'); } catch {}
}

function readLocalFiles() {
  if (!fs.existsSync(FILES_FILE)) return [];
  return fs.readFileSync(FILES_FILE, 'utf8').split(/\r?\n/)
    .map(s => s.trim()).filter(s => s && !s.startsWith('#'));
}

function writeLocalFiles(files) {
  const unique = [...new Set(files)];
  fs.writeFileSync(FILES_FILE, unique.join('\n') + (unique.length ? '\n' : ''), 'utf8');
}

// v7.7.5: per-file forced protocol type (asked at add time for LOCAL FILES,
// since a filename like "myproxies.txt" carries no protocol hint).
function readFileTypes() {
  try {
    if (!fs.existsSync(FILE_TYPES_FILE)) return {};
    const raw = JSON.parse(fs.readFileSync(FILE_TYPES_FILE, 'utf8'));
    return raw && typeof raw === 'object' ? raw : {};
  } catch { return {}; }
}
function writeFileTypes(map) {
  try { fs.writeFileSync(FILE_TYPES_FILE, JSON.stringify(map || {}, null, 2), 'utf8'); } catch {}
}
function setFileType(filePath, type) {
  const m = readFileTypes();
  if (type && ['http','https','socks4','socks5'].includes(type)) m[filePath] = type;
  else delete m[filePath];
  writeFileTypes(m);
}
function getFileType(filePath) {
  const m = readFileTypes();
  return m[filePath] || '';
}

// v7.7: PRIVATE sources — link/file that needs a per-source username & password.
// Stored separately so they can't get mixed with public/auto sources and each
// entry carries its own credentials that are applied to proxies that parse
// without auth. Structure: [{ kind: 'url'|'file', value, username, password, type? }]
function readPrivateSources() {
  try {
    if (!fs.existsSync(PRIVATE_FILE)) return [];
    const arr = JSON.parse(fs.readFileSync(PRIVATE_FILE, 'utf8'));
    return Array.isArray(arr) ? arr.filter(x => x && x.value) : [];
  } catch { return []; }
}
function writePrivateSources(list) {
  fs.writeFileSync(PRIVATE_FILE, JSON.stringify(list || [], null, 2), 'utf8');
}

// v1.0.1: track which URLs / file paths were added via Smart Paste,
// so the Collect menu can offer a dedicated "Smart Paste only" scope.
function readPastedSources() {
  try {
    if (!fs.existsSync(PASTED_SOURCES_FILE)) return { urls: [], files: [] };
    const j = JSON.parse(fs.readFileSync(PASTED_SOURCES_FILE, 'utf8'));
    return { urls: Array.isArray(j.urls) ? j.urls : [], files: Array.isArray(j.files) ? j.files : [] };
  } catch { return { urls: [], files: [] }; }
}
function writePastedSources(p) {
  try { fs.writeFileSync(PASTED_SOURCES_FILE, JSON.stringify(p || { urls: [], files: [] }, null, 2), 'utf8'); } catch {}
}
function addPastedSources({ urls = [], files = [] } = {}) {
  const cur = readPastedSources();
  const U = new Set(cur.urls); for (const u of urls) if (u) U.add(u);
  const F = new Set(cur.files); for (const f of files) if (f) F.add(f);
  writePastedSources({ urls: [...U], files: [...F] });
}

async function selectLinkSubset(links, config) {
  if (config.__nonInteractive || links.length <= 1) return links;
  console.log(theme.info(`Saved source links: ${chalk.bold(links.length)}`));
  const answer = (await ask(theme.key(`How many links should be collected? (1-${links.length}, Enter = all): `))).trim();
  if (!answer) return links;
  const n = Number(answer);
  if (!Number.isInteger(n) || n < 1) {
    console.log(theme.warn('Invalid number; collecting all links.'));
    return links;
  }
  return links.slice(0, Math.min(n, links.length));
}

async function collectFromLinks(config, opts = {}) {
  // v7.7: opts.mode = 'user' (default) | 'auto' | 'private-only'
  //   'user'         -> only user's saved public links + files + private sources
  //   'auto'         -> only the built-in DEFAULT_SOURCE_URLS, NOT written to disk
  //   'private-only' -> only private sources
  // Nothing auto-restores DEFAULT_SOURCE_URLS into links.txt anymore.
  const mode = opts.mode || 'user';
  ensureDir(OUTPUT);
  // v7.7.2: a previous aborted test could leave STOP.requested = true, which would
  // make every "if (STOP.requested) break;" in the collect loops fire immediately
  // and silently produce 0 sources processed. Reset it at the start of every collect.
  resetStop();
  // v7.8.4: if a previous collect (Option 4/5/7) already filled the store this session,
  // let the user MERGE the new run with it instead of always wiping. This lets you
  // do Option 4 (MY sources) and then Option 5 (built-in) and test them together.
  const _prevCount = allCollected().length;
  let _mergePrevious = false;
  if (_prevCount > 0) {
    if (opts.merge === true || opts.__merge === true) _mergePrevious = true;
    else if (opts.merge === false || config.__nonInteractive) _mergePrevious = false;
    else {
      const ans = (await ask(theme.key(`Previous collect has ${chalk.bold(_prevCount)} proxies in memory. Merge NEW results with them? y/N: `))).trim().toLowerCase();
      _mergePrevious = (ans === 'y' || ans === 'yes' || ans === '1');
    }
  }
  if (!_mergePrevious) {
    for (const t of Object.keys(store)) store[t].clear();
  } else {
    console.log(theme.info(`▶ Merging: keeping ${_prevCount} previously collected proxies and adding new ones on top.`));
  }
  let links = [];
  let localFiles = [];
  let privateSources = [];
  if (mode === 'auto') {
    // v7.7.1: interactive built-in auto-collect — ask how many built-in
    // sources to pull from and whether to skip ones already used before.
    // Nothing is ever written to links.txt.
    const seen = new Set(readAutocollectSeen());
    const allDefaults = [...DEFAULT_SOURCE_URLS];
    const freshDefaults = allDefaults.filter(u => !seen.has(u));
    let pool = allDefaults;
    if (!config.__nonInteractive) {
      console.log(theme.info(`Built-in sources available: ${chalk.bold(allDefaults.length)}   already used: ${chalk.bold(allDefaults.length - freshDefaults.length)}   new: ${chalk.bold(freshDefaults.length)}`));
      const onlyNew = /^(y|1|yes|true|on)/i.test((await ask(theme.key('Only NEW built-in sources (skip ones already auto-collected)? y/N: '))).trim());
      pool = onlyNew ? (freshDefaults.length ? freshDefaults : allDefaults) : allDefaults;
      if (onlyNew && !freshDefaults.length) console.log(theme.warn('No new built-in sources left — falling back to all built-in sources.'));
      const ans = (await ask(theme.key(`How many built-in link(s) should be collected? (1-${pool.length}, Enter = all): `))).trim();
      if (ans) {
        const n = Number(ans);
        if (Number.isInteger(n) && n >= 1) pool = pool.slice(0, Math.min(n, pool.length));
        else console.log(theme.warn('Invalid number; collecting all.'));
      }
    }
    links = pool;
    writeAutocollectSeen([...seen, ...links]);
    console.log(theme.info(`Auto-collect mode: using ${links.length} built-in source(s). Your saved sources are NOT touched.`));
  } else if (mode === 'private-only') {
    privateSources = readPrivateSources();
    if (!privateSources.length) { console.log(theme.warn('No private sources saved. Add them from menu > Add sources > Private.')); return; }
    links = [];
    localFiles = [];
  } else {
    links = readSavedLinks();
    const rawLocalFiles = readLocalFiles();
    localFiles = rawLocalFiles.filter(fp => fs.existsSync(fp));
    const missingFiles = rawLocalFiles.filter(fp => !fs.existsSync(fp));
    if (missingFiles.length) {
      writeLocalFiles(localFiles);
      console.log(theme.warn(`Ignored and removed ${missingFiles.length} missing local file path(s) from files.txt.`));
      log(`removed missing local files: ${missingFiles.join(' | ')}`);
    }
    privateSources = readPrivateSources();
    // v1.0.1: scope filter — 'public' excludes Smart Paste sources; 'pasted' keeps only them.
    const scope = opts.scope || 'all';
    if (scope !== 'all') {
      const past = readPastedSources();
      const pUrls = new Set(past.urls);
      const pFiles = new Set(past.files);
      pFiles.add(PASTED_FILE);
      if (scope === 'public') {
        links = links.filter(u => !pUrls.has(u));
        localFiles = localFiles.filter(f => !pFiles.has(f));
        privateSources = [];
      } else if (scope === 'pasted') {
        links = links.filter(u => pUrls.has(u));
        localFiles = localFiles.filter(f => pFiles.has(f));
        privateSources = [];
      } else if (scope === 'no-private') {
        // v1.0.5: keep public + Smart Paste URLs/files, drop private user:pass sources.
        privateSources = [];
      }
    }
  }
  if (mode === 'user') links = await selectLinkSubset(links, config);
  const totalSources = links.length + localFiles.length + privateSources.length;
  if (!totalSources) {
    console.log(theme.warn('No sources to collect from. Add links/files, or use "Auto-collect from built-in sources".'));
    return;
  }
  const stats = { rawFound: 0, added: 0, duplicates: 0, invalid: 0, sourcesOk: 0, sourcesFail: 0 };
  const failedUrls = [];
  const failedFiles = [];
  const failedPrivate = [];
  console.log(theme.info(`▶ Collecting from ${chalk.bold(links.length)} link(s) + ${chalk.bold(localFiles.length)} file(s) + ${chalk.bold(privateSources.length)} private source(s)...\n`));
  const bar = new cliProgress.SingleBar({
    format: `  ${chalk.cyan('Sources')} ${chalk.hex('#7c4dff')('│{bar}│')} {value}/{total}  ${chalk.gray('•')} added=${chalk.green('{added}')}  dup=${chalk.yellow('{dup}')}  fail=${chalk.red('{fail}')}`,
    barCompleteChar: '█', barIncompleteChar: '░', hideCursor: true, barsize: 32
  }, cliProgress.Presets.shades_classic);
  bar.start(totalSources, 0, { added: 0, dup: 0, fail: 0 });
  // Local files first (fast, offline)
  // v7.7.5: pass the user-picked forced type per file so a filename like
  // "myproxies.txt" is still tested as socks5/http exactly as chosen at add time.
  const fileTypeMap = readFileTypes();
  for (const fp of localFiles) {
    if (STOP.requested) break;
    try {
      if (!fs.existsSync(fp)) throw new Error('file not found');
      const txt = fs.readFileSync(fp, 'utf8');
      const forced = fileTypeMap[fp];
      const defs = forced ? { type: forced } : undefined;
      extractProxies(txt, fp, stats, defs);
      stats.sourcesOk++;
    } catch (e) {
      stats.sourcesFail++;
      failedFiles.push(fp);
      log(`file fail ${fp}: ${e.message}`);
    }
    bar.increment(1, { added: stats.added, dup: stats.duplicates, fail: stats.sourcesFail });
  }
  for (const url of links) {
    if (STOP.requested) break;
    try {
      const txt = await fetchText(url);
      extractProxies(txt, url, stats);
      stats.sourcesOk++;
    } catch (e) {
      stats.sourcesFail++;
      failedUrls.push(url);
      log(`collect fail ${url}: ${e.message || e.code}`);
    }
    bar.increment(1, { added: stats.added, dup: stats.duplicates, fail: stats.sourcesFail });
    if (config.collectRateLimitMs > 0) await new Promise(r => setTimeout(r, config.collectRateLimitMs));
  }
  // v7.7: PRIVATE sources — each carries its own credentials applied to auth-less lines.
  for (const src of privateSources) {
    if (STOP.requested) break;
    const defaults = { username: src.username || '', password: src.password || '', type: src.type || '' };
    try {
      let txt = '';
      if (src.kind === 'url') txt = await fetchText(src.value);
      else txt = fs.readFileSync(src.value, 'utf8');
      extractProxies(txt, src.value, stats, defaults);
      stats.sourcesOk++;
    } catch (e) {
      stats.sourcesFail++;
      failedPrivate.push(src.value);
      log(`private collect fail ${src.value}: ${e.message || e.code}`);
    }
    bar.increment(1, { added: stats.added, dup: stats.duplicates, fail: stats.sourcesFail });
  }
  bar.stop();
  writeCollectOutputs(config);
  const _allC = allCollected();
  const _cnt = (t) => _allC.filter(p => p.type === t).length;
  const box = panel(
    `${theme.ok('✔ Collected')}  ${theme.value(stats.added)} unique proxies\n` +
    `${theme.label('Sources OK  :')} ${theme.value(stats.sourcesOk)}   ${theme.label('failed:')} ${chalk.red(stats.sourcesFail)}\n` +
    `${theme.label('Duplicates  :')} ${theme.value(stats.duplicates)}   ${theme.label('invalid:')} ${chalk.yellow(stats.invalid)}\n` +
    `${theme.label('By type     :')} ` +
      `${theme.key('http')} ${theme.value(_cnt('http'))}  ` +
      `${theme.key('https')} ${theme.value(_cnt('https'))}  ` +
      `${theme.key('socks4')} ${theme.value(_cnt('socks4'))}  ` +
      `${theme.key('socks5')} ${theme.value(_cnt('socks5'))}  ` +
      `${theme.key('unknown')} ${theme.value(_cnt('unknown'))}`,
    { borderColor: 'green' }
  );
  console.log('\n' + box);

  // Offer to remove failed sources from links.txt
  if (failedUrls.length && !STOP.requested && !config.__nonInteractive) {
    console.log('');
    console.log(panel(
      `${theme.warn('⚠ ' + failedUrls.length + ' source(s) failed to fetch:')}\n\n` +
      failedUrls.slice(0, 20).map((u, i) => theme.dim(`  ${String(i + 1).padStart(3)}. `) + u).join('\n') +
      (failedUrls.length > 20 ? theme.dim(`\n  ... and ${failedUrls.length - 20} more`) : ''),
      { borderColor: 'yellow' }
    ));
    const ans = (await ask('\n' + theme.key('Remove these failed links from your list? (y/N): '))).trim().toLowerCase();
    if (ans === 'y' || ans === 'yes') {
      const current = readSavedLinks();
      const failSet = new Set(failedUrls);
      const kept = current.filter(u => !failSet.has(u));
      writeSavedLinks(kept);
      console.log(theme.ok(`✔ Removed ${current.length - kept.length} failed link(s). Remaining: ${kept.length}.`));
    } else {
      console.log(theme.dim('Kept all links as-is.'));
    }
  }
}

function allCollected() {
  const out = [];
  for (const t of Object.keys(store)) for (const p of store[t].values()) out.push(p);
  return out;
}

function writeCollectOutputs(config) {
  ensureDir(OUTPUT);
  ensureDir(BASE_COLLECT_DIR);
  // v7.7.7: each collect writes into a fresh numbered subfolder (All_proxy_1, All_proxy_2, ...)
  COLLECT_DIR = nextRunDir(BASE_COLLECT_DIR, 'All_proxy');
  ensureDir(COLLECT_DIR);
  LAST_COLLECTED = path.join(COLLECT_DIR, 'all_proxies_with_auth.txt');
  const all = allCollected();
  const write = (name, arr) => fs.writeFileSync(path.join(COLLECT_DIR, name), arr.join('\n'), 'utf8');
  write('all_proxies.txt', all.map(p => proxyToUrl(p, false)));
  // Preserve the original type — including 'unknown' — so testing can try all schemes
  write('all_proxies_with_auth.txt', all.map(p => `${p.type}://${(p.username||p.password)?`${encodeURIComponent(p.username)}:${encodeURIComponent(p.password)}@`:''}${p.host}:${p.port}`));
  write('ip_port_only.txt', all.map(p => `${p.host}:${p.port}`));
  for (const t of ['http','https','socks4','socks5','unknown']) write(`${t}.txt`, all.filter(p => p.type === t).map(p => proxyToUrl(p, true)));
  write('collect_summary.txt', [
    'Collect Summary', '---------------',
    `Run folder: ${path.basename(COLLECT_DIR)}`,
    `Total unique: ${all.length}`,
    `HTTP:   ${all.filter(p => p.type==='http').length}`,
    `HTTPS:  ${all.filter(p => p.type==='https').length}`,
    `SOCKS4: ${all.filter(p => p.type==='socks4').length}`,
    `SOCKS5: ${all.filter(p => p.type==='socks5').length}`,
    `Unknown:${all.filter(p => p.type==='unknown').length}   (will be tested against ALL enabled protocols)`,
    `At: ${new Date().toISOString()}`
  ]);
  // Remove legacy loose files that older versions dropped at output root
  purgeLegacyRootFiles();
}

function purgeLegacyRootFiles() {
  const legacyRoot = [
    'all_proxies.txt','all_proxies_with_auth.txt','ip_port_only.txt','collect_summary.txt',
    'http.txt','https.txt','socks4.txt','socks5.txt','unknown.txt',
    'alive.txt','alive_with_auth.txt','alive_plain.txt','best.txt','elite.txt','anonymous.txt','dead.txt','results.csv','summary.txt','tested_results.json','auth_required.txt'
  ];
  for (const f of legacyRoot) { try { fs.unlinkSync(path.join(OUTPUT, f)); } catch {} }
  // v7.4.5: alive_plain.txt and anonymous.txt were merged into alive.txt / elite.txt — drop leftovers
  for (const f of ['alive_plain.txt','anonymous.txt']) { try { fs.unlinkSync(path.join(BASE_TEST_DIR, f)); } catch {} }
  try {
    const oldByCountry = path.join(OUTPUT, 'by_country');
    if (fs.existsSync(oldByCountry) && fs.statSync(oldByCountry).isDirectory()) {
      for (const f of fs.readdirSync(oldByCountry)) { try { fs.unlinkSync(path.join(oldByCountry, f)); } catch {} }
      try { fs.rmdirSync(oldByCountry); } catch {}
    }
  } catch {}
}

function parseProxyLine(line) {
  line = String(line || '').trim();
  if (!line || line.startsWith('#')) return null;
  const urlRe = /^(https?|socks4|socks5|unknown):\/\/(?:(.*?):(.*?)@)?([^:\/\s]+):(\d{1,5})/i;
  const m = line.match(urlRe);
  if (m) {
    const t = m[1].toLowerCase();
    const u = m[2] ? decodeSafe(m[2]) : ''; const pw = m[3] ? decodeSafe(m[3]) : '';
    return { type: t === 'unknown' ? 'unknown' : cleanType(t), username: u, password: pw, host: normalizeHost(m[4]), port: m[5], __hasAuth: !!(u || pw) };
  }
  const c = line.match(/^([^:\s]+):(\d{1,5})(?::([^:\s]+):([^:\s]+))?$/);
  // Schemeless bare host:port -> mark 'unknown' so tester tries every protocol
  if (c) { const u = c[3] || ''; const pw = c[4] || ''; return { type: 'unknown', username: u, password: pw, host: normalizeHost(c[1]), port: c[2], __hasAuth: !!(u || pw) }; }
  return null;
}

function readCollectedForTest(config) {
  // Prefer LAST_COLLECTED (current session). Otherwise pick the newest All_proxy_N/
  // subfolder written by a previous run, then legacy paths for backwards compat.
  let file = LAST_COLLECTED;
  if (!fs.existsSync(file)) {
    const latest = latestRunDir(BASE_COLLECT_DIR, 'All_proxy');
    if (latest) file = path.join(latest, 'all_proxies_with_auth.txt');
  }
  if (!fs.existsSync(file)) file = path.join(BASE_COLLECT_DIR, 'all_proxies_with_auth.txt');
  if (!fs.existsSync(file)) file = path.join(OUTPUT, 'all_proxies_with_auth.txt');
  if (!fs.existsSync(file)) return [];
  const list = fs.readFileSync(file, 'utf8').split(/\r?\n/).map(parseProxyLine).filter(Boolean);
  const seen = new Set();
  const enabled = config.testTypes || [];
  const before = list.length;
  const out = list.filter(p => {
    // 'unknown' passes as long as ANY type is enabled (dispatcher will iterate)
    if (p.type !== 'unknown' && !enabled.includes(p.type)) return false;
    if (p.type === 'unknown' && !enabled.length) return false;
    const k = proxyKey(p); if (seen.has(k)) return false; seen.add(k); return true;
  });
  const dupCount = before - out.length;
  if (dupCount > 0) console.log(theme.dim(`↷ dedup: ${dupCount} duplicate/filtered line(s) dropped (${out.length} unique to test).`));
  return out;
}



// ============================================================
// TESTING — Phase 1 TCP probe (fast filter)
// ============================================================
function tcpProbe(host, port, timeoutMs) {
  return new Promise(resolve => {
    const start = Date.now();
    const socket = new net.Socket();
    let done = false;
    const finish = (ok, err) => {
      if (done) return; done = true;
      try { socket.destroy(); } catch {}
      try { stopSignal().removeEventListener('abort', onAbort); } catch {}
      resolve({ ok, latency: Date.now() - start, error: err || '' });
    };
    const onAbort = () => finish(false, 'aborted');
    if (STOP.requested) return finish(false, 'aborted');
    try { stopSignal().addEventListener('abort', onAbort, { once: true }); } catch {}
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false, 'TCP timeout'));
    socket.once('error', e => finish(false, e.code || 'TCP error'));
    try { socket.connect(Number(port), host); } catch (e) { finish(false, e.message); }
  });
}

function createAgent(proxy, config = null, targetUrl = '', agentOptions = {}) {
  const url = proxyToAgentUrl(proxy, config, agentOptions.proxyScheme || '');
  const opts = { keepAlive: false, timeout: Math.max(1000, Number(config?.timeoutMs) || 6000) };
  const scheme = String(url).split(':', 1)[0];
  if (scheme === 'socks4' || scheme === 'socks5') return new SocksProxyAgent(url, opts);
  if (String(targetUrl).toLowerCase().startsWith('http://')) return new HttpProxyAgent(url, opts);
  return new HttpsProxyAgent(url, opts);
}

function isLiveStatus(status) {
  // 2xx/3xx are clean success. 403/404/405/429 still prove the request reached
  // the target through the proxy (common with public checker URLs), so count as
  // live but score will stay low if later IP/judge checks fail. 407 is auth.
  return (status >= 200 && status < 400) || [403, 404, 405, 429].includes(Number(status));
}

function classifyFailure(error) {
  const e = String(error || '').toLowerCase();
  if (!e) return '';
  // v1.0.0: narrower AUTH_REQUIRED signal — only real credential-required errors,
  // not every SOCKS handshake / generic "unauthorized" noise.
  if (
    e.includes('407') ||
    e.includes('proxy authentication required') ||
    e.includes('no acceptable authentication') ||
    e.includes('socks5 authentication') ||
    e.includes('socks authentication')
  ) return 'AUTH_REQUIRED';
  if (e.includes('tcp timeout') || e.includes('timeout') || e.includes('err_canceled')) return 'TIMEOUT';
  if (e.includes('econnrefused')) return 'CONNECTION_REFUSED';
  if (e.includes('ehostunreach') || e.includes('enetunreach')) return 'UNREACHABLE';
  if (e.includes('cert') || e.includes('tls') || e.includes('ssl')) return 'TLS_ERROR';
  if (e.includes('400') || e.includes('bad response') || e.includes('connect response')) return 'PROTOCOL_MISMATCH';
  return 'FAILED';
}

function safeOrigin(data) {
  if (!data) return '';
  if (typeof data === 'string') { const m = data.match(/\d{1,3}(\.\d{1,3}){3}/); return m ? m[0] : data.slice(0, 60); }
  if (data.ip) return String(data.ip);
  if (data.origin) return String(data.origin).split(',')[0].trim();
  return '';
}

async function oneProbe(proxy, testUrl, config, opts = {}) {
  const start = Date.now();
  if (STOP.requested) return { ok: false, latency: 0, status: 0, ip: '', error: 'aborted' };
  const controller = new AbortController();
  let agent = null;
  let hardTimer = null;
  const onStop = () => { try { controller.abort(); } catch {} };
  try { stopSignal().addEventListener('abort', onStop, { once: true }); } catch {}
  try {
    agent = createAgent(proxy, config, testUrl, opts);
    const hardTimeoutMs = Math.max(1500, Number(config.timeoutMs) || 10000) + 750;
    const request = axios.get(testUrl, {
      timeout: config.timeoutMs, httpAgent: agent, httpsAgent: agent, maxRedirects: 2,
      signal: controller.signal, proxy: false,
      validateStatus: s => s >= 200 && s < 500,
      headers: { 'User-Agent': `Mozilla/5.0 ProxyProTest/${APP_VERSION}`, 'Accept': 'application/json,text/plain,*/*', 'Connection': 'close' }
    }).then(res => ({ res })).catch(err => ({ err }));
    const hardTimeout = new Promise(resolve => {
      hardTimer = setTimeout(() => {
        try { controller.abort(); } catch {}
        try { agent && agent.destroy && agent.destroy(); } catch {}
        resolve({ timeout: true });
      }, hardTimeoutMs);
    });
    const raced = await Promise.race([request, hardTimeout]);
    if (raced.timeout) return { ok: false, latency: Date.now() - start, status: 0, ip: '', error: 'HARD_TIMEOUT' };
    if (raced.err) {
      const e = raced.err;
      return { ok: false, latency: Date.now() - start, status: e.response?.status || 0, ip: '', error: e.response?.status ? `HTTP ${e.response.status}` : (e.code || (e.message || 'failed').slice(0, 80)) };
    }
    const res = raced.res;
    const latency = Date.now() - start;
    const ok = isLiveStatus(res.status);
    return { ok, latency, status: res.status, ip: safeOrigin(res.data), error: ok ? '' : `HTTP ${res.status}` };
  } catch (e) {
    return { ok: false, latency: Date.now() - start, status: 0, ip: '', error: (e && (e.code || e.message)) || 'failed' };
  } finally {
    if (hardTimer) clearTimeout(hardTimer);
    try { stopSignal().removeEventListener('abort', onStop); } catch {}
    try { agent && agent.destroy && agent.destroy(); } catch {}
  }
}

async function judgeProbe(proxy, config) {
  if (STOP.requested) return null;
  const controller = new AbortController();
  const hardTimer = setTimeout(() => { try { controller.abort(); } catch {} }, config.timeoutMs + 750);
  const onStop = () => { try { controller.abort(); } catch {} };
  try { stopSignal().addEventListener('abort', onStop, { once: true }); } catch {}
  try {
    const agent = createAgent(proxy, config, config.judgeUrl);
    const res = await axios.get(config.judgeUrl, {
      timeout: config.timeoutMs, httpAgent: agent, httpsAgent: agent,
      signal: controller.signal, proxy: false,
      validateStatus: s => s >= 200 && s < 500,
      headers: { 'User-Agent': `Mozilla/5.0 ProxyProJudge/${APP_VERSION}`, 'Connection': 'close' }
    });
    return res.data && typeof res.data === 'object' ? res.data : null;
  } catch { return null; }
  finally {
    clearTimeout(hardTimer);
    try { stopSignal().removeEventListener('abort', onStop); } catch {}
  }
}

function urlsForProxyType(type, config) {
  const urls = Array.isArray(config.testUrls) && config.testUrls.length ? config.testUrls : DEFAULT_CONFIG.testUrls;
  const unique = [...new Set(urls.filter(Boolean))];
  const https = unique.filter(u => /^https:\/\//i.test(u));
  const http = unique.filter(u => /^http:\/\//i.test(u));
  // SOCKS and HTTPS-capable HTTP proxies usually work best with CONNECT/HTTPS,
  // but keep HTTP fallbacks because many public proxies block CONNECT.
  if (type === 'socks4' || type === 'socks5' || type === 'https') return [...https, ...http];
  // Plain HTTP proxies are often forwarding-only; try simple HTTP first.
  return [...http, ...https];
}

async function checkTestEndpoints(config) {
  const urls = [...new Set((config.testUrls || []).filter(Boolean))].slice(0, 8);
  if (!urls.length || config.__skipEndpointCheck) return;
  const checks = await Promise.all(urls.map(async (url) => {
    try {
      const r = await axios.get(url, {
        timeout: 3500,
        proxy: false,
        maxRedirects: 2,
        validateStatus: s => s >= 200 && s < 500,
        headers: { 'User-Agent': `ProxyProEndpointSelfCheck/${APP_VERSION}` }
      });
      return { url, ok: isLiveStatus(r.status), status: r.status };
    } catch (e) {
      return { url, ok: false, status: e.code || 'ERR' };
    }
  }));
  const ok = checks.filter(x => x.ok).length;
  const msg = `Test endpoints reachable from this PC: ${ok}/${checks.length}`;
  console.log(ok ? theme.dim(`◉ ${msg}`) : theme.warn(`⚠ ${msg} — change Settings > Test URLs or try another internet/VPN.`));
  if (!ok) log(`endpoint self-check failed: ${checks.map(x => `${x.url}=${x.status}`).join(' | ')}`);
}

function strongestFailureCategory(attempts) {
  const cats = attempts.map(a => classifyFailure(a && a.error)).filter(Boolean);
  const priority = ['AUTH_REQUIRED','CONNECTION_REFUSED','UNREACHABLE','TIMEOUT','PROTOCOL_MISMATCH','TLS_ERROR','FAILED'];
  return priority.find(c => cats.includes(c)) || cats[0] || 'FAILED';
}

function classifyAnonymity(judgeData, myIp) {
  if (!judgeData) return 'unknown';
  const headers = judgeData.headers || {};
  const origin = String(judgeData.origin || '').toLowerCase();
  const via = headers['Via'] || headers['via'] || '';
  const xff = headers['X-Forwarded-For'] || headers['x-forwarded-for'] || '';
  const forwarded = headers['Forwarded'] || headers['forwarded'] || '';
  const proxyHeaders = ['Proxy-Connection','X-Real-Ip','X-Proxy-Id','Client-Ip'];
  const hasProxyHeader = proxyHeaders.some(h => headers[h] || headers[h.toLowerCase()]);
  if (myIp && origin.includes(String(myIp).toLowerCase())) return 'transparent';
  if (xff || via || forwarded || hasProxyHeader) return 'anonymous';
  return 'elite';
}

const GEO_CACHE = new Map();
async function geoLookup(ip, provider = 'ip-api') {
  if (!ip) return null;
  if (GEO_CACHE.has(ip)) return GEO_CACHE.get(ip);
  try {
    const url = provider === 'ipwho'
      ? `https://ipwho.is/${ip}`
      : `http://ip-api.com/json/${ip}?fields=status,country,countryCode,city,isp,query`;
    const r = await axios.get(url, { timeout: 6000 });
    const d = r.data || {};
    const geo = {
      country: d.country || d.country_name || '',
      countryCode: d.countryCode || d.country_code || '',
      city: d.city || '',
      isp: d.isp || d.connection?.isp || d.org || ''
    };
    GEO_CACHE.set(ip, geo);
    return geo;
  } catch { return null; }
}

async function testProxySingle(proxy, config) {
  const attempts = [];
  const urls = urlsForProxyType(proxy.type, config);
  // v7.6 accuracy model — driven by the active mode, not by ad-hoc retry math:
  //   requiredSuccesses = how many DIFFERENT endpoints must return live before we
  //                       declare the proxy Alive (higher = fewer false-positives).
  //   coverage           = cap on how many endpoints we try in total this pass.
  //   retries            = per-endpoint retry budget for transient network noise.
  // Endpoints are tried sequentially to avoid the "hundreds of sockets per proxy"
  // storm that broke Windows in <=7.5.3. We short-circuit as soon as we have
  // enough successes; on Deep/Strict modes this pushes coverage higher.
  const required = Math.max(1, Number(config.requiredSuccesses) || 1);
  const cov = Math.max(required, Math.min(urls.length, Number(config.coverage) || required));
  const perEndpointRetry = Math.max(1, Number(config.retries) || 1);

  // v7.7.3: per-proxy wall-time budget so a dead SOCKS5 can never stall the
  // whole run. Default = timeoutMs * 3 (balanced -> 30s). Override via config.perProxyMaxMs.
  const perProxyMaxMs = Math.max(
    (Number(config.timeoutMs) || 10000) + 2000,
    Number(config.perProxyMaxMs) || (Number(config.timeoutMs) || 10000) * 3
  );
  const proxyStart = Date.now();
  let timeoutStrikes = 0;

  let successCount = 0;
  outer: for (let i = 0; i < cov; i++) {
    if (STOP.requested) break;
    if (Date.now() - proxyStart > perProxyMaxMs) break;
    const url = urls[i % urls.length];
    for (let k = 0; k < perEndpointRetry; k++) {
      if (STOP.requested) break outer;
      if (Date.now() - proxyStart > perProxyMaxMs) break outer;
      const r = await oneProbe(proxy, url, config);
      attempts.push(r);
      if (r.ok) { successCount++; break; }
      const cat = classifyFailure(r.error);
      // hard-fatal errors: don't retry
      if (cat === 'AUTH_REQUIRED' || cat === 'CONNECTION_REFUSED' || cat === 'UNREACHABLE') break;
      // v7.7.3: on TIMEOUT allow at most one retry per endpoint
      if (cat === 'TIMEOUT') { timeoutStrikes++; if (k >= 1) break; }
      // v7.7.3: if the proxy has already timed out on >=2 probes, stop the
      // whole coverage loop — no point trying 5 x 3 = 15 timeouts.
      if (timeoutStrikes >= 2) break outer;
    }
    if (successCount >= required) break;
  }

  const successes = attempts.filter(x => x.ok);
  const successRate = attempts.length ? successes.length / attempts.length : 0;
  const latencies = successes.map(x => x.latency);
  const avgLatency = latencies.length ? Math.round(latencies.reduce((a,b) => a+b, 0) / latencies.length) : 0;
  const minLatency = latencies.length ? Math.min(...latencies) : 0;
  const maxLatency = latencies.length ? Math.max(...latencies) : 0;
  const jitter = latencies.length > 1 ? Math.round(maxLatency - minLatency) : 0;
  let alive = successCount >= required;

  // v7.6: optional double-check pass for high-accuracy modes.
  // We re-hit the first working endpoint after a short delay to make sure the
  // proxy is truly stable (not a one-hit fluke) before flagging Alive.
  if (alive && config.doubleCheck) {
    const url = successes[0] ? urls.find(u => successes.some(s => true)) || urls[0] : urls[0];
    const r2 = await oneProbe(proxy, url, config);
    attempts.push(r2);
    if (!r2.ok) alive = false;
  }

  // v7.5.3: generate_204 endpoints return empty body, so IP echo runs as a
  // separate final probe ONLY for alive proxies.
  let exitIp = successes[0] ? successes[0].ip : '';
  if (alive && !exitIp && (config.checkAnonymity || config.checkGeo)) {
    const ipUrl = (proxy.type === 'socks4' || proxy.type === 'socks5' || proxy.type === 'https')
      ? (config.ipEchoUrl || 'https://api.ipify.org?format=json')
      : (config.ipEchoUrlHttp || 'http://api.ipify.org?format=json');
    const ipRes = await oneProbe(proxy, ipUrl, config);
    if (ipRes.ok && ipRes.ip) exitIp = ipRes.ip;
  }

  let anonymity = 'unknown';
  let geo = null;
  if (alive && config.checkAnonymity) {
    const j = await judgeProbe(proxy, config);
    anonymity = classifyAnonymity(j, PUBLIC_IP);
  }
  if (alive && config.checkGeo && exitIp) geo = await geoLookup(exitIp, config.geoProvider);

  const score = calculateScore({ successRate, avgLatency, jitter, type: proxy.type, anonymity });
  const grade = score >= config.excellentScore && avgLatency <= config.maxExcellentLatencyMs ? 'A+' : score >= config.excellentScore ? 'A' : score >= config.goodScore ? 'B' : alive ? 'C' : 'DEAD';

  return {
    ...proxy,
    url: proxyToUrl(proxy, true, config),
    alive, score, grade,
    failureCategory: alive ? '' : strongestFailureCategory(attempts),
    successRate: Number((successRate * 100).toFixed(0)),
    avgLatency, minLatency, maxLatency, jitter,
    exitIp, anonymity,
    country: geo?.country || '', countryCode: geo?.countryCode || '', city: geo?.city || '', isp: geo?.isp || '',
    successCount, requiredSuccesses: required,
    attempts: attempts.map(x => ({ ok: x.ok, latency: x.latency, status: x.status, error: x.error }))
  };
}

// Multi-protocol dispatcher: schemeless / unknown proxies are tested against
// every enabled protocol; first working type wins. Typed proxies are tested once.
async function testProxyHttp(proxy, config) {
  const enabled = (config.testTypes && config.testTypes.length ? config.testTypes : ['http','https','socks4','socks5']);
  const isUnknown = !proxy.type || proxy.type === 'unknown' || !enabled.includes(proxy.type);
  if (!isUnknown) {
    const primary = await testProxySingle(proxy, config);
    if (primary.alive || primary.failureCategory === 'AUTH_REQUIRED' || config.smartProtocolFallback === false) return primary;
    // If a list tagged the proxy with the wrong scheme, one protocol may fail
    // immediately with protocol/TLS noise while another works. Try alternatives
    // only for those mismatch-like failures; do not spend minutes retrying pure
    // TCP/timeouts across every protocol.
    const fallbackable = ['PROTOCOL_MISMATCH', 'TLS_ERROR', 'FAILED'].includes(primary.failureCategory);
    if (!fallbackable) return primary;
    // v7.7.3: cap alternate-protocol retries to 1 (was 3). If a typed proxy fails
    // on its declared scheme AND on one alternate, extra attempts just multiply wall-time.
    const alternates = ['socks5','socks4','http','https'].filter(t => enabled.includes(t) && t !== proxy.type).slice(0, 1);
    for (const t of alternates) {
      if (STOP.requested) break;
      const r = await testProxySingle({ ...proxy, type: t }, config);
      if (r.alive || r.failureCategory === 'AUTH_REQUIRED') return r;
    }
    return primary;
  }
  // Unknown/schemeless proxies are tested against every enabled protocol; first
  // working type wins. Sequential avoids opening 4x sockets for each unknown.
  const order = ['socks5','http','socks4','https'].filter(t => enabled.includes(t));
  const dead = [];
  for (const t of order) {
    if (STOP.requested) break;
    const r = await testProxySingle({ ...proxy, type: t }, config).catch(() => null);
    if (r && r.alive) return r;
    if (r) dead.push(r);
  }
  const authDead = dead.find(r => r && r.failureCategory === 'AUTH_REQUIRED');
  return authDead || dead[0] || deadResult(proxy, 'all-protocols-failed');
}




function deadResult(proxy, reason) {
  return {
    ...proxy, url: proxyToUrl(proxy, true),
    alive: false, score: 0, grade: 'DEAD',
    failureCategory: classifyFailure(reason || 'tcp-fail'),
    successRate: 0, avgLatency: 0, minLatency: 0, maxLatency: 0, jitter: 0,
    exitIp: '', anonymity: 'unknown',
    country: '', countryCode: '', city: '', isp: '',
    attempts: [{ ok: false, latency: 0, status: 0, error: reason || 'tcp-fail' }]
  };
}

function calculateScore({ successRate, avgLatency, jitter, type, anonymity }) {
  if (successRate <= 0) return 0;
  let score = 0;
  score += successRate * 50;
  if (avgLatency <= 500) score += 28;
  else if (avgLatency <= 1000) score += 23;
  else if (avgLatency <= 2000) score += 16;
  else if (avgLatency <= 3500) score += 9;
  else if (avgLatency <= 6000) score += 4;
  if (jitter <= 300) score += 9;
  else if (jitter <= 1000) score += 5;
  else if (jitter <= 2000) score += 2;
  if (type === 'socks5' || type === 'https') score += 5;
  if (anonymity === 'elite') score += 8;
  else if (anonymity === 'anonymous') score += 4;
  else if (anonymity === 'transparent') score -= 5;
  return Math.max(0, Math.min(100, Math.round(score)));
}

// Concurrent runner with STOP support
async function runConcurrent(items, worker, concurrency, onDone) {
  const results = new Array(items.length);
  let index = 0, done = 0;
  const loop = async () => {
    while (true) {
      if (STOP.requested) return;
      const i = index++;
      if (i >= items.length) return;
      try { results[i] = await worker(items[i], i); }
      catch (e) { results[i] = null; log(`worker error idx=${i}: ${e.message}`); }
      done++;
      if (onDone) onDone(done, results[i]);
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(concurrency, items.length)) }, loop));
  return results.filter(Boolean);
}

// ============================================================
// KEYPRESS LISTENER — 'q' to stop mid-test
// ============================================================
let keypressActive = false;
function enableStopKey() {
  if (keypressActive || !process.stdin.isTTY) return;
  keypressActive = true;
  try {
    readline.emitKeypressEvents(process.stdin);
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.on('keypress', onKey);
  } catch {}
}
function disableStopKey(options = {}) {
  if (!keypressActive) return;
  keypressActive = false;
  try {
    process.stdin.removeListener('keypress', onKey);
    process.stdin.setRawMode(false);
    if (!options.keepOpen) process.stdin.pause();
  } catch {}
}
function onKey(str, key) {
  if (!key) return;
  if (key.ctrl && key.name === 'c') { requestStop('ctrl+c'); return; }
  if (key.name === 'q' || key.name === 's') requestStop('keypress');
}

// ============================================================
// TEST FLOW
// ============================================================
async function testCollected(config) {
  ensureDir(OUTPUT);
  resetStop();
  let proxies = readCollectedForTest(config);
  if (!proxies.length) { console.log(theme.warn('No collected proxies. Run Collect first.')); return []; }

  const history = config.useHistory ? loadHistory() : {};
  const now = Date.now();
  if (config.useHistory) {
    const before = proxies.length;
    proxies = proxies.filter(p => {
      const h = history[proxyKey(p)];
      if (h && h.grade === 'DEAD' && (now - h.at) < 6 * 3600 * 1000) return false;
      return true;
    });
    if (proxies.length < before) console.log(theme.dim(`↷ history skipped ${before - proxies.length} recently-dead proxies.`));
  }

  if (config.maxToTest > 0) proxies = proxies.slice(0, config.maxToTest);
  await checkTestEndpoints(config);
  if (config.checkAnonymity) { const ip = await detectPublicIp(); console.log(theme.dim(`◉ Public IP: ${ip || 'unknown'} (for anonymity)`)); }

  // v7.8.0: RESUME — if a resume file exists for the SAME set of proxies (same hash),
  // offer to skip already-tested ones and merge their results into this run.
  const listHash = hashProxyList(proxies);
  let priorResults = [];
  let skipKeys = new Set();
  const resume = loadResume();
  if (resume && resume.hash === listHash && Array.isArray(resume.results) && resume.results.length && !config.__nonInteractive) {
    const doneN = resume.results.length;
    const totalN = proxies.length;
    console.log('\n' + theme.info(`↻ Previous incomplete run detected: ${doneN}/${totalN} already tested.`));
    const ans = (await ask(theme.key('  Resume and skip already-tested proxies? (Y/n): '))).trim().toLowerCase();
    if (ans === '' || ans === 'y' || ans === 'yes') {
      priorResults = resume.results;
      skipKeys = new Set(priorResults.map(r => proxyKey(r)));
      proxies = proxies.filter(p => !skipKeys.has(proxyKey(p)));
      console.log(theme.ok(`✔ Resuming. ${proxies.length} proxies still to test (${priorResults.filter(r=>r.alive).length} alive already carried over).`));
    } else {
      clearResume();
      console.log(theme.dim('Starting fresh — resume file cleared.'));
    }
  } else if (resume) {
    // stale resume for a different list — drop it silently
    clearResume();
  }

  const cfgBox = panel(
    `${theme.label('Mode    :')} ${theme.key(config.activeMode)}       ${theme.label('Two-Phase:')} ${config.twoPhase ? theme.ok('on') : theme.dim('off')}\n` +
    `${theme.label('Conc    :')} ${theme.value(config.concurrency)}      ${theme.label('Retries :')} ${theme.value(config.retries)}\n` +
    `${theme.label('TCP TO  :')} ${theme.value(config.tcpTimeoutMs + 'ms')}    ${theme.label('HTTP TO :')} ${theme.value(config.timeoutMs + 'ms')}\n` +
    `${theme.label('Anon    :')} ${config.checkAnonymity ? theme.ok('on') : theme.dim('off')}         ${theme.label('Geo     :')} ${config.checkGeo ? theme.ok('on') : theme.dim('off')}\n` +
    `${theme.label('Targets :')} ${theme.value(proxies.length)} proxies` + (priorResults.length ? `  ${theme.dim('(+ ' + priorResults.length + ' from resume)')}` : ''),
    { borderColor: 'magenta' }
  );
  console.log('\n' + cfgBox);
  console.log(chalk.yellow.bold('\n  Press ') + chalk.bgYellow.black(' Q ') + chalk.yellow.bold(' or ') + chalk.bgYellow.black(' Ctrl+C ') + chalk.yellow.bold(' anytime to stop and save partial results (auto-resumable next time).\n'));

  enableStopKey();
  const startedAt = Date.now();

  // Seed accumulators from prior results (v7.8.0)
  let results = [...priorResults];
  let alive = priorResults.filter(r => r.alive).length;
  let best = priorResults.filter(r => r.grade === 'A+' || r.grade === 'A').length;
  let elite = priorResults.filter(r => r.anonymity === 'elite').length;
  let tcpPass = 0;

  // Persist resume state periodically so a crash/kill doesn't lose progress.
  let lastResumeSave = 0;
  const persistResume = (partial) => {
    if (!partial.length) return;
    // Throttle to at most once every 1.5s
    const nowT = Date.now();
    if (nowT - lastResumeSave < 1500) return;
    lastResumeSave = nowT;
    saveResume({ hash: listHash, at: nowT, results: partial });
  };

  const speedOf = (done) => {
    const dt = (Date.now() - startedAt) / 1000;
    return dt > 0.2 ? Math.round(done / dt) : 0;
  };

  try {
    if (config.twoPhase) {
      // ---------- PHASE 1: TCP ----------
      console.log(theme.info('▶ Phase 1/2 — TCP reachability filter'));
      const tcpBar = new cliProgress.SingleBar({
        format: `  ${chalk.cyan('TCP  ')} ${chalk.hex('#7c4dff')('│{bar}│')} {percentage}%  {value}/{total}  ${chalk.gray('•')} reachable=${chalk.green('{pass}')}  speed=${chalk.cyan('{speed}')}/s  ETA:${chalk.hex('#40c4ff')('{eta_formatted}')}`,
        barCompleteChar: '█', barIncompleteChar: '░', hideCursor: true, barsize: 32
      }, cliProgress.Presets.shades_classic);
      const authed = proxies.filter(p => (p.username && p.username.length) || (p.password && p.password.length));
      const publicProxies = proxies.filter(p => !((p.username && p.username.length) || (p.password && p.password.length)));
      authed.forEach(p => { tcpPass++; });
      tcpBar.start(proxies.length, authed.length, { pass: tcpPass, speed: 0 });
      const tcpResults = await runConcurrent(publicProxies, async (p) => {
        const r = await tcpProbe(p.host, p.port, config.tcpTimeoutMs);
        if (r.ok) tcpPass++;
        return { proxy: p, tcp: r };
      }, Math.min(1000, config.concurrency * 3), (d) => tcpBar.update(authed.length + d, { pass: tcpPass, speed: speedOf(d) }));
      tcpBar.stop();

      const survivors = [...authed, ...tcpResults.filter(x => x.tcp.ok).map(x => x.proxy)];
      const deadTcp = tcpResults.filter(x => !x.tcp.ok).map(x => deadResult(x.proxy, x.tcp.error));
      results.push(...deadTcp);

      console.log(theme.dim(`  ${survivors.length}/${proxies.length} passed TCP  (${Math.round(survivors.length/Math.max(1,proxies.length)*100)}%)\n`));

      if (!STOP.requested) {
        // ---------- PHASE 2: HTTP ----------
        console.log(theme.info('▶ Phase 2/2 — Protocol test (http/https/socks4/socks5) + anonymity + geo'));
        const httpBar = new cliProgress.SingleBar({
          format: `  ${chalk.cyan('PROTO')} ${chalk.hex('#00e676')('│{bar}│')} {percentage}%  {value}/{total}  ${chalk.gray('•')} alive=${chalk.green('{alive}')}  best=${chalk.magenta('{best}')}  elite=${chalk.cyan('{elite}')}  speed=${chalk.cyan('{speed}')}/s  ETA:${chalk.hex('#40c4ff')('{eta_formatted}')}`,
          barCompleteChar: '█', barIncompleteChar: '░', hideCursor: true, barsize: 32
        }, cliProgress.Presets.shades_classic);
        httpBar.start(survivors.length, 0, { alive: 0, best: 0, elite: 0, speed: 0 });
        const phase2Start = Date.now();
        const phase2Acc = [];
        const httpResults = await runConcurrent(survivors, p => testProxyHttp(p, config), config.concurrency, (d, r) => {
          if (r && r.alive) alive++;
          if (r && (r.grade === 'A+' || r.grade === 'A')) best++;
          if (r && r.anonymity === 'elite') elite++;
          const dt = (Date.now() - phase2Start) / 1000;
          const sp = dt > 0.2 ? Math.round(d / dt) : 0;
          httpBar.update(d, { alive, best, elite, speed: sp });
          if (r) { phase2Acc.push(r); persistResume([...results, ...phase2Acc]); }
        });
        httpBar.stop();
        results.push(...httpResults);
      }
    } else {
      // ---------- SINGLE-PHASE ----------
      console.log(theme.info('▶ Protocol test (http/https/socks4/socks5) + anonymity + geo'));
      const bar = new cliProgress.SingleBar({
        format: `  ${chalk.cyan('Test ')} ${chalk.hex('#00e676')('│{bar}│')} {percentage}%  {value}/{total}  ${chalk.gray('•')} alive=${chalk.green('{alive}')}  best=${chalk.magenta('{best}')}  elite=${chalk.cyan('{elite}')}  speed=${chalk.cyan('{speed}')}/s  ETA:${chalk.hex('#40c4ff')('{eta_formatted}')}`,
        barCompleteChar: '█', barIncompleteChar: '░', hideCursor: true, barsize: 32
      }, cliProgress.Presets.shades_classic);
      bar.start(proxies.length, 0, { alive: 0, best: 0, elite: 0, speed: 0 });
      const singleAcc = [];
      const single = await runConcurrent(proxies, p => testProxyHttp(p, config), config.concurrency, (d, r) => {
        if (r && r.alive) alive++;
        if (r && (r.grade === 'A+' || r.grade === 'A')) best++;
        if (r && r.anonymity === 'elite') elite++;
        bar.update(d, { alive, best, elite, speed: speedOf(d) });
        if (r) { singleAcc.push(r); persistResume([...results, ...singleAcc]); }
      });
      bar.stop();
      results.push(...single);
    }
  } finally {
    disableStopKey();
  }

  // country filter
  let filtered = results;
  if (config.countryFilter && config.countryFilter.length) filtered = filtered.filter(r => !r.alive || config.countryFilter.includes(r.countryCode));
  if (config.excludeCountries && config.excludeCountries.length) filtered = filtered.filter(r => !r.alive || !config.excludeCountries.includes(r.countryCode));

  if (config.useHistory) {
    for (const r of results) history[proxyKey(r)] = { grade: r.grade, score: r.score, at: now };
    saveHistory(history);
  }

  writeTestOutputs(filtered, config);

  // v7.8.0: resume-state hygiene — clear on clean completion, keep on partial stop.
  if (STOP.requested) {
    saveResume({ hash: listHash, at: Date.now(), results: results });
    console.log(theme.dim('↻ Resume state saved. Next test on the same list will offer to continue.'));
  } else {
    clearResume();
  }

  // v7.7.2: expose the top failure categories in the summary
  const failByCat = new Map();
  for (const r of results) {
    if (r.alive) continue;
    const k = r.failureCategory || 'FAILED';
    failByCat.set(k, (failByCat.get(k) || 0) + 1);
  }
  const authFail = failByCat.get('AUTH_REQUIRED') || 0;
  const topFail = [...failByCat.entries()].sort((a,b) => b[1]-a[1]).slice(0, 3)
    .map(([k,v]) => `${k}=${v}`).join('  ');

  const duration = Date.now() - startedAt;
  const partial = STOP.requested;
  const hint = (!partial && alive === 0 && results.length > 0)
    ? '\n' + theme.warn(`⚠ 0 alive out of ${results.length} — likely wrong credentials or forced type. ${authFail ? `AUTH_REQUIRED=${authFail}. ` : ''}Check private source user/pass and forced type.`)
    : '';
  const box = panel(
    `${partial ? theme.warn('⏸ Stopped — partial results saved (resumable)') : theme.ok('✔ Test complete')}\n` +
    `${theme.label('Tested   :')} ${theme.value(results.length)}    ${theme.label('Alive:')} ${chalk.green.bold(alive)}    ${theme.label('Best:')} ${chalk.magenta.bold(best)}    ${theme.label('Elite:')} ${chalk.cyan.bold(elite)}\n` +
    `${theme.label('Duration :')} ${theme.value(fmtDuration(duration))}    ${theme.label('Speed:')} ${theme.value(Math.round(results.length / Math.max(1, duration/1000)) + ' /s')}\n` +
    (topFail ? `${theme.label('Top fails:')} ${theme.dim(topFail)}\n` : '') +
    `${theme.label('Output   :')} ${theme.dim(OUTPUT)}${hint}`,
    { borderColor: partial ? 'yellow' : (alive === 0 && results.length > 0 ? 'yellow' : 'green') }
  );
  console.log('\n' + box);
  return filtered;
}


function compareResults(a, b) {
  if (b.score !== a.score) return b.score - a.score;
  if (a.avgLatency !== b.avgLatency) return a.avgLatency - b.avgLatency;
  return a.url.localeCompare(b.url);
}
function resultLine(r, mk) { return mk && !r.__hasAuth ? mask(r.url) : r.url; }
function resultLineSpeed(r, mk) {
  const u = mk && !r.__hasAuth ? mask(r.url) : r.url;
  return `${u} | score=${r.score} grade=${r.grade} avg=${r.avgLatency}ms ok=${r.successRate}% jitter=${r.jitter}ms anon=${r.anonymity} geo=${r.countryCode || '?'} ip=${r.exitIp}`;
}
function writeLines(name, lines) { fs.writeFileSync(path.join(TEST_DIR, name), lines.join('\n'), 'utf8'); }

function writeTestOutputs(results, config) {
  ensureDir(OUTPUT);
  ensureDir(BASE_TEST_DIR);
  // v7.7.7: each test writes into a fresh numbered subfolder (results_1, results_2, ...)
  TEST_DIR = nextRunDir(BASE_TEST_DIR, 'results');
  BY_TYPE_DIR = path.join(TEST_DIR, 'by_type');
  BY_COUNTRY_DIR = path.join(TEST_DIR, 'by_country');
  RESULT_JSON = path.join(TEST_DIR, 'tested_results.json');
  ensureDir(TEST_DIR);
  ensureDir(BY_TYPE_DIR);
  ensureDir(BY_COUNTRY_DIR);

  const mk = !!config.maskCredentialsInLogs;
  const alive = results.filter(r => r.alive).sort(compareResults);
  const dead = results.filter(r => !r.alive);
  // v1.0.5: auth_required.txt removed — those entries are still counted in
  // dead.txt / summary diagnostics, but no dedicated file is produced.
  const authRequiredAll = dead.filter(r => r.failureCategory === 'AUTH_REQUIRED');
  const authRequired    = authRequiredAll.filter(r => r.__hasAuth);
  const byFailure = new Map();
  for (const r of dead) { const k = r.failureCategory || classifyFailure((r.attempts && r.attempts[0] && r.attempts[0].error) || 'FAILED'); byFailure.set(k, (byFailure.get(k) || 0) + 1); }
  const excellent = alive.filter(r => r.score >= config.excellentScore && r.avgLatency <= config.maxExcellentLatencyMs);
  const good = alive.filter(r => r.score >= config.goodScore);
  const veryBest = excellent.slice(0, config.veryBestLimit);
  const elite = alive.filter(r => r.anonymity === 'elite' || r.anonymity === 'anonymous');

  // ---- Result_test/  (top-level result files -- kept minimal, one line per proxy) ----
  // v1.0.1: alive.txt contains ONLY credential-less working proxies.
  // Working proxies that carry user:pass live in alive_with_auth.txt so users can
  // pick them up separately for use in tools that accept authenticated URLs.
  const aliveNoAuth   = alive.filter(r => !r.__hasAuth);
  const aliveWithAuth = alive.filter(r =>  r.__hasAuth);
  writeLines('alive.txt',            aliveNoAuth.map(r => r.url));
  // v1.0.5: alive_with_auth.txt always shows the FULL user:pass — it exists
  // so the user can reuse THEIR OWN working authenticated proxies.
  writeLines('alive_with_auth.txt',  aliveWithAuth.map(r => r.url));
  writeLines('best.txt',  veryBest.filter(r => !r.__hasAuth).map(r => r.url));
  writeLines('elite.txt', elite.filter(r => !r.__hasAuth).map(r => r.url));
  writeLines('dead.txt',  config.saveDead ? dead.map(r => (mk && !r.__hasAuth) ? mask(r.url) : r.url) : []);

  // ---- Result_test/by_type/  ----
  try { for (const f of fs.readdirSync(BY_TYPE_DIR)) fs.unlinkSync(path.join(BY_TYPE_DIR, f)); } catch {}
  for (const t of ['http','https','socks4','socks5']) {
    const arr = alive.filter(r => r.type === t && !r.__hasAuth);
    fs.writeFileSync(path.join(BY_TYPE_DIR, `${t}.txt`), arr.map(r => r.url).join('\n'));
  }

  // ---- Result_test/by_country/  ----
  const byCountry = new Map();
  for (const r of alive) { if (r.__hasAuth) continue; const cc = r.countryCode || 'XX'; if (!byCountry.has(cc)) byCountry.set(cc, []); byCountry.get(cc).push(r); }
  try { for (const f of fs.readdirSync(BY_COUNTRY_DIR)) fs.unlinkSync(path.join(BY_COUNTRY_DIR, f)); } catch {}
  for (const [cc, arr] of byCountry) fs.writeFileSync(path.join(BY_COUNTRY_DIR, `${cc}.txt`), arr.map(r => r.url).join('\n'));

  // ---- Result_test/results.csv + tested_results.json (all detail lives here) ----
  const csvHead = 'url,type,host,port,alive,score,grade,failureCategory,successRate,avgLatency,jitter,anonymity,countryCode,country,city,isp,exitIp';
  const csvRows = results.sort(compareResults).map(r => [
    (mk && !r.__hasAuth) ? mask(r.url) : r.url, r.type, r.host, r.port, r.alive, r.score, r.grade, r.failureCategory || '', r.successRate, r.avgLatency, r.jitter,
    r.anonymity, r.countryCode, JSON.stringify(r.country || ''), JSON.stringify(r.city || ''), JSON.stringify(r.isp || ''), r.exitIp
  ].join(','));
  fs.writeFileSync(path.join(TEST_DIR, 'results.csv'), [csvHead, ...csvRows].join('\n'));
  fs.writeFileSync(RESULT_JSON, JSON.stringify(results.sort(compareResults), null, 2), 'utf8');

  // Clean up any leftover legacy files at output root and old alive_plain/anonymous
  purgeLegacyRootFiles();

  writeLines('summary.txt', [
    '=================================================',
    `  PROXY PRO ADVANCED v${APP_VERSION}  -  Test Summary`,
    '=================================================',
    `Time:            ${new Date().toISOString()}`,
    `Mode:            ${config.activeMode}  (twoPhase=${config.twoPhase}, conc=${config.concurrency})`,
    '',
    '--- Overview -----------------------------------',
    `Total Tested:    ${results.length}`,
    `Alive (working): ${alive.length}   (no-auth -> alive.txt: ${aliveNoAuth.length}, with-auth -> alive_with_auth.txt: ${aliveWithAuth.length})`,
    `Dead:            ${dead.length}    -> dead.txt`,
    `Auth required:   ${authRequired.length}    (counted in dead.txt; no dedicated file since v1.0.5)`,
    '',
    '--- Dead reason diagnostics --------------------',
    ...[...byFailure.entries()].sort((a,b) => b[1]-a[1]).map(([k,v]) => `  ${String(k).padEnd(20)} ${v}`),
    authRequired.length ? '  NOTE: AUTH_REQUIRED means proxy is online but needs username/password.' : '',
    '',
    '--- Quality ------------------------------------',
    `Best (top):      ${veryBest.length}   -> best.txt`,
    `Excellent:       ${excellent.length}`,
    `Good+:           ${good.length}`,
    `Elite/Anonymous: ${elite.length}    -> elite.txt`,
    '',
    '--- By Type (alive) ----------------------------',
    `HTTP:   ${alive.filter(x => x.type==='http').length}    -> by_type/http.txt`,
    `HTTPS:  ${alive.filter(x => x.type==='https').length}   -> by_type/https.txt`,
    `SOCKS4: ${alive.filter(x => x.type==='socks4').length}  -> by_type/socks4.txt`,
    `SOCKS5: ${alive.filter(x => x.type==='socks5').length}  -> by_type/socks5.txt`,
    '',
    '--- By Country (alive) -------------------------',
    ...[...byCountry.entries()].sort((a,b) => b[1].length - a[1].length).map(([cc, arr]) => `  ${cc}: ${arr.length}`),
    '',
    '--- Folder layout (v7.7.7 — numbered history) ----',
    '  output/',
    '   ├── All_proxy/',
    '   │    ├── All_proxy_1/   (first collect run)',
    '   │    ├── All_proxy_2/   (second collect run)',
    '   │    └── All_proxy_N/   -> all_proxies.txt, *.txt per type, collect_summary.txt',
    '   └── Result_test/',
    '        ├── results_1/     (first test run)',
    '        ├── results_2/     (second test run)',
    '        └── results_N/     -> alive.txt / alive_with_auth.txt / best.txt / elite.txt /',
    '                              dead.txt / results.csv / summary.txt / tested_results.json /',
    '                              by_type/ / by_country/',
    `Current run folder: ${path.basename(TEST_DIR)}`,
    '================================================='
  ]);

  // v7.8.0: HTML report + previous-run comparison
  try { writeHtmlReport(results, config); } catch (e) { log('html report error: ' + e.message); }
  try { writePreviousComparison(results, config); } catch (e) { log('compare error: ' + e.message); }
}

// v7.8.0: interactive HTML report — filter/sort/search over the same data.
function writeHtmlReport(results, config) {
  const mk = !!config.maskCredentialsInLogs;
  const rows = results.map(r => ({
    url: (mk && !r.__hasAuth) ? mask(r.url) : r.url,
    type: r.type, host: r.host, port: r.port,
    alive: !!r.alive, score: r.score || 0, grade: r.grade || 'DEAD',
    fail: r.failureCategory || '', latency: r.avgLatency || 0, jitter: r.jitter || 0,
    successRate: r.successRate || 0, anonymity: r.anonymity || 'unknown',
    countryCode: r.countryCode || '', country: r.country || '', city: r.city || '',
    isp: r.isp || '', exitIp: r.exitIp || ''
  }));
  const aliveN = rows.filter(r => r.alive).length;
  const eliteN = rows.filter(r => r.anonymity === 'elite').length;
  const bestN = rows.filter(r => r.grade === 'A+' || r.grade === 'A').length;
  const byType = {};
  for (const r of rows.filter(x => x.alive)) byType[r.type] = (byType[r.type] || 0) + 1;
  const byCountry = {};
  for (const r of rows.filter(x => x.alive)) byCountry[r.countryCode || 'XX'] = (byCountry[r.countryCode || 'XX'] || 0) + 1;
  const topCountries = Object.entries(byCountry).sort((a,b)=>b[1]-a[1]).slice(0,10);
  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Proxy Pro Report v${APP_VERSION}</title>
<style>
:root{color-scheme:dark;--bg:#0e1116;--card:#161a22;--txt:#e6edf3;--dim:#8b98a5;--ok:#2ea043;--bad:#f85149;--warn:#e3b341;--acc:#58a6ff;--el:#7ee787}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;padding:24px}
h1{margin:0 0 6px;font-size:22px}.sub{color:var(--dim);margin-bottom:20px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:20px}
.card{background:var(--card);border-radius:10px;padding:14px 16px;border:1px solid #24303c}
.card .n{font-size:26px;font-weight:700}.card .l{color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.05em}
.row{display:flex;gap:20px;flex-wrap:wrap;margin-bottom:16px}
.box{background:var(--card);border:1px solid #24303c;border-radius:10px;padding:12px 16px;flex:1;min-width:260px}
.box h3{margin:0 0 8px;font-size:13px;color:var(--dim);text-transform:uppercase;letter-spacing:.05em}
.bar{display:flex;align-items:center;gap:8px;margin:4px 0;font-size:13px}
.bar .lbl{width:70px;color:var(--dim)}.bar .fill{background:#24303c;height:8px;border-radius:4px;flex:1;overflow:hidden}
.bar .fill>i{display:block;height:100%;background:var(--acc)}
.controls{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px}
input,select{background:#0d1117;border:1px solid #30363d;color:var(--txt);padding:6px 10px;border-radius:6px;font:inherit}
input[type=search]{min-width:240px}
button{background:#1f6feb;border:0;color:#fff;padding:6px 12px;border-radius:6px;font:inherit;cursor:pointer}
button:hover{background:#388bfd}
table{width:100%;border-collapse:collapse;background:var(--card);border-radius:10px;overflow:hidden;font-size:13px}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid #21262d;white-space:nowrap}
th{background:#1c232d;color:var(--dim);text-transform:uppercase;letter-spacing:.04em;font-size:11px;cursor:pointer;user-select:none}
tr.alive td{color:var(--txt)}tr.dead td{color:var(--dim)}
td.g-Aplus,td.g-A{color:var(--el);font-weight:700}td.g-B{color:var(--acc)}td.g-DEAD{color:var(--bad)}
.pill{display:inline-block;padding:2px 8px;border-radius:20px;font-size:11px}
.pill.ok{background:rgba(46,160,67,.15);color:var(--ok)}.pill.no{background:rgba(248,81,73,.15);color:var(--bad)}
</style></head><body>
<h1>Proxy Pro Report — v${APP_VERSION}</h1>
<div class="sub">Generated ${new Date().toISOString()} • Mode: <b>${config.activeMode}</b> • ${rows.length} tested</div>
<div class="cards">
  <div class="card"><div class="n" style="color:var(--el)">${aliveN}</div><div class="l">Alive</div></div>
  <div class="card"><div class="n" style="color:var(--acc)">${bestN}</div><div class="l">Best (A / A+)</div></div>
  <div class="card"><div class="n" style="color:var(--warn)">${eliteN}</div><div class="l">Elite/Anon</div></div>
  <div class="card"><div class="n">${rows.length - aliveN}</div><div class="l">Dead</div></div>
  <div class="card"><div class="n">${rows.length ? Math.round(aliveN/rows.length*100) : 0}%</div><div class="l">Success rate</div></div>
</div>
<div class="row">
  <div class="box"><h3>By type (alive)</h3>${['http','https','socks4','socks5'].map(t=>{const v=byType[t]||0;const pct=aliveN?Math.round(v/aliveN*100):0;return `<div class="bar"><span class="lbl">${t}</span><div class="fill"><i style="width:${pct}%"></i></div><span>${v}</span></div>`;}).join('')}</div>
  <div class="box"><h3>Top countries (alive)</h3>${topCountries.map(([cc,n])=>{const pct=aliveN?Math.round(n/aliveN*100):0;return `<div class="bar"><span class="lbl">${cc||'??'}</span><div class="fill"><i style="width:${pct}%;background:var(--el)"></i></div><span>${n}</span></div>`;}).join('') || '<div class="bar">(no alive)</div>'}</div>
</div>
<div class="controls">
  <input id="q" type="search" placeholder="Search host, url, country, isp...">
  <select id="fType"><option value="">All types</option><option>http</option><option>https</option><option>socks4</option><option>socks5</option></select>
  <select id="fAlive"><option value="">All</option><option value="1">Alive only</option><option value="0">Dead only</option></select>
  <select id="fAnon"><option value="">All anonymity</option><option>elite</option><option>anonymous</option><option>transparent</option><option>unknown</option></select>
  <select id="fCountry"><option value="">All countries</option></select>
  <span style="flex:1"></span>
  <button id="exTxt" title="Download filtered proxies as .txt">⬇ Export .txt</button>
  <button id="exCsv" title="Download filtered proxies as .csv">⬇ Export .csv</button>
  <button id="exJson" title="Download filtered results as .json">⬇ Export .json</button>
  <button id="copyBtn" title="Copy filtered proxies to clipboard">Copy list</button>
  <span id="cnt" style="align-self:center;color:var(--dim)"></span>
</div>
<table id="t"><thead><tr>
  <th data-k="url">URL</th><th data-k="type">Type</th><th data-k="grade">Grade</th><th data-k="score">Score</th>
  <th data-k="latency">Latency (ms)</th><th data-k="successRate">OK%</th><th data-k="anonymity">Anon</th>
  <th data-k="countryCode">Country</th><th data-k="isp">ISP</th><th data-k="exitIp">Exit IP</th>
</tr></thead><tbody></tbody></table>
<script>
const DATA = ${JSON.stringify(rows)};
const tbody = document.querySelector('#t tbody');
let sortK = 'score', sortDir = -1;
function render(){
  const q = document.getElementById('q').value.toLowerCase().trim();
  const ft = document.getElementById('fType').value;
  const fa = document.getElementById('fAlive').value;
  const fn = document.getElementById('fAnon').value;
  const fc = (document.getElementById('fCountry')||{}).value||'';
  const rows = DATA.filter(r=>{
    if(ft && r.type!==ft) return false;
    if(fa==='1' && !r.alive) return false;
    if(fa==='0' && r.alive) return false;
    if(fn && r.anonymity!==fn) return false;
    if(fc && r.countryCode!==fc) return false;
    if(q){ const s = [r.url,r.host,r.country,r.countryCode,r.isp,r.exitIp,r.fail].join(' ').toLowerCase(); if(!s.includes(q)) return false; }
    return true;
  }).sort((a,b)=>{ const va=a[sortK], vb=b[sortK]; if(va<vb) return -1*sortDir; if(va>vb) return 1*sortDir; return 0; });
  tbody.innerHTML = rows.slice(0, 5000).map(r=>{
    const gClass = 'g-' + String(r.grade).replace('+','plus');
    return \`<tr class="\${r.alive?'alive':'dead'}"><td><code>\${escapeHtml(r.url)}</code></td><td>\${r.type}</td><td class="\${gClass}">\${r.grade}</td><td>\${r.score}</td><td>\${r.latency}</td><td>\${r.successRate}</td><td>\${r.anonymity}</td><td>\${r.countryCode} \${escapeHtml(r.country||'')}</td><td>\${escapeHtml(r.isp||'')}</td><td>\${r.exitIp||''}</td></tr>\`;
  }).join('');
  if(rows.length>5000) tbody.innerHTML += '<tr><td colspan="10" style="text-align:center;color:var(--dim);padding:16px">Showing first 5000 of '+rows.length+' — refine filters to see more</td></tr>';
  window.__FILTERED = rows;
  const cnt=document.getElementById('cnt'); if(cnt) cnt.textContent = rows.length + ' shown';
}
function escapeHtml(s){return String(s||'').replace(/[&<>"']/g,c=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
document.querySelectorAll('#t th').forEach(th=>th.addEventListener('click',()=>{ const k=th.dataset.k; if(sortK===k) sortDir*=-1; else {sortK=k; sortDir=-1;} render(); }));
const CC=[...new Set(DATA.map(r=>r.countryCode).filter(Boolean))].sort();const fcEl=document.getElementById('fCountry');CC.forEach(c=>{const o=document.createElement('option');o.value=c;o.textContent=c;fcEl.appendChild(o);});['q','fType','fAlive','fAnon','fCountry'].forEach(id=>document.getElementById(id).addEventListener('input',render));function _dl(name,text,type){const b=new Blob([text],{type:type||'text/plain'});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download=name;document.body.appendChild(a);a.click();setTimeout(()=>{URL.revokeObjectURL(a.href);a.remove();},500);}function _stamp(){const d=new Date();const p=n=>String(n).padStart(2,'0');return d.getFullYear()+p(d.getMonth()+1)+p(d.getDate())+'_'+p(d.getHours())+p(d.getMinutes());}document.getElementById('exTxt').onclick=()=>{const r=window.__FILTERED||[];_dl('proxies_'+_stamp()+'.txt',r.map(x=>x.url).join('\\n'));};document.getElementById('exCsv').onclick=()=>{const r=window.__FILTERED||[];const h=['url','type','host','port','alive','grade','score','latency','successRate','anonymity','countryCode','country','isp','exitIp'];const e=v=>{const s=String(v==null?'':v);return /[",\\n]/.test(s)?'"'+s.replace(/"/g,'""')+'"':s;};const csv=[h.join(',')].concat(r.map(x=>h.map(k=>e(x[k])).join(','))).join('\\n');_dl('proxies_'+_stamp()+'.csv',csv,'text/csv');};document.getElementById('exJson').onclick=()=>{const r=window.__FILTERED||[];_dl('proxies_'+_stamp()+'.json',JSON.stringify(r,null,2),'application/json');};document.getElementById('copyBtn').onclick=async()=>{const r=window.__FILTERED||[];try{await navigator.clipboard.writeText(r.map(x=>x.url).join('\\n'));const b=document.getElementById('copyBtn');const t=b.textContent;b.textContent='Copied '+r.length+'!';setTimeout(()=>b.textContent=t,1500);}catch(e){alert('Copy failed');}};
render();
</script></body></html>`;
  fs.writeFileSync(path.join(TEST_DIR, 'report.html'), html, 'utf8');
}

// v7.8.0: compare current run with previous numbered run and write a diff report.
function writePreviousComparison(results, config) {
  const parent = path.dirname(TEST_DIR);
  const cur = path.basename(TEST_DIR);
  const m = cur.match(/^results_(\d+)$/);
  if (!m) return;
  const prevN = parseInt(m[1], 10) - 1;
  if (prevN < 1) return;
  const prevPath = path.join(parent, `results_${prevN}`, 'tested_results.json');
  if (!fs.existsSync(prevPath)) return;
  let prev = [];
  try { prev = JSON.parse(fs.readFileSync(prevPath, 'utf8')); } catch { return; }
  const key = r => `${r.type}://${r.host}:${r.port}`;
  const prevAlive = new Map(prev.filter(r => r.alive).map(r => [key(r), r]));
  const curAlive = new Map(results.filter(r => r.alive).map(r => [key(r), r]));
  const newlyAlive = [...curAlive.keys()].filter(k => !prevAlive.has(k));
  const lostAlive = [...prevAlive.keys()].filter(k => !curAlive.has(k));
  const both = [...curAlive.keys()].filter(k => prevAlive.has(k));
  const improved = both.filter(k => (curAlive.get(k).score || 0) > (prevAlive.get(k).score || 0) + 5);
  const worsened = both.filter(k => (curAlive.get(k).score || 0) < (prevAlive.get(k).score || 0) - 5);
  const lines = [
    'Comparison with previous run',
    '----------------------------',
    `Previous: results_${prevN}   Current: ${cur}`,
    `Previous alive: ${prevAlive.size}    Current alive: ${curAlive.size}    Delta: ${curAlive.size - prevAlive.size >= 0 ? '+' : ''}${curAlive.size - prevAlive.size}`,
    `Newly alive:    ${newlyAlive.length}`,
    `Lost (was alive, now dead): ${lostAlive.length}`,
    `Score improved (> +5): ${improved.length}`,
    `Score worsened (> -5): ${worsened.length}`,
    '',
    'Newly alive (first 30):',
    ...newlyAlive.slice(0, 30).map(k => '  + ' + k),
    '',
    'Lost (first 30):',
    ...lostAlive.slice(0, 30).map(k => '  - ' + k)
  ];
  fs.writeFileSync(path.join(TEST_DIR, 'compare_with_previous.txt'), lines.join('\n'), 'utf8');
}


// ============================================================
// HELP CONTENT (English only -- avoids ??? on Windows CMD)
// ============================================================
const HELP = {
  '1': ['Add sources',              'Public URL/file, PRIVATE URL/file with user:pass, or Smart Paste (auto-detect).'],
  '2': ['Manage sources',           'View every saved source (links + files + private) and remove one/many/all.'],
  '3': ['Collect proxies',          'Fetch from YOUR saved sources, or auto-collect from built-in defaults.'],
  '4': ['Test proxies',             'Re-test the last collected list. Before starting, pick a mode or let the app auto-pick.'],
  '5': ['Settings / Modes',         'Change test mode (ultra / fast / balanced / accurate / deep / strict / lowpc / sample) + manual knobs.'],
  '6': ['Open output folder',       'Open output/ (All_proxy/, Result_test/) — numbered runs, nothing overwritten.'],
  'H': ['Help',                     'Show this help screen (or press ? anywhere).'],
  '0': ['Exit',                     'Quit the program.']
};

async function showHelp() {
  header();
  console.log(panel(chalk.bold('  Help  /  Complete Guide  '), { borderColor: 'yellow' }));
  console.log('');
  console.log(chalk.hex('#ffd54f').bold('  MAIN MENU'));
  for (const [k, [en, desc]] of Object.entries(HELP)) {
    console.log(`  ${theme.key(k.padStart(2))}  ${chalk.white.bold(en.padEnd(22))}${theme.dim('|')}  ${chalk.hex('#ffcc80')(desc)}`);
  }
  console.log('');
  console.log(panel(
    `${theme.info('TEST MODES (option 5 or "Test proxies" pre-prompt):')}\n` +
    `  ${theme.key('ultra   ')} -> Max speed. 1 endpoint hit, no anon/geo. 100k+ lists.\n` +
    `  ${theme.key('fast    ')} -> Fast with geo. 1 endpoint hit. Large lists.\n` +
    `  ${theme.key('balanced')} -> Recommended default. 2 endpoints + anon + geo.\n` +
    `  ${theme.key('accurate')} -> 3 endpoints + double-check. Best for 5k-40k.\n` +
    `  ${theme.key('deep    ')} -> 8 endpoints, lowest false-dead rate. Slowest.\n` +
    `  ${theme.key('strict  ')} -> Only top-tier proxies pass (score >= 92).\n` +
    `  ${theme.key('lowpc   ')} -> Light-weight for weak PC / slow internet.\n` +
    `  ${theme.key('sample  ')} -> First 1000 only (quick sanity check).`,
    { borderColor: 'cyan' }
  ));
  console.log('');
  console.log(panel(
    `${theme.info('WORKFLOW (typical use):')}\n` +
    `  1) ${chalk.white.bold('Add sources')} — paste your links/files (or use Smart Paste for mixed input).\n` +
    `  2) ${chalk.white.bold('Collect proxies')} — fetch from your sources (or auto built-in).\n` +
    `  3) ${chalk.white.bold('Test proxies')} — the app asks: keep current mode, auto-pick by count, or choose manually.\n` +
    `  4) ${chalk.white.bold('Open output folder')} — grab alive.txt / best.txt / elite.txt / results.csv / HTML report.`,
    { borderColor: 'green' }
  ));
  console.log('');
  console.log(panel(
    `${theme.info('SMART PASTE (inside Add sources -> 3):')}\n` +
    `  Paste anything on separate lines — auto-detected per line:\n` +
    `    ${chalk.green('http(s)://...')}                 -> saved as a link\n` +
    `    ${chalk.green('C:\\path\\file.txt  /path/file')}   -> saved as a local file\n` +
    `    ${chalk.green('ip:port  /  ip:port:user:pass')}  -> saved into pasted_proxies.txt (auto-source)`,
    { borderColor: 'cyan' }
  ));
  console.log('');
  console.log(panel(
    `${theme.warn('DURING A TEST:')}\n` +
    `  Press ${chalk.bgYellow.black(' Q ')} or ${chalk.bgYellow.black(' Ctrl+C ')} = stop and save partial results.\n` +
    `  Everything already tested is exported to output/ before exit.\n` +
    `  If a run is interrupted, the next Test offers to RESUME from where it stopped.`,
    { borderColor: 'yellow' }
  ));
  console.log('');
  console.log(panel(
    `${theme.info(`OUTPUT LAYOUT (v${APP_VERSION} — numbered history, nothing overwritten):`)}\n` +
    `  output/All_proxy/All_proxy_N/   -> all_proxies.txt / ip_port_only.txt / http.txt / https.txt /\n` +
    `                                     socks4.txt / socks5.txt / unknown.txt / collect_summary.txt\n` +
    `  output/Result_test/results_N/   -> alive.txt (all working, best->worst)\n` +
    `                                     best.txt / elite.txt / dead.txt\n` +
    `                                     results.csv / summary.txt / tested_results.json / report.html\n` +
    `                                     by_type/*.txt   by_country/*.txt\n` +
    `  Each Collect and each Test creates the next numbered folder — previous runs stay intact.`,
    { borderColor: 'green' }
  ));
  console.log('');
  console.log(panel(
    `${theme.info('CLI FLAGS (advanced):')}\n` +
    `  node proxy-pro.js --collect        fetch from your sources, non-interactive\n` +
    `  node proxy-pro.js --auto-collect   fetch from built-in defaults, non-interactive\n` +
    `  node proxy-pro.js --test           test the last collected list\n` +
    `  node proxy-pro.js --auto           collect + test in one shot\n` +
    `  node proxy-pro.js --schedule       run collect+test automatically every N hours\n` +
    `                                     (interval configured in Settings -> schedule)`,
    { borderColor: 'magenta' }
  ));
  await ask('\n' + theme.dim('Enter to return...'));
}


// ============================================================
// UI screens
// ============================================================
// Split a single input line into multiple tokens.
// Handles Windows drag-drop where multiple files land on ONE line as any of:
//   "C:\a b\1.txt" "C:\c\2.txt" C:\d\3.txt
//   C:\a\1.txt C:\b\2.txt          (unquoted, no spaces in names)
//   /home/u/a.txt /home/u/b.txt    (POSIX)
//   https://x/a.txt https://y/b.txt
// Preserves a single unquoted path with spaces as one token when there's no
// evidence of multiple tokens (no quotes, tabs, or repeated absolute-path markers).
function splitDroppedTokens(line) {
  const s = String(line || '');
  if (!s.trim()) return [];
  const hasQuote = /["'`]/.test(s);
  const hasTab = /\t/.test(s);
  // Count strong start-of-path markers separated by whitespace or quotes
  const driveMarkers = (s.match(/(?:^|[\s"'`])[a-zA-Z]:[\\/]/g) || []).length;
  const urlMarkers   = (s.match(/(?:^|[\s"'`])https?:\/\//gi) || []).length;
  const posixMarkers = (s.match(/(?:^|[\s"'`])\/[^\s"'`/][^\s"'`]*\.(?:txt|list|csv)\b/gi) || []).length;
  const multi = hasQuote || hasTab || driveMarkers > 1 || urlMarkers > 1 || posixMarkers > 1
                || (driveMarkers + urlMarkers + posixMarkers) > 1;
  if (!multi) return [s.trim()];
  // Quote-aware tokenization first
  const re = /"([^"]*)"|'([^']*)'|`([^`]*)`|(\S+)/g;
  let m;
  const rawToks = [];
  while ((m = re.exec(s)) !== null) {
    const tok = m[1] ?? m[2] ?? m[3] ?? m[4];
    if (tok && tok.trim()) rawToks.push(tok);
  }
  // Second pass: split each token when concatenated absolute-path/URL markers appear
  // The marker must be at position > 0 to count as a split (avoid splitting the start).
  const out = [];
  for (const t of rawToks) {
    const positions = [];
    // find split positions where a new URL / drive letter starts mid-string
    const rex = /(?:https?:\/\/)|(?:file:\/\/)|(?:[a-zA-Z]:[\\/])/gi;
    let mm;
    while ((mm = rex.exec(t)) !== null) {
      if (mm.index > 0) positions.push(mm.index);
    }
    if (!positions.length) { out.push(t); continue; }
    let last = 0;
    for (const p of positions) {
      const seg = t.slice(last, p).trim();
      if (seg) out.push(seg);
      last = p;
    }
    const tail = t.slice(last).trim();
    if (tail) out.push(tail);
  }
  return out.length ? out : [s.trim()];
}

// Expand a directory into its contained .txt / .list / .csv files (non-recursive).
function expandDirectoryTokens(p) {
  try {
    const st = fs.statSync(p);
    if (!st.isDirectory()) return null;
    const entries = fs.readdirSync(p)
      .filter(f => /\.(txt|list|csv)$/i.test(f))
      .map(f => path.join(p, f))
      .filter(f => { try { return fs.statSync(f).isFile(); } catch { return false; } });
    return entries;
  } catch { return null; }
}

// Detect whether a raw line looks like a URL or a local file path
function classifySourceLine(line) {
  let t = String(line || '').trim();
  if (!t) return { kind: 'blank' };
  // Strip wrapping quotes (Windows "Copy as path" wraps in double quotes)
  if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'")) || (t.startsWith('`') && t.endsWith('`'))) {
    t = t.slice(1, -1).trim();
  }
  // file:// URI — convert to a local path
  if (/^file:\/\//i.test(t)) {
    try { t = decodeURIComponent(t.replace(/^file:\/\/\/?/i, '')); } catch {}
    // On Windows a leading slash before drive letter is common: /C:/...
    t = t.replace(/^\/([a-zA-Z]:)/, '$1');
  }
  if (!t) return { kind: 'blank' };
  if (/^(https?):\/\//i.test(t)) return { kind: 'url', value: t };
  // Windows drive letter (C:\ or C:/), UNC (\\server), or POSIX absolute path
  if (/^[a-zA-Z]:[\\/]/.test(t) || t.startsWith('\\\\') || t.startsWith('/') || t.startsWith('./') || t.startsWith('../') || t.startsWith('~')) {
    return { kind: 'file', value: t };
  }
  // Bare filename — treat as file if it exists on disk relative to ROOT
  const abs = path.isAbsolute(t) ? t : path.join(ROOT, t);
  if (fs.existsSync(abs)) return { kind: 'file', value: abs };
  return { kind: 'unknown', value: t };
}

async function addLinks() {
  while (true) {
    header();
    console.log(panel(chalk.bold('  +  Add sources  '), { borderColor: 'cyan' }));
    console.log('');
    console.log('  ' + theme.key(' 1') + '. ' + chalk.white.bold('Public sources') + '   ' + theme.dim('- URLs or local files, NO credentials'));
    console.log('  ' + theme.key(' 2') + '. ' + chalk.white.bold('Private sources') + '  ' + theme.dim('- URL/file + username/password for that source'));
    console.log('  ' + theme.key(' 3') + '. ' + chalk.hex('#ffb86c').bold('Smart Paste') + '     ' + theme.dim('- paste ANYTHING (URLs, files, ip:port, ip:port:user:pass) - auto-routed'));
    console.log('  ' + theme.key(' 0') + '. ' + chalk.white('Back'));
    console.log('');
    const c = (await ask(theme.key('  Choose: '))).trim();
    if (c === '0' || c === '') return;
    if (c === '1') { await addPublicSources(); }
    else if (c === '2') { await addPrivateSource(); }
    else if (c === '3') { await addSmartPaste(); }
  }
}

async function addPublicSources() {
  header();
  console.log(panel(chalk.bold('  +  Add PUBLIC sources - links or local files  '), { borderColor: 'cyan' }));
  console.log(theme.warn('\nPaste or drag & drop URLs / local files (Ctrl+V and multi-file drop supported).'));
  console.log(theme.dim('  Tip: select multiple files in Explorer and drag them all here - every path is parsed in order.'));
  console.log(theme.dim('  You can also drop a folder - all .txt / .list / .csv files inside are added.'));
  console.log(theme.dim('  Examples:'));
  console.log(theme.dim('    https://example.com/proxies.txt'));
  console.log(theme.dim('    C:\\Users\\me\\Desktop\\proxies.txt'));
  console.log(theme.dim('    /home/user/proxies.txt'));
  console.log(theme.dim('\nFinish with: blank line (Enter on empty line), or type END / . , or Ctrl+D.\n'));

  const buf = await new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: false });
    const acc = [];
    let done = false;
    const finish = () => { if (done) return; done = true; try { rl.close(); } catch {} resolve(acc); };
    process.stdout.write(theme.key('  > '));
    rl.on('line', (l) => {
      const t = l.trim();
      if (t === '' || t.toLowerCase() === 'end' || t === '.') return finish();
      acc.push(l);
      process.stdout.write(theme.key('  > '));
    });
    rl.on('close', finish);
  });

  const oldUrls = readSavedLinks();
  const oldFiles = readLocalFiles();
  const newUrls = [];
  const newFiles = [];
  const unknowns = [];
  for (const raw of buf) {
    const tokens = splitDroppedTokens(raw);
    for (const tok of tokens) {
      const c = classifySourceLine(tok);
      if (c.kind === 'url') { if (!newUrls.includes(c.value)) newUrls.push(c.value); }
      else if (c.kind === 'file') {
        const dirFiles = expandDirectoryTokens(c.value);
        if (dirFiles && dirFiles.length) {
          for (const df of dirFiles) if (!newFiles.includes(df)) newFiles.push(df);
        } else if (!newFiles.includes(c.value)) newFiles.push(c.value);
      }
      else if (c.kind === 'unknown') unknowns.push(c.value);
    }
  }
  const extraUrls = readUrlsFromText(buf.join('\n'));
  for (const u of extraUrls) if (!newUrls.includes(u)) newUrls.push(u);

  const mergedUrls = [...new Set([...oldUrls, ...newUrls])];
  const mergedFiles = [...new Set([...oldFiles, ...newFiles])];
  writeSavedLinks(mergedUrls);
  writeLocalFiles(mergedFiles);

  // v7.7.5: URLs auto-detect protocol from the URL text (socks5.txt, /http/, ...).
  // Local FILES have arbitrary names, so ask the user which protocol each new
  // file contains. Empty = auto (guess from filename, fallback unknown).
  const trulyNewFiles = mergedFiles.filter(f => !oldFiles.includes(f));
  if (trulyNewFiles.length) {
    console.log('\n' + theme.info(`Pick a protocol for each new FILE (empty = auto-guess from filename):`));
    console.log(theme.dim('  Accepted: http / https / socks4 / socks5   —   press Enter to skip.'));
    let bulk = '';
    if (trulyNewFiles.length > 1) {
      bulk = (await ask(theme.key(`  Same type for ALL ${trulyNewFiles.length} files? (http/https/socks4/socks5, empty = ask per file): `))).trim().toLowerCase();
      if (!['http','https','socks4','socks5'].includes(bulk)) bulk = '';
    }
    for (const fp of trulyNewFiles) {
      let t = bulk;
      if (!t) {
        const ans = (await ask(theme.key(`  Type for ${chalk.white(fp)}: `))).trim().toLowerCase();
        if (['http','https','socks4','socks5'].includes(ans)) t = ans;
      }
      if (t) setFileType(fp, t);
    }
  }

  const addedU = mergedUrls.length - oldUrls.length;
  const addedF = mergedFiles.length - oldFiles.length;
  console.log(theme.ok(`\nLinks: +${addedU} new  (total ${mergedUrls.length})   ` + theme.dim('(protocol auto-detected from URL)')));
  console.log(theme.ok(  `Files: +${addedF} new  (total ${mergedFiles.length})   ` + theme.dim('(protocol from your pick)')));
  if (unknowns.length) console.log(theme.warn(`Skipped ${unknowns.length} line(s) that were neither a URL nor an existing file:\n  ` + unknowns.slice(0,5).join('\n  ')));
  await ask('\n' + theme.dim('Enter to return...'));
}

async function addPrivateSource() {
  header();
  console.log(panel(chalk.bold('  +  Add PRIVATE source (needs user/password)  '), { borderColor: 'magenta' }));
  console.log(theme.dim('\n  Private sources are kept separate from public sources.'));
  console.log(theme.dim('  Each private source carries ONE username + ONE password'));
  console.log(theme.dim('  which is applied ONLY to proxy lines that arrive without their own auth.'));
  console.log(theme.dim('  Tester probes these proxies with the given credentials, so private proxies work correctly.\n'));
  // v7.7.5: ask protocol FIRST — filename/URL text is unreliable for private sources.
  const typeIn = (await ask(theme.key('  Protocol for this source? (http/https/socks4/socks5, empty = auto-guess): '))).trim().toLowerCase();
  const type = ['http','https','socks4','socks5'].includes(typeIn) ? typeIn : '';
  const raw = (await ask(theme.key('  Paste ONE URL or local file path: '))).trim();
  if (!raw) { console.log(theme.warn('Nothing entered.')); await ask('\n' + theme.dim('Enter...')); return; }
  const cls = classifySourceLine(raw);
  if (cls.kind !== 'url' && cls.kind !== 'file') {
    console.log(theme.err('Not a valid URL and not an existing file path.'));
    await ask('\n' + theme.dim('Enter...'));
    return;
  }
  const username = (await ask(theme.key('  Username for this source (empty = none): '))).trim();
  const password = (await ask(theme.key('  Password for this source (empty = none): '))).trim();
  const list = readPrivateSources();
  // v1.0.1: de-dupe by the FULL tuple (kind,value,username,password,type) so the same URL
  // can be saved with different credential pairs without silently overwriting each other.
  const filtered = list.filter(x => !(x.kind === cls.kind && x.value === cls.value && (x.username||'') === username && (x.password||'') === password && (x.type||'') === type));
  filtered.push({ kind: cls.kind, value: cls.value, username, password, type });
  writePrivateSources(filtered);
  console.log(theme.ok(`\nSaved private source. Total: ${filtered.length}`));
  await ask('\n' + theme.dim('Enter...'));
}

async function viewLinks() {
  header();
  const urls = readSavedLinks();
  const files = readLocalFiles();
  const priv = readPrivateSources();
  console.log(panel(chalk.bold(`  Saved sources - ${urls.length} link(s) + ${files.length} file(s) + ${priv.length} private  `), { borderColor: 'cyan' }));
  console.log('');
  console.log(theme.info('  Public links (URLs):'));
  if (!urls.length) console.log(theme.dim('    (none)'));
  urls.forEach((u, i) => console.log(theme.dim(`    ${String(i + 1).padStart(3)}.`) + ' ' + u));
  console.log('');
  console.log(theme.info('  Public files (local paths):'));
  if (!files.length) console.log(theme.dim('    (none)'));
  files.forEach((f, i) => {
    const exists = fs.existsSync(f);
    const idx = String(urls.length + i + 1).padStart(3);
    console.log(theme.dim(`    ${idx}.`) + ' ' + (exists ? f : chalk.red(f + '  (missing)')));
  });
  console.log('');
  console.log(theme.info('  Private sources (with per-source credentials):'));
  if (!priv.length) console.log(theme.dim('    (none)'));
  priv.forEach((p, i) => {
    const idx = String(urls.length + files.length + i + 1).padStart(3);
    const cred = (p.username || p.password) ? ` [user=${mask((p.username||'')+':'+(p.password||'')+'@x')}]` : ' [no creds]';
    const t = p.type ? ` type=${p.type}` : '';
    console.log(theme.dim(`    ${idx}.`) + ` [${p.kind}] ${p.value}${cred}${t}`);
  });
  await ask('\n' + theme.dim('Enter...'));
}

// Parse a selection like "1,3,5-8, 12" or "all" into a set of 1-based indices
function parseIndexSelection(input, max) {
  const s = String(input || '').trim().toLowerCase();
  if (!s) return new Set();
  if (s === 'all' || s === '*') { const all = new Set(); for (let i = 1; i <= max; i++) all.add(i); return all; }
  const out = new Set();
  for (const part of s.split(/[\s,;]+/).filter(Boolean)) {
    const m = part.match(/^(\d+)\s*-\s*(\d+)$/);
    if (m) {
      let a = Number(m[1]), b = Number(m[2]);
      if (a > b) [a, b] = [b, a];
      for (let i = Math.max(1, a); i <= Math.min(max, b); i++) out.add(i);
    } else if (/^\d+$/.test(part)) {
      const n = Number(part);
      if (n >= 1 && n <= max) out.add(n);
    }
  }
  return out;
}

async function removeLink() {
  header();
  const urls = readSavedLinks();
  const files = readLocalFiles();
  const priv = readPrivateSources();
  const total = urls.length + files.length + priv.length;
  if (!total) { console.log(theme.warn('\n  No sources saved.')); await ask('\n' + theme.dim('Enter...')); return; }
  console.log(panel(chalk.bold(`  Remove sources - ${urls.length} link(s) + ${files.length} file(s) + ${priv.length} private  `), { borderColor: 'cyan' }));
  console.log('');
  urls.forEach((u, i) => console.log(theme.dim(`  ${String(i + 1).padStart(3)}. [link]`) + ' ' + u));
  files.forEach((f, i) => console.log(theme.dim(`  ${String(urls.length + i + 1).padStart(3)}. [file]`) + ' ' + f));
  priv.forEach((p, i) => {
    const idx = String(urls.length + files.length + i + 1).padStart(3);
    const cred = (p.username || p.password) ? '  [has creds]' : '';
    console.log(theme.dim(`  ${idx}. [private:${p.kind}]`) + ' ' + p.value + cred);
  });
  console.log(theme.dim('\n  Enter one or many:  e.g.  3   or   1,4,7   or   2-6,10   or   all'));
  const raw = await ask(theme.key('  Numbers to remove: '));
  const sel = parseIndexSelection(raw, total);
  if (!sel.size) { console.log(theme.warn('\n  Nothing removed (no valid numbers).')); }
  else {
    const keptUrls = urls.filter((_, i) => !sel.has(i + 1));
    const keptFiles = files.filter((_, i) => !sel.has(urls.length + i + 1));
    const keptPriv  = priv.filter((_, i) => !sel.has(urls.length + files.length + i + 1));
    writeSavedLinks(keptUrls);
    writeLocalFiles(keptFiles);
    // v7.7.5: drop forced-type entries for removed files.
    { const tm = readFileTypes(); const keep = new Set(keptFiles); for (const k of Object.keys(tm)) if (!keep.has(k)) delete tm[k]; writeFileTypes(tm); }
    writePrivateSources(keptPriv);
    const removed = total - (keptUrls.length + keptFiles.length + keptPriv.length);
    console.log(theme.ok(`\nRemoved ${removed} source(s). Remaining: ${keptUrls.length} link + ${keptFiles.length} file + ${keptPriv.length} private.`));
  }
  await ask('\n' + theme.dim('Enter...'));
}


// v7.6: applyMode replaces applyPreset. A "mode" now owns ALL speed/accuracy/depth
// knobs (concurrency, timeouts, retries, requiredSuccesses, coverage, doubleCheck,
// score thresholds, anonymity/geo toggles). Manual-only settings (test URLs, judge,
// proxy auth, country filter, output flags, scheduler, geo provider) are preserved
// and never touched by a mode change — they stay in the Manual Settings section.
function applyMode(config, key) {
  const p = TEST_MODES[key]; if (!p) return config;
  const preserved = {
    testUrls: config.testUrls,
    ipEchoUrl: config.ipEchoUrl, ipEchoUrlHttp: config.ipEchoUrlHttp, judgeUrl: config.judgeUrl,
    saveDead: config.saveDead, keepAuth: config.keepAuth, outputWithScheme: config.outputWithScheme,
    sortBy: config.sortBy, geoProvider: config.geoProvider,
    countryFilter: config.countryFilter, excludeCountries: config.excludeCountries,
    maskCredentialsInLogs: config.maskCredentialsInLogs, useHistory: config.useHistory,
    collectRateLimitMs: config.collectRateLimitMs, schedule: config.schedule,
    proxyAuth: config.proxyAuth
  };
  const next = { ...config, ...p, ...preserved, activeMode: key, activePreset: key };
  saveConfig(next); return next;
}
// legacy alias so any external caller / plugin using applyPreset keeps working
const applyPreset = applyMode;

async function pickMode(config) {
  header();
  console.log(panel(chalk.bold('  Pick a Test Mode  '), { borderColor: 'cyan' }));
  console.log('');
  console.log(theme.dim('  Pick one mode. All speed/accuracy/depth knobs are set at once.'));
  console.log('');
  const entries = Object.entries(TEST_MODES);
  entries.forEach(([k, p], i) => {
    const mark = k === config.activeMode ? theme.ok(' ●') : '  ';
    console.log(`${mark} ${theme.key(String(i+1).padStart(2))}. ${chalk.white.bold(p.name.padEnd(22))} ${theme.dim('conc=' + String(p.concurrency).padEnd(4))} ${theme.dim('need=' + p.requiredSuccesses + '/' + p.coverage)} ${theme.dim(p.doubleCheck ? '2xCheck' : '       ')}`);
    console.log(`     ${theme.dim(p.description)}`);
  });
  console.log('');
  console.log('  ' + theme.key(' 0') + '. ' + chalk.white('Back'));
  console.log('');
  const c = (await ask(theme.key('  Choose: '))).trim();
  if (c === '0' || !c) return config;
  const idx = Number(c) - 1;
  const key = entries[idx] ? entries[idx][0] : c.toLowerCase();
  if (TEST_MODES[key]) {
    config = applyMode(config, key);
    console.log(theme.ok(`\n  Mode "${TEST_MODES[key].name}" applied.`));
    await new Promise(r => setTimeout(r, 900));
  }
  return config;
}

async function settingsMenu(config) {
  while (true) {
    header();
    console.log(panel(chalk.bold('  Settings  '), { borderColor: 'magenta' }));
    console.log('');
    const currentMode = TEST_MODES[config.activeMode] || TEST_MODES.balanced;
    // ---------- SECTION 1: MODE PICKER (bundled speed/accuracy) ----------
    console.log('  ' + chalk.bold.cyan('SECTION 1 - Test Mode'));
    console.log('  ' + theme.dim('Pick one mode; it sets speed / accuracy / depth in one shot.'));
    console.log('  ' + theme.dim('Current mode: ') + theme.key(config.activeMode) + '  ' + theme.dim('- ' + currentMode.name));
    console.log('     ' + theme.dim(`conc=${config.concurrency}  timeout=${config.timeoutMs}ms  retries=${config.retries}  need=${config.requiredSuccesses}/${config.coverage}  2xCheck=${config.doubleCheck?'on':'off'}  anon=${config.checkAnonymity?'on':'off'}  geo=${config.checkGeo?'on':'off'}  twoPhase=${config.twoPhase?'on':'off'}`));
    console.log('');
    console.log('  ' + theme.key(' 1') + '. ' + chalk.white.bold('Pick / change mode') + theme.dim('  (ultra/fast/balanced/accurate/deep/strict/lowpc/sample)'));
    console.log('');
    // ---------- SECTION 2: MANUAL-ONLY SETTINGS (independent of modes) ----------
    console.log('  ' + chalk.bold.magenta('SECTION 2 - Manual Settings (independent of modes)'));
    console.log('  ' + theme.dim('These are not touched by mode changes. Set them by hand.'));
    console.log('');
    const row = (n, label, val, hint) => `  ${theme.key(String(n).padStart(2))}. ${chalk.white(label.padEnd(34))} ${theme.dim('(')} ${theme.value(String(val))} ${theme.dim(')')}${hint ? '  ' + theme.dim(hint) : ''}`;
    console.log(row(2, 'API / Test URLs', `${config.testUrls.length} url`, 'endpoints the proxy is dialed against'));
    console.log(row(3, 'Judge URL (anonymity)', config.judgeUrl));
    console.log(row(4, 'IP echo URL (https)', config.ipEchoUrl));
    console.log(row(5, 'IP echo URL (http)', config.ipEchoUrlHttp));
    console.log(row(6, 'Global proxy auth (user/pass)', config.proxyAuth?.enabled ? `on  user=${mask(config.proxyAuth.username||'')}` : 'off', 'fallback for private proxies without per-source creds'));
    console.log(row(7, 'Country filter (only these)', (config.countryFilter||[]).join(',') || '-'));
    console.log(row(8, 'Exclude countries', (config.excludeCountries||[]).join(',') || '-'));
    console.log(row(9, 'Geo provider', config.geoProvider, 'ip-api / ipwho'));
    console.log(row(10,'Test types', config.testTypes.join(',')));
    console.log(row(11,'Save dead list', config.saveDead));
    console.log(row(12,'Keep auth in output', config.keepAuth));
    console.log(row(13,'Output with scheme', config.outputWithScheme));
    console.log(row(14,'Mask credentials in logs', config.maskCredentialsInLogs));
    console.log(row(15,'Use history (skip dead 6h)', config.useHistory));
    console.log(row(16,'Sort by', config.sortBy, 'score / latency / country'));
    console.log(row(17,'Collect rate-limit (ms)', config.collectRateLimitMs, '0 = no limit (v7.6+ default for high-volume)'));
    console.log(row(18,'Scheduler', `enabled=${config.schedule.enabled} every=${config.schedule.everyHours}h`));
    console.log(row(19,'Advanced override (per-knob)', '...', 'expert only; overrides mode values'));
    console.log(row(20,'Settings profiles', `${listProfiles().length} saved`, 'save/load/delete named config presets'));
    console.log('');
    console.log('  ' + theme.key(' 0') + '. ' + chalk.white('Back'));
    console.log('');
    const c = (await ask(theme.key('  Choose: '))).trim();
    if (c === '0' || c === '') return config;
    if (c === '1') { config = await pickMode(config); continue; }
    else if (c === '2') { const v = (await ask('Test URLs (comma-separated): ')).split(',').map(x=>x.trim()).filter(Boolean); if (v.length) config.testUrls = v; }
    else if (c === '3') { const v = (await ask('Judge URL: ')).trim(); if (v) config.judgeUrl = v; }
    else if (c === '4') { const v = (await ask('IP echo (https): ')).trim(); if (v) config.ipEchoUrl = v; }
    else if (c === '5') { const v = (await ask('IP echo (http): ')).trim(); if (v) config.ipEchoUrlHttp = v; }
    else if (c === '6') {
      config.proxyAuth = config.proxyAuth || { enabled: false, username: '', password: '', applyToMissingOnly: true };
      config.proxyAuth.enabled = /^(y|1|true|on)/i.test(await ask('Enable global proxy auth? y/n: '));
      if (config.proxyAuth.enabled) {
        config.proxyAuth.username = await ask('Proxy username: ');
        config.proxyAuth.password = await ask('Proxy password: ');
        config.proxyAuth.applyToMissingOnly = !/^(n|0|false|off)/i.test(await ask('Use only when a proxy line has no auth? Y/n: '));
      }
    }
    else if (c === '7') config.countryFilter = (await ask('Country codes (comma, empty=none): ')).split(',').map(x=>x.trim().toUpperCase()).filter(Boolean);
    else if (c === '8') config.excludeCountries = (await ask('Country codes to exclude: ')).split(',').map(x=>x.trim().toUpperCase()).filter(Boolean);
    else if (c === '9') { const v = (await ask('Geo provider (ip-api / ipwho): ')).trim(); if (v) config.geoProvider = v; }
    else if (c === '10'){ const v = (await ask('Types (http,https,socks4,socks5): ')).split(',').map(x=>x.trim()).filter(Boolean); if (v.length) config.testTypes = v; }
    else if (c === '11') config.saveDead = /^(y|1|true|on)/i.test(await ask('Save dead list? y/n: '));
    else if (c === '12') config.keepAuth = /^(y|1|true|on)/i.test(await ask('Keep auth in output? y/n: '));
    else if (c === '13') config.outputWithScheme = /^(y|1|true|on)/i.test(await ask('Output with scheme? y/n: '));
    else if (c === '14') config.maskCredentialsInLogs = /^(y|1|true|on)/i.test(await ask('Mask credentials in logs? y/n: '));
    else if (c === '15') config.useHistory = /^(y|1|true|on)/i.test(await ask('Use history? y/n: '));
    else if (c === '16') { const v = (await ask('Sort by (score/latency/country): ')).trim().toLowerCase(); if (v) config.sortBy = v; }
    else if (c === '17') { const v = Number(await ask('Collect rate-limit ms (0 = no limit): ')); if (!Number.isNaN(v)) config.collectRateLimitMs = Math.max(0, v); }
    else if (c === '18') {
      config.schedule.enabled = /^(y|1|true|on)/i.test(await ask('Enable scheduler? y/n: '));
      config.schedule.everyHours = Number(await ask('Every N hours: ')) || config.schedule.everyHours;
      config.schedule.runCollect = /^(y|1|true|on)/i.test(await ask('Include collect? y/n: '));
      config.schedule.runTest = /^(y|1|true|on)/i.test(await ask('Include test? y/n: '));
    }
    else if (c === '19') config = await advancedOverride(config);
    else if (c === '20') config = await profilesMenu(config);
    saveConfig(config);
  }
}

// v7.8.0: named settings profiles — save/load/delete whole configs.
async function profilesMenu(config) {
  while (true) {
    header();
    const profiles = listProfiles();
    console.log(panel(chalk.bold('  Settings Profiles  '), { borderColor: 'cyan' }));
    console.log('');
    console.log(theme.dim('  Save the current config under a name, then load it back any time.'));
    console.log(theme.dim('  Useful for switching between "telegram", "scraping", "torrent", etc.\n'));
    if (!profiles.length) console.log(theme.dim('  (no profiles yet)'));
    else profiles.forEach((n, i) => console.log(`  ${theme.key(String(i+1).padStart(2))}. ${chalk.white(n)}`));
    console.log('');
    console.log('  ' + theme.key(' S') + '. ' + chalk.white('Save current config as new profile'));
    console.log('  ' + theme.key(' L') + '. ' + chalk.white('Load a profile by number'));
    console.log('  ' + theme.key(' D') + '. ' + chalk.white('Delete a profile by number'));
    console.log('  ' + theme.key(' 0') + '. ' + chalk.white('Back'));
    console.log('');
    const c = (await ask(theme.key('  Choose: '))).trim().toLowerCase();
    if (c === '0' || c === '') return config;
    if (c === 's') {
      const name = (await ask(theme.key('  Profile name (letters/digits/_/-): '))).trim();
      if (!name) { console.log(theme.warn('Empty name — skipped.')); }
      else { const fp = saveProfile(name, config); if (fp) console.log(theme.ok(`Saved -> ${fp}`)); }
      await ask('\n' + theme.dim('Enter...'));
    } else if (c === 'l') {
      const raw = (await ask(theme.key('  Number to load: '))).trim();
      const i = Number(raw) - 1;
      if (profiles[i]) {
        const loaded = loadProfile(profiles[i]);
        if (loaded) { config = { ...config, ...loaded }; saveConfig(config); console.log(theme.ok(`Loaded profile "${profiles[i]}".`)); }
        else console.log(theme.err('Failed to load profile.'));
      } else console.log(theme.warn('Invalid number.'));
      await ask('\n' + theme.dim('Enter...'));
    } else if (c === 'd') {
      const raw = (await ask(theme.key('  Number to delete: '))).trim();
      const i = Number(raw) - 1;
      if (profiles[i]) { deleteProfile(profiles[i]); console.log(theme.ok(`Deleted "${profiles[i]}".`)); }
      else console.log(theme.warn('Invalid number.'));
      await ask('\n' + theme.dim('Enter...'));
    }
  }
}


// v7.6: expert-only. Lets power users override the individual knobs that
// normally come from the active mode. Intentionally hidden behind option 19.
async function advancedOverride(config) {
  header();
  console.log(panel(chalk.bold('  Advanced Override  ') + theme.dim(' - normally set by the active mode'), { borderColor: 'red' }));
  console.log(theme.dim('  Empty Enter = keep current. Overrides last until you pick another mode.\n'));
  const num = async (label, cur) => { const v = (await ask(`  ${label} [${cur}]: `)).trim(); return v === '' ? cur : (Number(v) || cur); };
  const bool = async (label, cur) => { const v = (await ask(`  ${label} [${cur?'y':'n'}]: `)).trim(); return v === '' ? cur : /^(y|1|true|on)/i.test(v); };
  config.concurrency          = await num('Concurrency',              config.concurrency);
  config.timeoutMs            = await num('HTTP timeout ms',          config.timeoutMs);
  config.retries              = await num('Per-endpoint retries',     config.retries);
  config.requiredSuccesses    = await num('Required successes',       config.requiredSuccesses);
  config.coverage             = await num('Coverage (max endpoints)', config.coverage);
  config.tcpTimeoutMs         = await num('TCP timeout ms',           config.tcpTimeoutMs);
  config.twoPhase             = await bool('Two-phase TCP+HTTP',      config.twoPhase);
  config.doubleCheck          = await bool('Double-check alive',      config.doubleCheck);
  config.smartProtocolFallback= await bool('Smart protocol fallback', config.smartProtocolFallback);
  config.checkAnonymity       = await bool('Check anonymity',         config.checkAnonymity);
  config.checkGeo             = await bool('Check geo',               config.checkGeo);
  config.excellentScore       = await num('Excellent score',          config.excellentScore);
  config.goodScore            = await num('Good score',               config.goodScore);
  config.maxExcellentLatencyMs= await num('Max excellent latency ms', config.maxExcellentLatencyMs);
  config.veryBestLimit        = await num('Very-best limit',          config.veryBestLimit);
  config.maxToTest            = await num('Max to test (0=all)',      config.maxToTest);
  saveConfig(config);
  console.log(theme.ok('\n  Saved.'));
  await new Promise(r => setTimeout(r, 700));
  return config;
}


async function openOutput() {
  ensureDir(OUTPUT);
  console.log(theme.dim('Output: ') + OUTPUT);
  try {
    const { exec } = require('child_process');
    if (process.platform === 'win32') exec(`start "" "${OUTPUT}"`);
    else if (process.platform === 'darwin') exec(`open "${OUTPUT}"`);
    else exec(`xdg-open "${OUTPUT}"`);
  } catch {}
  await ask('\n' + theme.dim('Enter...'));
}

async function runSchedule(config) {
  header();
  const hours = Math.max(0.1, Number(config.schedule.everyHours) || 6);
  console.log(panel(chalk.bold(`  ⏱  Scheduler — every ${hours}h  `) + theme.dim(' Ctrl+C to stop'), { borderColor: 'cyan' }));
  const runOnce = async () => {
    resetSessionArchive();
    console.log(theme.dim(`\n[${new Date().toLocaleString()}] cycle start`));
    if (config.schedule.runCollect) await collectFromLinks({ ...config, __nonInteractive: true }, { mode: 'user' });
    if (config.schedule.runTest) await testCollected(config);
    console.log(theme.dim(`[${new Date().toLocaleString()}] cycle done. Sleeping ${hours}h...\n`));
  };
  await runOnce();
  setInterval(runOnce, hours * 3600 * 1000);
}

// ============================================================
// MAIN MENU
// ============================================================

// ============================================================
// v7.9.0 - Smart Paste: accept URLs, files, and inline proxies
// ============================================================
async function addSmartPaste() {
  header();
  console.log(panel(chalk.bold('  ✨  Smart Paste  '), { borderColor: 'yellow' }));
  console.log(theme.dim('\n  Paste ANYTHING - the app will figure it out:'));
  console.log(theme.dim('    - https://... URL           -> saved as public source'));
  console.log(theme.dim('    - C:\\path\\file.txt / /path  -> saved as local file source'));
  console.log(theme.dim('    - ip:port                    -> saved as inline proxy'));
  console.log(theme.dim('    - ip:port:user:pass          -> saved as inline proxy w/ auth'));
  console.log(theme.dim('    - http://user:pass@ip:port   -> saved as inline proxy'));
  console.log(theme.dim('\n  Finish with an empty line, END, or . (dot).\n'));

  const buf = await new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: false });
    const acc = []; let done = false;
    const finish = () => { if (done) return; done = true; try { rl.close(); } catch {} resolve(acc); };
    process.stdout.write(theme.key('  > '));
    rl.on('line', (l) => {
      const t = l.trim();
      if (t === '' || t.toLowerCase() === 'end' || t === '.') return finish();
      acc.push(l);
      process.stdout.write(theme.key('  > '));
    });
    rl.on('close', finish);
  });

  const oldUrls  = readSavedLinks();
  const oldFiles = readLocalFiles();
  const newUrls = [];
  const newFiles = [];
  const inlineProxies = [];
  const unknowns = [];

  for (const raw of buf) {
    const tokens = splitDroppedTokens(raw);
    for (const tok of tokens) {
      const cls = classifySourceLine(tok);
      if (cls.kind === 'url')  { if (!newUrls.includes(cls.value))  newUrls.push(cls.value); continue; }
      if (cls.kind === 'file') {
        const dirFiles = expandDirectoryTokens(cls.value);
        if (dirFiles && dirFiles.length) { for (const df of dirFiles) if (!newFiles.includes(df)) newFiles.push(df); }
        else if (!newFiles.includes(cls.value)) newFiles.push(cls.value);
        continue;
      }
      // Try as an inline proxy line (v1.0.1: normalise to URL form so credentials are always preserved)
      const p = parseProxyLine(tok);
      if (p) {
        const auth = (p.username || p.password) ? `${encodeURIComponent(p.username)}:${encodeURIComponent(p.password)}@` : '';
        const canonical = `${p.type || 'unknown'}://${auth}${p.host}:${p.port}`;
        inlineProxies.push(canonical);
        continue;
      }
      if (tok.trim()) unknowns.push(tok.trim());
    }
  }
  const extraUrls = readUrlsFromText(buf.join('\n'));
  for (const u of extraUrls) if (!newUrls.includes(u)) newUrls.push(u);

  // Persist inline proxies into pasted_proxies.txt and register file as a source
  let addedInline = 0;
  if (inlineProxies.length) {
    let existing = '';
    try { if (fs.existsSync(PASTED_FILE)) existing = fs.readFileSync(PASTED_FILE, 'utf8'); } catch {}
    const already = new Set(existing.split(/\r?\n/).map(x => x.trim()).filter(Boolean));
    const fresh = inlineProxies.filter(x => !already.has(x));
    addedInline = fresh.length;
    if (fresh.length) {
      try {
        fs.appendFileSync(PASTED_FILE, (existing && !existing.endsWith('\n') ? '\n' : '') + fresh.join('\n') + '\n', 'utf8');
      } catch (e) { console.log(theme.err('Could not write inline proxies: ' + e.message)); }
    }
    if (!newFiles.includes(PASTED_FILE) && !oldFiles.includes(PASTED_FILE)) newFiles.push(PASTED_FILE);
  }

  const mergedUrls  = [...new Set([...oldUrls,  ...newUrls])];
  const mergedFiles = [...new Set([...oldFiles, ...newFiles])];
  writeSavedLinks(mergedUrls);
  writeLocalFiles(mergedFiles);
  // v1.0.1: remember which URLs and files came via Smart Paste for the dedicated Collect scope.
  try { addPastedSources({ urls: newUrls, files: newFiles }); } catch {}

  const addedU = mergedUrls.length  - oldUrls.length;
  const addedF = mergedFiles.length - oldFiles.length;
  console.log('');
  console.log(theme.ok('  Smart Paste results:'));
  console.log(theme.ok('    URLs added        : +' + addedU + '   (total ' + mergedUrls.length + ')'));
  console.log(theme.ok('    Files added       : +' + addedF + '   (total ' + mergedFiles.length + ')'));
  console.log(theme.ok('    Inline proxies    : +' + addedInline + '   (saved to pasted_proxies.txt)'));
  if (unknowns.length) console.log(theme.warn('    Skipped (unknown) : ' + unknowns.length + '  -> ' + unknowns.slice(0,3).join(' , ') + (unknowns.length>3?' ...':'')));
  await ask('\n' + theme.dim('Enter to return...'));
}

// ============================================================
// v7.9.2 - Manage sources (merged View + Remove)
// ============================================================
async function manageSourcesMenu() {
  while (true) {
    header();
    const urls = readSavedLinks();
    const files = readLocalFiles();
    const priv = readPrivateSources();
    console.log(panel(chalk.bold(`  Manage sources - ${urls.length} link(s) + ${files.length} file(s) + ${priv.length} private  `), { borderColor: 'cyan' }));
    console.log('');
    console.log('  ' + theme.key(' 1') + '. ' + chalk.white.bold('View saved sources') + '   ' + theme.dim('- list every link, file, and private source'));
    console.log('  ' + theme.key(' 2') + '. ' + chalk.white.bold('Remove sources')     + '       ' + theme.dim('- delete one, many (1,4,7 / 2-6), or all'));
    console.log('  ' + theme.key(' 0') + '. ' + chalk.white('Back'));
    console.log('');
    const c = (await ask(theme.key('  Choose: '))).trim().toLowerCase();
    if (c === '0' || c === '') return;
    if (c === '1') await viewLinks();
    else if (c === '2') await removeLink();
    else if (c === 'h' || c === '?') await showHelp();
  }
}

// ============================================================
// v7.9.2 - Collect proxies (merged: from MY sources / auto built-in)
// ============================================================
async function collectMenu(config) {
  while (true) {
    header();
    console.log(panel(chalk.bold('  Collect proxies  '), { borderColor: 'cyan' }));
    console.log('');
    console.log('  ' + theme.key(' 1') + '. ' + chalk.hex('#a1662f').bold('Public sources')   + '   ' + theme.dim('- only URLs/files you added via Add sources > Public'));
    console.log('  ' + theme.key(' 2') + '. ' + chalk.hex('#ff9800').bold('Private sources')  + '  ' + theme.dim('- only URLs/files added via Add sources > Private (user:pass)'));
    console.log('  ' + theme.key(' 3') + '. ' + chalk.hex('#ffeb3b').bold('Smart Paste')      + '     ' + theme.dim('- only URLs/files/inline proxies added via Smart Paste'));
    console.log('  ' + theme.key(' 4') + '. ' + chalk.white.bold('Auto (built-in)') + '     ' + theme.dim('- use built-in default list, nothing saved to your sources'));
    console.log('  ' + theme.key(' 5') + '. ' + chalk.white.bold('Both (merged)')   + '       ' + theme.dim('- Public + Smart Paste first, then merge built-in defaults (Private NOT included)'));
    console.log('  ' + theme.key(' 0') + '. ' + chalk.white('Back'));
    console.log('');
    const c = (await ask(theme.key('  Choose: '))).trim().toLowerCase();
    if (c === '0' || c === '') return;
    if (c === '1') { resetSessionArchive(); await collectFromLinks(config, { mode: 'user', scope: 'public' }); await ask('\n' + theme.dim('Enter...')); return; }
    if (c === '2') { resetSessionArchive(); await collectFromLinks(config, { mode: 'private-only' }); await ask('\n' + theme.dim('Enter...')); return; }
    if (c === '3') { resetSessionArchive(); await collectFromLinks(config, { mode: 'user', scope: 'pasted' }); await ask('\n' + theme.dim('Enter...')); return; }
    if (c === '4') { resetSessionArchive(); await collectFromLinks(config, { mode: 'auto' }); await ask('\n' + theme.dim('Enter...')); return; }
    if (c === '5') {
      // v1.0.5: Both = Public + Smart Paste + Auto built-in. Private sources are
      // intentionally excluded — use option 2 to run them on their own.
      resetSessionArchive();
      resetStop();
      await collectFromLinks(config, { mode: 'user', scope: 'no-private' });
      if (!STOP.requested) await collectFromLinks(config, { mode: 'auto', __merge: true });
      resetStop();
      await ask('\n' + theme.dim('Enter...'));
      return;
    }
    if (c === 'h' || c === '?') await showHelp();
  }
}

// ============================================================
// v7.9.2 - Pre-test mode chooser: asked BEFORE every Test run
// ============================================================
function autoPickMode(count) {
  // Sensible defaults tuned to list size
  if (count <= 1000)   return 'deep';
  if (count <= 5000)   return 'accurate';
  if (count <= 40000)  return 'accurate';
  if (count <= 100000) return 'fast';
  return 'ultra';
}

async function chooseTestModeBeforeRun(config) {
  const proxies = readCollectedForTest(config);
  const count = proxies.length;
  header();
  console.log(panel(chalk.bold('  Test proxies  '), { borderColor: 'cyan' }));
  console.log('');
  if (!count) {
    console.log(theme.warn('  No collected proxies found. Run "Collect proxies" first.'));
    await ask('\n' + theme.dim('Enter...'));
    return null;
  }
  console.log(`  ${theme.label('Collected list:')} ${theme.value(count)} proxies`);
  console.log(`  ${theme.label('Current mode  :')} ${theme.key(config.activeMode)}   ${theme.dim('conc=' + config.concurrency + ' timeout=' + config.timeoutMs + 'ms retries=' + config.retries)}`);
  console.log('');
  console.log('  ' + theme.key(' 1') + '. ' + chalk.white.bold('Use CURRENT mode')  + '        ' + theme.dim('- keep the mode set in Settings (' + config.activeMode + ')'));
  console.log('  ' + theme.key(' 2') + '. ' + chalk.white.bold('AUTO-pick for me')  + '        ' + theme.dim('- app chooses based on list size (' + count + ' -> ' + autoPickMode(count) + ')'));
  console.log('  ' + theme.key(' 3') + '. ' + chalk.white.bold('Choose manually')   + '        ' + theme.dim('- fast / balanced / accurate / deep / strict / ultra / lowpc / sample'));
  console.log('  ' + theme.key(' 0') + '. ' + chalk.white('Back (cancel test)'));
  console.log('');
  const c = (await ask(theme.key('  Choose: '))).trim().toLowerCase();
  if (c === '0' || c === '') return null;
  if (c === '1') return config;
  if (c === '2') {
    const mode = autoPickMode(count);
    config = applyMode(config, mode);
    console.log('\n' + theme.ok('  ✓ Auto-picked mode: ' + chalk.bold(mode)) + theme.dim('   conc=' + config.concurrency + ' timeout=' + config.timeoutMs + 'ms'));
    await new Promise(r => setTimeout(r, 700));
    return config;
  }
  if (c === '3') {
    return await pickMode(config);
  }
  if (c === 'h' || c === '?') { await showHelp(); return chooseTestModeBeforeRun(config); }
  return null;
}

async function mainMenu() {
  let config = loadConfig();
  while (true) {
    header();
    const lbl = (t) => chalk.hex('#9d4edd').bold(t);
    const modeLbl = (t) => chalk.hex('#9d4edd').bold(t);
    const val = (t) => chalk.hex('#00e5ff').bold(t);
    const onC = chalk.hex('#00ff00').bold('on');
    const offC = chalk.hex('#ff0000').bold('off');
    const status = panel(
      `${modeLbl('Mode   :')} ${val(config.activeMode)}   ${lbl('Two-Phase:')} ${config.twoPhase ? onC : offC}   ${lbl('Conc:')} ${val(config.concurrency)}   ${lbl('Anon:')} ${config.checkAnonymity ? onC : offC}   ${lbl('Geo:')} ${config.checkGeo ? onC : offC}`,
      { borderColor: '#00e5ff', borderStyle: 'round', padding: { top: 0, bottom: 0, left: 1, right: 1 } }
    );
    console.log(status);
    console.log('');
    const item = (k, en, hint) => `  ${theme.key(String(k).padStart(2))}  ${chalk.white.bold(en.padEnd(24))}${theme.dim('|')}  ${chalk.hex('#b39ddb')(hint)}`;
    console.log(item(1, 'Add sources',        'public / private / smart paste'));
    console.log(item(2, 'Manage sources',     'view + remove saved sources'));
    console.log(item(3, 'Collect proxies',    'public / private / smart paste / auto / both'));
    console.log(item(4, 'Test proxies',       'test last collected (asks for mode first)'));
    console.log(item(5, 'Settings / Modes',   'change mode + manual settings'));
    console.log(item(6, 'Open output folder', 'alive / best / csv / html report'));
    // Highlighted Help — attention-grabbing so new users notice it
    const helpLine = `  ${theme.key(' H')}  ${theme.brand('Help'.padEnd(24))}${theme.dim('|')}  ${chalk.hex('#b71c1c').bold('Start with the full guide — press ')}${chalk.hex('#b71c1c').bold('[')}${chalk.hex('#ff1744').bold('H')}${chalk.hex('#b71c1c').bold(']')}`;
    console.log(helpLine);
    console.log(item(0, 'Exit',               'quit'));
    console.log('');
    const c = (await ask(theme.key('  Choose: '))).trim().toLowerCase();
    if (c === '0') { console.log(theme.brand('\n  Bye\n')); process.exit(0); }
    else if (c === '1') await addLinks();
    else if (c === '2') await manageSourcesMenu();
    else if (c === '3') { config = loadConfig(); await collectMenu(config); }
    else if (c === '4') {
      const chosen = await chooseTestModeBeforeRun(config);
      if (chosen) {
        config = chosen;
        resetSessionArchive();
        await testCollected(config);
        await ask('\n' + theme.dim('Enter...'));
      }
    }
    else if (c === '5') { config = await settingsMenu(config); }
    else if (c === '6') await openOutput();
    else if (c === 'h' || c === '?') await showHelp();
  }
}


// ============================================================
// SIGINT — stop cleanly even outside test
// ============================================================
let sigintCount = 0;
process.on('SIGINT', () => {
  sigintCount++;
  if (sigintCount >= 2) { console.log(theme.err('\n\nForce exit.')); process.exit(130); }
  requestStop('SIGINT');
});

// ============================================================
// CLI
// ============================================================
async function main() {
  const config = loadConfig();
  const args = process.argv.slice(2);
  if (args.includes('--collect')) return collectFromLinks({ ...config, __nonInteractive: true }, { mode: 'user' });
  if (args.includes('--auto-collect')) return collectFromLinks({ ...config, __nonInteractive: true }, { mode: 'auto' });
  if (args.includes('--test')) return testCollected(config);
  if (args.includes('--auto')) { await collectFromLinks({ ...config, __nonInteractive: true }, { mode: 'user' }); if (!STOP.requested) await testCollected(config); return; }
  if (args.includes('--schedule')) return runSchedule(config);
  return mainMenu();
}

main().catch(e => { console.error(theme.err('Fatal:'), e.message); log(`fatal: ${e.stack || e.message}`); process.exit(1); });
