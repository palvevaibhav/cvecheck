#!/usr/bin/env node
/**
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║   CVE Intelligence Platform  v8.0  –  Production Architecture          ║
 * ║                                                                          ║
 * ║  WHAT v7 WAS MISSING (Gap Analysis):                                    ║
 * ║  ─────────────────────────────────────────────────────────────────────  ║
 * ║  [CRITICAL] No circuit breakers → one slow API kills entire scan       ║
 * ║  [CRITICAL] No per-domain rate limiting → instant IP ban from NVD/GH   ║
 * ║  [CRITICAL] No CISA KEV feed → miss actively-exploited CVEs            ║
 * ║  [CRITICAL] No CWE extraction → can't do weakness-class analysis       ║
 * ║  [CRITICAL] No VEX output → can't suppress false positives at scale    ║
 * ║  [HIGH]     No worker pool → one CVE at a time, unusable at 50GB+      ║
 * ║  [HIGH]     EPSS fetched one-by-one → 100 CVEs = 100 API calls         ║
 * ║  [HIGH]     No retry with jitter → transient failures become hard fails ║
 * ║  [HIGH]     No metrics/observability → no idea what's failing in prod   ║
 * ║  [HIGH]     DeepAnalysisAgent hardcodes log4j repo URL                  ║
 * ║  [HIGH]     No SBOM correlation → can't link package→CVE in context    ║
 * ║  [MEDIUM]   No package alias resolution (log4j vs log4j-core)          ║
 * ║  [MEDIUM]   No false-positive suppression pipeline                      ║
 * ║  [MEDIUM]   No structured event bus → agents are tightly coupled        ║
 * ║                                                                          ║
 * ║  Architecture: Event-driven pipeline over in-process EventEmitter.      ║
 * ║  Drop-in swap to Redis Streams / Kafka by replacing EventBus class.     ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 *
 * Usage:
 *   node cve-platform-v8.js CVE-2021-44228
 *   CONCURRENCY=8 SAVE_OUTPUT=1 node cve-platform-v8.js CVE-2021-44228
 *
 * Env:
 *   NVD_API_KEY      – removes NVD rate cap (2000 req/30s vs 5/30s)
 *   GITHUB_TOKEN     – removes GitHub 60 req/h anon cap
 *   REDIS_URL        – redis://user:pass@host:6379  (optional)
 *   CONCURRENCY      – worker pool size (default 4)
 *   SAVE_OUTPUT      – write JSON report to disk
 *   DEBUG            – verbose stack traces
 */

"use strict";

const { EventEmitter } = require("events");
const axios            = require("axios");
const https            = require("https");
const fs               = require("fs");
const crypto           = require("crypto");

let Redis;
try { Redis = require("ioredis"); } catch (_) { /* optional */ }

// ══════════════════════════════════════════════════════════════════════════
//  §1  CONSTANTS & CONFIGURATION
// ══════════════════════════════════════════════════════════════════════════

const CONCURRENCY = parseInt(process.env.CONCURRENCY || "4", 10);

const API = {
  NVD_CVE:        "https://services.nvd.nist.gov/rest/json/cves/2.0",
  OSV_VULNS:      "https://api.osv.dev/v1/vulns",
  GHSA_REST:      "https://api.github.com/advisories",
  REDHAT_JSON:    "https://access.redhat.com/hydra/rest/securitydata/cve/",
  UBUNTU_CVE:     "https://ubuntu.com/security/cves",
  DEBIAN_TRACKER: "https://security-tracker.debian.org/tracker",
  EPSS_API:       "https://api.first.org/data/v1/epss",
  // NEW v8 feeds
  CISA_KEV:       "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
  OSV_QUERY:      "https://api.osv.dev/v1/query",
  VULNCHECK_NVD:  "https://api.vulncheck.com/v3/index/nist-nvd2",  // optional enrichment
};

// Per-domain rate limits (requests / window_ms).
// These reflect the *public* (unauthenticated) limits of each API.
const RATE_LIMITS = {
  "services.nvd.nist.gov": { rps: process.env.NVD_API_KEY ? 50 : 5,  windowMs: 30_000 },
  "api.github.com":         { rps: process.env.GITHUB_TOKEN ? 5000 : 60, windowMs: 3_600_000 },
  "api.osv.dev":            { rps: 100, windowMs: 60_000 },
  "api.first.org":          { rps: 30,  windowMs: 60_000 },
  "www.cisa.gov":           { rps: 5,   windowMs: 60_000 },
  "default":                { rps: 10,  windowMs: 60_000 },
};

const VERSION_RE       = /^\d+\.\d+(\.\d+)?(-\d+)?([+~][a-zA-Z0-9.]+)?$/;
const GHCOMMIT_RE      = /github\.com\/([^/]+)\/([^/]+)\/commit\/([0-9a-f]{40})/i;
const FILE_PATH_RE     = /(?:\/[\w\-.]+)+\.(?:java|js|ts|py|go|rs|c|cpp|h|hpp|xml|properties|yaml|yml|json|sh|rb|php)/gi;
const CWE_RE           = /CWE-(\d+)/gi;
const RHSA_RE          = /RHSA-\d{4}:\d{4,}/g;

// CWE descriptions for the most common 30 weakness IDs
const CWE_MAP = {
  "79": "Cross-site Scripting (XSS)", "89": "SQL Injection",
  "94": "Code Injection",            "119": "Buffer Overflow",
  "125": "Out-of-bounds Read",       "190": "Integer Overflow",
  "200": "Information Exposure",     "22": "Path Traversal",
  "269": "Improper Privilege Management",
  "287": "Improper Authentication",  "306": "Missing Authentication",
  "326": "Inadequate Encryption",    "327": "Broken Cryptographic Algorithm",
  "400": "Uncontrolled Resource Consumption",
  "416": "Use After Free",           "434": "Unrestricted Upload",
  "502": "Deserialization of Untrusted Data",
  "601": "URL Redirection (Open Redirect)",
  "611": "XML External Entity (XXE)",
  "787": "Out-of-bounds Write",      "918": "SSRF",
  "1321": "Prototype Pollution",     "20": "Improper Input Validation",
  "77": "Command Injection",         "78": "OS Command Injection",
};

// ══════════════════════════════════════════════════════════════════════════
//  §2  METRICS COLLECTOR  (Prometheus-compatible, plug in prom-client)
//  GAP: v7 had zero observability. In production you MUST know
//       which source is slow, which CVEs hit circuit breakers, cache hit rate.
// ══════════════════════════════════════════════════════════════════════════

class Metrics {
  constructor() {
    this._counters   = new Map();
    this._histograms = new Map();
    this._gauges     = new Map();
  }
  incr(name, labels = {}) {
    const k = `${name}|${JSON.stringify(labels)}`;
    this._counters.set(k, (this._counters.get(k) || 0) + 1);
  }
  gauge(name, value, labels = {}) {
    const k = `${name}|${JSON.stringify(labels)}`;
    this._gauges.set(k, value);
  }
  observe(name, valueMs, labels = {}) {
    const k = `${name}|${JSON.stringify(labels)}`;
    const arr = this._histograms.get(k) || [];
    arr.push(valueMs);
    this._histograms.set(k, arr);
  }
  summary() {
    const out = {};
    for (const [k, v] of this._counters)   out[`counter:${k}`]   = v;
    for (const [k, v] of this._gauges)     out[`gauge:${k}`]     = v;
    for (const [k, arr] of this._histograms) {
      const sorted = [...arr].sort((a, b) => a - b);
      const p = (p) => sorted[Math.floor(sorted.length * p)] ?? 0;
      out[`hist:${k}`] = { count: arr.length, p50: p(0.5), p95: p(0.95), p99: p(0.99) };
    }
    return out;
  }
}
const metrics = new Metrics();

// ══════════════════════════════════════════════════════════════════════════
//  §3  TOKEN-BUCKET RATE LIMITER  (per domain)
//  GAP: v7 had no rate limiting. NVD will 403 you after 5 requests/30s
//       without an API key. GitHub bans unauthenticated IPs aggressively.
// ══════════════════════════════════════════════════════════════════════════

class TokenBucket {
  constructor(capacity, refillMs) {
    this.capacity  = capacity;
    this.tokens    = capacity;
    this.refillMs  = refillMs;
    this.lastRefill = Date.now();
    this._queue    = [];
  }
  _refill() {
    const now    = Date.now();
    const delta  = (now - this.lastRefill) / this.refillMs;
    this.tokens  = Math.min(this.capacity, this.tokens + delta * this.capacity);
    this.lastRefill = now;
  }
  acquire() {
    return new Promise((resolve) => {
      this._tryAcquire(resolve);
    });
  }
  _tryAcquire(resolve) {
    this._refill();
    if (this.tokens >= 1) {
      this.tokens -= 1;
      resolve();
    } else {
      const wait = (1 - this.tokens) / this.capacity * this.refillMs;
      setTimeout(() => this._tryAcquire(resolve), Math.ceil(wait) + 10);
    }
  }
}

class RateLimiterRegistry {
  constructor() { this._buckets = new Map(); }
  _cfg(domain) {
    return RATE_LIMITS[domain] || RATE_LIMITS.default;
  }
  async throttle(url) {
    const domain = new URL(url).hostname;
    if (!this._buckets.has(domain)) {
      const cfg = this._cfg(domain);
      // capacity = max burst = rps (we refill over windowMs)
      this._buckets.set(domain, new TokenBucket(cfg.rps, cfg.windowMs));
    }
    await this._buckets.get(domain).acquire();
    metrics.incr("rate_limiter.throttled", { domain });
  }
}
const rateLimiter = new RateLimiterRegistry();

// ══════════════════════════════════════════════════════════════════════════
//  §4  CIRCUIT BREAKER
//  GAP: v7 would hang forever if NVD went down. CircuitBreaker opens
//       after N consecutive failures and fast-fails for cooldown period.
// ══════════════════════════════════════════════════════════════════════════

class CircuitBreaker {
  constructor(name, { failureThreshold = 5, cooldownMs = 60_000 } = {}) {
    this.name             = name;
    this.failureThreshold = failureThreshold;
    this.cooldownMs       = cooldownMs;
    this.failures         = 0;
    this.state            = "CLOSED"; // CLOSED | OPEN | HALF-OPEN
    this.lastFailureAt    = null;
  }
  async call(fn) {
    if (this.state === "OPEN") {
      if (Date.now() - this.lastFailureAt > this.cooldownMs) {
        this.state = "HALF-OPEN";
      } else {
        metrics.incr("circuit_breaker.rejected", { name: this.name });
        return null; // fast-fail
      }
    }
    try {
      const result = await fn();
      if (this.state === "HALF-OPEN") {
        this.state    = "CLOSED";
        this.failures = 0;
      }
      return result;
    } catch (err) {
      this.failures++;
      this.lastFailureAt = Date.now();
      if (this.failures >= this.failureThreshold) {
        this.state = "OPEN";
        console.warn(`  ⚡ CircuitBreaker [${this.name}] OPEN after ${this.failures} failures`);
        metrics.incr("circuit_breaker.opened", { name: this.name });
      }
      return null;
    }
  }
}

// ══════════════════════════════════════════════════════════════════════════
//  §5  HTTP CLIENT  (retry + jitter + circuit breaker per source)
//  GAP: v7 had a single axios instance with no retries.
//       Transient 429/503 from NVD or GHSA caused silent null returns.
// ══════════════════════════════════════════════════════════════════════════

const breakers = {
  nvd:    new CircuitBreaker("NVD",    { failureThreshold: 3, cooldownMs: 30_000 }),
  osv:    new CircuitBreaker("OSV",    { failureThreshold: 5, cooldownMs: 20_000 }),
  ghsa:   new CircuitBreaker("GHSA",   { failureThreshold: 5, cooldownMs: 30_000 }),
  epss:   new CircuitBreaker("EPSS",   { failureThreshold: 3, cooldownMs: 60_000 }),
  kev:    new CircuitBreaker("KEV",    { failureThreshold: 2, cooldownMs: 120_000 }),
  redhat: new CircuitBreaker("RedHat", { failureThreshold: 4, cooldownMs: 30_000 }),
  ubuntu: new CircuitBreaker("Ubuntu", { failureThreshold: 4, cooldownMs: 30_000 }),
};

const httpClient = axios.create({
  httpsAgent: new https.Agent({ rejectUnauthorized: false }),
  timeout:    22_000,
  headers:    { "User-Agent": "cve-platform/8.0 (security-scanner)", Accept: "application/json, */*" },
});

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function fetchWithRetry(url, opts = {}, breakerName = null) {
  const { extraHeaders = {}, maxRetries = 3, breakerOverride } = opts;
  const breaker = breakerOverride || (breakerName ? breakers[breakerName] : null);

  const doFetch = async () => {
    await rateLimiter.throttle(url);
    const t0 = Date.now();
    try {
      const res = await httpClient.get(url, {
        headers: { ...httpClient.defaults.headers, ...extraHeaders },
        responseType: "arraybuffer",
        validateStatus: () => true,
      });
      metrics.observe("http.latency_ms", Date.now() - t0, { domain: new URL(url).hostname });
      if (res.status === 429) {
        const retryAfter = parseInt(res.headers["retry-after"] || "10", 10);
        await sleep(retryAfter * 1_000);
        throw new Error("Rate limited (429)");
      }
      if (res.status >= 500) throw new Error(`Server error ${res.status}`);
      if (res.status >= 400) return null; // 404 etc – not an error
      const body = Buffer.from(res.data).toString("utf8");
      metrics.incr("http.success", { domain: new URL(url).hostname });
      return body;
    } catch (err) {
      metrics.incr("http.error", { domain: new URL(url).hostname, message: err.message.slice(0, 40) });
      throw err;
    }
  };

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const fn   = breaker ? () => breaker.call(doFetch) : doFetch;
      const body = await fn();
      return body;
    } catch (err) {
      if (attempt === maxRetries - 1) return null;
      const jitter = Math.random() * 1_000;
      await sleep(Math.pow(2, attempt) * 1_000 + jitter); // exponential backoff + jitter
    }
  }
  return null;
}

async function fetchJSON(url, opts = {}, breakerName = null) {
  const body = await fetchWithRetry(url, opts, breakerName);
  if (!body) return null;
  try { return JSON.parse(body); } catch { return null; }
}

async function fetchText(url, opts = {}, breakerName = null) {
  return fetchWithRetry(url, opts, breakerName);
}

// ══════════════════════════════════════════════════════════════════════════
//  §6  SHARED MEMORY MANAGER  (Redis-first, in-memory fallback)
//  Improvements over v7:
//  - Redis pipeline for batch ops
//  - Namespaced key schema
//  - Stampede protection via in-flight dedup
//  - TTL strategy varies by data freshness characteristics
// ══════════════════════════════════════════════════════════════════════════

/**
 * KEY SCHEMA
 * ──────────────────────────────────────────────────────────────────
 * cve-platform:{env}:cve:{source}:{cveId}           → raw API data     TTL 24h
 * cve-platform:{env}:epss:batch:{date}               → bulk EPSS dump  TTL 12h
 * cve-platform:{env}:kev:catalog                     → CISA KEV set    TTL  6h
 * cve-platform:{env}:exploit:{cveId}                 → bool            TTL 12h
 * cve-platform:{env}:risk:{cveId}:{assetHash}        → risk result     TTL  1h
 * cve-platform:{env}:meta:scan:{scanId}              → scan metadata   TTL 72h
 *
 * INVALIDATION STRATEGY
 * ──────────────────────────────────────────────────────────────────
 * NVD / OSV / GHSA data: 24h TTL (they publish advisories in batches)
 * EPSS: 12h TTL (updated daily by FIRST)
 * KEV catalog: 6h TTL (CISA updates within hours of disclosure)
 * Risk scores: 1h TTL (asset context changes frequently)
 *
 * DEDUPLICATION / CONCURRENCY
 * ──────────────────────────────────────────────────────────────────
 * inFlight Map holds Promise<T> – concurrent callers for the same key
 * await the same Promise, avoiding N duplicate API calls.
 */

const ENV = process.env.NODE_ENV || "prod";

class SharedMemory {
  constructor() {
    this._inFlight = new Map();
    this._local    = new Map();  // { value, expiresAt }
    if (Redis && process.env.REDIS_URL) {
      this._redis = new Redis(process.env.REDIS_URL, {
        keyPrefix:         `cve-platform:${ENV}:`,
        maxRetriesPerRequest: 3,
        lazyConnect:       true,
      });
      this._redis.connect().catch(() => { this._redis = null; });
    }
  }

  _key(...parts) { return parts.join(":"); }

  async get(key) {
    // 1) in-flight dedup
    if (this._inFlight.has(key)) return this._inFlight.get(key);
    // 2) local cache
    const local = this._local.get(key);
    if (local && local.expiresAt > Date.now()) {
      metrics.incr("cache.hit", { tier: "local" });
      return local.value;
    }
    // 3) Redis
    if (this._redis) {
      try {
        const raw = await this._redis.get(key);
        if (raw) {
          metrics.incr("cache.hit", { tier: "redis" });
          const v = JSON.parse(raw);
          this._local.set(key, { value: v, expiresAt: Date.now() + 60_000 }); // L1 cache 1m
          return v;
        }
      } catch { /* Redis hiccup – fall through */ }
    }
    metrics.incr("cache.miss");
    return null;
  }

  async set(key, value, ttlSec = 86_400) {
    this._local.set(key, { value, expiresAt: Date.now() + Math.min(ttlSec, 60) * 1_000 });
    if (this._redis) {
      try { await this._redis.setex(key, ttlSec, JSON.stringify(value)); } catch { /* ignore */ }
    }
  }

  /**
   * Stampede-protected fetch.
   * If two workers both miss cache for the same CVE, only ONE fires the network call;
   * the other awaits the same Promise.
   */
  async getOrFetch(key, fetchFn, ttlSec = 86_400) {
    const cached = await this.get(key);
    if (cached !== null) return cached;
    if (this._inFlight.has(key)) return this._inFlight.get(key);
    const promise = (async () => {
      try {
        const v = await fetchFn();
        if (v !== null && v !== undefined) await this.set(key, v, ttlSec);
        return v ?? null;
      } finally {
        this._inFlight.delete(key);
      }
    })();
    this._inFlight.set(key, promise);
    return promise;
  }

  async mget(keys) {
    // Try Redis pipeline for batch reads
    if (this._redis) {
      try {
        const pipeline = this._redis.pipeline();
        keys.forEach(k => pipeline.get(k));
        const results = await pipeline.exec();
        return results.map(([err, val]) => {
          if (err || !val) return null;
          try { return JSON.parse(val); } catch { return null; }
        });
      } catch { /* fallback */ }
    }
    return Promise.all(keys.map(k => this.get(k)));
  }

  async close() {
    if (this._redis) await this._redis.quit().catch(() => {});
  }
}

// ══════════════════════════════════════════════════════════════════════════
//  §7  EVENT BUS  (in-process; swap for Redis Streams / Kafka adapter)
//  GAP: v7 agents were tightly coupled via direct method calls.
//       EventBus decouples them: Agent A emits "cve.resolved",
//       Agents B & C react independently.
//
//  To scale horizontally, replace EventBus with:
//    Redis Streams:  client.xadd / client.xread
//    Kafka:          kafkajs producer/consumer
//  The agent classes stay unchanged.
// ══════════════════════════════════════════════════════════════════════════

class EventBus extends EventEmitter {
  constructor() {
    super();
    this.setMaxListeners(50);
  }
  publish(event, payload) {
    metrics.incr("event.published", { event });
    process.nextTick(() => this.emit(event, payload));
  }
  subscribe(event, handler) {
    this.on(event, async (payload) => {
      try { await handler(payload); }
      catch (err) { console.error(`  ✗ Handler error [${event}]:`, err.message); }
    });
  }
}

// ══════════════════════════════════════════════════════════════════════════
//  §8  WORKER POOL
//  GAP: v7 analyzed one CVE at a time. At 50 GB+ scan output with
//       thousands of unique CVEs, you need controlled concurrency.
// ══════════════════════════════════════════════════════════════════════════

class WorkerPool {
  constructor(concurrency = CONCURRENCY) {
    this._concurrency = concurrency;
    this._running     = 0;
    this._queue       = [];
  }
  async run(fn) {
    return new Promise((resolve, reject) => {
      this._queue.push({ fn, resolve, reject });
      this._drain();
    });
  }
  _drain() {
    while (this._running < this._concurrency && this._queue.length) {
      const { fn, resolve, reject } = this._queue.shift();
      this._running++;
      Promise.resolve().then(fn).then(resolve, reject).finally(() => {
        this._running--;
        this._drain();
      });
    }
  }
  get queueDepth()   { return this._queue.length; }
  get activeWorkers() { return this._running; }
}

// ══════════════════════════════════════════════════════════════════════════
//  §9  DATA FETCHERS (enriched vs v7)
// ══════════════════════════════════════════════════════════════════════════

function isValidVersion(v) {
  return !!(v && typeof v === "string" && VERSION_RE.test(v.trim()));
}
function cleanVersions(arr) {
  return [...new Set((arr || []).filter(v => isValidVersion(v?.trim?.())).map(v => v.trim()))];
}
function extractCWEs(text = "") {
  const ids = new Set();
  let m;
  while ((m = CWE_RE.exec(text)) !== null) ids.add(m[1]);
  return [...ids].map(id => ({ id: `CWE-${id}`, name: CWE_MAP[id] || "Unknown Weakness" }));
}

// ─── NVD ──────────────────────────────────────────────────────────────────
async function fetchNVD(cveId) {
  if (!/^CVE-/i.test(cveId)) return null;
  const headers = {};
  if (process.env.NVD_API_KEY) headers.apiKey = process.env.NVD_API_KEY;
  const raw = await fetchJSON(`${API.NVD_CVE}?cveId=${cveId}`, { extraHeaders: headers }, "nvd");
  const cve  = raw?.vulnerabilities?.[0]?.cve;
  if (!cve) return null;

  const descEn = cve.descriptions?.find(d => d.lang === "en")?.value || "";
  const result = {
    id:             cve.id,
    published:      cve.published,
    last_modified:  cve.lastModified,
    descriptions:   Object.fromEntries((cve.descriptions || []).map(d => [d.lang, d.value])),
    cwes:           extractCWEs(descEn),
    cvss:           {},
    configurations: [],
    fixed_versions: [],
    references:     (cve.references || []).map(r => r.url),
    vulnerable_files: [],
  };

  // Multi-version CVSS  (v2, v3.0, v3.1, v4.0)
  const metricsMap = {
    cvssMetricV2:  "v2",
    cvssMetricV30: "v3.0",
    cvssMetricV31: "v3.1",
    cvssMetricV40: "v4.0",
  };
  for (const [field, label] of Object.entries(metricsMap)) {
    const m = cve.metrics?.[field]?.[0];
    if (m) result.cvss[label] = { score: m.cvssData?.baseScore, vector: m.cvssData?.vectorString, severity: m.baseSeverity };
  }

  // CPE → fixed versions
  for (const config of cve.configurations || []) {
    for (const node of config.nodes || []) {
      for (const cpe of node.cpeMatch || []) {
        result.configurations.push({ cpe: cpe.criteria, vulnerable: cpe.vulnerable });
        if (cpe.vulnerable && cpe.versionEndExcluding) result.fixed_versions.push(cpe.versionEndExcluding);
        if (cpe.vulnerable && cpe.versionEndIncluding) result.fixed_versions.push(cpe.versionEndIncluding);
      }
    }
  }
  result.fixed_versions   = cleanVersions(result.fixed_versions);
  result.vulnerable_files = extractFilePaths(descEn);
  return result;
}

// ─── OSV ──────────────────────────────────────────────────────────────────
async function fetchOSV(cveId) {
  const raw = await fetchJSON(`${API.OSV_VULNS}/${cveId}`, {}, "osv");
  if (!raw) return null;
  const combinedText = `${raw.summary || ""} ${raw.details || ""}`;
  const result = {
    id:               raw.id,
    summary:          raw.summary || "",
    details:          raw.details || "",
    cwes:             extractCWEs(combinedText),
    fixed_versions:   [],
    fixed_commits:    [],
    affected_packages: [],
    references:       (raw.references || []).map(r => r.url),
    vulnerable_files: extractFilePaths(combinedText),
  };
  for (const a of raw.affected || []) {
    result.affected_packages.push({
      name:      a.package?.name,
      ecosystem: a.package?.ecosystem,
      versions:  a.versions,
      severity:  a.severity,
    });
    for (const r of a.ranges || []) {
      for (const e of r.events || []) {
        if (e.fixed) {
          if (r.type === "GIT") result.fixed_commits.push(e.fixed);
          else if (isValidVersion(e.fixed)) result.fixed_versions.push(e.fixed);
        }
      }
    }
  }
  result.fixed_versions = cleanVersions(result.fixed_versions);
  result.fixed_commits  = [...new Set(result.fixed_commits)].slice(0, 5);
  return result;
}

// ─── GHSA ─────────────────────────────────────────────────────────────────
async function fetchGHSA(id) {
  const isCve     = /^CVE-/i.test(id);
  const headers   = { Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" };
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  const url = isCve
    ? `${API.GHSA_REST}?cve_id=${id}&per_page=1`
    : `${API.GHSA_REST}/${id.toUpperCase()}`;
  const raw  = await fetchJSON(url, { extraHeaders: headers }, "ghsa");
  const ghsa = Array.isArray(raw) ? raw[0] : raw;
  if (!ghsa) return null;

  const combinedText = `${ghsa.summary || ""} ${ghsa.description || ""}`;
  const result = {
    ghsa_id:         ghsa.ghsa_id,
    cve_id:          ghsa.cve_id,
    summary:         ghsa.summary,
    description:     ghsa.description,
    severity:        ghsa.severity,
    cvss:            ghsa.cvss ? { score: ghsa.cvss.score, vector: ghsa.cvss.vector_string } : null,
    cwes:            extractCWEs(combinedText),
    fixed_versions:  [],
    vulnerable_files: extractFilePaths(combinedText),
    references:      (ghsa.references || []).map(r => r.url || r),
  };
  for (const v of ghsa.vulnerabilities || []) {
    if (v.first_patched_version) result.fixed_versions.push(v.first_patched_version);
  }
  result.fixed_versions = cleanVersions(result.fixed_versions);
  return result;
}

// ─── Red Hat ──────────────────────────────────────────────────────────────
async function fetchRedHat(cveId) {
  if (!/^CVE-/i.test(cveId)) return null;
  const [json, html] = await Promise.all([
    fetchJSON(`${API.REDHAT_JSON}${cveId}.json`, {}, "redhat"),
    fetchText(`https://access.redhat.com/security/cve/${cveId}`, {}, "redhat"),
  ]);
  const result = {
    cve_id:           cveId,
    severity:         json?.severity,
    mitigation:       json?.mitigation,
    affected_releases: [],
    advisories:       [],
    fixed_versions:   [],
    cvss:             json?.cvss3?.cvss3_base_score ? { score: parseFloat(json.cvss3.cvss3_base_score), vector: json.cvss3.cvss3_scoring_vector } : null,
  };
  for (const rel of json?.affected_release || []) {
    result.affected_releases.push({ product: rel.product_name, advisory: rel.advisory, package: rel.package });
    if (rel.advisory) result.advisories.push(rel.advisory);
    if (rel.package) {
      const m = rel.package.match(/[-_](\d+\.\d+(?:\.\d+)?)/);
      if (m && isValidVersion(m[1])) result.fixed_versions.push(m[1]);
    }
  }
  if (html) {
    (html.match(RHSA_RE) || []).forEach(r => result.advisories.push(r));
    result.advisories = [...new Set(result.advisories)];
  }
  result.fixed_versions = cleanVersions(result.fixed_versions);
  return result;
}

// ─── Ubuntu ───────────────────────────────────────────────────────────────
async function fetchUbuntu(cveId) {
  if (!/^CVE-/i.test(cveId)) return null;
  const raw = await fetchJSON(`${API.UBUNTU_CVE}/${cveId}.json`, {}, "ubuntu");
  if (!raw) return null;
  const result = { cve_id: raw.id, description: raw.description, priority: raw.priority, packages: [], fixed_versions: [] };
  for (const pkg of raw.packages || []) {
    const pkgInfo = { name: pkg.name, releases: [] };
    for (const [release, info] of Object.entries(pkg.statuses || {})) {
      pkgInfo.releases.push({ release, status: info.status, fixed_version: info.fixed_version });
      if (info.fixed_version && isValidVersion(info.fixed_version)) result.fixed_versions.push(info.fixed_version);
    }
    result.packages.push(pkgInfo);
  }
  result.fixed_versions = cleanVersions(result.fixed_versions);
  return result;
}

// ─── File path extraction helper ──────────────────────────────────────────
function extractFilePaths(text = "") {
  const paths = new Set();
  (text.match(FILE_PATH_RE) || []).forEach(p => paths.add(p));
  const blobRe = /github\.com\/[^\/]+\/[^\/]+\/blob\/[^\/]+\/([^#\s"'<>]+)/gi;
  let m;
  while ((m = blobRe.exec(text)) !== null) paths.add("/" + m[1]);
  return [...paths].filter(p => p.length < 200 && p.includes("/")).map(p => ({
    file_path: p,
    confidence: p.includes("src/") || p.endsWith(".java") || p.endsWith(".go") ? 0.9 : 0.7,
  }));
}

// ══════════════════════════════════════════════════════════════════════════
//  §10  NEW FEED: CISA KEV  (Known Exploited Vulnerabilities catalog)
//  GAP: v7 had a hardcoded list of 4 CVEs as "known exploits".
//       CISA publishes a machine-readable catalog of 1000+ CVEs with
//       confirmed exploitation in the wild. This is the authoritative source.
//       Every security platform must ingest this.
// ══════════════════════════════════════════════════════════════════════════

class KEVCatalog {
  constructor(memory) {
    this._memory     = memory;
    this._localCache = null;
    this._localExpiry = 0;
  }

  async _load() {
    if (this._localCache && this._localExpiry > Date.now()) return this._localCache;
    const CACHE_KEY = "kev:catalog";
    const cached    = await this._memory.get(CACHE_KEY);
    if (cached) { this._localCache = cached; this._localExpiry = Date.now() + 60_000; return cached; }

    const raw = await fetchJSON(API.CISA_KEV, {}, "kev");
    if (!raw?.vulnerabilities) return new Set();

    const kevSet = new Set(raw.vulnerabilities.map(v => v.cveID));
    const kevMeta = Object.fromEntries(raw.vulnerabilities.map(v => [v.cveID, {
      vendor:        v.vendorProject,
      product:       v.product,
      name:          v.vulnerabilityName,
      date_added:    v.dateAdded,
      due_date:      v.dueDate,
      ransomware:    v.knownRansomwareCampaignUse === "Known",
    }]));

    const catalog = { set: [...kevSet], meta: kevMeta, total: kevSet.size, loaded_at: new Date().toISOString() };
    await this._memory.set(CACHE_KEY, catalog, 21_600); // 6h
    this._localCache  = catalog;
    this._localExpiry = Date.now() + 60_000;
    console.log(`  [KEV] Loaded ${catalog.total} known-exploited CVEs from CISA`);
    return catalog;
  }

  async isKnownExploited(cveId) {
    const catalog = await this._load();
    return { exploited: catalog.set?.includes(cveId) || false, meta: catalog.meta?.[cveId] || null };
  }
}

// ══════════════════════════════════════════════════════════════════════════
//  §11  BATCH EPSS FETCHER
//  GAP: v7 fetched EPSS one CVE at a time. EPSS API supports up to 100
//       CVEs per request. At scale this is a 100x performance improvement.
// ══════════════════════════════════════════════════════════════════════════

class BatchEPSS {
  constructor(memory) { this._memory = memory; }

  async fetch(cveIds) {
    const result   = {};
    const toFetch  = [];

    // Check cache first (batch mget)
    const keys     = cveIds.map(id => `epss:${id}`);
    const cached   = await this._memory.mget(keys);
    for (let i = 0; i < cveIds.length; i++) {
      if (cached[i] !== null) result[cveIds[i]] = cached[i];
      else toFetch.push(cveIds[i]);
    }

    if (!toFetch.length) return result;

    // Batch API call (up to 100 per request)
    for (let i = 0; i < toFetch.length; i += 100) {
      const chunk = toFetch.slice(i, i + 100);
      const url   = `${API.EPSS_API}?cve=${chunk.join(",")}&envelope=true`;
      const raw   = await fetchJSON(url, {}, "epss");
      for (const item of raw?.data || []) {
        const score       = parseFloat(item.epss);
        result[item.cve]  = { score, percentile: parseFloat(item.percentile) };
        await this._memory.set(`epss:${item.cve}`, { score, percentile: parseFloat(item.percentile) }, 43_200);
      }
    }
    // Default for any still missing
    for (const id of toFetch) {
      if (!result[id]) result[id] = { score: 0.01, percentile: 0 };
    }
    return result;
  }
}

// ══════════════════════════════════════════════════════════════════════════
//  §12  PATCH/COMMIT ANALYSIS AGENT
//  GAP: v7 hardcoded "apache/logging-log4j2" in commit URL construction.
//       We now resolve the canonical repo from OSV affected[].ranges.
// ══════════════════════════════════════════════════════════════════════════

class CommitAnalyzer {
  async analyzeCommit(commitUrl) {
    const m = commitUrl.match(GHCOMMIT_RE);
    if (!m) return null;
    const [, owner, repo, sha] = m;
    const headers = {};
    if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
    const diffText = await fetchText(
      `https://github.com/${owner}/${repo}/commit/${sha}.diff`,
      { extraHeaders: headers },
      "ghsa"
    );
    if (!diffText) return null;
    return this._parseDiff(diffText, sha, `${owner}/${repo}`);
  }

  _parseDiff(patchText, sha, repo) {
    const removedLines  = [];
    const affectedFiles = new Set();
    const lines         = patchText.split("\n");
    let currentFile     = null;
    let currentLine     = 0;

    for (const line of lines) {
      if (line.startsWith("diff --git")) {
        const m = line.match(/diff --git a\/(.+) b\/(.+)/);
        if (m) { currentFile = m[2]; affectedFiles.add(m[2]); }
        continue;
      }
      if (line.startsWith("@@") && currentFile) {
        const m = line.match(/@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
        if (m) currentLine = parseInt(m[2], 10);
        continue;
      }
      if (line.startsWith("-") && !line.startsWith("---") && currentFile) {
        removedLines.push({ file: currentFile, line: currentLine, code: line.slice(1, 150) });
      }
      if (!line.startsWith("-") && !line.startsWith("@@") && !line.startsWith("diff") && !line.startsWith("---") && !line.startsWith("+++")) {
        currentLine++;
      }
    }
    return { sha, repo, url: `https://github.com/${repo}/commit/${sha}`, removed_lines: removedLines, affected_files: [...affectedFiles] };
  }
}

// ══════════════════════════════════════════════════════════════════════════
//  §13  VEX DOCUMENT GENERATOR
//  GAP: v7 had no false-positive suppression. Without VEX, every CVE
//       associated with a package you ship triggers an alert, even if
//       the vulnerable code path is not reachable. VEX (CSAF/CycloneDX)
//       is the industry standard for stating "CVE-X does NOT affect us
//       because reason Y." Tools like Grype and Trivy consume VEX files.
// ══════════════════════════════════════════════════════════════════════════

function generateVEX(cveId, identity, assetContext) {
  const statement = {
    "@context":  "https://openvex.dev/ns/v0.2.0",
    "@id":       `https://your-org.com/vex/${cveId}/${Date.now()}`,
    author:      "CVE Platform v8 (automated)",
    timestamp:   new Date().toISOString(),
    version:     1,
    statements: [{
      vulnerability: { "@id": `https://nvd.nist.gov/vuln/detail/${cveId}`, name: cveId },
      products:      assetContext?.products || [],
      status:        assetContext?.packages?.some(p =>
        identity.affected_packages?.some(ap => ap.name?.includes(p.name))
      ) ? "affected" : "not_affected",
      justification: "vulnerable_code_not_in_execute_path",
      impact_statement: `Automated analysis by CVE Platform v8. Asset context: ${JSON.stringify(assetContext?.tags || [])}`,
    }],
  };
  return statement;
}

// ══════════════════════════════════════════════════════════════════════════
//  §14  AGENTS  A · B · C
// ══════════════════════════════════════════════════════════════════════════

// ─── Agent A: Identity Resolution ─────────────────────────────────────────
class IdentityAgent {
  constructor(memory, bus) { this._m = memory; this._bus = bus; }

  async resolve(cveId) {
    console.log(`  [A: Identity] Resolving ${cveId}`);
    const [nvd, osv, ghsa] = await Promise.all([
      this._m.getOrFetch(this._m._key("cve", "nvd", cveId),  () => fetchNVD(cveId),   86_400),
      this._m.getOrFetch(this._m._key("cve", "osv", cveId),  () => fetchOSV(cveId),   86_400),
      this._m.getOrFetch(this._m._key("cve", "ghsa", cveId), () => fetchGHSA(cveId),  86_400),
    ]);

    // Merge CVSS: prefer highest-version
    const cvss = nvd?.cvss?.["v3.1"] || nvd?.cvss?.["v3.0"] || nvd?.cvss?.["v4.0"] || ghsa?.cvss || null;
    const cvss_score = cvss?.score || null;

    // Merge CWEs (deduplicate by id)
    const cweMerged = new Map();
    for (const c of [...(nvd?.cwes || []), ...(osv?.cwes || []), ...(ghsa?.cwes || [])]) cweMerged.set(c.id, c);

    // Merge fixed versions (all sources, deduplicated)
    const allFixed = [...new Set([
      ...(osv?.fixed_versions  || []),
      ...(nvd?.fixed_versions  || []),
      ...(ghsa?.fixed_versions || []),
    ])];

    const identity = {
      id:               cveId,
      published:        nvd?.published,
      last_modified:    nvd?.last_modified,
      summary:          osv?.summary || ghsa?.summary || nvd?.descriptions?.en?.slice(0, 300) || "",
      severity:         (ghsa?.severity || "UNKNOWN").toUpperCase(),
      cvss_score,
      cvss_detail:      cvss,
      cwes:             [...cweMerged.values()],
      fixed_versions:   allFixed,
      fixed_commits:    osv?.fixed_commits || [],
      affected_packages: osv?.affected_packages || [],
      vulnerable_files: [
        ...(osv?.vulnerable_files  || []),
        ...(nvd?.vulnerable_files  || []),
        ...(ghsa?.vulnerable_files || []),
      ],
      references: [...new Set([
        ...(nvd?.references  || []),
        ...(osv?.references  || []),
        ...(ghsa?.references || []),
      ])].slice(0, 20),
      _raw: { nvd, osv, ghsa },
    };

    this._bus.publish("cve.resolved", { cveId, identity });
    metrics.incr("agent.identity.resolved");
    return identity;
  }
}

// ─── Agent B: Deep Patch Analysis ─────────────────────────────────────────
class DeepAnalysisAgent {
  constructor(memory, bus) { this._m = memory; this._bus = bus; this._commitAnalyzer = new CommitAnalyzer(); }

  async analyze(cveId, identity) {
    console.log(`  [B: DeepAnalysis] Analyzing patches for ${cveId} (${identity.fixed_commits.length} commits)`);

    // Resolve commit URLs from OSV ranges (correct repo, not hardcoded)
    const commitUrls = identity.fixed_commits.map(sha => {
      // Try to infer repo from OSV affected[].ranges
      const range = identity._raw?.osv?.affected
        ?.flatMap(a => a.ranges || [])
        .find(r => r.type === "GIT" && r.repo);
      const repo  = range?.repo || null;
      if (repo) {
        const clean = repo.replace(/\.git$/, "").replace("https://", "");
        return `https://${clean}/commit/${sha}`;
      }
      return null; // cannot determine repo without hints
    }).filter(Boolean);

    const commitResults = [];
    for (const url of commitUrls.slice(0, 3)) {
      const info = await this._commitAnalyzer.analyzeCommit(url);
      if (info) commitResults.push(info);
      await sleep(300);
    }

    const analysis = {
      commits:          commitResults,
      total_files_changed: [...new Set(commitResults.flatMap(c => c.affected_files))].length,
      vulnerable_code_patterns: commitResults.flatMap(c => c.removed_lines).slice(0, 20),
    };

    this._bus.publish("cve.analyzed", { cveId, analysis });
    metrics.incr("agent.analysis.completed");
    return analysis;
  }
}

// ─── Agent C: Contextual Risk ──────────────────────────────────────────────
class ContextualRiskAgent {
  constructor(memory, bus, kev, epss) {
    this._m    = memory;
    this._bus  = bus;
    this._kev  = kev;
    this._epss = epss;
  }

  async calculateRisk(cveId, identity, assetContext) {
    console.log(`  [C: Risk] Scoring ${cveId}`);
    const [epssData, kevInfo] = await Promise.all([
      this._epss.fetch([cveId]).then(r => r[cveId]),
      this._kev.isKnownExploited(cveId),
    ]);

    const cvssBase         = identity.cvss_score || 5.0;
    const epssScore        = epssData?.score || 0.01;
    const epssPercentile   = epssData?.percentile || 0;
    const exploited        = kevInfo.exploited;
    const ransomware       = kevInfo.meta?.ransomware || false;

    // Asset criticality
    const isInternetFacing = assetContext?.isInternetFacing || false;
    const isProduction     = assetContext?.isProduction || false;
    const assetCriticality = 0.5 + (isProduction ? 0.25 : 0) + (isInternetFacing ? 0.25 : 0); // 0.5–1.0

    // Reachability: is a vulnerable package actually present?
    const reachable = assetContext?.packages?.some(pkg =>
      identity.affected_packages?.some(ap => ap.name && pkg.name && ap.name.toLowerCase().includes(pkg.name.toLowerCase()))
    ) ? 1.0 : 0.3;

    // Weighted risk score
    const riskScore = Math.min(10, Math.max(0,
      cvssBase             * 0.25 +
      epssScore * 10       * 0.20 +
      (exploited ? 10 : 0) * 0.25 +
      assetCriticality * 10 * 0.20 +
      reachable * 10       * 0.10
    ));

    const priority = riskScore >= 9 ? "CRITICAL"
      : riskScore >= 7 ? "HIGH"
      : riskScore >= 4 ? "MEDIUM"
      : "LOW";

    const risk = {
      risk_score:        Math.round(riskScore * 10) / 10,
      priority,
      fix_available:     identity.fixed_versions.length > 0,
      kev:               kevInfo,
      epss:              { score: epssScore, percentile: epssPercentile },
      ransomware_threat: ransomware,
      components: {
        cvss_base:         cvssBase,
        epss_contribution: epssScore * 10 * 0.20,
        exploit_factor:    exploited ? 10 * 0.25 : 0,
        asset_criticality: assetCriticality * 10 * 0.20,
        reachability:      reachable * 10 * 0.10,
      },
    };

    this._bus.publish("cve.risk.scored", { cveId, risk });
    metrics.incr("agent.risk.scored", { priority });
    return risk;
  }
}

// ══════════════════════════════════════════════════════════════════════════
//  §15  ORCHESTRATOR PIPELINE
//  Flow: Input → A (Identity) → B (Deep Analysis) ─┐
//                             └──────────────────── C (Risk) → Output
// ══════════════════════════════════════════════════════════════════════════

class Platform {
  constructor() {
    this._memory = new SharedMemory();
    this._bus    = new EventBus();
    this._kev    = new KEVCatalog(this._memory);
    this._epss   = new BatchEPSS(this._memory);
    this._pool   = new WorkerPool(CONCURRENCY);

    this._agents = {
      identity: new IdentityAgent(this._memory, this._bus),
      analysis: new DeepAnalysisAgent(this._memory, this._bus),
      risk:     new ContextualRiskAgent(this._memory, this._bus, this._kev, this._epss),
    };

    // Wire event-driven listeners for logging/auditing
    this._bus.subscribe("cve.resolved",    ({ cveId }) => metrics.incr("pipeline.stage", { stage: "resolved",  cveId }));
    this._bus.subscribe("cve.analyzed",    ({ cveId }) => metrics.incr("pipeline.stage", { stage: "analyzed",  cveId }));
    this._bus.subscribe("cve.risk.scored", ({ cveId }) => metrics.incr("pipeline.stage", { stage: "scored",    cveId }));
  }

  /**
   * Analyze a single CVE through the full pipeline.
   */
  async analyzeCVE(cveId, assetContext = {}) {
    return this._pool.run(async () => {
      const t0 = Date.now();
      try {
        const identity = await this._agents.identity.resolve(cveId);
        // Run deep analysis and risk in parallel where possible
        const [analysis, risk] = await Promise.all([
          this._agents.analysis.analyze(cveId, identity),
          this._agents.risk.calculateRisk(cveId, identity, assetContext),
        ]);
        const vex        = generateVEX(cveId, identity, assetContext);
        const remediation = buildRemediation(identity, risk);
        const duration   = Date.now() - t0;
        metrics.observe("pipeline.duration_ms", duration);
        return {
          meta: { cve_id: cveId, analyzed_at: new Date().toISOString(), duration_ms: duration },
          identity,
          analysis,
          risk,
          remediation,
          vex,
        };
      } catch (err) {
        metrics.incr("pipeline.error");
        throw err;
      }
    });
  }

  /**
   * Analyze many CVEs in parallel, respecting worker pool limits.
   */
  async analyzeBatch(cveIds, assetContext = {}) {
    console.log(`\n[Platform] Batch analyzing ${cveIds.length} CVEs (concurrency=${CONCURRENCY})`);
    // Pre-warm EPSS cache for all CVEs in one call
    await this._epss.fetch(cveIds);
    const results = await Promise.all(cveIds.map(id => this.analyzeCVE(id, assetContext).catch(err => ({ error: err.message, cve_id: id }))));
    return results;
  }

  async shutdown() { await this._memory.close(); }
}

// ══════════════════════════════════════════════════════════════════════════
//  §16  REMEDIATION BUILDER
// ══════════════════════════════════════════════════════════════════════════

function buildRemediation(identity, risk) {
  const steps = [];

  if (risk.kev.exploited) {
    steps.push({
      priority: "IMMEDIATE",
      title:    "⚠️  Actively Exploited – Patch within 24h (CISA KEV)",
      kev_meta: risk.kev.meta,
    });
  }

  if (identity.fixed_versions.length) {
    steps.push({
      priority:       "PATCH",
      title:          "Upgrade to Fixed Version",
      fixed_versions: identity.fixed_versions,
      commands: {
        rhel:   `dnf update -y && rpm -q --changelog $(rpm -qa | grep -i "${identity.affected_packages?.[0]?.name || ""}") | grep -i "${identity.id}"`,
        debian: `apt-get update && apt-get upgrade -y`,
        npm:    identity.affected_packages?.[0]?.name ? `npm audit fix --force` : null,
        maven:  identity.cwes?.length ? `mvn dependency:tree | grep -i "${identity.affected_packages?.[0]?.name || ""}"` : null,
      },
    });
  }

  if (identity.cwes.length) {
    steps.push({
      priority: "MITIGATE",
      title:    "Weakness Class Mitigations",
      cwes:     identity.cwes,
      guidance: identity.cwes.map(c => cweGuidance(c.id)).filter(Boolean),
    });
  }

  steps.push({
    priority: "VERIFY",
    title:    "Verification Commands",
    commands: [
      `rpm -qa --changelog | grep -i "${identity.id}" || true`,
      `apt-cache show $(dpkg -l | awk 'NR>5{print $2}') 2>/dev/null | grep -A5 "${identity.id}" || true`,
      `npm audit --json | jq '.vulnerabilities | to_entries[] | select(.value.name | test("${identity.affected_packages?.[0]?.name || ""}"))' 2>/dev/null || true`,
    ],
  });

  return { risk_priority: risk.priority, steps };
}

function cweGuidance(cweId) {
  const map = {
    "CWE-79":   "Apply Content Security Policy headers and encode output in all contexts",
    "CWE-89":   "Use parameterized queries / prepared statements exclusively",
    "CWE-94":   "Disable or sandbox user-controlled code execution. Validate all input strictly",
    "CWE-502":  "Disable Java deserialization entirely if possible; use allowlist-based deserialization filters",
    "CWE-611":  "Disable external entity processing in XML parsers",
    "CWE-918":  "Enforce strict allowlist for outbound connections; block RFC1918 ranges",
    "CWE-22":   "Canonicalize paths and validate against a base directory",
    "CWE-400":  "Implement rate limiting, request size limits, and timeout enforcement",
    "CWE-78":   "Avoid shell execution with user-supplied input; use execve with arg arrays",
    "CWE-1321": "Freeze Object.prototype; use Object.create(null) for dictionaries",
  };
  return map[cweId] || null;
}

// ══════════════════════════════════════════════════════════════════════════
//  §17  OUTPUT FORMATTER
// ══════════════════════════════════════════════════════════════════════════

function printReport(result) {
  const { meta, identity, risk, remediation } = result;
  const line  = "═".repeat(72);
  const title = (s) => `\n  ${s}`;

  console.log(`\n${line}`);
  console.log(`  VULNERABILITY INTELLIGENCE REPORT  –  CVE Platform v8.0`);
  console.log(line);

  console.log(`\n📋 ${meta.cve_id}  (analyzed in ${meta.duration_ms}ms)`);
  console.log(`   ${identity.summary}`);
  console.log(`\n📊 Severity : ${identity.severity}  |  CVSS: ${identity.cvss_score ?? "N/A"}  |  Risk Score: ${risk.risk_score}/10 (${risk.priority})`);
  console.log(`   EPSS     : ${(risk.epss.score * 100).toFixed(2)}%  (top ${(100 - risk.epss.percentile * 100).toFixed(0)}th percentile)`);
  console.log(`   KEV      : ${risk.kev.exploited ? "✅ YES — actively exploited in the wild" : "❌ Not in CISA KEV"}`);
  if (risk.ransomware_threat) console.log(`   ☠️  RANSOMWARE: linked to ransomware campaigns`);

  if (identity.cwes.length) {
    console.log(title("🔗 Weakness Classes:"));
    identity.cwes.forEach(c => console.log(`     ${c.id}  ${c.name}`));
  }

  if (identity.fixed_versions.length) {
    console.log(title("✅ Fixed Versions:  " + identity.fixed_versions.join(", ")));
  } else {
    console.log(title("⚠️  No fixed version identified yet"));
  }

  if (identity.vulnerable_files.length) {
    console.log(title(`📁 Vulnerable file hints (${identity.vulnerable_files.length}):`));
    identity.vulnerable_files.slice(0, 5).forEach(f => console.log(`     ${f.file_path} (confidence ${Math.round(f.confidence * 100)}%)`));
  }

  console.log(title("🔧 Remediation Plan:"));
  for (const s of remediation.steps) console.log(`     [${s.priority}] ${s.title}`);

  console.log(`\n${line}\n`);
}

// ══════════════════════════════════════════════════════════════════════════
//  §18  CLI ENTRY POINT
// ══════════════════════════════════════════════════════════════════════════

(async () => {
  const id = process.argv[2];
  if (!id) {
    console.log(`
╔══════════════════════════════════════════════════════════════════════════╗
║   CVE Intelligence Platform v8.0  –  Multi-Agent Orchestration          ║
╚══════════════════════════════════════════════════════════════════════════╝

Usage:  node cve-platform-v8.js <CVE-ID>  [CVE-ID-2 ...]
        node cve-platform-v8.js CVE-2021-44228
        node cve-platform-v8.js CVE-2021-44228 CVE-2022-22965

Environment:
  NVD_API_KEY   – removes NVD rate cap   (strongly recommended)
  GITHUB_TOKEN  – removes GitHub 60 req/h anon cap
  REDIS_URL     – redis://host:6379       (optional shared cache)
  CONCURRENCY   – parallel worker count   (default: 4)
  SAVE_OUTPUT   – write JSON to disk      (SAVE_OUTPUT=1)
  DEBUG         – verbose stack traces

Architecture:
  Input → Agent A (Identity) → Agent B (Patch Analysis) ──┐
                              └─────────────────────────── Agent C (Risk) → Report + VEX
`);
    process.exit(0);
  }

  const cveIds = process.argv.slice(2).map(s => s.toUpperCase());
  const assetContext = {
    isProduction:    true,
    isInternetFacing: true,
    packages:        [{ name: "log4j-core" }, { name: "spring-webmvc" }],
    products:        ["pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"],
    tags:            ["production", "internet-facing", "k8s-pod"],
  };

  const platform = new Platform();
  try {
    const results = cveIds.length === 1
      ? [await platform.analyzeCVE(cveIds[0], assetContext)]
      : await platform.analyzeBatch(cveIds, assetContext);

    for (const r of results) {
      if (r.error) { console.error(`\n❌ ${r.cve_id}: ${r.error}`); continue; }
      printReport(r);
      if (process.env.SAVE_OUTPUT === "1") {
        const fname = `${r.meta.cve_id}_v8.json`;
        fs.writeFileSync(fname, JSON.stringify(r, null, 2));
        console.log(`💾 Report saved → ${fname}`);
      }
    }

    if (process.env.DEBUG) {
      console.log("\n📈 Metrics Summary:");
      console.log(JSON.stringify(metrics.summary(), null, 2));
    }
  } catch (err) {
    console.error("\n❌ Fatal:", err.message);
    if (process.env.DEBUG) console.error(err.stack);
    process.exit(1);
  } finally {
    await platform.shutdown();
  }
})();