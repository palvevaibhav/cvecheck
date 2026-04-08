#!/usr/bin/env node

/**
 * ════════════════════════════════════════════════════════════════════════
 *  CVE Intelligence Analyzer v7.0 - MULTI-AGENT ORCHESTRATION
 *  
 *  Features:
 *    - Multi-agent architecture (Identity, Deep Analysis, Risk)
 *    - Shared memory with Redis (fallback to in-memory Map)
 *    - File path detection & remediation MOPS
 *    - EPSS & exploit prioritization
 *    - Production-ready caching & rate limiting
 * ════════════════════════════════════════════════════════════════════════
 */

"use strict";

global.File = class File {};
const axios = require("axios");
const https = require("https");
const zlib = require("zlib");
const cheerio = require("cheerio");
const fs = require("fs");
const crypto = require("crypto");

// Try to load Redis (optional)
let Redis;
try {
  Redis = require("ioredis");
} catch (e) {
  console.warn("⚠️  Redis not installed. Using in-memory fallback.");
}

// ════════════════════════════════════════════════════════════════════════
//  SECTION 0 – Configuration & Constants
// ════════════════════════════════════════════════════════════════════════

const TRUSTED_DOMAINS = [
  "github.com", "raw.githubusercontent.com", "api.github.com",
  "git.kernel.org", "nvd.nist.gov", "services.nvd.nist.gov",
  "api.osv.dev", "ubuntu.com", "debian.org", "access.redhat.com",
  "npmjs.com", "registry.npmjs.org",
];

const API = {
  NVD_CVE: "https://services.nvd.nist.gov/rest/json/cves/2.0",
  OSV_VULNS: "https://api.osv.dev/v1/vulns",
  GHSA_REST: "https://api.github.com/advisories",
  REDHAT_JSON: "https://access.redhat.com/hydra/rest/securitydata/cve/",
  REDHAT_PAGE: "https://access.redhat.com/security/cve",
  UBUNTU_CVE: "https://ubuntu.com/security/cves",
  DEBIAN_TRACKER: "https://security-tracker.debian.org/tracker",
  NPM_REGISTRY: "https://registry.npmjs.org/-/npm/v1/security/advisories/search",
  EPSS_API: "https://api.first.org/data/v1/epss",
};

const SCORE = { osv: 1.0, ghsa: 0.95, nvd: 0.9, redhat: 0.85, ubuntu: 0.8, debian: 0.8 };
const VERSION_RE = /^\d+\.\d+(\.\d+)?(-\d+)?$/;
const COMMIT_RE = /\b[0-9a-f]{40}\b/gi;
const GHCOMMIT_RE = /github\.com\/([^/]+)\/([^/]+)\/commit\/([0-9a-f]{40})/i;
const RHSA_RE = /RHSA-\d{4}:\d{4,}/g;
const FILE_PATH_RE = /(?:\/[\w\-.]+)+\.(?:java|js|py|go|rs|c|cpp|h|hpp|xml|properties|yaml|yml|json|sh|rb|php)/gi;
const LINE_NUMBER_RE = /[Ll]ine[s]?\s+(\d+)(?:-(\d+))?/g;

// ════════════════════════════════════════════════════════════════════════
//  SECTION 1 – HTTP & Helpers
// ════════════════════════════════════════════════════════════════════════

const httpClient = axios.create({
  httpsAgent: new https.Agent({ rejectUnauthorized: false }),
  timeout: 20000,
  headers: { "User-Agent": "cve-intel-analyzer/7.0", Accept: "application/json, text/html, */*" },
});

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function fetchRaw(url, extraHeaders = {}) {
  try {
    const res = await httpClient.get(url, {
      headers: { ...httpClient.defaults.headers, ...extraHeaders },
      responseType: "arraybuffer",
      validateStatus: () => true,
    });
    return { status: res.status, data: res.data, headers: res.headers };
  } catch {
    return null;
  }
}

async function fetchJSON(url, extraHeaders = {}) {
  const res = await fetchRaw(url, extraHeaders);
  if (!res || res.status >= 400) return null;
  try {
    return JSON.parse(Buffer.from(res.data).toString("utf8"));
  } catch {
    return null;
  }
}

async function fetchText(url, extraHeaders = {}) {
  const res = await fetchRaw(url, extraHeaders);
  if (!res || res.status >= 400) return null;
  return Buffer.from(res.data).toString("utf8");
}

function isValidVersion(v) {
  return !!(v && typeof v === "string" && VERSION_RE.test(v));
}

function cleanVersions(arr) {
  return [...new Set((arr || []).filter(isValidVersion))];
}

function getCommonPackagePaths(packageName, ecosystem) {
  const paths = {
    java: [`/usr/share/java/${packageName}.jar`, `/opt/${packageName}/lib`, `~/.m2/repository/org/apache/${packageName}`],
    node: [`/usr/lib/node_modules/${packageName}`, `./node_modules/${packageName}`, `~/.npm/lib/node_modules/${packageName}`],
    python: [`/usr/lib/python3*/site-packages/${packageName}`, `./venv/lib/python*/site-packages/${packageName}`],
  };
  if (packageName?.includes("log4j")) return paths.java;
  if (packageName?.includes("express")) return paths.node;
  return paths[ecosystem?.toLowerCase()] || [`/usr/lib/${packageName}`, `/opt/${packageName}`];
}

// ════════════════════════════════════════════════════════════════════════
//  SECTION 2 – Shared Memory Manager (Redis or In-Memory)
// ════════════════════════════════════════════════════════════════════════

class SharedMemoryManager {
  constructor(useRedis = true) {
    this.useRedis = useRedis && Redis;
    this.inFlight = new Map(); // prevent duplicate API calls
    if (this.useRedis) {
      this.redis = new Redis({ host: "localhost", port: 6379, keyPrefix: "cve-agent:" });
      console.log("✅ Connected to Redis");
    } else {
      this.cache = new Map();
      console.log("⚠️  Using in-memory cache (no Redis)");
    }
  }

  _getKey(type, id, version = null) {
    return version ? `${type}:${id}:${version}` : `${type}:${id}`;
  }

  async _get(key) {
    if (this.useRedis) {
      const data = await this.redis.get(key);
      return data ? JSON.parse(data) : null;
    } else {
      const entry = this.cache.get(key);
      if (entry && entry.expiry > Date.now()) return entry.value;
      return null;
    }
  }

  async _set(key, value, ttlSec) {
    if (this.useRedis) {
      await this.redis.setex(key, ttlSec, JSON.stringify(value));
    } else {
      this.cache.set(key, { value, expiry: Date.now() + ttlSec * 1000 });
    }
  }

  async getCVE(cveId, source = "nvd") {
    const key = this._getKey("cve", cveId, source);
    if (this.inFlight.has(key)) return this.inFlight.get(key);
    const cached = await this._get(key);
    if (cached) return cached;
    const promise = this._fetchAndCacheCVE(cveId, source, key);
    this.inFlight.set(key, promise);
    try {
      return await promise;
    } finally {
      this.inFlight.delete(key);
    }
  }

  async _fetchAndCacheCVE(cveId, source, key) {
    let data = null;
    switch (source) {
      case "nvd":
        data = await fetchNVD(cveId);
        break;
      case "osv":
        data = await fetchOSV(cveId);
        break;
      case "ghsa":
        data = await fetchGHSA(cveId);
        break;
    }
    if (data) await this._set(key, data, 86400);
    return data;
  }

  async getEPSS(cveId) {
    const key = `epss:${cveId}`;
    const cached = await this._get(key);
    if (cached !== null) return cached;
    try {
      const url = `${API.EPSS_API}?cve=${cveId}`;
      const res = await fetchJSON(url);
      const score = res?.data?.[0]?.epss || 0.01;
      await this._set(key, score, 43200);
      return score;
    } catch {
      return 0.01;
    }
  }

  async getExploitExists(cveId) {
    const key = `exploit:${cveId}`;
    const cached = await this._get(key);
    if (cached !== null) return cached;
    // Simple check against known exploited CVEs (expandable)
    const knownExploits = ["CVE-2021-44228", "CVE-2022-22965", "CVE-2023-22515"];
    const exists = knownExploits.includes(cveId);
    await this._set(key, exists, 86400);
    return exists;
  }

  async close() {
    if (this.useRedis) await this.redis.quit();
  }
}

// ════════════════════════════════════════════════════════════════════════
//  SECTION 3 – Data Fetchers (OSV, NVD, GHSA, Red Hat, Ubuntu, Debian, NPM)
// ════════════════════════════════════════════════════════════════════════

async function fetchOSV(cveId) {
  const raw = await fetchJSON(`${API.OSV_VULNS}/${cveId}`);
  if (!raw) return null;
  const result = {
    id: raw.id, summary: raw.summary || "", details: raw.details || "",
    fixed_versions: [], fixed_commits: [], affected_packages: [], vulnerable_files: [],
  };
  const finder = new VulnerabilityLocationFinder();
  if (raw.details) result.vulnerable_files = finder.searchAdvisoryForVulnerableFiles(raw.details, "OSV");
  for (const a of raw.affected || []) {
    result.affected_packages.push({ name: a.package?.name, ecosystem: a.package?.ecosystem });
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
  result.fixed_commits = [...new Set(result.fixed_commits)].slice(0, 10);
  return result;
}

async function fetchNVD(cveId) {
  if (!/^CVE-/i.test(cveId)) return null;
  const headers = {};
  if (process.env.NVD_API_KEY) headers.apiKey = process.env.NVD_API_KEY;
  const raw = await fetchJSON(`${API.NVD_CVE}?cveId=${cveId}`, headers);
  const cve = raw?.vulnerabilities?.[0]?.cve;
  if (!cve) return null;
  const result = { id: cve.id, descriptions: {}, cvss_score: null, vulnerable_configurations: [], vulnerable_files: [] };
  for (const d of cve.descriptions || []) result.descriptions[d.lang] = d.value;
  const cvssV31 = cve.metrics?.cvssMetricV31?.[0]?.cvssData;
  if (cvssV31) result.cvss_score = cvssV31.baseScore;
  if (cve.descriptions?.[0]?.value) {
    const finder = new VulnerabilityLocationFinder();
    result.vulnerable_files = finder.searchAdvisoryForVulnerableFiles(cve.descriptions[0].value, "NVD");
  }
  return result;
}

async function fetchGHSA(id) {
  const idType = /^GHSA-/i.test(id) ? "ghsa" : "cve";
  const headers = { Accept: "application/vnd.github+json" };
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  const url = idType === "ghsa" ? `${API.GHSA_REST}/${id.toUpperCase()}` : `${API.GHSA_REST}?cve_id=${id}&per_page=1`;
  const raw = await fetchJSON(url, headers);
  const ghsa = Array.isArray(raw) ? raw[0] : raw;
  if (!ghsa) return null;
  const result = {
    ghsa_id: ghsa.ghsa_id, cve_id: ghsa.cve_id, summary: ghsa.summary, description: ghsa.description,
    severity: ghsa.severity, cvss_score: ghsa.cvss?.score, vulnerable_files: [], vulnerable_functions: [],
  };
  if (ghsa.description) {
    const finder = new VulnerabilityLocationFinder();
    result.vulnerable_files = finder.searchAdvisoryForVulnerableFiles(ghsa.description, "GHSA");
    const funcMatches = ghsa.description.match(/\b[a-z][a-zA-Z0-9_]*(?=\()/g) || [];
    result.vulnerable_functions = [...new Set(funcMatches)].slice(0, 10);
  }
  return result;
}

async function fetchRedHat(cveId) {
  if (!/^CVE-/i.test(cveId)) return null;
  const json = await fetchJSON(`${API.REDHAT_JSON}${cveId}.json`);
  const html = await fetchText(`${API.REDHAT_PAGE}/${cveId}`);
  const result = {
    cve_id: cveId, severity: json?.severity, affected_releases: [], advisories: [],
    fixed_versions: [], vulnerable_files: [], mitigation: json?.mitigation,
  };
  if (json) {
    for (const rel of json.affected_release || []) {
      result.affected_releases.push({ product: rel.product_name, advisory: rel.advisory, package: rel.package });
      if (rel.advisory) result.advisories.push(rel.advisory);
    }
  }
  if (html) {
    const finder = new VulnerabilityLocationFinder();
    result.vulnerable_files = finder.searchAdvisoryForVulnerableFiles(html, "RedHat");
    const rhsaMatches = html.match(RHSA_RE) || [];
    result.advisories.push(...rhsaMatches);
    result.advisories = [...new Set(result.advisories)];
  }
  return result;
}

async function fetchUbuntu(cveId) {
  if (!/^CVE-/i.test(cveId)) return null;
  const raw = await fetchJSON(`${API.UBUNTU_CVE}/${cveId}.json`);
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

async function fetchDebian(cveId) {
  if (!/^CVE-/i.test(cveId)) return null;
  const raw = await fetchJSON(`${API.DEBIAN_TRACKER}/${cveId}`);
  if (!raw) return { cve_id: cveId, packages: [], fixed_versions: [] };
  const result = { cve_id: cveId, packages: [], fixed_versions: [] };
  for (const [pkgName, distros] of Object.entries(raw)) {
    if (pkgName === "scope") continue;
    const pkg = { name: pkgName, releases: [] };
    for (const [distro, info] of Object.entries(distros || {})) {
      pkg.releases.push({ distro, status: info.status, fixed_version: info.fixed_version });
      if (info.fixed_version && isValidVersion(info.fixed_version)) result.fixed_versions.push(info.fixed_version);
    }
    result.packages.push(pkg);
  }
  result.fixed_versions = cleanVersions(result.fixed_versions);
  return result;
}

async function fetchNPM(cveId) {
  const url = `${API.NPM_REGISTRY}?text=${cveId}&size=5`;
  const raw = await fetchJSON(url);
  if (!raw) return { advisories: [], fixed_versions: [] };
  const advisories = [], fixed_versions = [];
  for (const adv of raw.objects || []) {
    const advisory = adv.advisory || adv;
    advisories.push({
      id: advisory.id, title: advisory.title, severity: advisory.severity,
      module_name: advisory.module_name, patched_versions: advisory.patched_versions,
    });
    if (advisory.patched_versions) {
      const v = advisory.patched_versions.replace(/[^0-9.\-]/g, "").trim();
      if (isValidVersion(v)) fixed_versions.push(v);
    }
  }
  return { advisories, fixed_versions: cleanVersions(fixed_versions) };
}

// ════════════════════════════════════════════════════════════════════════
//  SECTION 4 – Vulnerability Location Finder (File Paths)
// ════════════════════════════════════════════════════════════════════════

class VulnerabilityLocationFinder {
  constructor() {
    this.vulnerableFiles = new Map();
  }
  extractFilePaths(text) {
    if (!text) return [];
    const paths = new Set();
    const fileMatches = text.match(FILE_PATH_RE) || [];
    fileMatches.forEach(p => paths.add(p));
    const blobRegex = /github\.com\/[^\/]+\/[^\/]+\/blob\/[^\/]+\/([^#\s]+)/gi;
    let match;
    while ((match = blobRegex.exec(text)) !== null) paths.add(match[1]);
    const diffRegex = /diff --git a\/(.+) b\/(.+)/g;
    while ((match = diffRegex.exec(text)) !== null) { paths.add(match[1]); paths.add(match[2]); }
    return Array.from(paths);
  }
  extractLineNumbers(text) {
    const lineRanges = [];
    let match;
    while ((match = LINE_NUMBER_RE.exec(text)) !== null) {
      lineRanges.push({ start: parseInt(match[1], 10), end: match[2] ? parseInt(match[2], 10) : parseInt(match[1], 10) });
    }
    return lineRanges;
  }
  parsePatchForVulnerableLines(patchText, commitSha) {
    const vulnerableLocations = [];
    const lines = patchText.split("\n");
    let currentFile = null, currentLineNum = 0;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.startsWith("diff --git")) {
        const match = line.match(/diff --git a\/(.+) b\/(.+)/);
        if (match) currentFile = match[2];
        continue;
      }
      if (line.startsWith("@@") && currentFile) {
        const hunkMatch = line.match(/@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/);
        if (hunkMatch) currentLineNum = parseInt(hunkMatch[3], 10);
        continue;
      }
      if (line.startsWith("-") && !line.startsWith("---") && currentFile) {
        vulnerableLocations.push({
          file: currentFile, line_number: currentLineNum, vulnerable_code: line.substring(1),
          commit: commitSha, change_type: "removed",
        });
      }
      if (!line.startsWith("---") && !line.startsWith("+++") && !line.startsWith("diff") && !line.startsWith("@@")) {
        if (!line.startsWith("-")) currentLineNum++;
      }
    }
    return vulnerableLocations;
  }
  searchAdvisoryForVulnerableFiles(advisoryText, source) {
    const findings = [];
    const paths = this.extractFilePaths(advisoryText);
    const lineNumbers = this.extractLineNumbers(advisoryText);
    for (const filePath of paths) {
      let confidence = 0.7;
      if (filePath.includes("src/main/java")) confidence = 0.9;
      if (filePath.includes("core")) confidence = 0.85;
      const finding = { file_path: filePath, source, confidence, line_numbers: lineNumbers, excerpt: advisoryText.substring(0, 200) };
      findings.push(finding);
      this.vulnerableFiles.set(filePath, finding);
    }
    return findings;
  }
  getVulnerableLocations() {
    return Array.from(this.vulnerableFiles.values()).sort((a, b) => b.confidence - a.confidence);
  }
}

async function fetchCommitDiff(commitUrl) {
  const ghMatch = commitUrl.match(GHCOMMIT_RE);
  if (!ghMatch) return null;
  const [, owner, repo, sha] = ghMatch;
  const headers = {};
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  const diffUrl = `https://github.com/${owner}/${repo}/commit/${sha}.diff`;
  const diffText = await fetchText(diffUrl, headers);
  if (!diffText) return null;
  const finder = new VulnerabilityLocationFinder();
  const vulnerableLocations = finder.parsePatchForVulnerableLines(diffText, sha);
  const filePaths = finder.extractFilePaths(diffText);
  return { commit_sha: sha, repo: `${owner}/${repo}`, url: commitUrl, vulnerable_locations: vulnerableLocations, affected_files: filePaths };
}

// ════════════════════════════════════════════════════════════════════════
//  SECTION 5 – Multi-Agent Orchestration
// ════════════════════════════════════════════════════════════════════════

class IdentityAgent {
  constructor(memory) { this.memory = memory; }
  async resolve(cveId) {
    console.log(`  [IdentityAgent] Resolving ${cveId}`);
    const [nvd, osv, ghsa] = await Promise.all([
      this.memory.getCVE(cveId, "nvd"),
      this.memory.getCVE(cveId, "osv"),
      this.memory.getCVE(cveId, "ghsa"),
    ]);
    const merged = {
      id: cveId, cvss_score: nvd?.cvss_score || ghsa?.cvss_score || null,
      severity: ghsa?.severity || nvd?.severity || "Unknown",
      summary: osv?.summary || ghsa?.summary || nvd?.descriptions?.en || "",
      fixed_versions: [...new Set([...(osv?.fixed_versions || []), ...(nvd?.fixed_versions || [])])],
      fixed_commits: osv?.fixed_commits || [],
      affected_packages: osv?.affected_packages || [],
      vulnerable_files: [...(osv?.vulnerable_files || []), ...(nvd?.vulnerable_files || []), ...(ghsa?.vulnerable_files || [])],
    };
    return merged;
  }
}

class DeepAnalysisAgent {
  constructor(memory) { this.memory = memory; }
  async analyze(cveData) {
    console.log(`  [DeepAnalysisAgent] Analyzing patches for ${cveData.id}`);
    const commitUrls = (cveData.fixed_commits || []).map(c => `https://github.com/apache/logging-log4j2/commit/${c}`);
    const commitInfo = [];
    for (const url of commitUrls.slice(0, 3)) {
      const info = await fetchCommitDiff(url);
      if (info) commitInfo.push(info);
      await sleep(200);
    }
    const vulnerablePatterns = commitInfo.flatMap(c => c.vulnerable_locations || []);
    return { commits: commitInfo, vulnerable_patterns: vulnerablePatterns, file_changes: [...new Set(commitInfo.flatMap(c => c.affected_files || []))] };
  }
}

class ContextualRiskAgent {
  constructor(memory) { this.memory = memory; }
  async calculateRisk(cveData, analysisData, assetContext) {
    console.log(`  [ContextualRiskAgent] Calculating risk for ${cveData.id}`);
    const epss = await this.memory.getEPSS(cveData.id);
    const exploitExists = await this.memory.getExploitExists(cveData.id);
    const assetCriticality = (assetContext?.isInternetFacing ? 0.3 : 0) + (assetContext?.isProduction ? 0.2 : 0) + 0.5;
    const cvssBase = cveData.cvss_score || 5;
    const reachable = assetContext?.packages?.some(pkg => cveData.affected_packages?.some(ap => ap.name === pkg.name)) ? 0.8 : 0.2;
    const riskScore = Math.min(10, Math.max(0,
      cvssBase * 0.25 + (epss * 10) * 0.2 + (exploitExists ? 10 : 0) * 0.25 + assetCriticality * 10 * 0.2 + reachable * 10 * 0.1
    ));
    const priority = riskScore >= 8 ? "CRITICAL" : riskScore >= 6 ? "HIGH" : riskScore >= 4 ? "MEDIUM" : "LOW";
    return { risk_score: Math.round(riskScore * 10) / 10, priority, components: { epss, exploit_exists: exploitExists, asset_criticality: assetCriticality, cvss_base: cvssBase, reachable } };
  }
}

class AgentOrchestrator {
  constructor(useRedis = true) {
    this.memory = new SharedMemoryManager(useRedis);
    this.agents = {
      identity: new IdentityAgent(this.memory),
      analysis: new DeepAnalysisAgent(this.memory),
      risk: new ContextualRiskAgent(this.memory),
    };
  }
  async analyze(cveId, assetContext = {}) {
    const start = Date.now();
    const identity = await this.agents.identity.resolve(cveId);
    const analysis = await this.agents.analysis.analyze(identity);
    const risk = await this.agents.risk.calculateRisk(identity, analysis, assetContext);
    return { identity, analysis, risk, duration_ms: Date.now() - start };
  }
  async close() { await this.memory.close(); }
}

// ════════════════════════════════════════════════════════════════════════
//  SECTION 6 – Remediation MOPS Generator
// ════════════════════════════════════════════════════════════════════════

function generateRemediationSteps(cveId, identity, risk, assetContext) {
  const steps = [];
  if (identity.vulnerable_files?.length) {
    steps.push({
      step: 1, title: "🔍 VULNERABLE FILE LOCATIONS",
      vulnerable_files: identity.vulnerable_files.slice(0, 5).map(vf => ({
        path: vf.file_path, source: vf.source, confidence: `${Math.round(vf.confidence * 100)}%`, line_numbers: vf.line_numbers,
      })),
    });
  }
  steps.push({
    step: 2, title: "📦 AFFECTED PACKAGES",
    affected_packages: identity.affected_packages.slice(0, 5).map(p => ({ name: p.name, ecosystem: p.ecosystem, common_paths: getCommonPackagePaths(p.name, p.ecosystem) })),
  });
  steps.push({
    step: 3, title: "🖥️ SYSTEM REMEDIATION",
    commands: [
      "# Update all packages (RHEL/CentOS/AlmaLinux/Rocky):",
      "yum update -y 2>/dev/null || dnf update -y",
      `# Verify fix: rpm -qa --changelog | grep -i "${cveId}"`,
    ],
  });
  if (risk.priority === "CRITICAL") {
    steps.unshift({ step: 0, title: "🚨 CRITICAL - ACTIVE EXPLOIT", description: "Patch immediately! Use these commands:", commands: ["yum update -y", "systemctl restart affected-services"] });
  }
  return steps;
}

// ════════════════════════════════════════════════════════════════════════
//  SECTION 7 – Main Orchestrator & CLI
// ════════════════════════════════════════════════════════════════════════

async function analyzeWithAgents(cveId, assetContext = {}) {
  const orchestrator = new AgentOrchestrator(!!process.env.REDIS_URL);
  try {
    const result = await orchestrator.analyze(cveId, assetContext);
    const remediationSteps = generateRemediationSteps(cveId, result.identity, result.risk, assetContext);
    const output = {
      meta: { cve_id: cveId, analyzed_at: new Date().toISOString(), duration_ms: result.duration_ms },
      vulnerability_summary: {
        title: result.identity.summary?.substring(0, 200), severity: result.identity.severity,
        cvss_score: result.identity.cvss_score, fix_available: result.identity.fixed_versions.length > 0,
        fixed_versions: result.identity.fixed_versions, fixed_commits: result.identity.fixed_commits,
      },
      vulnerable_locations: { total_files_found: result.identity.vulnerable_files.length, files: result.identity.vulnerable_files.slice(0, 10) },
      risk_assessment: result.risk,
      remediation_mops: { steps: remediationSteps },
      quick_fix_commands: { rhel: "yum update -y || dnf update -y", verify: `rpm -qa --changelog | grep -i "${cveId}"` },
    };
    return output;
  } finally {
    await orchestrator.close();
  }
}

// CLI Entry Point
(async () => {
  const id = process.argv[2];
  if (!id) {
    console.log(`
╔════════════════════════════════════════════════════════════════════════╗
║     CVE Intelligence Analyzer v7.0 - MULTI-AGENT ORCHESTRATION        ║
╚════════════════════════════════════════════════════════════════════════╝
Usage: node cve-agent.js CVE-2021-45046
Environment: REDIS_URL=redis://... (optional), GITHUB_TOKEN, NVD_API_KEY, SAVE_OUTPUT=1
    `);
    process.exit(1);
  }
  try {
    const assetContext = { isProduction: true, isInternetFacing: true, packages: [{ name: "log4j-core" }] };
    const result = await analyzeWithAgents(id.toUpperCase(), assetContext);
    console.log("\n" + "═".repeat(72));
    console.log("  VULNERABILITY ANALYSIS REPORT (Multi-Agent)");
    console.log("═".repeat(72));
    console.log(`\n📋 CVE: ${result.meta.cve_id}`);
    console.log(`📊 Severity: ${result.vulnerability_summary.severity} | CVSS: ${result.vulnerability_summary.cvss_score || "N/A"}`);
    console.log(`🎯 Risk Score: ${result.risk_assessment.risk_score}/10 (${result.risk_assessment.priority})`);
    console.log(`✅ Fix Available: ${result.vulnerability_summary.fix_available ? "YES" : "NO"}`);
    if (result.vulnerable_locations.total_files_found) {
      console.log(`\n🔍 Vulnerable files (${result.vulnerable_locations.total_files_found}):`);
      result.vulnerable_locations.files.slice(0, 3).forEach(f => console.log(`   • ${f.file_path} (${f.source}, ${Math.round(f.confidence * 100)}%)`));
    }
    console.log(`\n🚀 Quick fix: ${result.quick_fix_commands.rhel}`);
    if (process.env.SAVE_OUTPUT === "1") {
      const filename = `${result.meta.cve_id}_v7.json`;
      fs.writeFileSync(filename, JSON.stringify(result, null, 2));
      console.log(`\n💾 Full report saved → ${filename}`);
    }
    console.log("\n" + "═".repeat(72) + "\n");
  } catch (err) {
    console.error("\n❌ Fatal error:", err.message);
    if (process.env.DEBUG) console.error(err.stack);
    process.exit(1);
  }
})();