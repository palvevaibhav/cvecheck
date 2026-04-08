#!/usr/bin/env node

/**
 * ════════════════════════════════════════════════════════════════════════
 *  CVE Intelligence Analyzer v6.0 - WITH FILE PATH DETECTION
 *  
 *  Shows exact vulnerable file paths and code locations
 * ════════════════════════════════════════════════════════════════════════
 */

"use strict";

global.File = class File {};

const axios   = require("axios");
const https   = require("https");
const zlib    = require("zlib");
const cheerio = require("cheerio");
const fs      = require("fs");

// ════════════════════════════════════════════════════════════════════════
//  SECTION 0 – Configuration & Constants
// ════════════════════════════════════════════════════════════════════════

const TRUSTED_DOMAINS = [
  "github.com", "raw.githubusercontent.com", "api.github.com",
  "git.kernel.org",
  "nvd.nist.gov", "services.nvd.nist.gov", "cve.mitre.org",
  "api.osv.dev",
  "ubuntu.com", "debian.org", "access.redhat.com",
  "npmjs.com", "registry.npmjs.org",
];

const API = {
  NVD_CVE:        "https://services.nvd.nist.gov/rest/json/cves/2.0",
  OSV_VULNS:      "https://api.osv.dev/v1/vulns",
  GHSA_REST:      "https://api.github.com/advisories",
  REDHAT_JSON:    "https://access.redhat.com/hydra/rest/securitydata/cve/",
  REDHAT_PAGE:    "https://access.redhat.com/security/cve",
  REDHAT_ERRATA:  "https://access.redhat.com/errata",
  UBUNTU_CVE:     "https://ubuntu.com/security/cves",
  DEBIAN_TRACKER: "https://security-tracker.debian.org/tracker",
  NPM_REGISTRY:   "https://registry.npmjs.org/-/npm/v1/security/advisories/search",
};

const SCORE = {
  osv: 1.00, ghsa: 0.95, nvd: 0.90, redhat: 0.85,
  ubuntu: 0.80, debian: 0.80, almalinux: 0.75, alpine: 0.75,
};

const VERSION_RE = /^\d+\.\d+(\.\d+)?(-\d+)?$/;
const COMMIT_RE = /\b[0-9a-f]{40}\b/gi;
const GHCOMMIT_RE = /github\.com\/([^/]+)\/([^/]+)\/commit\/([0-9a-f]{40})/i;
const RHSA_RE = /RHSA-\d{4}:\d{4,}/g;
const FILE_PATH_RE = /(?:\/[\w\-.]+)+\.(?:java|js|py|go|rs|c|cpp|h|hpp|xml|properties|yaml|yml|json|sh|rb|php)/gi;
const LINE_NUMBER_RE = /[Ll]ine[s]?\s+(\d+)(?:-(\d+))?/g;

// ════════════════════════════════════════════════════════════════════════
//  SECTION 1 – HTTP Layer
// ════════════════════════════════════════════════════════════════════════

const httpClient = axios.create({
  httpsAgent: new https.Agent({ rejectUnauthorized: false }),
  timeout: 20_000,
  headers: { "User-Agent": "cve-intel-analyzer/6.0", Accept: "application/json, text/html, */*" },
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
  } catch (err) {
    return null;
  }
}

async function fetchJSON(url, extraHeaders = {}) {
  const res = await fetchRaw(url, extraHeaders);
  if (!res || res.status >= 400) return null;
  try {
    return JSON.parse(Buffer.from(res.data).toString("utf8"));
  } catch { return null; }
}

async function fetchText(url, extraHeaders = {}) {
  const res = await fetchRaw(url, extraHeaders);
  if (!res || res.status >= 400) return null;
  return Buffer.from(res.data).toString("utf8");
}

async function fetchGzipJSON(url) {
  const res = await fetchRaw(url);
  if (!res || res.status >= 400) return null;
  try {
    const buf = await new Promise((resolve, reject) => {
      zlib.gunzip(res.data, (err, result) => (err ? reject(err) : resolve(result)));
    });
    return buf.toString("utf8").split("\n").filter(Boolean)
      .map((line) => { try { return JSON.parse(line); } catch { return null; } })
      .filter(Boolean);
  } catch { return null; }
}

// ════════════════════════════════════════════════════════════════════════
//  SECTION 2 – FILE PATH & VULNERABLE LOCATION DETECTOR
// ════════════════════════════════════════════════════════════════════════

class VulnerabilityLocationFinder {
  constructor() {
    this.vulnerableFiles = new Map(); // file path -> { line_numbers, code_snippets, confidence }
  }

  /**
   * Extract file paths from text (commit messages, advisories, patch diffs)
   */
  extractFilePaths(text) {
    if (!text) return [];
    const paths = new Set();
    
    // Match file paths like src/main/java/org/apache/logging/log4j/core/layout/PatternLayout.java
    const fileMatches = text.match(FILE_PATH_RE) || [];
    fileMatches.forEach(p => paths.add(p));
    
    // Match GitHub blob URLs
    const blobRegex = /github\.com\/[^\/]+\/[^\/]+\/blob\/[^\/]+\/([^#\s]+)/gi;
    let match;
    while ((match = blobRegex.exec(text)) !== null) {
      paths.add(match[1]);
    }
    
    // Match git diff file headers
    const diffRegex = /diff --git a\/(.+) b\/(.+)/g;
    while ((match = diffRegex.exec(text)) !== null) {
      paths.add(match[1]);
      paths.add(match[2]);
    }
    
    return Array.from(paths);
  }

  /**
   * Extract line numbers from text
   */
  extractLineNumbers(text) {
    const lineRanges = [];
    let match;
    while ((match = LINE_NUMBER_RE.exec(text)) !== null) {
      lineRanges.push({
        start: parseInt(match[1], 10),
        end: match[2] ? parseInt(match[2], 10) : parseInt(match[1], 10)
      });
    }
    return lineRanges;
  }

  /**
   * Parse patch diff to find exact vulnerable lines
   */
  parsePatchForVulnerableLines(patchText, commitSha) {
    const vulnerableLocations = [];
    const lines = patchText.split('\n');
    let currentFile = null;
    let currentLineNum = 0;
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      // Detect file being changed
      if (line.startsWith('diff --git')) {
        const match = line.match(/diff --git a\/(.+) b\/(.+)/);
        if (match) currentFile = match[2];
        continue;
      }
      
      // Detect hunk header (contains line numbers)
      if (line.startsWith('@@') && currentFile) {
        const hunkMatch = line.match(/@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/);
        if (hunkMatch) {
          currentLineNum = parseInt(hunkMatch[3], 10);
          continue;
        }
      }
      
      // Lines being removed (vulnerable code)
      if (line.startsWith('-') && !line.startsWith('---') && currentFile) {
        vulnerableLocations.push({
          file: currentFile,
          line_number: currentLineNum,
          vulnerable_code: line.substring(1),
          commit: commitSha,
          change_type: 'removed'
        });
      }
      
      // Count lines to track position
      if (!line.startsWith('---') && !line.startsWith('+++') && !line.startsWith('diff') && !line.startsWith('@@')) {
        if (!line.startsWith('-')) currentLineNum++;
      }
    }
    
    return vulnerableLocations;
  }

  /**
   * Search for vulnerable file references in advisory data
   */
  searchAdvisoryForVulnerableFiles(advisoryText, source) {
    const findings = [];
    const paths = this.extractFilePaths(advisoryText);
    const lineNumbers = this.extractLineNumbers(advisoryText);
    
    for (const filePath of paths) {
      // Determine confidence based on file extension and context
      let confidence = 0.7;
      if (filePath.includes('src/main/java')) confidence = 0.9;
      if (filePath.includes('core')) confidence = 0.85;
      if (filePath.includes('vulnerable')) confidence = 0.95;
      
      const finding = {
        file_path: filePath,
        source: source,
        confidence: confidence,
        line_numbers: lineNumbers,
        excerpt: advisoryText.substring(0, 200)
      };
      
      findings.push(finding);
      this.vulnerableFiles.set(filePath, finding);
    }
    
    return findings;
  }

  /**
   * Get all unique vulnerable locations
   */
  getVulnerableLocations() {
    return Array.from(this.vulnerableFiles.values())
      .sort((a, b) => b.confidence - a.confidence);
  }
}

// ════════════════════════════════════════════════════════════════════════
//  SECTION 3 – SOURCE: OSV (with file path extraction)
// ════════════════════════════════════════════════════════════════════════

async function fetchOSV(cveId) {
  console.log("  [OSV] Fetching …");
  const raw = await fetchJSON(`https://api.osv.dev/v1/vulns/${cveId}`);
  if (!raw) return null;

  const result = {
    id: raw.id,
    summary: raw.summary || "",
    details: raw.details || "",
    fixed_versions: [],
    fixed_commits: [],
    affected_packages: [],
    vulnerable_files: [],
  };

  // Extract vulnerable files from details
  if (raw.details) {
    const fileFinder = new VulnerabilityLocationFinder();
    const findings = fileFinder.searchAdvisoryForVulnerableFiles(raw.details, "OSV");
    result.vulnerable_files.push(...findings);
  }

  for (const a of raw.affected ?? []) {
    const pkg = { name: a.package?.name, ecosystem: a.package?.ecosystem };
    result.affected_packages.push(pkg);
    
    for (const r of a.ranges ?? []) {
      for (const e of r.events ?? []) {
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

// ════════════════════════════════════════════════════════════════════════
//  SECTION 4 – SOURCE: NVD
// ════════════════════════════════════════════════════════════════════════

async function fetchNVD(cveId) {
  if (!/^CVE-/i.test(cveId)) return null;
  console.log("  [NVD] Fetching …");
  
  const headers = {};
  if (process.env.NVD_API_KEY) headers["apiKey"] = process.env.NVD_API_KEY;
  
  const raw = await fetchJSON(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`, headers);
  if (!raw) return null;
  
  const cve = raw.vulnerabilities?.[0]?.cve;
  if (!cve) return null;
  
  const result = {
    id: cve.id,
    descriptions: {},
    cvss_score: null,
    vulnerable_configurations: [],
    vulnerable_files: [],
  };
  
  for (const d of cve.descriptions ?? []) result.descriptions[d.lang] = d.value;
  
  // Extract vulnerable configurations (CPEs)
  for (const config of cve.configurations ?? []) {
    for (const node of config.nodes ?? []) {
      for (const cpe of node.cpeMatch ?? []) {
        if (cpe.vulnerable) {
          result.vulnerable_configurations.push({
            criteria: cpe.criteria,
            version_start: cpe.versionStartIncluding || cpe.versionStartExcluding,
            version_end: cpe.versionEndExcluding || cpe.versionEndIncluding
          });
        }
      }
    }
  }
  
  // Extract CVSS score
  const cvssV31 = cve.metrics?.cvssMetricV31?.[0]?.cvssData;
  if (cvssV31) result.cvss_score = cvssV31.baseScore;
  
  // Extract vulnerable files from description
  if (cve.descriptions?.[0]?.value) {
    const fileFinder = new VulnerabilityLocationFinder();
    const findings = fileFinder.searchAdvisoryForVulnerableFiles(
      cve.descriptions[0].value, "NVD"
    );
    result.vulnerable_files.push(...findings);
  }
  
  return result;
}

// ════════════════════════════════════════════════════════════════════════
//  SECTION 5 – SOURCE: GHSA
// ════════════════════════════════════════════════════════════════════════

async function fetchGHSA(id) {
  console.log("  [GHSA] Fetching …");
  const idType = /^GHSA-/i.test(id) ? "ghsa" : "cve";
  const headers = { Accept: "application/vnd.github+json" };
  if (process.env.GITHUB_TOKEN) headers["Authorization"] = `Bearer ${process.env.GITHUB_TOKEN}`;
  
  const url = idType === "ghsa"
    ? `https://api.github.com/advisories/${id.toUpperCase()}`
    : `https://api.github.com/advisories?cve_id=${id}&per_page=1`;
  
  const raw = await fetchJSON(url, headers);
  if (!raw) return null;
  
  const ghsa = Array.isArray(raw) ? raw[0] : raw;
  if (!ghsa) return null;
  
  const result = {
    ghsa_id: ghsa.ghsa_id,
    cve_id: ghsa.cve_id,
    summary: ghsa.summary,
    description: ghsa.description,
    severity: ghsa.severity,
    cvss_score: ghsa.cvss?.score,
    vulnerable_files: [],
    vulnerable_functions: [],
  };
  
  // Extract vulnerable files from description
  if (ghsa.description) {
    const fileFinder = new VulnerabilityLocationFinder();
    const findings = fileFinder.searchAdvisoryForVulnerableFiles(ghsa.description, "GHSA");
    result.vulnerable_files.push(...findings);
    
    // Also look for function names
    const functionMatches = ghsa.description.match(/\b[a-z][a-zA-Z0-9_]*(?=\()/g) || [];
    result.vulnerable_functions = [...new Set(functionMatches)].slice(0, 10);
  }
  
  return result;
}

// ════════════════════════════════════════════════════════════════════════
//  SECTION 6 – SOURCE: Red Hat (with file paths)
// ════════════════════════════════════════════════════════════════════════

async function fetchRedHat(cveId) {
  if (!/^CVE-/i.test(cveId)) return null;
  console.log("  [RedHat] Fetching …");
  
  const json = await fetchJSON(`https://access.redhat.com/hydra/rest/securitydata/cve/${cveId}.json`);
  const html = await fetchText(`https://access.redhat.com/security/cve/${cveId}`);
  
  const result = {
    cve_id: cveId,
    severity: json?.severity,
    affected_releases: [],
    advisories: [],
    fixed_versions: [],
    vulnerable_files: [],
    mitigation: json?.mitigation,
  };
  
  if (json) {
    for (const rel of json.affected_release ?? []) {
      result.affected_releases.push({
        product: rel.product_name,
        advisory: rel.advisory,
        package: rel.package
      });
      if (rel.advisory) result.advisories.push(rel.advisory);
    }
  }
  
  if (html) {
    const fileFinder = new VulnerabilityLocationFinder();
    const findings = fileFinder.searchAdvisoryForVulnerableFiles(html, "RedHat");
    result.vulnerable_files.push(...findings);
    
    // Extract RHSA IDs
    const rhsaMatches = html.match(RHSA_RE) || [];
    result.advisories.push(...rhsaMatches);
    result.advisories = [...new Set(result.advisories)];
  }
  
  return result;
}

// ════════════════════════════════════════════════════════════════════════
//  SECTION 7 – SOURCE: Ubuntu
// ════════════════════════════════════════════════════════════════════════

async function fetchUbuntu(cveId) {
  if (!/^CVE-/i.test(cveId)) return null;
  console.log("  [Ubuntu] Fetching …");
  
  const raw = await fetchJSON(`https://ubuntu.com/security/cves/${cveId}.json`);
  if (!raw) return null;
  
  const result = {
    cve_id: raw.id,
    description: raw.description,
    priority: raw.priority,
    packages: [],
    fixed_versions: [],
  };
  
  for (const pkg of raw.packages ?? []) {
    const pkgInfo = { name: pkg.name, releases: [] };
    for (const [release, info] of Object.entries(pkg.statuses ?? {})) {
      pkgInfo.releases.push({ release, status: info.status, fixed_version: info.fixed_version });
      if (info.fixed_version && isValidVersion(info.fixed_version)) {
        result.fixed_versions.push(info.fixed_version);
      }
    }
    result.packages.push(pkgInfo);
  }
  
  result.fixed_versions = cleanVersions(result.fixed_versions);
  return result;
}

// ════════════════════════════════════════════════════════════════════════
//  SECTION 8 – SOURCE: Debian
// ════════════════════════════════════════════════════════════════════════

async function fetchDebian(cveId) {
  if (!/^CVE-/i.test(cveId)) return null;
  console.log("  [Debian] Fetching …");
  
  const raw = await fetchJSON(`https://security-tracker.debian.org/tracker/${cveId}`);
  if (!raw) return { cve_id: cveId, packages: [], fixed_versions: [] };
  
  const result = { cve_id: cveId, packages: [], fixed_versions: [] };
  
  for (const [pkgName, distros] of Object.entries(raw)) {
    if (pkgName === "scope") continue;
    const pkg = { name: pkgName, releases: [] };
    for (const [distro, info] of Object.entries(distros ?? {})) {
      pkg.releases.push({ distro, status: info.status, fixed_version: info.fixed_version });
      if (info.fixed_version && isValidVersion(info.fixed_version)) {
        result.fixed_versions.push(info.fixed_version);
      }
    }
    result.packages.push(pkg);
  }
  
  result.fixed_versions = cleanVersions(result.fixed_versions);
  return result;
}

// ════════════════════════════════════════════════════════════════════════
//  SECTION 9 – NPM Advisory
// ════════════════════════════════════════════════════════════════════════

async function fetchNPM(cveId) {
  console.log("  [NPM] Fetching …");
  const url = `https://registry.npmjs.org/-/npm/v1/security/advisories/search?text=${cveId}&size=5`;
  const raw = await fetchJSON(url);
  
  if (!raw) return { advisories: [], fixed_versions: [] };
  
  const advisories = [];
  const fixed_versions = [];
  
  for (const adv of raw.objects ?? []) {
    const advisory = adv.advisory ?? adv;
    advisories.push({
      id: advisory.id,
      title: advisory.title,
      severity: advisory.severity,
      module_name: advisory.module_name,
      patched_versions: advisory.patched_versions,
    });
    if (advisory.patched_versions) {
      const v = advisory.patched_versions.replace(/[^0-9.\-]/g, "").trim();
      if (isValidVersion(v)) fixed_versions.push(v);
    }
  }
  
  return { advisories, fixed_versions: cleanVersions(fixed_versions) };
}

// ════════════════════════════════════════════════════════════════════════
//  SECTION 10 – COMMIT & PATCH ANALYZER (for file paths)
// ════════════════════════════════════════════════════════════════════════

async function fetchCommitDiff(commitUrl) {
  const ghMatch = commitUrl.match(GHCOMMIT_RE);
  if (!ghMatch) return null;
  
  const [, owner, repo, sha] = ghMatch;
  const headers = {};
  if (process.env.GITHUB_TOKEN) headers["Authorization"] = `Bearer ${process.env.GITHUB_TOKEN}`;
  
  const diffUrl = `https://github.com/${owner}/${repo}/commit/${sha}.diff`;
  const diffText = await fetchText(diffUrl, headers);
  
  if (!diffText) return null;
  
  const locationFinder = new VulnerabilityLocationFinder();
  const vulnerableLocations = locationFinder.parsePatchForVulnerableLines(diffText, sha);
  const filePaths = locationFinder.extractFilePaths(diffText);
  
  return {
    commit_sha: sha,
    repo: `${owner}/${repo}`,
    url: commitUrl,
    vulnerable_locations: vulnerableLocations,
    affected_files: filePaths,
    patch_preview: diffText.substring(0, 1000)
  };
}

// ════════════════════════════════════════════════════════════════════════
//  SECTION 11 – REMEDIATION MOPS WITH FILE PATHS
// ════════════════════════════════════════════════════════════════════════

function generateRemediationWithPaths(cveId, vulnerableFiles, affectedPackages, commitInfo) {
  const steps = [];
  
  // Step 1: Show vulnerable file locations
  if (vulnerableFiles.length > 0) {
    steps.push({
      step: 1,
      title: "🔍 VULNERABLE FILE LOCATIONS DETECTED",
      description: "The following files contain the vulnerability. Check these locations in your codebase.",
      vulnerable_files: vulnerableFiles.map(vf => ({
        path: vf.file_path,
        source: vf.source,
        confidence: `${Math.round(vf.confidence * 100)}%`,
        line_numbers: vf.line_numbers,
        excerpt: vf.excerpt?.substring(0, 200)
      })),
      search_commands: [
        `# Search for vulnerable files in your codebase:`,
        `find . -type f -name "*.java" -o -name "*.js" -o -name "*.py" | xargs grep -l "vulnerable_pattern" 2>/dev/null`,
        `# Or use ripgrep for faster searching:`,
        `rg -g "*.{java,js,py,go}" -l "ClassName" .`
      ]
    });
  }
  
  // Step 2: Show affected packages with file paths
  if (affectedPackages.length > 0) {
    steps.push({
      step: steps.length + 1,
      title: "📦 AFFECTED PACKAGES & COMMON PATHS",
      description: "These packages are vulnerable. Here are typical installation paths:",
      affected_packages: affectedPackages.map(pkg => ({
        name: pkg.name,
        ecosystem: pkg.ecosystem,
        common_paths: getCommonPackagePaths(pkg.name, pkg.ecosystem)
      })),
      verification_commands: [
        `# Check if vulnerable package is installed:`,
        `rpm -qa | grep -i "${affectedPackages[0]?.name?.split('-')[0] || 'package'}"`,
        `# Or for language-specific packages:`,
        `npm list ${affectedPackages[0]?.name} 2>/dev/null || echo "Not an npm package"`
      ]
    });
  }
  
  // Step 3: Commit-based remediation with exact file paths
  if (commitInfo && commitInfo.length > 0) {
    const allFiles = [...new Set(commitInfo.flatMap(c => c.affected_files || []))];
    steps.push({
      step: steps.length + 1,
      title: "🔧 PATCH COMMITS WITH EXACT FILE PATHS",
      description: "Apply these patches to fix the vulnerability at the source level.",
      commits: commitInfo.map(c => ({
        sha: c.commit_sha?.substring(0, 12),
        repo: c.repo,
        url: c.url,
        vulnerable_locations: c.vulnerable_locations?.slice(0, 5).map(vl => ({
          file: vl.file,
          line: vl.line_number,
          vulnerable_code: vl.vulnerable_code?.substring(0, 100)
        }))
      })),
      patch_commands: [
        `# Apply patches manually:`,
        ...allFiles.slice(0, 3).map(f => `# Fix file: ${f}`),
        `# Or cherry-pick the commit if you have the repo:`,
        `git fetch origin && git cherry-pick ${commitInfo[0]?.commit_sha}`
      ]
    });
  }
  
  // Step 4: System-level remediation
  steps.push({
    step: steps.length + 1,
    title: "🖥️ SYSTEM-LEVEL REMEDIATION",
    description: "Run these commands to update the vulnerable packages:",
    commands: [
      "# Update all packages (RHEL/CentOS/AlmaLinux/Rocky):",
      "yum update -y 2>/dev/null || dnf update -y",
      "",
      "# For specific package:",
      `yum update ${affectedPackages[0]?.name?.split('-')[0] || 'package'} -y`,
      "",
      "# Verify the fix:",
      "rpm -qa --changelog | grep -i 'CVE' | head -5"
    ]
  });
  
  return steps;
}

function getCommonPackagePaths(packageName, ecosystem) {
  const paths = {
    java: [`/usr/share/java/${packageName}.jar`, `/opt/${packageName}/lib`, `~/.m2/repository/org/apache/${packageName}`],
    node: [`/usr/lib/node_modules/${packageName}`, `./node_modules/${packageName}`, `~/.npm/lib/node_modules/${packageName}`],
    python: [`/usr/lib/python3*/site-packages/${packageName}`, `./venv/lib/python*/site-packages/${packageName}`],
    ruby: [`/usr/lib/ruby/gems/*/gems/${packageName}`, `./vendor/bundle/ruby/*/gems/${packageName}`],
    go: [`/usr/local/go/src/${packageName}`, `~/go/pkg/mod/${packageName}`],
  };
  
  // Detect ecosystem from package name or default to generic
  if (packageName?.includes('log4j')) return paths.java;
  if (packageName?.includes('spring')) return paths.java;
  if (packageName?.includes('express')) return paths.node;
  if (packageName?.includes('django')) return paths.python;
  if (packageName?.includes('rails')) return paths.ruby;
  
  return paths[ecosystem?.toLowerCase()] || [`/usr/lib/${packageName}`, `/opt/${packageName}`];
}

function isValidVersion(v) {
  if (!v || typeof v !== "string") return false;
  if (!VERSION_RE.test(v)) return false;
  return true;
}

function cleanVersions(arr) {
  return [...new Set((arr ?? []).filter(isValidVersion))];
}

function deduplicateAndRank(entries) {
  const best = new Map();
  for (const e of entries) {
    const ex = best.get(e.version);
    if (!ex || e.score > ex.score) best.set(e.version, e);
  }
  return [...best.values()].sort((a, b) => b.score - a.score).slice(0, 20);
}

// ════════════════════════════════════════════════════════════════════════
//  SECTION 12 – MAIN ORCHESTRATOR
// ════════════════════════════════════════════════════════════════════════

async function analyze(id) {
  const startAt = Date.now();
  const normalised = id.trim().toUpperCase();
  const idType = /^CVE-/i.test(normalised) ? "cve" : "ghsa";
  
  console.log(`\n${"═".repeat(72)}`);
  console.log(`  CVE Intelligence Analyzer v6.0 - WITH FILE PATH DETECTION`);
  console.log(`  Target: ${normalised}`);
  console.log(`${"═".repeat(72)}\n`);
  
  // Fetch all sources
  console.log("[Phase 1] Fetching vulnerability data from all sources...");
  const [osv, nvd, ghsa, redhat, ubuntu, debian, npm] = await Promise.all([
    fetchOSV(normalised),
    fetchNVD(normalised),
    fetchGHSA(normalised),
    fetchRedHat(normalised),
    fetchUbuntu(normalised),
    fetchDebian(normalised),
    fetchNPM(normalised),
  ]);
  
  // Collect all vulnerable files from all sources
  const allVulnerableFiles = [
    ...(osv?.vulnerable_files || []),
    ...(nvd?.vulnerable_files || []),
    ...(ghsa?.vulnerable_files || []),
    ...(redhat?.vulnerable_files || []),
  ];
  
  // Extract commit URLs and fetch patch details
  const commitUrls = [];
  if (osv?.fixed_commits) {
    for (const commit of osv.fixed_commits) {
      if (commit.length === 40) {
        commitUrls.push(`https://github.com/apache/logging-log4j2/commit/${commit}`);
      }
    }
  }
  
  console.log("\n[Phase 2] Fetching commit details for file path analysis...");
  const commitInfo = [];
  for (const url of commitUrls.slice(0, 3)) {
    const info = await fetchCommitDiff(url);
    if (info) commitInfo.push(info);
    await sleep(200);
  }
  
  // Collect affected packages
  const affectedPackages = [
    ...(osv?.affected_packages || []),
    ...(ubuntu?.packages || []).map(p => ({ name: p.name, ecosystem: "ubuntu" })),
    ...(debian?.packages || []).map(p => ({ name: p.name, ecosystem: "debian" })),
  ];
  
  // Generate remediation steps with file paths
  console.log("\n[Phase 3] Generating remediation steps with file paths...");
  const remediationSteps = generateRemediationWithPaths(
    normalised,
    allVulnerableFiles,
    affectedPackages,
    commitInfo
  );
  
  // Build output
  const output = {
    meta: {
      cve_id: normalised,
      analyzed_at: new Date().toISOString(),
      duration_ms: Date.now() - startAt,
      sources_used: {
        osv: !!osv,
        nvd: !!nvd,
        ghsa: !!ghsa,
        redhat: !!redhat,
        ubuntu: !!ubuntu,
        debian: !!debian,
      }
    },
    vulnerability_summary: {
      title: osv?.summary || ghsa?.summary || nvd?.descriptions?.en?.substring(0, 200),
      severity: ghsa?.severity || redhat?.severity || "Unknown",
      cvss_score: nvd?.cvss_score || ghsa?.cvss_score,
      fix_available: (osv?.fixed_versions?.length > 0 || osv?.fixed_commits?.length > 0),
      fixed_versions: osv?.fixed_versions || [],
      fixed_commits: osv?.fixed_commits || [],
    },
    vulnerable_locations: {
      total_files_found: allVulnerableFiles.length,
      files: allVulnerableFiles.slice(0, 15).map(vf => ({
        path: vf.file_path,
        source: vf.source,
        confidence: vf.confidence,
        line_numbers: vf.line_numbers
      })),
      commit_details: commitInfo.map(ci => ({
        commit: ci.commit_sha,
        affected_files: ci.affected_files,
        vulnerable_lines: ci.vulnerable_locations?.length
      }))
    },
    affected_packages: affectedPackages.slice(0, 10),
    remediation_mops: {
      overview: "Follow these steps to remediate the vulnerability",
      requires_reboot: false,
      estimated_time: "15-30 minutes",
      steps: remediationSteps
    },
    quick_fix_commands: {
      rhel: "yum update -y || dnf update -y",
      verify: `rpm -qa --changelog | grep -i "${normalised}"`,
      rollback: "yum history undo last"
    }
  };
  
  return output;
}

// ════════════════════════════════════════════════════════════════════════
//  SECTION 13 – CLI Entry Point
// ════════════════════════════════════════════════════════════════════════

(async () => {
  const id = process.argv[2];
  
  if (!id) {
    console.log(`
╔════════════════════════════════════════════════════════════════════════╗
║     CVE Intelligence Analyzer v6.0 - WITH FILE PATH DETECTION         ║
║                     Find exact vulnerable file locations              ║
╚════════════════════════════════════════════════════════════════════════╝

Usage:
  node deepseakAI.js CVE-2021-45046
  node deepseakAI.js GHSA-xxxx-xxxx-xxxx

Features:
  🔍 Shows exact vulnerable file paths (like src/main/java/...)
  📍 Detects line numbers from patches and advisories
  📦 Shows affected package installation paths
  🔧 Provides copy-paste ready remediation commands

Environment Variables:
  GITHUB_TOKEN=ghp_xxx    Better API rate limits
  NVD_API_KEY=xxxx        Higher NVD rate limits
  SAVE_OUTPUT=1           Save full JSON report

Example Output:
  🔍 VULNERABLE FILE LOCATIONS:
     • src/main/java/org/apache/logging/log4j/core/layout/PatternLayout.java (line 234)
     • log4j-core/src/main/java/org/apache/logging/log4j/core/pattern/MessagePatternConverter.java (line 89)
    `);
    process.exit(1);
  }
  
  try {
    const result = await analyze(id);
    const json = JSON.stringify(result, null, 2);
    
    // Print human-readable output
    console.log("\n" + "═".repeat(72));
    console.log("  VULNERABILITY ANALYSIS REPORT");
    console.log("═".repeat(72) + "\n");
    
    console.log(`📋 CVE: ${result.meta.cve_id}`);
    console.log(`📊 Severity: ${result.vulnerability_summary.severity}`);
    console.log(`🎯 CVSS Score: ${result.vulnerability_summary.cvss_score || "N/A"}`);
    console.log(`✅ Fix Available: ${result.vulnerability_summary.fix_available ? "YES" : "NO"}`);
    
    // Show vulnerable files
    if (result.vulnerable_locations.total_files_found > 0) {
      console.log(`\n🔍 VULNERABLE FILE LOCATIONS (${result.vulnerable_locations.total_files_found} files):`);
      for (const file of result.vulnerable_locations.files.slice(0, 5)) {
        console.log(`   • ${file.path}`);
        if (file.line_numbers?.length) {
          console.log(`     Lines: ${file.line_numbers.map(l => `${l.start}-${l.end}`).join(", ")}`);
        }
        console.log(`     Source: ${file.source} (${Math.round(file.confidence * 100)}% confidence)`);
      }
    }
    
    // Show affected packages
    if (result.affected_packages.length > 0) {
      console.log(`\n📦 AFFECTED PACKAGES:`);
      for (const pkg of result.affected_packages.slice(0, 5)) {
        console.log(`   • ${pkg.name} (${pkg.ecosystem || "system"})`);
      }
    }
    
    // Show quick fix commands
    console.log(`\n🚀 QUICK FIX COMMANDS (copy-paste):`);
    console.log(`   $ ${result.quick_fix_commands.rhel}`);
    console.log(`\n📝 To verify the fix:`);
    console.log(`   $ ${result.quick_fix_commands.verify}`);
    
    if (process.env.SAVE_OUTPUT === "1") {
      const filename = `${result.meta.cve_id}_with_paths.json`;
      fs.writeFileSync(filename, json, "utf8");
      console.log(`\n💾 Full report saved → ${filename}`);
    }
    
    console.log("\n" + "═".repeat(72) + "\n");
    
  } catch (err) {
    console.error("\n❌ Fatal error:", err.message);
    if (process.env.DEBUG) console.error(err.stack);
    process.exit(1);
  }
})();