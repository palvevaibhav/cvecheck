#!/usr/bin/env node
"use strict";

global.File = class File { };

const axios = require("axios");
const https = require("https");
const zlib = require("zlib");
const cheerio = require("cheerio");
const fs = require("fs");
const { execSync } = require("child_process");

let crawled = {};
const TRUSTED_DOMAINS = [
  "github.com", "raw.githubusercontent.com", "api.github.com",
  "git.kernel.org",
  "nvd.nist.gov", "services.nvd.nist.gov", "cve.mitre.org", "cveawg.mitre.org",
  "api.osv.dev",
  "ubuntu.com",
  "debian.org", "security-tracker.debian.org",
  "access.redhat.com", "bugzilla.redhat.com",
  "wpscan.com",
  "bugzilla.suse.com",
  "lists.fedoraproject.org",
  "npmjs.com", "registry.npmjs.org",
];

const API = {
  NVD_CVE: "https://services.nvd.nist.gov/rest/json/cves/2.0",
  OSV_VULNS: "https://api.osv.dev/v1/vulns",
  OSV_QUERY: "https://api.osv.dev/v1/query",
  GHSA_REST: "https://api.github.com/advisories",
  GH_COMMITS: "https://api.github.com/repos",
  KERNEL_PATCH: "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch",
  REDHAT_JSON: "https://access.redhat.com/hydra/rest/securitydata/cve/",
  REDHAT_PAGE: "https://access.redhat.com/security/cve",
  REDHAT_ERRATA: "https://access.redhat.com/errata",
  UBUNTU_CVE: "https://ubuntu.com/security/cves",
  DEBIAN_TRACKER: "https://security-tracker.debian.org/tracker",
  NPM_ADVISORY: "https://www.npmjs.com/advisories",
  NPM_REGISTRY: "https://registry.npmjs.org/-/npm/v1/security/advisories/search",
};

const OSV_DISTRO_BUCKETS = {
  almalinux: "https://osv-vulnerabilities.storage.googleapis.com/AlmaLinux/all.zip",
  alpine: "https://osv-vulnerabilities.storage.googleapis.com/Alpine/all.zip",
  debian: "https://osv-vulnerabilities.storage.googleapis.com/Debian/all.zip",
  redhat: "https://osv-vulnerabilities.storage.googleapis.com/Red%20Hat/all.zip",
  ubuntu: "https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip",
};

const SCORE = {
  osv: 0.20,
  ghsa: 0.95,
  nvd: 0.90,
  redhat: 1.00,
  ubuntu: 0.80,
  debian: 0.80,
  almalinux: 0.75,
  alpine: 0.75,
  crawled: 0.30,
};

const VERSION_RE = /^\d+\.\d+(\.\d+)?(-\d+)?$/;
const COMMIT_RE = /\b[0-9a-f]{40}\b/gi;
const GHCOMMIT_RE = /github\.com\/([^/]+)\/([^/]+)\/commit\/([0-9a-f]{40})/i;
const RHSA_RE = /RHSA-\d{4}:\d{4,}/g;
const CVE_RE = /CVE-\d{4}-\d{4,}/gi;

// ════════════════════════════════════════════════════════════════════════
//  SECTION 1 – HTTP Layer (same as before)
// ════════════════════════════════════════════════════════════════════════

const httpClient = axios.create({
  httpsAgent: new https.Agent({ rejectUnauthorized: false }),
  timeout: 20_000,
  headers: {
    "User-Agent": "cve-intel-analyzer/4.0 (+security-research)",
    Accept: "application/json, text/html, */*",
  },
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
    console.warn(`  [HTTP] ${url} → ${err.message}`);
    return null;
  }
}

async function fetchJSON(url, extraHeaders = {}) {
  const res = await fetchRaw(url, extraHeaders);
  if (!res) return null;
  if (res.status === 404) { console.warn(`  [404] ${url}`); return null; }
  if (res.status === 403) { console.warn(`  [403] ${url}`); return null; }
  if (res.status >= 400) { console.warn(`  [${res.status}] ${url}`); return null; }
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

async function fetchGzipJSON(url) {
  const res = await fetchRaw(url);
  if (!res || res.status >= 400) return null;
  try {
    const buf = await new Promise((resolve, reject) => {
      zlib.gunzip(res.data, (err, result) => (err ? reject(err) : resolve(result)));
    });
    return buf
      .toString("utf8")
      .split("\n")
      .filter(Boolean)
      .map((line) => { try { return JSON.parse(line); } catch { return null; } })
      .filter(Boolean);
  } catch {
    return null;
  }
}

// ════════════════════════════════════════════════════════════════════════
//  SECTION 2 – Shared Utilities
// ════════════════════════════════════════════════════════════════════════

function isValidVersion(v) {
  if (!v || typeof v !== "string") return false;
  if (!VERSION_RE.test(v)) return false;
  if (v.length > 14) return false;
  if (v.split(/[.\-]/).some((p) => parseInt(p, 10) > 9999)) return false;
  return true;
}

const cleanVersions = (arr) =>
  [...new Set((arr ?? []).filter(isValidVersion))];

function isTrusted(url) {
  try {
    const { hostname } = new URL(url);
    return TRUSTED_DOMAINS.some(
      (d) => hostname === d || hostname.endsWith("." + d)
    );
  } catch { return false; }
}

function getDomain(url) {
  try { return new URL(url).hostname.replace(/^www\./, ""); }
  catch { return "unknown"; }
}

function detectIdType(id) {
  if (/^GHSA-/i.test(id)) return "ghsa";
  if (/^CVE-/i.test(id)) return "cve";
  return "unknown";
}

function makeVersionEntry(version, source, score) {
  return { version, source, score };
}

function deduplicateAndRank(entries) {
  const best = new Map();

  for (const e of entries) {
    if (!isValidVersion(e.version)) continue;

    const ex = best.get(e.version);
    if (!ex || e.score > ex.score) {
      best.set(e.version, e);
    }
  }

  return [...best.values()]
    .sort((a, b) => {
      // Prefer higher version numbers FIRST
      const vA = a.version.split(/[.-]/).map(Number);
      const vB = b.version.split(/[.-]/).map(Number);

      for (let i = 0; i < Math.max(vA.length, vB.length); i++) {
        const diff = (vB[i] || 0) - (vA[i] || 0);
        if (diff !== 0) return diff;
      }

      return b.score - a.score;
    })
    .slice(0, 10);
}

function mapSeverityFromCVSS(score) {
  if (!score) return "Unknown";
  if (score >= 9) return "Critical";
  if (score >= 7) return "High";
  if (score >= 4) return "Medium";
  return "Low";
}

function splitVersionsByContext(osv, ghsa, redhat) {
  return {
    library: [
      ...(osv?.fixed_versions ?? []),
      ...(ghsa?.fixed_versions ?? [])
    ],
    os: [
      ...(redhat?.fixed_versions ?? [])
    ]
  };
}

function classifyReferences(urls) {
  const result = { patches: [], advisories: [], exploits: [], other: [] };
  for (const url of urls) {
    if (!url) continue;
    const u = url.toLowerCase();
    if (u.includes("commit") || u.includes("patch") || u.includes("diff") || u.includes("pull"))
      result.patches.push(url);
    else if (u.includes("advisory") || u.includes("security") || u.includes("announce") || u.includes("errata") || u.includes("usn") || u.includes("rhsa") || u.includes("dsa"))
      result.advisories.push(url);
    else if (u.includes("exploit") || u.includes("poc") || u.includes("proof-of-concept") || u.includes("metasploit"))
      result.exploits.push(url);
    else
      result.other.push(url);
  }
  return result;
}

// ════════════════════════════════════════════════════════════════════════
//  SECTION 3 – SOURCE: OSV (same as before)
// ════════════════════════════════════════════════════════════════════════

async function fetchOSV(cveId) {
  console.log("  [OSV] Fetching …");
  const raw = await fetchJSON(`${API.OSV_VULNS}/${cveId}`);
  if (!raw) return null;

  const result = {
    id: raw.id,
    aliases: raw.aliases ?? [],
    related: raw.related ?? [],
    published: raw.published ?? null,
    modified: raw.modified ?? null,
    withdrawn: raw.withdrawn ?? null,
    summary: raw.summary ?? "",
    details: raw.details ?? "",
    severity: [],
    cwes: [],
    credits: [],
    references: [],
    affected: [],
    fixed_versions: [],
    fixed_commits: [],
  };

  for (const s of raw.severity ?? [])
    result.severity.push({ type: s.type, score: s.score });

  for (const c of raw.database_specific?.cwe_ids ?? [])
    result.cwes.push(c);

  for (const c of raw.credits ?? [])
    result.credits.push({ name: c.name, contact: c.contact ?? [] });

  for (const r of raw.references ?? [])
    result.references.push({ type: r.type, url: r.url });

  for (const a of raw.affected ?? []) {
    const pkg = {
      package: {
        name: a.package?.name ?? null,
        ecosystem: a.package?.ecosystem ?? null,
        purl: a.package?.purl ?? null,
      },
      ranges: [],
      versions: a.versions ?? [],
      ecosystem_specific: a.ecosystem_specific ?? {},
      database_specific: a.database_specific ?? {},
      fixed_versions: [],
      fixed_commits: [],
      introduced: [],
      last_affected: [],
    };

    for (const r of a.ranges ?? []) {
      const range = {
        type: r.type,
        repo: r.repo ?? null,
        events: r.events ?? [],
        introduced: [],
        fixed: [],
        last_affected: null,
      };

      for (const e of r.events ?? []) {
        if (e.introduced && e.introduced !== "0") {
          range.introduced.push(e.introduced);
          pkg.introduced.push(e.introduced);
        }
        if (e.fixed) {
          range.fixed.push(e.fixed);
          if (r.type === "GIT") {
            pkg.fixed_commits.push(e.fixed);
            result.fixed_commits.push(e.fixed);
          } else if (isValidVersion(e.fixed)) {
            pkg.fixed_versions.push(e.fixed);
            result.fixed_versions.push(e.fixed);
          }
        }
        if (e.last_affected) {
          range.last_affected = e.last_affected;
          pkg.last_affected.push(e.last_affected);
        }
      }
      pkg.ranges.push(range);
    }

    for (const r of a.database_specific?.unresolved_ranges ?? []) {
      for (const e of r.events ?? []) {
        if (e.fixed && isValidVersion(e.fixed)) {
          pkg.fixed_versions.push(e.fixed);
          result.fixed_versions.push(e.fixed);
        }
      }
    }

    result.affected.push(pkg);
  }

  result.fixed_versions = cleanVersions(result.fixed_versions);
  result.fixed_commits = [...new Set(result.fixed_commits)].slice(0, 10);

  return result;
}

// ════════════════════════════════════════════════════════════════════════
//  SECTION 4 – SOURCE: NVD (same as before)
// ════════════════════════════════════════════════════════════════════════

async function fetchNVD(cveId) {
  if (!/^CVE-/i.test(cveId)) return null;
  console.log("  [NVD] Fetching …");

  const headers = {};
  if (process.env.NVD_API_KEY) headers["apiKey"] = process.env.NVD_API_KEY;

  const raw = await fetchJSON(`${API.NVD_CVE}?cveId=${cveId}`, headers);
  if (!raw) return null;

  const cve = raw.vulnerabilities?.[0]?.cve;
  if (!cve) return null;

  const descriptions = {};
  for (const d of cve.descriptions ?? []) descriptions[d.lang] = d.value;

  const cvssMetrics = { v2: [], v30: [], v31: [], v40: [] };
  const metricMap = {
    cvssMetricV2: "v2",
    cvssMetricV30: "v30",
    cvssMetricV31: "v31",
    cvssMetricV40: "v40",
  };
  for (const [key, label] of Object.entries(metricMap)) {
    for (const m of cve.metrics?.[key] ?? []) {
      const d = m.cvssData ?? {};
      cvssMetrics[label].push({
        source: m.source,
        type: m.type,
        version: d.version,
        vector_string: d.vectorString,
        base_score: d.baseScore,
        base_severity: d.baseSeverity ?? m.baseSeverity,
        exploitability_score: m.exploitabilityScore ?? null,
        impact_score: m.impactScore ?? null,
        attack_vector: d.attackVector,
        attack_complexity: d.attackComplexity,
        privileges_required: d.privilegesRequired,
        user_interaction: d.userInteraction,
        scope: d.scope,
        confidentiality_impact: d.confidentialityImpact,
        integrity_impact: d.integrityImpact,
        availability_impact: d.availabilityImpact,
        access_vector: d.accessVector,
        access_complexity: d.accessComplexity,
        authentication: d.authentication,
        attack_requirements: d.attackRequirements,
      });
    }
  }

  const weaknesses = [];
  for (const w of cve.weaknesses ?? []) {
    for (const d of w.description ?? []) {
      if (d.lang === "en") weaknesses.push({ source: w.source, type: w.type, cwe_id: d.value });
    }
  }

  const configurations = [];
  const fixVersionsFromCPE = [];

  for (const config of cve.configurations ?? []) {
    const parsedConfig = { operator: config.operator ?? null, negate: config.negate ?? false, nodes: [] };

    for (const node of config.nodes ?? []) {
      const parsedNode = { operator: node.operator, negate: node.negate ?? false, cpe_match: [] };

      for (const cpe of node.cpeMatch ?? []) {
        parsedNode.cpe_match.push({
          vulnerable: cpe.vulnerable,
          criteria: cpe.criteria,
          match_criteria_id: cpe.matchCriteriaId,
          version_start_including: cpe.versionStartIncluding ?? null,
          version_start_excluding: cpe.versionStartExcluding ?? null,
          version_end_including: cpe.versionEndIncluding ?? null,
          version_end_excluding: cpe.versionEndExcluding ?? null,
        });

        if (cpe.vulnerable) {
          if (cpe.versionEndExcluding) fixVersionsFromCPE.push(cpe.versionEndExcluding);
          if (cpe.versionEndIncluding) fixVersionsFromCPE.push(cpe.versionEndIncluding);
        }
      }

      parsedConfig.nodes.push(parsedNode);
    }
    configurations.push(parsedConfig);
  }

  const references = (cve.references ?? []).map((r) => ({
    url: r.url,
    source: r.source ?? null,
    tags: r.tags ?? [],
  }));

  const vendor_comments = (cve.vendorComments ?? []).map((v) => ({
    organization: v.organization,
    comment: v.comment,
    last_modified: v.lastModified ?? null,
  }));

  const allScores = [...cvssMetrics.v2, ...cvssMetrics.v30, ...cvssMetrics.v31, ...cvssMetrics.v40]
    .map((m) => m.base_score).filter(Boolean);
  const allSeverities = [...cvssMetrics.v31, ...cvssMetrics.v30, ...cvssMetrics.v40, ...cvssMetrics.v2]
    .map((m) => m.base_severity).filter(Boolean);

  return {
    id: cve.id,
    source_identifier: cve.sourceIdentifier ?? null,
    published: cve.published ?? null,
    last_modified: cve.lastModified ?? null,
    vuln_status: cve.vulnStatus ?? null,
    descriptions,
    cvss_metrics: cvssMetrics,
    weaknesses,
    configurations,
    references,
    vendor_comments,
    fixed_versions: cleanVersions(fixVersionsFromCPE),
    highest_cvss_score: allScores.length ? Math.max(...allScores) : null,
    highest_severity: allSeverities[0] ?? null,
  };
}

// ════════════════════════════════════════════════════════════════════════
//  SECTION 5 – SOURCE: GHSA (same as before)
// ════════════════════════════════════════════════════════════════════════

async function fetchGHSA(id) {
  console.log("  [GHSA] Fetching …");
  const idType = detectIdType(id);
  const headers = { Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" };
  if (process.env.GITHUB_TOKEN) headers["Authorization"] = `Bearer ${process.env.GITHUB_TOKEN}`;

  const url =
    idType === "ghsa"
      ? `${API.GHSA_REST}/${id.toUpperCase()}`
      : `${API.GHSA_REST}?cve_id=${id}&per_page=1`;

  const raw = await fetchJSON(url, headers);
  if (!raw) return null;

  const ghsa = Array.isArray(raw) ? (raw[0] ?? null) : raw;
  if (!ghsa) return null;

  const fixed_versions = [];
  for (const v of ghsa.vulnerabilities ?? []) {
    const fp = v.first_patched_version ?? v.patched_versions ?? null;
    if (fp) {
      const clean = fp.replace(/[^0-9.\-]/g, "").trim();
      if (isValidVersion(clean)) fixed_versions.push(clean);
    }
  }

  return {
    ghsa_id: ghsa.ghsa_id ?? null,
    cve_id: ghsa.cve_id ?? null,
    url: ghsa.html_url ?? null,
    summary: ghsa.summary ?? "",
    description: ghsa.description ?? "",
    severity: ghsa.severity ?? null,
    cvss_score: ghsa.cvss?.score ?? null,
    cvss_vector: ghsa.cvss?.vector_string ?? null,
    cwes: (ghsa.cwes ?? []).map((c) => c.cwe_id),
    published_at: ghsa.published_at ?? null,
    updated_at: ghsa.updated_at ?? null,
    withdrawn_at: ghsa.withdrawn_at ?? null,
    vulnerabilities: (ghsa.vulnerabilities ?? []).map((v) => ({
      package: v.package?.name ?? null,
      ecosystem: v.package?.ecosystem ?? null,
      vulnerable_range: v.vulnerable_version_range ?? null,
      first_patched_version: v.first_patched_version ?? null,
    })),
    identifiers: ghsa.identifiers ?? [],
    references: (ghsa.references ?? []).map((r) => r.url),
    fixed_versions: cleanVersions(fixed_versions),
  };
}

// ════════════════════════════════════════════════════════════════════════
//  SECTION 6 – SOURCE: Red Hat (same as before)
// ════════════════════════════════════════════════════════════════════════

async function fetchRedHat(cveId) {
  if (!/^CVE-/i.test(cveId)) return null;
  console.log("  [RedHat] Fetching …");

  let json = null;
  const jsonData = await fetchJSON(`${API.REDHAT_JSON}${cveId}.json`);

  if (jsonData) {
    json = Array.isArray(jsonData)
      ? (jsonData.find((d) => d.CVE?.toUpperCase() === cveId) ?? jsonData[0] ?? null)
      : jsonData;
  }

  const html = await fetchText(`${API.REDHAT_PAGE}/${cveId}`);

  const result = {
    cve_id: json?.CVE ?? null,
    severity: json?.severity ?? null,
    public_date: json?.public_date ?? null,
    statement: json?.statement ?? null,
    mitigation: json?.mitigation ?? null,
    acknowledgement: json?.acknowledgement ?? null,
    iava: json?.iava ?? null,
    cwe: json?.cwe ?? null,
    bugzilla: json?.bugzilla ? {
      id: json.bugzilla.id ?? null,
      url: json.bugzilla.url ?? null,
      description: json.bugzilla.description ?? null,
    } : null,
    cvss: json?.cvss ? {
      score: json.cvss.cvss_base_score ?? null,
      scoring_vector: json.cvss.cvss_scoring_vector ?? null,
      status: json.cvss.status ?? null,
    } : null,
    cvss3: json?.cvss3 ? {
      score: json.cvss3.cvss3_base_score ?? null,
      scoring_vector: json.cvss3.cvss3_scoring_vector ?? null,
      status: json.cvss3.status ?? null,
    } : null,
    affected_releases: [],
    package_states: [],
    advisories: [],
    fixed_versions: [],
    references: [],
  };

  if (json) {
    for (const rel of json.affected_release ?? []) {
      result.affected_releases.push({
        product_name: rel.product_name ?? null,
        release_date: rel.release_date ?? null,
        advisory: rel.advisory ?? null,
        cpe: rel.cpe ?? null,
        package: rel.package ?? null,
      });

      if (rel.advisory) {
        result.advisories.push({ id: rel.advisory, url: `${API.REDHAT_ERRATA}/${rel.advisory}` });
      }

      if (rel.package) {
        const m = rel.package.match(/[-_](\d+\.\d+(?:\.\d+)?(?:-\d+)?)/);
        if (m && isValidVersion(m[1])) result.fixed_versions.push(m[1]);
      }
    }

    for (const ps of json.package_state ?? []) {
      result.package_states.push({
        product_name: ps.product_name ?? null,
        fix_state: ps.fix_state ?? null,
        package_name: ps.package_name ?? null,
        cpe: ps.cpe ?? null,
      });
    }
  }

  if (html) {
    const $ = cheerio.load(html);

    for (const id of [...new Set(html.match(RHSA_RE) ?? [])]) {
      if (!result.advisories.find((a) => a.id === id)) {
        result.advisories.push({ id, url: `${API.REDHAT_ERRATA}/${id}` });
      }
    }

    $("a[href]").each((_, el) => {
      const href = $(el).attr("href");
      if (href?.startsWith("http")) result.references.push(href);
    });

    for (const v of cleanVersions(html.match(/\b\d+\.\d+(?:\.\d+)?(?:-\d+)?\b/g) ?? [])) {
      result.fixed_versions.push(v);
    }
  }

  result.fixed_versions = cleanVersions(result.fixed_versions);
  result.advisories = [...new Map(result.advisories.map((a) => [a.id, a])).values()];
  result.references = [...new Set(result.references)].slice(0, 25);

  return result;
}

// ════════════════════════════════════════════════════════════════════════
//  SECTION 7 – SOURCE: Ubuntu (same as before)
// ════════════════════════════════════════════════════════════════════════

async function fetchUbuntu(cveId) {
  if (!/^CVE-/i.test(cveId)) return null;
  console.log("  [Ubuntu] Fetching …");

  const raw = await fetchJSON(`${API.UBUNTU_CVE}/${cveId}.json`);
  if (!raw) return null;

  const packages = [];
  for (const pkg of raw.packages ?? []) {
    const releases = {};
    for (const [rel, info] of Object.entries(pkg.statuses ?? {})) {
      releases[rel] = {
        status: info.status,
        fixed_version: info.fixed_version ?? null,
        pocket: info.pocket ?? null,
      };
    }
    packages.push({ name: pkg.name, source_package: pkg.source_package ?? null, releases });
  }

  const allFixed = packages.flatMap((p) =>
    Object.values(p.releases).map((r) => r.fixed_version).filter(Boolean)
  );

  return {
    cve_id: raw.id,
    description: raw.description ?? "",
    published: raw.published_at ?? null,
    priority: raw.priority ?? null,
    notices: (raw.notices ?? []).map((n) => ({
      id: n.id,
      title: n.title ?? null,
      url: `https://ubuntu.com/security/notices/${n.id}`,
    })),
    packages,
    fixed_versions: cleanVersions(allFixed),
  };
}

// ════════════════════════════════════════════════════════════════════════
//  SECTION 8 – SOURCE: Debian (same as before)
// ════════════════════════════════════════════════════════════════════════

async function fetchDebian(cveId) {
  if (!/^CVE-/i.test(cveId)) return null;
  console.log("  [Debian] Fetching …");

  const raw = await fetchJSON(`${API.DEBIAN_TRACKER}/${cveId}`);

  const result = {
    cve_id: cveId,
    scope: null,
    packages: [],
    fixed_versions: [],
    references: [],
    raw: raw,
  };

  if (!raw) return result;

  for (const [pkgName, distros] of Object.entries(raw)) {
    if (pkgName === "scope") { result.scope = distros; continue; }
    const pkg = { name: pkgName, distros: [] };

    for (const [distro, info] of Object.entries(distros ?? {})) {
      pkg.distros.push({
        distro,
        status: info.status ?? null,
        urgency: info.urgency ?? null,
        fixed_version: info.fixed_version ?? null,
        nodsa: info.nodsa ?? null,
      });
      if (info.fixed_version) result.fixed_versions.push(info.fixed_version);
    }
    result.packages.push(pkg);
  }

  result.fixed_versions = cleanVersions(result.fixed_versions);
  return result;
}

// ════════════════════════════════════════════════════════════════════════
//  SECTION 9 – SOURCE: OSV Linux Distro Bucket (same as before)
// ════════════════════════════════════════════════════════════════════════

async function fetchLinuxDistroVulnList(distroKey, cveId) {
  const url = OSV_DISTRO_BUCKETS[distroKey];
  if (!url) return null;

  console.log(`  [${distroKey}] Fetching OSV bucket …`);
  const records = await fetchGzipJSON(url);
  if (!records) return null;

  const matches = records.filter((r) =>
    r.id === cveId || (r.aliases ?? []).some((a) => a.toUpperCase() === cveId)
  );

  if (matches.length === 0) return { distro: distroKey, found: false, records: [] };

  const fixed_versions = [];
  for (const rec of matches) {
    for (const a of rec.affected ?? []) {
      for (const range of a.ranges ?? []) {
        for (const e of range.events ?? []) {
          if (e.fixed && isValidVersion(e.fixed)) fixed_versions.push(e.fixed);
        }
      }
    }
  }

  return {
    distro: distroKey,
    found: true,
    records: matches,
    fixed_versions: cleanVersions(fixed_versions),
  };
}

// ════════════════════════════════════════════════════════════════════════
//  SECTION 10 – SOURCE: NPM Advisory (same as before)
// ════════════════════════════════════════════════════════════════════════

async function fetchNPM(cveId) {
  console.log("  [NPM] Fetching …");

  const url = `${API.NPM_REGISTRY}?text=${cveId}&size=5`;
  const raw = await fetchJSON(url);

  if (!raw) {
    return {
      search_url: `${API.NPM_ADVISORY}?search=${cveId}`,
      advisories: [],
      fixed_versions: [],
    };
  }

  const advisories = [];
  const fixed_versions = [];

  for (const adv of raw.objects ?? []) {
    const advisory = adv.advisory ?? adv;
    advisories.push({
      id: advisory.id ?? null,
      ghsa_id: advisory.github_advisory_id ?? null,
      cve: advisory.cve ?? [],
      title: advisory.title ?? null,
      severity: advisory.severity ?? null,
      module_name: advisory.module_name ?? null,
      vulnerable_versions: advisory.vulnerable_versions ?? null,
      patched_versions: advisory.patched_versions ?? null,
      url: advisory.url ?? `https://www.npmjs.com/advisories/${advisory.id}`,
      overview: advisory.overview ?? null,
      recommendation: advisory.recommendation ?? null,
    });
    if (advisory.patched_versions) {
      const v = advisory.patched_versions.replace(/[^0-9.\-]/g, "").trim();
      if (isValidVersion(v)) fixed_versions.push(v);
    }
  }

  return {
    search_url: url,
    advisories,
    fixed_versions: cleanVersions(fixed_versions),
  };
}

// ════════════════════════════════════════════════════════════════════════
//  SECTION 11 – NEW: REMEDIATION MOPS GENERATOR
// ════════════════════════════════════════════════════════════════════════

/**
 * Generate step-by-step remediation commands for RHEL/CentOS/AlmaLinux/Rocky
 */
function generateRHELRemediationMOPs(cveId, redhatData, rankedVersions, allCommits, sources) {
  const steps = [];
  const commands = [];
  const verificationCommands = [];

  steps.push({
    step: 1,
    title: "System Information Collection",
    description: "Collect current system information to understand the environment",
    commands: [
      "cat /etc/redhat-release",
      "uname -a",
      "rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\n' | grep -E '(kernel|openssl|curl|httpd|nginx|mysql|postgresql|java|node|python)' | head -20",
      "subscription-manager status 2>/dev/null || echo 'No subscription-manager found'"
    ],
    verification: "Verify output shows RHEL version and installed packages"
  });

  // Check if Red Hat provided advisory
  if (redhatData && redhatData.advisories && redhatData.advisories.length > 0) {
    steps.push({
      step: steps.length + 1,
      title: "Apply Official Red Hat Errata",
      description: `Red Hat has released official advisories for ${cveId}`,
      commands: redhatData.advisories.map(adv => [
        `echo "Checking advisory: ${adv.id}"`,
        `yum update --advisory=${adv.id} -y 2>/dev/null || dnf update --advisory=${adv.id} -y 2>/dev/null`
      ]).flat(),
      verification: `rpm -qa --changelog | grep -A5 -B5 "${cveId}" | head -20`
    });
  }

  // Check affected releases
  if (redhatData && redhatData.affected_releases && redhatData.affected_releases.length > 0) {
    const packages = [...new Set(redhatData.affected_releases.map(r => {
      const match = r.package?.match(/^([a-zA-Z0-9_-]+)/);
      return match ? match[1] : null;
    }).filter(Boolean))];

    if (packages.length > 0) {
      steps.push({
        step: steps.length + 1,
        title: "Update Affected Packages",
        description: `The following packages are affected and have available updates: ${packages.join(', ')}`,
        commands: [
          "# Update all packages (recommended for security)",
          "yum update -y 2>/dev/null || dnf update -y 2>/dev/null",
          "",
          "# OR update specific packages only:",
          ...packages.map(pkg => `yum update ${pkg} -y 2>/dev/null || dnf update ${pkg} -y 2>/dev/null`)
        ],
        verification: `echo "Run 'rpm -q ${packages[0] || '--all'}' to verify versions"`
      });
    }
  }

  // Version-based remediation
  if (rankedVersions && rankedVersions.length > 0) {
    const recommendedVersion = rankedVersions[0].version;
    steps.push({
      step: steps.length + 1,
      title: "Target Version Upgrade",
      description: `Upgrade to version ${recommendedVersion} or later`,
      commands: [
        `# For package managers:`,
        `yum list available --showduplicates | grep -E '(${recommendedVersion.split('.')[0]}\\.[0-9]+)'`,
        `yum install <package-name>-${recommendedVersion} -y`,
        "",
        `# For language-specific packages:`,
        `npm update --depth 0  # For Node.js packages`,
        `pip install --upgrade <package>==${recommendedVersion}  # For Python packages`,
        `go get -u <package>@${recommendedVersion}  # For Go modules`
      ],
      verification: `<package-name> --version | grep ${recommendedVersion.split('.')[0]}`
    });
  }

  // Commit-based remediation (source builds)
  if (allCommits && allCommits.length > 0) {
    const commitHash = allCommits[0].substring(0, 12);
    steps.push({
      step: steps.length + 1,
      title: "Source Code Patch (If Building From Source)",
      description: `Apply the security patch commit: ${allCommits[0]}`,
      commands: [
        `# Clone/fetch the repository`,
        `git fetch origin`,
        `git cherry-pick ${allCommits[0]}`,
        `# Or apply as a patch:`,
        `wget https://github.com/owner/repo/commit/${allCommits[0]}.patch`,
        `git apply ${commitHash}.patch`,
        `# Rebuild and redeploy the application`
      ],
      verification: `git log --oneline | grep ${commitHash}`
    });
  }

  // Kernel-specific remediation
  if (cveId.includes('CVE') && redhatData?.affected_releases?.some(r => r.package?.includes('kernel'))) {
    steps.push({
      step: steps.length + 1,
      title: "Kernel Update (Requires Reboot)",
      description: "A kernel update is available for this CVE",
      commands: [
        "# Update kernel package",
        "yum update kernel -y 2>/dev/null || dnf update kernel -y 2>/dev/null",
        "",
        "# Verify the new kernel is installed",
        "rpm -q kernel",
        "",
        "# Schedule reboot (critical for kernel updates to take effect)",
        "shutdown -r +5 'System will reboot in 5 minutes for kernel security update'",
        "# Or reboot immediately after saving work:",
        "# reboot"
      ],
      verification: "uname -r"
    });
  }

  // Mitigation workarounds (if no fix available)
  if (rankedVersions.length === 0 && allCommits.length === 0) {
    steps.push({
      step: steps.length + 1,
      title: "Mitigation Workarounds (No Official Fix Available)",
      description: "Apply temporary mitigations while waiting for official fix",
      commands: [
        "# 1. Disable vulnerable feature if possible",
        "# Example: For Apache Struts, disable certain endpoints",
        "",
        "# 2. Apply network restrictions",
        "firewall-cmd --add-rich-rule='rule family=ipv4 source address=10.0.0.0/8 port port=8080 protocol=tcp reject'",
        "firewall-cmd --runtime-to-permanent",
        "",
        "# 3. Use Web Application Firewall (WAF) rules",
        "# 4. Implement additional input validation",
        "# 5. Monitor logs for exploitation attempts",
        "journalctl -f | grep -i '${cveId}'"
      ],
      verification: "firewall-cmd --list-rich-rules"
    });
  }

  // Post-remediation verification
  steps.push({
    step: steps.length + 1,
    title: "Post-Remediation Verification",
    description: "Verify the fix was applied correctly",
    commands: [
      `# Check package versions`,
      `rpm -qa | sort | grep -E '(openssl|curl|httpd|kernel|java)' | head -10`,
      "",
      `# Check if CVE is still reported`,
      `yum updateinfo list ${cveId} 2>/dev/null || dnf updateinfo list ${cveId} 2>/dev/null`,
      "",
      `# Run vulnerability scanner (if available)`,
      `# oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_standard /usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml`,
      "",
      `# Test application functionality`,
      `curl -I http://localhost/ || echo "Test your application endpoints"`
    ],
    verification: "All checks should show fixed versions and no vulnerability"
  });

  return {
    cve_id: cveId,
    generated_at: new Date().toISOString(),
    target_os: "RHEL/CentOS/AlmaLinux/Rocky Linux 7/8/9",
    requires_reboot: steps.some(s => s.title.includes("Kernel")),
    total_steps: steps.length,
    steps: steps,
    quick_commands: {
      full_update: "yum update -y 2>/dev/null || dnf update -y",
      check_status: `yum updateinfo list ${cveId} 2>/dev/null || dnf updateinfo list ${cveId} 2>/dev/null`,
      rollback: "yum history undo last 2>/dev/null || dnf history undo last"
    }
  };
}

/**
 * Generate remediation steps for other package managers
 */
function generateGenericRemediationMOPs(cveId, npmData, rankedVersions, allCommits) {
  const steps = [];

  // NPM/Yarn remediation
  if (npmData && npmData.advisories && npmData.advisories.length > 0) {
    steps.push({
      step: 1,
      title: "NPM/Yarn Package Update",
      description: `Update vulnerable npm packages for ${cveId}`,
      commands: npmData.advisories.map(adv => [
        `# Advisory: ${adv.title}`,
        `# Affected module: ${adv.module_name}`,
        `# Patched versions: ${adv.patched_versions}`,
        `npm update ${adv.module_name} --depth 0`,
        `# OR yarn upgrade ${adv.module_name}`
      ]).flat(),
      verification: `npm list ${npmData.advisories[0]?.module_name} 2>/dev/null || yarn list --pattern ${npmData.advisories[0]?.module_name}`
    });
  }

  // Docker/Container remediation
  steps.push({
    step: steps.length + 1,
    title: "Container/Image Remediation",
    description: "If running in containers, rebuild with patched base images",
    commands: [
      "# Update Dockerfile base image",
      "FROM <base-image>:latest  # or specific patched version",
      "",
      "# Rebuild image",
      "docker build --no-cache -t your-app:patched .",
      "",
      "# Scan for vulnerabilities",
      "docker scan your-app:patched",
      "trivy image your-app:patched",
      "",
      "# Deploy updated containers",
      "docker-compose down && docker-compose up -d"
    ],
    verification: "docker scan your-app:patched | grep -i 'vulnerability'"
  });

  // Kubernetes remediation
  steps.push({
    step: steps.length + 1,
    title: "Kubernetes Deployment Update",
    description: "Rolling update for Kubernetes deployments",
    commands: [
      "# Update image tag in deployment",
      "kubectl set image deployment/your-deployment your-container=your-image:patched",
      "",
      "# Monitor rollout status",
      "kubectl rollout status deployment/your-deployment",
      "",
      "# Rollback if needed",
      "kubectl rollout undo deployment/your-deployment"
    ],
    verification: "kubectl get pods -l app=your-app -o wide"
  });

  return {
    cve_id: cveId,
    generated_at: new Date().toISOString(),
    target_os: "Cross-platform (Node.js/Docker/K8s)",
    total_steps: steps.length,
    steps: steps
  };
}

/**
 * Generate comprehensive MOPs combining all sources
 */
function generateCompleteMOPs(cveId, allData) {
  const {
    redhat,
    rankedVersions,
    allCommits,
    npm,
    sources
  } = allData;

  const mops = {
    cve_id: cveId,
    generated_at: new Date().toISOString(),
    executive_summary: {
      severity: allData.summary?.severity || "Unknown",
      cvss_score: allData.summary?.cvss_score || "Unknown",
      fix_available: allData.summary?.fix_available || false,
      fix_type: allData.summary?.fix_type || "none",
      recommended_action: "",
      estimated_downtime: "Varies based on update type"
    },
    remediation_plans: {}
  };

  // Set recommended action
  if (mops.executive_summary.fix_available) {
    if (mops.executive_summary.fix_type === "version") {
      mops.executive_summary.recommended_action = `Upgrade to version ${rankedVersions[0]?.version || "latest"} or later`;
    } else if (mops.executive_summary.fix_type === "commit") {
      mops.executive_summary.recommended_action = `Apply security patch commit ${allCommits[0]?.substring(0, 12) || "available"}`;
    }
  } else {
    mops.executive_summary.recommended_action = "No official fix available - implement mitigations and monitor";
  }

  // Generate RHEL-specific MOPs
  if (redhat && (redhat.affected_releases?.length > 0 || redhat.advisories?.length > 0)) {
    mops.remediation_plans.rhel = generateRHELRemediationMOPs(
      cveId, redhat, rankedVersions, allCommits, sources
    );
  }

  // Generate generic MOPs for other environments
  if (npm && npm.advisories?.length > 0) {
    mops.remediation_plans.npm = generateGenericRemediationMOPs(
      cveId, npm, rankedVersions, allCommits
    );
  }

  // Add rollback plan
  mops.rollback_plan = {
    description: "Procedure to revert changes if issues occur",
    commands: [
      "# For package updates:",
      "yum history  # Find the transaction ID",
      "yum history undo <transaction-id> -y",
      "",
      "# For git patches:",
      "git reset --hard HEAD~1",
      "",
      "# For container rollback:",
      "docker tag your-app:previous your-app:latest",
      "docker-compose up -d"
    ]
  };

  // Add monitoring commands
  mops.monitoring = {
    description: "Post-remediation monitoring",
    commands: [
      `# Watch for exploitation attempts`,
      `journalctl -fu --since "1 hour ago" | grep -i "${cveId.replace('-', '')}"`,
      "",
      `# Monitor system logs for related errors`,
      `tail -f /var/log/messages /var/log/secure | grep -i error`,
      "",
      `# Check for unexpected service restarts`,
      `systemctl --failed`,
      "",
      `# Monitor resource usage`,
      `top -b -n 1 | head -20`
    ]
  };

  return mops;
}

// ════════════════════════════════════════════════════════════════════════
//  SECTION 12 – MAIN ORCHESTRATOR (Enhanced with MOPs)
// ════════════════════════════════════════════════════════════════════════

async function analyze(id) {
  const startAt = Date.now();
  const normalised = id.trim().toUpperCase();
  const idType = detectIdType(normalised);

  console.log(`\n${"═".repeat(72)}`);
  console.log(`  CVE Intelligence Analyzer v5.0 - WITH REMEDIATION MOPS`);
  console.log(`  Target: ${normalised}  [${idType}]`);
  console.log(`${"═".repeat(72)}\n`);

  // ── Parallel fetch: OSV + NVD + GHSA ─────────────────
  console.log("[Phase 1] Fetching primary sources in parallel …");
  const [osv, nvd, ghsa] = await Promise.all([
    fetchOSV(normalised),
    fetchNVD(normalised),
    fetchGHSA(normalised),
  ]);

  // ── Sequential fetch ────────────────────────────────
  console.log("\n[Phase 2] Fetching secondary sources …");
  const redhat = await fetchRedHat(normalised);
  await sleep(500);
  const ubuntu = await fetchUbuntu(normalised);
  await sleep(300);
  const debian = await fetchDebian(normalised);
  await sleep(300);
  const npm = await fetchNPM(normalised);

  // ── Distro buckets ──────────────────────────────────
  console.log("\n[Phase 3] Fetching Linux distro OSV buckets …");
  const [almalinux, alpine] = await Promise.all([
    fetchLinuxDistroVulnList("almalinux", normalised),
    fetchLinuxDistroVulnList("alpine", normalised),
  ]);

  // ── Aggregate versions with scoring ─────────────────
  const scoredEntries = [];
  const addVersions = (arr, source, score) =>
    arr.forEach((v) => scoredEntries.push(makeVersionEntry(v, source, score)));

  addVersions(osv?.fixed_versions ?? [], "OSV", SCORE.osv);
  addVersions(ghsa?.fixed_versions ?? [], "GHSA", SCORE.ghsa);
  addVersions(nvd?.fixed_versions ?? [], "NVD", SCORE.nvd);
  addVersions(redhat?.fixed_versions ?? [], "RedHat", SCORE.redhat);
  addVersions(ubuntu?.fixed_versions ?? [], "Ubuntu", SCORE.ubuntu);
  addVersions(debian?.fixed_versions ?? [], "Debian", SCORE.debian);
  addVersions(almalinux?.fixed_versions ?? [], "AlmaLinux", SCORE.almalinux);
  addVersions(alpine?.fixed_versions ?? [], "Alpine", SCORE.alpine);

  const rankedVersions = deduplicateAndRank(scoredEntries);

  // ── All commits ──────────────────────────────────────
  const allCommits = [...new Set([
    ...(osv?.fixed_commits ?? []),
    ...Object.values(crawled || {}).flatMap((d) => d.commits || []),
  ])].slice(0, 15);

  // ── Collect all reference URLs ───────────────────────
  const allRefUrls = [
    ...(osv?.references ?? []).map((r) => r.url),
    ...(nvd?.references ?? []).map((r) => r.url),
    ...(ghsa?.references ?? []),
    ...(redhat?.references ?? []),
  ].filter(Boolean);

  // Skip crawling if NO_CRAWL is set

  if (process.env.NO_CRAWL !== "1") {
    console.log("\n[Phase 4] Deep crawling trusted references …");
    crawled = await crawlAllReferences(allRefUrls);
  } else {
    console.log("\n[Phase 4] Skipping crawling (NO_CRAWL=1)");
  }

  for (const [domain, data] of Object.entries(crawled)) {
    addVersions(data.versions, `crawled:${domain}`, SCORE.crawled);
  }

  const references = classifyReferences(allRefUrls);

  // ── Aggregate summary ────────────────────────────────

  const split = splitVersionsByContext(osv, ghsa, redhat);
  const fixedVersions = {
  library: cleanVersions(split.library),
  os: cleanVersions(split.os)
};
  const topScore = rankedVersions[0]?.score ?? 0;
  const confidence = topScore >= SCORE.ghsa ? "HIGH" : topScore >= SCORE.debian ? "MEDIUM" : "LOW";
  const fix_available = fixedVersions.length > 0 || allCommits.length > 0;
  const fix_type =
  (fixedVersions.library?.length > 0 || fixedVersions.os?.length > 0)
    ? "version"
    : allCommits.length > 0
      ? "commit"
      : "none";

  const activeSources = [
    osv && "OSV",
    nvd && "NVD",
    ghsa && "GHSA",
    redhat && (redhat.cve_id || redhat.affected_releases?.length) && "RedHat",
    ubuntu && "Ubuntu",
    debian && "Debian",
    almalinux?.found && "AlmaLinux",
    alpine?.found && "Alpine",
    npm?.advisories?.length && "NPM",
  ].filter(Boolean);
  const cvssScore = nvd?.highest_cvss_score ?? ghsa?.cvss_score ?? null;

  const summary = {
    description: osv?.summary || nvd?.descriptions?.en || ghsa?.summary || "",
    // severity: (() => {
    //   if (osv?.severity?.[0]?.type) return osv.severity[0].type;
    //   if (ghsa?.severity) return ghsa.severity;
    //   if (nvd?.cvss_metrics?.v31?.[0]?.base_severity) return nvd.cvss_metrics.v31[0].base_severity;
    //   return null;
    // })(),
    cvss_score: cvssScore,
  severity: mapSeverityFromCVSS(cvssScore),
    cvss_score: nvd?.highest_cvss_score ?? ghsa?.cvss_score ?? null,
    cvss_vector: nvd?.cvss_metrics?.v31?.[0]?.vector_string ?? ghsa?.cvss_vector ?? null,
    cwes: [...new Set([...(osv?.cwes ?? []), ...(ghsa?.cwes ?? []), ...(nvd?.weaknesses ?? []).map((w) => w.cwe_id)])],
    published: osv?.published ?? nvd?.published ?? ghsa?.published_at ?? null,
    modified: osv?.modified ?? nvd?.last_modified ?? ghsa?.updated_at ?? null,
    fix_available,
    fix_type,
    fixed_versions: fixedVersions,
    fixed_commits: allCommits,
    confidence,
    scored_versions: rankedVersions,
     how_to_fix: (() => {
  if (fixedVersions.library?.length > 0) {
    return `Upgrade application dependency to ${fixedVersions.library[0]} or later`;
  }
  if (fixedVersions.os?.length > 0) {
    return `Apply OS patch version ${fixedVersions.os[0]}`;
  }
  if (allCommits.length > 0) {
    return `Apply patch commit ${allCommits[0].substring(0,12)}`;
  }
  return "No fix available";
})(),
    active_sources: activeSources,
  };

  // ── Generate Remediation MOPS ────────────────────────
  console.log("\n[Phase 5] Generating Remediation MOPS …");
  const mops = generateCompleteMOPs(normalised, {
    redhat,
    rankedVersions,
    allCommits,
    npm,
    sources: activeSources,
    summary
  });

  // ════════════════════════════════════════════════════════════════════
  //  Final output object
  // ════════════════════════════════════════════════════════════════════
  const output = {
    meta: {
      cve_id: normalised,
      id_type: idType,
      run_at: new Date().toISOString(),
      duration_ms: Date.now() - startAt,
    },
    summary,
    mops,  // ← NEW: Step-by-step remediation MOPS
    sources: {
      osv,
      nvd,
      ghsa,
      redhat,
      ubuntu,
      debian,
      almalinux,
      alpine,
      npm,
    },
    references,
    crawled,
  };

  return output;
}

// ════════════════════════════════════════════════════════════════════════
//  SECTION 13 – CLI Entry Point
// ════════════════════════════════════════════════════════════════════════

(async () => {
  const id = process.argv[2];

  if (!id) {
    process.stderr.write([
      "",
      "  CVE Intelligence Analyzer v5.0 - WITH REMEDIATION MOPS",
      "  ─────────────────────────────────────────────────────────────",
      "  Usage:",
      "    node cve_analyzer.js CVE-2022-42889",
      "    node cve_analyzer.js GHSA-xxxx-xxxx-xxxx",
      "",
      "  Optional env vars:",
      "    GITHUB_TOKEN=ghp_xxx    GitHub API rate limit: 60 → 5000 req/hr",
      "    NVD_API_KEY=xxxx        NVD API rate limit:   5  → 50  req/30s",
      "    SAVE_OUTPUT=1           Write <CVE_ID>.json to current directory",
      "    NO_CRAWL=1              Skip trusted reference crawling",
      "",
      "  OUTPUT INCLUDES:",
      "    - Step-by-step RHEL remediation commands",
      "    - Package update instructions",
      "    - Kernel update procedures (with reboot)",
      "    - Mitigation workarounds when no fix available",
      "    - Post-remediation verification steps",
      "    - Rollback procedures",
      "",
    ].join("\n"));
    process.exit(1);
  }

  try {
    const result = await analyze(id);
    const json = JSON.stringify(result, null, 2);

    // Print summary first
    console.log("\n" + "═".repeat(72));
    console.log("  CVE INTELLIGENCE REPORT with REMEDIATION MOPS");
    console.log("═".repeat(72) + "\n");

    console.log(`📋 CVE: ${result.meta.cve_id}`);
    console.log(`📊 Severity: ${result.summary.severity || "Unknown"}`);
    console.log(`🎯 CVSS Score: ${result.summary.cvss_score || "N/A"}`);
    console.log(`✅ Fix Available: ${result.summary.fix_available ? "YES" : "NO"}`);
    console.log(`🔧 Fix Type: ${result.summary.fix_type}`);
    console.log(`🎯 Confidence: ${result.summary.confidence}`);
    console.log(`\n Recommended Action: ${result.summary.how_to_fix}`);

    // Print MOPS summary
    console.log("\n" + "─".repeat(72));
    console.log("  REMEDIATION MOPS (Method of Procedure)");
    console.log("─".repeat(72));

    const mops = result.mops;
    console.log(`\n📋 Executive Summary:`);
    console.log(`   Severity: ${mops.executive_summary.severity}`);
    console.log(`   CVSS Score: ${mops.executive_summary.cvss_score}`);
    console.log(`   Fix Available: ${mops.executive_summary.fix_available}`);
    console.log(`   Recommended: ${mops.executive_summary.recommended_action}`);
    console.log(`   Estimated Downtime: ${mops.executive_summary.estimated_downtime}`);

    if (mops.remediation_plans.rhel) {
      console.log(`\n📦 RHEL Remediation Steps (${mops.remediation_plans.rhel.total_steps} steps):`);
      for (const step of mops.remediation_plans.rhel.steps) {
        console.log(`\n   Step ${step.step}: ${step.title}`);
        console.log(`   └─ ${step.description}`);
        console.log(`   Commands:`);
        for (const cmd of step.commands.slice(0, 3)) {
          if (cmd && !cmd.startsWith('#')) {
            console.log(`      $ ${cmd}`);
          } else if (cmd) {
            console.log(`      ${cmd}`);
          }
        }
        if (step.commands.length > 3) {
          console.log(`      ... and ${step.commands.length - 3} more commands`);
        }
      }
    }

    if (mops.rollback_plan) {
      console.log(`\n🔄 Rollback Plan:`);
      console.log(`   ${mops.rollback_plan.description}`);
      console.log(`   Quick rollback: ${mops.rollback_plan.commands[1] || 'yum history undo'}`);
    }

    console.log("\n" + "═".repeat(72));
    console.log("  Full JSON output below (including all raw data)");
    console.log("═".repeat(72) + "\n");

    // Print limited JSON to avoid overwhelming terminal
    const limitedOutput = {
      ...result,
      mops: {
        ...result.mops,
        remediation_plans: {
          rhel: result.mops.remediation_plans.rhel ? {
            ...result.mops.remediation_plans.rhel,
            steps: result.mops.remediation_plans.rhel.steps.map(s => ({
              ...s,
              commands: s.commands.slice(0, 5)  // Limit displayed commands
            }))
          } : undefined
        }
      },
      sources: {
        osv: result.sources.osv ? { id: result.sources.osv.id, fixed_versions: result.sources.osv.fixed_versions } : null,
        nvd: result.sources.nvd ? { id: result.sources.nvd.id, highest_cvss_score: result.sources.nvd.highest_cvss_score } : null,
        redhat: result.sources.redhat ? { cve_id: result.sources.redhat.cve_id, advisories: result.sources.redhat.advisories?.length } : null
      }
    };

    if (process.env.SAVE_OUTPUT === "1") {
      const filename = `${result.meta.cve_id}_with_mops.json`;
      fs.writeFileSync(filename, json, "utf8");
      console.log(`\n💾  Full report saved → ${filename}`);
      console.log(`   (Includes all raw data and complete MOPS)`);
    }

    // Print quick reference commands
    console.log("\n" + "═".repeat(72));
    console.log("  QUICK REFERENCE COMMANDS (copy-paste ready)");
    console.log("═".repeat(72));

    if (mops.remediation_plans.rhel) {
      console.log("\n# For RHEL/CentOS/AlmaLinux/Rocky:");
      console.log(mops.remediation_plans.rhel.quick_commands.full_update);
      console.log(mops.remediation_plans.rhel.quick_commands.check_status);
      console.log("\n# To verify after update:");
      console.log(`rpm -qa --changelog | grep -i "${result.meta.cve_id}" | head -5`);
      console.log("done")
    }

  } catch (err) {
    console.error("\nFatal error:", err.message);
    if (process.env.DEBUG) console.error(err.stack);
    process.exit(1);
  }
})();

// Keep the crawlAllReferences function (simplified version)
async function crawlAllReferences(allRefs) {
  const byDomain = {};
  const visited = new Set();
  const trusted = allRefs.filter(isTrusted);

  if (!trusted.length) return byDomain;

  console.log(`  [Crawl] Processing ${trusted.length} trusted URL(s) …`);

  for (const url of trusted.slice(0, 10)) {  // Limit to 10 URLs
    const domain = getDomain(url);

    // Simple fetch without deep crawling
    const text = await fetchText(url);
    if (!text) continue;

    const versions = cleanVersions(text.match(/\b\d+\.\d+(?:\.\d+)?(?:-\d+)?\b/g) ?? []);
    const commits = [...new Set((text.match(COMMIT_RE) ?? []))].slice(0, 5);

    if (!byDomain[domain]) byDomain[domain] = { pages: [], versions: [], commits: [] };
    byDomain[domain].pages.push({ url, title: "", text_excerpt: text.slice(0, 500) });
    byDomain[domain].versions = cleanVersions([...byDomain[domain].versions, ...versions]);
    byDomain[domain].commits = [...new Set([...byDomain[domain].commits, ...commits])].slice(0, 10);

    await sleep(200);
  }

  return byDomain;
}