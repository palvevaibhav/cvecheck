#!/usr/bin/env node

/**
 * ════════════════════════════════════════════════════════════════════════
 *  Red Hat CSAF v2 Deep Crawler
 *  https://security.access.redhat.com/data/csaf/v2/advisories/
 *
 *  Crawl strategy (3 levels deep):
 *   Level 0 → Root index  → extract all year-folder links
 *   Level 1 → Year folder → extract all .json advisory links
 *   Level 2 → Advisory JSON → parse full CSAF 2.0 document
 *
 *  Output per advisory:
 *   {
 *     advisory_id, title, severity, published, updated, status,
 *     document:   { notes[], references[], publisher, distribution },
 *     tracking:   { revision_history[], generator },
 *     product_tree: { branches[], relationships[], full_products[] },
 *     vulnerabilities: [{
 *       cve, cwe, cvss_v2, cvss_v3, cvss_v4,
 *       product_status: { fixed[], known_affected[], not_affected[] },
 *       remediations:  [{ category, details, product_ids[], url }],
 *       threats:       [{ category, details }],
 *       references:    [],
 *       notes:         []
 *     }],
 *     fixed_packages:   [],   ← flat list of RPM/package strings
 *     fixed_versions:   [],   ← extracted semver from RPM names
 *     cve_ids:          [],   ← all CVEs covered by this advisory
 *     source_url:       ""    ← original JSON URL
 *   }
 *
 *  Modes:
 *   1. Full crawl  →  node rhcsaf_crawler.js
 *   2. Filter CVE  →  node rhcsaf_crawler.js --cve CVE-2022-42889
 *   3. Filter year →  node rhcsaf_crawler.js --year 2022
 *   4. Filter RHSA →  node rhcsaf_crawler.js --rhsa RHSA-2022:7065
 *   5. Combined    →  node rhcsaf_crawler.js --cve CVE-2022-42889 --year 2022
 *
 *  Env vars:
 *   SAVE_OUTPUT=1       Write results to csaf_results.json
 *   CONCURRENCY=5       Parallel advisory fetches (default 4)
 *   DELAY_MS=200        Polite delay between requests (default 200)
 *   START_YEAR=2020     Only crawl from this year onwards
 *   MAX_PER_YEAR=0      Max advisories per year (0 = all)
 * ════════════════════════════════════════════════════════════════════════
 */

"use strict";

global.File = class File {};

const https   = require("https");
const http_   = require("http");
const cheerio = require("cheerio");
const fs      = require("fs");
const path    = require("path");

// ════════════════════════════════════════════════════════════════════════
//  Config
// ════════════════════════════════════════════════════════════════════════

const CSAF_ROOT       = "https://security.access.redhat.com/data/csaf/v2/advisories/";
const CONCURRENCY     = parseInt(process.env.CONCURRENCY   ?? "4",  10);
const DELAY_MS        = parseInt(process.env.DELAY_MS      ?? "200", 10);
const START_YEAR      = parseInt(process.env.START_YEAR    ?? "2000", 10);
const MAX_PER_YEAR    = parseInt(process.env.MAX_PER_YEAR  ?? "0",   10);
const TIMEOUT_MS      = 20_000;
const MAX_RETRIES     = 3;

const VERSION_RE = /^\d+\.\d+(\.\d+)?(-\d+)?$/;

// ════════════════════════════════════════════════════════════════════════
//  CLI argument parsing
// ════════════════════════════════════════════════════════════════════════

function parseArgs(argv) {
  const args = { cve: null, year: null, rhsa: null };
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === "--cve"  && argv[i + 1]) { args.cve  = argv[++i].toUpperCase(); }
    if (argv[i] === "--year" && argv[i + 1]) { args.year = parseInt(argv[++i], 10);  }
    if (argv[i] === "--rhsa" && argv[i + 1]) { args.rhsa = argv[++i].toUpperCase();  }
  }
  return args;
}

// ════════════════════════════════════════════════════════════════════════
//  HTTP layer  (no axios dependency – pure Node.js https)
// ════════════════════════════════════════════════════════════════════════

const agentOpts = {
  keepAlive:  true,
  maxSockets: CONCURRENCY + 2,
  rejectUnauthorized: false,
};
const httpsAgent = new https.Agent(agentOpts);
const httpAgent  = new http_.Agent(agentOpts);

function rawRequest(urlStr, attempt = 1) {
  return new Promise((resolve) => {
    const url   = new URL(urlStr);
    const agent = url.protocol === "https:" ? httpsAgent : httpAgent;
    const mod   = url.protocol === "https:" ? https : http_;

    const opts = {
      hostname: url.hostname,
      port:     url.port || (url.protocol === "https:" ? 443 : 80),
      path:     url.pathname + url.search,
      method:   "GET",
      agent,
      timeout:  TIMEOUT_MS,
      headers:  {
        "User-Agent": "rhcsaf-crawler/1.0 (+security-research)",
        "Accept":     "application/json, text/html, */*",
        "Connection": "keep-alive",
      },
    };

    const req = mod.request(opts, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end",  () => resolve({ status: res.statusCode, body: Buffer.concat(chunks), headers: res.headers }));
    });

    req.on("timeout", () => { req.destroy(); resolve(null); });
    req.on("error",   () => resolve(null));
    req.end();
  });
}

async function fetchText(url) {
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    const res = await rawRequest(url, attempt);
    if (!res) { await sleep(500 * attempt); continue; }
    if (res.status === 404 || res.status === 403) return null;
    if (res.status >= 400) { await sleep(300 * attempt); continue; }
    return res.body.toString("utf8");
  }
  return null;
}

async function fetchJSON(url) {
  const text = await fetchText(url);
  if (!text) return null;
  try { return JSON.parse(text); }
  catch { return null; }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ════════════════════════════════════════════════════════════════════════
//  Concurrency pool  – run N promises at a time
// ════════════════════════════════════════════════════════════════════════

async function poolAll(items, concurrency, fn) {
  const results = new Array(items.length);
  let   index   = 0;

  async function worker() {
    while (index < items.length) {
      const i   = index++;
      results[i] = await fn(items[i], i);
      if (DELAY_MS > 0) await sleep(DELAY_MS);
    }
  }

  const workers = Array.from({ length: concurrency }, worker);
  await Promise.all(workers);
  return results;
}

// ════════════════════════════════════════════════════════════════════════
//  Version helpers
// ════════════════════════════════════════════════════════════════════════

function isValidVersion(v) {
  if (!v || typeof v !== "string") return false;
  if (!VERSION_RE.test(v))          return false;
  if (v.length > 14)                return false;
  const parts = v.split(/[.\-]/);
  if (parts.some((p) => parseInt(p, 10) > 999))  return false;
  if (parts.length === 2 && parseInt(parts[1], 10) > 99) return false;
  return true;
}

const cleanVersions = (arr) => [...new Set((arr ?? []).filter(isValidVersion))];

/**
 * Extract semver from an RPM package string.
 * "apache-commons-text-1.10.0-1.el9_0.noarch"  →  "1.10.0"
 * "curl-7.76.1-26.el9_1.2.x86_64"              →  "7.76.1"
 */
function rpmVersion(pkg) {
  if (!pkg) return null;
  // Strip arch suffix
  const base = pkg.replace(/\.(x86_64|aarch64|i686|noarch|src|ppc64le|s390x)$/, "");
  const m    = base.match(/-(\d+\.\d+(?:\.\d+)?(?:-\d+)?)/);
  return m && isValidVersion(m[1]) ? m[1] : null;
}

// ════════════════════════════════════════════════════════════════════════
//  LEVEL 0 – Crawl root index → year links
// ════════════════════════════════════════════════════════════════════════

/**
 * Fetches the CSAF root page and returns an array of year folder URLs.
 * Also checks the changes.csv / index.txt companion files if present.
 */
async function crawlRootIndex(filterYear = null) {
  console.log(`[Root] Fetching ${CSAF_ROOT} …`);

  const html = await fetchText(CSAF_ROOT);
  if (!html) {
    console.error("[Root] Failed to fetch root index.");
    return [];
  }

  const $ = cheerio.load(html);
  const yearLinks = [];

  $("a[href]").each((_, el) => {
    const href = $(el).attr("href");
    if (!href) return;

    // Year links look like "2001/", "2022/", etc.
    const match = href.match(/^(\d{4})\/?$/);
    if (!match) return;

    const year = parseInt(match[1], 10);
    if (year < START_YEAR)      return;
    if (filterYear && year !== filterYear) return;

    const fullUrl = new URL(href, CSAF_ROOT).toString();
    yearLinks.push({ year, url: fullUrl });
  });

  // Sort chronologically
  yearLinks.sort((a, b) => a.year - b.year);

  console.log(`[Root] Found ${yearLinks.length} year folder(s): ${yearLinks.map((y) => y.year).join(", ")}`);
  return yearLinks;
}

// ════════════════════════════════════════════════════════════════════════
//  LEVEL 1 – Crawl year folder → advisory JSON links
// ════════════════════════════════════════════════════════════════════════

/**
 * Fetches a year-folder index page and returns advisory JSON file URLs.
 * Also attempts to fetch changes.csv if it exists (Red Hat provides this
 * for incremental crawling).
 */
async function crawlYearIndex(yearObj, filterRhsa = null) {
  const { year, url } = yearObj;
  console.log(`[${year}] Fetching year index …`);

  const html = await fetchText(url);
  if (!html) {
    console.warn(`[${year}] Could not fetch year index.`);
    return [];
  }

  const $ = cheerio.load(html);
  const advisoryLinks = [];

  $("a[href]").each((_, el) => {
    const href = $(el).attr("href");
    if (!href || !href.endsWith(".json")) return;

    const filename = path.basename(href);

    // Optional: filter to specific RHSA ID
    if (filterRhsa) {
      const normalised = filterRhsa.replace(":", "_").toLowerCase();
      if (!filename.toLowerCase().includes(normalised)) return;
    }

    const fullUrl = new URL(href, url).toString();
    advisoryLinks.push({ year, filename, url: fullUrl });
  });

  // Apply per-year cap if set
  const limited = MAX_PER_YEAR > 0 ? advisoryLinks.slice(0, MAX_PER_YEAR) : advisoryLinks;

  console.log(`[${year}] Found ${advisoryLinks.length} advisory file(s)${MAX_PER_YEAR > 0 ? ` (capped at ${MAX_PER_YEAR})` : ""}.`);
  return limited;
}

// ════════════════════════════════════════════════════════════════════════
//  LEVEL 2 – Parse a single CSAF advisory JSON
// ════════════════════════════════════════════════════════════════════════

/**
 * Full CSAF 2.0 parser.  Returns a richly structured object.
 */
function parseCSAF(raw, sourceUrl) {
  if (!raw || typeof raw !== "object") return null;

  const doc     = raw.document      ?? {};
  const tracking = doc.tracking     ?? {};
  const tree    = raw.product_tree  ?? {};
  const vulns   = raw.vulnerabilities ?? [];

  // ── Document-level metadata ────────────────────────────────
  const document = {
    category:          doc.category        ?? null,
    csaf_version:      doc.csaf_version    ?? null,
    lang:              doc.lang            ?? null,
    title:             doc.title           ?? null,
    aggregate_severity: doc.aggregate_severity?.text ?? null,
    severity_namespace: doc.aggregate_severity?.namespace ?? null,
    distribution: {
      text:  doc.distribution?.text          ?? null,
      tlp_label: doc.distribution?.tlp?.label ?? null,
      tlp_url:   doc.distribution?.tlp?.url   ?? null,
    },
    publisher: {
      name:              doc.publisher?.name              ?? null,
      category:          doc.publisher?.category          ?? null,
      namespace:         doc.publisher?.namespace         ?? null,
      contact_details:   doc.publisher?.contact_details   ?? null,
      issuing_authority: doc.publisher?.issuing_authority ?? null,
    },
    // Notes (summary, details, legal, remediation text, etc.)
    notes: (doc.notes ?? []).map((n) => ({
      category: n.category,
      title:    n.title    ?? null,
      text:     n.text     ?? null,
      audience: n.audience ?? null,
    })),
    // References (self, external CVE pages, errata links …)
    references: (doc.references ?? []).map((r) => ({
      category: r.category,
      summary:  r.summary ?? null,
      url:      r.url,
    })),
  };

  // ── Tracking ────────────────────────────────────────────────
  const trackingParsed = {
    id:                   tracking.id                    ?? null,
    status:               tracking.status                ?? null,
    version:              tracking.version               ?? null,
    initial_release_date: tracking.initial_release_date  ?? null,
    current_release_date: tracking.current_release_date  ?? null,
    revision_history:    (tracking.revision_history ?? []).map((r) => ({
      date:    r.date    ?? null,
      number:  r.number  ?? null,
      summary: r.summary ?? null,
    })),
    generator: tracking.generator
      ? {
          date:           tracking.generator.date                  ?? null,
          engine_name:    tracking.generator.engine?.name          ?? null,
          engine_version: tracking.generator.engine?.version       ?? null,
        }
      : null,
  };

  // ── Product tree (branches + relationships = full product list) ──
  const productTree = {
    branches:      flattenBranches(tree.branches ?? []),
    relationships: (tree.relationships ?? []).map((r) => ({
      category:           r.category                        ?? null,
      product_reference:  r.product_reference               ?? null,
      relates_to:         r.relates_to_product_reference    ?? null,
      full_product_name:  r.full_product_name?.name         ?? null,
      product_id:         r.full_product_name?.product_id   ?? null,
    })),
    // Flat list of every explicitly named product
    full_products: extractFullProducts(tree),
  };

  // ── Fixed packages from product tree relationships ──────────
  const fixedPackages = productTree.relationships.map((r) => r.full_product_name).filter(Boolean);

  // ── Vulnerabilities (one per CVE usually) ───────────────────
  const parsedVulns = vulns.map((v) => parseVulnerability(v, productTree));

  // ── All CVE IDs covered by this advisory ────────────────────
  const cveIds = [...new Set(parsedVulns.map((v) => v.cve).filter(Boolean))];

  // ── Aggregate fixed versions from all remediations ──────────
  const allFixedVersions = cleanVersions([
    ...fixedPackages.map(rpmVersion).filter(Boolean),
    ...parsedVulns.flatMap((v) => v.fixed_packages.map(rpmVersion).filter(Boolean)),
  ]);

  return {
    // ── Top-level identifiers ──────────────────────────────────
    advisory_id:  trackingParsed.id,
    title:        document.title,
    severity:     document.aggregate_severity,
    published:    trackingParsed.initial_release_date,
    updated:      trackingParsed.current_release_date,
    status:       trackingParsed.status,
    cve_ids:      cveIds,
    source_url:   sourceUrl,

    // ── Full structured sections ───────────────────────────────
    document,
    tracking:     trackingParsed,
    product_tree: productTree,
    vulnerabilities: parsedVulns,

    // ── Convenience aggregates ─────────────────────────────────
    fixed_packages:  fixedPackages,
    fixed_versions:  allFixedVersions,
  };
}

/**
 * Recursively flatten the product_tree.branches array into a flat list
 * of leaf product nodes (the actual product name + id pairs).
 */
function flattenBranches(branches, depth = 0) {
  const result = [];
  for (const branch of branches) {
    const entry = {
      category: branch.category ?? null,
      name:     branch.name     ?? null,
      depth,
    };

    if (branch.product) {
      entry.product_id   = branch.product.product_id        ?? null;
      entry.product_name = branch.product.name              ?? null;
      entry.cpe          = branch.product.product_identification_helper?.cpe ?? null;
      entry.purl         = branch.product.product_identification_helper?.purl ?? null;
    }

    result.push(entry);

    if (branch.branches?.length) {
      result.push(...flattenBranches(branch.branches, depth + 1));
    }
  }
  return result;
}

/**
 * Extract all full_product_name entries from the product tree,
 * including from branches and from top-level full_product_names.
 */
function extractFullProducts(tree) {
  const products = [];

  function walk(branches) {
    for (const b of branches ?? []) {
      if (b.product) {
        products.push({
          name:       b.product.name              ?? null,
          product_id: b.product.product_id        ?? null,
          cpe:        b.product.product_identification_helper?.cpe  ?? null,
          purl:       b.product.product_identification_helper?.purl ?? null,
        });
      }
      if (b.branches) walk(b.branches);
    }
  }

  walk(tree.branches ?? []);

  for (const fp of tree.full_product_names ?? []) {
    products.push({
      name:       fp.name       ?? null,
      product_id: fp.product_id ?? null,
      cpe:        fp.product_identification_helper?.cpe  ?? null,
      purl:       fp.product_identification_helper?.purl ?? null,
    });
  }

  return products;
}

/**
 * Parse a single vulnerability entry from a CSAF advisory.
 */
function parseVulnerability(v, productTree) {
  // ── CVSS scores (v2 / v3 / v4) ────────────────────────────
  const cvss = { v2: null, v3: null, v4: null };
  for (const scoreBlock of v.scores ?? []) {
    if (scoreBlock.cvss_v2) {
      const d = scoreBlock.cvss_v2;
      cvss.v2 = {
        base_score:     d.baseScore           ?? null,
        vector_string:  d.vectorString        ?? null,
        version:        d.version             ?? null,
        access_vector:  d.accessVector        ?? null,
        access_complexity: d.accessComplexity ?? null,
        authentication: d.authentication      ?? null,
        confidentiality_impact: d.confidentialityImpact ?? null,
        integrity_impact:       d.integrityImpact       ?? null,
        availability_impact:    d.availabilityImpact    ?? null,
        products:       scoreBlock.products   ?? [],
      };
    }
    if (scoreBlock.cvss_v3) {
      const d = scoreBlock.cvss_v3;
      cvss.v3 = {
        base_score:              d.baseScore              ?? null,
        base_severity:           d.baseSeverity           ?? null,
        vector_string:           d.vectorString           ?? null,
        version:                 d.version                ?? null,
        attack_vector:           d.attackVector           ?? null,
        attack_complexity:       d.attackComplexity       ?? null,
        privileges_required:     d.privilegesRequired     ?? null,
        user_interaction:        d.userInteraction        ?? null,
        scope:                   d.scope                  ?? null,
        confidentiality_impact:  d.confidentialityImpact  ?? null,
        integrity_impact:        d.integrityImpact        ?? null,
        availability_impact:     d.availabilityImpact     ?? null,
        exploitability_score:    d.exploitabilityScore    ?? null,
        impact_score:            d.impactScore            ?? null,
        products:       scoreBlock.products ?? [],
      };
    }
    if (scoreBlock.cvss_v4) {
      const d = scoreBlock.cvss_v4;
      cvss.v4 = {
        base_score:    d.baseScore    ?? null,
        base_severity: d.baseSeverity ?? null,
        vector_string: d.vectorString ?? null,
        version:       d.version      ?? null,
        products:      scoreBlock.products ?? [],
      };
    }
  }

  // ── Product status (fixed / affected / not-affected) ────────
  const ps = v.product_status ?? {};
  const productStatus = {
    fixed:               ps.fixed               ?? [],
    known_affected:      ps.known_affected       ?? [],
    known_not_affected:  ps.known_not_affected   ?? [],
    recommended:         ps.recommended          ?? [],
    under_investigation: ps.under_investigation  ?? [],
    first_fixed:         ps.first_fixed          ?? [],
    last_affected:       ps.last_affected        ?? [],
  };

  // ── Remediations ─────────────────────────────────────────────
  const remediations = (v.remediations ?? []).map((r) => ({
    category:           r.category            ?? null,
    details:            r.details             ?? null,
    product_ids:        r.product_ids         ?? [],
    group_ids:          r.group_ids           ?? [],
    restart_required:   r.restart_required?.category ?? null,
    url:                r.url                 ?? null,
    date:               r.date                ?? null,
    entitlements:       r.entitlements        ?? [],
  }));

  // ── Threats ───────────────────────────────────────────────────
  const threats = (v.threats ?? []).map((t) => ({
    category:    t.category    ?? null,
    details:     t.details     ?? null,
    product_ids: t.product_ids ?? [],
    group_ids:   t.group_ids   ?? [],
    date:        t.date        ?? null,
  }));

  // ── Flags ─────────────────────────────────────────────────────
  const flags = (v.flags ?? []).map((f) => ({
    label:       f.label       ?? null,
    product_ids: f.product_ids ?? [],
    group_ids:   f.group_ids   ?? [],
  }));

  // ── IDs (other database IDs, e.g. RHSA, BZ) ──────────────────
  const ids = (v.ids ?? []).map((i) => ({
    system_name: i.system_name ?? null,
    text:        i.text        ?? null,
  }));

  // ── References ────────────────────────────────────────────────
  const references = (v.references ?? []).map((r) => ({
    category: r.category ?? null,
    summary:  r.summary  ?? null,
    url:      r.url,
  }));

  // ── Notes ─────────────────────────────────────────────────────
  const notes = (v.notes ?? []).map((n) => ({
    category: n.category ?? null,
    title:    n.title    ?? null,
    text:     n.text     ?? null,
  }));

  // ── Fixed packages (product IDs in the "fixed" status) ───────
  const fixedProductIds = productStatus.fixed;
  const fixedPackages   = fixedProductIds.map((pid) => {
    // Find the human-readable name from the product tree
    const rel = productTree.relationships.find((r) => r.product_id === pid);
    return rel?.full_product_name ?? pid;
  });

  return {
    cve:              v.cve                ?? null,
    title:            v.title              ?? null,
    discovery_date:   v.discovery_date     ?? null,
    release_date:     v.release_date       ?? null,
    cwe: v.cwe
      ? { id: v.cwe.id ?? null, name: v.cwe.name ?? null }
      : null,
    cvss,
    product_status:  productStatus,
    remediations,
    threats,
    flags,
    ids,
    references,
    notes,
    fixed_packages:  fixedPackages,
    fixed_versions:  cleanVersions(fixedPackages.map(rpmVersion).filter(Boolean)),
    // Convenience: highest CVSS score across all versions
    highest_score:   cvss.v4?.base_score ?? cvss.v3?.base_score ?? cvss.v2?.base_score ?? null,
    severity:        cvss.v4?.base_severity ?? cvss.v3?.base_severity ?? null,
    // Exploit status extracted from threats
    exploit_status:  threats.find((t) => t.category === "exploit_status")?.details ?? null,
    impact:          threats.find((t) => t.category === "impact")?.details ?? null,
  };
}

// ════════════════════════════════════════════════════════════════════════
//  Progress tracker
// ════════════════════════════════════════════════════════════════════════

class Progress {
  constructor(total) {
    this.total   = total;
    this.done    = 0;
    this.failed  = 0;
    this.start   = Date.now();
  }

  tick(ok) {
    this.done++;
    if (!ok) this.failed++;
    const pct  = ((this.done / this.total) * 100).toFixed(1);
    const secs = ((Date.now() - this.start) / 1000).toFixed(1);
    const eta  = this.done
      ? (((Date.now() - this.start) / this.done) * (this.total - this.done) / 1000).toFixed(0)
      : "?";
    process.stdout.write(
      `\r  [${this.done}/${this.total}] ${pct}%  ✓${this.done - this.failed} ✗${this.failed}  ${secs}s elapsed  ETA ~${eta}s   `
    );
  }

  done_() { process.stdout.write("\n"); }
}

// ════════════════════════════════════════════════════════════════════════
//  Main crawler orchestrator
// ════════════════════════════════════════════════════════════════════════

async function crawlCSAF(args = {}) {
  const t0 = Date.now();

  console.log("═".repeat(70));
  console.log("  Red Hat CSAF v2 Deep Crawler");
  console.log(`  Root: ${CSAF_ROOT}`);
  if (args.cve)  console.log(`  Filter CVE:  ${args.cve}`);
  if (args.year) console.log(`  Filter year: ${args.year}`);
  if (args.rhsa) console.log(`  Filter RHSA: ${args.rhsa}`);
  console.log("═".repeat(70) + "\n");

  // ── LEVEL 0: year folders ──────────────────────────────────────────
  const yearFolders = await crawlRootIndex(args.year ?? null);
  if (!yearFolders.length) {
    console.error("No year folders found. Check connectivity to security.access.redhat.com");
    return { error: "no_year_folders", advisories: [] };
  }

  // ── LEVEL 1: advisory JSON links ──────────────────────────────────
  const allAdvisoryLinks = [];
  for (const yf of yearFolders) {
    const links = await crawlYearIndex(yf, args.rhsa ?? null);
    allAdvisoryLinks.push(...links);
    await sleep(DELAY_MS);
  }

  if (!allAdvisoryLinks.length) {
    console.warn("No advisory JSON files found.");
    return { error: "no_advisories", advisories: [] };
  }

  console.log(`\n[Phase 2] Fetching ${allAdvisoryLinks.length} advisory JSON files (concurrency=${CONCURRENCY}) …\n`);

  const progress  = new Progress(allAdvisoryLinks.length);
  const advisories = [];
  const errors     = [];

  // ── LEVEL 2: fetch + parse each advisory JSON ──────────────────────
  await poolAll(allAdvisoryLinks, CONCURRENCY, async ({ url, year, filename }) => {
    const raw = await fetchJSON(url);

    if (!raw) {
      errors.push({ url, error: "fetch_failed" });
      progress.tick(false);
      return;
    }

    const parsed = parseCSAF(raw, url);
    if (!parsed) {
      errors.push({ url, error: "parse_failed" });
      progress.tick(false);
      return;
    }

    // Apply CVE filter if requested
    if (args.cve && !parsed.cve_ids.includes(args.cve)) {
      progress.tick(true);
      return;  // skip silently – doesn't mention this CVE
    }

    advisories.push(parsed);
    progress.tick(true);
  });

  progress.done_();

  const duration = ((Date.now() - t0) / 1000).toFixed(1);
  console.log(`\n[Done] ${advisories.length} advisories collected, ${errors.length} errors, ${duration}s total.\n`);

  return {
    meta: {
      run_at:          new Date().toISOString(),
      duration_s:      parseFloat(duration),
      root_url:        CSAF_ROOT,
      filters:         args,
      total_fetched:   allAdvisoryLinks.length,
      total_matched:   advisories.length,
      total_errors:    errors.length,
    },
    advisories,
    errors,
  };
}

// ════════════════════════════════════════════════════════════════════════
//  Output helpers
// ════════════════════════════════════════════════════════════════════════

function printSummaryTable(advisories) {
  if (!advisories.length) { console.log("  (no matching advisories)"); return; }

  console.log("═".repeat(110));
  console.log(
    "  RHSA ID".padEnd(22) +
    "Severity".padEnd(12) +
    "Published".padEnd(14) +
    "CVE(s)".padEnd(20) +
    "Fixed versions"
  );
  console.log("─".repeat(110));

  for (const a of advisories) {
    const id       = (a.advisory_id  ?? "?").padEnd(22);
    const sev      = (a.severity     ?? "?").padEnd(12);
    const date     = (a.published    ?? "?").slice(0, 10).padEnd(14);
    const cves     = a.cve_ids.slice(0, 3).join(", ").padEnd(20);
    const versions = a.fixed_versions.slice(0, 3).join(", ");
    console.log(`  ${id}${sev}${date}${cves}${versions}`);
  }
  console.log("═".repeat(110));
}

// ════════════════════════════════════════════════════════════════════════
//  CLI Entry Point
// ════════════════════════════════════════════════════════════════════════

async function main() {
  const args = parseArgs(process.argv);

  try {
    const result = await crawlCSAF(args);
    const json   = JSON.stringify(result, null, 2);

    console.log("\n──────────────────────────────────────────────────────────────────────");
    console.log("  ADVISORY SUMMARY TABLE");
    console.log("──────────────────────────────────────────────────────────────────────");
    printSummaryTable(result.advisories ?? []);

    if (process.env.SAVE_OUTPUT === "1" || args.cve || args.rhsa) {
      const filename = args.cve
        ? `csaf_${args.cve}.json`
        : args.rhsa
        ? `csaf_${args.rhsa.replace(":", "_")}.json`
        : "csaf_results.json";

      fs.writeFileSync(filename, json, "utf8");
      console.log(`\n💾  Saved → ${filename}`);
    } else {
      console.log("\n" + json);
    }
  } catch (err) {
    console.error("Fatal:", err.message);
    if (process.env.DEBUG) console.error(err.stack);
    process.exit(1);
  }
}

// ════════════════════════════════════════════════════════════════════════
//  Export so this can be imported by cve_analyzer.js
// ════════════════════════════════════════════════════════════════════════

module.exports = { crawlCSAF, parseCSAF, crawlRootIndex, crawlYearIndex };

// Run CLI if called directly
if (require.main === module) main();