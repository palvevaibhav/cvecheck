// =======================================
// AI-Style CVE Analyzer - Node.js
// =======================================
const axios = require("axios");
const semver = require("semver"); // npm install semver

// ----------------------------
// CWE → Vulnerability Type Mapping
// ----------------------------
const CWE_MAPPING = {
    "CWE-79": "Prototype pollution / injection",
    "CWE-89": "SQL Injection / Injection",
    "CWE-20": "Input validation / Other",
    "CWE-287": "Authentication/Authorization issue",
    "CWE-306": "Authentication/Authorization issue",
    "CWE-200": "Information disclosure",
    "CWE-502": "Remote code execution",
    "CWE-119": "Remote code execution / Buffer overflow",
};

// ----------------------------
// Classify vulnerability
// ----------------------------
function classifyVulnerability(cweIds, description) {
    for (const cwe of cweIds) {
        if (CWE_MAPPING[cwe]) return CWE_MAPPING[cwe];
    }
    description = description.toLowerCase();
    if (description.includes("remote code execution")) return "Remote code execution";
    if (description.includes("denial of service")) return "Denial of service";
    if (description.includes("authentication") || description.includes("authorization")) return "Authentication/Authorization issue";
    if (description.includes("information disclosure") || description.includes("leak")) return "Information disclosure";
    if (description.includes("prototype pollution") || description.includes("injection")) return "Prototype pollution / injection";
    return "Other";
}

// ----------------------------
// Fetch NVD CVE data
// ----------------------------
async function fetchNVD(cveId) {
    const url = `https://services.nvd.nist.gov/rest/json/cve/1.0/${cveId}`;
    const res = await axios.get(url);
    const items = res.data.result.CVE_Items;
    if (!items || !items.length) return {};
    const cve = items[0];
    const description = cve.cve.description.description_data[0]?.value || "";
    const impact = cve.impact?.baseMetricV3?.cvssV3 || {};
    const cvssScore = impact.baseScore;
    const cvssVector = impact.vectorString;
    const cweIds = [];
    const problemData = cve.cve.problemtype.problemtype_data || [];
    problemData.forEach(item => {
        item.description.forEach(desc => {
            if (desc.value !== "NVD-CWE-noinfo") cweIds.push(desc.value);
        });
    });
    const references = (cve.cve.references.reference_data || []).map(r => r.url);
    return { description, cvssScore, cvssVector, cweIds, references };
}

// ----------------------------
// Fetch OSV data
// ----------------------------
async function fetchOSV(cveId) {
    const url = "https://api.osv.dev/v1/query";
    const res = await axios.post(url, { query: cveId });
    if (!res.data.vulns || !res.data.vulns.length) return [];
    const vuln = res.data.vulns[0];
    const affectedPackages = [];
    vuln.affected?.forEach(a => {
        const pkgName = a.package?.name;
        const ecosystem = a.package?.ecosystem;
        let fixedVersions = [];
        a.ranges?.forEach(rng => {
            rng.events?.forEach(ev => {
                if (ev.fixed) fixedVersions.push(ev.fixed);
            });
        });
        affectedPackages.push({ package: pkgName, ecosystem, fixedVersions });
    });
    return affectedPackages;
}

// ----------------------------
// Generate remediation commands
// ----------------------------
function generateRemediation(packages) {
    const commands = [];
    packages.forEach(pkg => {
        if (!pkg.fixedVersions?.length) return;
        const latestFixed = pkg.fixedVersions[pkg.fixedVersions.length - 1];
        const eco = pkg.ecosystem?.toLowerCase();
        const name = pkg.package;
        if (eco === "npm") commands.push(`npm install ${name}@${latestFixed}`);
        else if (eco === "pypi") commands.push(`pip install --upgrade ${name}==${latestFixed}`);
        else if (["maven", "java"].includes(eco)) commands.push(`Update ${name} to ${latestFixed} in pom.xml`);
        else if (["debian", "ubuntu"].includes(eco)) commands.push(`apt-get update ${name}`);
        else if (["redhat", "centos", "fedora"].includes(eco)) commands.push(`yum update ${name}`);
        else commands.push(`Update ${name} to ${latestFixed} (${eco})`);
    });
    return commands;
}

// ----------------------------
// Compare SBOM
// ----------------------------
function checkSBOM(report, sbom) {
    const flagged = [];
    report.affectedPackages?.forEach(pkg => {
        const eco = pkg.ecosystem?.toLowerCase();
        const installedVersion = sbom[eco]?.[pkg.package];
        if (!installedVersion || !pkg.fixedVersions?.length) return;
        const latestFixed = pkg.fixedVersions[pkg.fixedVersions.length - 1];
        if (semver.valid(installedVersion) && semver.valid(latestFixed) && semver.lt(installedVersion, latestFixed)) {
            flagged.push({
                package: pkg.package,
                ecosystem: eco,
                installedVersion,
                fixedVersion: latestFixed,
                remediation: generateRemediation([pkg])[0]
            });
        }
    });
    return flagged;
}

// ----------------------------
// Main AI-style CVE Analyzer
// ----------------------------
async function analyzeCVE(cveId, sbom = null) {
    const nvd = await fetchNVD(cveId);
    const osv = await fetchOSV(cveId);
    const vulnType = classifyVulnerability(nvd.cweIds || [], nvd.description || "");
    const remediation = generateRemediation(osv);

    const report = {
        cveId,
        description: nvd.description,
        cvssScore: nvd.cvssScore,
        cvssVector: nvd.cvssVector,
        vulnerabilityType: vulnType,
        affectedPackages: osv,
        remediationCommands: remediation,
        references: nvd.references
    };

    if (sbom) report.vulnerableInstalledPackages = checkSBOM(report, sbom);

    return report;
}

// ----------------------------
// Example Usage
// ----------------------------
(async () => {
    const exampleSBOM = {
        npm: { lodash: "4.17.10" },
        pypi: { requests: "2.22.0" }
    };
    const cveId = "CVE-2020-8203";
    const report = await analyzeCVE(cveId, exampleSBOM);
    console.log(JSON.stringify(report, null, 4));
})();