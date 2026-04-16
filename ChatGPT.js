const { chromium } = require('playwright');

const VENDOR_SCRAPERS = {
  redhat: {
    url: (cve) => `https://access.redhat.com/security/cve/${cve}`,
    selectors: {
      mitigation: '#mitigations',
      statement: '.affected-statement',
      packages: '.errata-list'
    }
  },
  ubuntu: {
    url: (cve) => `https://ubuntu.com/security/${cve}`,
    selectors: {
      mitigation: '.cve-mitigation',
      packages: 'table.cve-packages'
    }
  }
};

async function scrapeMitigation(browser, cveId, vendor = 'redhat') {
  const page = await browser.newPage();
  const cfg = VENDOR_SCRAPERS[vendor];

  try {
    await page.goto(cfg.url(cveId), {
      waitUntil: 'domcontentloaded',
      timeout: 30000
    });

    const result = {
      cve: cveId,
      vendor,
      url: cfg.url(cveId)
    };

    for (const [key, sel] of Object.entries(cfg.selectors)) {
      const locator = page.locator(sel);
      result[key] = await locator.first().textContent().catch(() => null);
    }

    return result;

  } catch (err) {
    return {
      cve: cveId,
      vendor,
      error: err.message
    };
  } finally {
    await page.close();
  }
}

// 🔥 MAIN FUNCTION
(async () => {
  const browser = await chromium.launch({ headless: true });

  const cveList = ['CVE-2023-44487'];

  for (const cve of cveList) {
    console.log(`\n🔍 Fetching ${cve}\n`);

    const data = await scrapeMitigation(browser, cve, 'redhat');

    console.log(JSON.stringify(data, null, 2));
  }

  await browser.close();
})();