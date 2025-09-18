#!/usr/bin/env node
/**
 * Minimal Node.js script to (1) fetch compromised packages from advisories,
 * (2) scan local package.json and package-lock.json for matches.
 * No external dependencies.
 */
const fs = require('fs');
const path = require('path');
const https = require('https');
const { URL } = require('url');

// 1. Advisory sources (matching the Python toolkit)
const ADVISORY_SOURCES = [
  // JFrog advisory
  { url: "https://jfrog.com/blog/shai-hulud-npm-supply-chain-attack-new-compromised-packages-detected/", type: "generic" },
  // Semgrep advisory
  { url: "https://semgrep.dev/blog/2025/security-advisory-npm-packages-using-secret-scanning-tools-to-steal-credentials/", type: "generic" },
  // Socket advisory
  { url: "https://socket.dev/blog/tinycolor-supply-chain-attack-affects-40-packages", type: "generic" },
  // OX Security advisory
  { url: "https://www.ox.security/blog/npm-2-0-hack-40-npm-packages-hit-in-major-supply-chain-attack/", type: "ox" },
  // Wiz advisory
  { url: "https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack", type: "wiz" },
  // StepSecurity advisory
  { url: "https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised", type: "stepsecurity" }
];

// 2. Helper: fetch URL as text (promise)
function fetchURL(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(new URL(url), (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data));
    });
    req.on('error', reject);
  });
}

// 3. HTML parsers (for different advisory types)
function parseStepSecurity(html) {
  // Looks for <td class="package-name">pkg</td><td class="versions">x.y.z</td>
  const pkgRe = /<td[^>]*class="package-name"[^>]*>(.*?)<\/td>\s*<td[^>]*class="versions"[^>]*>(.*?)<\/td>/g;
  let match, packages = {};
  while ((match = pkgRe.exec(html)) !== null) {
    const pkg = stripHTML(match[1]).trim();
    const versions = (stripHTML(match[2]).match(/\d+\.\d+\.\d+/g) || []).map(v => v.trim());
    if (pkg && versions.length) {
      packages[pkg] = new Set([...(packages[pkg] || []), ...versions]);
    }
  }
  return packages;
}

function parseOX(html) {
  // Parse OX Security table format
  let packages = {};
  const tableMatch = html.match(/<table[^>]*class="[^"]*has-fixed-layout[^"]*"[^>]*>(.*?)<\/table>/is);
  if (!tableMatch) return packages;
  
  const tableHtml = tableMatch[1];
  const rowsRe = /<tr[^>]*>(.*?)<\/tr>/gs;
  const cellsRe = /<t[dh][^>]*>(.*?)<\/t[dh]>/gi;
  
  let rowMatch;
  while ((rowMatch = rowsRe.exec(tableHtml)) !== null) {
    const cells = [];
    let cellMatch;
    const rowHtml = rowMatch[1];
    while ((cellMatch = cellsRe.exec(rowHtml)) !== null) {
      cells.push(cellMatch[1]);
    }
    
    if (cells.length < 2) continue;
    const pkg = stripHTML(cells[0]).trim();
    if (pkg.toLowerCase() === 'package') continue; // Skip header row
    
    const versions = (stripHTML(cells[1]).match(/\d+\.\d+\.\d+/g) || []).map(v => v.trim());
    if (pkg && versions.length) {
      packages[pkg] = new Set([...(packages[pkg] || []), ...versions]);
    }
  }
  return packages;
}

function parseWiz(html) {
  // Parse Wiz list format
  let packages = {};
  const itemRe = /<li>\s*<p[^>]*class="my-0"[^>]*>(.*?)<\/p>\s*<\/li>/gi;
  const pkgRe = /(@?[A-Za-z0-9_.\-]+(?:\/[A-Za-z0-9_.\-]+)?)/;
  const versionRe = /\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.]+)?/g;
  
  let match;
  while ((match = itemRe.exec(html)) !== null) {
    const text = stripHTML(match[1]).trim();
    if (!text) continue;
    
    const pkgMatch = text.match(pkgRe);
    if (!pkgMatch) continue;
    
    const pkg = pkgMatch[1];
    const versions = [];
    let versionMatch;
    while ((versionMatch = versionRe.exec(text)) !== null) {
      versions.push(versionMatch[0]);
    }
    
    if (pkg && versions.length) {
      packages[pkg] = new Set([...(packages[pkg] || []), ...versions]);
    }
  }
  return packages;
}

function parseGeneric(html) {
  // Generic parser that looks for package@version patterns in text
  let packages = {};
  const pattern = /(@?[a-zA-Z0-9_.\-]+(?:\/[a-zA-Z0-9_.\-]+)?)@(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.]+)?)/g;
  
  let match;
  while ((match = pattern.exec(html)) !== null) {
    const pkg = match[1];
    const version = match[2];
    if (pkg && version) {
      if (!packages[pkg]) packages[pkg] = new Set();
      packages[pkg].add(version);
    }
  }
  return packages;
}

function stripHTML(str) {
  return str.replace(/<[^>]+>/g, '').replace(/&amp;/g, "&").replace(/&#39;/g, "'").replace(/&quot;/g, '"');
}

// 4. Fetch and parse all advisories
async function fetchCompromisedPackages() {
  let masterList = {};
  for (const src of ADVISORY_SOURCES) {
    console.log(`Fetching from ${src.url}...`);
    let html;
    try { html = await fetchURL(src.url); }
    catch (e) {
      console.error(`Failed to fetch ${src.url}: ${e}`);
      continue;
    }
    let result = {};
    
    // Select parser based on source type
    if (src.type === 'stepsecurity') result = parseStepSecurity(html);
    else if (src.type === 'ox') result = parseOX(html);
    else if (src.type === 'wiz') result = parseWiz(html);
    else if (src.type === 'generic') result = parseGeneric(html);
    else {
      console.warn(`Unknown source type: ${src.type}, trying generic parser`);
      result = parseGeneric(html);
    }
    
    console.log(`Found ${Object.keys(result).length} packages from ${src.url}`);
    
    for (const [pkg, versSet] of Object.entries(result)) {
      if (!(pkg in masterList)) masterList[pkg] = new Set();
      for (const v of versSet) masterList[pkg].add(v);
    }
  }
  // Convert all sets to arrays for easier later use
  for (const k in masterList) masterList[k] = Array.from(masterList[k]);
  console.log(`Total unique packages found: ${Object.keys(masterList).length}`);
  return masterList;
}

// 5. Scan local project files
function scanPackageJSON(pkgData, compromised) {
  const findings = [];
  const sections = [
    "dependencies", "devDependencies", "peerDependencies",
    "optionalDependencies", "bundleDependencies", "bundledDependencies"
  ];
  for (const section of sections) {
    if (pkgData[section]) {
      for (const [pkg, version] of Object.entries(pkgData[section])) {
        if (compromised[pkg] && compromised[pkg].some(v => version.includes(v))) {
          findings.push({ pkg, version, section });
        }
      }
    }
  }
  return findings;
}

function scanPackageLock(pkgLockData, compromised) {
  const findings = [];
  if (pkgLockData.dependencies) {
    for (const [pkg, meta] of Object.entries(pkgLockData.dependencies)) {
      if (!meta.version) continue;
      if (compromised[pkg] && compromised[pkg].includes(meta.version)) {
        findings.push({ pkg, version: meta.version, section: "package-lock" });
      }
      // Recursively check nested dependencies
      if (meta.dependencies) {
        findings.push(...scanPackageLock({ dependencies: meta.dependencies }, compromised));
      }
    }
  }
  return findings;
}

// 6. Main
(async function main() {
  console.log("Fetching compromised packages...");
  const compromised = await fetchCompromisedPackages();
  if (!Object.keys(compromised).length) {
    console.log("No compromised packages found in advisories. Exiting.");
    process.exit(0);
  }
  
  let findings = [];
  
  // Try to load package.json (optional)
  let pkgData;
  try { 
    pkgData = JSON.parse(fs.readFileSync('package.json', 'utf8')); 
    console.log("Scanning package.json...");
    findings = scanPackageJSON(pkgData, compromised);
  } catch (e) { 
    console.log("No package.json found in current directory."); 
  }

  // Try to load package-lock.json (optional)
  let pkgLockData = null;
  try { 
    pkgLockData = JSON.parse(fs.readFileSync('package-lock.json', 'utf8')); 
    console.log("Scanning package-lock.json...");
    findings.push(...scanPackageLock(pkgLockData, compromised));
  } catch (e) { 
    console.log("No package-lock.json found in current directory."); 
  }

  // Report
  if (findings.length) {
    console.log("Detected compromised packages:");
    for (const f of findings) {
      console.log(`- ${f.pkg}@${f.version} (${f.section})`);
    }
  } else {
    console.log("No compromised packages detected in your project.");
  }
  
  // Print summary of compromised packages database
  console.log(`\nAdvisory database summary:`);
  console.log(`- Total compromised packages: ${Object.keys(compromised).length}`);
  
  // Print a few examples
  const examples = Object.entries(compromised).slice(0, 5);
  if (examples.length) {
    console.log(`- Examples of compromised packages:`);
    for (const [pkg, versions] of examples) {
      console.log(`  * ${pkg} (${versions.length} versions)`);
    }
  }
})();