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
  // Wiz advisory
  { url: "https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack", type: "wiz" },
  // StepSecurity advisory
  { url: "https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised", type: "stepsecurity" },
  // Additional sources can be added here if needed
];

// 2. Helper: fetch URL as text (promise)
function fetchURL(url, timeout = 15000) {
  // For testing, use a shorter timeout if environment variable is set
  if (process.env.WORM_SCANNER_TEST) {
    timeout = 5000;
  }
  
  return new Promise((resolve, reject) => {
    const req = https.get(new URL(url), { timeout: timeout }, (res) => {
      // Check for error status codes
      if (res.statusCode >= 400) {
        reject(new Error(`HTTP Error: ${res.statusCode} ${res.statusMessage}`));
        return;
      }
      
      let data = '';
      res.on('data', chunk => data += chunk);
      
      // Set a timeout for the response reading as well
      const responseTimeout = setTimeout(() => {
        reject(new Error(`Response reading timeout after ${timeout}ms`));
      }, timeout);
      
      res.on('end', () => {
        clearTimeout(responseTimeout);
        resolve(data);
      });
    });
    
    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`Request timeout after ${timeout}ms`));
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

function parseGitHubAdvisory(html) {
  // Parse GitHub Advisory format
  let packages = {};
  
  try {
    // Look for the affected package name
    const titleMatch = html.match(/<h1[^>]*>([^<]+)<\/h1>/);
    let packageName = '';
    
    if (titleMatch) {
      const title = stripHTML(titleMatch[1]).trim();
      // Format is often "Malicious code in X package" or similar
      const pkgMatch = title.match(/(?:in|of|from|with)\s+(@?[a-zA-Z0-9_.\-]+(?:\/[a-zA-Z0-9_.\-]+)?)/i);
      if (pkgMatch) {
        packageName = pkgMatch[1];
      }
    }
    
    // If we couldn't find the package name in the title, try looking for it elsewhere
    if (!packageName) {
      const packageMatch = html.match(/Package Name[:\s]+<[^>]+>([^<]+)<\/[^>]+>/i);
      if (packageMatch) {
        packageName = stripHTML(packageMatch[1]).trim();
      }
    }
    
    // Look for affected versions
    if (packageName) {
      const versionSections = [
        // Look for affected versions section
        html.match(/Affected Versions[:\s]+<[^>]+>([\s\S]+?)<\/(?:div|span|p)>/i),
        // Look for vulnerable versions section
        html.match(/Vulnerable Versions[:\s]+<[^>]+>([\s\S]+?)<\/(?:div|span|p)>/i),
        // Look for version information in CVE details
        html.match(/CVE-\d+-\d+[^<]*<[^>]+>([\s\S]+?)<\/(?:div|span|p)>/i)
      ].filter(Boolean);
      
      let versions = new Set();
      
      for (const section of versionSections) {
        if (section) {
          const versionText = stripHTML(section[1]);
          const versionMatches = versionText.match(/\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.]+)?/g);
          if (versionMatches) {
            for (const v of versionMatches) {
              versions.add(v);
            }
          }
        }
      }
      
      if (versions.size > 0) {
        packages[packageName] = versions;
      }
    }
  } catch (e) {
    console.warn(`Error parsing GitHub advisory: ${e.message}`);
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
  
  // Also try to find packages listed in tables with version information
  try {
    const tableRe = /<table[^>]*>(.*?)<\/table>/gs;
    let tableMatch;
    while ((tableMatch = tableRe.exec(html)) !== null) {
      const tableContent = tableMatch[1];
      const rowRe = /<tr[^>]*>(.*?)<\/tr>/gs;
      let rowMatch;
      
      while ((rowMatch = rowRe.exec(tableContent)) !== null) {
        const row = rowMatch[1];
        const cellRe = /<t[dh][^>]*>(.*?)<\/t[dh]>/gi;
        const cells = [];
        
        let cellMatch;
        while ((cellMatch = cellRe.exec(row)) !== null) {
          cells.push(stripHTML(cellMatch[1]).trim());
        }
        
        if (cells.length >= 2) {
          // Common table formats have package name in first column and version in another
          const potentialPackage = cells[0];
          const packageMatch = potentialPackage.match(/^(@?[a-zA-Z0-9_.\-]+(?:\/[a-zA-Z0-9_.\-]+)?)$/);
          
          if (packageMatch) {
            const pkg = packageMatch[1];
            // Check other cells for version numbers
            for (let i = 1; i < cells.length; i++) {
              const versionMatches = cells[i].match(/\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.]+)?/g);
              if (versionMatches) {
                if (!packages[pkg]) packages[pkg] = new Set();
                for (const version of versionMatches) {
                  packages[pkg].add(version);
                }
              }
            }
          }
        }
      }
    }
  } catch (e) {
    console.warn(`Error parsing tables: ${e.message}`);
  }
  
  return packages;
}

function stripHTML(str) {
  return str.replace(/<[^>]+>/g, '').replace(/&amp;/g, "&").replace(/&#39;/g, "'").replace(/&quot;/g, '"');
}

// Helper function to handle semver range checks
function satisfiesRange(versionRange, version) {
  // If the range is exact, only check equality
  if (!isRange(versionRange)) {
    return versionRange === version;
  }
  
  try {
    // Parse version and range into components
    const parsedVersion = parseVersion(version);
    
    // Handle different range formats
    if (versionRange.startsWith('~')) {
      // Tilde ranges (~1.2.3) allow patch-level changes
      const baseVersion = versionRange.substring(1);
      const parsedBase = parseVersion(baseVersion);
      
      // Match major and minor version, allow patch version >= baseVersion.patch
      return parsedVersion.major === parsedBase.major && 
             parsedVersion.minor === parsedBase.minor && 
             parsedVersion.patch >= parsedBase.patch;
    } 
    else if (versionRange.startsWith('^')) {
      // Caret ranges (^1.2.3) allow changes that don't modify the major version
      const baseVersion = versionRange.substring(1);
      const parsedBase = parseVersion(baseVersion);
      
      if (parsedBase.major === 0) {
        // For 0.y.z versions, ^ is more like ~
        return parsedVersion.major === 0 && 
               parsedVersion.minor === parsedBase.minor && 
               parsedVersion.patch >= parsedBase.patch;
      } else {
        // For x.y.z where x > 0, allow anything with same major version
        return parsedVersion.major === parsedBase.major && 
               (parsedVersion.minor > parsedBase.minor || 
                (parsedVersion.minor === parsedBase.minor && parsedVersion.patch >= parsedBase.patch));
      }
    }
    else if (versionRange.endsWith('.x') || versionRange.endsWith('.*')) {
      // Handle 1.2.x or 1.2.* format
      const parts = versionRange.replace(/\.x|\.\*/g, '').split('.').map(Number);
      
      if (parts.length === 1) {
        // Format 1.x - match major version
        return parsedVersion.major === parts[0];
      } else if (parts.length === 2) {
        // Format 1.2.x - match major and minor versions
        return parsedVersion.major === parts[0] && parsedVersion.minor === parts[1];
      }
    }
    else if (versionRange.includes(' - ')) {
      // Handle range format (1.2.3 - 2.3.4)
      const [min, max] = versionRange.split(' - ').map(parseVersion);
      
      // Check if version is within range (inclusive)
      return isVersionGreaterOrEqual(parsedVersion, min) && isVersionLessOrEqual(parsedVersion, max);
    }
    else if (versionRange.includes('>=') || versionRange.includes('<=') || 
             versionRange.includes('>') || versionRange.includes('<')) {
      // Handle complex ranges like ">=1.0.0 <2.0.0"
      const conditions = versionRange.split(/\s+/);
      
      for (const condition of conditions) {
        if (condition.startsWith('>=')) {
          const minVersion = parseVersion(condition.substring(2));
          if (!isVersionGreaterOrEqual(parsedVersion, minVersion)) return false;
        }
        else if (condition.startsWith('>')) {
          const minVersion = parseVersion(condition.substring(1));
          if (!isVersionGreater(parsedVersion, minVersion)) return false;
        }
        else if (condition.startsWith('<=')) {
          const maxVersion = parseVersion(condition.substring(2));
          if (!isVersionLessOrEqual(parsedVersion, maxVersion)) return false;
        }
        else if (condition.startsWith('<')) {
          const maxVersion = parseVersion(condition.substring(1));
          if (!isVersionLess(parsedVersion, maxVersion)) return false;
        }
      }
      return true; // All conditions passed
    }
  } catch (e) {
    // If there's any error in parsing, fall back to a simple check
    console.warn(`Error parsing version range "${versionRange}": ${e.message}`);
  }
  
  // Fallback to simple string inclusion check
  return versionRange.includes(version);
}

// Helper to check if a version string is a range
function isRange(version) {
  return /[\^~><=.*xX]/.test(version) || version.includes(' - ');
}

// Parse a version string into components
function parseVersion(version) {
  // Handle version strings with prerelease or build metadata
  const mainVersion = version.split(/[-+]/)[0];
  const parts = mainVersion.split('.').map(p => parseInt(p, 10));
  
  return {
    major: parts[0] || 0,
    minor: parts[1] || 0,
    patch: parts[2] || 0
  };
}

// Version comparison helpers
function isVersionGreaterOrEqual(v1, v2) {
  return v1.major > v2.major || 
         (v1.major === v2.major && v1.minor > v2.minor) || 
         (v1.major === v2.major && v1.minor === v2.minor && v1.patch >= v2.patch);
}

function isVersionGreater(v1, v2) {
  return v1.major > v2.major || 
         (v1.major === v2.major && v1.minor > v2.minor) || 
         (v1.major === v2.major && v1.minor === v2.minor && v1.patch > v2.patch);
}

function isVersionLessOrEqual(v1, v2) {
  return v1.major < v2.major || 
         (v1.major === v2.major && v1.minor < v2.minor) || 
         (v1.major === v2.major && v1.minor === v2.minor && v1.patch <= v2.patch);
}

function isVersionLess(v1, v2) {
  return v1.major < v2.major || 
         (v1.major === v2.major && v1.minor < v2.minor) || 
         (v1.major === v2.major && v1.minor === v2.minor && v1.patch < v2.patch);
}

// 4. Fetch and parse all advisories
async function fetchCompromisedPackages() {
  let masterList = {};
  let failedSources = 0;
  let successfulSources = 0;
  let pendingRequests = [];
  
  // Start all requests in parallel
  for (const src of ADVISORY_SOURCES) {
    pendingRequests.push(
      (async () => {
        console.log(`Fetching from ${src.url}...`);
        try { 
          const html = await fetchURL(src.url); 
          successfulSources++;
          
          let result = {};
          
          try {
            // Select parser based on source type
            if (src.type === 'stepsecurity') result = parseStepSecurity(html);
            else if (src.type === 'ox') result = parseOX(html);
            else if (src.type === 'wiz') result = parseWiz(html);
            else if (src.type === 'github') result = parseGitHubAdvisory(html);
            else if (src.type === 'generic') result = parseGeneric(html);
            else {
              console.warn(`Unknown source type: ${src.type}, trying generic parser`);
              result = parseGeneric(html);
            }
            
            console.log(`Found ${Object.keys(result).length} packages from ${src.url}`);
            
            return result;
          } catch (e) {
            console.error(`Error parsing data from ${src.url}: ${e.message}`);
            return {};
          }
        } catch (e) {
          console.error(`Failed to fetch ${src.url}: ${e.message}`);
          failedSources++;
          return {};
        }
      })()
    );
  }
  
  // Wait for all requests to complete
  const results = await Promise.allSettled(pendingRequests);
  
  // Merge all results
  for (const result of results) {
    if (result.status === 'fulfilled' && result.value) {
      for (const [pkg, versSet] of Object.entries(result.value)) {
        if (!(pkg in masterList)) masterList[pkg] = new Set();
        for (const v of versSet) masterList[pkg].add(v);
      }
    }
  }
  
  // Convert all sets to arrays for easier later use
  for (const k in masterList) masterList[k] = Array.from(masterList[k]);
  
  console.log(`Advisory sources: ${successfulSources} succeeded, ${failedSources} failed`);
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
      for (const [pkg, versionRange] of Object.entries(pkgData[section])) {
        // Check if package name is in the compromised list
        if (compromised[pkg]) {
          // Check if any of the compromised versions match
          for (const compVersion of compromised[pkg]) {
            // First, check for exact match
            if (versionRange === compVersion) {
              findings.push({ pkg, version: versionRange, section });
              break;
            }
            
            // Next, check if the range could include the compromised version
            if (satisfiesRange(versionRange, compVersion)) {
              findings.push({ 
                pkg, 
                version: `${versionRange} (matches ${compVersion})`, 
                section 
              });
              break;
            }
          }
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
      
      // Check if package name is in the compromised list
      if (compromised[pkg]) {
        // Check if any of the compromised versions match
        for (const compVersion of compromised[pkg]) {
          // Check for exact match
          if (meta.version === compVersion) {
            findings.push({ pkg, version: meta.version, section: "package-lock" });
            break;
          }
          
          // Next, check if the version could include the compromised version
          if (satisfiesRange(meta.version, compVersion)) {
            findings.push({ 
              pkg, 
              version: `${meta.version} (matches ${compVersion})`, 
              section: "package-lock" 
            });
            break;
          }
        }
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
    console.log("\n🚨 Detected compromised packages:");
    for (const f of findings) {
      console.log(`- ${f.pkg}@${f.version} (${f.section})`);
    }
  } else {
    console.log("\n✅ No compromised packages detected in your project.");
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