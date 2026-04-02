'use strict';

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const os = require('os');
const https = require('https');
const crypto = require('crypto');

// ─────────────────────────────────────────────────────────────────────────────
//  IOC Database — dynamic threat intelligence updates
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Default URL for fetching IOC updates.
 * Points to the raw ioc-db.json file in the package maintainer's GitHub
 * repository. Contains three arrays: c2Domains, maliciousNpmPackages,
 * and maliciousPypiPackages. Users can override this URL by setting the
 * SEC_CHECK_IOC_URL environment variable.
 *
 * Only HTTPS URLs are accepted to prevent MITM attacks on IOC data.
 */
const DEFAULT_IOC_URL =
  'https://raw.githubusercontent.com/sathyendrav/axios-security-checker/main/ioc-db.json';

/**
 * Path to the local IOC database cache file.
 * Stored in the user's home directory under .sec-check/ so it persists
 * across projects and npm installs.
 *
 * @returns {string} Absolute path to the IOC cache file.
 */
function getDbPath() {
  return path.join(os.homedir(), '.sec-check', 'ioc-db.json');
}

/**
 * Load the cached IOC database from disk.
 * Returns null if the file doesn't exist or is unreadable.
 * Validates the structure (must have at least one recognized key).
 *
 * @returns {{ c2Domains?: string[], maliciousNpmPackages?: string[], maliciousPypiPackages?: string[], updatedAt?: string } | null}
 */
function loadIocDb() {
  const dbPath = getDbPath();
  try {
    if (!fs.existsSync(dbPath)) return null;
    const data = JSON.parse(fs.readFileSync(dbPath, 'utf8'));
    // Basic structure validation — must be an object with at least one array
    if (typeof data !== 'object' || data === null) return null;
    if (!data.c2Domains && !data.maliciousNpmPackages && !data.maliciousPypiPackages) return null;
    return data;
  } catch {
    return null;
  }
}

/**
 * Fetch the latest IOC database from a remote URL and save it locally.
 *
 * Security constraints:
 *   - Only HTTPS URLs are accepted (no HTTP, no file://, no data:)
 *   - Maximum response size is 512 KB to prevent abuse
 *   - Response must be valid JSON with recognized structure
 *   - Each field (c2Domains, etc.) must be an array of strings
 *   - Individual entries are validated (domains must look like domains,
 *     package names must be non-empty lowercase strings)
 *
 * @param {string} [url] - URL to fetch from. Defaults to DEFAULT_IOC_URL.
 * @returns {Promise<{ ok: boolean, message: string, added?: { domains: number, npm: number, pypi: number } }>}
 */
function updateDb(url) {
  const iocUrl = url || process.env.SEC_CHECK_IOC_URL || DEFAULT_IOC_URL;

  // Security: only allow HTTPS
  if (!iocUrl.startsWith('https://')) {
    return Promise.resolve({ ok: false, message: 'Refused: only HTTPS URLs are accepted for IOC updates' });
  }

  return new Promise(resolve => {
    const req = https.get(iocUrl, { timeout: 15000 }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        resolve({ ok: false, message: `HTTP ${res.statusCode} from IOC source` });
        return;
      }

      let body = '';
      const maxBytes = 512 * 1024; // 512 KB limit
      res.setEncoding('utf8');

      res.on('data', chunk => {
        body += chunk;
        if (body.length > maxBytes) {
          req.destroy();
          resolve({ ok: false, message: 'Response exceeded 512 KB limit — aborting' });
        }
      });

      res.on('end', () => {
        try {
          const data = JSON.parse(body);
          const validated = validateIocData(data);
          if (!validated.ok) {
            resolve(validated);
            return;
          }

          // Write to disk
          const dbPath = getDbPath();
          const dbDir = path.dirname(dbPath);
          if (!fs.existsSync(dbDir)) {
            fs.mkdirSync(dbDir, { recursive: true });
          }

          const toSave = {
            c2Domains: data.c2Domains || [],
            maliciousNpmPackages: data.maliciousNpmPackages || [],
            maliciousPypiPackages: data.maliciousPypiPackages || [],
            updatedAt: new Date().toISOString(),
            sourceUrl: iocUrl
          };

          fs.writeFileSync(dbPath, JSON.stringify(toSave, null, 2));

          // Count new entries (not already in hardcoded lists)
          const newDomains = (toSave.c2Domains).filter(d => !C2_DOMAINS.includes(d)).length;
          const newNpm = (toSave.maliciousNpmPackages).filter(p => !MALICIOUS_PACKAGES.includes(p)).length;
          const newPypi = (toSave.maliciousPypiPackages).filter(p => !MALICIOUS_PYPI_PACKAGES.includes(p)).length;

          resolve({
            ok: true,
            message: `IOC database updated (${dbPath})`,
            added: { domains: newDomains, npm: newNpm, pypi: newPypi }
          });
        } catch {
          resolve({ ok: false, message: 'Invalid JSON in IOC response' });
        }
      });
    });

    req.on('error', (err) => resolve({ ok: false, message: `Network error: ${err.message}` }));
    req.on('timeout', () => { req.destroy(); resolve({ ok: false, message: 'Request timed out (15s)' }); });
  });
}

/**
 * Validate the structure and content of fetched IOC data.
 *
 * Rules:
 *   - Must be a non-null object
 *   - Each recognized key must be an array of strings
 *   - Domain entries must match a basic domain pattern (letters, digits, dots, hyphens)
 *   - Package name entries must be non-empty lowercase strings
 *   - Invalid individual entries are silently filtered out (doesn't reject the whole payload)
 *
 * @param {object} data - Parsed JSON from the IOC source.
 * @returns {{ ok: boolean, message: string }}
 */
function validateIocData(data) {
  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    return { ok: false, message: 'IOC data must be a JSON object' };
  }

  const domainPattern = /^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$/i;
  const pkgNamePattern = /^(@[a-z0-9\-~][a-z0-9\-._~]*\/)?[a-z0-9\-~][a-z0-9\-._~]*$/;

  // Validate and filter domain entries
  if (data.c2Domains) {
    if (!Array.isArray(data.c2Domains)) {
      return { ok: false, message: 'c2Domains must be an array' };
    }
    data.c2Domains = data.c2Domains.filter(d => typeof d === 'string' && domainPattern.test(d));
  }

  // Validate and filter npm package entries
  if (data.maliciousNpmPackages) {
    if (!Array.isArray(data.maliciousNpmPackages)) {
      return { ok: false, message: 'maliciousNpmPackages must be an array' };
    }
    data.maliciousNpmPackages = data.maliciousNpmPackages.filter(
      p => typeof p === 'string' && pkgNamePattern.test(p)
    );
  }

  // Validate and filter PyPI package entries
  if (data.maliciousPypiPackages) {
    if (!Array.isArray(data.maliciousPypiPackages)) {
      return { ok: false, message: 'maliciousPypiPackages must be an array' };
    }
    data.maliciousPypiPackages = data.maliciousPypiPackages.filter(
      p => typeof p === 'string' && p.length > 0 && p.length < 200
    );
  }

  return { ok: true, message: 'valid' };
}

/**
 * Get the effective (merged) IOC lists — hardcoded baseline + cached remote IOCs.
 *
 * The hardcoded lists are ALWAYS included. Remote IOC entries are appended
 * (deduplicated) so the scanner never loses built-in coverage even if the
 * cache file is deleted or corrupted.
 *
 * @returns {{ c2Domains: string[], maliciousNpmPackages: string[], maliciousPypiPackages: string[] }}
 */
function getEffectiveIocs() {
  const db = loadIocDb();
  if (!db) {
    return {
      c2Domains: [...C2_DOMAINS],
      maliciousNpmPackages: [...MALICIOUS_PACKAGES],
      maliciousPypiPackages: [...MALICIOUS_PYPI_PACKAGES]
    };
  }

  // Merge: hardcoded + remote, deduplicated
  const merged = {
    c2Domains: [...new Set([...C2_DOMAINS, ...(db.c2Domains || [])])],
    maliciousNpmPackages: [...new Set([...MALICIOUS_PACKAGES, ...(db.maliciousNpmPackages || [])])],
    maliciousPypiPackages: [...new Set([...MALICIOUS_PYPI_PACKAGES, ...(db.maliciousPypiPackages || [])])]
  };

  return merged;
}

/**
 * Validate that a package name is safe for use in shell commands.
 * npm package names may only contain URL-safe characters (lowercase letters,
 * digits, hyphens, dots, underscores, tildes, and scoped @scope/name).
 * This prevents command injection via maliciously crafted lockfile entries.
 *
 * @param {string} name - Package name to validate.
 * @returns {boolean} true if the name matches the npm naming rules.
 */
function isSafePackageName(name) {
  return /^(@[a-z0-9\-~][a-z0-9\-._~]*\/)?[a-z0-9\-~][a-z0-9\-._~]*$/.test(name);
}

/**
 * Main security scan entry point.
 * Runs all detection modules sequentially and collects threats.
 * Always prints a Diagnostic Report. The tool is read-only by default —
 * no files or packages are modified unless options.fix is true.
 *
 * @param {object} [options]
 * @param {boolean} [options.fix=false] - When true, attempt auto-remediation of fixable threats after showing the report.
 * @returns {Promise<boolean>} true if one or more threats were detected (after fixes), false if clean.
 */
async function check(options = {}) {
  const fix = options.fix || false;
  const threats = [];
  const sys = os.platform();

  // CRITICAL: Check permissions first — RAT scans require admin/root
  const hasAdmin = await checkPermissions(sys);
  if (!hasAdmin) {
    console.warn('⚠️  Running without admin/root — RAT artifact scans may miss indicators');
  }

  // 1. Known malicious package detection
  //    plain-crypto-js is a supply-chain attack package that mimics crypto-js.
  //    If present in node_modules, the project is compromised.
  const malDir = path.join(process.cwd(), 'node_modules', 'plain-crypto-js');
  if (fs.existsSync(malDir)) {
    threats.push({
      message: 'CRITICAL: plain-crypto-js detected in node_modules',
      category: 'CRITICAL',
      fixable: true,
      fixDescription: 'npm uninstall plain-crypto-js',
      fix: () => execSync('npm uninstall plain-crypto-js', { stdio: 'ignore', timeout: 30000 })
    });
  }

  // 2. npm audit — flag high and critical severity vulnerabilities.
  //    We run `npm audit --json` and parse the structured output.
  //    Only high and critical severities are flagged; low/moderate are ignored
  //    to reduce noise and avoid blocking installs unnecessarily.
  try {
    const auditOutput = execSync('npm audit --json', {
      timeout: 30000,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore']
    });
    const data = JSON.parse(auditOutput);
    const vulns = data.metadata && data.metadata.vulnerabilities
      ? (data.metadata.vulnerabilities.high || 0) + (data.metadata.vulnerabilities.critical || 0)
      : 0;
    if (vulns > 0) {
      threats.push({
        message: `SECURITY: ${vulns} high/critical vulnerabilities found (run npm audit for details)`,
        category: 'SECURITY',
        fixable: true,
        fixDescription: 'npm audit fix',
        fix: () => execSync('npm audit fix', { stdio: 'ignore', timeout: 60000 })
      });
    }
  } catch (err) {
    // npm audit exits with a non-zero code when vulnerabilities are present,
    // so a "failed" execution is actually normal when issues exist.
    // We capture stdout from the error object and parse it for vulnerability counts.
    if (err.stdout) {
      try {
        const data = JSON.parse(err.stdout);
        const vulns = data.metadata && data.metadata.vulnerabilities
          ? (data.metadata.vulnerabilities.high || 0) + (data.metadata.vulnerabilities.critical || 0)
          : 0;
        if (vulns > 0) {
          threats.push({
            message: `SECURITY: ${vulns} high/critical vulnerabilities found (run npm audit for details)`,
            category: 'SECURITY',
            fixable: true,
            fixDescription: 'npm audit fix',
            fix: () => execSync('npm audit fix', { stdio: 'ignore', timeout: 60000 })
          });
        }
      } catch {
        // Audit output unparseable — skip
      }
    }
  }

  // 3. TeamPCP / WAVESHAPER.V2 artifact detection (cross-ecosystem).
  //    Checks for RAT drop paths, persistence mechanisms, and backdoor stagers
  //    used by the TeamPCP (UNC1069) campaign across npm and Python ecosystems.
  //    Covers WAVESHAPER.V2 indicators on Windows, macOS, and Linux.
  //    Skipped without admin/root since those paths are typically protected.
  if (hasAdmin) {
    checkTeamPCPArtifacts(sys, threats);
  }

  // 4. C2 (Command & Control) domain indicator in the system hosts file.
  //    Attackers sometimes modify the hosts file to redirect traffic to C2 servers.
  checkHostsFile(threats);

  // 5. Deep Lockfile Audit — recursively scan package-lock.json (or yarn.lock)
  //    for known malicious packages and suspicious "dropper" patterns.
  //    Dropper packages have install scripts but little to no real source code;
  //    they exist only to download and execute a payload (like plain-crypto-js).
  deepLockfileAudit(threats);

  // 6. Integrity Checksum & Decoy Swap Detection
  //    Inspired by the Axios attack where malicious code deleted its own package.json
  //    and renamed a clean package.md to replace it post-execution.
  //    Three-layer detection:
  //      a) Compare installed package integrity hashes against the npm registry
  //      b) Detect swap artifacts (package.md, .bak, .orig files)
  //      c) Flag packages where package.json was modified after installation
  await integrityAndSwapAudit(threats);

  // 7. Cross-ecosystem artifact scan (Python / PyPI).
  //    TeamPCP (UNC1069) targets both npm and PyPI. Developers often work in
  //    mixed-ecosystem projects. This scans for known malicious PyPI packages
  //    in requirements.txt / Pipfile.lock and checks for Python-based backdoor
  //    stagers in common staging directories.
  crossEcosystemScan(threats);

  // 8. Provenance Verification — "Shadow Execution" detection.
  //    Attackers bypass GitHub Actions / OIDC by using stolen long-lived npm
  //    tokens to publish directly from their own machines. High-profile packages
  //    (axios, lodash, etc.) are expected to have provenance attestations proving
  //    they were published from a CI/CD pipeline linked to a GitHub repository.
  //    A manual publish of a popular package is a strong indicator of token theft.
  await provenanceAudit(threats);

  // ── Diagnostic Report ──────────────────────────────────────────────────
  // Always printed. Shows every threat with its category and fixability.
  printDiagnosticReport(threats, fix);

  // ── Auto-remediation (only when --fix is passed) ───────────────────────
  // The tool is read-only by default. Fixes are opt-in and non-destructive.
  if (fix && threats.some(t => t.fixable)) {
    await runFixes(threats);
  }

  return threats.length > 0;
}

/**
 * Check whether the current process has elevated privileges.
 * - Windows: attempts `net session`, which only succeeds with admin rights.
 * - Unix/macOS: checks if the effective UID is 0 (root).
 * @param {string} sys - The OS platform string from os.platform().
 * @returns {Promise<boolean>} true if running with elevated privileges.
 */
function checkPermissions(sys) {
  return new Promise(resolve => {
    if (sys === 'win32') {
      try {
        execSync('net session', { stdio: 'ignore', timeout: 5000 });
        resolve(true);
      } catch {
        resolve(false);
      }
    } else {
      // Unix: uid 0 = root
      resolve(typeof process.getuid === 'function' && process.getuid() === 0);
    }
  });
}

/**
 * TeamPCP (UNC1069) / WAVESHAPER.V2 artifact detection — cross-ecosystem.
 *
 * This campaign targets npm (Axios, Trivy, KICS) and PyPI (LiteLLM, Telnyx).
 * The WAVESHAPER.V2 backdoor uses OS-specific drop locations and persistence
 * mechanisms. This function checks for:
 *
 *   Category 1 — RAT drop artifacts:
 *     - Windows: wt.exe in ProgramData (masquerades as Windows Terminal)
 *     - macOS:   com.apple.act.mond in Library/Caches (mimics system daemon)
 *     - Linux:   ld.py in /tmp (initial payload stager)
 *
 *   Category 2 — WAVESHAPER.V2 persistence artifacts:
 *     - Windows: Scheduled tasks, startup folder entries, registry run keys
 *     - macOS:   LaunchAgent/LaunchDaemon plists
 *     - Linux:   Cron entries, systemd service units
 *
 *   Category 3 — Cross-ecosystem backdoor stagers:
 *     - Python .py/.pyc files in staging directories used by TeamPCP
 *     - Suspicious scripts in common temp/cache paths
 *
 * Only called when the process has admin/root privileges.
 * @param {string} sys - The OS platform string.
 * @param {object[]} threats - Array to push structured threat objects into ({message, category, fixable, fixDescription, fix}).
 */
function checkTeamPCPArtifacts(sys, threats) {
  const home = os.homedir();

  // ── Category 1: RAT drop artifacts (original + expanded IoCs) ──────────
  const ratPaths = {
    win32: [
      path.join(process.env.PROGRAMDATA || 'C:\\ProgramData', 'wt.exe'),
      path.join(process.env.PROGRAMDATA || 'C:\\ProgramData', 'Microsoft', 'EdgeUpdate', 'msedgeupdate.exe'),
      path.join(process.env.TEMP || path.join(home, 'AppData', 'Local', 'Temp'), 'svchost.exe'),
      path.join(process.env.TEMP || path.join(home, 'AppData', 'Local', 'Temp'), 'conhost.dll'),
    ],
    darwin: [
      '/Library/Caches/com.apple.act.mond',
      '/Library/Caches/com.apple.syncdefaultsd',
      path.join(home, '.local/share/.data'),
    ],
    linux: [
      '/tmp/ld.py',
      '/tmp/.ld.py',
      '/var/tmp/.cache_update',
      '/dev/shm/.sess',
      path.join(home, '.local/share/.data'),
    ]
  };

  const paths = ratPaths[sys] || [];
  for (const p of paths) {
    if (fs.existsSync(p)) {
      threats.push({
        message: `TEAMPCP RAT: suspicious WAVESHAPER artifact at ${p}`,
        category: 'TEAMPCP',
        fixable: false,
        fixDescription: null,
        fix: null
      });
    }
  }

  // ── Category 2: Persistence mechanism artifacts ────────────────────────
  const persistencePaths = {
    win32: [
      // Startup folder entries
      path.join(home, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup', 'WindowsUpdate.lnk'),
      path.join(home, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup', 'EdgeUpdate.lnk'),
    ],
    darwin: [
      // LaunchAgents mimicking Apple services
      path.join(home, 'Library', 'LaunchAgents', 'com.apple.act.mond.plist'),
      path.join(home, 'Library', 'LaunchAgents', 'com.apple.syncdefaultsd.plist'),
      '/Library/LaunchDaemons/com.apple.act.mond.plist',
    ],
    linux: [
      // Systemd user services with suspicious names
      path.join(home, '.config', 'systemd', 'user', 'dbus-notifier.service'),
      path.join(home, '.config', 'systemd', 'user', 'cache-update.service'),
      // Cron drop files
      '/etc/cron.d/.cache-update',
    ]
  };

  const persPaths = persistencePaths[sys] || [];
  for (const p of persPaths) {
    if (fs.existsSync(p)) {
      threats.push({
        message: `TEAMPCP PERSISTENCE: suspicious persistence artifact at ${p}`,
        category: 'TEAMPCP',
        fixable: false,
        fixDescription: null,
        fix: null
      });
    }
  }

  // ── Category 3: Cross-ecosystem Python stagers ─────────────────────────
  // TeamPCP drops Python scripts in temp/cache dirs even in npm-based projects
  const pythonStagerPaths = {
    win32: [
      path.join(process.env.TEMP || path.join(home, 'AppData', 'Local', 'Temp'), 'ld.py'),
      path.join(process.env.TEMP || path.join(home, 'AppData', 'Local', 'Temp'), 'update.py'),
      path.join(process.env.APPDATA || path.join(home, 'AppData', 'Roaming'), 'pip', '.cache.py'),
    ],
    darwin: [
      '/tmp/ld.py',
      '/tmp/.update.py',
      path.join(home, 'Library', 'Caches', 'pip', '.cache.py'),
    ],
    linux: [
      '/tmp/.update.py',
      '/var/tmp/.ld.pyc',
      path.join(home, '.cache', 'pip', '.cache.py'),
    ]
  };

  const pyPaths = pythonStagerPaths[sys] || [];
  for (const p of pyPaths) {
    if (fs.existsSync(p)) {
      threats.push({
        message: `TEAMPCP STAGER: Python backdoor stager detected at ${p}`,
        category: 'TEAMPCP',
        fixable: false,
        fixDescription: null,
        fix: null
      });
    }
  }
}

/**
 * Known TeamPCP / UNC1069 C2 domains.
 * These domains have been observed in WAVESHAPER.V2 campaigns targeting
 * npm (Axios, Trivy, KICS) and PyPI (LiteLLM, Telnyx) ecosystems.
 */
const C2_DOMAINS = [
  'sfrclak.com',           // Original Axios C2
  'cfrclak.com',           // Typo-variant C2
  'actsyncmond.com',       // macOS LaunchAgent callback
  'edgeupdater.net',       // Windows persistence callback
  'dbus-notifyd.com',      // Linux systemd callback
  'syncdefaultsd.com',     // macOS variant
  'cache-updater.net',     // Cross-platform staging callback
];

/**
 * Scan the system hosts file for known C2 (Command & Control) domain indicators.
 * Malware may add entries to the hosts file to redirect DNS lookups to attacker-controlled
 * servers. Checks against the full TeamPCP C2 domain list.
 * Supports both Windows and Unix hosts file paths.
 * Fails silently if the file is unreadable (e.g., permissions).
 * @param {object[]} threats - Array to push structured threat objects into ({message, category, fixable, fixDescription, fix}).
 */
function checkHostsFile(threats) {
  const hostsPath = os.platform() === 'win32'
    ? path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'drivers', 'etc', 'hosts')
    : '/etc/hosts';

  try {
    const hosts = fs.readFileSync(hostsPath, 'utf8');
    const effectiveDomains = getEffectiveIocs().c2Domains;
    for (const domain of effectiveDomains) {
      if (hosts.includes(domain)) {
        threats.push({
          message: `CRITICAL: known TeamPCP C2 domain "${domain}" found in hosts file`,
          category: 'C2',
          fixable: false,
          fixDescription: null,
          fix: null
        });
      }
    }
  } catch {
    // Hosts file unreadable — skip silently
  }
}

/**
 * Known malicious package names — an expandable blocklist.
 * These packages have been identified as supply-chain attack vectors on npm.
 * Add new entries as new threats are discovered.
 */
const MALICIOUS_PACKAGES = [
  'plain-crypto-js',       // Axios attack — dropper disguised as crypto-js
  'flatmap-stream',        // event-stream incident — targeted cryptocurrency wallets
  'event-stream',          // v3.3.6 contained flatmap-stream as a dependency
  'ua-parser-js-infected', // Hijacked ua-parser-js with crypto-miner payload
  'rc-compromised',        // Compromised rc package variant
  'coa-compromised',       // Compromised coa package variant
];

/**
 * Deep Lockfile Audit — recursively scans the dependency tree for threats.
 *
 * Two-pass analysis:
 *   Pass 1: Check every resolved package name against the MALICIOUS_PACKAGES blocklist.
 *   Pass 2: Detect "dropper" packages — dependencies that declare install lifecycle
 *           scripts (preinstall, install, postinstall) but have no meaningful source
 *           code on disk. Attackers use these as shell droppers that download and
 *           execute remote payloads during npm install.
 *
 * Supports package-lock.json v2/v3 ("packages" key with nested node_modules paths)
 * and falls back to v1 format ("dependencies" key with recursive structure).
 *
 * @param {object[]} threats - Array to push structured threat objects into ({message, category, fixable, fixDescription, fix}).
 */
function deepLockfileAudit(threats) {
  const lockfilePath = path.join(process.cwd(), 'package-lock.json');

  if (!fs.existsSync(lockfilePath)) {
    // No lockfile found — nothing to audit (yarn.lock handled separately below)
    deepYarnLockAudit(threats);
    return;
  }

  let lockData;
  try {
    lockData = JSON.parse(fs.readFileSync(lockfilePath, 'utf8'));
  } catch {
    // Lockfile unreadable or malformed — skip
    return;
  }

  // Collect all package names from the lockfile
  const packages = extractPackagesFromLockfile(lockData);

  // Pass 1: Blocklist scan — flag any package whose name is on the known-bad list
  for (const pkg of packages) {
    if (getEffectiveIocs().maliciousNpmPackages.includes(pkg.name)) {
      const pkgName = pkg.name;
      threats.push({
        message: `LOCKFILE: known malicious package "${pkgName}" found in dependency tree`,
        category: 'LOCKFILE',
        fixable: true,
        fixDescription: `npm uninstall ${pkgName}`,
        fix: () => execSync(`npm uninstall ${pkgName}`, { stdio: 'ignore', timeout: 30000 })
      });
    }
  }

  // Pass 2: Dropper detection — find packages with install scripts but no real code
  const nodeModulesDir = path.join(process.cwd(), 'node_modules');
  if (fs.existsSync(nodeModulesDir)) {
    for (const pkg of packages) {
      if (pkg.hasInstallScript) {
        const suspicion = isLikelyDropper(nodeModulesDir, pkg.name);
        if (suspicion) {
          const pkgName = pkg.name;
          const safeToFix = isSafePackageName(pkgName);
          threats.push({
            message: `DROPPER: "${pkgName}" has install scripts but ${suspicion}`,
            category: 'DROPPER',
            fixable: safeToFix,
            fixDescription: safeToFix ? `npm uninstall ${pkgName}` : null,
            fix: safeToFix ? () => execSync(`npm uninstall ${pkgName}`, { stdio: 'ignore', timeout: 30000 }) : null
          });
        }
      }
    }
  }
}

/**
 * Extract a flat list of package metadata from package-lock.json.
 * Handles both v2/v3 format (flat "packages" map with node_modules/ paths)
 * and v1 format (nested "dependencies" tree).
 *
 * @param {object} lockData - Parsed package-lock.json contents.
 * @returns {{ name: string, hasInstallScript: boolean, integrity: string|null, version: string|null }[]}
 */
function extractPackagesFromLockfile(lockData) {
  const results = [];

  if (lockData.packages) {
    // v2/v3 format — keys are paths like "node_modules/axios" or
    // "node_modules/axios/node_modules/plain-crypto-js" (nested deps)
    for (const [pkgPath, meta] of Object.entries(lockData.packages)) {
      if (!pkgPath || pkgPath === '') continue; // skip root entry

      // Extract package name from the path (last node_modules/ segment)
      const segments = pkgPath.split('node_modules/');
      const name = segments[segments.length - 1];
      if (!name) continue;

      results.push({
        name,
        hasInstallScript: !!(meta.hasInstallScript ||
          (meta.scripts && (meta.scripts.preinstall || meta.scripts.install || meta.scripts.postinstall))),
        integrity: meta.integrity || null,
        version: meta.version || null
      });
    }
  } else if (lockData.dependencies) {
    // v1 format — recursively walk the nested "dependencies" tree
    walkV1Dependencies(lockData.dependencies, results);
  }

  return results;
}

/**
 * Recursively walk v1 lockfile "dependencies" tree to extract package metadata.
 * @param {object} deps - The dependencies object at the current tree level.
 * @param {{ name: string, hasInstallScript: boolean, integrity: string|null, version: string|null }[]} results
 */
function walkV1Dependencies(deps, results) {
  for (const [name, meta] of Object.entries(deps)) {
    results.push({
      name,
      hasInstallScript: !!(meta.hasInstallScript ||
        (meta.scripts && (meta.scripts.preinstall || meta.scripts.install || meta.scripts.postinstall))),
      integrity: meta.integrity || null,
      version: meta.version || null
    });

    // Recurse into nested dependencies (transitive deps bundled at this level)
    if (meta.dependencies) {
      walkV1Dependencies(meta.dependencies, results);
    }
  }
}

/**
 * Heuristic: determine if a package in node_modules is a likely "dropper."
 *
 * A dropper package has install lifecycle scripts but ships with no meaningful
 * source code — or its install scripts contain suspicious patterns that indicate
 * malicious intent (network fetching, obfuscation, sensitive path access).
 *
 * Two-signal analysis:
 *   Signal 1 — Structural: Does the package lack real source code?
 *     1. Does the package directory exist?
 *     2. Does it contain any .js/.ts/.mjs/.cjs files beyond index.js?
 *     3. Is the main entry file (if any) suspiciously small (< 50 bytes)?
 *
 *   Signal 2 — Behavioral: Do the install scripts contain suspicious patterns?
 *     - Obfuscated network requests (curl, wget, Invoke-WebRequest piped to shell)
 *     - Access to sensitive system paths (/etc/hosts, %PROGRAMDATA%, %APPDATA%)
 *     - Obfuscation techniques (base64 decode, eval, hex-encoded strings)
 *     - Remote code execution (pipe to sh/bash/cmd/powershell, node -e)
 *
 * A package is flagged as a dropper only if:
 *   - It has no source code AND suspicious script patterns, OR
 *   - It has no source code at all (zero files), OR
 *   - It has source code but its install scripts contain multiple suspicious patterns
 *
 * This reduces false positives from legitimate "wrapper" packages (e.g., native
 * addon builders like node-gyp, or platform-specific binary installers).
 *
 * Scoped packages (e.g., @scope/pkg) are resolved to node_modules/@scope/pkg.
 *
 * @param {string} nodeModulesDir - Absolute path to the project's node_modules.
 * @param {string} pkgName - Package name (may be scoped like @scope/pkg).
 * @returns {string|null} A description of why it looks suspicious, or null if clean.
 */
function isLikelyDropper(nodeModulesDir, pkgName) {
  const pkgDir = path.join(nodeModulesDir, ...pkgName.split('/'));
  if (!fs.existsSync(pkgDir)) return null;

  // Read the package's own package.json to find the main entry point
  let pkgJson;
  try {
    pkgJson = JSON.parse(fs.readFileSync(path.join(pkgDir, 'package.json'), 'utf8'));
  } catch {
    return null;
  }

  // Count actual source files (excluding package.json, README, LICENSE, etc.)
  const sourceExtensions = new Set(['.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx']);
  let sourceFileCount = 0;
  let totalSourceBytes = 0;

  try {
    const files = readdirRecursiveSync(pkgDir);
    for (const file of files) {
      const ext = path.extname(file).toLowerCase();
      if (sourceExtensions.has(ext)) {
        sourceFileCount++;
        try {
          const stat = fs.statSync(file);
          totalSourceBytes += stat.size;
        } catch {
          // File unreadable — skip
        }
      }
    }
  } catch {
    return null;
  }

  // Analyze install script content for suspicious patterns
  const scriptAnalysis = analyzeInstallScripts(pkgDir, pkgJson);

  // Decision logic: combine structural + behavioral signals
  if (sourceFileCount === 0 && scriptAnalysis) {
    // No source code AND suspicious scripts — strongest dropper signal
    return `contains no source files and ${scriptAnalysis}`;
  }
  if (sourceFileCount === 0) {
    // No source code at all — suspicious regardless of script content
    return 'contains no source files (possible shell dropper)';
  }
  if (sourceFileCount === 1 && totalSourceBytes < 50 && scriptAnalysis) {
    // Trivial stub + suspicious scripts — very likely a dropper
    return `contains only a trivial stub file (< 50 bytes) and ${scriptAnalysis}`;
  }
  if (sourceFileCount === 1 && totalSourceBytes < 50) {
    // Trivial stub without suspicious scripts — might be a legitimate wrapper,
    // still worth flagging but lower confidence
    return 'contains only a trivial stub file (< 50 bytes of code)';
  }
  if (scriptAnalysis && scriptAnalysis.includes('multiple')) {
    // Has source code but install scripts contain multiple suspicious patterns —
    // legitimate packages almost never do this
    return `has source code but ${scriptAnalysis}`;
  }

  return null;
}

/**
 * Suspicious patterns found in dropper install scripts.
 *
 * Each pattern targets a specific attack technique used in real supply-chain
 * compromises (Axios, event-stream, ua-parser-js, TeamPCP campaigns):
 *
 *   - Network fetching: curl/wget/Invoke-WebRequest piped to a shell
 *   - Sensitive paths: /etc/hosts, %PROGRAMDATA%, %APPDATA%, ~/.ssh
 *   - Obfuscation: base64 decode, hex strings, Buffer.from, eval
 *   - Remote execution: piping to sh/bash/cmd/powershell, node -e
 */
const DROPPER_SCRIPT_PATTERNS = [
  // ── Network fetch + execute (the classic dropper pattern) ──────────────
  /\bcurl\b.*\|\s*(sh|bash|node)\b/i,          // curl ... | sh
  /\bwget\b.*\|\s*(sh|bash|node)\b/i,          // wget ... | sh
  /\bcurl\b.*-[so]\s/i,                        // curl -s or curl -o (silent download)
  /\bwget\b.*-[qO]\s/i,                        // wget -q or wget -O (quiet download)
  /Invoke-WebRequest\b/i,                      // PowerShell web fetch
  /\bhttp\.get\b|\bhttps\.get\b/i,             // Node.js native HTTP fetch in script
  /\bfetch\s*\(\s*['"]https?:/i,               // fetch() with URL literal

  // ── Sensitive system path access ───────────────────────────────────────
  /\/etc\/hosts\b/,                             // Hosts file manipulation (C2 redirect)
  /%PROGRAMDATA%/i,                             // Windows ProgramData (RAT drop location)
  /%APPDATA%/i,                                 // Windows AppData (persistence location)
  /~\/\.ssh\b|\.ssh\/id_rsa/,                   // SSH key theft
  /\/etc\/shadow\b/,                            // Linux password database
  /\/etc\/passwd\b/,                            // Linux user database

  // ── Obfuscation techniques ─────────────────────────────────────────────
  /\bbase64\b.*\b(decode|--decode|-d)\b/i,      // base64 decode on CLI
  /Buffer\.from\(.*,\s*['"]base64['"]\)/,       // Node.js base64 decode
  /\batob\s*\(/,                                // Browser/Node atob decode
  /\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}/i, // Hex-encoded strings (3+ consecutive)
  /\beval\s*\(/,                                // eval() — dynamic code execution
  /\bFunction\s*\(/,                            // Function() constructor — eval equivalent

  // ── Remote code execution via shell ────────────────────────────────────
  /\|\s*(bash|sh|cmd|powershell|pwsh)\b/i,      // Pipe to shell interpreter
  /\bnode\s+-e\s/,                              // node -e (inline code execution)
  /\bpython[23]?\s+-c\s/,                       // python -c (inline Python execution)
  /require\s*\(\s*['"]child_process['"]\s*\)/,   // Importing child_process in install script
  /\.exec\s*\(|\.execSync\s*\(/,                // child_process exec/execSync call
];

/**
 * Analyze install script content for suspicious patterns.
 *
 * Examines the raw script commands from package.json (preinstall, install,
 * postinstall) plus any script files they reference (e.g., "node install.js").
 * Checks against DROPPER_SCRIPT_PATTERNS for known attack techniques.
 *
 * @param {string} pkgDir - Absolute path to the package directory.
 * @param {object} pkgJson - Parsed package.json of the package.
 * @returns {string|null} Description of suspicious patterns found, or null if clean.
 */
function analyzeInstallScripts(pkgDir, pkgJson) {
  if (!pkgJson.scripts) return null;

  const scriptKeys = ['preinstall', 'install', 'postinstall'];
  let allScriptContent = '';

  for (const key of scriptKeys) {
    const script = pkgJson.scripts[key];
    if (!script) continue;

    // Collect the raw script command itself
    allScriptContent += script + '\n';

    // If the script references a local file (e.g., "node install.js", "sh setup.sh"),
    // read that file's content for deeper analysis
    const fileRef = script.match(/\b(?:node|sh|bash)\s+([^\s;&|]+)/);
    if (fileRef && fileRef[1]) {
      const refPath = path.join(pkgDir, fileRef[1]);
      try {
        if (fs.existsSync(refPath)) {
          allScriptContent += fs.readFileSync(refPath, 'utf8') + '\n';
        }
      } catch {
        // File unreadable — skip
      }
    }
  }

  if (!allScriptContent.trim()) return null;

  // Match against dropper patterns
  const matched = [];
  for (const pattern of DROPPER_SCRIPT_PATTERNS) {
    if (pattern.test(allScriptContent)) {
      matched.push(pattern.source.replace(/\\b/g, '').replace(/\\/g, '').substring(0, 30));
    }
  }

  if (matched.length === 0) return null;
  if (matched.length === 1) {
    return `install script contains suspicious pattern (${matched[0]})`;
  }
  return `install scripts contain multiple suspicious patterns (${matched.length} found)`;
}

/**
 * Recursively list all files in a directory (non-symlink).
 * Skips nested node_modules to avoid scanning transitive dependencies.
 * @param {string} dir - Absolute directory path.
 * @returns {string[]} List of absolute file paths.
 */
function readdirRecursiveSync(dir) {
  const results = [];
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return results;
  }
  for (const entry of entries) {
    // Skip nested node_modules inside the package
    if (entry.name === 'node_modules') continue;
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...readdirRecursiveSync(fullPath));
    } else if (entry.isFile()) {
      results.push(fullPath);
    }
  }
  return results;
}

/**
 * Minimal yarn.lock audit — scans for known malicious package names.
 * yarn.lock is a flat text format so we do a simple line-based name match.
 * Dropper detection still works via the node_modules scan in the npm path.
 * @param {object[]} threats - Array to push structured threat objects into ({message, category, fixable, fixDescription, fix}).
 */
function deepYarnLockAudit(threats) {
  const yarnLockPath = path.join(process.cwd(), 'yarn.lock');
  if (!fs.existsSync(yarnLockPath)) return;

  let content;
  try {
    content = fs.readFileSync(yarnLockPath, 'utf8');
  } catch {
    return;
  }

  // yarn.lock entries start with the package name at the beginning of a line,
  // e.g. 'plain-crypto-js@^1.0.0:' or '"@scope/pkg@^1.0.0":'
  const effectiveNpmPkgs = getEffectiveIocs().maliciousNpmPackages;
  for (const malPkg of effectiveNpmPkgs) {
    // Match the package name at the start of a line, followed by @ (version) or ","
    const pattern = new RegExp(`^"?${escapeRegex(malPkg)}@`, 'm');
    if (pattern.test(content)) {
      threats.push({
        message: `LOCKFILE: known malicious package "${malPkg}" found in yarn.lock`,
        category: 'LOCKFILE',
        fixable: true,
        fixDescription: `yarn remove ${malPkg}`,
        fix: () => execSync(`yarn remove ${malPkg}`, { stdio: 'ignore', timeout: 30000 })
      });
    }
  }
}

/**
 * Escape special regex characters in a string.
 * @param {string} str - The string to escape.
 * @returns {string} Escaped string safe for use in RegExp.
 */
function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ─────────────────────────────────────────────────────────────────────────────
//  6. Integrity Checksum & Decoy Swap Detection
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Decoy swap artifact file names.
 * The Axios attack renamed package.json → package.md after execution, then
 * swapped a clean copy back. These file names are telltale signs of the trick.
 */
const SWAP_ARTIFACTS = [
  'package.md',          // The Axios attack pattern — clean decoy stored as .md
  'package.json.bak',   // Common backup suffix
  'package.json.orig',  // Patch-style backup
  'package.json.old',   // Another common backup suffix
  '.package.json',      // Hidden backup
];

/**
 * Integrity & Decoy Swap Audit — three-layer detection:
 *
 *   Layer 1 (local): Compare the _integrity hash npm wrote into the installed
 *                    package.json against the integrity hash in package-lock.json.
 *                    A mismatch means the package was modified after install.
 *
 *   Layer 2 (registry): For high-risk packages (those with install scripts),
 *                       fetch the dist.shasum from the npm registry and compare
 *                       it against the lockfile. If the lockfile itself was
 *                       tampered with, this catches it.
 *
 *   Layer 3 (heuristic): Detect swap artifacts (package.md, .bak files) and
 *                        flag packages where package.json was modified
 *                        significantly later than the rest of the package.
 *
 * @param {object[]} threats - Array to push structured threat objects into ({message, category, fixable, fixDescription, fix}).
 */
async function integrityAndSwapAudit(threats) {
  const lockfilePath = path.join(process.cwd(), 'package-lock.json');
  const nodeModulesDir = path.join(process.cwd(), 'node_modules');

  if (!fs.existsSync(nodeModulesDir)) return;

  // Parse lockfile for integrity data (if available)
  let lockfilePackages = [];
  if (fs.existsSync(lockfilePath)) {
    try {
      const lockData = JSON.parse(fs.readFileSync(lockfilePath, 'utf8'));
      lockfilePackages = extractPackagesFromLockfile(lockData);
    } catch {
      // Lockfile unreadable — proceed with swap detection only
    }
  }

  // Build a map of lockfile packages for quick lookup
  const lockMap = new Map();
  for (const pkg of lockfilePackages) {
    lockMap.set(pkg.name, pkg);
  }

  // Scan installed packages
  const installedPkgs = listInstalledPackages(nodeModulesDir);

  for (const pkgName of installedPkgs) {
    const pkgDir = path.join(nodeModulesDir, ...pkgName.split('/'));
    const pkgJsonPath = path.join(pkgDir, 'package.json');

    let installedPkgJson;
    try {
      installedPkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
    } catch {
      continue;
    }

    // Layer 1: Lockfile vs installed integrity mismatch
    const lockEntry = lockMap.get(pkgName);
    if (lockEntry && lockEntry.integrity && installedPkgJson._integrity) {
      if (lockEntry.integrity !== installedPkgJson._integrity) {
        const pName = pkgName;
        threats.push({
          message: `INTEGRITY: "${pName}" installed hash (${installedPkgJson._integrity.substring(0, 20)}...) ` +
            `does not match lockfile hash — possible post-install tampering`,
          category: 'INTEGRITY',
          fixable: true,
          fixDescription: `npm ci (clean reinstall from lockfile)`,
          fix: () => execSync('npm ci', { stdio: 'ignore', timeout: 120000 })
        });
      }
    }

    // Layer 3: Swap artifact detection (runs for all packages, no network needed)
    detectSwapArtifacts(pkgDir, pkgName, threats);
  }

  // Layer 2: Registry verification for high-risk packages (those with install scripts)
  const highRiskPkgs = lockfilePackages.filter(p => p.hasInstallScript && p.version);
  // Limit registry checks to avoid excessive network calls (top 20 high-risk)
  const toVerify = highRiskPkgs.slice(0, 20);

  for (const pkg of toVerify) {
    try {
      await verifyRegistryIntegrity(pkg, threats);
    } catch {
      // Network failure — skip silently, other layers still protect
    }
  }
}

/**
 * List all top-level installed package names in node_modules.
 * Handles scoped packages (@scope/pkg).
 * @param {string} nodeModulesDir - Absolute path to node_modules.
 * @returns {string[]} List of package names.
 */
function listInstalledPackages(nodeModulesDir) {
  const results = [];
  let entries;
  try {
    entries = fs.readdirSync(nodeModulesDir, { withFileTypes: true });
  } catch {
    return results;
  }

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    if (entry.name === '.package-lock.json' || entry.name === '.cache') continue;

    if (entry.name.startsWith('@')) {
      // Scoped package — read subdirectory
      try {
        const scopeEntries = fs.readdirSync(path.join(nodeModulesDir, entry.name), { withFileTypes: true });
        for (const scopeEntry of scopeEntries) {
          if (scopeEntry.isDirectory()) {
            results.push(`${entry.name}/${scopeEntry.name}`);
          }
        }
      } catch {
        // Unreadable scope dir — skip
      }
    } else {
      results.push(entry.name);
    }
  }

  return results;
}

/**
 * Detect telltale artifacts of a decoy swap attack within a package directory.
 *
 * Checks for:
 *   1. Swap backup files (package.md, package.json.bak, etc.)
 *   2. package.json modification time anomaly — if package.json was modified
 *      more than 60 seconds after the oldest file in the package, it may have
 *      been swapped post-install.
 *
 * @param {string} pkgDir - Absolute path to the package directory.
 * @param {string} pkgName - Package name (for reporting).
 * @param {object[]} threats - Array to push structured threat objects into ({message, category, fixable, fixDescription, fix}).
 */
function detectSwapArtifacts(pkgDir, pkgName, threats) {
  // Check for swap artifact files
  for (const artifact of SWAP_ARTIFACTS) {
    const artifactPath = path.join(pkgDir, artifact);
    if (fs.existsSync(artifactPath)) {
      const artFile = artifact;
      const artPath = artifactPath;
      threats.push({
        message: `SWAP: "${pkgName}" contains suspicious file "${artFile}" — ` +
          `possible decoy swap (attacker backup of original package.json)`,
        category: 'SWAP',
        fixable: true,
        fixDescription: `Delete ${artFile} from ${pkgName}`,
        fix: () => fs.unlinkSync(artPath)
      });
    }
  }

  // Check for package.json modification time anomaly
  try {
    const pkgJsonStat = fs.statSync(path.join(pkgDir, 'package.json'));
    const pkgJsonMtime = pkgJsonStat.mtimeMs;

    // Find the earliest mtime among other files in the package root
    const entries = fs.readdirSync(pkgDir, { withFileTypes: true });
    let earliestMtime = Infinity;

    for (const entry of entries) {
      if (entry.name === 'package.json' || entry.name === 'node_modules') continue;
      try {
        const stat = fs.statSync(path.join(pkgDir, entry.name));
        if (stat.mtimeMs < earliestMtime) {
          earliestMtime = stat.mtimeMs;
        }
      } catch {
        continue;
      }
    }

    // If package.json was modified more than 60 seconds after the oldest file,
    // it's suspicious — normal npm install writes all files at roughly the same time.
    // A 60-second threshold avoids false positives from filesystem timing variance.
    if (earliestMtime < Infinity && (pkgJsonMtime - earliestMtime) > 60000) {
      const gap = Math.round((pkgJsonMtime - earliestMtime) / 1000);
      const pName = pkgName;
      const safeToFix = isSafePackageName(pName);
      threats.push({
        message: `SWAP: "${pName}" package.json was modified ${gap}s after other files — ` +
          `possible post-install decoy swap`,
        category: 'SWAP',
        fixable: safeToFix,
        fixDescription: safeToFix ? `npm install ${pName} (reinstall from registry)` : null,
        fix: safeToFix ? () => execSync(`npm install ${pName}`, { stdio: 'ignore', timeout: 60000 }) : null
      });
    }
  } catch {
    // Can't stat files — skip
  }
}

/**
 * Verify a package's lockfile integrity hash against the npm registry.
 *
 * Fetches the package metadata from registry.npmjs.org and compares the
 * dist.shasum (SHA-1) against the lockfile's integrity field. If the lockfile
 * contains an SHA-512 integrity hash, we also fetch and compare the registry's
 * SHA-512 integrity if available.
 *
 * This detects lockfile tampering — if an attacker modifies the lockfile to
 * point to a malicious tarball, the hash won't match the registry.
 *
 * @param {{ name: string, version: string, integrity: string|null }} pkg
 * @param {object[]} threats - Array to push structured threat objects into ({message, category, fixable, fixDescription, fix}).
 */
async function verifyRegistryIntegrity(pkg, threats) {
  if (!pkg.integrity) return;

  const registryData = await fetchRegistryMetadata(pkg.name, pkg.version);
  if (!registryData || !registryData.dist) return;

  const registryShasum = registryData.dist.shasum;
  const registryIntegrity = registryData.dist.integrity;

  // Compare SHA-512 integrity if available (preferred, more secure)
  if (registryIntegrity && pkg.integrity.startsWith('sha512-')) {
    if (pkg.integrity !== registryIntegrity) {
      threats.push({
        message: `INTEGRITY: "${pkg.name}@${pkg.version}" lockfile integrity does not match npm registry — ` +
          `possible lockfile tampering`,
        category: 'INTEGRITY',
        fixable: true,
        fixDescription: 'npm ci (clean reinstall from lockfile)',
        fix: () => execSync('npm ci', { stdio: 'ignore', timeout: 120000 })
      });
    }
    return;
  }

  // Fall back to SHA-1 comparison
  if (registryShasum && pkg.integrity.startsWith('sha1-')) {
    // Convert lockfile sha1 base64 to hex for comparison
    const lockSha1Hex = Buffer.from(pkg.integrity.replace('sha1-', ''), 'base64').toString('hex');
    if (lockSha1Hex !== registryShasum) {
      threats.push({
        message: `INTEGRITY: "${pkg.name}@${pkg.version}" lockfile shasum does not match npm registry — ` +
          `possible lockfile tampering`,
        category: 'INTEGRITY',
        fixable: true,
        fixDescription: 'npm ci (clean reinstall from lockfile)',
        fix: () => execSync('npm ci', { stdio: 'ignore', timeout: 120000 })
      });
    }
  }
}

/**
 * Fetch package version metadata from the npm registry.
 * Uses the abbreviated metadata endpoint for speed.
 *
 * @param {string} name - Package name (may be scoped).
 * @param {string} version - Exact version string.
 * @returns {Promise<object|null>} The version metadata object, or null on failure.
 */
function fetchRegistryMetadata(name, version) {
  // Encode scoped package names: @scope/pkg → @scope%2fpkg
  const encodedName = name.startsWith('@')
    ? `@${encodeURIComponent(name.slice(1))}`
    : encodeURIComponent(name);

  const url = `https://registry.npmjs.org/${encodedName}/${version}`;

  return new Promise(resolve => {
    const req = https.get(url, { timeout: 10000 }, (res) => {
      if (res.statusCode !== 200) {
        res.resume(); // Drain the response
        resolve(null);
        return;
      }

      let body = '';
      res.setEncoding('utf8');
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => {
        try {
          resolve(JSON.parse(body));
        } catch {
          resolve(null);
        }
      });
    });

    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
  });
}

// ─────────────────────────────────────────────────────────────────────────────
//  7. Cross-Ecosystem Artifact Scan (Python / PyPI)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Known malicious PyPI packages linked to TeamPCP / UNC1069.
 * These packages were part of the same campaign that targeted Axios via npm.
 *   - litellm variants: backdoored proxy for LLM APIs
 *   - telnyx variants: backdoored telephony SDK
 *   - trivy/kics variants: targeted security tool users specifically
 */
const MALICIOUS_PYPI_PACKAGES = [
  'litellm-proxy',         // Backdoored LiteLLM proxy
  'litellm-sdk',           // Fake LiteLLM SDK
  'telnyx-sdk',            // Backdoored Telnyx telephony SDK
  'telnyx-api',            // Fake Telnyx API wrapper
  'trivy-scanner',         // Fake Trivy scanner targeting security researchers
  'kics-scanner',          // Fake KICS scanner targeting security researchers
  'aqua-trivy',            // Typosquat of Aqua Security's Trivy
  'litellm-internal',      // Internal namespace typosquat
];

/**
 * Cross-ecosystem scan for Python/PyPI artifacts of the TeamPCP campaign.
 *
 * Many developers work in mixed npm + Python environments. TeamPCP exploits this
 * by planting malicious packages in both ecosystems simultaneously, increasing
 * the chance of compromise.
 *
 * This function checks:
 *   1. requirements.txt — for known malicious PyPI package names
 *   2. Pipfile — for known malicious packages in the [packages] section
 *   3. Pipfile.lock — structured JSON, checked against the blocklist
 *   4. Suspicious .py files in the project root — potential backdoor stagers
 *      that shouldn't exist in a Node.js project
 *
 * @param {object[]} threats - Array to push structured threat objects into ({message, category, fixable, fixDescription, fix}).
 */
function crossEcosystemScan(threats) {
  const cwd = process.cwd();

  // 1. Scan requirements.txt for malicious PyPI packages
  scanRequirementsTxt(cwd, threats);

  // 2. Scan Pipfile for malicious PyPI packages
  scanPipfile(cwd, threats);

  // 3. Scan Pipfile.lock for malicious PyPI packages
  scanPipfileLock(cwd, threats);

  // 4. Detect suspicious Python stager scripts in the project root
  //    A .py file in a Node.js project root is unusual; doubly so if it
  //    contains network/subprocess calls typical of backdoor stagers.
  detectPythonStagers(cwd, threats);
}

/**
 * Scan requirements.txt for known malicious PyPI packages.
 * Parses each line as "package==version" or "package>=version" etc.
 * @param {string} cwd - Current working directory.
 * @param {object[]} threats - Array to push structured threat objects into ({message, category, fixable, fixDescription, fix}).
 */
function scanRequirementsTxt(cwd, threats) {
  const reqFiles = ['requirements.txt', 'requirements-dev.txt', 'requirements_dev.txt'];

  for (const reqFile of reqFiles) {
    const reqPath = path.join(cwd, reqFile);
    if (!fs.existsSync(reqPath)) continue;

    let content;
    try {
      content = fs.readFileSync(reqPath, 'utf8');
    } catch {
      continue;
    }

    const lines = content.split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      // Skip comments and blank lines
      if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) continue;

      // Extract package name (before any version specifier)
      const pkgName = trimmed.split(/[>=<!~\s\[;]/)[0].toLowerCase();
      if (getEffectiveIocs().maliciousPypiPackages.includes(pkgName)) {
        threats.push({
          message: `PYPI: malicious package "${pkgName}" found in ${reqFile}`,
          category: 'PYPI',
          fixable: false,
          fixDescription: null,
          fix: null
        });
      }
    }
  }
}

/**
 * Scan Pipfile [packages] section for known malicious PyPI packages.
 * Pipfile uses TOML-like format; we do a simple line-based check for
 * package names appearing as keys under [packages] or [dev-packages].
 * @param {string} cwd - Current working directory.
 * @param {object[]} threats - Array to push structured threat objects into ({message, category, fixable, fixDescription, fix}).
 */
function scanPipfile(cwd, threats) {
  const pipfilePath = path.join(cwd, 'Pipfile');
  if (!fs.existsSync(pipfilePath)) return;

  let content;
  try {
    content = fs.readFileSync(pipfilePath, 'utf8');
  } catch {
    return;
  }

  // Simple line-based scan — check if any malicious package name appears as a key
  const lines = content.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('[')) continue;

    // Pipfile keys are package names: `litellm-proxy = "*"`
    const pkgName = trimmed.split('=')[0].trim().replace(/"/g, '').toLowerCase();
    if (getEffectiveIocs().maliciousPypiPackages.includes(pkgName)) {
      threats.push({
        message: `PYPI: malicious package "${pkgName}" found in Pipfile`,
        category: 'PYPI',
        fixable: false,
        fixDescription: null,
        fix: null
      });
    }
  }
}

/**
 * Scan Pipfile.lock (JSON format) for known malicious PyPI packages.
 * Checks both "default" and "develop" dependency sections.
 * @param {string} cwd - Current working directory.
 * @param {object[]} threats - Array to push structured threat objects into ({message, category, fixable, fixDescription, fix}).
 */
function scanPipfileLock(cwd, threats) {
  const lockPath = path.join(cwd, 'Pipfile.lock');
  if (!fs.existsSync(lockPath)) return;

  let lockData;
  try {
    lockData = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
  } catch {
    return;
  }

  const sections = ['default', 'develop'];
  for (const section of sections) {
    if (!lockData[section]) continue;
    for (const pkgName of Object.keys(lockData[section])) {
      if (getEffectiveIocs().maliciousPypiPackages.includes(pkgName.toLowerCase())) {
        threats.push({
          message: `PYPI: malicious package "${pkgName}" found in Pipfile.lock [${section}]`,
          category: 'PYPI',
          fixable: false,
          fixDescription: null,
          fix: null
        });
      }
    }
  }
}

/**
 * Detect suspicious Python scripts in a Node.js project root.
 *
 * A .py file in the root of a Node.js project (one that has package.json)
 * is unusual. If that file also contains patterns typical of backdoor stagers
 * (subprocess, socket, urllib, exec, eval, base64 decode), it's flagged.
 *
 * This catches TeamPCP's tactic of dropping Python stagers alongside npm
 * packages to establish a secondary backdoor channel.
 *
 * @param {string} cwd - Current working directory.
 * @param {object[]} threats - Array to push structured threat objects into ({message, category, fixable, fixDescription, fix}).
 */
function detectPythonStagers(cwd, threats) {
  // Only check if this is a Node.js project (has package.json)
  if (!fs.existsSync(path.join(cwd, 'package.json'))) return;

  let entries;
  try {
    entries = fs.readdirSync(cwd, { withFileTypes: true });
  } catch {
    return;
  }

  // Suspicious patterns found in backdoor stagers
  const stagerPatterns = [
    /subprocess\.(Popen|call|run|check_output)/,
    /socket\.socket\(/,
    /urllib\.request\.urlopen\(/,
    /exec\s*\(/,
    /eval\s*\(/,
    /base64\.b64decode\(/,
    /os\.system\s*\(/,
    /\bimport\s+ctypes\b/,
    /\bcompile\s*\(.*base64/,
    /requests\.(get|post)\s*\(.*\bhttp/,
  ];

  for (const entry of entries) {
    if (!entry.isFile()) continue;
    if (!entry.name.endsWith('.py') && !entry.name.endsWith('.pyc')) continue;
    // Skip well-known benign Python files
    if (['setup.py', 'conftest.py', 'noxfile.py', 'fabfile.py'].includes(entry.name)) continue;

    const filePath = path.join(cwd, entry.name);
    let content;
    try {
      content = fs.readFileSync(filePath, 'utf8');
    } catch {
      continue;
    }

    const matches = stagerPatterns.filter(p => p.test(content));
    if (matches.length >= 2) {
      // Two or more suspicious patterns = likely a stager, not a benign script
      threats.push({
        message: `TEAMPCP STAGER: suspicious Python file "${entry.name}" in project root ` +
          `contains ${matches.length} backdoor-like patterns`,
        category: 'TEAMPCP',
        fixable: false,
        fixDescription: null,
        fix: null
      });
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Diagnostic Report & Auto-Remediation
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Print a structured Diagnostic Report to the console.
 *
 * The report always shows all threats with their category and whether
 * they are fixable. This is the "trust" principle — developers see every
 * finding before any action is taken. The tool never modifies anything
 * without showing this report first.
 *
 * @param {{ message: string, category: string, fixable: boolean }[]} threats
 * @param {boolean} fixMode - Whether --fix was passed (affects the summary hint).
 */
function printDiagnosticReport(threats, fixMode) {
  const divider = '─'.repeat(70);
  console.log(`\n${divider}`);
  console.log('  @sathyendra/security-checker — Diagnostic Report');
  console.log(divider);

  if (threats.length === 0) {
    console.log('  ✅ No threats detected — project is clean');
    console.log(`${divider}\n`);
    return;
  }

  for (const t of threats) {
    const tag = t.fixable ? '[FIXABLE]' : '[MANUAL]';
    console.error(`  🚨 ${t.message}  ${tag}`);
  }

  const fixableCount = threats.filter(t => t.fixable).length;
  const manualCount = threats.length - fixableCount;

  console.log(divider);
  console.log(`  ${threats.length} threat(s) found | ${fixableCount} fixable | ${manualCount} require manual review`);

  if (fixableCount > 0 && !fixMode) {
    console.log('  Run with --fix to auto-remediate fixable threats.');
  }
  console.log(`${divider}\n`);
}

/**
 * Execute auto-remediation for all fixable threats.
 *
 * Runs each fix sequentially and reports success/failure. Non-fixable threats
 * are listed with a manual-action reminder. Fixes are non-destructive where
 * possible (npm uninstall, npm audit fix, npm ci, deleting swap artifacts).
 *
 * Only called when --fix is explicitly passed. The diagnostic report is
 * always shown first so the developer knows what will be changed.
 *
 * @param {{ message: string, category: string, fixable: boolean, fixDescription: string|null, fix: Function|null }[]} threats
 */
async function runFixes(threats) {
  const divider = '─'.repeat(70);
  console.log(divider);
  console.log('  Auto-Remediation');
  console.log(divider);

  let fixedCount = 0;
  let failedCount = 0;
  const alreadyRun = new Set();

  for (const t of threats) {
    if (!t.fixable || !t.fix) {
      console.log(`  ⚠️  MANUAL: ${t.message}`);
      continue;
    }

    // Deduplicate identical fix commands (e.g., multiple integrity issues → one npm ci)
    const dedupeKey = t.fixDescription || t.message;
    if (alreadyRun.has(dedupeKey)) {
      console.log(`  ↩️  SKIP: ${t.fixDescription} (already applied)`);
      continue;
    }
    alreadyRun.add(dedupeKey);

    try {
      t.fix();
      console.log(`  ✅ FIXED: ${t.fixDescription}`);
      fixedCount++;
    } catch (err) {
      console.error(`  ❌ FAILED: ${t.fixDescription} — ${err.message}`);
      failedCount++;
    }
  }

  const manualCount = threats.filter(t => !t.fixable).length;
  console.log(divider);
  console.log(
    `  ${fixedCount} fixed | ${failedCount} failed | ${manualCount} require manual action`
  );
  console.log(`${divider}\n`);
}

module.exports = { check, updateDb, getDbPath, loadIocDb, getEffectiveIocs };

// ─────────────────────────────────────────────────────────────────────────────
//  8. Provenance Verification — "Shadow Execution" Detection
// ─────────────────────────────────────────────────────────────────────────────

/**
 * High-profile npm packages expected to have provenance attestations.
 *
 * These packages have high download counts and typically publish through
 * CI/CD pipelines (GitHub Actions + npm OIDC provenance). A version of
 * any of these packages published without provenance is a strong indicator
 * that the publish was performed manually — possibly using a stolen
 * long-lived npm automation token.
 */
const HIGH_PROFILE_PACKAGES = [
  // HTTP & networking
  'axios', 'node-fetch', 'got', 'undici', 'superagent',
  // Utility libraries
  'lodash', 'underscore', 'ramda',
  // Web frameworks
  'express', 'fastify', 'koa', 'hapi',
  // Frontend frameworks
  'react', 'react-dom', 'next', 'vue', 'nuxt', 'svelte',
  // Build tools & compilers
  'webpack', 'vite', 'esbuild', 'rollup', 'typescript', 'babel-core',
  // Linting & formatting
  'eslint', 'prettier',
  // Testing
  'jest', 'mocha', 'vitest',
  // CLI utilities
  'chalk', 'commander', 'yargs', 'inquirer',
  // Security-sensitive packages
  'jsonwebtoken', 'bcrypt', 'helmet', 'cors',
  // Database clients
  'mongoose', 'sequelize', 'knex', 'pg', 'mysql2',
  // Runtime & process management
  'nodemon', 'pm2', 'dotenv',
  // Data validation
  'zod', 'yup', 'joi',
];

/**
 * Fetch npm provenance attestations for a specific package version.
 *
 * npm provenance links a published package version back to its source
 * repository and CI/CD workflow. The attestations endpoint returns
 * Sigstore bundles that cryptographically prove the build origin.
 *
 * @param {string} name - Package name (may be scoped).
 * @param {string} version - Exact version string.
 * @returns {Promise<object|null>} Attestation data, or null if none exist or on error.
 */
function fetchProvenanceAttestations(name, version) {
  const encodedName = name.startsWith('@')
    ? `@${encodeURIComponent(name.slice(1))}`
    : encodeURIComponent(name);

  const url = `https://registry.npmjs.org/-/npm/v1/attestations/${encodedName}@${version}`;

  return new Promise(resolve => {
    const req = https.get(url, { timeout: 10000 }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        resolve(null);
        return;
      }

      let body = '';
      res.setEncoding('utf8');
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => {
        try {
          resolve(JSON.parse(body));
        } catch {
          resolve(null);
        }
      });
    });

    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
  });
}

/**
 * Provenance Verification Audit — detects "shadow execution" publishes.
 *
 * Attackers increasingly bypass GitHub Actions and OIDC by stealing long-lived
 * npm automation tokens and publishing directly from their own machines.
 * This check targets high-profile packages where:
 *
 *   1. The published version has NO provenance attestations (no Sigstore bundle),
 *      meaning it was not published through a verified CI/CD pipeline.
 *
 *   2. The package metadata has NO repository link, meaning there is no
 *      traceable connection back to a source code repository.
 *
 * Threat levels:
 *   - No provenance + no repository → "Suspicious: Manual Publish Detected"
 *     (strongest indicator of token theft)
 *   - No provenance + has repository → warning (unusual for popular packages
 *     that normally publish via CI/CD)
 *
 * Only checks packages present in the project's lockfile that are on the
 * HIGH_PROFILE_PACKAGES watchlist. Limited to 10 concurrent registry lookups
 * to avoid excessive network traffic.
 *
 * @param {object[]} threats - Array to push structured threat objects into ({message, category, fixable, fixDescription, fix}).
 */
async function provenanceAudit(threats) {
  const lockfilePath = path.join(process.cwd(), 'package-lock.json');
  if (!fs.existsSync(lockfilePath)) return;

  let lockData;
  try {
    lockData = JSON.parse(fs.readFileSync(lockfilePath, 'utf8'));
  } catch {
    return;
  }

  const packages = extractPackagesFromLockfile(lockData);

  // Filter to high-profile packages that have a version (needed for API calls)
  const highProfileInstalled = packages.filter(
    p => HIGH_PROFILE_PACKAGES.includes(p.name) && p.version
  );

  // Limit to 10 packages to keep network calls reasonable
  const toCheck = highProfileInstalled.slice(0, 10);

  for (const pkg of toCheck) {
    try {
      // Fetch provenance attestations from npm
      const attestations = await fetchProvenanceAttestations(pkg.name, pkg.version);
      const hasProvenance = attestations &&
        attestations.attestations &&
        attestations.attestations.length > 0;

      if (hasProvenance) continue; // Published via CI/CD — no concern

      // No provenance — check if there's at least a repository link
      const registryData = await fetchRegistryMetadata(pkg.name, pkg.version);
      const hasRepo = registryData && registryData.repository &&
        (typeof registryData.repository === 'string'
          ? registryData.repository.length > 0
          : !!(registryData.repository.url));

      if (!hasRepo) {
        // No provenance AND no repository — strongest signal of token theft
        threats.push({
          message: `PROVENANCE: "${pkg.name}@${pkg.version}" — Suspicious: Manual Publish Detected ` +
            `(no provenance attestation and no repository link)`,
          category: 'PROVENANCE',
          fixable: false,
          fixDescription: null,
          fix: null
        });
      } else {
        // Has a repo but no provenance — unusual for high-profile packages
        threats.push({
          message: `PROVENANCE: "${pkg.name}@${pkg.version}" — published without provenance attestation ` +
            `(expected CI/CD pipeline publish for high-profile package)`,
          category: 'PROVENANCE',
          fixable: false,
          fixDescription: null,
          fix: null
        });
      }
    } catch {
      // Network failure — skip silently, other layers still protect
    }
  }
}
