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
 * Ed25519 public key for verifying IOC database signatures.
 *
 * The IOC database is signed by the package maintainer using the corresponding
 * private key (stored offline, never committed). This prevents a compromised
 * GitHub account from pushing a malicious ioc-db.json that whitelists attacker
 * domains — the signature check will fail without the private key.
 *
 * Signature file convention: <ioc-url>.sig (e.g., ioc-db.json.sig)
 * Format: raw Ed25519 signature, base64-encoded, single line.
 *
 * Users who set a custom SEC_CHECK_IOC_URL can bypass signature verification
 * by also setting SEC_CHECK_IOC_SKIP_VERIFY=1 (they trust their own source).
 */
const IOC_SIGNING_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAsnjcIEFf47loa7NYKRNlN221rtV2CZm9cOpoHmwqtKQ=
-----END PUBLIC KEY-----`;

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
 *   - Ed25519 signature verification (fetches <url>.sig and verifies against
 *     the hardcoded public key). Skipped when using a custom URL with
 *     SEC_CHECK_IOC_SKIP_VERIFY=1.
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

  // Determine whether signature verification should be performed.
  // Custom URLs can opt out by setting SEC_CHECK_IOC_SKIP_VERIFY=1.
  const isDefaultUrl = (iocUrl === DEFAULT_IOC_URL);
  const skipVerify = !isDefaultUrl && process.env.SEC_CHECK_IOC_SKIP_VERIFY === '1';

  return new Promise(async resolve => {
    try {
      // 1. Fetch the IOC JSON body
      const body = await fetchHttps(iocUrl, 512 * 1024);

      // 2. Signature verification (unless explicitly skipped for custom URLs)
      if (!skipVerify) {
        const sigUrl = iocUrl + '.sig';
        let sigBody;
        try {
          sigBody = await fetchHttps(sigUrl, 1024);
        } catch (sigErr) {
          resolve({ ok: false, message: `Signature fetch failed (${sigUrl}): ${sigErr.message}` });
          return;
        }

        const sigValid = verifyIocSignature(body, sigBody.trim());
        if (!sigValid) {
          resolve({ ok: false, message: 'Signature verification failed — IOC data may have been tampered with' });
          return;
        }
      }

      // 3. Parse and validate
      const data = JSON.parse(body);
      const validated = validateIocData(data);
      if (!validated.ok) {
        resolve(validated);
        return;
      }

      // 4. Write to disk
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
        message: `IOC database updated (${dbPath})${skipVerify ? ' [signature verification skipped]' : ' [signature verified ✓]'}`,
        added: { domains: newDomains, npm: newNpm, pypi: newPypi }
      });
    } catch (err) {
      resolve({ ok: false, message: err.message || 'Unknown error during IOC update' });
    }
  });
}

/**
 * Fetch a URL over HTTPS and return the response body as a string.
 *
 * @param {string} url - HTTPS URL to fetch.
 * @param {number} maxBytes - Maximum response size in bytes.
 * @returns {Promise<string>} The response body.
 * @throws {Error} On HTTP errors, size limit, timeout, or network failures.
 */
function fetchHttps(url, maxBytes) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { timeout: 15000 }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        reject(new Error(`HTTP ${res.statusCode} from ${url}`));
        return;
      }

      let body = '';
      res.setEncoding('utf8');

      res.on('data', chunk => {
        body += chunk;
        if (body.length > maxBytes) {
          req.destroy();
          reject(new Error(`Response exceeded ${Math.round(maxBytes / 1024)} KB limit`));
        }
      });

      res.on('end', () => resolve(body));
    });

    req.on('error', (err) => reject(new Error(`Network error: ${err.message}`)));
    req.on('timeout', () => { req.destroy(); reject(new Error('Request timed out (15s)')); });
  });
}

/**
 * Verify the Ed25519 signature of IOC data.
 *
 * @param {string} data - The raw IOC JSON string (exactly as fetched).
 * @param {string} signatureBase64 - Base64-encoded Ed25519 signature.
 * @returns {boolean} true if the signature is valid.
 */
function verifyIocSignature(data, signatureBase64) {
  try {
    const publicKey = crypto.createPublicKey(IOC_SIGNING_PUBLIC_KEY);
    const signature = Buffer.from(signatureBase64, 'base64');
    return crypto.verify(null, Buffer.from(data), publicKey, signature);
  } catch {
    return false;
  }
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
 * Prints a Diagnostic Report unless json mode is enabled. The tool is
 * read-only by default — no files or packages are modified unless
 * options.fix is true.
 *
 * @param {object} [options]
 * @param {boolean} [options.fix=false] - When true, attempt auto-remediation of fixable threats after showing the report.
 * @param {boolean} [options.json=false] - When true, suppress human-readable output and return a structured result object.
 * @returns {Promise<boolean|object>} When json=false: true if threats detected, false if clean.
 *   When json=true: { threats, summary, metadata } object for machine consumption.
 */
async function check(options = {}) {
  const fix = options.fix || false;
  const jsonMode = options.json || false;
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

  // 9. Process-level shadow execution detection.
  //    Checks for library preload hijacking (LD_PRELOAD, DYLD_INSERT_LIBRARIES),
  //    NODE_OPTIONS --require injection, and suspicious parent processes (netcat,
  //    mshta, wscript, and other LOLBins). These indicate the Node.js process
  //    was spawned or hijacked by a reverse shell or stager chain.
  checkShadowExecution(sys, threats);

  // 10. Outdated dependency detection (A06 — Vulnerable and Outdated Components).
  //     Runs `npm outdated --json` and flags packages where the installed version
  //     is a major version behind the latest release. Major version drift often
  //     means the package no longer receives security patches.
  checkOutdatedDeps(threats);

  // 11. Registry configuration check (A08 — Software and Data Integrity Failures).
  //     Verifies that the configured npm registry is the official one
  //     (https://registry.npmjs.org). A non-official registry — especially an
  //     attacker-controlled one — enables Dependency Confusion attacks where
  //     an internal package name is claimed on the rogue registry.
  //     Checks project .npmrc, user ~/.npmrc, npm effective config, and
  //     lockfile resolved URLs for non-official registry hosts.
  checkRegistryConfig(threats);

  // 12. Lifecycle script injection detection (A03 — Injection).
  //     Scans the project's own package.json lifecycle hooks (postinstall,
  //     prestart, etc.) for suspicious commands: network piping (curl | sh),
  //     sensitive path access (/etc/hosts, %PROGRAMDATA%), obfuscation
  //     (base64, eval), and remote code execution patterns. Unlike step 5
  //     (dropper detection on dependencies), this targets the project itself.
  //     Recommendation: use `npm install --ignore-scripts` during vetting.
  checkLifecycleScripts(threats);

  // 13. npm doctor — environment health check (A05 — Security Misconfiguration).
  //     Runs `npm doctor` and flags any failing checks (permission issues,
  //     cache corruption, unreachable registry). These misconfigurations can
  //     lead to privilege escalation or cache poisoning.
  checkNpmDoctor(threats);

  // 14. Lockfile enforcement (A05 — Security Misconfiguration).
  //     Alerts if the project has no package-lock.json, yarn.lock, or
  //     pnpm-lock.yaml. Without a lockfile, builds are non-deterministic
  //     and vulnerable to "latest version" poisoning.
  checkLockfilePresence(threats);

  // 15. Secrets detection (A05 — Security Misconfiguration).
  //     Scans for .env files and hardcoded credentials (NPM_TOKEN,
  //     AWS keys, GitHub tokens, PEM private keys, passwords) in
  //     project-root source files that could be accidentally published.
  checkSecretsLeakage(threats);

  // 16. SSRF indicator detection (A10 — Server-Side Request Forgery).
  //     Scans installed packages in node_modules/ for hardcoded URLs and
  //     IP addresses pointing to known C2 / malware infrastructure.
  //     While SSRF is a runtime risk, compromised packages embed callback
  //     URLs directly — this catches them before they can phone home.
  checkSsrfIndicators(threats);

  // 17. Dependency Script Sandboxing (OWASP A03).
  //     Scans lifecycle scripts of ALL dependencies in node_modules/ for
  //     risky patterns (curl, wget, eval, base64, etc.).  Packages on the
  //     project-local approved list (.sec-check-approved.json) are skipped.
  //     Users vet flagged packages and allowlist them via --approve.
  checkDependencyScripts(threats);

  // 18. Lockfile Sentinel — integrity hash verification (OWASP A08).
  //     Compares every package hash in the lockfile against a known-compromised
  //     hash database BEFORE npm install runs. Also flags packages with no
  //     integrity hash (non-deterministic builds vulnerable to MITM).
  lockfileSentinel(threats);

  // ── Diagnostic Report ──────────────────────────────────────────────────
  // Always printed. Shows every threat with its category and fixability.
  if (!jsonMode) {
    printDiagnosticReport(threats, fix);
  }

  // ── Auto-remediation (only when --fix is passed) ───────────────────────
  // The tool is read-only by default. Fixes are opt-in and non-destructive.
  if (fix && threats.some(t => t.fixable)) {
    await runFixes(threats);
  }

  // ── JSON mode: return structured result object ─────────────────────────
  if (jsonMode) {
    const pkg = (() => {
      try {
        return JSON.parse(fs.readFileSync(path.join(process.cwd(), 'package.json'), 'utf8'));
      } catch { return {}; }
    })();
    const fixableCount = threats.filter(t => t.fixable).length;
    return {
      threats: threats.map(t => ({
        message: t.message,
        category: t.category,
        fixable: t.fixable,
        fixDescription: t.fixDescription || null
      })),
      summary: {
        total: threats.length,
        fixable: fixableCount,
        manual: threats.length - fixableCount,
        clean: threats.length === 0
      },
      metadata: {
        tool: '@sathyendra/security-checker',
        version: require('./package.json').version,
        timestamp: new Date().toISOString(),
        project: pkg.name || path.basename(process.cwd()),
        platform: sys,
        node: process.version
      }
    };
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
 *   5. Malicious .pth files in Python site-packages — "importless" execution
 *      backdoors that run at Python startup via the site module
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

  // 5. Scan for malicious .pth files in Python site-packages
  //    TeamPCP used .pth files for "importless" execution — Python's site module
  //    processes .pth files at startup, executing any line starting with `import`.
  //    Only triggered when a Python dependency file exists (cross-ecosystem project).
  const hasPythonDeps = ['requirements.txt', 'requirements-dev.txt', 'requirements_dev.txt',
    'Pipfile', 'Pipfile.lock', 'pyproject.toml', 'setup.py', 'setup.cfg']
    .some(f => fs.existsSync(path.join(cwd, f)));
  if (hasPythonDeps) {
    scanMaliciousPthFiles(threats);
  }
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
 * Malicious .pth file patterns — used for "importless" execution.
 *
 * Python's `site` module processes `.pth` files in `site-packages` at startup.
 * Any line beginning with `import ` is executed as Python code. TeamPCP abused
 * this to achieve persistent code execution without importing a module directly.
 *
 * This array contains regex patterns that detect:
 *   - base64 decoding (obfuscated payload injection)
 *   - subprocess/os.system calls (command execution)
 *   - socket/urllib/requests usage (C2 communication)
 *   - exec/eval (dynamic code execution)
 *   - compile() with encoded strings (obfuscated compilation)
 *   - __import__ (stealth imports to avoid detection)
 *   - codecs.decode (alternative obfuscation)
 */
const PTH_SUSPICIOUS_PATTERNS = [
  /base64\s*\.\s*b64decode/,
  /subprocess\s*\.\s*(Popen|call|run|check_output)/,
  /os\s*\.\s*system\s*\(/,
  /socket\s*\.\s*socket\s*\(/,
  /urllib/,
  /requests\s*\.\s*(get|post)\s*\(/,
  /\bexec\s*\(/,
  /\beval\s*\(/,
  /\bcompile\s*\(/,
  /__import__\s*\(/,
  /codecs\s*\.\s*decode/,
];

/**
 * Scan Python site-packages directories for malicious .pth files.
 *
 * `.pth` files are automatically processed by Python at startup. Legitimate
 * `.pth` files contain simple directory paths (one per line) that get added
 * to `sys.path`. However, any line starting with `import ` in a `.pth` file
 * is executed as Python code — TeamPCP exploited this for "importless"
 * backdoor execution that persists across all Python invocations.
 *
 * Detection strategy:
 *   1. Locate Python site-packages directories using `python -c "import site; ..."`
 *   2. Scan all `.pth` files in each site-packages directory
 *   3. Look for `import` lines that contain suspicious patterns (base64 decode,
 *      subprocess calls, network operations, eval/exec)
 *   4. Flag files with any suspicious executable import line
 *
 * @param {object[]} threats - Array to push structured threat objects into ({message, category, fixable, fixDescription, fix}).
 */
function scanMaliciousPthFiles(threats) {
  // Discover site-packages directories from the Python environment
  const sitePackagesDirs = discoverSitePackages();
  if (sitePackagesDirs.length === 0) return;

  for (const siteDir of sitePackagesDirs) {
    let entries;
    try {
      entries = fs.readdirSync(siteDir, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      if (!entry.isFile() || !entry.name.endsWith('.pth')) continue;

      const pthPath = path.join(siteDir, entry.name);
      let content;
      try {
        content = fs.readFileSync(pthPath, 'utf8');
      } catch {
        continue;
      }

      // .pth files are line-based. Lines starting with "import " are executed
      // as Python code at startup. Normal .pth files only contain directory paths.
      const lines = content.split('\n');
      const suspiciousLines = [];

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;

        // Check lines that contain executable import statements
        // Python executes any line starting with "import " in .pth files
        const isImportLine = /^\s*import\s/.test(trimmed);
        if (!isImportLine) continue;

        // Check if this import line contains suspicious patterns
        const matchedPatterns = PTH_SUSPICIOUS_PATTERNS.filter(p => p.test(trimmed));
        if (matchedPatterns.length > 0) {
          suspiciousLines.push(trimmed);
        }
      }

      if (suspiciousLines.length > 0) {
        threats.push({
          message: `PTH BACKDOOR: malicious .pth file "${entry.name}" in ${siteDir} — ` +
            `contains ${suspiciousLines.length} executable import line(s) with suspicious patterns ` +
            `(base64, subprocess, exec, eval, network calls). This enables "importless" ` +
            `code execution at Python startup.`,
          category: 'TEAMPCP',
          fixable: false,
          fixDescription: null,
          fix: null
        });
      }
    }
  }
}

/**
 * Discover Python site-packages directories.
 *
 * Tries multiple approaches:
 *   1. Run `python3 -c "..."` or `python -c "..."` to get site-packages paths
 *   2. Fall back to common well-known site-packages locations
 *
 * @returns {string[]} Array of existing site-packages directory paths.
 */
function discoverSitePackages() {
  const allDirs = [];
  const pythonCmds = os.platform() === 'win32'
    ? ['python', 'python3', 'py']
    : ['python3', 'python'];

  // Attempt to discover site-packages via Python's site module
  for (const pyCmd of pythonCmds) {
    try {
      const output = execSync(
        `${pyCmd} -c "import site; print('\\n'.join(site.getsitepackages()))"`,
        { encoding: 'utf8', timeout: 10000, stdio: ['ignore', 'pipe', 'ignore'] }
      );
      const dirs = output.trim().split('\n')
        .map(d => d.trim())
        .filter(d => d && fs.existsSync(d));
      if (dirs.length > 0) {
        allDirs.push(...dirs);
        break; // Found system site-packages, stop trying other Python commands
      }
    } catch {
      // Python not available or failed — try next
    }
  }

  // If no system site-packages found, check common well-known paths
  if (allDirs.length === 0) {
    if (os.platform() === 'win32') {
      const localAppData = process.env.LOCALAPPDATA || '';
      if (localAppData) {
        try {
          const pythonDir = path.join(localAppData, 'Programs', 'Python');
          if (fs.existsSync(pythonDir)) {
            const versions = fs.readdirSync(pythonDir).filter(d =>
              d.startsWith('Python')
            );
            for (const ver of versions) {
              const sp = path.join(pythonDir, ver, 'Lib', 'site-packages');
              if (fs.existsSync(sp)) allDirs.push(sp);
            }
          }
        } catch { /* ignore */ }
      }
    } else {
      const homeDir = os.homedir();
      const candidates = [
        '/usr/lib/python3/dist-packages',
        '/usr/local/lib/python3/dist-packages',
        path.join(homeDir, '.local', 'lib'),
      ];
      for (const candidate of candidates) {
        try {
          if (fs.existsSync(candidate)) {
            if (candidate.endsWith('dist-packages') || candidate.endsWith('site-packages')) {
              allDirs.push(candidate);
            } else {
              const subDirs = fs.readdirSync(candidate).filter(d => d.startsWith('python'));
              for (const sub of subDirs) {
                const sp = path.join(candidate, sub, 'site-packages');
                if (fs.existsSync(sp)) allDirs.push(sp);
              }
            }
          }
        } catch { /* ignore */ }
      }
    }
  }

  // ALWAYS check for local venvs in the project directory — these can be
  // compromised independently of the system Python installation
  const cwd = process.cwd();
  const venvDirs = ['.venv', 'venv', 'env', '.env'];
  for (const vd of venvDirs) {
    const venvBase = path.join(cwd, vd);
    if (!fs.existsSync(venvBase)) continue;
    const libDir = os.platform() === 'win32'
      ? path.join(venvBase, 'Lib', 'site-packages')
      : path.join(venvBase, 'lib');
    if (os.platform() === 'win32') {
      if (fs.existsSync(libDir)) allDirs.push(libDir);
    } else {
      try {
        if (fs.existsSync(libDir)) {
          const pyVersionDirs = fs.readdirSync(libDir).filter(d => d.startsWith('python'));
          for (const pv of pyVersionDirs) {
            const sp = path.join(libDir, pv, 'site-packages');
            if (fs.existsSync(sp)) allDirs.push(sp);
          }
        }
      } catch { /* ignore */ }
    }
  }

  // Deduplicate
  return [...new Set(allDirs)];
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
//  9. Process-Level Shadow Execution Detection
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Known suspicious parent process names.
 *
 * Attackers may spawn Node.js from a dropper binary, a reverse shell,
 * or a scripting engine used as a stager. Legitimate parent processes
 * (bash, cmd.exe, node, npm, etc.) are NOT listed here.
 *
 * Each entry is lowercase for case-insensitive comparison.
 */
const SUSPICIOUS_PARENT_NAMES = [
  'nc',             // netcat — classic reverse shell
  'ncat',           // nmap's netcat
  'socat',          // bidirectional relay (reverse shell)
  'mshta',          // Windows LOLBin — runs HTA payloads
  'wscript',        // Windows Script Host — runs VBS/JS stagers
  'cscript',        // Windows Script Host (console)
  'regsvr32',       // Windows LOLBin — can download and exec DLLs
  'rundll32',       // Windows LOLBin — runs DLL exports
  'certutil',       // Windows LOLBin — used for download/decode
  'bitsadmin',      // Windows LOLBin — background transfer
  'msiexec',        // Windows LOLBin — remote MSI execution
];

/**
 * Detect process-level execution hijacking.
 *
 * Two categories of checks:
 *
 *   1. Library preload hijacking (Linux / macOS):
 *      - LD_PRELOAD (Linux): Forces a shared library to be loaded before all others,
 *        allowing function interception (e.g., hooking crypto, network, or file I/O).
 *      - DYLD_INSERT_LIBRARIES (macOS): Same technique for Darwin systems.
 *      - NODE_OPTIONS with --require: Injects a module before the app starts.
 *      These are legitimate for debugging but extremely suspicious in production
 *      or CI/CD pipelines.
 *
 *   2. Suspicious parent process detection:
 *      Node.js being spawned by netcat, mshta, wscript, or other known LOLBins
 *      (Living Off the Land Binaries) indicates a reverse shell or stager chain.
 *      We read /proc/<ppid>/comm on Linux, use `ps` on macOS, and
 *      `wmic process` on Windows.
 *
 * @param {string} sys - The OS platform string from os.platform().
 * @param {object[]} threats - Array to push structured threat objects into.
 */
function checkShadowExecution(sys, threats) {
  // ── 1. Library preload / module injection environment variables ─────────
  const preloadVars = {
    LD_PRELOAD: process.env.LD_PRELOAD,
    DYLD_INSERT_LIBRARIES: process.env.DYLD_INSERT_LIBRARIES,
  };

  for (const [varName, value] of Object.entries(preloadVars)) {
    if (value && value.trim().length > 0) {
      threats.push({
        message: `SHADOW EXEC: ${varName} is set ("${value.length > 80 ? value.slice(0, 80) + '…' : value}") — ` +
          'library preload can intercept crypto, network, or file I/O calls',
        category: 'SHADOW_EXEC',
        fixable: false,
        fixDescription: null,
        fix: null
      });
    }
  }

  // Check NODE_OPTIONS for --require injection (preloads a module before the app)
  const nodeOpts = process.env.NODE_OPTIONS || '';
  if (/--require\s/.test(nodeOpts) || /-r\s/.test(nodeOpts)) {
    threats.push({
      message: `SHADOW EXEC: NODE_OPTIONS contains --require ("${nodeOpts.length > 80 ? nodeOpts.slice(0, 80) + '…' : nodeOpts}") — ` +
        'a module is injected before application startup',
      category: 'SHADOW_EXEC',
      fixable: false,
      fixDescription: null,
      fix: null
    });
  }

  // ── 2. Suspicious parent process detection ─────────────────────────────
  try {
    let parentName = '';
    const ppid = process.ppid;

    if (sys === 'win32') {
      // Use wmic to get parent process name by PID
      const out = execSync(
        `wmic process where ProcessId=${Number(ppid)} get Name /format:list`,
        { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] }
      );
      const match = out.match(/Name=(.+)/i);
      if (match) parentName = match[1].trim().replace(/\.exe$/i, '');
    } else if (sys === 'linux') {
      // /proc/<ppid>/comm contains the short process name (max 15 chars)
      const commPath = `/proc/${ppid}/comm`;
      if (fs.existsSync(commPath)) {
        parentName = fs.readFileSync(commPath, 'utf8').trim();
      }
    } else if (sys === 'darwin') {
      parentName = execSync(
        `ps -p ${Number(ppid)} -o comm=`,
        { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] }
      ).trim();
      // ps on macOS returns the full path — extract just the binary name
      parentName = path.basename(parentName);
    }

    if (parentName) {
      const lower = parentName.toLowerCase();
      if (SUSPICIOUS_PARENT_NAMES.includes(lower)) {
        threats.push({
          message: `SHADOW EXEC: Node.js spawned by suspicious parent process "${parentName}" (PID ${ppid}) — ` +
            'possible reverse shell or LOLBin stager chain',
          category: 'SHADOW_EXEC',
          fixable: false,
          fixDescription: null,
          fix: null
        });
      }
    }
  } catch {
    // Parent process lookup failed — non-fatal, skip silently
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

// ─────────────────────────────────────────────────────────────────────────────
//  10. Outdated Dependency Detection (OWASP A06)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Run `npm outdated --json` and flag packages where the installed version
 * is a major version behind the latest release.
 *
 * A package that is one or more major versions behind is unlikely to receive
 * security patches, violating OWASP A06 (Vulnerable and Outdated Components).
 * Minor/patch drift is ignored to avoid excessive noise.
 *
 * @param {{ message: string, category: string, fixable: boolean, fixDescription: string|null, fix: Function|null }[]} threats
 * @param {object} [_testData] - Optional pre-parsed npm-outdated data (for testing only).
 */
function checkOutdatedDeps(threats, _testData) {
  let data = _testData;

  if (!data) {
    let outdatedJson;
    try {
      outdatedJson = execSync('npm outdated --json', {
        timeout: 30000,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore']
      });
    } catch (err) {
      // npm outdated exits with code 1 when outdated packages exist — this is normal.
      outdatedJson = err.stdout || '';
    }

    if (!outdatedJson.trim()) return;

    try {
      data = JSON.parse(outdatedJson);
    } catch {
      return; // Unparseable — skip silently
    }
  }

  for (const [name, info] of Object.entries(data)) {
    const current = info.current;
    const latest = info.latest;
    if (!current || !latest) continue;

    const currentMajor = parseMajor(current);
    const latestMajor = parseMajor(latest);
    if (currentMajor === null || latestMajor === null) continue;

    if (latestMajor > currentMajor) {
      threats.push({
        message: `OUTDATED: ${name}@${current} is ${latestMajor - currentMajor} major version(s) behind (latest: ${latest})`,
        category: 'OUTDATED',
        fixable: false,
        fixDescription: null,
        fix: null
      });
    }
  }
}

/**
 * Parse the major version number from a semver string.
 * Returns null for unparseable versions.
 *
 * @param {string} version - A semver version string (e.g., "3.2.1").
 * @returns {number|null}
 */
function parseMajor(version) {
  const match = /^(\d+)\./.exec(version);
  return match ? parseInt(match[1], 10) : null;
}

// ─────────────────────────────────────────────────────────────────────────────
//  11. Registry Configuration Check (OWASP A08 — Dependency Confusion)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * The canonical npm registry URL. Any configured registry that differs from
 * this (and is not a well-known SaaS mirror like GitHub Packages, Azure
 * Artifacts, or JFrog Artifactory) is flagged as a Dependency Confusion risk.
 */
const OFFICIAL_NPM_REGISTRY = 'https://registry.npmjs.org/';

/**
 * Check the npm registry configuration for Dependency Confusion risks.
 *
 * Dependency Confusion (OWASP A08) occurs when an internal package name
 * collides with a public npm package, and the developer's registry points
 * to a private feed that an attacker can also publish to — or worse, a
 * completely attacker-controlled registry.
 *
 * Detection layers:
 *   1. Project .npmrc — checks <cwd>/.npmrc for a `registry=` override.
 *   2. User .npmrc — checks ~/.npmrc for a global `registry=` override.
 *   3. npm config — runs `npm config get registry` to capture the effective
 *      registry URL (accounts for env vars, built-in defaults, etc.).
 *   4. Lockfile resolved URLs — scans every `resolved` URL in
 *      package-lock.json for non-official registry hosts.
 *
 * @param {{ message: string, category: string, fixable: boolean, fixDescription: string|null, fix: Function|null }[]} threats
 * @param {object} [_testData] - Optional test injection data to avoid filesystem/exec calls.
 * @param {string|null} [_testData.projectNpmrc] - Contents of project .npmrc (null = not present).
 * @param {string|null} [_testData.userNpmrc] - Contents of user ~/.npmrc (null = not present).
 * @param {string|null} [_testData.npmConfigRegistry] - Simulated `npm config get registry` output.
 * @param {string|null} [_testData.lockfileContent] - Simulated package-lock.json content.
 */
function checkRegistryConfig(threats, _testData) {
  const flagged = new Set();

  // ── Layer 1: Project .npmrc ──────────────────────────────────────────
  const projectNpmrc = _testData
    ? _testData.projectNpmrc
    : readFileSafe(path.join(process.cwd(), '.npmrc'));

  if (projectNpmrc) {
    const reg = extractRegistryFromNpmrc(projectNpmrc);
    if (reg && !isOfficialRegistry(reg)) {
      const key = `project-npmrc:${reg}`;
      if (!flagged.has(key)) {
        flagged.add(key);
        threats.push({
          message: `REGISTRY: Project .npmrc overrides registry to ${reg} — Dependency Confusion risk (OWASP A08)`,
          category: 'REGISTRY',
          fixable: false,
          fixDescription: null,
          fix: null
        });
      }
    }
  }

  // ── Layer 2: User ~/.npmrc ───────────────────────────────────────────
  const userNpmrc = _testData
    ? _testData.userNpmrc
    : readFileSafe(path.join(os.homedir(), '.npmrc'));

  if (userNpmrc) {
    const reg = extractRegistryFromNpmrc(userNpmrc);
    if (reg && !isOfficialRegistry(reg)) {
      const key = `user-npmrc:${reg}`;
      if (!flagged.has(key)) {
        flagged.add(key);
        threats.push({
          message: `REGISTRY: User ~/.npmrc overrides registry to ${reg} — Dependency Confusion risk (OWASP A08)`,
          category: 'REGISTRY',
          fixable: false,
          fixDescription: null,
          fix: null
        });
      }
    }
  }

  // ── Layer 3: Effective npm config ────────────────────────────────────
  let npmConfigReg = _testData ? _testData.npmConfigRegistry : null;
  if (!_testData) {
    try {
      npmConfigReg = execSync('npm config get registry', {
        encoding: 'utf8',
        timeout: 10000,
        stdio: ['ignore', 'pipe', 'ignore']
      }).trim();
    } catch {
      // npm not available or timed out — skip
    }
  }

  if (npmConfigReg && !isOfficialRegistry(npmConfigReg)) {
    const key = `npm-config:${npmConfigReg}`;
    if (!flagged.has(key)) {
      flagged.add(key);
      threats.push({
        message: `REGISTRY: npm effective registry is ${npmConfigReg} — Dependency Confusion risk (OWASP A08)`,
        category: 'REGISTRY',
        fixable: false,
        fixDescription: null,
        fix: null
      });
    }
  }

  // ── Layer 4: Lockfile resolved URLs ──────────────────────────────────
  let lockContent = _testData ? _testData.lockfileContent : null;
  if (!_testData) {
    lockContent = readFileSafe(path.join(process.cwd(), 'package-lock.json'));
  }

  if (lockContent) {
    let lockData;
    try { lockData = JSON.parse(lockContent); } catch { lockData = null; }

    if (lockData) {
      const nonOfficialHosts = new Set();
      collectResolvedUrls(lockData, nonOfficialHosts);

      for (const host of nonOfficialHosts) {
        threats.push({
          message: `REGISTRY: package-lock.json contains resolved URLs from ${host} — verify this is a trusted registry (OWASP A08)`,
          category: 'REGISTRY',
          fixable: false,
          fixDescription: null,
          fix: null
        });
      }
    }
  }
}

/**
 * Read a file and return its contents, or null if it doesn't exist.
 * @param {string} filePath
 * @returns {string|null}
 */
function readFileSafe(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch {
    return null;
  }
}

/**
 * Extract the `registry=<url>` value from an .npmrc file's text.
 * Only matches the base registry setting, not scoped registries like
 * `@myorg:registry=...` (those are legitimate private scope configs).
 *
 * @param {string} content - Contents of an .npmrc file.
 * @returns {string|null} The registry URL, or null if not found.
 */
function extractRegistryFromNpmrc(content) {
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    // Skip comments and scoped registry overrides (@scope:registry=...)
    if (trimmed.startsWith('#') || trimmed.startsWith(';')) continue;
    if (trimmed.startsWith('@')) continue;
    const match = /^registry\s*=\s*(.+)$/i.exec(trimmed);
    if (match) return match[1].trim();
  }
  return null;
}

/**
 * Check if a registry URL is the official npm registry.
 * Normalizes trailing slashes and protocol for comparison.
 *
 * @param {string} url - Registry URL to check.
 * @returns {boolean} true if it matches the official npm registry.
 */
function isOfficialRegistry(url) {
  const normalized = url.replace(/\/+$/, '').toLowerCase();
  return normalized === 'https://registry.npmjs.org';
}

/**
 * Recursively collect non-official registry hostnames from lockfile `resolved` URLs.
 *
 * @param {object} obj - The lockfile data (or a sub-object).
 * @param {Set<string>} hosts - Set to collect non-official hostnames into.
 */
function collectResolvedUrls(obj, hosts) {
  if (!obj || typeof obj !== 'object') return;

  if (typeof obj.resolved === 'string') {
    try {
      const u = new URL(obj.resolved);
      const host = u.hostname.toLowerCase();
      if (host !== 'registry.npmjs.org') {
        hosts.add(host);
      }
    } catch {
      // Malformed URL — skip
    }
  }

  // Recurse into packages (lockfile v2/v3) and dependencies (lockfile v1)
  if (obj.packages && typeof obj.packages === 'object') {
    for (const val of Object.values(obj.packages)) {
      collectResolvedUrls(val, hosts);
    }
  }
  if (obj.dependencies && typeof obj.dependencies === 'object') {
    for (const val of Object.values(obj.dependencies)) {
      collectResolvedUrls(val, hosts);
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  12. Lifecycle Script Injection Detection (OWASP A03)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Lifecycle script hooks that attackers inject malicious commands into.
 * These run automatically during npm install / npm publish / npm start.
 */
const LIFECYCLE_HOOKS = [
  'preinstall', 'install', 'postinstall',
  'preuninstall', 'uninstall', 'postuninstall',
  'prepublish', 'prepublishOnly', 'prepare', 'prepack', 'postpack',
  'prestart', 'start', 'poststart',
  'prestop', 'stop', 'poststop',
  'pretest', 'test', 'posttest'
];

/**
 * Patterns that indicate command/script injection in lifecycle hooks.
 * Reuses the same attack-technique patterns from DROPPER_SCRIPT_PATTERNS
 * but applied to the project's own package.json rather than dependencies.
 */
const LIFECYCLE_INJECTION_PATTERNS = [
  // ── Network fetch + execute ────────────────────────────────────────────
  { pattern: /\bcurl\b.*\|\s*(sh|bash|node)\b/i,  label: 'curl piped to shell' },
  { pattern: /\bwget\b.*\|\s*(sh|bash|node)\b/i,  label: 'wget piped to shell' },
  { pattern: /\bcurl\b.*-[so]\s/i,                label: 'curl silent/output download' },
  { pattern: /\bwget\b.*-[qO]\s/i,                label: 'wget quiet/output download' },
  { pattern: /Invoke-WebRequest\b/i,              label: 'PowerShell Invoke-WebRequest' },

  // ── Sensitive system path access ───────────────────────────────────────
  { pattern: /\/etc\/hosts\b/,                     label: '/etc/hosts access' },
  { pattern: /%PROGRAMDATA%/i,                     label: '%PROGRAMDATA% access' },
  { pattern: /%APPDATA%/i,                         label: '%APPDATA% access' },
  { pattern: /~\/\.ssh\b|\.ssh\/id_rsa/,           label: 'SSH key access' },
  { pattern: /\/etc\/shadow\b/,                    label: '/etc/shadow access' },
  { pattern: /\/etc\/passwd\b/,                    label: '/etc/passwd access' },

  // ── Obfuscation ────────────────────────────────────────────────────────
  { pattern: /\bbase64\b.*\b(decode|--decode|-d)\b/i, label: 'base64 decode' },
  { pattern: /Buffer\.from\(.*,\s*['"]base64['"]\)/,  label: 'Buffer.from base64' },
  { pattern: /\batob\s*\(/,                            label: 'atob() decode' },
  { pattern: /\beval\s*\(/,                            label: 'eval()' },
  { pattern: /\bFunction\s*\(/,                        label: 'Function() constructor' },

  // ── Remote code execution via shell ────────────────────────────────────
  { pattern: /\|\s*(bash|sh|cmd|powershell|pwsh)\b/i,     label: 'pipe to shell' },
  { pattern: /\bnode\s+-e\s/,                              label: 'node -e inline execution' },
  { pattern: /\bpython[23]?\s+-c\s/,                       label: 'python -c inline execution' },
];

/**
 * Scan the project's own package.json for lifecycle script injection (OWASP A03).
 *
 * Unlike the dropper detection (step 5) which scans dependency packages inside
 * node_modules, this check targets the **project itself**. An attacker who gains
 * commit access or submits a PR can inject malicious commands into lifecycle
 * hooks (postinstall, prestart, etc.) that run automatically.
 *
 * For each lifecycle hook, the script content (and any referenced script files)
 * is matched against LIFECYCLE_INJECTION_PATTERNS. Matches are reported with
 * the specific hook name and pattern label.
 *
 * The recommendation is to use `npm install --ignore-scripts` during the
 * vetting process to prevent automatic execution of lifecycle hooks.
 *
 * @param {{ message: string, category: string, fixable: boolean, fixDescription: string|null, fix: Function|null }[]} threats
 * @param {object} [_testData] - Optional pre-parsed package.json scripts (for testing only).
 * @param {string} [_testData.projectDir] - Project directory path (defaults to cwd).
 * @param {object} [_testData.scripts] - The scripts object from package.json.
 */
function checkLifecycleScripts(threats, _testData) {
  let scripts = _testData ? _testData.scripts : null;
  const projectDir = (_testData && _testData.projectDir) ? _testData.projectDir : process.cwd();

  if (!scripts) {
    try {
      const pkgJson = JSON.parse(fs.readFileSync(path.join(projectDir, 'package.json'), 'utf8'));
      scripts = pkgJson.scripts;
    } catch {
      return; // No package.json or unreadable — skip
    }
  }

  if (!scripts || typeof scripts !== 'object') return;

  for (const hook of LIFECYCLE_HOOKS) {
    const cmd = scripts[hook];
    if (!cmd || typeof cmd !== 'string') continue;

    // Collect all script content: the raw command + any referenced file
    let content = cmd;
    const fileRef = cmd.match(/\b(?:node|sh|bash)\s+([^\s;&|]+)/);
    if (fileRef && fileRef[1]) {
      const refPath = path.join(projectDir, fileRef[1]);
      try {
        if (fs.existsSync(refPath)) {
          content += '\n' + fs.readFileSync(refPath, 'utf8');
        }
      } catch {
        // File unreadable — skip
      }
    }

    // Match against injection patterns
    const matched = [];
    for (const { pattern, label } of LIFECYCLE_INJECTION_PATTERNS) {
      if (pattern.test(content)) {
        matched.push(label);
      }
    }

    if (matched.length > 0) {
      threats.push({
        message: `LIFECYCLE_SCRIPT: "${hook}" script contains suspicious pattern(s): ${matched.join(', ')} — use \`npm install --ignore-scripts\` during vetting (OWASP A03)`,
        category: 'LIFECYCLE_SCRIPT',
        fixable: false,
        fixDescription: null,
        fix: null
      });
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  13. npm doctor — Environment Health Check (OWASP A05)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Run `npm doctor` and flag any failing checks.
 *
 * npm doctor verifies:
 *   - npm is able to find the node binary
 *   - node_modules is not writable by non-owners
 *   - npm cache exists and is correctly structured
 *   - npm registry is reachable
 *   - git is available
 *
 * Any line in npm doctor output that contains "not ok" indicates a
 * misconfiguration that could lead to permission escalation, cache
 * poisoning, or install failures.
 *
 * @param {{ message: string, category: string, fixable: boolean, fixDescription: string|null, fix: Function|null }[]} threats
 * @param {object} [_testData] - Optional test injection.
 * @param {string|null} [_testData.doctorOutput] - Simulated npm doctor output text.
 * @param {boolean} [_testData.doctorFailed] - Whether npm doctor exited with error.
 */
function checkNpmDoctor(threats, _testData) {
  let output = '';
  let failed = false;

  if (_testData) {
    output = _testData.doctorOutput || '';
    failed = !!_testData.doctorFailed;
  } else {
    // Only run npm doctor in a real project context (has package.json and node_modules)
    if (!fs.existsSync(path.join(process.cwd(), 'package.json'))) return;
    if (!fs.existsSync(path.join(process.cwd(), 'node_modules'))) return;

    try {
      output = execSync('npm doctor', {
        encoding: 'utf8',
        timeout: 30000,
        stdio: ['ignore', 'pipe', 'pipe']
      });
    } catch (err) {
      // npm doctor exits non-zero when checks fail
      output = (err.stdout || '') + (err.stderr || '');
      failed = true;
    }
  }

  if (!output.trim()) return;

  // Parse npm doctor output format:
  //   Checking <description>
  //   Not ok
  //   <recommendation>
  //
  // We track the current check name and capture "Not ok" with its context.
  const lines = output.split('\n');
  const issues = [];
  let currentCheck = '';
  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    const checkMatch = /^Checking\s+(.+)/i.exec(trimmed);
    if (checkMatch) {
      currentCheck = checkMatch[1];
      continue;
    }
    if (/^not ok$/i.test(trimmed)) {
      // Next line may contain the recommendation
      const recommendation = (i + 1 < lines.length) ? lines[i + 1].trim() : '';
      const desc = currentCheck
        ? `${currentCheck}${recommendation ? ' — ' + recommendation : ''}`
        : recommendation || 'unknown check';
      issues.push(desc);
    }
  }

  if (issues.length > 0) {
    threats.push({
      message: `NPM_DOCTOR: ${issues.length} npm doctor check(s) failed: ${issues.map(i => i.replace(/^not ok\s*/i, '').trim()).join('; ')} — run \`npm doctor\` for details (OWASP A05)`,
      category: 'NPM_DOCTOR',
      fixable: false,
      fixDescription: null,
      fix: null
    });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  14. Lockfile Enforcement (OWASP A05)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Alert if the project is missing a lockfile (package-lock.json or yarn.lock).
 *
 * Without a lockfile, `npm install` resolves the latest matching version for
 * every dependency at install time. This makes builds non-deterministic and
 * opens the door to "latest version" poisoning: an attacker publishes a
 * malicious patch release that matches a semver range, and every new install
 * picks it up automatically.
 *
 * A committed lockfile pins exact versions and integrity hashes, ensuring
 * reproducible builds.
 *
 * @param {{ message: string, category: string, fixable: boolean, fixDescription: string|null, fix: Function|null }[]} threats
 * @param {object} [_testData] - Optional test injection.
 * @param {string} [_testData.projectDir] - Project directory (defaults to cwd).
 */
function checkLockfilePresence(threats, _testData) {
  const projectDir = (_testData && _testData.projectDir) ? _testData.projectDir : process.cwd();

  // Only relevant for actual projects (must have package.json)
  if (!fs.existsSync(path.join(projectDir, 'package.json'))) return;
  // In integration mode (no _testData), also require node_modules to avoid
  // false positives in scratch directories that happen to have a package.json.
  if (!_testData && !fs.existsSync(path.join(projectDir, 'node_modules'))) return;

  const hasNpmLock = fs.existsSync(path.join(projectDir, 'package-lock.json'));
  const hasYarnLock = fs.existsSync(path.join(projectDir, 'yarn.lock'));
  const hasPnpmLock = fs.existsSync(path.join(projectDir, 'pnpm-lock.yaml'));

  if (!hasNpmLock && !hasYarnLock && !hasPnpmLock) {
    threats.push({
      message: 'NO_LOCKFILE: No package-lock.json, yarn.lock, or pnpm-lock.yaml found — builds are non-deterministic and vulnerable to latest-version poisoning (OWASP A05)',
      category: 'NO_LOCKFILE',
      fixable: true,
      fixDescription: 'npm install --package-lock-only (generates lockfile without modifying node_modules)',
      fix: () => execSync('npm install --package-lock-only', { stdio: 'ignore', timeout: 60000 })
    });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  15. Secrets Detection (OWASP A05)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * File patterns that commonly contain secrets. We scan for these at the
 * project root level (not recursively into node_modules).
 */
const SECRET_FILE_PATTERNS = [
  '.env',
  '.env.local',
  '.env.production',
  '.env.development',
  '.env.staging',
  '.env.test',
  '.npmrc'
];

/**
 * Regex patterns for hardcoded credentials/tokens in source files.
 * Each entry has a pattern and a human-readable label.
 */
const SECRET_VALUE_PATTERNS = [
  { pattern: /NPM_TOKEN\s*=\s*\S+/i,                                 label: 'NPM_TOKEN' },
  { pattern: /npm_[0-9a-zA-Z]{36}/,                                   label: 'npm automation token' },
  { pattern: /\bAWS_SECRET_ACCESS_KEY\s*=\s*\S+/i,                    label: 'AWS_SECRET_ACCESS_KEY' },
  { pattern: /\bAWS_ACCESS_KEY_ID\s*=\s*\S+/i,                        label: 'AWS_ACCESS_KEY_ID' },
  { pattern: /\bGITHUB_TOKEN\s*=\s*\S+/i,                             label: 'GITHUB_TOKEN' },
  { pattern: /\bghp_[0-9a-zA-Z]{36,}/,                                label: 'GitHub personal access token' },
  { pattern: /\bgho_[0-9a-zA-Z]{36,}/,                                label: 'GitHub OAuth token' },
  { pattern: /\bghs_[0-9a-zA-Z]{36,}/,                                label: 'GitHub server-to-server token' },
  { pattern: /\bghr_[0-9a-zA-Z]{36,}/,                                label: 'GitHub refresh token' },
  { pattern: /\bSECRET_KEY\s*=\s*['"][^'"]{8,}['"]/i,                 label: 'SECRET_KEY' },
  { pattern: /\bPRIVATE_KEY\s*=\s*\S+/i,                              label: 'PRIVATE_KEY' },
  { pattern: /\bDATABASE_URL\s*=\s*\S+/i,                             label: 'DATABASE_URL' },
  { pattern: /\bAPI_KEY\s*=\s*['"][^'"]{8,}['"]/i,                     label: 'API_KEY' },
  { pattern: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/,               label: 'PEM private key' },
  { pattern: /\b(password|passwd|pwd)\s*[:=]\s*['"][^'"]{4,}['"]/i,    label: 'hardcoded password' },
];

/**
 * Source file extensions to scan for hardcoded credentials.
 * Covers JavaScript, TypeScript, JSON config, YAML config, and shell scripts.
 */
const SCANNABLE_EXTENSIONS = new Set([
  '.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx',
  '.json', '.yaml', '.yml', '.toml',
  '.sh', '.bash', '.cmd', '.bat', '.ps1'
]);

/**
 * Scan the project for leaked secrets (OWASP A05 — Security Misconfiguration).
 *
 * Two-layer detection:
 *   1. Dot-env files: Checks for the existence of .env, .env.local, .env.production,
 *      etc. at the project root. If a .npmignore or "files" whitelist does NOT
 *      exclude them, they could be published to npm and expose credentials.
 *   2. Hardcoded credentials: Scans project-root source files for patterns like
 *      NPM_TOKEN=..., AWS_SECRET_ACCESS_KEY=..., PEM private keys, GitHub tokens,
 *      and hardcoded passwords.
 *
 * @param {{ message: string, category: string, fixable: boolean, fixDescription: string|null, fix: Function|null }[]} threats
 * @param {object} [_testData] - Optional test injection.
 * @param {string} [_testData.projectDir] - Project directory (defaults to cwd).
 * @param {string[]} [_testData.existingFiles] - List of filenames present (overrides fs check).
 * @param {object} [_testData.fileContents] - Map of filename → file contents (overrides fs read).
 */
function checkSecretsLeakage(threats, _testData) {
  const projectDir = (_testData && _testData.projectDir) ? _testData.projectDir : process.cwd();

  // Determine which files are excluded from npm publish via "files" whitelist or .npmignore
  let publishExcludes = null; // null means no whitelist — everything is included
  try {
    const pkgJson = JSON.parse(fs.readFileSync(path.join(projectDir, 'package.json'), 'utf8'));
    if (Array.isArray(pkgJson.files)) {
      publishExcludes = new Set(pkgJson.files.map(f => f.toLowerCase()));
    }
  } catch {
    // No package.json — skip publish exclusion check
  }

  // ── Layer 1: .env file detection ───────────────────────────────────────
  for (const envFile of SECRET_FILE_PATTERNS) {
    const exists = _testData && _testData.existingFiles
      ? _testData.existingFiles.includes(envFile)
      : fs.existsSync(path.join(projectDir, envFile));

    if (exists) {
      // Check if the file would be published
      const wouldPublish = publishExcludes === null || publishExcludes.has(envFile.toLowerCase());
      const riskLevel = wouldPublish ? 'may be published to npm' : 'exists in project root';

      threats.push({
        message: `SECRETS: ${envFile} found — ${riskLevel}. Add to .npmignore or .gitignore to prevent credential leakage (OWASP A05)`,
        category: 'SECRETS',
        fixable: false,
        fixDescription: null,
        fix: null
      });
    }
  }

  // ── Layer 2: Hardcoded credential patterns in source files ─────────────
  let filesToScan = [];

  if (_testData && _testData.fileContents) {
    filesToScan = Object.keys(_testData.fileContents);
  } else {
    try {
      const entries = fs.readdirSync(projectDir, { withFileTypes: true });
      for (const entry of entries) {
        if (!entry.isFile()) continue;
        if (entry.name === 'node_modules') continue;
        const ext = path.extname(entry.name).toLowerCase();
        if (SCANNABLE_EXTENSIONS.has(ext) || entry.name === '.npmrc') {
          filesToScan.push(entry.name);
        }
      }
    } catch {
      return;
    }
  }

  for (const fileName of filesToScan) {
    let content;
    if (_testData && _testData.fileContents && _testData.fileContents[fileName]) {
      content = _testData.fileContents[fileName];
    } else {
      try {
        content = fs.readFileSync(path.join(projectDir, fileName), 'utf8');
      } catch {
        continue;
      }
    }

    // Limit scan to first 100KB per file to avoid performance issues on large bundles
    const scanContent = content.length > 102400 ? content.substring(0, 102400) : content;

    const foundSecrets = [];
    for (const { pattern, label } of SECRET_VALUE_PATTERNS) {
      if (pattern.test(scanContent)) {
        foundSecrets.push(label);
      }
    }

    if (foundSecrets.length > 0) {
      threats.push({
        message: `SECRETS: ${fileName} contains hardcoded credential(s): ${foundSecrets.join(', ')} — use environment variables instead (OWASP A05)`,
        category: 'SECRETS',
        fixable: false,
        fixDescription: null,
        fix: null
      });
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  16. C2 Domain Blocklist Scan — SSRF Indicator Detection (OWASP A10)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Scan installed packages in node_modules/ for hardcoded URLs or IP addresses
 * that resolve to known command-and-control (C2) domains.
 *
 * While SSRF is typically a runtime vulnerability, in a supply-chain context
 * the risk manifests when a dependency contains hardcoded network calls to
 * known malware infrastructure. The TeamPCP campaign, for example, embedded
 * C2 callback URLs directly in compromised packages.
 *
 * Strategy:
 *   1. Walk top-level directories under node_modules/ (and scoped @org/ dirs).
 *   2. For each package, scan .js / .mjs / .cjs / .json files (first 100KB).
 *   3. Extract all URL-like strings and raw IP addresses.
 *   4. Compare extracted hostnames/IPs against the C2 blocklist from
 *      getEffectiveIocs().c2Domains, plus a hardcoded suspicious-IP list.
 *   5. Flag matches as SSRF category threats.
 *
 * @param {{ message: string, category: string, fixable: boolean, fixDescription: string|null, fix: Function|null }[]} threats
 * @param {object} [_testData] - Optional test injection.
 * @param {string} [_testData.nodeModulesDir] - Path to node_modules (defaults to cwd/node_modules).
 * @param {Object<string, string>} [_testData.packageFiles] - Map of "pkgName/file" → content.
 */

/** File extensions to scan inside packages for network indicators. */
const SSRF_SCANNABLE_EXTENSIONS = ['.js', '.mjs', '.cjs', '.json'];

/** Maximum file size (bytes) to scan per file. */
const SSRF_MAX_FILE_SIZE = 102400;

/**
 * Known suspicious IP addresses associated with malware campaigns.
 * These are non-RFC1918, non-loopback addresses seen in TeamPCP and similar
 * campaigns as fallback C2 beacons.
 */
const SUSPICIOUS_IPS = [
  '45.61.136.85',        // TeamPCP staging server
  '45.61.137.171',       // TeamPCP variant
  '185.62.56.25',        // WAVESHAPER beacon
  '193.233.20.2',        // Credential exfil relay
  '194.26.135.89',       // PyPI dropper callback
];

/**
 * Regex to extract URLs from source code. Matches http(s) and ws(s) schemes.
 * Captures the full URL including path.
 */
const URL_EXTRACTION_REGEX = /(?:https?|wss?):\/\/([a-zA-Z0-9._-]+(?:\.[a-zA-Z]{2,}))(\/[^\s'"`,;)\]}>]*)?/g;

/**
 * Regex to extract raw IPv4 addresses from source code.
 * Excludes common false positives like version strings (e.g., "1.2.3").
 */
const IPV4_EXTRACTION_REGEX = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;

function checkSsrfIndicators(threats, _testData) {
  const cwd = process.cwd();
  const nodeModulesDir = (_testData && _testData.nodeModulesDir)
    ? _testData.nodeModulesDir
    : path.join(cwd, 'node_modules');

  // Only scan when node_modules exists (unless test data provides packageFiles)
  if (!_testData || !_testData.packageFiles) {
    if (!fs.existsSync(nodeModulesDir)) return;
  }

  const blockedDomains = new Set(getEffectiveIocs().c2Domains.map(d => d.toLowerCase()));
  const blockedIPs = new Set(SUSPICIOUS_IPS);

  // ── Test-data path: scan synthetic file contents ───────────────────────
  if (_testData && _testData.packageFiles) {
    for (const [filePath, content] of Object.entries(_testData.packageFiles)) {
      const pkgName = filePath.split('/')[0];
      const scanContent = content.length > SSRF_MAX_FILE_SIZE
        ? content.substring(0, SSRF_MAX_FILE_SIZE) : content;
      scanContentForSsrf(scanContent, pkgName, filePath, blockedDomains, blockedIPs, threats);
    }
    return;
  }

  // ── Real path: walk node_modules ───────────────────────────────────────
  let topLevelEntries;
  try {
    topLevelEntries = fs.readdirSync(nodeModulesDir, { withFileTypes: true });
  } catch { return; }

  const packageDirs = [];
  for (const entry of topLevelEntries) {
    if (!entry.isDirectory()) continue;
    if (entry.name === '.package-lock.json' || entry.name === '.cache') continue;

    if (entry.name.startsWith('@')) {
      // Scoped packages: @org/pkg
      try {
        const scopedEntries = fs.readdirSync(path.join(nodeModulesDir, entry.name), { withFileTypes: true });
        for (const scoped of scopedEntries) {
          if (scoped.isDirectory()) {
            packageDirs.push({ name: `${entry.name}/${scoped.name}`, dir: path.join(nodeModulesDir, entry.name, scoped.name) });
          }
        }
      } catch { /* unreadable scope dir */ }
    } else {
      packageDirs.push({ name: entry.name, dir: path.join(nodeModulesDir, entry.name) });
    }
  }

  for (const pkg of packageDirs) {
    scanPackageDir(pkg.dir, pkg.name, blockedDomains, blockedIPs, threats);
  }
}

/**
 * Recursively scan a package directory for files with matching extensions,
 * up to one level of nesting (to avoid scanning nested node_modules).
 */
function scanPackageDir(dir, pkgName, blockedDomains, blockedIPs, threats) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }

  for (const entry of entries) {
    if (entry.name === 'node_modules') continue;

    const fullPath = path.join(dir, entry.name);
    if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      if (!SSRF_SCANNABLE_EXTENSIONS.includes(ext)) continue;

      try {
        const stat = fs.statSync(fullPath);
        if (stat.size > SSRF_MAX_FILE_SIZE) continue;
        const content = fs.readFileSync(fullPath, 'utf8');
        scanContentForSsrf(content, pkgName, `${pkgName}/${entry.name}`, blockedDomains, blockedIPs, threats);
      } catch { /* unreadable file */ }
    } else if (entry.isDirectory()) {
      // One level deeper (e.g., lib/, dist/, src/)
      scanPackageSubdir(fullPath, pkgName, blockedDomains, blockedIPs, threats);
    }
  }
}

/**
 * Scan a single subdirectory within a package (one level only).
 */
function scanPackageSubdir(dir, pkgName, blockedDomains, blockedIPs, threats) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }

  for (const entry of entries) {
    if (!entry.isFile()) continue;
    const ext = path.extname(entry.name).toLowerCase();
    if (!SSRF_SCANNABLE_EXTENSIONS.includes(ext)) continue;

    const fullPath = path.join(dir, entry.name);
    try {
      const stat = fs.statSync(fullPath);
      if (stat.size > SSRF_MAX_FILE_SIZE) continue;
      const content = fs.readFileSync(fullPath, 'utf8');
      const relativePath = `${pkgName}/${path.basename(dir)}/${entry.name}`;
      scanContentForSsrf(content, pkgName, relativePath, blockedDomains, blockedIPs, threats);
    } catch { /* unreadable file */ }
  }
}

/**
 * Scan a string of source code for URLs / IPs matching blocklists.
 * Deduplicates findings per package to avoid flooding the threat list.
 */
function scanContentForSsrf(content, pkgName, filePath, blockedDomains, blockedIPs, threats) {
  const findings = [];

  // ── URL extraction ────────────────────────────────────────────────────
  let match;
  URL_EXTRACTION_REGEX.lastIndex = 0;
  while ((match = URL_EXTRACTION_REGEX.exec(content)) !== null) {
    const hostname = match[1].toLowerCase();
    if (blockedDomains.has(hostname)) {
      findings.push(`C2 domain "${hostname}" in URL`);
    }
  }

  // ── Raw IP extraction ─────────────────────────────────────────────────
  IPV4_EXTRACTION_REGEX.lastIndex = 0;
  while ((match = IPV4_EXTRACTION_REGEX.exec(content)) !== null) {
    const ip = match[1];
    // Skip version-like octets (0.x.x, x.0.0) and loopback / private ranges
    if (/^0\./.test(ip) || ip === '127.0.0.1' || ip === '0.0.0.0') continue;
    if (/^10\./.test(ip) || /^172\.(1[6-9]|2\d|3[01])\./.test(ip) || /^192\.168\./.test(ip)) continue;
    if (blockedIPs.has(ip)) {
      findings.push(`suspicious IP ${ip}`);
    }
  }

  if (findings.length > 0) {
    const deduped = [...new Set(findings)];
    threats.push({
      message: `SSRF: ${pkgName} contains ${deduped.length} network indicator(s) pointing to known malware infrastructure: ${deduped.join('; ')} — found in ${filePath} (OWASP A10)`,
      category: 'SSRF',
      fixable: true,
      fixDescription: `npm uninstall ${pkgName} (remove the compromised package)`,
      fix: () => execSync(`npm uninstall ${pkgName}`, { stdio: 'ignore', timeout: 30000 })
    });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  17. Dependency Script Sandboxing — Risk Report (OWASP A03)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Default path for the project-local allowlist file.
 * Stored in the project root so it can be committed to version control,
 * giving the team a shared record of vetted packages.
 */
const APPROVED_FILE = '.sec-check-approved.json';

/**
 * Load the list of approved (allowlisted) packages from the project root.
 *
 * File format: { "approved": ["pkg-a", "@scope/pkg-b"], "approvedAt": { "pkg-a": "2025-01-01T00:00:00.000Z" } }
 *
 * @param {string} projectDir - Absolute path to the project root.
 * @returns {Set<string>} Set of approved package names (lowercase).
 */
function loadApprovedPackages(projectDir) {
  const filePath = path.join(projectDir, APPROVED_FILE);
  try {
    if (!fs.existsSync(filePath)) return new Set();
    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    if (Array.isArray(data.approved)) {
      return new Set(data.approved.map(n => n.toLowerCase()));
    }
  } catch {
    // Corrupted or unreadable — treat as empty
  }
  return new Set();
}

/**
 * Add a package to the project-local approved list.
 *
 * Creates `.sec-check-approved.json` if it doesn't exist, or merges into
 * the existing file.  Records a timestamp for each approval.
 *
 * @param {string} pkgName - Package name to approve (e.g. "husky").
 * @param {object} [_testData] - Optional test injection.
 * @param {string} [_testData.projectDir] - Override project directory.
 * @returns {object} { ok, message, file }
 */
function approvePackage(pkgName, _testData) {
  const projectDir = (_testData && _testData.projectDir) ? _testData.projectDir : process.cwd();
  const filePath = path.join(projectDir, APPROVED_FILE);

  if (!pkgName || typeof pkgName !== 'string' || pkgName.trim().length === 0) {
    return { ok: false, message: 'Package name is required.' };
  }

  const name = pkgName.trim().toLowerCase();

  // Validate package name format
  if (!isSafePackageName(name)) {
    return { ok: false, message: `Invalid package name: "${name}"` };
  }

  // Load or create data
  let data = { approved: [], approvedAt: {} };
  try {
    if (fs.existsSync(filePath)) {
      data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      if (!Array.isArray(data.approved)) data.approved = [];
      if (!data.approvedAt || typeof data.approvedAt !== 'object') data.approvedAt = {};
    }
  } catch {
    data = { approved: [], approvedAt: {} };
  }

  // Check if already approved
  if (data.approved.includes(name)) {
    return { ok: true, message: `"${name}" is already approved.`, file: filePath };
  }

  // Add and write
  data.approved.push(name);
  data.approvedAt[name] = new Date().toISOString();

  try {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + '\n', 'utf8');
  } catch (err) {
    return { ok: false, message: `Cannot write ${APPROVED_FILE}: ${err.message}` };
  }

  return { ok: true, message: `"${name}" approved and added to ${APPROVED_FILE}`, file: filePath };
}

/**
 * Patterns that flag a dependency's lifecycle script as risky.
 * Broader than the project-level LIFECYCLE_INJECTION_PATTERNS because
 * we want to surface ANY script that does non-trivial work — the user
 * must explicitly approve it with --approve.
 */
const DEP_SCRIPT_RISK_PATTERNS = [
  { pattern: /\bcurl\b/i,                     label: 'curl' },
  { pattern: /\bwget\b/i,                     label: 'wget' },
  { pattern: /\beval\s*\(/,                   label: 'eval()' },
  { pattern: /\bbase64\b/i,                   label: 'base64' },
  { pattern: /\bFunction\s*\(/,               label: 'Function()' },
  { pattern: /Invoke-WebRequest\b/i,          label: 'Invoke-WebRequest' },
  { pattern: /\bexec\s*\(/,                   label: 'exec()' },
  { pattern: /\bchild_process\b/,             label: 'child_process' },
  { pattern: /\bnode\s+-e\s/,                 label: 'node -e' },
  { pattern: /\bpython[23]?\s+-c\s/,          label: 'python -c' },
  { pattern: /\|\s*(sh|bash|cmd|powershell)\b/i, label: 'pipe to shell' },
];

/**
 * Lifecycle hooks that run automatically during install/uninstall.
 * We only flag these — scripts like "test" or "start" are user-triggered.
 */
const DEP_AUTO_HOOKS = [
  'preinstall', 'install', 'postinstall',
  'preuninstall', 'uninstall', 'postuninstall',
  'prepare'
];

/**
 * Scan all dependencies in node_modules for lifecycle scripts containing
 * suspicious patterns.  Packages on the approved list are skipped.
 *
 * This is the "Script Sandboxing" analysis (OWASP A03) — it generates a
 * Risk Report telling the user which dependencies want to run code during
 * install.  The user can vet each package and approve it with
 * `sec-check --approve <pkg>`.
 *
 * @param {object[]} threats - Array to push structured threat objects into.
 * @param {object} [_testData] - Optional test injection.
 * @param {object} [_testData.depScripts] - Map of { pkgName: { hook: cmd } } to simulate.
 * @param {string[]} [_testData.approved] - Simulated approved package list.
 */
function checkDependencyScripts(threats, _testData) {
  const projectDir = process.cwd();
  const nodeModulesDir = path.join(projectDir, 'node_modules');

  // Build approved set
  const approved = _testData && _testData.approved
    ? new Set(_testData.approved.map(n => n.toLowerCase()))
    : loadApprovedPackages(projectDir);

  // Get dependency scripts (real or injected)
  let depMap; // { pkgName: { hook: cmd, ... }, ... }

  if (_testData && _testData.depScripts) {
    depMap = _testData.depScripts;
  } else {
    depMap = {};
    if (!fs.existsSync(nodeModulesDir)) return;

    const pkgNames = listInstalledPackages(nodeModulesDir);
    for (const pkgName of pkgNames) {
      const pkgJsonPath = path.join(nodeModulesDir, pkgName, 'package.json');
      try {
        const pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
        if (pkgJson.scripts && typeof pkgJson.scripts === 'object') {
          const autoScripts = {};
          for (const hook of DEP_AUTO_HOOKS) {
            if (pkgJson.scripts[hook] && typeof pkgJson.scripts[hook] === 'string') {
              autoScripts[hook] = pkgJson.scripts[hook];
            }
          }
          if (Object.keys(autoScripts).length > 0) {
            depMap[pkgName] = autoScripts;
          }
        }
      } catch {
        // Unreadable package.json — skip
      }
    }
  }

  // Scan each dependency's scripts for risk patterns
  for (const [pkgName, hooks] of Object.entries(depMap)) {
    if (approved.has(pkgName.toLowerCase())) continue;

    const riskEntries = [];

    for (const [hook, cmd] of Object.entries(hooks)) {
      if (!DEP_AUTO_HOOKS.includes(hook)) continue;

      const matched = [];
      for (const { pattern, label } of DEP_SCRIPT_RISK_PATTERNS) {
        if (pattern.test(cmd)) {
          matched.push(label);
        }
      }

      if (matched.length > 0) {
        riskEntries.push({ hook, patterns: matched, cmd });
      }
    }

    if (riskEntries.length > 0) {
      const hookSummary = riskEntries
        .map(e => `"${e.hook}" (${e.patterns.join(', ')})`)
        .join('; ');

      threats.push({
        message: `DEP_SCRIPT: "${pkgName}" has risky lifecycle script(s): ${hookSummary} — vet and run \`sec-check --approve ${pkgName}\` to allowlist (OWASP A03)`,
        category: 'DEP_SCRIPT',
        fixable: false,
        fixDescription: `sec-check --approve ${pkgName}`,
        fix: null
      });
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Script Blocker — combined lifecycle + dependency script analysis (A03)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Script Blocker — unified gate for lifecycle script injection (A03).
 *
 * Combines two analyses:
 *   1. Project-level: `checkLifecycleScripts` — scans the project's own
 *      package.json for injection patterns in lifecycle hooks.
 *   2. Dependency-level: `checkDependencyScripts` — scans every dependency
 *      in node_modules for risky auto-hook scripts.
 *
 * Returns a structured result with a blocking verdict.  When used in the
 * shield workflow, any finding blocks the install.
 *
 * @param {object} [_testData] - Test injection data.
 * @param {object} [_testData.scripts] - Override project scripts (for checkLifecycleScripts).
 * @param {string} [_testData.projectDir] - Override project dir.
 * @param {object} [_testData.depScripts] - Override dependency scripts (for checkDependencyScripts).
 * @param {string[]} [_testData.approved] - Override approved packages list.
 * @returns {{ blocked: boolean, threats: object[], summary: { project: number, dependencies: number } }}
 */
function scriptBlocker(_testData) {
  const projectThreats = [];
  const depThreats = [];

  checkLifecycleScripts(projectThreats, _testData);
  checkDependencyScripts(depThreats, _testData);

  const allThreats = [...projectThreats, ...depThreats];

  return {
    blocked: allThreats.length > 0,
    threats: allThreats,
    summary: {
      project: projectThreats.length,
      dependencies: depThreats.length
    }
  };
}

// ─────────────────────────────────────────────────────────────────────────────
//  Registry Guard — reject non-official & unencrypted registries (A05)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Check if a registry URL uses unencrypted HTTP transport.
 *
 * @param {string} url - Registry URL to check.
 * @returns {boolean} true if the URL uses plain HTTP (not HTTPS).
 */
function isHttpRegistry(url) {
  const trimmed = url.trim().toLowerCase();
  return trimmed.startsWith('http://');
}

/**
 * Registry Guard — blocks install when a non-official or unencrypted
 * (HTTP) registry is detected in .npmrc or npm config.
 *
 * Extends the existing `checkRegistryConfig()` with HTTP detection.
 * Returns a structured result with a blocking verdict.
 *
 * @param {object} [_testData] - Same test injection as checkRegistryConfig.
 * @returns {{ blocked: boolean, threats: object[], summary: { nonOfficial: number, httpInsecure: number } }}
 */
function registryGuard(_testData) {
  const threats = [];

  // Run existing registry config check (non-official detection)
  checkRegistryConfig(threats, _testData);

  // Additional HTTP (unencrypted) detection across all layers
  const httpThreats = [];

  // Layer 1: Project .npmrc
  const projectNpmrc = _testData
    ? _testData.projectNpmrc
    : readFileSafe(path.join(process.cwd(), '.npmrc'));

  if (projectNpmrc) {
    const reg = extractRegistryFromNpmrc(projectNpmrc);
    if (reg && isHttpRegistry(reg)) {
      httpThreats.push({
        message: `REGISTRY_HTTP: Project .npmrc uses unencrypted HTTP registry ${reg} — credentials and packages can be intercepted (OWASP A05)`,
        category: 'REGISTRY_HTTP',
        fixable: false,
        fixDescription: null,
        fix: null
      });
    }
  }

  // Layer 2: User ~/.npmrc
  const userNpmrc = _testData
    ? _testData.userNpmrc
    : readFileSafe(path.join(os.homedir(), '.npmrc'));

  if (userNpmrc) {
    const reg = extractRegistryFromNpmrc(userNpmrc);
    if (reg && isHttpRegistry(reg)) {
      httpThreats.push({
        message: `REGISTRY_HTTP: User ~/.npmrc uses unencrypted HTTP registry ${reg} — credentials and packages can be intercepted (OWASP A05)`,
        category: 'REGISTRY_HTTP',
        fixable: false,
        fixDescription: null,
        fix: null
      });
    }
  }

  // Layer 3: Effective npm config
  let npmConfigReg = _testData ? _testData.npmConfigRegistry : null;
  if (!_testData) {
    try {
      npmConfigReg = execSync('npm config get registry', {
        encoding: 'utf8',
        timeout: 10000,
        stdio: ['ignore', 'pipe', 'ignore']
      }).trim();
    } catch {
      // skip
    }
  }

  if (npmConfigReg && isHttpRegistry(npmConfigReg)) {
    httpThreats.push({
      message: `REGISTRY_HTTP: npm effective registry uses unencrypted HTTP ${npmConfigReg} — credentials and packages can be intercepted (OWASP A05)`,
      category: 'REGISTRY_HTTP',
      fixable: false,
      fixDescription: null,
      fix: null
    });
  }

  // Layer 4: Lockfile resolved URLs with HTTP
  let lockContent = _testData ? _testData.lockfileContent : null;
  if (!_testData) {
    lockContent = readFileSafe(path.join(process.cwd(), 'package-lock.json'));
  }

  if (lockContent) {
    let lockData;
    try { lockData = JSON.parse(lockContent); } catch { lockData = null; }

    if (lockData) {
      const httpHosts = new Set();
      collectHttpResolvedUrls(lockData, httpHosts);
      for (const host of httpHosts) {
        httpThreats.push({
          message: `REGISTRY_HTTP: package-lock.json contains HTTP (unencrypted) resolved URLs from ${host} — packages may have been tampered with (OWASP A05)`,
          category: 'REGISTRY_HTTP',
          fixable: false,
          fixDescription: null,
          fix: null
        });
      }
    }
  }

  // Deduplicate HTTP threats (same message shouldn't appear from both
  // the existing checkRegistryConfig and the new HTTP check)
  const existingMessages = new Set(threats.map(t => t.message));
  for (const ht of httpThreats) {
    if (!existingMessages.has(ht.message)) {
      threats.push(ht);
    }
  }

  const nonOfficial = threats.filter(t => t.category === 'REGISTRY').length;
  const httpInsecure = threats.filter(t => t.category === 'REGISTRY_HTTP').length;

  return {
    blocked: threats.length > 0,
    threats,
    summary: { nonOfficial, httpInsecure }
  };
}

/**
 * Recursively collect hostnames from lockfile `resolved` URLs that use HTTP.
 *
 * @param {object} obj - The lockfile data (or sub-object).
 * @param {Set<string>} hosts - Set to collect HTTP hostnames into.
 */
function collectHttpResolvedUrls(obj, hosts) {
  if (!obj || typeof obj !== 'object') return;

  if (typeof obj.resolved === 'string') {
    try {
      const u = new URL(obj.resolved);
      if (u.protocol === 'http:') {
        hosts.add(u.hostname.toLowerCase());
      }
    } catch {
      // Malformed URL
    }
  }

  if (obj.packages && typeof obj.packages === 'object') {
    for (const val of Object.values(obj.packages)) {
      collectHttpResolvedUrls(val, hosts);
    }
  }
  if (obj.dependencies && typeof obj.dependencies === 'object') {
    for (const val of Object.values(obj.dependencies)) {
      collectHttpResolvedUrls(val, hosts);
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Lockfile Sentinel — integrity hash verification against clean DB (A08)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Known-compromised integrity hashes.
 *
 * These are SHA-512 integrity strings extracted from confirmed malicious
 * package versions. When a lockfile contains one of these hashes, we know
 * the dependency is a known-compromised version — even before npm install.
 *
 * The list is extensible via the IOC database (--update-db). Remote IOC
 * entries are merged with the hardcoded baseline at runtime.
 */
const COMPROMISED_HASHES = [
  // Placeholder — real hashes will be populated via --update-db
  // Format: 'sha512-<base64...>'
];

/**
 * Get the effective set of compromised hashes (hardcoded + IOC DB).
 *
 * @returns {Set<string>} Set of known-compromised integrity hash strings.
 */
function getCompromisedHashes() {
  const hashes = new Set(COMPROMISED_HASHES);
  const db = loadIocDb();
  if (db && Array.isArray(db.compromisedHashes)) {
    for (const h of db.compromisedHashes) {
      if (typeof h === 'string' && h.startsWith('sha')) {
        hashes.add(h);
      }
    }
  }
  return hashes;
}

/**
 * Lockfile Sentinel — verify lockfile package hashes against a known-clean
 * database BEFORE npm install runs.
 *
 * This is the "Integrity" pillar of the OWASP A08 mapping. It parses every
 * integrity hash in the lockfile and:
 *   1. Flags packages whose integrity hash matches a known-compromised hash
 *      from the IOC database.
 *   2. Flags packages with NO integrity hash at all (non-deterministic, can
 *      be silently replaced by a registry MITM).
 *
 * Unlike the post-install integrity check (step 6), this runs BEFORE any
 * packages are downloaded — it works on the lockfile alone.
 *
 * @param {{ message: string, category: string, fixable: boolean, fixDescription: string|null, fix: Function|null }[]} threats
 * @param {object} [_testData] - Optional test injection.
 * @param {string} [_testData.lockfileContent] - Simulated lockfile JSON string.
 * @param {string[]} [_testData.compromisedHashes] - Override compromised hash list.
 */
function lockfileSentinel(threats, _testData) {
  // Load lockfile
  let lockContent = _testData ? _testData.lockfileContent : null;
  if (!_testData) {
    lockContent = readFileSafe(path.join(process.cwd(), 'package-lock.json'));
  }
  if (!lockContent) return;

  let lockData;
  try { lockData = JSON.parse(lockContent); } catch { return; }

  // Get known-compromised hashes
  const compromised = _testData && _testData.compromisedHashes
    ? new Set(_testData.compromisedHashes)
    : getCompromisedHashes();

  // Extract all packages from lockfile
  const packages = extractPackagesFromLockfile(lockData);

  // Check each package's integrity
  const missingIntegrity = [];

  for (const pkg of packages) {
    // Check against compromised hash DB
    if (pkg.integrity && compromised.size > 0 && compromised.has(pkg.integrity)) {
      threats.push({
        message: `LOCKFILE_INTEGRITY: "${pkg.name}@${pkg.version || 'unknown'}" has a known-compromised integrity hash — this exact version was flagged as malicious (OWASP A08)`,
        category: 'LOCKFILE_INTEGRITY',
        fixable: true,
        fixDescription: `npm uninstall ${pkg.name} && npm install ${pkg.name}`,
        fix: isSafePackageName(pkg.name)
          ? () => execSync(`npm uninstall ${pkg.name} && npm install ${pkg.name}`, { stdio: 'ignore', timeout: 30000 })
          : null
      });
    }

    // Flag packages with no integrity hash (non-deterministic)
    if (!pkg.integrity && pkg.name) {
      missingIntegrity.push(pkg.name);
    }
  }

  // Report missing integrity as a single grouped threat (not per-package)
  if (missingIntegrity.length > 0) {
    const preview = missingIntegrity.slice(0, 5).join(', ');
    const more = missingIntegrity.length > 5 ? ` and ${missingIntegrity.length - 5} more` : '';
    threats.push({
      message: `LOCKFILE_INTEGRITY: ${missingIntegrity.length} package(s) in lockfile have no integrity hash (${preview}${more}) — run \`npm install --package-lock-only\` to regenerate (OWASP A08)`,
      category: 'LOCKFILE_INTEGRITY',
      fixable: true,
      fixDescription: 'npm install --package-lock-only',
      fix: () => execSync('npm install --package-lock-only', { stdio: 'ignore', timeout: 30000 })
    });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  SBOM (Software Bill of Materials) — CycloneDX format
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Generate a CycloneDX SBOM (spec 1.6) from the project's package-lock.json.
 *
 * Produces a machine-readable inventory of every dependency (direct and
 * transitive) in the project. Each component includes name, version, purl
 * (Package URL), and scope. The SBOM can be fed into OWASP Dependency-Track,
 * Grype, or any CycloneDX-compatible tool for continuous supply-chain
 * monitoring.
 *
 * @returns {object} CycloneDX SBOM document object, or an object with an error property.
 */
function generateSbom() {
  const cwd = process.cwd();
  const serialNumber = `urn:uuid:${crypto.randomUUID()}`;

  // Read root package.json for project metadata
  let rootPkg = {};
  try {
    rootPkg = JSON.parse(fs.readFileSync(path.join(cwd, 'package.json'), 'utf8'));
  } catch {
    return { error: 'No package.json found in current directory' };
  }

  const projectName = rootPkg.name || path.basename(cwd);
  const projectVersion = rootPkg.version || '0.0.0';

  // Read package-lock.json for the full dependency tree
  let lockData;
  try {
    lockData = JSON.parse(fs.readFileSync(path.join(cwd, 'package-lock.json'), 'utf8'));
  } catch {
    return { error: 'No package-lock.json found — run npm install first' };
  }

  // Determine direct dependencies for scope classification
  const directDeps = new Set();
  if (rootPkg.dependencies) {
    for (const name of Object.keys(rootPkg.dependencies)) directDeps.add(name);
  }
  const directDevDeps = new Set();
  if (rootPkg.devDependencies) {
    for (const name of Object.keys(rootPkg.devDependencies)) directDevDeps.add(name);
  }

  // Extract all packages from the lockfile
  const packages = extractPackagesFromLockfile(lockData);

  const components = packages.map((pkg) => {
    const scope = directDeps.has(pkg.name)
      ? 'required'
      : directDevDeps.has(pkg.name)
        ? 'optional'
        : 'required'; // transitive deps of production deps default to required

    const component = {
      type: 'library',
      name: pkg.name,
      version: pkg.version || 'unknown',
      scope,
      purl: `pkg:npm/${pkg.name.startsWith('@') ? pkg.name.replace('/', '%2F') : pkg.name}@${pkg.version || 'unknown'}`,
      'bom-ref': `${pkg.name}@${pkg.version || 'unknown'}`
    };

    if (pkg.integrity) {
      // Parse the integrity hash (e.g., "sha512-abc123...")
      const match = /^(sha\d+)-(.+)$/.exec(pkg.integrity);
      if (match) {
        component.hashes = [
          {
            alg: match[1].toUpperCase().replace('SHA', 'SHA-'),
            content: Buffer.from(match[2], 'base64').toString('hex')
          }
        ];
      }
    }

    return component;
  });

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    serialNumber,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: {
        components: [
          {
            type: 'application',
            name: '@sathyendra/security-checker',
            version: require('./package.json').version
          }
        ]
      },
      component: {
        type: 'application',
        name: projectName,
        version: projectVersion,
        'bom-ref': `${projectName}@${projectVersion}`
      }
    },
    components
  };
}

// ─────────────────────────────────────────────────────────────────────────────
//  VEX (Vulnerability Exploitability eXchange) — CycloneDX format
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Map internal threat categories to CycloneDX severity rating values.
 * Categories not listed here default to 'unknown'.
 * @type {Object<string, string>}
 */
const VEX_SEVERITY_MAP = {
  CRITICAL: 'critical',
  SECURITY: 'high',
  DROPPER: 'critical',
  INTEGRITY: 'high',
  SWAP: 'medium',
  MTIME: 'low',
  PYPI: 'high',
  PROVENANCE: 'high',
  SHADOW_EXEC: 'critical',
  PTH_MALWARE: 'critical',
  LOCKFILE: 'high',
  C2: 'critical',
  TEAMPCP: 'critical',
  OUTDATED: 'medium',
  REGISTRY: 'high',
  LIFECYCLE_SCRIPT: 'high',
  NPM_DOCTOR: 'medium',
  NO_LOCKFILE: 'high',
  SECRETS: 'critical',
  SSRF: 'critical',
  ENVIRONMENT: 'high',
  DEP_SCRIPT: 'high',
  REGISTRY_HTTP: 'critical',
  LOCKFILE_INTEGRITY: 'critical'
};

/**
 * Format a JSON scan result into a CycloneDX VEX document (spec 1.6).
 *
 * Produces a standards-compliant CycloneDX BOM with vulnerability entries
 * that include exploitability analysis, severity ratings, and remediation
 * recommendations. The output can be consumed by any CycloneDX-compatible
 * toolchain (e.g., OWASP Dependency-Track, Grype, Trivy).
 *
 * Each threat is assigned a deterministic ID based on a SHA-256 hash of its
 * message, so the same finding always produces the same vulnerability ID
 * across runs.
 *
 * @param {object} jsonResult - The structured result from check({ json: true }).
 * @returns {object} CycloneDX VEX document object.
 */
function formatAsVex(jsonResult) {
  const serialNumber = `urn:uuid:${crypto.randomUUID()}`;
  const projectRef = jsonResult.metadata.project || 'unknown-project';

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    serialNumber,
    metadata: {
      timestamp: jsonResult.metadata.timestamp,
      tools: {
        components: [
          {
            type: 'application',
            name: jsonResult.metadata.tool,
            version: jsonResult.metadata.version
          }
        ]
      },
      component: {
        type: 'application',
        name: projectRef,
        'bom-ref': projectRef
      }
    },
    vulnerabilities: jsonResult.threats.map((t) => {
      const hash = crypto.createHash('sha256').update(t.message).digest('hex').substring(0, 8);
      const id = `SEC-CHECK-${(t.category || 'UNKNOWN').toUpperCase()}-${hash}`;
      const severity = VEX_SEVERITY_MAP[t.category] || 'unknown';

      return {
        id,
        source: {
          name: '@sathyendra/security-checker',
          url: 'https://github.com/sathyendrav/axios-security-checker'
        },
        ratings: [
          {
            severity,
            method: 'other',
            source: {
              name: '@sathyendra/security-checker'
            }
          }
        ],
        description: t.message,
        recommendation: t.fixDescription || 'Manual review required',
        analysis: {
          state: 'exploitable',
          response: [t.fixable ? 'update' : 'can_not_fix']
        },
        affects: [
          {
            ref: projectRef
          }
        ]
      };
    })
  };
}

module.exports = { check, shield, preinstall, postVet, initShield, updateDb, getDbPath, loadIocDb, getEffectiveIocs, verifyIocSignature, formatAsVex, generateSbom, checkOutdatedDeps, checkRegistryConfig, checkLifecycleScripts, checkNpmDoctor, checkLockfilePresence, checkSecretsLeakage, checkSsrfIndicators, checkEnvironment, checkDependencyScripts, approvePackage, loadApprovedPackages, scriptBlocker, registryGuard, lockfileSentinel };

// ─────────────────────────────────────────────────────────────────────────────
//  Zero Trust Shield — multi-stage install workflow
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Orchestrate a three-stage Zero Trust install workflow.
 *
 *   Stage 1 — Pre-flight:  Check the lockfile and project configuration for
 *     known malicious packages, registry misconfigurations, lifecycle script
 *     injection, secrets leakage, and missing lockfiles *before* anything is
 *     downloaded.  If blocking threats are found, abort early.
 *
 *   Stage 2 — Isolated Install:  Run `npm install --ignore-scripts` so code
 *     is downloaded to disk without executing any lifecycle hooks (postinstall,
 *     preinstall, etc.).  This blocks dropper-style attacks like the Axios
 *     postinstall payload.
 *
 *   Stage 3 — Post-vetting:  Run the full `check({ fix })` scan against the
 *     downloaded files (integrity, swap detection, SSRF indicators, C2 scans,
 *     etc.) and optionally auto-remediate fixable threats.
 *
 * @param {object} [options]
 * @param {boolean} [options.fix=false] - Auto-remediate fixable threats in Stage 3.
 * @param {boolean} [options.json=false] - Return a structured JSON result instead of printing.
 * @param {object} [_testData] - Optional test injection to avoid real installs.
 * @param {boolean} [_testData.skipInstall] - Skip the real npm install (for testing).
 * @param {string} [_testData.installOutput] - Simulated install stdout.
 * @param {boolean} [_testData.installFails] - Simulate install failure.
 * @returns {Promise<boolean|object>} Same contract as check(): boolean or structured object.
 */
async function shield(options = {}, _testData) {
  const fix = options.fix || false;
  const jsonMode = options.json || false;
  const divider = '─'.repeat(70);
  const stageThreats = { preflight: [], install: null, postVetting: [] };

  if (!jsonMode) {
    console.log(`\n${divider}`);
    console.log('  🛡️  @sathyendra/security-checker — Zero Trust Shield');
    console.log(divider);
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  STAGE 1 — Pre-flight (lockfile + config checks, no node_modules)
  // ═══════════════════════════════════════════════════════════════════════
  if (!jsonMode) {
    console.log('\n  ▸ Stage 1: Pre-flight — scanning lockfile & configuration...');
  }

  const preflightThreats = [];

  // Lockfile blocklist scan (known malicious packages)
  deepLockfileAudit(preflightThreats);

  // Registry Guard: reject non-official + unencrypted HTTP registries (A05)
  const rgResult = registryGuard(_testData);
  preflightThreats.push(...rgResult.threats);

  // Script Blocker: lifecycle script injection detection (A03)
  checkLifecycleScripts(preflightThreats);

  // Secrets in project root that could be published
  checkSecretsLeakage(preflightThreats);

  // Missing lockfile
  checkLockfilePresence(preflightThreats);

  // Lockfile Sentinel: integrity hash verification (A08)
  lockfileSentinel(preflightThreats, _testData);

  // Cross-ecosystem (PyPI requirements.txt, Pipfile.lock — no install needed)
  crossEcosystemScan(preflightThreats);

  stageThreats.preflight = preflightThreats;

  if (!jsonMode) {
    if (preflightThreats.length === 0) {
      console.log('    ✅ Pre-flight passed — no threats in lockfile or configuration\n');
    } else {
      console.log(`    ⚠️  ${preflightThreats.length} threat(s) found in pre-flight:\n`);
      for (const t of preflightThreats) {
        const tag = t.fixable ? '[FIXABLE]' : '[MANUAL]';
        console.error(`    🚨 ${t.message}  ${tag}`);
      }
      console.log();
    }
  }

  // Determine if any pre-flight threat is blocking.
  // CRITICAL, LOCKFILE (known malware in dep tree), and SECRETS are blocking.
  const blockingCategories = new Set(['CRITICAL', 'LOCKFILE', 'SECRETS', 'LIFECYCLE_SCRIPT', 'DEP_SCRIPT', 'REGISTRY', 'REGISTRY_HTTP', 'LOCKFILE_INTEGRITY']);
  const hasBlocker = preflightThreats.some(t => blockingCategories.has(t.category));

  if (hasBlocker) {
    if (!jsonMode) {
      console.log(`  ✋ Stage 1 BLOCKED — critical threats detected. Resolve them before installing.`);
      console.log(`${divider}\n`);
      printDiagnosticReport(preflightThreats, fix);
      if (fix && preflightThreats.some(t => t.fixable)) {
        await runFixes(preflightThreats);
      }
    }

    if (jsonMode) {
      return buildShieldResult(stageThreats, 'blocked', fix);
    }
    return true; // threats found
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  STAGE 2 — Isolated Install (npm install --ignore-scripts)
  // ═══════════════════════════════════════════════════════════════════════
  if (!jsonMode) {
    console.log('  ▸ Stage 2: Isolated Install — downloading packages (scripts disabled)...');
  }

  let installOk = true;
  if (_testData && _testData.skipInstall) {
    installOk = !_testData.installFails;
    if (_testData.installOutput && !jsonMode) {
      console.log(`    ${_testData.installOutput}`);
    }
  } else {
    try {
      execSync('npm install --ignore-scripts', {
        encoding: 'utf8',
        timeout: 120000,
        stdio: ['ignore', 'pipe', 'pipe']
      });
    } catch (err) {
      installOk = false;
      stageThreats.install = (err.stderr || err.message || 'unknown error').trim();
    }
  }

  if (!installOk) {
    if (!jsonMode) {
      console.log(`    ❌ npm install --ignore-scripts failed: ${stageThreats.install}`);
      console.log(`  ✋ Stage 2 FAILED — cannot proceed to post-vetting.`);
      console.log(`${divider}\n`);
    }
    if (jsonMode) {
      return buildShieldResult(stageThreats, 'install-failed', fix);
    }
    return true; // treat install failure as a threat
  }

  if (!jsonMode) {
    console.log('    ✅ Packages downloaded with scripts disabled\n');
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  STAGE 3 — Post-vetting (full scan + optional auto-fix)
  // ═══════════════════════════════════════════════════════════════════════
  if (!jsonMode) {
    console.log('  ▸ Stage 3: Post-vetting — full integrity & security scan...');
  }

  // Run the full check() which includes all 16 detection steps.
  // Combine pre-flight threats with post-vetting threats to avoid duplicates:
  // check() will re-run some of the same checks (lockfile, registry, etc.) but
  // that's intentional — the installed state may reveal new issues.
  const fullResult = await check({ fix, json: true });

  // Separate threats that are NEW (not already found in pre-flight)
  const preflightMessages = new Set(preflightThreats.map(t => t.message));
  const newThreats = fullResult.threats.filter(t => !preflightMessages.has(t.message));
  stageThreats.postVetting = newThreats;

  if (!jsonMode) {
    const allThreats = [...preflightThreats, ...newThreats];

    if (allThreats.length === 0) {
      console.log('    ✅ Post-vetting passed — all packages verified\n');
    } else if (newThreats.length > 0) {
      console.log(`    ⚠️  ${newThreats.length} new threat(s) found in post-vetting:\n`);
      for (const t of newThreats) {
        const tag = t.fixable ? '[FIXABLE]' : '[MANUAL]';
        console.error(`    🚨 ${t.message}  ${tag}`);
      }
      console.log();
    }

    // Print combined diagnostic report
    const combinedThreats = allThreats.map(t => {
      // Reconstruct full threat objects for the report
      const orig = [...preflightThreats, ...fullResult.threats].find(ft => ft.message === t.message);
      return orig || t;
    });

    console.log(`${divider}`);
    console.log('  🛡️  Shield Summary');
    console.log(divider);
    console.log(`  Stage 1 (Pre-flight):    ${preflightThreats.length} threat(s)`);
    console.log(`  Stage 2 (Install):       ✅ success`);
    console.log(`  Stage 3 (Post-vetting):  ${newThreats.length} new threat(s)`);
    console.log(`${divider}`);

    if (combinedThreats.length > 0) {
      printDiagnosticReport(combinedThreats, fix);
      if (fix && combinedThreats.some(t => t.fixable)) {
        await runFixes(combinedThreats);
      }
    } else {
      console.log('  ✅ All stages passed — project is clean');
      console.log(`${divider}\n`);
    }

    return allThreats.length > 0;
  }

  return buildShieldResult(stageThreats, 'complete', fix);
}

/**
 * Build a structured JSON result for shield() mode.
 * @param {object} stageThreats - Threats collected from each stage.
 * @param {string} outcome - 'blocked' | 'install-failed' | 'complete'.
 * @param {boolean} fix - Whether --fix was requested.
 * @returns {object} Structured shield result.
 */
function buildShieldResult(stageThreats, outcome, fix) {
  const allThreats = [
    ...stageThreats.preflight,
    ...stageThreats.postVetting
  ].map(t => ({
    message: t.message,
    category: t.category,
    fixable: t.fixable,
    fixDescription: t.fixDescription || null
  }));

  const fixableCount = allThreats.filter(t => t.fixable).length;

  let pkg = {};
  try { pkg = JSON.parse(fs.readFileSync(path.join(process.cwd(), 'package.json'), 'utf8')); } catch {}

  return {
    mode: 'shield',
    outcome,
    stages: {
      preflight: {
        threats: stageThreats.preflight.map(t => ({
          message: t.message, category: t.category, fixable: t.fixable,
          fixDescription: t.fixDescription || null
        })),
        passed: stageThreats.preflight.length === 0
      },
      install: {
        passed: outcome !== 'install-failed',
        error: stageThreats.install || null
      },
      postVetting: {
        threats: stageThreats.postVetting.map(t => ({
          message: t.message, category: t.category, fixable: t.fixable,
          fixDescription: t.fixDescription || null
        })),
        passed: stageThreats.postVetting.length === 0
      }
    },
    threats: allThreats,
    summary: {
      total: allThreats.length,
      fixable: fixableCount,
      manual: allThreats.length - fixableCount,
      clean: allThreats.length === 0
    },
    metadata: {
      tool: '@sathyendra/security-checker',
      version: require('./package.json').version,
      timestamp: new Date().toISOString(),
      project: pkg.name || path.basename(process.cwd()),
      platform: os.platform(),
      node: process.version
    }
  };
}

// ─────────────────────────────────────────────────────────────────────────────
//  Preinstall Mode — lightweight pre-hook scan
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Suspicious environment variables that can compromise an npm install.
 *
 * Each entry has:
 *   - envVar:  the variable name (checked case-sensitively against process.env)
 *   - check:   function(value) → truthy if suspicious
 *   - label:   human-readable description of the risk
 *   - category: threat category for the report
 */
const SUSPICIOUS_ENV_CHECKS = [
  // Library preload hijacking
  {
    envVar: 'LD_PRELOAD',
    check: v => v && v.trim().length > 0,
    label: 'LD_PRELOAD is set — shared library preload can intercept crypto, network, or file I/O calls',
    category: 'ENVIRONMENT'
  },
  {
    envVar: 'DYLD_INSERT_LIBRARIES',
    check: v => v && v.trim().length > 0,
    label: 'DYLD_INSERT_LIBRARIES is set — macOS library injection can intercept system calls',
    category: 'ENVIRONMENT'
  },
  // NODE_OPTIONS --require injection
  {
    envVar: 'NODE_OPTIONS',
    check: v => v && (/--require\s/.test(v) || /-r\s/.test(v)),
    label: 'NODE_OPTIONS contains --require — a module is injected before every Node.js process',
    category: 'ENVIRONMENT'
  },
  // npm registry override via env (Dependency Confusion)
  {
    envVar: 'npm_config_registry',
    check: v => v && v.trim().length > 0 && !isOfficialRegistry(v.trim()),
    label: 'npm_config_registry overrides the package registry via environment — Dependency Confusion risk (OWASP A08)',
    category: 'ENVIRONMENT'
  },
  // Custom CA cert injection (MITM potential)
  {
    envVar: 'NODE_EXTRA_CA_CERTS',
    check: v => v && v.trim().length > 0,
    label: 'NODE_EXTRA_CA_CERTS is set — custom CA certificates can enable MITM interception of HTTPS traffic',
    category: 'ENVIRONMENT'
  }
];

/**
 * Proxy environment variables to check. These are examined separately because
 * we only flag them when they point to non-localhost hosts (corporate proxies
 * through localhost/127.0.0.1 are common and benign).
 */
const PROXY_ENV_VARS = ['http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY'];

/**
 * Check the process environment for variables that could compromise an
 * npm install (OWASP A05 — Security Misconfiguration).
 *
 * This is distinct from checkShadowExecution() which is focused on runtime
 * threats (suspicious parent processes, LOLBins). checkEnvironment() targets
 * install-time risks: registry overrides, proxy MITM, CA injection, and
 * library preload that could affect the install process itself.
 *
 * @param {object[]} threats - Array to push structured threat objects into.
 * @param {object} [_testData] - Optional test injection.
 * @param {object} [_testData.env] - Mock environment variable map (overrides process.env).
 */
function checkEnvironment(threats, _testData) {
  const env = (_testData && _testData.env) ? _testData.env : process.env;

  // ── Fixed checks (LD_PRELOAD, NODE_OPTIONS, npm_config_registry, etc.) ──
  for (const rule of SUSPICIOUS_ENV_CHECKS) {
    const value = env[rule.envVar];
    if (rule.check(value)) {
      const safeValue = value.length > 80 ? value.slice(0, 80) + '…' : value;
      threats.push({
        message: `ENVIRONMENT: ${rule.label} ("${safeValue}")`,
        category: 'ENVIRONMENT',
        fixable: false,
        fixDescription: `Unset ${rule.envVar} before running npm install`,
        fix: null
      });
    }
  }

  // ── Proxy variables (only flag non-localhost proxies) ────────────────────
  for (const varName of PROXY_ENV_VARS) {
    const value = env[varName];
    if (!value || value.trim().length === 0) continue;

    try {
      const proxyUrl = new URL(value.trim().startsWith('http') ? value.trim() : `http://${value.trim()}`);
      const host = proxyUrl.hostname.toLowerCase();
      // Localhost proxies are benign (common corporate dev setup)
      if (host === 'localhost' || host === '127.0.0.1' || host === '::1') continue;

      threats.push({
        message: `ENVIRONMENT: ${varName} routes traffic through external proxy "${host}" — potential MITM risk during package download`,
        category: 'ENVIRONMENT',
        fixable: false,
        fixDescription: `Verify ${varName} points to a trusted proxy or unset it`,
        fix: null
      });
    } catch {
      // Malformed proxy URL — flag it as suspicious
      threats.push({
        message: `ENVIRONMENT: ${varName} contains malformed proxy URL ("${value.length > 80 ? value.slice(0, 80) + '…' : value}")`,
        category: 'ENVIRONMENT',
        fixable: false,
        fixDescription: `Fix or unset ${varName}`,
        fix: null
      });
    }
  }
}

/**
 * Run a lightweight preinstall scan focused on the lockfile and environment.
 *
 * Designed to run as a `preinstall` hook BEFORE `npm install` downloads
 * any packages.  Does NOT scan `node_modules` (which may not exist yet).
 *
 * Checks performed:
 *   1. Lockfile integrity — scan package-lock.json for known malicious packages
 *   2. Registry configuration — ensure registry is official npmjs.org (A08)
 *   3. Environment — check for suspicious env vars (LD_PRELOAD, proxy MITM, etc.)
 *   4. Lifecycle scripts — flag injection patterns in the project's package.json
 *   5. Lockfile presence — warn if no lockfile exists
 *
 * @param {object} [options]
 * @param {boolean} [options.json=false] - Return structured JSON instead of printing.
 * @param {object} [_testData] - Optional test injection (passed through to sub-checks).
 * @param {object} [_testData.env] - Mock environment variables for checkEnvironment().
 * @returns {Promise<boolean|object>} boolean in print mode (true=threats), object in JSON mode.
 */
async function preinstall(options = {}, _testData) {
  const jsonMode = options.json || false;
  const divider = '─'.repeat(70);
  const threats = [];

  if (!jsonMode) {
    console.log(`\n${divider}`);
    console.log('  🛡️  Preinstall Shield — scanning lockfile & environment');
    console.log(`${divider}\n`);
  }

  // 1. Lockfile integrity (deep audit for known malicious packages)
  deepLockfileAudit(threats);

  // 2. Registry Guard — reject non-official + unencrypted HTTP (OWASP A05)
  const rgResult = registryGuard(_testData);
  threats.push(...rgResult.threats);

  // 3. Environment variables (LD_PRELOAD, proxy, CA certs, npm_config_registry)
  checkEnvironment(threats, _testData);

  // 4. Lifecycle script injection in the project's own package.json
  checkLifecycleScripts(threats, _testData);

  // 5. Missing lockfile
  checkLockfilePresence(threats, _testData);

  // 6. Lockfile Sentinel — hash verification against clean DB (OWASP A08)
  lockfileSentinel(threats, _testData);

  if (!jsonMode) {
    if (threats.length === 0) {
      console.log('  ✅ Preinstall checks passed — safe to proceed with npm install\n');
    } else {
      console.log(`  ⚠️  ${threats.length} threat(s) found:\n`);
      for (const t of threats) {
        const tag = t.fixable ? '[FIXABLE]' : '[MANUAL]';
        console.error(`  🚨 ${t.message}  ${tag}`);
      }
      console.log();
      console.log('  ✋ Resolve these issues before running npm install.');
      console.log(`${divider}\n`);
    }
    return threats.length > 0;
  }

  // JSON mode — return structured result
  let pkg = {};
  try { pkg = JSON.parse(fs.readFileSync(path.join(process.cwd(), 'package.json'), 'utf8')); } catch {}

  return {
    mode: 'preinstall',
    threats: threats.map(t => ({
      message: t.message,
      category: t.category,
      fixable: t.fixable,
      fixDescription: t.fixDescription || null
    })),
    summary: {
      total: threats.length,
      fixable: threats.filter(t => t.fixable).length,
      manual: threats.filter(t => !t.fixable).length,
      clean: threats.length === 0
    },
    metadata: {
      tool: '@sathyendra/security-checker',
      version: require('./package.json').version,
      timestamp: new Date().toISOString(),
      project: pkg.name || path.basename(process.cwd()),
      platform: os.platform(),
      node: process.version
    }
  };
}

// ─────────────────────────────────────────────────────────────────────────────
//  Post-install Vetting (`--post`)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Post-install vetting scan.
 *
 * The complement to `preinstall()` (`--pre`).  Designed to run AFTER packages
 * have been installed with `npm ci --ignore-scripts` (or `npm install --ignore-scripts`).
 * Executes the full `check()` scan on the downloaded files and wraps the
 * output with a "Post-install Vetting" banner so CI logs clearly show which
 * stage produced the findings.
 *
 * Typical CI workflow:
 *   1. sec-check --pre          (lockfile + env scan)
 *   2. npm ci --ignore-scripts  (download without executing hooks)
 *   3. sec-check --post         (full integrity & security scan)
 *
 * @param {object}  [options]        Options forwarded to check().
 * @param {boolean} [options.fix]    Auto-remediate fixable threats.
 * @param {boolean} [options.json]   Return structured JSON result.
 * @param {object}  [_testData]      Test injection (unused, reserved for parity).
 * @returns {Promise<boolean|object>} boolean in print mode (true=threats), object in JSON mode.
 */
async function postVet(options = {}, _testData) {
  const jsonMode = options.json || false;
  const fix = options.fix || false;
  const divider = '─'.repeat(70);

  if (!jsonMode) {
    console.log(`\n${divider}`);
    console.log('  🔍 Post-install Vetting — verifying installed packages');
    console.log(`${divider}\n`);
  }

  // Run the full check() scan.  In JSON mode we need the structured object;
  // in print mode check() prints its own Diagnostic Report.
  const result = await check({ fix, json: jsonMode });

  if (jsonMode) {
    // Annotate the result with mode = 'post-vet' so consumers can distinguish
    // it from a plain check() result.
    result.mode = 'post-vet';
    return result;
  }

  // In print mode, check() already printed the Diagnostic Report,
  // so we only add a footer summarizing the post-vetting outcome.
  if (result) {
    // result === true means threats were found
    console.log(`${divider}`);
    console.log('  ❌ Post-install vetting FAILED — threats detected in installed packages');
    console.log(`${divider}\n`);
  } else {
    console.log(`${divider}`);
    console.log('  ✅ Post-install vetting passed — all packages verified');
    console.log(`${divider}\n`);
  }

  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Init Shield — automatic package.json configuration
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Scripts that `--init` will add to the user's package.json.
 * Keys are npm script names, values are the commands.
 */
const INIT_SCRIPTS = {
  preinstall: 'sec-check --pre',
  'secure-install': 'npm install --ignore-scripts && sec-check'
};

/**
 * Automatically configure the user's package.json with security scripts.
 *
 * Adds the following npm scripts:
 *   - "preinstall": "sec-check --pre"        (lockfile + env scan before install)
 *   - "secure-install": "npm install --ignore-scripts && sec-check"
 *                                             (isolated install + full scan)
 *
 * Existing scripts are NOT overwritten — the user is told which scripts were
 * skipped so they can merge them manually.
 *
 * @param {object} [_testData] - Optional test injection.
 * @param {string} [_testData.projectDir] - Override project directory (default: process.cwd()).
 * @param {boolean} [_testData.dryRun] - If true, do not write changes — return the result only.
 * @returns {object} Result: { ok, added[], skipped[], pkg (after), error? }.
 */
function initShield(_testData) {
  const projectDir = (_testData && _testData.projectDir) ? _testData.projectDir : process.cwd();
  const pkgPath = path.join(projectDir, 'package.json');
  const dryRun = _testData && _testData.dryRun;

  // ── Read package.json ────────────────────────────────────────────────
  if (!fs.existsSync(pkgPath)) {
    return { ok: false, added: [], skipped: [], error: 'No package.json found in the current directory.' };
  }

  let raw;
  try {
    raw = fs.readFileSync(pkgPath, 'utf8');
  } catch (err) {
    return { ok: false, added: [], skipped: [], error: `Cannot read package.json: ${err.message}` };
  }

  let pkg;
  try {
    pkg = JSON.parse(raw);
  } catch (err) {
    return { ok: false, added: [], skipped: [], error: `package.json is not valid JSON: ${err.message}` };
  }

  // ── Ensure scripts section exists ────────────────────────────────────
  if (!pkg.scripts || typeof pkg.scripts !== 'object') {
    pkg.scripts = {};
  }

  const added = [];
  const skipped = [];

  for (const [name, cmd] of Object.entries(INIT_SCRIPTS)) {
    if (pkg.scripts[name]) {
      skipped.push({ name, existing: pkg.scripts[name], wanted: cmd });
    } else {
      pkg.scripts[name] = cmd;
      added.push({ name, cmd });
    }
  }

  // ── Write back ──────────────────────────────────────────────────────
  if (added.length > 0 && !dryRun) {
    // Detect original indentation (default to 2 spaces)
    const indentMatch = raw.match(/^(\s+)"/m);
    const indent = indentMatch ? indentMatch[1].length : 2;

    try {
      fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, indent) + '\n', 'utf8');
    } catch (err) {
      return { ok: false, added: [], skipped, error: `Cannot write package.json: ${err.message}` };
    }
  }

  return { ok: true, added, skipped, pkg };
}

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
