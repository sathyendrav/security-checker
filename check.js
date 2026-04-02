'use strict';

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const os = require('os');

/**
 * Main security scan entry point.
 * Runs all detection modules sequentially and collects threats.
 * @returns {Promise<boolean>} true if one or more threats were detected, false if clean.
 */
async function check() {
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
    threats.push('CRITICAL: plain-crypto-js detected in node_modules');
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
      threats.push(`SECURITY: ${vulns} high/critical vulnerabilities found (run npm audit for details)`);
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
          threats.push(`SECURITY: ${vulns} high/critical vulnerabilities found (run npm audit for details)`);
        }
      } catch {
        // Audit output unparseable — skip
      }
    }
  }

  // 3. RAT (Remote Access Trojan) artifact detection.
  //    Checks well-known file drop locations used by trojans.
  //    Skipped without admin/root since those paths are typically protected.
  if (hasAdmin) {
    checkRATArtifacts(sys, threats);
  }

  // 4. C2 (Command & Control) domain indicator in the system hosts file.
  //    Attackers sometimes modify the hosts file to redirect traffic to C2 servers.
  checkHostsFile(threats);

  // Report results
  if (threats.length === 0) {
    console.log('✅ Security check passed — no threats detected');
  } else {
    threats.forEach(t => console.error(`🚨 ${t}`));
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
 * Check well-known RAT (Remote Access Trojan) drop locations per OS.
 * These paths are commonly used by malware families to stage payloads:
 *   - Windows: wt.exe in ProgramData (masquerades as Windows Terminal)
 *   - macOS:   com.apple.act.mond in Library/Caches (mimics a system daemon)
 *   - Linux:   ld.py in /tmp (a common staging directory for initial payloads)
 * Only called when the process has admin/root privileges.
 * @param {string} sys - The OS platform string.
 * @param {string[]} threats - Array to push threat descriptions into.
 */
function checkRATArtifacts(sys, threats) {
  const ratPaths = {
    win32: [
      path.join(process.env.PROGRAMDATA || 'C:\\ProgramData', 'wt.exe')
    ],
    darwin: [
      '/Library/Caches/com.apple.act.mond'
    ],
    linux: [
      '/tmp/ld.py'
    ]
  };

  const paths = ratPaths[sys] || [];
  paths.forEach(p => {
    if (fs.existsSync(p)) {
      threats.push(`RAT DETECTED: suspicious artifact at ${p}`);
    }
  });
}

/**
 * Scan the system hosts file for known C2 (Command & Control) domain indicators.
 * Malware may add entries to the hosts file to redirect DNS lookups to attacker-controlled
 * servers. Currently checks for "sfrclak.com", a known C2 domain.
 * Supports both Windows and Unix hosts file paths.
 * Fails silently if the file is unreadable (e.g., permissions).
 * @param {string[]} threats - Array to push threat descriptions into.
 */
function checkHostsFile(threats) {
  const hostsPath = os.platform() === 'win32'
    ? path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'drivers', 'etc', 'hosts')
    : '/etc/hosts';

  try {
    const hosts = fs.readFileSync(hostsPath, 'utf8');
    if (hosts.includes('sfrclak.com')) {
      threats.push('CRITICAL: known C2 domain "sfrclak.com" found in hosts file');
    }
  } catch {
    // Hosts file unreadable — skip silently
  }
}

module.exports = check;
