'use strict';

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const os = require('os');

/**
 * Main security scan. Returns true if any threats are found.
 */
async function check() {
  const threats = [];
  const sys = os.platform();

  // CRITICAL: Check permissions first — RAT scans require admin/root
  const hasAdmin = await checkPermissions(sys);
  if (!hasAdmin) {
    console.warn('⚠️  Running without admin/root — RAT artifact scans may miss indicators');
  }

  // 1. Known malicious package: plain-crypto-js
  const malDir = path.join(process.cwd(), 'node_modules', 'plain-crypto-js');
  if (fs.existsSync(malDir)) {
    threats.push('CRITICAL: plain-crypto-js detected in node_modules');
  }

  // 2. npm audit — flag high and critical severity vulnerabilities
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
    // npm audit exits with non-zero when vulnerabilities exist; parse what we can
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

  // 3. RAT artifact detection (requires admin/root)
  if (hasAdmin) {
    checkRATArtifacts(sys, threats);
  }

  // 4. C2 domain indicator in hosts file
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
 * Check for admin (Windows) or root (Unix) privileges.
 * Returns a Promise<boolean>.
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
 * Check well-known RAT drop locations per OS.
 * Only called when we have sufficient permissions.
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
 * Scan the hosts file for known C2 domain indicators.
 * Only checks Unix-style path; Windows hosts file check is a no-op
 * (Windows users can extend this as needed).
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
