#!/usr/bin/env node
'use strict';

// Import the main security scanning logic and IOC database utilities
const { check, shield, preinstall, postVet, initShield, approvePackage, updateDb, getDbPath, loadIocDb, formatAsVex, generateSbom } = require('./check.js');

/**
 * Entry point for the `sec-check` CLI command.
 *
 * Usage:
 *   sec-check               Run a read-only scan and print the Diagnostic Report.
 *   sec-check --fix         Print the report, then auto-remediate fixable threats.
 *   sec-check --json        Output machine-readable JSON (for dashboards / VEX reports).
 *   sec-check --vex-out     Output results as a CycloneDX VEX document (spec 1.6).
 *   sec-check --sbom        Generate a CycloneDX SBOM (Software Bill of Materials).
 *   sec-check --update-db   Fetch the latest IOC database from a trusted source.
 *   sec-check --pre         Preinstall mode: lockfile + environment scan (no node_modules needed).
 *   sec-check --init        Auto-configure package.json with preinstall & secure-install scripts.
 *   sec-check --shield     Run the Zero Trust Shield: pre-flight → isolated install → post-vetting.
 *   sec-check --help        Show usage information.
 *
 * Exit codes:
 *   0 — No threats detected (clean) / update succeeded
 *   1 — Threats found or an error occurred
 */
async function run() {
  const args = process.argv.slice(2);

  if (args.includes('--help') || args.includes('-h')) {
    console.log(`
Usage: sec-check [options]

Options:
  --fix         Auto-remediate fixable threats after showing the Diagnostic Report.
                Without this flag the tool is strictly read-only.
  --json        Output results as machine-readable JSON instead of the human-readable
                Diagnostic Report. Suitable for CI/CD pipelines, security dashboards,
                and VEX (Vulnerability Exploitability eXchange) report generation.
  --vex-out     Output a CycloneDX VEX document (spec 1.6) instead of the human-readable
                Diagnostic Report. Directly consumable by OWASP Dependency-Track, Grype,
                and other CycloneDX-compatible tools.
  --sbom        Generate a CycloneDX SBOM (Software Bill of Materials) listing every
                dependency in the project with name, version, purl, scope, and integrity
                hashes. Does not run a security scan.
  --pre         Preinstall mode. Lightweight scan for the preinstall hook that checks
                the lockfile and environment BEFORE npm downloads any packages.
                Checks: lockfile integrity, registry config, suspicious env vars,
                lifecycle script injection, lockfile presence.
                Combine with --json for machine-readable output.
  --post        Post-install vetting. Full security scan designed to run AFTER
                packages have been installed with --ignore-scripts. Verifies
                integrity, provenance, SSRF indicators, and all other checks.
                Combine with --fix to auto-remediate. Combine with --json.
  --init        Auto-configure your package.json with security scripts:
                  "preinstall": "sec-check --pre"  (lockfile + env scan before install)
                  "secure-install": "npm install --ignore-scripts && sec-check"
                Existing scripts are never overwritten.
  --approve <p> Add package <p> to the project-local approved list
                (.sec-check-approved.json). Approved packages are skipped
                during Dependency Script Sandboxing (step 17).
  --shield      Zero Trust Shield mode. Runs a three-stage secure install workflow:
                  Stage 1 — Pre-flight: scan lockfile & config for threats before downloading.
                  Stage 2 — Isolated Install: npm install --ignore-scripts (no lifecycle hooks).
                  Stage 3 — Post-vetting: full integrity & security scan on downloaded files.
                Combine with --fix to auto-remediate after post-vetting.
                Combine with --json for machine-readable stage-by-stage results.
  --update-db   Fetch the latest IOC (Indicators of Compromise) database from a
                trusted remote source. The fetched data is cached locally at
                ${getDbPath()}
                and merged with the built-in lists on every scan.
                Override the source URL with SEC_CHECK_IOC_URL env variable.
  --help        Show this help message.

Exit codes:
  0  No threats detected / database updated successfully
  1  One or more threats found / update failed
`);
    process.exit(0);
  }

  // Handle --update-db: fetch latest IOCs and exit
  if (args.includes('--update-db')) {
    console.log('🔄 Fetching latest IOC database...');
    const result = await updateDb();
    if (result.ok) {
      console.log(`✅ ${result.message}`);
      if (result.added) {
        console.log(`   New indicators: ${result.added.domains} domains, ${result.added.npm} npm packages, ${result.added.pypi} PyPI packages`);
      }
      const db = loadIocDb();
      if (db && db.updatedAt) {
        console.log(`   Last updated: ${db.updatedAt}`);
      }
      process.exit(0);
    } else {
      console.error(`❌ Update failed: ${result.message}`);
      process.exit(1);
    }
  }

  // Handle --approve <pkg>: add a package to the approved list
  if (args.includes('--approve')) {
    const idx = args.indexOf('--approve');
    const pkgName = args[idx + 1];
    if (!pkgName || pkgName.startsWith('--')) {
      console.error('❌ Usage: sec-check --approve <package-name>');
      process.exit(1);
    }
    const result = approvePackage(pkgName);
    if (result.ok) {
      console.log(`✅ ${result.message}`);
    } else {
      console.error(`❌ ${result.message}`);
      process.exit(1);
    }
    process.exit(0);
  }

  // Handle --init: auto-configure package.json with security scripts
  if (args.includes('--init')) {
    const result = initShield();
    if (!result.ok) {
      console.error(`❌ ${result.error}`);
      process.exit(1);
    }
    if (result.added.length > 0) {
      console.log('✅ Added the following scripts to package.json:\n');
      for (const s of result.added) {
        console.log(`   "${s.name}": "${s.cmd}"`);
      }
    }
    if (result.skipped.length > 0) {
      console.log('\n⚠️  Skipped (already defined):');
      for (const s of result.skipped) {
        console.log(`   "${s.name}": "${s.existing}"  (wanted: "${s.wanted}")`);
      }
    }
    if (result.added.length === 0 && result.skipped.length > 0) {
      console.log('\n   All scripts were already configured. No changes made.');
    }
    console.log();
    process.exit(0);
  }

  // Handle --sbom: generate CycloneDX SBOM and exit (no security scan)
  if (args.includes('--sbom')) {
    const sbom = generateSbom();
    if (sbom.error) {
      console.error(`❌ SBOM generation failed: ${sbom.error}`);
      process.exit(1);
    }
    console.log(JSON.stringify(sbom, null, 2));
    process.exit(0);
  }

  const fix = args.includes('--fix');
  const jsonMode = args.includes('--json');
  const vexOut = args.includes('--vex-out');
  const preMode = args.includes('--pre');
  const postMode = args.includes('--post');
  const shieldMode = args.includes('--shield');

  try {
    // ── Preinstall mode: lightweight lockfile + environment scan ────────
    if (preMode) {
      const result = await preinstall({ json: jsonMode || vexOut });

      if (vexOut) {
        const vexDoc = formatAsVex(result);
        console.log(JSON.stringify(vexDoc, null, 2));
        process.exit(result.summary.clean ? 0 : 1);
      } else if (jsonMode) {
        console.log(JSON.stringify(result, null, 2));
        process.exit(result.summary.clean ? 0 : 1);
      } else {
        process.exit(result ? 1 : 0);
      }
      return;
    }

    // ── Post-install vetting mode ──────────────────────────────────────
    if (postMode) {
      const result = await postVet({ fix, json: jsonMode || vexOut });

      if (vexOut) {
        const vexDoc = formatAsVex(result);
        console.log(JSON.stringify(vexDoc, null, 2));
        process.exit(result.summary.clean ? 0 : 1);
      } else if (jsonMode) {
        console.log(JSON.stringify(result, null, 2));
        process.exit(result.summary.clean ? 0 : 1);
      } else {
        process.exit(result ? 1 : 0);
      }
      return;
    }

    // ── Shield mode: three-stage Zero Trust workflow ─────────────────────
    if (shieldMode) {
      const result = await shield({ fix, json: jsonMode || vexOut });

      if (vexOut) {
        const vexDoc = formatAsVex(result);
        console.log(JSON.stringify(vexDoc, null, 2));
        process.exit(result.summary.clean ? 0 : 1);
      } else if (jsonMode) {
        console.log(JSON.stringify(result, null, 2));
        process.exit(result.summary.clean ? 0 : 1);
      } else {
        process.exit(result ? 1 : 0);
      }
      return;
    }

    // --vex-out implies JSON mode internally (needs the structured result object).
    // In default mode the Diagnostic Report is printed first; in JSON/VEX mode it is suppressed.
    // When --fix is passed, fixable threats are auto-remediated after the report.
    const result = await check({ fix, json: jsonMode || vexOut });

    if (vexOut) {
      // CycloneDX VEX document — directly consumable by Dependency-Track, Grype, etc.
      const vexDoc = formatAsVex(result);
      console.log(JSON.stringify(vexDoc, null, 2));
      process.exit(result.summary.clean ? 0 : 1);
    } else if (jsonMode) {
      // Machine-readable output to stdout — suitable for piping to dashboards / VEX generators
      console.log(JSON.stringify(result, null, 2));
      process.exit(result.summary.clean ? 0 : 1);
    } else {
      // Exit with code 1 if threats were found, 0 if clean
      process.exit(result ? 1 : 0);
    }
  } catch (err) {
    // Handle unexpected errors gracefully
    console.error('❌ Security check failed:', err.message);
    process.exit(1);
  }
}

run();
