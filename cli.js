#!/usr/bin/env node
'use strict';

// Import the main security scanning logic and IOC database utilities
const { check, updateDb, getDbPath, loadIocDb } = require('./check.js');

/**
 * Entry point for the `sec-check` CLI command.
 *
 * Usage:
 *   sec-check               Run a read-only scan and print the Diagnostic Report.
 *   sec-check --fix         Print the report, then auto-remediate fixable threats.
 *   sec-check --json        Output machine-readable JSON (for dashboards / VEX reports).
 *   sec-check --update-db   Fetch the latest IOC database from a trusted source.
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

  const fix = args.includes('--fix');
  const jsonMode = args.includes('--json');

  try {
    // Run security checks; returns true/false when json=false, structured object when json=true.
    // In default mode the Diagnostic Report is printed first; in JSON mode it is suppressed.
    // When --fix is passed, fixable threats are auto-remediated after the report.
    const result = await check({ fix, json: jsonMode });

    if (jsonMode) {
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
