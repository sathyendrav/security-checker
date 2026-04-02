#!/usr/bin/env node
'use strict';

// Import the main security scanning logic
const check = require('./check.js');

/**
 * Entry point for the `sec-check` CLI command.
 *
 * Usage:
 *   sec-check          Run a read-only scan and print the Diagnostic Report.
 *   sec-check --fix    Print the report, then auto-remediate fixable threats.
 *   sec-check --help   Show usage information.
 *
 * Exit codes:
 *   0 — No threats detected (clean)
 *   1 — Threats found or an error occurred
 */
async function run() {
  const args = process.argv.slice(2);

  if (args.includes('--help') || args.includes('-h')) {
    console.log(`
Usage: sec-check [options]

Options:
  --fix    Auto-remediate fixable threats after showing the Diagnostic Report.
           Without this flag the tool is strictly read-only.
  --help   Show this help message.

Exit codes:
  0  No threats detected
  1  One or more threats found
`);
    process.exit(0);
  }

  const fix = args.includes('--fix');

  try {
    // Run security checks; returns true if any threats were found.
    // The Diagnostic Report is always printed first.
    // When --fix is passed, fixable threats are auto-remediated after the report.
    const threatsFound = await check({ fix });

    // Exit with code 1 if threats were found, 0 if clean
    process.exit(threatsFound ? 1 : 0);
  } catch (err) {
    // Handle unexpected errors gracefully
    console.error('❌ Security check failed:', err.message);
    process.exit(1);
  }
}

run();
