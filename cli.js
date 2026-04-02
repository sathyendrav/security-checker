#!/usr/bin/env node
'use strict';

// Import the main security scanning logic
const check = require('./check.js');

/**
 * Entry point for the `sec-check` CLI command.
 * Runs all security checks and exits with an appropriate code:
 *   - Exit 0: No threats detected (clean)
 *   - Exit 1: Threats found or an error occurred
 */
async function run() {
  try {
    // Run security checks; returns true if any threats were found
    const threatsFound = await check();

    // Exit with code 1 if threats were found, 0 if clean
    process.exit(threatsFound ? 1 : 0);
  } catch (err) {
    // Handle unexpected errors gracefully
    console.error('❌ Security check failed:', err.message);
    process.exit(1);
  }
}

run();
