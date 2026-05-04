#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

// Import the main security scanning logic and IOC database utilities
const { check, shield, preinstall, postVet, initShield, approvePackage, updateDb, getDbPath, loadIocDb, formatAsVex, formatAsSarif, generateSbom, addProjectIoc, buildIocSubmission, buildIocBatchSubmission, openUrl, loadPolicy, applySuppressions, CHECK_NAMES } = require('./check.js');

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
 *   sec-check --add-ioc     Add one project-local IOC entry to .sec-check-ioc.json.
 *   sec-check --submit-ioc  Generate a prefilled GitHub issue URL for global IOC submission.
 *   sec-check --submit-ioc-batch Generate submission URL(s) from all local IOC entries.
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
  --sarif       Output results as a SARIF 2.1.0 document for GitHub Code Scanning
                and other SARIF-compatible security workflows. Pipe to a file and
                upload via the github/codeql-action/upload-sarif action:
                  sec-check --sarif > sec-check.sarif
  --sarif-out <file>
                Like --sarif but writes directly to <file> instead of stdout.
                If the file already exists it is overwritten.
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
                Note: This also runs automatically when you install the package
                via npm install --save-dev @sathyendra/security-checker.
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
  --add-ioc <type> <value>
                Add a project-local IOC to .sec-check-ioc.json.
                <type> must be one of: c2, npm, pypi
                Examples:
                  sec-check --add-ioc c2 bad-domain.example
                  sec-check --add-ioc npm typosquat-package
                  sec-check --add-ioc pypi fake-litellm
  --submit-ioc <type> <value>
                Generate a prefilled GitHub issue URL for submitting the IOC
                to the upstream global database (ioc-db.json) for all users.
                <type> must be one of: c2, npm, pypi
                Add --open to immediately open the URL in the default browser.
  --submit-ioc-batch
                Generate a prefilled GitHub issue URL using ALL entries in
                .sec-check-ioc.json.
                Add --split to generate one URL per IOC entry instead of one
                combined issue.
                Add --open to immediately open each URL in the default browser.
  --init-policy Create a starter .sec-check-policy.json in the current directory
                with all checks enabled, empty thresholds, and no suppressions.
                Fails if the file already exists (use --force to overwrite).
  --show-policy Print the active policy loaded from .sec-check-policy.json (or
                "all defaults" when no policy file exists), then exit.
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

  // Handle --add-ioc <type> <value>: add project-local IOC entry
  if (args.includes('--add-ioc')) {
    const idx = args.indexOf('--add-ioc');
    const iocType = args[idx + 1];
    const iocValue = args[idx + 2];
    if (!iocType || !iocValue || iocType.startsWith('--') || iocValue.startsWith('--')) {
      console.error('❌ Usage: sec-check --add-ioc <c2|npm|pypi> <value>');
      process.exit(1);
    }

    const result = addProjectIoc(iocType, iocValue);
    if (!result.ok) {
      console.error(`❌ ${result.message}`);
      process.exit(1);
    }

    console.log(`✅ ${result.message}`);
    console.log(`   File: ${result.file}`);
    console.log('   This IOC will be merged with built-in + cached IOC lists for this project.');
    process.exit(0);
  }

  // Handle --submit-ioc <type> <value>: generate global submission link
  if (args.includes('--submit-ioc')) {
    const idx = args.indexOf('--submit-ioc');
    const iocType = args[idx + 1];
    const iocValue = args[idx + 2];
    if (!iocType || !iocValue || iocType.startsWith('--') || iocValue.startsWith('--')) {
      console.error('❌ Usage: sec-check --submit-ioc <c2|npm|pypi> <value>');
      process.exit(1);
    }

    const result = buildIocSubmission(iocType, iocValue);
    if (!result.ok) {
      console.error(`❌ ${result.message}`);
      process.exit(1);
    }

    console.log('✅ IOC global submission template generated.');
    console.log(`Title: ${result.title}`);
    console.log('\nBody:\n');
    console.log(result.body);
    console.log('\nOpen this URL to submit:');
    console.log(result.url);
    if (args.includes('--open')) {
      openUrl(result.url);
      console.log('🌐 Opening URL in default browser...');
    }
    process.exit(0);
  }

  // Handle --submit-ioc-batch: generate submission URL(s) from local IOC file
  if (args.includes('--submit-ioc-batch')) {
    const splitMode = args.includes('--split');
    const result = buildIocBatchSubmission({ mode: splitMode ? 'split' : 'combined' });
    if (!result.ok) {
      console.error(`❌ ${result.message}`);
      process.exit(1);
    }

    console.log(`✅ ${result.message}`);
    if (result.mode === 'combined') {
      if (result.title) {
        console.log(`Title: ${result.title}`);
      }
      if (result.body) {
        console.log('\nBody:\n');
        console.log(result.body);
      }
    }

    console.log('\nOpen URL(s) to submit:');
    for (const u of result.urls || []) {
      console.log(u);
      if (args.includes('--open')) {
        openUrl(u);
      }
    }
    if (args.includes('--open') && (result.urls || []).length > 0) {
      console.log('🌐 Opening URL(s) in default browser...');
    }
    process.exit(0);
  }

  // Handle --on-install: postinstall hook — chdir to consumer's project,
  // patch their package.json with security scripts, then run a full scan.
  // Always exits 0 so npm install is never marked as failed.
  if (args.includes('--on-install')) {
    const targetDir = process.env.INIT_CWD || process.cwd();
    if (targetDir !== process.cwd()) {
      try { process.chdir(targetDir); } catch (_) { /* fall back to cwd */ }
    }

    // Self-install guard: don't auto-configure or scan this package itself.
    let targetPkg = {};
    try { targetPkg = JSON.parse(fs.readFileSync(path.join(process.cwd(), 'package.json'), 'utf8')); } catch (_) {}
    if (targetPkg.name === '@sathyendra/security-checker') {
      process.exit(0);
    }

    // Patch the consumer's package.json with preinstall + secure-install scripts.
    const initResult = initShield();
    if (initResult.ok && initResult.added && initResult.added.length > 0) {
      console.log('\n🛡️  @sathyendra/security-checker — Auto-Setup');
      console.log('   Added security scripts to your package.json:\n');
      for (const s of initResult.added) {
        console.log(`   "${s.name}": "${s.cmd}"`);
      }
      console.log();
    }

    // Run a full security scan of the consumer's project.
    // Non-blocking: exit 0 regardless of findings so npm install succeeds.
    // The consumer can run `sec-check --fix` to remediate.
    try {
      await check({ fix: false, json: false });
    } catch (_) { /* scan errors are non-fatal during install */ }

    process.exit(0);
  }

  // Handle --init: auto-configure package.json with security scripts
  if (args.includes('--init')) {
    const result = initShield();
    if (!result.ok) {
      console.error(`❌ ${result.error}`);
      process.exit(1);
    }
    // Self-install guard: running inside this package's own repo — nothing to do.
    if (result.selfInstall) {
      process.exit(0);
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

  // Handle --show-policy: display the active policy and exit
  if (args.includes('--show-policy')) {
    const policy = loadPolicy();
    const hasFile = (() => {
      try { return require('fs').existsSync(require('path').join(process.cwd(), '.sec-check-policy.json')); } catch { return false; }
    })();
    if (!hasFile) {
      console.log('No .sec-check-policy.json found — all defaults active (all checks enabled, no suppressions).');
    } else {
      console.log('Active policy from .sec-check-policy.json:\n');
      const disabled = CHECK_NAMES.filter(n => policy.checks[n] === false);
      const enabled  = CHECK_NAMES.filter(n => policy.checks[n] !== false);
      console.log(`  Checks enabled  : ${enabled.length === CHECK_NAMES.length ? 'all (22)' : enabled.join(', ')}`);
      if (disabled.length) console.log(`  Checks disabled : ${disabled.join(', ')}`);
      if (Object.keys(policy.thresholds).length) {
        console.log('\n  Thresholds:');
        for (const [k, v] of Object.entries(policy.thresholds)) {
          console.log(`    ${k}: ${JSON.stringify(v)}`);
        }
      }
      if (policy.suppressions.length) {
        console.log(`\n  Suppressions (${policy.suppressions.length}):`);
        for (const s of policy.suppressions) {
          const parts = [];
          if (s.check)           parts.push(`check=${s.check}`);
          if (s.category)        parts.push(`category=${s.category}`);
          if (s.messageContains) parts.push(`messageContains="${s.messageContains}"`);
          if (s.until)           parts.push(`until=${s.until}`);
          if (s.reason)          parts.push(`reason="${s.reason}"`);
          console.log(`    - ${parts.join('  ')}`);
        }
      } else {
        console.log('\n  Suppressions    : none');
      }
    }
    process.exit(0);
  }

  // Handle --init-policy: scaffold a starter .sec-check-policy.json
  if (args.includes('--init-policy')) {
    const policyPath = require('path').join(process.cwd(), '.sec-check-policy.json');
    const force = args.includes('--force');
    if (require('fs').existsSync(policyPath) && !force) {
      console.error('❌ .sec-check-policy.json already exists. Use --force to overwrite.');
      process.exit(1);
    }
    const checksObj = {};
    for (const n of CHECK_NAMES) checksObj[n] = true;
    const starter = {
      $schema: 'https://raw.githubusercontent.com/sathyendrav/security-checker/main/schema/policy.schema.json',
      version: 1,
      checks: checksObj,
      thresholds: {
        npmAudit: { minVulns: 1 },
        outdatedDeps: { minMajorDrift: 1 }
      },
      suppressions: [
        {
          _comment: 'Example: suppress OUTDATED findings for a specific package',
          check: 'outdatedDeps',
          messageContains: 'some-package',
          reason: 'Internal fork — not updated on npm',
          until: '2026-12-31'
        }
      ]
    };
    require('fs').writeFileSync(policyPath, JSON.stringify(starter, null, 2) + '\n', 'utf8');
    console.log('✅ Created .sec-check-policy.json');
    console.log('   Edit it to disable checks, tune thresholds, or add suppressions.');
    console.log(`   Run 'sec-check --show-policy' to verify your configuration.`);
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
  const sarifMode = args.includes('--sarif');
  const sarifOutIdx = args.indexOf('--sarif-out');
  const sarifOutFile = sarifOutIdx !== -1 ? args[sarifOutIdx + 1] : null;
  const preMode = args.includes('--pre');
  const postMode = args.includes('--post');
  const shieldMode = args.includes('--shield');

  try {
    // ── Preinstall mode: lightweight lockfile + environment scan ────────
    if (preMode) {
      const result = await preinstall({ json: jsonMode || vexOut || sarifMode || !!sarifOutFile });

      if (vexOut) {
        const vexDoc = formatAsVex(result);
        console.log(JSON.stringify(vexDoc, null, 2));
        process.exit(result.summary.clean ? 0 : 1);
      } else if (sarifMode || sarifOutFile) {
        _outputSarif(result, sarifOutFile);
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
      const result = await postVet({ fix, json: jsonMode || vexOut || sarifMode || !!sarifOutFile });

      if (vexOut) {
        const vexDoc = formatAsVex(result);
        console.log(JSON.stringify(vexDoc, null, 2));
        process.exit(result.summary.clean ? 0 : 1);
      } else if (sarifMode || sarifOutFile) {
        _outputSarif(result, sarifOutFile);
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
      const result = await shield({ fix, json: jsonMode || vexOut || sarifMode || !!sarifOutFile });

      if (vexOut) {
        const vexDoc = formatAsVex(result);
        console.log(JSON.stringify(vexDoc, null, 2));
        process.exit(result.summary.clean ? 0 : 1);
      } else if (sarifMode || sarifOutFile) {
        _outputSarif(result, sarifOutFile);
        process.exit(result.summary.clean ? 0 : 1);
      } else if (jsonMode) {
        console.log(JSON.stringify(result, null, 2));
        process.exit(result.summary.clean ? 0 : 1);
      } else {
        process.exit(result ? 1 : 0);
      }
      return;
    }

    // --vex-out / --sarif imply JSON mode internally (need the structured result object).
    // In default mode the Diagnostic Report is printed first; in JSON/VEX/SARIF mode it is suppressed.
    // When --fix is passed, fixable threats are auto-remediated after the report.
    const result = await check({ fix, json: jsonMode || vexOut || sarifMode || !!sarifOutFile });

    if (vexOut) {
      // CycloneDX VEX document — directly consumable by Dependency-Track, Grype, etc.
      const vexDoc = formatAsVex(result);
      console.log(JSON.stringify(vexDoc, null, 2));
      process.exit(result.summary.clean ? 0 : 1);
    } else if (sarifMode || sarifOutFile) {
      // SARIF 2.1.0 — for GitHub Code Scanning and SARIF-compatible CI tools.
      _outputSarif(result, sarifOutFile);
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

/**
 * Render a JSON scan result as SARIF 2.1.0 and either print to stdout or
 * write to a file (when sarifOutFile is provided).
 *
 * @param {object} result - Structured scan result from check({ json: true }).
 * @param {string|null} sarifOutFile - Destination file path, or null for stdout.
 */
function _outputSarif(result, sarifOutFile) {
  const sarifDoc = formatAsSarif(result);
  const sarifJson = JSON.stringify(sarifDoc, null, 2);
  if (sarifOutFile) {
    try {
      fs.writeFileSync(path.resolve(sarifOutFile), sarifJson, 'utf8');
      console.error(`✅ SARIF report written to ${sarifOutFile}`);
    } catch (err) {
      console.error(`❌ Failed to write SARIF file: ${err.message}`);
      process.exit(1);
    }
  } else {
    console.log(sarifJson);
  }
}

run();
