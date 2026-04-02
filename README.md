# @sathyendra/security-checker

A lightweight, zero-dependency security scanner for npm projects. Detects malicious packages, high/critical vulnerabilities, dropper packages, decoy swap attacks, integrity mismatches, TeamPCP/WAVESHAPER artifacts, cross-ecosystem (PyPI) threats, provenance violations, and C2 domain indicators — before they can execute.

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
sec-check            # Read-only scan — prints Diagnostic Report only
sec-check --fix      # Print report, then auto-remediate fixable threats
sec-check --help     # Show usage information
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

Threats that **cannot** be auto-fixed (always `[MANUAL]`): TeamPCP system artifacts, C2 hosts entries, PyPI packages, Python stagers, provenance issues.

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
| C2 domains | Checks the system hosts file for all known TeamPCP C2 domain indicators (7 domains tracked) |
| Cross-ecosystem (PyPI) | Scans `requirements.txt`, `Pipfile`, and `Pipfile.lock` for known malicious PyPI packages from the same TeamPCP campaign (LiteLLM, Telnyx, Trivy, KICS variants) |
| Python stager detection | Flags suspicious `.py` files in Node.js project roots that contain backdoor-like patterns (subprocess, socket, exec, base64) |
| Provenance verification | Checks high-profile packages (axios, lodash, express, etc.) for npm provenance attestations. Flags “Suspicious: Manual Publish Detected” when a popular package is published without a CI/CD pipeline link or GitHub repository — a sign of stolen npm token usage |

## Permissions

TeamPCP/WAVESHAPER artifact detection requires **admin** (Windows) or **root** (Unix/macOS). Without elevated permissions the tool still runs all other checks but emits a warning and skips system-level artifact scans.

## Use in CI/CD

Add to your GitHub Actions workflow:

```yaml
- name: Security scan
  run: npx @sathyendra/security-checker
```

Exits `1` on any threat, blocking the pipeline.

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
