# @sathyendra/security-checker

A lightweight, zero-dependency security scanner for npm projects. Detects malicious packages, high/critical vulnerabilities, RAT artifacts, and C2 domain indicators — before they can execute.

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
sec-check
```

**Exit codes:**
- `0` — No threats detected (clean)
- `1` — One or more threats found (CI will fail)

## What it checks

| Check | Description |
|---|---|
| Malicious packages | Detects known bad packages (e.g. `plain-crypto-js`) in `node_modules` |
| npm audit | Flags high and critical severity vulnerabilities |
| RAT artifacts | Scans OS-specific paths for Remote Access Trojan drop indicators (requires admin/root) |
| C2 hosts | Checks the system hosts file for known C2 domain indicators (`sfrclak.com`) |

## Permissions

RAT artifact detection requires **admin** (Windows) or **root** (Unix/macOS). Without elevated permissions the tool still runs but emits a warning and skips RAT path checks to avoid false negatives silently passing.

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
