# Contributing to @sathyendra/security-checker

Thank you for helping improve supply-chain security tooling.

## Ground rules

- **Zero runtime dependencies.** Detection logic must use only Node.js built-ins (`fs`, `path`, `crypto`, `child_process`, `os`, `https`). Never add entries to `dependencies` in `package.json`.
- **Node >= 18.** Do not use APIs unavailable in Node 18.
- **Strict mode everywhere.** All files begin with `'use strict';`.
- **Tests are required.** Every new detection module needs a corresponding simulation test in `test/simulate-malware.js`.

## Getting started

```bash
git clone https://github.com/sathyendrav/security-checker.git
cd security-checker
node cli.js          # self-scan — should exit 0
npm test             # run simulation tests
```

No build step, no install step. It's pure JavaScript.

## Adding a detection module

1. Add a `check*()` function to `check.js` following the existing naming convention.
2. Call it from the main `check()` function.
3. Push detected threats as strings onto the `threats` array using the format:  
   `CATEGORY: description`
4. Add a simulation test in `test/simulate-malware.js`:
   - Create artifacts in a temp directory via `withTempDir`.
   - Monkey-patch `fs` or `execSync` if needed.
   - Restore all globals in a `finally` block.
   - Assert `result === true` when the threat is present.

## IOC database changes

Any change to `ioc-db.json` must be re-signed:

```bash
node scripts/sign-ioc-db.js
```

This requires the Ed25519 private key. Contact the maintainer if you need access for a legitimate IOC update.

## Submitting a pull request

1. Fork the repo and create a branch from `main`.
2. Make your changes and run `npm test`.
3. Ensure `node cli.js` exits `0` (self-scan clean).
4. Open a PR — the template will guide you through the checklist.

## Code style

- Constants in `UPPERCASE`.
- Detection functions named `check*()`.
- Threat objects: `{ message, category, fixable, fixDescription, fix? }` (when returning structured output).
- JSDoc on all exported and major functions.

## Reporting bugs

Use the [bug report template](https://github.com/sathyendrav/security-checker/issues/new?template=bug_report.yml).

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). Be respectful.
