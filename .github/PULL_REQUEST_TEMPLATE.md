---
name: Pull Request
about: Describe what this PR changes and why
---

## Summary

<!-- One-line description of the change -->

## Type of change

- [ ] Bug fix
- [ ] New detection module
- [ ] IOC database update
- [ ] Refactor / code quality
- [ ] Documentation
- [ ] CI/build

## Motivation

<!-- Why is this change needed? Link related issues with "Closes #N" -->

## Changes

<!-- Bullet-point list of what changed -->

## Testing

- [ ] `npm test` passes locally (`node test/simulate-malware.js`)
- [ ] `node cli.js` self-scan exits 0 in the repo root
- [ ] New / updated simulation test added for any new detection logic
- [ ] All monkey-patched globals are restored in `finally` blocks

## Zero-dependency checklist

- [ ] No new `require()` calls to packages outside Node.js built-ins
- [ ] `package.json` `dependencies` field is unchanged (or still empty)

## Notes for reviewer

<!-- Anything that needs special attention -->
