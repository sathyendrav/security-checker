# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| latest  | ✅        |
| older   | ❌        |

Only the latest published version on npm receives security fixes.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report vulnerabilities privately using [GitHub Security Advisories](https://github.com/sathyendrav/security-checker/security/advisories/new).

Include:

1. A description of the vulnerability and its potential impact
2. The version(s) affected
3. Steps to reproduce or a proof-of-concept (be as specific as possible)
4. Any proposed mitigations you have identified

You will receive acknowledgement within **48 hours** and a status update within **7 days**.

## Disclosure policy

We follow coordinated disclosure. Once a fix is released we will publish a GitHub Security Advisory crediting the reporter (unless you prefer to remain anonymous).

## Scope

Vulnerabilities in scope:

- Detection bypass — a threat indicator that `sec-check` should flag but does not
- Remote code execution or privilege escalation introduced by this package itself
- Signature verification bypass for `ioc-db.json`
- Dependency confusion / supply-chain issues in the package itself

Out of scope:

- Vulnerabilities in your own project that `sec-check` correctly detected
- False positives (use [Discussions](https://github.com/sathyendrav/security-checker/discussions) for those)
- Issues in Node.js or npm themselves
