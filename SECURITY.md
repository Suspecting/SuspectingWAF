# Security Policy

## Reporting a Vulnerability

If you find a security vulnerability in SuspectingWAF, **do not open a public issue**. 

Instead, please report it responsibly:

1. Email: shakyaprakhar20@gmail.com
2. Include a description of the vulnerability
3. Steps to reproduce if possible
4. Your assessment of the impact

We'll acknowledge receipt within 48 hours and aim to provide a fix within 7 days for critical issues.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Scope

The following are in scope:
- Authentication bypasses in the management dashboard
- WAF rule bypasses that allow attacks to pass through
- Remote code execution in the WAF itself
- Information disclosure from the management API
- Denial of service against the WAF process

Out of scope:
- Social engineering
- Attacks requiring physical access
- Issues in dependencies (report those upstream)

## Disclosure

We follow coordinated disclosure. We'll credit you in the release notes (unless you prefer to stay anonymous). We don't offer a bug bounty at this time, but we'll make sure you get proper credit.
