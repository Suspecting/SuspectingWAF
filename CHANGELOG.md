# Changelog

All notable changes to SuspectingWAF will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-07-31

### Added
- Complete HTTPS & TLSv1.3 support on port `8443`
- Automatic self-signed certificate generation on first boot via `openssl`
- In-memory caching engine (10s TTL) for Site configurations, WAF Mode, and Rate Limits to achieve zero-latency DB lookups
- `keepAliveTimeout` (120s) and connection reuse on proxy servers to handle massive concurrency
- HTTP (8080) to HTTPS (8443) automatic 301 redirection
- Documented `mkcert` workflow for trusted local development

### Changed
- Refactored `server.js` to utilize Node.js native `https` module alongside `http-proxy`
- Modified `handler.js` and `inspector.js` to rely on memory cache instead of synchronous database calls per request
- Achieved stable 4,823 RPS under `wrk` stress testing with 0 connection drops

## [1.0.0] - 2026-07-09

### Added
- Initial release of SuspectingWAF
- Reverse proxy with HTTP/HTTPS support
- Detection engine with 8 rule modules:
  - SQL Injection (SQLi)
  - Cross-Site Scripting (XSS)
  - OS Command Injection
  - Path Traversal
  - Remote Code Execution (RCE)
  - Server-Side Request Forgery (SSRF)
  - XML External Entity (XXE)
  - CRLF Injection
- Rate limiting (per-IP sliding window)
- Bot detection (User-Agent analysis, request patterns)
- Management dashboard with dark theme
- REST API for programmatic management
- JWT-based authentication
- Site management (add/edit/delete upstream backends)
- Attack log viewer with filtering
- Custom rules (block/allow by IP, URL, header, User-Agent)
- IP blocklist and allowlist with optional expiration
- SSL certificate management
- SQLite database (zero-config)
- Docker support (Dockerfile + docker-compose.yml)
- Full documentation in `/docs`

### Security
- Password hashing with bcrypt
- JWT tokens with configurable secret
- Rate limiting on login endpoint
- Input validation on all API endpoints
