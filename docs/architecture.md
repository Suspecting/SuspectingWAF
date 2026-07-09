# Architecture Overview

SuspectingWAF is built as a monolithic Node.js application, split into several distinct layers. This approach keeps deployment simple (just one process to run) while maintaining separation of concerns in the codebase.

## Core Components

### 1. The Reverse Proxy (`src/proxy/`)
Built around `http-proxy`, this is the main entry point for internet traffic. It listens on the configured ports (usually 80 and 443).
- When a request comes in, the proxy first determines which configured "Site" (upstream) the request belongs to based on the `Host` header.
- If SSL is required, it handles SNI (Server Name Indication) to dynamically load the correct certificate from the database.
- It then pauses the request and hands it over to the Detection Engine.
- If the engine allows the request, it is proxied to the upstream target. If blocked, a 403 Forbidden is returned.

### 2. The Detection Engine (`src/engine/`)
This is the brain of the WAF. It runs synchronously to inspect requests before they are forwarded.
- **Rule Modules:** Individual files in `src/engine/rules/` that export a `check()` function (e.g., `sqli.js`, `xss.js`). They mostly use highly optimized regular expressions.
- **Inspector (`inspector.js`):** Coordinates the execution of rules. It checks the IP against the blocklist, applies rate limiting, checks custom rules, and finally runs the core attack detection modules.
- **Performance:** To avoid disk I/O blocking the proxy, the inspector caches IP lists, rate limits, and custom rules in memory.

### 3. The Management API (`src/api/`)
An Express.js server that runs on a separate, administrative port (default 9443).
- It provides a RESTful API for managing the WAF.
- All endpoints under `/api/v1/` (except login) require a JWT token for authentication.
- It also serves the static files for the frontend dashboard.

### 4. The Database (`src/db/`)
We use `better-sqlite3`, a fast, synchronous SQLite driver for Node.js.
- **Why synchronous?** SQLite is incredibly fast for small to medium workloads. Because Node.js is single-threaded, the overhead of context-switching for async SQLite calls is actually slower than just executing them synchronously.
- **Schema:** Stores sites, custom rules, attack logs, certificates, and IP lists.
- **Migrations:** Handled automatically on startup via `src/db/migrations.js`.

## Traffic Flow

1. Client sends HTTP request ➡️ SuspectingWAF Proxy (Port 80/443)
2. Proxy identifies target Site
3. Proxy calls `inspector.inspect(req)`
4. Inspector checks:
   - Is IP on Blocklist?
   - Is IP Rate Limited?
   - Does a Custom Rule block it?
   - Do Core Rules detect an attack (SQLi, XSS, etc.)?
5. If **Blocked**: Log to DB, return 403 to Client.
6. If **Allowed**: Proxy forwards request to Upstream Server.
7. Upstream Server responds ➡️ Proxy ➡️ Client.
