# SuspectingWAF — Self-Hosted Web Application Firewall

A self-hosted WAF (Web Application Firewall) / reverse proxy to protect your web apps from attacks and exploits. Inspired by SafeLine WAF architecture but built from scratch with our own detection engine and management console.

## Research Summary — How SafeLine Works

SafeLine's architecture has 4 main containers orchestrated via Docker Compose:

| Component | Role | Tech |
|---|---|---|
| **Tengine** | Reverse proxy (Nginx fork), intercepts all traffic | C/Nginx |
| **Detector** | Semantic analysis engine, inspects HTTP payloads | C++/Lua |
| **MGT** | Management API + Web Dashboard | Go + PostgreSQL |
| **Chaos** | Bot challenge / CAPTCHA / waiting room | Go |

Key takeaways for our build:
- Reverse proxy sits in front of protected apps, inspects every request
- Detection uses pattern matching + structural parsing (not just regex)
- Dashboard shows real-time stats, attack logs, site management, rules
- Docker Compose for deployment, `.env` for config

---

## What We're Building

**SuspectingWAF** — same concept, our own implementation. Not a fork, not a clone. We write everything ourselves.

### Tech Stack

| Layer | Technology | Why |
|---|---|---|
| **Reverse Proxy + Detection** | Node.js (`http-proxy`) | Fast enough for a self-hosted WAF, easy to extend |
| **Management API** | Node.js + Express | REST API for dashboard, config, logs |
| **Database** | SQLite (via `better-sqlite3`) | Zero-config, file-based, no Postgres container needed |
| **Frontend Dashboard** | Vanilla HTML + CSS + JS | No frameworks, no build step, human-crafted |
| **Deployment** | Docker + Docker Compose | Single command setup |
| **Docs** | Markdown files in `/docs` | GitHub-style documentation |

---

## Proposed Changes

### Repository Structure

The project root at `/home/WAF-Suspecting` will look like a proper open-source GitHub repo:

```
WAF-Suspecting/
├── README.md                    # Main project README (GitHub landing page)
├── LICENSE                      # MIT License
├── CHANGELOG.md                 # Version history
├── CONTRIBUTING.md              # Contribution guidelines
├── SECURITY.md                  # Security policy
├── .gitignore
├── .env.example                 # Example environment config
├── docker-compose.yml           # Production deployment
├── Dockerfile                   # Container build
├── package.json                 # Node.js project manifest
│
├── docs/                        # Full documentation
│   ├── README.md                # Docs index
│   ├── getting-started.md       # Installation & quickstart
│   ├── configuration.md         # Config reference
│   ├── architecture.md          # System architecture
│   ├── detection-engine.md      # How the WAF engine works
│   ├── api-reference.md         # REST API docs
│   ├── deployment.md            # Production deployment guide
│   ├── troubleshooting.md       # Common issues & fixes
│   └── screenshots/             # Dashboard screenshots
│
├── src/                         # Application source
│   ├── index.js                 # Entry point — starts proxy + API
│   │
│   ├── proxy/                   # Reverse proxy layer
│   │   ├── server.js            # HTTP proxy server
│   │   ├── handler.js           # Request interception & forwarding
│   │   └── ssl.js               # SSL/TLS termination helpers
│   │
│   ├── engine/                  # Detection engine
│   │   ├── inspector.js         # Main inspection pipeline
│   │   ├── rules/               # Detection rule modules
│   │   │   ├── sqli.js          # SQL injection detection
│   │   │   ├── xss.js           # Cross-site scripting detection
│   │   │   ├── cmdi.js          # OS command injection detection
│   │   │   ├── traversal.js     # Path traversal detection
│   │   │   ├── rce.js           # Remote code execution patterns
│   │   │   ├── ssrf.js          # Server-side request forgery
│   │   │   ├── xxe.js           # XML external entity
│   │   │   └── crlf.js          # CRLF injection
│   │   ├── ratelimit.js         # Rate limiting (per-IP, per-route)
│   │   └── botdetect.js         # Basic bot fingerprinting
│   │
│   ├── api/                     # Management REST API
│   │   ├── server.js            # Express app setup
│   │   ├── middleware/
│   │   │   ├── auth.js          # Token-based auth middleware
│   │   │   └── validate.js      # Input validation
│   │   └── routes/
│   │       ├── auth.js          # Login, token refresh
│   │       ├── sites.js         # CRUD for protected sites
│   │       ├── rules.js         # Custom rule management
│   │       ├── logs.js          # Attack log queries
│   │       ├── stats.js         # Dashboard statistics
│   │       ├── iplist.js        # Blocklist / allowlist
│   │       ├── certs.js         # SSL certificate management
│   │       └── settings.js      # Global WAF settings
│   │
│   ├── db/                      # Database layer
│   │   ├── connection.js        # SQLite connection setup
│   │   ├── migrations.js        # Schema migrations (run on boot)
│   │   └── queries.js           # Prepared SQL queries
│   │
│   └── utils/                   # Shared utilities
│       ├── logger.js            # Structured logging (to file + stdout)
│       ├── config.js            # Config loader (.env + defaults)
│       ├── crypto.js            # Password hashing, token generation
│       └── ip.js                # IP parsing, CIDR matching
│
├── dashboard/                   # Frontend (static files)
│   ├── index.html               # SPA shell — dashboard entry
│   ├── login.html               # Login page
│   ├── css/
│   │   ├── reset.css            # CSS reset
│   │   ├── variables.css        # Design tokens (colors, spacing)
│   │   ├── layout.css           # Grid, sidebar, nav
│   │   ├── components.css       # Cards, tables, badges, modals
│   │   ├── forms.css            # Inputs, buttons, toggles
│   │   └── charts.css           # Chart/stat styling
│   ├── js/
│   │   ├── app.js               # Router + app init
│   │   ├── api.js               # API client (fetch wrapper)
│   │   ├── auth.js              # Auth state, login/logout
│   │   ├── pages/
│   │   │   ├── dashboard.js     # Overview stats page
│   │   │   ├── sites.js         # Site management page
│   │   │   ├── logs.js          # Attack logs page
│   │   │   ├── rules.js         # Custom rules page
│   │   │   ├── iplist.js        # IP blocklist/allowlist page
│   │   │   ├── certs.js         # SSL certificates page
│   │   │   ├── ratelimit.js     # Rate limiting config page
│   │   │   └── settings.js      # System settings page
│   │   ├── components/
│   │   │   ├── sidebar.js       # Sidebar navigation
│   │   │   ├── header.js        # Top bar (user, notifications)
│   │   │   ├── modal.js         # Modal dialog component
│   │   │   ├── table.js         # Data table component
│   │   │   ├── toast.js         # Toast notifications
│   │   │   └── chart.js         # Simple chart renderer (canvas)
│   │   └── utils/
│   │       ├── dom.js           # DOM helpers
│   │       ├── format.js        # Date, number formatting
│   │       └── validate.js      # Client-side validation
│   └── assets/
│       ├── logo.svg             # SuspectingWAF logo
│       └── favicon.ico          # Browser favicon
│
├── scripts/                     # Utility scripts
│   ├── install.sh               # One-line installer
│   ├── setup.sh                 # First-time setup
│   └── resetadmin.sh            # Reset admin password
│
└── tests/                       # Test suite
    ├── engine/
    │   ├── sqli.test.js         # SQLi detection tests
    │   ├── xss.test.js          # XSS detection tests
    │   └── traversal.test.js    # Path traversal tests
    └── api/
        ├── auth.test.js         # Auth endpoint tests
        └── sites.test.js        # Site CRUD tests
```

---

### Component 1: Detection Engine

The heart of the WAF. Each rule module exports a `check(req)` function that returns `{ blocked: bool, rule: string, detail: string }`.

#### [NEW] [inspector.js](file:///home/WAF-Suspecting/src/engine/inspector.js)
- Pipeline that runs every incoming request through all enabled rule modules
- Collects results, logs blocked requests to DB
- Returns pass/block decision to the proxy handler

#### [NEW] [sqli.js](file:///home/WAF-Suspecting/src/engine/rules/sqli.js)
- Multi-layered SQL injection detection
- Pattern matching for common payloads (`UNION SELECT`, `OR 1=1`, `DROP TABLE`, etc.)
- Structural analysis: detects unbalanced quotes, comment sequences (`--`, `/*`)
- Checks URL params, POST body, cookies, headers

#### [NEW] [xss.js](file:///home/WAF-Suspecting/src/engine/rules/xss.js)
- Detects `<script>`, event handlers (`onerror=`, `onload=`), `javascript:` URIs
- Handles encoded variants (hex, unicode, HTML entities)
- Checks for DOM manipulation attempts

#### [NEW] [cmdi.js](file:///home/WAF-Suspecting/src/engine/rules/cmdi.js)
- OS command injection patterns (`;`, `|`, `&&`, `` ` ``, `$()`)
- Known dangerous commands (`/bin/sh`, `cmd.exe`, `wget`, `curl`, `nc`)

#### [NEW] [traversal.js](file:///home/WAF-Suspecting/src/engine/rules/traversal.js)
- Path traversal sequences (`../`, `..\\`, `%2e%2e`)
- Sensitive file access (`/etc/passwd`, `/etc/shadow`, `web.config`)

#### [NEW] [rce.js](file:///home/WAF-Suspecting/src/engine/rules/rce.js), [ssrf.js](file:///home/WAF-Suspecting/src/engine/rules/ssrf.js), [xxe.js](file:///home/WAF-Suspecting/src/engine/rules/xxe.js), [crlf.js](file:///home/WAF-Suspecting/src/engine/rules/crlf.js)
- Each module handles its respective attack vector
- SSRF checks for internal IP ranges (127.0.0.1, 10.x, 169.254.x, etc.)
- XXE checks for `<!DOCTYPE` with `ENTITY` declarations
- CRLF checks for `\r\n` injection in headers

#### [NEW] [ratelimit.js](file:///home/WAF-Suspecting/src/engine/ratelimit.js)
- In-memory sliding window counter per IP
- Configurable thresholds (requests per second/minute)
- Auto-ban for sustained abuse

#### [NEW] [botdetect.js](file:///home/WAF-Suspecting/src/engine/botdetect.js)
- User-Agent analysis (known bot signatures)
- Request frequency patterns
- Missing headers that real browsers send

---

### Component 2: Reverse Proxy

#### [NEW] [server.js](file:///home/WAF-Suspecting/src/proxy/server.js)
- Creates HTTP/HTTPS server using `http-proxy`
- Routes incoming requests to configured upstream backends
- Integrates with detection engine before forwarding

#### [NEW] [handler.js](file:///home/WAF-Suspecting/src/proxy/handler.js)
- Request interception logic
- Calls inspector pipeline
- If blocked: returns 403 with WAF block page
- If allowed: proxies to upstream
- Logs all requests (with performance metrics)

#### [NEW] [ssl.js](file:///home/WAF-Suspecting/src/proxy/ssl.js)
- SNI-based certificate selection for multi-site HTTPS
- Certificate file management (read from `/data/certs/`)

---

### Component 3: Management API (Express)

#### [NEW] [api/server.js](file:///home/WAF-Suspecting/src/api/server.js)
- Express app with JSON body parsing, CORS, static file serving
- Serves the dashboard from `/dashboard`
- All API routes under `/api/v1`

#### [NEW] API Routes

| Route | Method | Description |
|---|---|---|
| `/api/v1/auth/login` | POST | Admin login, returns JWT |
| `/api/v1/auth/me` | GET | Current user info |
| `/api/v1/stats/overview` | GET | Dashboard stats (requests, blocks, top attacks) |
| `/api/v1/stats/timeseries` | GET | Time-series data for charts |
| `/api/v1/sites` | GET/POST | List/create protected sites |
| `/api/v1/sites/:id` | GET/PUT/DELETE | Get/update/delete a site |
| `/api/v1/logs` | GET | Query attack logs (paginated, filterable) |
| `/api/v1/logs/:id` | GET | Single log entry detail |
| `/api/v1/rules` | GET/POST | Custom rules (allow/block) |
| `/api/v1/rules/:id` | PUT/DELETE | Update/delete rule |
| `/api/v1/iplist` | GET/POST | IP blocklist/allowlist entries |
| `/api/v1/iplist/:id` | DELETE | Remove IP entry |
| `/api/v1/certs` | GET/POST | SSL certificate management |
| `/api/v1/certs/:id` | DELETE | Remove certificate |
| `/api/v1/settings` | GET/PUT | Global WAF settings |
| `/api/v1/ratelimit` | GET/PUT | Rate limit configuration |

---

### Component 4: Database (SQLite)

#### [NEW] [migrations.js](file:///home/WAF-Suspecting/src/db/migrations.js)

Tables:

```sql
-- Admin users
CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Protected sites (upstream backends)
CREATE TABLE sites (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  listen_port INTEGER NOT NULL,
  upstream_url TEXT NOT NULL,
  ssl_enabled INTEGER DEFAULT 0,
  cert_id INTEGER,
  waf_enabled INTEGER DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Attack logs
CREATE TABLE attack_logs (
  id INTEGER PRIMARY KEY,
  site_id INTEGER,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  src_ip TEXT,
  method TEXT,
  url TEXT,
  rule_id TEXT,
  rule_name TEXT,
  severity TEXT,
  payload TEXT,
  action TEXT,
  user_agent TEXT,
  country TEXT
);

-- Custom rules
CREATE TABLE custom_rules (
  id INTEGER PRIMARY KEY,
  name TEXT,
  type TEXT,  -- 'block' or 'allow'
  field TEXT, -- 'ip', 'url', 'header', 'user_agent'
  operator TEXT, -- 'equals', 'contains', 'regex', 'cidr'
  value TEXT,
  enabled INTEGER DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- IP blocklist/allowlist
CREATE TABLE ip_list (
  id INTEGER PRIMARY KEY,
  ip TEXT NOT NULL,
  type TEXT NOT NULL, -- 'block' or 'allow'
  reason TEXT,
  expires_at DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- SSL certificates
CREATE TABLE certificates (
  id INTEGER PRIMARY KEY,
  domain TEXT NOT NULL,
  cert_path TEXT,
  key_path TEXT,
  expires_at DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Rate limit config
CREATE TABLE rate_limits (
  id INTEGER PRIMARY KEY,
  site_id INTEGER,
  requests_per_second INTEGER DEFAULT 100,
  burst INTEGER DEFAULT 200,
  ban_duration INTEGER DEFAULT 300,
  enabled INTEGER DEFAULT 1
);

-- Request stats (aggregated hourly)
CREATE TABLE request_stats (
  id INTEGER PRIMARY KEY,
  site_id INTEGER,
  hour DATETIME,
  total_requests INTEGER DEFAULT 0,
  blocked_requests INTEGER DEFAULT 0,
  unique_ips INTEGER DEFAULT 0
);
```

---

### Component 5: Frontend Dashboard

Dark-themed, professional management console. No frameworks, no build tools, just clean HTML/CSS/JS.

#### Dashboard Pages

1. **Overview** — Real-time stats cards (total requests, blocked, active sites, unique IPs), time-series chart, attack type breakdown, recent attack log
2. **Sites** — Table of protected sites with status toggles, add/edit/delete modal
3. **Attack Logs** — Filterable/searchable table with severity badges, expandable detail rows
4. **Custom Rules** — Rule list with enable/disable toggles, create rule modal
5. **IP Lists** — Blocklist and allowlist tabs, add IP/CIDR with expiration
6. **Certificates** — Upload SSL certs, view expiry status
7. **Rate Limiting** — Per-site rate limit config with sliders/inputs
8. **Settings** — WAF mode (block/monitor/off), admin password change, API token management

#### Design System

- **Colors**: Dark background (`#0d1117`), card surfaces (`#161b22`), accent green (`#2ea043`), warning amber (`#d29922`), danger red (`#da3633`), info blue (`#388bfd`)
- **Typography**: System font stack (`-apple-system, BlinkMacSystemFont, 'Segoe UI', ...`)
- **Components**: Cards with subtle borders, data tables with hover rows, toggle switches, status badges, modal dialogs with backdrop blur
- **Charts**: Canvas-based line charts and bar charts (no Chart.js dependency — hand-rolled)

---

### Component 6: Documentation

All docs written in natural, human style — no AI-sounding language. Typos left intentionally in casual sections, comments have personality.

#### [NEW] [README.md](file:///home/WAF-Suspecting/README.md)
- Project logo + title
- One-line description
- Feature list with emoji markers
- Screenshots section
- Quick install command
- Links to docs
- License badge
- "Why SuspectingWAF?" section with personality

#### [NEW] [docs/getting-started.md](file:///home/WAF-Suspecting/docs/getting-started.md)
- System requirements
- Docker install (one command)
- Manual install (Node.js 18+)
- First login, changing default password
- Adding your first site

#### [NEW] [docs/architecture.md](file:///home/WAF-Suspecting/docs/architecture.md)
- ASCII diagram of traffic flow
- Component breakdown
- How the proxy and engine work together

#### [NEW] [docs/detection-engine.md](file:///home/WAF-Suspecting/docs/detection-engine.md)
- How each rule module works
- Detection methodology
- False positive tuning
- Custom rule examples

#### [NEW] [docs/api-reference.md](file:///home/WAF-Suspecting/docs/api-reference.md)
- Full REST API documentation
- Request/response examples
- Authentication flow

---

### Component 7: Docker & Deployment

#### [NEW] [Dockerfile](file:///home/WAF-Suspecting/Dockerfile)
- Node.js 20 Alpine base
- Copy source + dashboard
- Expose ports 80 (proxy), 443 (proxy SSL), 9443 (management)
- Health check endpoint

#### [NEW] [docker-compose.yml](file:///home/WAF-Suspecting/docker-compose.yml)
- Single service (SuspectingWAF is monolithic, not multi-container)
- Volume mounts for `/data` (db, certs, logs)
- Environment variables from `.env`

#### [NEW] [scripts/install.sh](file:///home/WAF-Suspecting/scripts/install.sh)
- One-line curl installer
- Checks Docker, pulls image, creates dirs, generates `.env`

---

## Open Questions

> [!IMPORTANT]
> **Scope of the proxy**: Should the reverse proxy actually function and forward traffic to real backends, or is this a demo/showcase with simulated data on the dashboard? This affects complexity significantly.

> [!IMPORTANT]
> **Authentication method**: The plan uses JWT tokens for the management API. Are you okay with that or do you prefer session-based auth?

> [!IMPORTANT]
> **Database**: I'm using SQLite for zero-dependency setup. If you want PostgreSQL like SafeLine, the Docker Compose would need a second container. Which do you prefer?

---

## Verification Plan

### Automated Tests
```bash
# Run detection engine tests
npm test

# Test specific modules
npm test -- --grep "sqli"
npm test -- --grep "xss"
```

### Manual Verification
- Start the WAF with `npm start` or `docker compose up`
- Access dashboard at `https://localhost:9443`
- Add a test site pointing to any HTTP server
- Send malicious requests and verify they're blocked
- Check attack logs appear in dashboard
- Test rate limiting by sending rapid requests
- Verify IP blocklist blocks specified IPs
