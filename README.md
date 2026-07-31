<div align="center">
  <img src="dashboard/assets/strawhat.svg" alt="SuspectingWAF Logo - Straw Hat" width="240" height="240" />
  <h1>🛡️ SuspectingWAF</h1>
  <p><strong>A Next-Generation, Self-Hosted Web Application Firewall & Reverse Proxy built in Node.js.</strong></p>
  <p><b>Developed by Prakhar Shakya for the SSRL.in Internship</b></p>
</div>

---

<p align="center">
  <a href="#-about-the-developer">About</a> •
  <a href="#-architecture--core-mechanics">Architecture</a> •
  <a href="#-key-features">Features</a> •
  <a href="#-vulnerability-mitigation">Mitigation Engine</a> •
  <a href="#-quick-start--installation">Installation</a> •
  <a href="#-usage--stress-testing">Usage & Testing</a>
</p>

---

## 📖 Introduction

**SuspectingWAF** is a high-performance, locally hosted Web Application Firewall (WAF) developed from the ground up to protect vulnerable backend web applications from sophisticated cyber attacks. Designed to sit directly in front of target servers (acting as a reverse proxy), it actively intercepts, normalizes, and inspects all inbound HTTP**S** traffic before it reaches the application layer.

This project was built from scratch as part of an intensive defensive security internship project for **SSRL.in** to demonstrate a deep, foundational understanding of the OWASP Top 10 vulnerabilities, web proxy architectures, and threat mitigation strategies.

### ⚡ Benchmark Results

> Tested using `wrk` with 10 threads, 100 concurrent connections over 30 seconds:

| Metric | Result |
|---|---|
| **Requests per second** | **4,823 RPS** |
| **Total requests handled** | 144,815 |
| **Average latency** | 20.22ms |
| **Max latency** | 63.80ms |
| **Failed requests** | 0 |
| **TLS Protocol** | TLSv1.3 |

---

## 👨‍💻 About the Developer

- **Name**: Prakhar Shakya
- **Profile**: B.Tech CSE (Cyber Security) Student, 3rd Year
- **GitHub**: [@Suspecting](https://github.com/Suspecting)
- **LinkedIn**: [linkedin.com/in/shakyaprakhar](https://www.linkedin.com/in/shakyaprakhar/)
- **Portfolio**: [sussy-port.netlify.app](https://sussy-port.netlify.app/)
- **Specializations**: Defensive Security, Malware Analysis, Bug Bounty Hunting, Threat Intelligence, and Secure Software Development.

---

## ⚙️ Architecture & Core Mechanics

SuspectingWAF is designed for **zero-latency overhead**. It achieves this by bypassing heavy database transactions during the request lifecycle.

1. **In-Memory Caching Engine**: The WAF caches IP blocklists, site configurations, WAF mode, rate-limit configs, and custom rules in RAM. A background thread synchronizes with the local SQLite database every 10 seconds.
2. **TLS Termination**: The WAF terminates SSL/TLS using SNI (Server Name Indication), enabling it to serve multiple HTTPS sites on a single IP. Self-signed certificates are auto-generated on first boot using `openssl`.
3. **HTTP → HTTPS Redirect**: All plaintext HTTP traffic on port `8080` is automatically redirected to HTTPS on port `8443` with a `301 Moved Permanently`.
4. **Asynchronous Body Buffering**: By listening to Node.js `data` streams, the proxy securely buffers `POST`, `PUT`, and `PATCH` payloads. Implements strict DoS constraints (1MB max body size) to prevent Buffer Overflow attacks.
5. **Custom URL Normalization**: Built-in parsers often drop malformed query parameters, allowing HTTP Parameter Pollution bypasses. SuspectingWAF uses a custom, strict URL parser to ensure the inspection engine sees exactly what the backend will execute.
6. **Keep-Alive Connections**: Both HTTP and HTTPS servers are configured with `keepAliveTimeout` to reuse TCP connections, dramatically increasing throughput under sustained load.

---

## ✨ Key Features

- 🔐 **TLS/HTTPS Termination**: Full SSL/TLS support on port `8443` with automatic self-signed cert generation and SNI-based multi-site cert routing.
- 🛡️ **Built-in Detection Engine**: Protects against SQL Injection, XSS, Command Injection, Path Traversal, SSRF, XXE, CSRF, and Malicious File Uploads.
- ⚡ **High Performance**: 4,823 RPS with 0 failed connections under sustained stress testing via `wrk`.
- 💾 **Zero-Config Database**: Uses SQLite for fast, localized storage. No need to stand up MySQL or Redis.
- 📊 **Dynamic Rate Limiting**: Per-IP sliding window rate limiting that automatically bans abusive IPs.
- 🕵️ **Advanced Bot Detection**: Identifies automated tools (curl, sqlmap, nmap, nikto, dirb).
- 🔁 **SPA & NextAuth Compatibility**: Intelligently whitelists standard authentication flows to prevent false-positive SSRF/RFI blocks in modern frontend applications.
- 🍪 **No-Break Cookie Policies**: Smart cookie handling and CSP headers that protect without breaking frontend UI functionality.
- 📋 **Management Dashboard**: A clean UI to view real-time attack logs, manage protected sites, configure custom rules, and manage IP blocklists.
- 💀 **Custom Block Page**: Professional One Piece Straw Hat Pirate themed SVG block page served when threats are neutralized.

---

## 🛡️ Vulnerability Mitigation Deep-Dive

### SQL Injection (SQLi)
The WAF utilizes a dual-engine approach to stop database exploitation:
1. **Regex Heuristics**: Scans for known malicious SQL structures (e.g., `UNION SELECT`, `INTO OUTFILE`) and authentication bypass tautologies (`' OR '1'='1`).
2. **Evasion Prevention**: Deep payload normalization (URL decode → HTML entity decode → Unicode normalize) strips all obfuscation layers before inspection runs.

### Cross-Site Scripting (XSS)
Prevents both Reflected and Stored XSS by neutralizing malicious `<script>` tags, inline event handlers (like `onerror=alert(1)`), and `javascript:` URIs across all HTTP vectors (Headers, Body, Cookies, URL).

### Malicious File Uploads
Instead of trusting the easily spoofed `Content-Type` header, SuspectingWAF performs deep semantic parsing of `multipart/form-data` boundaries to extract the true `filename=` attribute. Instantly drops connections attempting to upload webshells (`.php`, `.sh`, `.exe`).

### Cross-Site Request Forgery (CSRF)
Enforces strict state-changing validation. On `POST`, `PUT`, `DELETE`, and `PATCH` methods, the WAF validates that the `Origin` or `Referer` headers exactly match the destination `Host`. Forged requests are terminated immediately.

### Command Injection & Path Traversal
Monitors for shell metacharacters (`|`, `;`, `&&`) combined with system binaries (`netcat`, `curl`, `bash -i`), and detects directory climbing (`../`) or null-byte injections intended to escape the web-root.

---

## 🚀 Quick Start & Installation

### Prerequisites
- Node.js 18.x or higher
- npm
- `openssl` (pre-installed on most Linux/macOS systems)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Suspecting/SuspectingWAF.git
   cd SuspectingWAF
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Setup your environment:
   ```bash
   cp .env.example .env
   ```
   *Edit `.env` to change default ports or JWT secrets if needed.*

4. Start the WAF:
   ```bash
   npm start
   ```

On first boot, the WAF will **automatically generate a self-signed TLS certificate** and save it to `data/certs/`. Your browser will show a security warning — click **Advanced → Proceed to localhost** to continue. This is expected for self-signed certificates.

5. **Access the Dashboard:**
   Open `http://localhost:9444/login.html` in your browser.
   - **Default Username:** `admin`
   - **Default Password:** `suspecting123` *(Change this immediately in Settings!)*

### Default Ports

| Service | Port | Protocol |
|---|---|---|
| WAF Proxy (HTTPS) | `8443` | HTTPS (TLSv1.3) |
| WAF Proxy (HTTP redirect) | `8080` | HTTP → 301 HTTPS |
| Management Dashboard | `9444` | HTTP |

---

## 🌐 Connecting Your Website to the WAF

Once the WAF is running, you need to tell it which backend website it should protect. SuspectingWAF acts as a reverse proxy — users visit the WAF, and the WAF securely forwards them to your actual website.

### Example: Protecting DVWA (for lab testing)

1. Start DVWA: `dvwa-start` (Kali Linux) — it runs on `http://127.0.0.1:42001`
2. Open the WAF Dashboard → **Sites** → **Add Site**.
   - **Upstream URL:** `http://127.0.0.1:42001`
   - **Server Names:** leave blank (catches all traffic)
   - Set Status: **Active**, WAF: **Enabled**
3. Visit `https://localhost:8443` — DVWA will load through the WAF over HTTPS.
4. Try a SQL injection in the URL: `https://localhost:8443/?id=' OR 1=1--` → You will see the block page.

### Example: Protecting a Live Application

1. Run your backend on a local port (e.g., `http://localhost:3000`) and do NOT expose it directly to the internet.
2. Open the WAF Dashboard → **Sites** → **Add Site**.
   - **Upstream URL:** `http://localhost:3000`
   - **Server Names:** `www.yourdomain.com`
3. Point your DNS / load balancer to the WAF's HTTPS port `8443`. The WAF will terminate TLS, inspect traffic, and forward clean requests to your backend.

---

## 🔥 Usage & Stress Testing

### Running in Development Mode (auto-restart on code changes)
```bash
npm run dev
```

### Stress Testing with Apache Bench

```bash
# Legitimate traffic test (1000 requests, 50 concurrent)
ab -n 1000 -c 50 -k https://localhost:8443/

# SQL Injection attack simulation (should all return 403)
ab -n 500 -c 20 -k "https://localhost:8443/?id=' OR 1=1--"
```

### Stress Testing with wrk (sustained load)

```bash
# 30-second sustained load test, 10 threads, 100 concurrent connections
wrk -t10 -c100 -d30s https://localhost:8443/
```

**Expected results:** ~4,800+ requests/second, 0 failed connections, 20ms average latency.

### Live Attack Monitoring

Watch the WAF block attacks in real-time:
```bash
# In one terminal, fire attack traffic
for i in $(seq 1 100); do
  curl -sk "https://localhost:8443/?id=' OR 1=1--" -o /dev/null -w "%{http_code}\n"
done

# In another terminal, watch the WAF logs
npm start 2>&1 | grep "blocked"
```

---

## 🤝 Contributing & License

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
**Copyright (c) 2026 Prakhar Shakya.**
