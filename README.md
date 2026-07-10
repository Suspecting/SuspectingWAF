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
  <a href="#-quick-start">Installation</a>
</p>

---

## 📖 Introduction

**SuspectingWAF** is a high-performance, locally hosted Web Application Firewall (WAF) developed from the ground up to protect vulnerable backend web applications from sophisticated cyber attacks. Designed to sit directly in front of target servers (acting as a reverse proxy), it actively intercepts, normalizes, and inspects all inbound HTTP/HTTPS traffic before it reaches the application layer.

This project was built from scratch as part of an intensive defensive security internship project for **SSRL.in** to demonstrate a deep, foundational understanding of the OWASP Top 10 vulnerabilities, web proxy architectures, and threat mitigation strategies.

---

## 👨‍💻 About the Developer

- **Name**: Prakhar Shakya
- **Profile**: B.Tech CSE (Cyber Security) Student, 3rd Year
- **GitHub**: [@Suspecting](https://github.com/Suspecting)
- **Portfolio**: [sussy-port.netlify.app](https://sussy-port.netlify.app/)
- **Specializations**: Defensive Security, Malware Analysis, Bug Bounty Hunting, Threat Intelligence, and Secure Software Development.

---

## ⚙️ Architecture & Core Mechanics

SuspectingWAF is designed for **zero-latency overhead**. It achieves this by bypassing heavy database transactions during the request lifecycle. 

1. **In-Memory Caching Engine**: The WAF caches IP blocklists, custom rules, and rate-limit configurations in RAM. A background thread synchronizes this cache with the local SQLite database every 30 seconds.
2. **Asynchronous Body Buffering**: By listening to Node.js `data` streams, the proxy securely buffers `POST`, `PUT`, and `PATCH` payloads. It implements strict Denial of Service (DoS) constraints (1MB max body size) to prevent Buffer Overflow attacks during inspection.
3. **Custom URL Normalization**: Built-in parsers often drop malformed query parameters, allowing attackers to bypass security checks via HTTP Parameter Pollution. SuspectingWAF utilizes a custom, strict URL parser to ensure the inspection engine sees exactly what the backend server will execute.

---

## ✨ Key Features

- **Built-in Detection Engine**: Protects against SQL Injection, XSS, Command Injection, Path Traversal, SSRF, XXE, CSRF, and Malicious File Uploads.
- **High Performance**: Built on Node.js using asynchronous I/O and caching to minimize latency impact.
- **Zero-Config Database**: Uses SQLite for fast, localized storage. No need to stand up MySQL or Redis.
- **Dynamic Rate Limiting**: Per-IP sliding window rate limiting that automatically bans abusive IPs without relying on external memory stores.
- 🕵️ **Advanced Bot Detection**: Identifies automated tools (curl, sqlmap, nmap, nikto, dirb)
- 🔐 **SPA & NextAuth Compatibility**: Deep JSON and Form-Data parsing that intelligently whitelists standard authentication flows (e.g., NextAuth `callbackUrl`) to prevent false-positive SSRF/RFI blocks in modern frontend applications.
- 🏗 **No-Break Cookie Policies**: Smart cookie handling and CSP headers that protect upstream apps without breaking frontend UI functionality.
- **Automated Hardening**: Acts as a "Virtual Patch" by automatically rewriting insecure cookies (`HttpOnly`, `SameSite`) and injecting critical Security Headers (`CSP`, `X-Frame-Options`) into upstream responses.
- **Management Dashboard**: A beautiful, clean UI to view attack logs, manage protected sites, and configure rules.
- **Customized Block Pages**: Features a professional yet highly customized One Piece Straw Hat Pirate themed SVG block page when threats are neutralized.

---

## 🛡️ Vulnerability Mitigation Deep-Dive

### SQL Injection (SQLi)
The WAF utilizes a dual-engine approach to stop database exploitation:
1. **Regex Heuristics**: Scans for known malicious SQL structures (e.g., `UNION SELECT`, `INTO OUTFILE`) and authentication bypass tautologies (`' OR '1'='1`).
2. **Structural Anomaly Detection**: Tracks unbalanced quote injections mixed with SQL keywords, effectively blocking heavily obfuscated payloads that attempt to bypass regex signatures.

### Cross-Site Scripting (XSS)
Prevents both Reflected and Stored XSS by neutralizing malicious `<script>` tags, inline event handlers (like `onerror=alert(1)`), and `javascript:` URIs across all HTTP request vectors (Headers, Body, Cookies, URL).

### Malicious File Uploads
Instead of trusting the easily spoofed `Content-Type` header, SuspectingWAF performs deep semantic parsing of `multipart/form-data` boundaries to extract the true `filename=` attribute. It instantly drops connections attempting to upload webshells (`.php`, `.sh`, `.exe`).

### Cross-Site Request Forgery (CSRF)
Enforces strict state-changing validation. On `POST`, `PUT`, `DELETE`, and `PATCH` methods, the WAF validates that the `Origin` or `Referer` headers exactly match the destination `Host`. If a mismatch occurs, the forged request is terminated.

### Command Injection & Path Traversal
Monitors for shell metacharacters (`|`, `;`, `&&`) combined with system binaries (`netcat`, `curl`, `bash -i`), and detects directory climbing (`../`) or null-byte injections intended to escape the web-root.

---

## 🚀 Quick Start & Installation

### Prerequisites
- Node.js 18.x or higher
- npm

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

5. **Access the Dashboard**: 
   Open `http://localhost:9444/login.html` in your browser.
   - **Default Username:** `admin`
   - **Default Password:** `suspecting123` *(Change this immediately in Settings!)*

## 🌐 Connecting Your Website to the WAF

Once the WAF is running, you need to tell it which backend website it should protect. SuspectingWAF acts as a reverse proxy, meaning users will visit the WAF, and the WAF will securely forward them to your actual website.

### Example: Protecting Your Live Website
1. **Host your backend application:** Ensure your actual web application (Node, Python, PHP, etc.) is running on a specific port (e.g., `http://localhost:3000`) and is NOT exposed directly to the internet.
2. **Open the WAF Dashboard:** Navigate to `http://localhost:9444/dashboard/sites.html`.
3. **Add a New Site:**
   - Click **Add Site**.
   - **Upstream URL:** Enter the address of your hidden backend application (e.g., `http://localhost:3000`).
   - **Server Names:** Enter your actual public domain name (e.g., `www.myawesomeapp.com`). Leave it blank if you want it to catch all incoming traffic.
   - Set the Status to **Active** and WAF to **Enabled**.
   - Click **Save**.
4. **Route Public Traffic:** Configure your system (like Nginx, iptables, or your cloud load balancer) to route all incoming port 80/443 traffic to the WAF's proxy port (**`http://localhost:8080`**). The WAF will act as the public-facing gateway, intercepting attacks and seamlessly forwarding clean traffic to your hidden backend!


---

## 🤝 Contributing & License

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 
**Copyright (c) 2026 Prakhar Shakya.**
