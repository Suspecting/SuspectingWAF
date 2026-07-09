<div align="center">
  <img src="dashboard/assets/favicon.svg" alt="SuspectingWAF Logo" width="120" height="120" />
  <h1>🛡️ SuspectingWAF</h1>
  <p>A fast, self-hosted Web Application Firewall built in Node.js.</p>
  <p><b>Developed by Prakhar Shakya</b></p>
</div>

---

**SuspectingWAF** is a modern reverse proxy and Web Application Firewall (WAF) developed by **Prakhar Shakya**, an aspiring Cybersecurity Engineer specializing in Web Application Security, Malware Analysis, and Defensive Security. 

This project was built from scratch as part of a mission to develop production-quality defensive security tools and deeply understand the mechanics of web-based attacks (and how to stop them).

## 👨‍💻 About the Developer

- **Name**: Prakhar Shakya
- **Profile**: B.Tech CSE (Cyber Security) Student, 3rd Year
- **GitHub**: [@Suspecting](https://github.com/Suspecting)
- **Portfolio**: [sussy-port.netlify.app](https://sussy-port.netlify.app/)
- **Interests**: Defensive Security, Malware Analysis, Bug Bounty, Threat Hunting.

---

## ✨ Features

- **Built-in Detection Engine**: Protects against SQL Injection, XSS, Command Injection, Path Traversal, SSRF, XXE, and more right out of the box.
- **High Performance**: Built on Node.js using asynchronous I/O and caching to minimize latency impact.
- **Zero-Config Database**: Uses SQLite for fast, localized storage. No need to stand up MySQL or Redis.
- **Dynamic Rate Limiting**: Per-IP sliding window rate limiting that automatically bans abusive IPs.
- **Bot Detection**: Blocks known bad crawlers and scanners (Nuclei, SQLmap, Nikto, etc.).
- **SSL Termination**: Manage and terminate SSL/TLS certificates directly in the proxy.
- **Management Dashboard**: A beautiful, clean UI to view attack logs, manage sites, and configure rules.
- **Custom Rules Engine**: Create your own allow/block rules based on IP, User-Agent, URLs, or Headers.

## 🚀 Quick Start

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

## 📚 Documentation

For detailed information on how SuspectingWAF works, see the `/docs` directory:
- [Architecture Overview](docs/architecture.md)
- [Rule Engine & Detection](docs/rules.md)

## 🐳 Docker Deployment

You can easily run SuspectingWAF using Docker:

```bash
docker-compose up -d
```

This will build the image and start the WAF. The SQLite database will be mounted as a volume so your data persists across container restarts.

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. Copyright (c) 2026 Prakhar Shakya.
