# Rule Engine & Detection

The SuspectingWAF detection engine is designed to be fast, accurate, and easily extensible. It utilizes a combination of pattern matching, thresholding, and reputation checking.

## How Detection Works

When a request arrives, the `inspector` extracts the relevant parts of the HTTP request to inspect:
- URL Path and Query string
- HTTP Headers (especially `User-Agent`, `Referer`, and custom headers)
- Request Body (parsed if it's JSON or URL-encoded form data)

It then passes these extracted strings through a series of rule modules. If any module returns a match, the request is immediately blocked, and the loop terminates (fail-fast).

## Built-in Rule Modules

The core rules are located in `src/engine/rules/` and cover the following attack vectors:

| Module | Description | Example Payloads Blocked |
|--------|-------------|--------------------------|
| **SQLi** | SQL Injection | `' OR 1=1 --`, `UNION SELECT` |
| **XSS** | Cross-Site Scripting | `<script>alert(1)</script>`, `javascript:prompt()` |
| **CmdI** | OS Command Injection | `; cat /etc/passwd`, `| curl http://evil.com` |
| **PathTra** | Path Traversal | `../../../../etc/shadow`, `..%2f..%2f` |
| **RCE** | Remote Code Execution | `eval(`, `Runtime.getRuntime().exec` |
| **SSRF** | Server-Side Request Forgery| `file:///`, `dict://`, metadata endpoints (169.254.169.254) |
| **XXE** | XML External Entity | `<!ENTITY xxe SYSTEM "file:///">` |
| **CRLF** | HTTP Response Splitting | `%0d%0aSet-Cookie:` |

## False Positives

WAFs inevitably encounter false positives. If a legitimate request is blocked:
1. Check the **Attack Logs** in the dashboard to see which rule triggered it and what the payload was.
2. If it's a specific endpoint (e.g., an admin saving a blog post with HTML in it), you can create a **Custom Rule** in the dashboard to "Allow" traffic to that specific URL, bypassing the core WAF inspection.

## Adding New Core Rules

If you want to add a new core detection module (e.g., for a new zero-day vulnerability):
1. Create a new file in `src/engine/rules/`, e.g., `myrule.js`.
2. Export a function `check(reqStr, req)` that returns a matched payload or `false`.
3. Require and add it to the `rules` array in `src/engine/inspector.js`.
