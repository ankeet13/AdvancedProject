from crawler.selenium_crawler import SeleniumCrawler
import requests
import json
import os

SECURITY_HEADERS = {
    "Content-Security-Policy":      "High",
    "Strict-Transport-Security":    "High",
    "X-Frame-Options":              "Medium",
    "X-Content-Type-Options":       "Medium",
    "Referrer-Policy":              "Low",
    "Permissions-Policy":           "Low",
}

IDENTITY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]

CORS_ORIGINS = ["https://evil.com", "https://attacker.com", "null"]

SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.env.production",
    "/config.php", "/config.json", "/config.yaml",
    "/web.config", "/appsettings.json", "/wp-config.php",
    "/.git/config", "/.git/HEAD", "/.gitignore",
    "/phpinfo.php", "/server-status",
    "/actuator", "/actuator/env", "/metrics",
    "/swagger.json", "/openapi.json", "/api-docs",
    "/robots.txt", "/sitemap.xml",
    "/backup.zip", "/db.sql", "/database.sql",
]


def check_security_headers(url):
    findings = []
    try:
        resp = requests.get(url, timeout=10)
        for header, severity in SECURITY_HEADERS.items():
            if header not in resp.headers:
                findings.append({
                    "type":     "Security Misconfiguration",
                    "url":      url,
                    "severity": severity,
                    "detail":   f"Missing security header: {header}",
                })
        for h in IDENTITY_HEADERS:
            if h in resp.headers:
                findings.append({
                    "type":     "Security Misconfiguration",
                    "url":      url,
                    "severity": "Low",
                    "detail":   f"Server identity exposed — {h}: {resp.headers[h]}",
                })
    except Exception as e:
        print(f"[misconfiguration] Header check error: {e}")
    return findings


def check_cors(url):
    for origin in CORS_ORIGINS:
        try:
            resp = requests.get(url, headers={"Origin": origin}, timeout=10)
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            if acao == "*":
                return [{
                    "type":     "Security Misconfiguration",
                    "url":      url,
                    "severity": "High",
                    "detail":   "CORS wildcard (*) — any website can read this API.",
                }]
            elif acao == origin:
                return [{
                    "type":     "Security Misconfiguration",
                    "url":      url,
                    "severity": "High",
                    "detail":   f"CORS reflects malicious origin: {origin}",
                }]
        except Exception as e:
            print(f"[misconfiguration] CORS error: {e}")
    return []


def check_sensitive_files(url):
    findings, base = [], url.rstrip("/")
    for path in SENSITIVE_PATHS:
        try:
            r  = requests.get(base + path, timeout=5)
            ct = r.headers.get("Content-Type", "")
            if r.status_code == 200:
                is_real = (
                    "text/plain"       in ct or
                    "application/json" in ct or
                    "application/xml"  in ct or
                    (len(r.content) < 5000 and "text/html" in ct)
                )
                if is_real:
                    findings.append({
                        "type":     "Security Misconfiguration",
                        "url":      base + path,
                        "severity": "High",
                        "detail":   f"Sensitive file accessible: {path} ({ct})",
                    })
                else:
                    print(f"[misconfiguration] SPA false positive skipped: {path}")
        except Exception:
            pass
    return findings


def scan(url):
    findings = []

    # Selenium crawl
    crawler = SeleniumCrawler(url, max_pages=10)
    crawler.crawl()

    print("[misconfiguration] Checking security headers...")
    findings.extend(check_security_headers(url))

    print("[misconfiguration] Checking CORS...")
    findings.extend(check_cors(url))

    print("[misconfiguration] Checking sensitive files...")
    findings.extend(check_sensitive_files(url))

    print(f"[misconfiguration] Total: {len(findings)} findings")

    # ── Save results for team records ──────────────────
    os.makedirs("results", exist_ok=True)
    with open("results/misconfiguration_results.json", "w") as f:
        json.dump(findings, f, indent=2)
    print(f"[misconfiguration] Results saved to results/misconfiguration_results.json")

    return findings