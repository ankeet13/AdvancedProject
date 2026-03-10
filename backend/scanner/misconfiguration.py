from crawler.selenium_crawler import SeleniumCrawler
import requests

SECURITY_HEADERS = [
    "Content-Security-Policy","Strict-Transport-Security",
    "X-Frame-Options","X-Content-Type-Options",
    "Referrer-Policy","Permissions-Policy",
]

SENSITIVE_PATHS = [
    "/.env","/.env.local","/.env.production",
    "/config.php","/config.json","/config.yaml",
    "/web.config","/appsettings.json","/wp-config.php",
    "/.git/config","/.git/HEAD","/.gitignore",
    "/phpinfo.php","/server-status",
    "/actuator","/actuator/env","/metrics",
    "/swagger.json","/openapi.json","/api-docs",
    "/robots.txt","/sitemap.xml",
    "/backup.zip","/db.sql","/database.sql",
]


def collect_headers(url):
    try:
        resp = requests.get(url, timeout=10)
        return {
            "missing": [h for h in SECURITY_HEADERS if h not in resp.headers],
            "server":  resp.headers.get("Server",""),
            "powered": resp.headers.get("X-Powered-By",""),
        }
    except Exception as e:
        print(f"[misconfiguration] Header error: {e}")
        return {}


def probe_files(base_url):
    found, base = [], base_url.rstrip("/")
    for path in SENSITIVE_PATHS:
        try:
            r = requests.get(base+path, timeout=5)
            if r.status_code not in (404, 410):
                found.append({"path":path,"status":r.status_code,
                              "ct":r.headers.get("Content-Type","?")})
        except Exception:
            pass
    return found


def scan(url):
    findings = []
    crawler = SeleniumCrawler(url, max_pages=10)
    crawl_results = crawler.crawl()

    headers = collect_headers(url)
    for h in headers.get("missing", []):
        findings.append({
            "type": "Security Misconfiguration", "url": url,
            "severity": "Info",
            "detail": f"Missing security header: {h}",
        })

    for f in probe_files(url):
        findings.append({
            "type": "Security Misconfiguration",
            "url": url.rstrip("/")+f["path"],
            "severity": "Info",
            "detail": f"Sensitive path HTTP {f['status']}: {f['path']}",
        })

    print(f"[misconfiguration] Found {len(findings)} items")
    return findings

