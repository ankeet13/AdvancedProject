from crawler.selenium_crawler import SeleniumCrawler
import requests
import json, os


SEVERITY_MAP = {
    "rest/admin":   "Critical",
    "actuator/env": "Critical",
    ".env":         "Critical",
    ".git":         "Critical",
    "admin":        "Critical",
    "config":       "High",
    "users":        "High",
    "api":          "High",
    "metrics":      "High",
    "swagger":      "Medium",
    "robots":       "Low",
    "sitemap":      "Low",
}
def get_severity(ep_url):
    for keyword, sev in SEVERITY_MAP.items():
        if keyword in ep_url.lower():
            return sev
    return "High"


SENSITIVE_KEYWORDS = [
    "admin","dashboard","manage","config","settings",
    "user","users","account","api","internal","private",
    "secret","panel","control","backup","debug","dev",
]

GENERIC_SENSITIVE_PATHS = [
    "/admin","/admin/login","/administrator",
    "/wp-admin","/wp-login.php","/phpmyadmin",
    "/api","/api/v1","/api/v2",
    "/api/users","/api/admin","/api/config",
    "/rest","/rest/admin","/graphql",
    "/swagger.json","/openapi.json","/api-docs",
    "/actuator","/actuator/env","/metrics",
    "/.env","/.git/config","/config.json",
    "/phpinfo.php","/server-status",
    "/robots.txt","/sitemap.xml",
    # Juice Shop real endpoints
    "/rest/admin/application-configuration",
    "/rest/admin/application-version",
    "/api/Users","/api/Feedbacks",
    "/api/SecurityQuestions","/api/Challenges",
]


def collect_sensitive_endpoints(base_url, crawl_results):
    all_ep = set()
    base = base_url.rstrip("/")

    # Layer 1: Selenium links matching sensitive keywords
    for link in crawl_results.get("links", []):
        if any(kw in link.lower() for kw in SENSITIVE_KEYWORDS):
            all_ep.add(link)

    # Layer 2: API calls from Selenium network logs
    for api_url in crawl_results.get("api_calls", []):
        all_ep.add(api_url)

    # Layer 3: Generic wordlist
    for path in GENERIC_SENSITIVE_PATHS:
        ep_url = base + path
        try:
            r = requests.get(ep_url, timeout=5)
            if r.status_code not in (404, 410):
                all_ep.add(ep_url)
        except Exception:
            pass
    return list(all_ep)

def test_access(ep_url):
    try:
        resp    = requests.get(
            ep_url,
            headers={"Accept": "application/json"},
            timeout=10,
        )
        ct      = resp.headers.get("Content-Type", "")
        is_json = "application/json" in ct

        if resp.status_code == 200 and is_json:
            return {
                "type":     "Broken Access Control",
                "url":      ep_url,
                "severity": get_severity(ep_url),
                "detail":   f"Accessible without auth. HTTP 200 + JSON. Content-Type: {ct}",
            }
        elif resp.status_code == 200 and not is_json:
            print(f"[broken_access] Skipped SPA false positive: {ep_url}")
        else:
            print(f"[broken_access] Protected HTTP {resp.status_code}: {ep_url}")
    except Exception as e:
        print(f"[broken_access] Error on {ep_url}: {e}")
    return None


def scan(url):
    crawler = SeleniumCrawler(url, max_pages=15)
    crawl_results = crawler.crawl()
    endpoints = collect_sensitive_endpoints(url, crawl_results)
    print(f"[broken_access]  found {len(endpoints)} sensitive endpoints")
    findings = []
    for ep in endpoints:
        result = test_access(ep)
        if result:
            findings.append(result)
    print(f"[broken_access] Confirmed: {len(findings)} vulnerabilities")
    
    # Save results to JSON file(Just for demonstration, can be removed later)
    os.makedirs("results", exist_ok=True)
    with open("results/broken_access_results.json", "w") as f:
        json.dump(findings, f, indent=2)
    print(f"[broken_access] Results saved to results/broken_access_results.json")

    return findings

