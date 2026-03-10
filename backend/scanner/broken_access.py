from crawler.selenium_crawler import SeleniumCrawler
import requests

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


def scan(url):
    crawler = SeleniumCrawler(url, max_pages=15)
    crawl_results = crawler.crawl()
    endpoints = collect_sensitive_endpoints(url, crawl_results)
    print(f"[broken_access]  found {len(endpoints)} sensitive endpoints")
    return [{
        "type": "Broken Access Control", "url": ep,
        "severity": "Info",
        "detail": f" Sensitive endpoint discovered: {ep}"
    } for ep in endpoints]
