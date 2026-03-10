from crawler.selenium_crawler import SeleniumCrawler
import requests

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


def scan(url):
    crawler = SeleniumCrawler(url, max_pages=15)
    crawl_results = crawler.crawl()
    endpoints = collect_input_endpoints(url, crawl_results)
    print(f"[sql_injection] Found {len(endpoints)} input endpoints")
    return [{
        "type": "SQL Injection", "url": ep["url"],
        "severity": "Info",
        "detail": (f"Input endpoint via {ep['source']}. "
                   f"Fields: {ep['inputs']}")
    } for ep in endpoints]
