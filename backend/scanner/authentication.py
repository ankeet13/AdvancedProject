from crawler.selenium_crawler import SeleniumCrawler
import requests

AUTH_KEYWORDS = [
    "login","signin","sign-in","logout","register",
    "signup","auth","password","forgot","reset","token",
]

GENERIC_AUTH_PATHS = [
    "/login","/signin","/auth/login",
    "/user/login","/account/login","/admin/login",
    "/wp-login.php","/register","/signup",
    "/api/login","/api/auth","/api/auth/login",
    "/api/v1/login","/api/v1/auth","/api/token",
    "/rest/user/login",  # Juice Shop
]


def collect_auth_endpoints(base_url, crawl_results):
    all_ep, seen = [], set()
    base = base_url.rstrip("/")

    # Layer 1: Forms with password fields (Selenium)
    for form in crawl_results.get("forms", []):
        has_pwd = any(i.get("type","").lower()=="password"
                      for i in form["inputs"])
        if has_pwd and form["url"] not in seen:
            seen.add(form["url"])
            all_ep.append({
                "url": form["url"], "method": form["method"],
                "source": "selenium_password_form",
            })

    # Layer 2: Auth links from Selenium
    for link in crawl_results.get("links", []):
        if any(kw in link.lower() for kw in AUTH_KEYWORDS) and link not in seen:
            seen.add(link)
            all_ep.append({"url": link, "method": "POST",
                           "source": "selenium_auth_link"})

    # Layer 3: Auth API calls from Selenium
    for api_url in crawl_results.get("api_calls", []):
        if any(kw in api_url.lower() for kw in AUTH_KEYWORDS) and api_url not in seen:
            seen.add(api_url)
            all_ep.append({"url": api_url, "method": "POST",
                           "source": "selenium_api_intercept"})

    # Layer 4: Generic wordlist
    for path in GENERIC_AUTH_PATHS:
        ep_url = base + path
        if ep_url in seen: continue
        try:
            r = requests.get(ep_url, timeout=5)
            if r.status_code not in (404, 410):
                seen.add(ep_url)
                all_ep.append({"url": ep_url, "method": "POST",
                               "source": "wordlist"})
        except Exception:
            pass
    return all_ep


def scan(url):
    crawler = SeleniumCrawler(url, max_pages=15)
    crawl_results = crawler.crawl()
    endpoints = collect_auth_endpoints(url, crawl_results)
    print(f"[authentication] Found {len(endpoints)} auth endpoints")
    return [{
        "type": "Authentication Failure", "url": ep["url"],
        "severity": "Info",
        "detail": f"Auth endpoint via {ep['source']}. Method: {ep['method']}"
    } for ep in endpoints]