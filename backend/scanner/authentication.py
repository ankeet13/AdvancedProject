from crawler.selenium_crawler import SeleniumCrawler
import requests
import json
import os

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

WEAK_CREDENTIALS = [
    ("admin",             "admin"),
    ("admin",             "password"),
    ("admin",             "123456"),
    ("admin",             "admin123"),
    ("administrator",     "administrator"),
    ("test",              "test"),
    ("root",              "root"),
    ("guest",             "guest"),
    # Juice Shop
    ("admin@juice-sh.op", "admin"),
    ("admin@juice-sh.op", "admin123"),
    ("admin@admin.com",   "admin"),
    ("test@test.com",     "test"),
]

SUCCESS_INDICATORS = [
    "token", "access_token", "auth_token",
    "session", "bearer", "authenticated", "success",
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
        if ep_url in seen:
            continue
        try:
            r = requests.get(ep_url, timeout=5)
            if r.status_code not in (404, 410):
                seen.add(ep_url)
                all_ep.append({"url": ep_url, "method": "POST",
                               "source": "wordlist"})
        except Exception:
            pass
    return all_ep


def test_weak_credentials(ep_url):
    for email, password in WEAK_CREDENTIALS:
        try:
            resp = requests.post(
                ep_url,
                json={"email": email, "password": password},
                timeout=10,
            )
            if (resp.status_code == 200 and
                    any(s in resp.text.lower() for s in SUCCESS_INDICATORS)):
                return {
                    "type":     "Authentication Failure",
                    "url":      ep_url,
                    "severity": "Critical",
                    "detail":   f"Weak credentials accepted: {email} / {password}",
                }
        except Exception as e:
            print(f"[authentication] Credential test error: {e}")
    return None


def test_account_lockout(ep_url):
    for i in range(10):
        try:
            resp = requests.post(
                ep_url,
                json={"email": f"brute{i}@test.com", "password": f"wrongpass{i}"},
                timeout=10,
            )
            if resp.status_code == 429:
                return True
            if any(k in resp.text.lower()
                   for k in ["locked", "too many", "blocked", "captcha"]):
                return True
        except Exception:
            break
    return False


def scan(url):
    # Sprint 1: crawl and discover auth endpoints
    crawler       = SeleniumCrawler(url, max_pages=15)
    crawl_results = crawler.crawl()
    endpoints     = collect_auth_endpoints(url, crawl_results)
    print(f"[authentication] Found {len(endpoints)} auth endpoints")

    # Sprint 2: attack each endpoint
    findings = []
    tested   = set()

    for ep in endpoints:
        ep_url = ep["url"]
        if ep_url in tested:
            continue
        tested.add(ep_url)

        # Attack 1: weak credentials
        result = test_weak_credentials(ep_url)
        if result:
            findings.append(result)

        # Attack 2: account lockout
        if not test_account_lockout(ep_url):
            findings.append({
                "type":     "Authentication Failure",
                "url":      ep_url,
                "severity": "High",
                "detail":   "No lockout after 10 failed login attempts — brute force possible.",
            })

    print(f"[authentication] Total: {len(findings)} findings")

    # ── Save results for team records ─────────────────────────
    os.makedirs("results", exist_ok=True)
    with open("results/authentication_results.json", "w") as f:
        json.dump(findings, f, indent=2)
    print(f"[authentication] Results saved to results/authentication_results.json")

    return findings