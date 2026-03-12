from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from collections import deque
import time
import json

try:
    from webdriver_manager.chrome import ChromeDriverManager
    USE_MANAGER = True
except ImportError:
    USE_MANAGER = False


class SeleniumCrawler:
    def __init__(self, base_url, max_pages=15):
        self.base_url  = base_url.rstrip('/')
        self.max_pages = max_pages
        self.domain    = urlparse(base_url).netloc

    def _get_driver(self):
        opts = Options()
        opts.add_argument('--headless')
        opts.add_argument('--no-sandbox')
        opts.add_argument('--disable-dev-shm-usage')
        opts.add_argument('--disable-gpu')
        opts.set_capability('goog:loggingPrefs', {'performance': 'ALL'})
        if USE_MANAGER:
            return webdriver.Chrome(
                service=Service(ChromeDriverManager().install()), options=opts
            )
        return webdriver.Chrome(options=opts)

    def _get_api_calls(self, driver):
        api_calls = set()
        try:
            logs = driver.get_log('performance')
            for entry in logs:
                msg = json.loads(entry['message'])['message']
                if msg.get('method') == 'Network.requestWillBeSent':
                    req_url = msg['params']['request']['url']
                    if self.domain in req_url and any(
                        kw in req_url for kw in ['/api/', '/rest/', '/graphql']
                    ):
                        api_calls.add(req_url)
        except Exception:
            pass
        return list(api_calls)

    def crawl(self):
        results = {'forms': [], 'links': [], 'api_calls': [], 'param_urls': []}
        driver  = self._get_driver()
        visited = set()
        queue   = deque([self.base_url])

        while queue and len(visited) < self.max_pages:
            url = queue.popleft()
            if url in visited:
                continue
            visited.add(url)
            try:
                driver.get(url)
                time.sleep(10)
                soup = BeautifulSoup(driver.page_source, 'html.parser')
            except Exception as e:
                print(f'[crawler] Error loading {url}: {e}')
                continue

            for api_url in self._get_api_calls(driver):
                if api_url not in results['api_calls']:
                    results['api_calls'].append(api_url)

            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', 'get').upper()
                inputs = []
                for i in form.find_all('input'):
                    if i.get('type', '').lower() not in ('hidden', 'submit', 'button'):
                        inputs.append({
                            'name': i.get('name', 'input'),
                            'type': i.get('type', 'text')
                        })
                if inputs:
                    results['forms'].append({
                        'url':    urljoin(url, action) or url,
                        'method': method,
                        'inputs': inputs,
                        'page':   url
                    })

            for a in soup.find_all('a', href=True):
                href = urljoin(url, a['href'])
                if urlparse(href).netloc != self.domain:
                    continue
                if href not in visited:
                    queue.append(href)
                if href not in results['links']:
                    results['links'].append(href)
                if '?' in href:
                    params = list(parse_qs(urlparse(href).query).keys())
                    if params:
                        results['param_urls'].append({'url': href, 'params': params})

        driver.quit()
        print(f'[crawler] Done — {len(results["forms"])} forms, '
              f'{len(results["links"])} links, '
              f'{len(results["api_calls"])} API calls')
        return results