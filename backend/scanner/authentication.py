"""
authentication.py — Sprint 1 Crawler
Owner: Aayush Das (s4679660)
"""
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

WEAK_CREDENTIALS = [  # Sprint 2 — do NOT use yet
    ('admin','admin'),('admin','password'),('admin','123456'),
    ('test','test'),('user','user'),('root','root'),
]

AUTH_API_ENDPOINTS = [
    '/rest/user/login','/rest/user/logout',
    '/api/login','/api/auth/login',
    '/login','/register','/signup','/api/Users',
]

def crawl_auth_endpoints(url):
    auth_endpoints = []
    try:
        resp = requests.get(url, timeout=10)
        soup = BeautifulSoup(resp.text, 'html.parser')
        for form in soup.find_all('form'):
            inputs = form.find_all('input')
            input_types = [i.get('type','').lower() for i in inputs]
            input_names = [i.get('name','').lower() for i in inputs]
            if 'password' in input_types:
                action = form.get('action','')
                method = form.get('method','post').upper()
                full_url = urljoin(url,action) if action else url
                has_user = any(k in ' '.join(input_names)
                               for k in ['email','user','login','username'])
                auth_endpoints.append({'url':full_url,'method':method,
                                       'has_username_field':has_user,'source':'html_form'})
        for a in soup.find_all('a',href=True):
            href = a['href'].lower()
            if any(kw in href for kw in ['login','logout','signup','register','auth']):
                auth_endpoints.append({'url':urljoin(url,a['href']),'method':'GET',
                                       'has_username_field':False,'source':'link'})
    except Exception as e:
        print(f'[authentication crawler] Error: {e}')
    base = url.rstrip('/')
    for ep in AUTH_API_ENDPOINTS:
        auth_endpoints.append({'url':base+ep,'method':'POST',
                               'has_username_field':True,'source':'api'})
    return auth_endpoints

def scan(url):
    findings = []
    for ep in crawl_auth_endpoints(url):
        findings.append({
            'type': 'Authentication Failure',
            'url': ep['url'],
            'severity': 'High',
            'detail': f"[SPRINT 1 - CRAWLER] Auth endpoint via {ep['source']}. Method: {ep['method']}"
        })
    print(f'[authentication] Found {len(findings)} auth endpoints')
    return findings
