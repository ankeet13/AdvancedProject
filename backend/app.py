from flask import Flask, request, jsonify
from flask_cors import CORS
from concurrent.futures import ThreadPoolExecutor, as_completed
import traceback
from scanner.policy_engine import apply_policy, get_recommendations

from scanner.sql_injection    import scan as sql_scan
from scanner.broken_access    import scan as access_scan
from scanner.authentication   import scan as auth_scan
from scanner.misconfiguration import scan as misc_scan
from risk_scorer              import score_findings

app = Flask(__name__)
CORS(app)

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    url  = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    if not url.startswith('http'):
        url = 'http://' + url

    all_findings, errors = [], []
    scanners = {
        'SQL Injection':         sql_scan,
        'Broken Access Control': access_scan,
        'Authentication':        auth_scan,
        'Misconfiguration':      misc_scan,
    }
    with ThreadPoolExecutor(max_workers=4) as ex:
        futures = {ex.submit(fn, url): name for name, fn in scanners.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                all_findings.extend(future.result())
            except Exception as e:
                errors.append(f'{name}: {e}')
                traceback.print_exc()

    risk = score_findings(all_findings)

    return jsonify({
        'url':             url,
        'findings':        all_findings,
        'risk':            risk,
        'policy':          apply_policy(risk),
        'recommendations': get_recommendations(all_findings),
        'errors':          errors,
        'summary': {
            'total':    len(all_findings),
            'critical': sum(1 for f in all_findings if f['severity']=='Critical'),
            'high':     sum(1 for f in all_findings if f['severity']=='High'),
            'medium':   sum(1 for f in all_findings if f['severity']=='Medium'),
            'low':      sum(1 for f in all_findings if f['severity']=='Low'),
        },
    })

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'port': 5500})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5500, debug=True)