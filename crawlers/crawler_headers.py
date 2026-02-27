import requests
import json

def check_security_headers():
    base_url = 'http://localhost:3000'

    endpoints_to_check = [
        {'url': '/', 'method': 'GET', 'description': 'Homepage'},
        {'url': '/rest/products/search', 'method': 'GET', 'description': 'Product search'},
        {'url': '/rest/user/login', 'method': 'POST', 'description': 'User login'},
        {'url': '/api/Users', 'method': 'GET', 'description': 'All user accounts'},
        {'url': '/rest/admin/application-configuration', 'method': 'GET', 'description': 'Admin config'},
    ]

    required_headers = {
        'X-Frame-Options': 'Prevents clickjacking attacks',
        'X-Content-Type-Options': 'Prevents MIME type sniffing',
        'Content-Security-Policy': 'Prevents XSS attacks',
        'Strict-Transport-Security': 'Forces HTTPS connections'
    }

    all_results = []

    print('Checking security headers on all endpoints...')
    print('---')

    for endpoint in endpoints_to_check:
        try:
            if endpoint['method'] == 'GET':
                response = requests.get(
                    f"{base_url}{endpoint['url']}",
                    timeout=5
                )
            else:
                response = requests.post(
                    f"{base_url}{endpoint['url']}",
                    json={},
                    timeout=5
                )

            missing = []
            present = []

            for header in required_headers:
                if header in response.headers:
                    present.append(header)
                else:
                    missing.append(header)

            # If any required headers are missing it is a misconfiguration vulnerability
            is_vulnerable = True if len(missing) > 0 else False

            result = {
                'url': endpoint['url'],
                'description': endpoint['description'],
                'missing_headers': missing,
                'present_headers': present,
                'server': response.headers.get('Server', 'Not disclosed'),
                'x_powered_by': response.headers.get('X-Powered-By', 'Not disclosed'),
                'potential_misconfiguration': is_vulnerable
            }

            all_results.append(result)

            print(f"Endpoint: {endpoint['url']}")
            print(f" Missing headers ({len(missing)}): {missing}")
            print(f" Present headers ({len(present)}): {present}")
            print(f" Potential misconfiguration: {is_vulnerable}")
            print()

        except requests.RequestException as e:
            print(f"ERROR checking {endpoint['url']}: {e}")

    vulnerable = [e for e in all_results if e.get('potential_misconfiguration') is True]

    if all_results:
        print('---')
        print('SERVER INFORMATION EXPOSED:')
        print(f" Server: {all_results[0]['server']}")
        print(f" X-Powered-By: {all_results[0]['x_powered_by']}")

    print('---')
    print(f'Total endpoints checked: {len(all_results)}')
    print(f'Endpoints with missing headers: {len(vulnerable)}')

    with open('header_check_results.json', 'w', encoding='utf-8') as f:
        json.dump(all_results, f, indent=2)

    print('Results saved to header_check_results.json')

    return all_results


if __name__ == "__main__":
    check_security_headers()