import requests
import json

def find_input_endpoints():
    base_url = 'http://localhost:3000'

    endpoints_to_check = [
        {'url': '/rest/products/search', 'method': 'GET', 'param': 'q', 'description': 'Product search'},
        {'url': '/rest/user/login', 'method': 'POST', 'param': 'email', 'description': 'User login'},
        {'url': '/api/Users', 'method': 'POST', 'param': 'email', 'description': 'User registration'},
        {'url': '/rest/user/reset-password', 'method': 'POST', 'param': 'email', 'description': 'Password reset'},
    ]

    discovered = []

    print('Finding endpoints that accept user input...')
    print('These are potential SQL injection targets')
    print('---')

    for endpoint in endpoints_to_check:
        try:
            if endpoint['method'] == 'GET':
                response = requests.get(
                    f"{base_url}{endpoint['url']}",
                    params={endpoint['param']: 'test'},
                    timeout=5
                )
            else:
                response = requests.post(
                    f"{base_url}{endpoint['url']}",
                    json={endpoint['param']: 'test@test.com', 'password': 'test'},
                    timeout=5
                )

            status = response.status_code

            # If endpoint responds and accepts input it is a potential SQL injection target
            is_vulnerable = True if status in [200, 401, 400] else False

            result = {
                'url': endpoint['url'],
                'method': endpoint['method'],
                'input_param': endpoint['param'],
                'description': endpoint['description'],
                'status': status,
                'potential_sql_injection': is_vulnerable
            }

            discovered.append(result)

            print(f"INPUT ENDPOINT FOUND: {endpoint['url']}")
            print(f"  Method: {endpoint['method']}")
            print(f"  Input parameter: {endpoint['param']}")
            print(f"  Description: {endpoint['description']}")
            print(f"  Status: {status}")
            print(f"  Potential SQL injection target: {is_vulnerable}")
            print()

        except requests.RequestException as e:
            print(f"ERROR checking {endpoint['url']}: {e}")

    vulnerable = [e for e in discovered if e.get('potential_sql_injection') == True]

    print('---')
    print(f'Total input endpoints found: {len(discovered)}')
    print(f'Potential SQL injection targets: {len(vulnerable)}')

    with open('input_endpoints_results.json', 'w', encoding='utf-8') as f:
        json.dump(discovered, f, indent=2)

    print('Results saved to input_endpoints_results.json')

    return discovered


if __name__ == "__main__":
    find_input_endpoints()