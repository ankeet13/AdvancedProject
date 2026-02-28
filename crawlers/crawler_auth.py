import requests
import json

def find_auth_endpoints():
    # This is the local address where Juice Shop is running via Docker
    base_url = 'http://localhost:3000'

    # This is a list of dictionaries. Each dictionary contains the details of a 
    # specific authentication-related endpoint we want to test.
    # We test the API directly instead of crawling HTML because Juice Shop is a 
    # React app, meaning a normal HTML crawler would see nothing

    endpoints_to_check = [
        {'url': '/rest/user/login', 'method': 'POST', 'description': 'User login'},
        {'url': '/api/Users', 'method': 'POST', 'description': 'User registration'},
        {'url': '/rest/user/reset-password', 'method': 'POST', 'description': 'Password reset'},
        {'url': '/rest/user/whoami', 'method': 'GET', 'description': 'Current user session'},
        {'url': '/rest/user/change-password', 'method': 'GET', 'description': 'Change password'},
    ]

    discovered = []

    print('Finding authentication-related endpoints...')
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
                    json={'email': 'test@test.com', 'password': 'test'},
                    timeout=5
                )

            status = response.status_code

            # If endpoint responds it can be tested for auth failures
            # 401 means it needs login — good candidate for default credential testing
            # 200 means it responded — good candidate for lockout testing
            is_vulnerable = True if status in [200, 401, 400] else False

            result = {
                'url': endpoint['url'],
                'method': endpoint['method'],
                'description': endpoint['description'],
                'status': status,
                'potential_auth_failure': is_vulnerable
            }

            discovered.append(result)

            print(f"AUTH ENDPOINT FOUND: {endpoint['url']}")
            print(f"  Description: {endpoint['description']}")
            print(f"  Method: {endpoint['method']}")
            print(f"  Status: {status}")
            print(f"  Potential auth failure target: {is_vulnerable}")
            print()

        except requests.RequestException as e:
            print(f"ERROR checking {endpoint['url']}: {e}")

    vulnerable = [e for e in discovered if e.get('potential_auth_failure') == True]

    print('---')
    print(f'Total auth endpoints found: {len(discovered)}')
    print(f'Potential auth failure targets: {len(vulnerable)}')

    with open('auth_endpoints_results.json', 'w', encoding='utf-8') as f:
        json.dump(discovered, f, indent=2)

    print('Results saved to auth_endpoints_results.json')

    return discovered


if __name__ == "__main__":
    find_auth_endpoints()