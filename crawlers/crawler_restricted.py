import requests
import json

def discover_restricted_endpoints():
    base_url = 'http://localhost:3000'
    
    # Endpoints to test for Broken Access Control
    endpoints_to_check = [
        {'url': '/rest/admin/application-configuration', 'description': 'Admin configuration'},
        {'url': '/api/Users', 'description': 'All user accounts'},
        {'url': '/api/Users/1', 'description': 'Specific user account'},
        {'url': '/api/Feedbacks', 'description': 'All feedback'},
        {'url': '/rest/user/whoami', 'description': 'Current user info'},
        {'url': '/api/Complaints', 'description': 'All complaints'},
    ]
    
    discovered = []
    
    print('Discovering restricted endpoints on Juice Shop...')
    print('---')
    
    for endpoint in endpoints_to_check:
        try:
            response = requests.get(f"{base_url}{endpoint['url']}", timeout=5)
            status = response.status_code
            is_vulnerable = True if (status == 200 and endpoint.get('sensitive', True)) else False

            result = {
                'url': endpoint['url'],
                'description': endpoint['description'],
                'status': status,
                'potential_broken_access_control': is_vulnerable
            }
            
        
            
            discovered.append(result)
            
            if status == 200:
                print(f"ACCESSIBLE (200): {endpoint['url']} — {endpoint['description']}")
            elif status == 401:
                print(f"REQUIRES LOGIN (401): {endpoint['url']} — {endpoint['description']}")
            elif status == 403:
                print(f"FORBIDDEN (403): {endpoint['url']} — {endpoint['description']}")
            else:
                print(f"STATUS {status}: {endpoint['url']} — {endpoint['description']}")
                
        except requests.RequestException as e:
            print(f"ERROR checking {endpoint['url']}: {e}")
    
    accessible = [e for e in discovered if e.get('status') == 200]
    
    print('---')
    print(f'Total endpoints checked: {len(discovered)}')
    print(f'Accessible without login: {len(accessible)}')
    
    # Save results to JSON file (Sprint 1)
    with open('restricted_endpoints_results.json', 'w', encoding='utf-8') as f:
        json.dump(discovered, f, indent=2)
    
    print('Results saved to restricted_endpoints_results.json')
    
    return discovered


if __name__ == "__main__":
    discover_restricted_endpoints()