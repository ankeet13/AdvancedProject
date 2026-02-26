import requests
from bs4 import BeautifulSoup

def find_forms(url):
    response = requests.get(url) # vists the website and gets its html
    soup = BeautifulSoup(response.text, 'html.parser') # parse the html so we can search through it
    forms = soup.find_all('form')
    results = []

    print(f'Scanning for forms on: {url}')
    print(f'Found {len(forms)} forms')
    print('---')

    # Loop from each forms and extract its details
    for form in forms:
        form_details = {
            'action': form.get('action'),  # Where the form sends data
            'method': form.get('method'),  # Where it sends data (GET or POST)
            'inputs': [
                {'name': i.get('name'), 'type': i.get('type')}
                for i in form.find_all('input')
            ]
        }
        results.append(form_details)
        print(f'Form action: {form_details["action"]}')
        print(f'Form method: {form_details["method"]}')
        print(f'Input fields: {form_details["inputs"]}')
        print('---')
    
    return results
 

# Runs the crawler on Juice Shop
find_forms('http://localhost:3000')


