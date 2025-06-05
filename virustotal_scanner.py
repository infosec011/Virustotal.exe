# virustotal_scanner.py
import requests
import time

API_KEY = 'fe859b7e3e45b05fd7abd192265c7535b0be6eba74922cfce7a5e0d7daad67c1'  # Sizning API kalitingiz

def upload_file_to_virustotal(file_path):
    url = 'https://www.virustotal.com/api/v3/files'
    headers = {
        'x-apikey': API_KEY
    }

    with open(file_path, 'rb') as file:
        files = {'file': (file_path, file)}
        response = requests.post(url, files=files, headers=headers)

    if response.status_code == 200:
        file_id = response.json()['data']['id']
        return file_id
    else:
        return None

def get_scan_report(file_id):
    url = f'https://www.virustotal.com/api/v3/analyses/{file_id}'
    headers = {
        'x-apikey': API_KEY
    }

    while True:
        response = requests.get(url, headers=headers)
        data = response.json()
        status = data['data']['attributes']['status']
        if status == 'completed':
            return data
        time.sleep(5)

def parse_report(report):
    stats = report['data']['attributes']['stats']
    results = report['data']['attributes']['results']

    summary = f"\n--- Hisobot ---\n"
    summary += f"Zararli: {stats['malicious']}\n"
    summary += f"Shubhali: {stats['suspicious']}\n"
    summary += f"Zararsiz: {stats['harmless']}\n\n"

    for engine, result in results.items():
        category = result['category']
        if category in ['malicious', 'suspicious']:
            summary += f"[!] {engine}: {result['result']}\n"

    return summary
