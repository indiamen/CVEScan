from flask import Flask, jsonify, request
import sqlite3
import requests
import re
import json
from bs4 import BeautifulSoup



app = Flask(__name__)

def scan_host(host):
    url = f"https://www.shodan.io/host/{host}"
    response = requests.get(url)
    if response.status_code == 200:
        match = re.search(r'const VULNS = ({.*?});', response.text, re.DOTALL)
        if match:
            vulns_data = json.loads(match.group(1))

            vulnerabilities = []
            for vuln_id, details in vulns_data.items():
                html_content = response.text
                soup = BeautifulSoup(html_content, 'html.parser')
                ports_div = soup.find('div', id='ports')
                ports = [a.text for a in ports_div.find_all('a')]
                summary = details.get("summary", "Описание отсутствует")
                cvss = details.get("cvss", "Не указан")
                vulnerabilities.append({
                    "exploit": vuln_id,
                    "description": summary,
                    "cvss": cvss
                })
            return {"status": "success", "open-ports": ports, "vulnerabilities": vulnerabilities}
        else:
            return {"status": "error", "message": "Не удалось найти данные об уязвимостях."}
    else:
        return {"status": "error", "message": f"Ошибка запроса: {response.status_code}"}


def get_vulnerabilities():
    conn = sqlite3.connect("lastcve.db")
    cursor = conn.cursor()

    cursor.execute("SELECT id, title, publication_date, url FROM vulnerabilities")
    rows = cursor.fetchall()

    vulnerabilities = []
    for row in rows:
        exploit_id, exploit_title, publication_date, exploit_url = row
        vulnerabilities.append({
            "id": exploit_id,
            "title": exploit_title,
            "publication_date": publication_date,
            "url": exploit_url,
        })

    conn.close()
    return vulnerabilities

@app.route('/api/v1/vulnerabilities', methods=['GET', 'OPTIONS'])
def vulnerabilities():
    try:
        data = get_vulnerabilities()
        return jsonify({"status": "success", "vulnerabilities": data}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/v1/scan', methods=['POST'])
def scan():
    data = request.get_json()

    host = data.get('host')
    if not host:
        return jsonify({"error": "Необходимо передать параметр 'host' с IP или доменом"}), 400

    result = scan_host(host)

    return jsonify(result), 200

if __name__ == '__main__':
    app.run(debug=True)
