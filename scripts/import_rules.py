import requests
import os
import json
import xml.etree.ElementTree as ET
import urllib3
urllib3.disable_warnings()

QRADAR_IP = os.environ.get("QRADAR_IP")
QRADAR_TOKEN = os.environ.get("QRADAR_TOKEN")
GITHUB_REPO = "splunkteam-ailog/qradarteam_rules"
GITHUB_API = f"https://api.github.com/repos/{GITHUB_REPO}/contents/rules"

headers = {
    "SEC": QRADAR_TOKEN,
    "Version": "12.0",
    "Accept": "application/json",
    "Content-Type": "application/json"
}

# Windows Event ID → QRadar QID mapping
EVENT_ID_TO_QID = {
    "4720": 5000880,  # User Account Created
    "4732": 5000895,  # Member Added to Security Group
    "4625": 5000791,  # Logon Failure
    "4624": 5000790,  # Logon Success
    "4726": 5000882,  # User Account Deleted
    "4719": 5000869,  # Audit Policy Changed
    "7045": 5001003,  # New Service Installed
    "1102": 5000789,  # Audit Log Cleared
}

def get_rules_from_github():
    """Скачать XML rules из GitHub"""
    response = requests.get(GITHUB_API)
    if response.status_code != 200:
        print(f"❌ GitHub API error: {response.status_code}")
        return []

    rules = []
    for file in response.json():
        if file["name"].endswith(".xml"):
            content = requests.get(file["download_url"])
            rules.append({
                "name": file["name"],
                "content": content.text
            })
            print(f"📥 Получено: {file['name']}")
    return rules

def parse_xml_to_qradar(xml_content):
    """Конвертировать наш XML в формат QRadar"""
    try:
        root = ET.fromstring(xml_content)

        name = root.findtext("name", "Unknown Rule")
        severity = int(root.findtext("severity", "5"))
        credibility = int(root.findtext("credibility", "5"))
        relevance = int(root.findtext("relevance", "5"))
        notes = root.findtext("notes", "")

        # Получить event ID из conditions
        event_id = root.findtext(".//eventId", "")
        qid = EVENT_ID_TO_QID.get(event_id)

        # Получить threshold если есть
        threshold_count = root.findtext(".//count")
        threshold_time = root.findtext(".//timeInterval")

        # Построить test group для QRadar
        tests = []

        if qid:
            tests.append({
                "uid": 1,
                "name": "when the event QID is one of the following QIDs",
                "override_id": 15000,
                "enabled": True,
                "parameters": [
                    {
                        "parameter_name": "QIDList",
                        "value": str(qid)
                    }
                ]
            })

        if threshold_count and threshold_time:
            tests.append({
                "uid": 2,
                "name": "an event matches any of the following rules more than N times",
                "override_id": 15001,
                "enabled": True,
                "parameters": [
                    {
                        "parameter_name": "count",
                        "value": threshold_count
                    },
                    {
                        "parameter_name": "timeInterval",
                        "value": threshold_time
                    }
                ]
            })

        rule = {
            "name": name,
            "type": "EVENT",
            "enabled": True,
            "owner": "admin",
            "origin": "USER",
            "notes": notes,
            "groups": ["Windows"],
            "average_capacity": 0,
            "base_capacity": 0,
            "base_host_id": 0,
            "capacity_timestamp": 0,
            "creation_date": None,
            "identifier": name.replace(" ", "_").replace("-", "_").lower(),
        }

        return rule

    except ET.ParseError as e:
        print(f"❌ XML Parse Error: {e}")
        return None

def rule_exists(name):
    """Проверить что rule с таким именем уже существует"""
    url = f"https://{QRADAR_IP}/api/analytics/rules"
    params = {"filter": f'name="{name}"'}
    r = requests.get(url, headers=headers, params=params, verify=False)
    if r.status_code == 200 and len(r.json()) > 0:
        return True
    return False

def create_rule_in_qradar(rule_data):
    """Создать rule в QRadar через API"""
    url = f"https://{QRADAR_IP}/api/analytics/rules"
    r = requests.post(url, headers=headers, json=rule_data, verify=False)
    return r.status_code, r.text

def add_close_reasons():
    """Добавить True-Positive и False-Positive"""
    reasons = ["True-Positive", "False-Positive"]
    for reason in reasons:
        url = f"https://{QRADAR_IP}/api/siem/offense_closing_reasons"
        r = requests.post(
            url,
            headers=headers,
            params={"reason": reason},
            verify=False
        )
        if r.status_code == 201:
            print(f"✅ Close reason added: {reason}")
        else:
            print(f"⚠️  Already exists: {reason}")

def check_connection():
    """Проверить подключение к QRadar"""
    url = f"https://{QRADAR_IP}/api/system/about"
    r = requests.get(url, headers=headers, verify=False)
    if r.status_code == 200:
        info = r.json()
        print(f"✅ Connected to QRadar {info.get('external_version', '')}")
        return True
    else:
        print(f"❌ Connection failed: {r.status_code}")
        return False

def main():
    print("=" * 50)
    print("🚀 QRadar Rules Deployment from GitHub")
    print("=" * 50)

    if not QRADAR_IP or not QRADAR_TOKEN:
        print("❌ Missing QRADAR_IP or QRADAR_TOKEN!")
        exit(1)

    # Проверка подключения
    if not check_connection():
        exit(1)

    # Скачать rules из GitHub
    print("\n📋 Fetching rules from GitHub...")
    xml_rules = get_rules_from_github()
    print(f"Found {len(xml_rules)} rules\n")

    success = 0
    failed = 0
    skipped = 0

    for xml_rule in xml_rules:
        # Конвертировать XML → QRadar JSON
        rule_data = parse_xml_to_qradar(xml_rule["content"])

        if not rule_data:
            print(f"❌ Parse failed: {xml_rule['name']}")
            failed += 1
            continue

        # Проверить существует ли rule
        if rule_exists(rule_data["name"]):
            print(f"⏭️  Already exists: {rule_data['name']}")
            skipped += 1
            continue

        # Создать rule в QRadar
        status, response = create_rule_in_qradar(rule_data)

        if status in [200, 201]:
            print(f"✅ Created: {rule_data['name']}")
            success += 1
        else:
            print(f"❌ Failed [{status}]: {rule_data['name']}")
            print(f"   Response: {response[:200]}")
            failed += 1

    # Добавить close reasons
    print("\n📋 Adding custom close reasons...")
    add_close_reasons()

    # Итог
    print("\n" + "=" * 50)
    print(f"✅ Created : {success}")
    print(f"⏭️  Skipped : {skipped}")
    print(f"❌ Failed  : {failed}")
    print("⚠️  Click Deploy Changes in QRadar!")
    print("=" * 50)

if __name__ == "__main__":
    main()
