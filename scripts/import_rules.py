import requests
import os
import urllib3
urllib3.disable_warnings()

QRADAR_IP = os.environ.get("QRADAR_IP")
QRADAR_TOKEN = os.environ.get("QRADAR_TOKEN")
GITHUB_REPO = "splunkteam-ailog/qradarteam_rules"
GITHUB_API = f"https://api.github.com/repos/{GITHUB_REPO}/contents/rules"

def get_rules_from_github():
    response = requests.get(GITHUB_API)
    if response.status_code != 200:
        print(f"❌ GitHub API error: {response.status_code}")
        return []
    
    files = response.json()
    rules = []
    for file in files:
        if file["name"].endswith(".xml"):
            content = requests.get(file["download_url"])
            rules.append({
                "name": file["name"],
                "content": content.text
            })
            print(f"📥 Получено из GitHub: {file['name']}")
    return rules

def import_to_qradar(name, content):
    headers = {
        "SEC": QRADAR_TOKEN,
        "Version": "12.0",
        "Accept": "application/json",
        "Content-Type": "application/xml"
    }
    url = f"https://{QRADAR_IP}/api/config/extension_management/extensions"
    response = requests.post(
        url,
        headers=headers,
        data=content.encode("utf-8"),
        verify=False
    )
    return response.status_code, response.text

def add_close_reasons():
    import json
    headers = {
        "SEC": QRADAR_TOKEN,
        "Version": "12.0",
        "Accept": "application/json"
    }
    
    reasons = ["True-Positive", "False-Positive"]
    for reason in reasons:
        url = f"https://{QRADAR_IP}/api/siem/offense_closing_reasons"
        response = requests.post(
            url,
            headers=headers,
            params={"reason": reason},
            verify=False
        )
        if response.status_code == 201:
            print(f"✅ Close reason added: {reason}")
        else:
            print(f"⚠️  Close reason may already exist: {reason}")

def main():
    print("=" * 50)
    print("🚀 QRadar Rules Deployment from GitHub")
    print("=" * 50)

    if not QRADAR_IP or not QRADAR_TOKEN:
        print("❌ Missing QRADAR_IP or QRADAR_TOKEN!")
        exit(1)

    # Import rules
    print("\n📋 Fetching rules from GitHub...")
    rules = get_rules_from_github()
    print(f"Found {len(rules)} rules\n")

    success = 0
    failed = 0
    for rule in rules:
        status, response = import_to_qradar(rule["name"], rule["content"])
        if status in [200, 201]:
            print(f"✅ Imported: {rule['name']}")
            success += 1
        else:
            print(f"❌ Failed [{status}]: {rule['name']}")
            failed += 1

    # Add close reasons
    print("\n📋 Adding custom close reasons...")
    add_close_reasons()

    print("\n" + "=" * 50)
    print(f"✅ Success: {success} | ❌ Failed: {failed}")
    print("⚠️  Remember to click Deploy Changes in QRadar!")
    print("=" * 50)

if __name__ == "__main__":
    main()
