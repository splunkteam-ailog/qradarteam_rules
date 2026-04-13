import requests
import os
import json
import zipfile
import io
import urllib3
urllib3.disable_warnings()

QRADAR_IP = os.environ.get("QRADAR_IP")
QRADAR_TOKEN = os.environ.get("QRADAR_TOKEN")
GITHUB_REPO = "splunkteam-ailog/qradarteam_rules"
GITHUB_API = f"https://api.github.com/repos/{GITHUB_REPO}/contents/rules"

headers = {
    "SEC": QRADAR_TOKEN,
    "Version": "12.0",
    "Accept": "application/json"
}

# Windows EventID → QRadar Category ID mapping
RULES_CONFIG = [
    {
        "filename": "01_new_user_created.xml",
        "name": "WIN - New Local User Account Created",
        "event_id": "4720",
        "severity": 6,
        "notes": "MITRE T1136 - Create Account"
    },
    {
        "filename": "02_user_added_to_admins.xml",
        "name": "WIN - User Added to Privileged Group",
        "event_id": "4732",
        "severity": 8,
        "notes": "MITRE T1098 - Account Manipulation"
    },
    {
        "filename": "03_brute_force.xml",
        "name": "WIN - Brute Force Attack Detected",
        "event_id": "4625",
        "severity": 9,
        "notes": "MITRE T1110 - Brute Force"
    },
    {
        "filename": "04_success_after_bruteforce.xml",
        "name": "WIN - Successful Login After Brute Force",
        "event_id": "4624",
        "severity": 10,
        "notes": "MITRE T1110 - Brute Force Success"
    },
    {
        "filename": "05_user_account_deleted.xml",
        "name": "WIN - User Account Deleted",
        "event_id": "4726",
        "severity": 7,
        "notes": "MITRE T1531 - Account Access Removal"
    },
    {
        "filename": "06_audit_policy_changed.xml",
        "name": "WIN - Audit Policy Modified",
        "event_id": "4719",
        "severity": 8,
        "notes": "MITRE T1562 - Impair Defenses"
    },
    {
        "filename": "07_new_service_installed.xml",
        "name": "WIN - New Service Installed",
        "event_id": "7045",
        "severity": 7,
        "notes": "MITRE T1543 - Create System Process"
    },
    {
        "filename": "08_event_log_cleared.xml",
        "name": "WIN - Security Event Log Cleared",
        "event_id": "1102",
        "severity": 10,
        "notes": "MITRE T1070 - Indicator Removal"
    },
    {
        "filename": "09_login_outside_hours.xml",
        "name": "WIN - Login Outside Business Hours",
        "event_id": "4624",
        "severity": 6,
        "notes": "MITRE T1078 - Valid Accounts"
    },
    {
        "filename": "10_lateral_movement.xml",
        "name": "WIN - Lateral Movement Detected",
        "event_id": "4624",
        "severity": 9,
        "notes": "MITRE T1021 - Remote Services"
    }
]

def build_rule_xml(rule):
    """Создать XML в формате QRadar Extension"""
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<rule id="-1" name="{rule['name']}" owner="admin" type="EVENT" enabled="true">
  <notes>{rule['notes']}</notes>
  <testDefinitions>
    <testDefinition name="EVENT" id="-1">
      <testGroup uid="1" groupop="AND">
        <test id="1" name="when the event QID is contained in the following list"
              uid="1" override_id="15000" enabled="true"
              requiredCapabilities="">
          <parameter name="QIDList" id="1"
                     type="STRING"
                     value="{rule['event_id']}"
                     operator="CONTAINEDIN"/>
        </test>
      </testGroup>
    </testDefinition>
  </testDefinitions>
  <actions>
    <action type="NEWEVENT" enabled="true">
      <actionElement name="credibility" value="{min(rule['severity'], 10)}"/>
      <actionElement name="severity" value="{rule['severity']}"/>
      <actionElement name="relevance" value="{min(rule['severity'], 10)}"/>
    </action>
  </actions>
  <responses>
    <response type="OFFENSE" enabled="true">
      <responseElement name="offenseMapping" value="SOURCE_IP"/>
    </response>
  </responses>
</rule>"""

def build_manifest(rules):
    """Создать manifest.xml для Extension ZIP"""
    rule_entries = "\n".join([
        f'  <content type="RULE" name="{r["name"]}" ' 
        f'file="rules/{r["filename"]}"/>'
        for r in rules
    ])
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<manifest>
  <name>QRadar Team Rules</name>
  <version>1.0</version>
  <author>splunkteam-ailog</author>
  <description>10 Custom Windows Security Rules - MITRE ATT&amp;CK</description>
  <contents>
{rule_entries}
  </contents>
</manifest>"""

def create_extension_zip(rules):
    """Создать ZIP файл в формате QRadar Extension"""
    zip_buffer = io.BytesIO()

    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Добавить manifest
        manifest = build_manifest(rules)
        zf.writestr("manifest.xml", manifest)
        print("📄 manifest.xml создан")

        # Добавить каждый rule
        for rule in rules:
            rule_xml = build_rule_xml(rule)
            zf.writestr(f"rules/{rule['filename']}", rule_xml)
            print(f"📄 rules/{rule['filename']} добавлен")

    zip_buffer.seek(0)
    return zip_buffer.read()

def upload_extension_to_qradar(zip_data):
    """Загрузить Extension ZIP в QRadar"""
    url = f"https://{QRADAR_IP}/api/config/extension_management/extensions"

    upload_headers = {
        "SEC": QRADAR_TOKEN,
        "Version": "12.0",
        "Accept": "application/json"
    }

    files = {
        "file": ("qradar_rules.zip", zip_data, "application/zip")
    }

    print("\n⬆️  Загружаем Extension в QRadar...")
    r = requests.post(
        url,
        headers=upload_headers,
        files=files,
        verify=False
    )
    return r.status_code, r.json() if r.text else {}

def install_extension(extension_id):
    """Установить загруженный Extension"""
    url = f"https://{QRADAR_IP}/api/config/extension_management/extensions/{extension_id}"

    install_headers = {
        "SEC": QRADAR_TOKEN,
        "Version": "12.0",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    body = {"action": "INSTALL", "overwrite": True}

    r = requests.post(
        url,
        headers=install_headers,
        json=body,
        verify=False
    )
    return r.status_code, r.json() if r.text else {}

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
    url = f"https://{QRADAR_IP}/api/system/about"
    r = requests.get(url, headers=headers, verify=False)
    if r.status_code == 200:
        info = r.json()
        print(f"✅ Connected to QRadar {info.get('external_version', '')}")
        return True
    print(f"❌ Connection failed: {r.status_code}")
    return False

def main():
    print("=" * 50)
    print("🚀 QRadar Rules Deployment via Extension ZIP")
    print("=" * 50)

    if not QRADAR_IP or not QRADAR_TOKEN:
        print("❌ Missing QRADAR_IP or QRADAR_TOKEN!")
        exit(1)

    if not check_connection():
        exit(1)

    # Создать ZIP
    print("\n📦 Создаём Extension ZIP...")
    zip_data = create_extension_zip(RULES_CONFIG)
    print(f"✅ ZIP создан ({len(zip_data)} bytes)")

    # Загрузить в QRadar
    status, response = upload_extension_to_qradar(zip_data)
    print(f"Upload status: {status}")
    print(f"Response: {json.dumps(response, indent=2)[:300]}")

    if status in [200, 201]:
        extension_id = response.get("id")
        print(f"✅ Extension загружен, ID: {extension_id}")

        # Установить
        if extension_id:
            inst_status, inst_response = install_extension(extension_id)
            if inst_status in [200, 201]:
                print(f"✅ Extension установлен!")
            else:
                print(f"❌ Install failed [{inst_status}]: {inst_response}")
    else:
        print(f"❌ Upload failed [{status}]")

    # Close reasons
    print("\n📋 Adding custom close reasons...")
    add_close_reasons()

    print("\n" + "=" * 50)
    print("⚠️  Нажми Deploy Changes в QRadar!")
    print("=" * 50)

if __name__ == "__main__":
    main()
