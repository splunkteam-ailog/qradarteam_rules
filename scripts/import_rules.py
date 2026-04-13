import requests
import os
import json
import zipfile
import io
import base64
import urllib3
urllib3.disable_warnings()

QRADAR_IP = os.environ.get("QRADAR_IP")
QRADAR_TOKEN = os.environ.get("QRADAR_TOKEN")
GITHUBTOKEN = os.environ.get("GITHUBTOKEN")
GITHUB_REPO = "splunkteam-ailog/qradarteam_rules"
GITHUB_BRANCH = "main"

qradar_headers = {
    "SEC": QRADAR_TOKEN,
    "Version": "12.0",
    "Accept": "application/json"
}

github_headers = {
    "Authorization": f"token {GITHUBTOKEN}",
    "Accept": "application/vnd.github.v3+json"
}

RULES = [
    {
        "id": 1,
        "filename": "01_new_user_created.xml",
        "name": "WIN - New Local User Account Created",
        "notes": "MITRE T1136 - Detects creation of new local user accounts. EventID 4720",
        "severity": 6,
        "credibility": 8,
        "relevance": 8,
        "qid": "5000880",
    },
    {
        "id": 2,
        "filename": "02_user_added_to_admins.xml",
        "name": "WIN - User Added to Privileged Group",
        "notes": "MITRE T1098 - User added to Administrators group. EventID 4732",
        "severity": 8,
        "credibility": 9,
        "relevance": 9,
        "qid": "5000895",
    },
    {
        "id": 3,
        "filename": "03_brute_force.xml",
        "name": "WIN - Brute Force Attack Detected",
        "notes": "MITRE T1110 - Multiple failed logins from same IP. EventID 4625",
        "severity": 9,
        "credibility": 8,
        "relevance": 9,
        "qid": "5000791",
    },
    {
        "id": 4,
        "filename": "04_success_after_bruteforce.xml",
        "name": "WIN - Successful Login After Brute Force",
        "notes": "MITRE T1110 - Successful login following brute force. EventID 4624",
        "severity": 10,
        "credibility": 9,
        "relevance": 10,
        "qid": "5000790",
    },
    {
        "id": 5,
        "filename": "05_user_account_deleted.xml",
        "name": "WIN - User Account Deleted",
        "notes": "MITRE T1531 - User account deletion detected. EventID 4726",
        "severity": 7,
        "credibility": 8,
        "relevance": 7,
        "qid": "5000882",
    },
    {
        "id": 6,
        "filename": "06_audit_policy_changed.xml",
        "name": "WIN - Audit Policy Modified",
        "notes": "MITRE T1562 - Audit policy modification detected. EventID 4719",
        "severity": 8,
        "credibility": 9,
        "relevance": 8,
        "qid": "5000869",
    },
    {
        "id": 7,
        "filename": "07_new_service_installed.xml",
        "name": "WIN - New Service Installed",
        "notes": "MITRE T1543 - New Windows service installation. EventID 7045",
        "severity": 7,
        "credibility": 7,
        "relevance": 8,
        "qid": "5001003",
    },
    {
        "id": 8,
        "filename": "08_event_log_cleared.xml",
        "name": "WIN - Security Event Log Cleared",
        "notes": "MITRE T1070 - Security event log was cleared. EventID 1102",
        "severity": 10,
        "credibility": 10,
        "relevance": 10,
        "qid": "5000789",
    },
    {
        "id": 9,
        "filename": "09_login_outside_hours.xml",
        "name": "WIN - Login Outside Business Hours",
        "notes": "MITRE T1078 - Login detected outside business hours. EventID 4624",
        "severity": 6,
        "credibility": 6,
        "relevance": 7,
        "qid": "5000790",
    },
    {
        "id": 10,
        "filename": "10_lateral_movement.xml",
        "name": "WIN - Lateral Movement Detected",
        "notes": "MITRE T1021 - Single IP accessing multiple hosts. EventID 4624",
        "severity": 9,
        "credibility": 8,
        "relevance": 9,
        "qid": "5000790",
    }
]

def build_rule_xml(rule):
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<rule name="{rule['name']}" id="-1" type="EVENT" enabled="true" owner="admin"
      origin="USER" base_capacity="0" base_host_id="0"
      average_capacity="0" capacity_timestamp="0">
  <notes>{rule['notes']}</notes>
  <groups>
    <group name="Windows" />
  </groups>
  <testDefinitions>
    <testGroup uid="1" groupop="AND">
      <test id="1" uid="1" override_id="15000" enabled="true"
            name="when the event QID is contained in the following list"
            requiredCapabilities="">
        <parameter name="QIDList" id="1" type="STRING"
                   value="{rule['qid']}" operator="CONTAINEDIN"/>
      </test>
    </testGroup>
  </testDefinitions>
  <actions>
    <action type="SETPROPERTY" enabled="true">
      <parameter name="credibility" value="{rule['credibility']}"/>
      <parameter name="severity" value="{rule['severity']}"/>
      <parameter name="relevance" value="{rule['relevance']}"/>
    </action>
    <action type="OFFENSE" enabled="true">
      <parameter name="offensemapping" value="SOURCE_IP"/>
      <parameter name="offensename" value="{rule['name']}"/>
    </action>
  </actions>
</rule>"""

def build_manifest():
    contents = "\n".join([
        f'    <content type="CUSTOM_RULE" name="{r["name"]}" '
        f'file="rules/{r["filename"]}"/>'
        for r in RULES
    ])
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<manifest>
  <name>QRadarTeam Windows Security Rules</name>
  <version>1.0</version>
  <author>splunkteam-ailog</author>
  <description>10 Custom Windows Security Detection Rules - MITRE ATT&amp;CK</description>
  <contents>
{contents}
  </contents>
</manifest>"""

def create_zip():
    print("\n📦 Создаём Extension ZIP...")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.xml", build_manifest())
        print("  ✅ manifest.xml")
        for rule in RULES:
            zf.writestr(f"rules/{rule['filename']}", build_rule_xml(rule))
            print(f"  ✅ rules/{rule['filename']}")
    buf.seek(0)
    data = buf.read()
    print(f"✅ ZIP создан ({len(data)} bytes)")
    return data

def upload_zip_to_github(zip_data):
    print("\n📤 Загружаем ZIP в GitHub...")
    filename = "exports/qradar_rules.zip"
    url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{filename}"

    r = requests.get(url, headers=github_headers)
    sha = r.json().get("sha") if r.status_code == 200 else None

    payload = {
        "message": "Auto-update: QRadar rules deployment",
        "content": base64.b64encode(zip_data).decode("utf-8"),
        "branch": GITHUB_BRANCH
    }
    if sha:
        payload["sha"] = sha

    r = requests.put(url, headers=github_headers, json=payload)
    if r.status_code in [200, 201]:
        print("✅ ZIP загружен в GitHub: exports/qradar_rules.zip")
        return True
    else:
        print(f"❌ GitHub upload failed [{r.status_code}]: {r.text[:200]}")
        return False

def deploy_zip_to_qradar(zip_data):
    print("\n⬆️  Деплоим в QRadar...")
    url = f"https://{QRADAR_IP}/api/config/extension_management/extensions"
    upload_headers = {
        "SEC": QRADAR_TOKEN,
        "Version": "12.0",
        "Accept": "application/json"
    }
    files = {"file": ("qradar_rules.zip", zip_data, "application/zip")}
    r = requests.post(url, headers=upload_headers, files=files, verify=False)
    print(f"Upload status: {r.status_code}")

    if r.status_code not in [200, 201]:
        print(f"❌ Upload failed: {r.text[:300]}")
        return False

    ext_id = r.json().get("id")
    print(f"✅ Extension загружен, ID: {ext_id}")

    install_url = f"https://{QRADAR_IP}/api/config/extension_management/extensions/{ext_id}"
    install_headers = {
        "SEC": QRADAR_TOKEN,
        "Version": "12.0",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    r = requests.post(
        install_url,
        headers=install_headers,
        json={"action": "INSTALL", "overwrite": True},
        verify=False
    )
    if r.status_code in [200, 201]:
        print("✅ Extension установлен в QRadar!")
        return True
    else:
        print(f"❌ Install failed [{r.status_code}]: {r.text[:300]}")
        return False

def add_close_reasons():
    print("\n📋 Adding custom close reasons...")
    for reason in ["True-Positive", "False-Positive"]:
        url = f"https://{QRADAR_IP}/api/siem/offense_closing_reasons"
        r = requests.post(
            url,
            headers=qradar_headers,
            params={"reason": reason},
            verify=False
        )
        if r.status_code == 201:
            print(f"  ✅ Added: {reason}")
        else:
            print(f"  ⚠️  Already exists: {reason}")

def check_connection():
    url = f"https://{QRADAR_IP}/api/system/about"
    r = requests.get(url, headers=qradar_headers, verify=False)
    if r.status_code == 200:
        print(f"✅ Connected to QRadar {r.json().get('external_version', '')}")
        return True
    print(f"❌ Cannot connect: {r.status_code}")
    return False

def main():
    print("=" * 55)
    print("🚀 QRadar Rules: GitHub → QRadar Auto Deploy")
    print("=" * 55)

    if not QRADAR_IP or not QRADAR_TOKEN:
        print("❌ Missing QRADAR_IP or QRADAR_TOKEN!")
        exit(1)

    if not check_connection():
        exit(1)

    zip_data = create_zip()
    
    if GITHUBTOKEN:
        upload_zip_to_github(zip_data)
    else:
        print("⚠️  GITHUBTOKEN не задан — пропускаем загрузку в GitHub")

    deploy_zip_to_qradar(zip_data)
    add_close_reasons()

    print("\n" + "=" * 55)
    print("⚠️  Нажми Deploy Changes в QRadar!")
    print("=" * 55)

if __name__ == "__main__":
    main()
