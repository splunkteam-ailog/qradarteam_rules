import requests
import os
import base64
import zipfile
import io
import json
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
        "name": "WIN - New Local User Account Created",
        "notes": "MITRE T1136 - New user account created. EventID 4720",
        "event_name": "User Account Created",
        "severity": 6,
        "credibility": 8,
        "relevance": 8,
        "low_level_category": 4015,
    },
    {
        "name": "WIN - User Added to Privileged Group",
        "notes": "MITRE T1098 - User added to Administrators group. EventID 4732",
        "event_name": "User Added to Security Group",
        "severity": 8,
        "credibility": 9,
        "relevance": 9,
        "low_level_category": 4015,
    },
    {
        "name": "WIN - Brute Force Attack Detected",
        "notes": "MITRE T1110 - Multiple failed logins. EventID 4625",
        "event_name": "Brute Force Login",
        "severity": 9,
        "credibility": 8,
        "relevance": 9,
        "low_level_category": 4002,
    },
    {
        "name": "WIN - Successful Login After Brute Force",
        "notes": "MITRE T1110 - Successful login after brute force. EventID 4624",
        "event_name": "Login After Brute Force",
        "severity": 10,
        "credibility": 9,
        "relevance": 10,
        "low_level_category": 4002,
    },
    {
        "name": "WIN - User Account Deleted",
        "notes": "MITRE T1531 - User account deleted. EventID 4726",
        "event_name": "User Account Deleted",
        "severity": 7,
        "credibility": 8,
        "relevance": 7,
        "low_level_category": 4015,
    },
    {
        "name": "WIN - Audit Policy Modified",
        "notes": "MITRE T1562 - Audit policy changed. EventID 4719",
        "event_name": "Audit Policy Changed",
        "severity": 8,
        "credibility": 9,
        "relevance": 8,
        "low_level_category": 4019,
    },
    {
        "name": "WIN - New Service Installed",
        "notes": "MITRE T1543 - New service installed. EventID 7045",
        "event_name": "New Service Installed",
        "severity": 7,
        "credibility": 7,
        "relevance": 8,
        "low_level_category": 4019,
    },
    {
        "name": "WIN - Security Event Log Cleared",
        "notes": "MITRE T1070 - Event log cleared. EventID 1102",
        "event_name": "Event Log Cleared",
        "severity": 10,
        "credibility": 10,
        "relevance": 10,
        "low_level_category": 4019,
    },
    {
        "name": "WIN - Login Outside Business Hours",
        "notes": "MITRE T1078 - Login outside hours. EventID 4624",
        "event_name": "After Hours Login",
        "severity": 6,
        "credibility": 6,
        "relevance": 7,
        "low_level_category": 4002,
    },
    {
        "name": "WIN - Lateral Movement Detected",
        "notes": "MITRE T1021 - Lateral movement. EventID 4624",
        "event_name": "Lateral Movement",
        "severity": 9,
        "credibility": 8,
        "relevance": 9,
        "low_level_category": 4002,
    }
]

def get_or_create_qid(rule):
    """Найти или создать QID для rule"""
    url = f"https://{QRADAR_IP}/api/data_classification/qid_records"
    params = {
        "filter": f'name="{rule["event_name"]}"',
        "Range": "0-5"
    }
    r = requests.get(url, headers=qradar_headers, params=params, verify=False)

    if r.status_code == 200 and r.json():
        qid = r.json()[0]["qid"]
        print(f"  📌 Found QID {qid} for: {rule['event_name']}")
        return qid

    # Создать новый QID
    create_url = f"https://{QRADAR_IP}/api/data_classification/qid_records"
    create_headers = {
        "SEC": QRADAR_TOKEN,
        "Version": "12.0",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    payload = {
        "name": rule["event_name"],
        "description": rule["notes"],
        "severity": rule["severity"],
        "low_level_category_id": rule["low_level_category"]
    }
    r = requests.post(
        create_url,
        headers=create_headers,
        json=payload,
        verify=False
    )
    if r.status_code in [200, 201]:
        qid = r.json()["qid"]
        print(f"  ✅ Created QID {qid} for: {rule['event_name']}")
        return qid
    else:
        print(f"  ⚠️  Using default QID for: {rule['event_name']}")
        return 67500128  # fallback QID

def build_inner_rule_xml(rule, qid):
    """Создать внутренний XML rule (точный формат QRadar 7.5)"""
    return f"""<rule id="-1" enabled="true" buildingBlock="false" roleDefinition="false" type="EVENT" scope="LOCAL" owner="admin"><name>{rule['name']}</name><notes>{rule['notes']}</notes><testDefinitions><test id="19" name="com.q1labs.semsources.cre.tests.QID_Test" uid="0" group="jsp.qradar.rulewizard.condition.page.group.event" groupId="3" requiredCapabilities="EventViewer.RULECREATION|SURVEILLANCE.RULECREATION"><text>when the event QID is one of the following QIDs</text><parameter id="1"><initialText>QIDs</initialText><selectionLabel>Browse or Search for QIDs below.</selectionLabel><userOptions format="CustomizeParameter-QID.jsp" source="class" method="com.q1labs.sem.ui.semservices.UISemServices.getQidsByLowLevelCategory" multiselect="true"/><userSelection>{qid}</userSelection><userSelectionTypes>property</userSelectionTypes><userSelectionId>{qid}</userSelectionId></parameter></test></testDefinitions><actions><alterMetric metric="setSeverity" operation="setSeverity" value="{rule['severity']}"/><alterMetric metric="setCredibility" operation="setCredibility" value="{rule['credibility']}"/><alterMetric metric="setRelevance" operation="setRelevance" value="{rule['relevance']}"/></actions><responses referenceMap="false" referenceMapOfSets="false" referenceMapOfMaps="false" referenceTable="false" referenceMapRemove="false" referenceMapOfSetsRemove="false" referenceMapOfMapsRemove="false" referenceTableRemove="false"><newevent name="{rule['name']}" description="{rule['notes']}" severity="{rule['severity']}" credibility="{rule['credibility']}" relevance="{rule['relevance']}" describeOffense="false" overrideOffenseName="false" contributeOffenseName="false" qid="{qid}" forceOffenseCreation="false" offenseMapping="0" lowLevelCategory="{rule['low_level_category']}"/></responses></rule>"""

def build_content_xml(rule, qid):
    """Создать outer XML в точном формате QRadar export"""
    inner_xml = build_inner_rule_xml(rule, qid)
    rule_data_b64 = base64.b64encode(inner_xml.encode("utf-8")).decode("utf-8")

    return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<content>
    <qradarversion>2021.6.14.20251017194912</qradarversion>
    <custom_rule>
        <origin>USER</origin>
        <flags>0</flags>
        <rule_data>{rule_data_b64}</rule_data>
        <rule_type>0</rule_type>
        <id>-1</id>
    </custom_rule>
    <offense_type>
        <database>common</database>
        <legacy>true</legacy>
        <nva_name>by-attacker</nva_name>
        <composite>false</composite>
        <custom>false</custom>
        <name>BY_ATTACKER</name>
        <limiter_string>ATTACKER</limiter_string>
        <default_label>Source IP</default_label>
        <id>0</id>
        <property_name>sourceIP</property_name>
    </offense_type>
    <qidmap>
        <severity>{rule['severity']}</severity>
        <lowlevelcategory>{rule['low_level_category']}</lowlevelcategory>
        <reverseip>false</reverseip>
        <qid>{qid}</qid>
        <ratethreshold>0</ratethreshold>
        <rateinterval>0</rateinterval>
        <qdescription>{rule['notes']}</qdescription>
        <catpipename>Echo</catpipename>
        <ratelongwindow>0</ratelongwindow>
        <qname>{rule['name']}</qname>
        <rateshortwindow>0</rateshortwindow>
        <id>-1</id>
    </qidmap>
</content>"""

def create_zip(rules_with_qids):
    print("\n📦 Создаём правильный ZIP для QRadar...")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # 1. Твои правила
        for i, (rule, qid) in enumerate(rules_with_qids, 1):
            filename = f"{i:02d}_{rule['name'].replace(' ', '_')}.xml"
            zf.writestr(filename, build_content_xml(rule, qid))
            print(f"  ✅ Добавлено в архив: {filename}")
        
        # 2. Ультра-простой МАНИФЕСТ (строгий формат для QRadar 7.5)
        manifest = '<?xml version="1.0" encoding="UTF-8"?><metadata><task-version>1.0</task-version><name>GitHub_Rules_Pack</name><description>Windows Security Rules</description><version>1.0.0</version><author>GITHUB</author></metadata>'
        
        zf.writestr("manifest.xml", manifest)
        
    buf.seek(0)
    data = buf.read()
    print(f"✅ ZIP готов к деплою ({len(data)} bytes)")
    return data
def upload_to_github(zip_data):
    """Загрузить ZIP в GitHub"""
    print("\n📤 Загружаем в GitHub...")
    url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/exports/qradar_rules.zip"
    
    # Сначала проверяем, существует ли файл, чтобы получить его SHA (нужно для обновления)
    r = requests.get(url, headers=github_headers)
    sha = r.json().get("sha") if r.status_code == 200 else None

    payload = {
        "message": "Auto-update: QRadar rules deployment with manifest",
        "content": base64.b64encode(zip_data).decode("utf-8"),
        "branch": GITHUB_BRANCH
    }
    if sha:
        payload["sha"] = sha

    r = requests.put(url, headers=github_headers, json=payload)
    if r.status_code in [200, 201]:
        print("✅ ZIP загружен в GitHub")
    else:
        print(f"❌ GitHub error [{r.status_code}]: {r.text[:200]}")
def deploy_to_qradar(zip_data):
    """Задеплоить ZIP в QRadar"""
    print("\n⬆️  Деплоим в QRadar...")
    url = f"https://{QRADAR_IP}/api/config/extension_management/extensions"
    
    # 1. Загрузка файла (POST)
    files = {"file": ("qradar_rules.zip", zip_data, "application/zip")}
    # Мы не передаем Content-Type в заголовках здесь, requests сам выставит multipart/form-data
    r = requests.post(url, headers=qradar_headers, files=files, verify=False)
    print(f"Upload status: {r.status_code}")

    if r.status_code not in [200, 201]:
        print(f"❌ Upload failed: {r.text[:300]}")
        return False

    ext_id = r.json().get("id")
    print(f"✅ Загружен ID: {ext_id}")

    # 2. Установка (Активация) расширения
    # ВАЖНО: Параметры action_type и overwrite передаем в URL
    install_url = f"{url}/{ext_id}?action_type=INSTALL&overwrite=true"
    
    install_headers = {
        "SEC": QRADAR_TOKEN,
        "Version": "12.0",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    # Отправляем POST с пустым телом, так как параметры уже в URL
    r = requests.post(
        install_url,
        headers=install_headers,
        verify=False
    )

    if r.status_code in [200, 201, 202]:
        print("✅ Extension успешно отправлен на установку!")
        return True
    else:
        # Если INSTALL не прошел, пробуем UPDATE (на случай, если расширение уже есть)
        if r.status_code == 422:
            print("  🔄 Попытка обновления (UPDATE)...")
            update_url = f"{url}/{ext_id}?action_type=UPDATE&overwrite=true"
            r = requests.post(update_url, headers=install_headers, verify=False)
            if r.status_code in [200, 201, 202]:
                print("✅ Extension успешно обновлен!")
                return True

        print(f"❌ Install failed [{r.status_code}]: {r.text[:300]}")
        return False
def add_close_reasons():
    print("\n📋 Close reasons...")
    for reason in ["True-Positive", "False-Positive"]:
        url = f"https://{QRADAR_IP}/api/siem/offense_closing_reasons"
        r = requests.post(
            url, headers=qradar_headers,
            params={"reason": reason}, verify=False
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
    print("🚀 QRadar Rules Auto Deploy - Exact Format")
    print("=" * 55)

    if not QRADAR_IP or not QRADAR_TOKEN:
        print("❌ Missing secrets!")
        exit(1)

    if not check_connection():
        exit(1)

    # Получить QIDs
    print("\n🔍 Getting QIDs...")
    rules_with_qids = []
    for rule in RULES:
        qid = get_or_create_qid(rule)
        rules_with_qids.append((rule, qid))

    # Создать ZIP
    zip_data = create_zip(rules_with_qids)

    # Загрузить в GitHub
    if GITHUBTOKEN:
        upload_to_github(zip_data)
    else:
        print("⚠️  GITHUBTOKEN не задан")

    # Задеплоить в QRadar
    deploy_to_qradar(zip_data)

    # Close reasons
    add_close_reasons()

    print("\n" + "=" * 55)
    print("⚠️  Нажми Deploy Changes в QRadar!")
    print("=" * 55)

if __name__ == "__main__":
    main()
