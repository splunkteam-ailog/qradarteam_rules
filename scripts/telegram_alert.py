import requests
import time
import os
import urllib3
urllib3.disable_warnings()

QRADAR_IP = os.environ.get("QRADAR_IP")
QRADAR_TOKEN = os.environ.get("QRADAR_TOKEN")
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN")
CHAT_ID = os.environ.get("CHAT_ID")

def get_offenses():
    headers = {
        "SEC": QRADAR_TOKEN,
        "Version": "12.0",
        "Accept": "application/json"
    }
    url = f"https://{QRADAR_IP}/api/siem/offenses"
    params = {
        "filter": "status=OPEN",
        "sort": "-start_time",
        "fields": "id,description,severity,source_network,destination_networks,event_count,start_time"
    }
    response = requests.get(url, headers=headers, params=params, verify=False)
    return response.json() if response.status_code == 200 else []

def send_telegram(message):
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    data = {
        "chat_id": CHAT_ID,
        "text": message,
        "parse_mode": "HTML"
    }
    requests.post(url, data=data)

def format_message(offense):
    severity = offense.get("severity", 0)
    if severity >= 9:
        emoji = "🔴"
        level = "CRITICAL"
    elif severity >= 7:
        emoji = "🟠"
        level = "HIGH"
    elif severity >= 5:
        emoji = "🟡"
        level = "MEDIUM"
    else:
        emoji = "🟢"
        level = "LOW"

    return (
        f"{emoji} <b>QRadar Offense - {level}</b>\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🆔 <b>ID:</b> {offense['id']}\n"
        f"📝 <b>Rule:</b> {offense.get('description', 'N/A')}\n"
        f"⚠️ <b>Severity:</b> {severity}/10\n"
        f"🌐 <b>Source:</b> {offense.get('source_network', 'N/A')}\n"
        f"🎯 <b>Destination:</b> {offense.get('destination_networks', 'N/A')}\n"
        f"📊 <b>Events:</b> {offense.get('event_count', 0)}\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🔗 <a href='https://{QRADAR_IP}/console'>Open QRadar</a>"
    )

def main():
    seen = set()
    print("🤖 Telegram Alert Bot started...")

    while True:
        try:
            offenses = get_offenses()
            for offense in offenses:
                if offense["id"] not in seen:
                    seen.add(offense["id"])
                    message = format_message(offense)
                    send_telegram(message)
                    print(f"📨 Alert sent: Offense #{offense['id']} (Severity: {offense['severity']})")
        except Exception as e:
            print(f"❌ Error: {e}")

        time.sleep(60)

if __name__ == "__main__":
    main()
