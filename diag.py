import os
import requests

NOTION_HEADERS = {
    "Authorization": f"Bearer {os.environ['NOTION_TOKEN']}",
    "Notion-Version": "2026-03-11",
    "Content-Type": "application/json",
}

resp = requests.post(
    "https://api.notion.com/v1/search",
    headers=NOTION_HEADERS,
    json={"filter": {"property": "object", "value": "data_source"}},
    timeout=30,
)
print("Status:", resp.status_code)
data = resp.json()
for r in data.get("results", []):
    title = r.get("title", [{}])
    name = title[0].get("plain_text", "?") if title else "?"
    print(f"{name}  ->  {r['id']}")
if not data.get("results"):
    print("No data sources visible to this integration.")
    print(data)
