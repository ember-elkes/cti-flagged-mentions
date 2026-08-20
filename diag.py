import os
import requests

NOTION_HEADERS = {
    "Authorization": f"Bearer {os.environ['NOTION_TOKEN']}",
    "Notion-Version": "2026-03-11",
    "Content-Type": "application/json",
}

ACTOR_DS_ID =  "2cb4ef9d-f9e9-80f4-a0d5-000ba2963368"

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

resp = requests.get(
    f"https://api.notion.com/v1/data_sources/{ACTOR_DS_ID}",
    headers=NOTION_HEADERS, timeout=30,
)
print("Status:", resp.status_code)
for name, spec in resp.json().get("properties", {}).items():
    print(f"  {name}  ({spec['type']})")
