import os
import sys
from datetime import datetime, timezone
import trafilatura
import feedparser
import requests
from urllib.parse import urlparse
from common import USER_AGENT, load_json, build_alias_index, match_actors, strip_html, safe_json

# --- config (application reads config, remember) ---
NOTION_TOKEN = os.environ["NOTION_TOKEN"]
INBOX_DS_ID = "3c14ef9df9e980aaba1ad597ac99021e"
ACTOR_DS_ID = "2cb4ef9df9e98008a652f38f5a908101"
ACTORS_FILE = os.environ.get("ACTORS_FILE", "actors.json")
actors = load_json(ACTORS_FILE, [])

NOTION_HEADERS = {
    "Authorization": f"Bearer {NOTION_TOKEN}",
    "Notion-Version": "2026-03-11",
    "Content-Type": "application/json",
}

def fetch_article(url):
    """GET the page. Returns HTML string on success, None on any failure."""
    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=30)
        resp.raise_for_status()
        return resp.text
    except requests.exceptions.RequestException as e:
        print(f"Fetch failed for {url}: {e}", file=sys.stderr)
        return None

def extract_content(html):
    """Returns (title, date, text) -- any of which may be None."""
    metadata = trafilatura.extract_metadata(html)
    text = trafilatura.extract(html)
    title = metadata.title if metadata else None
    date = metadata.date if metadata else None
    return title, date, text

def derive_vendor(url): 
        domain = urlparse(url).netloc
        return domain.removeprefix('www.')

def notion_entry_exists(url):
    resp = requests.post(
        f"https://api.notion.com/v1/data_sources/3c14ef9df9e980aaba1ad597ac99021e/query",
        headers=NOTION_HEADERS,
        json={"filter": {"property": "URL", "url": {"equals": url}},
            "page_size": 1},
        timeout=30,
    )
    resp.raise_for_status()
    return len(safe_json(resp, "inbox query")["results"]) > 0# rung 5, piece 1
def resolve_actor_ids(names):
    resolved, unresolved = [], []
    for name in names:
        resp = requests.post(
            f"https://api.notion.com/v1/data_sources/3c14ef9df9e980aaba1ad597ac99021e/query",
            headers=NOTION_HEADERS,
            json={"filter": {"property": "Primary Name", "title": {"equals": name}},
                "page_size": 1},
            timeout=30,
        )
        resp.raise_for_status()
        results = safe_json(resp, f"actor lookup {name}")["results"]
        if results:
            resolved.append((name, results[0]["id"]))
        else:
            unresolved.append(name)
    return resolved, unresolved
def create_entry(url, title, date, text_source, resolved, aliases_hit, status, reason):
    properties = {
        "Title": {"title": [{"text": {"content": title or url}}]},
        "URL": {"url": url},
        "Threat Actors": {"relation": [{"id": pid} for _, pid in resolved]},
        "Matched Aliases": {"rich_text": [{"text": {"content": aliases_hit}}]},
        "Source": {"rich_text": [{"text": {"content": text_source}}]},
        "Status": {"select": {"name": status}},
    }
    if date:
        properties["Published Date"] = {"date": {"start": date}}
    if reason:
        properties["Review Reason"] = {"rich_text": [{"text": {"content": reason}}]}

    resp = requests.post(
        "https://api.notion.com/v1/pages",
        headers=NOTION_HEADERS,
        json={"parent": {"data_source_id": INBOX_DS_ID}, "properties": properties},
        timeout=30,
    )
    resp.raise_for_status()
    print(f"Created entry: {title or url} [{status}]")     

if __name__ == "__main__":
    html = fetch_article("https://www.tenable.com/blog/what-to-know-about-cyberav3ngers-the-irgc-linked-group-targeting-critical-infrastructure")
    if html:
        title, date, text = extract_content(html)
        print(f"Title: {title}")
        print(f"Date:  {date}")
        print(f"Text:  {(text or '')[:200]}")
    threat_match = f"{title} {text}"

    alias_index = build_alias_index(actors)
    matches = match_actors(threat_match, alias_index)

print(f"matches:    {matches}")



    
