import os
import io
import sys
from datetime import datetime, timezone
import trafilatura
import feedparser
import requests
import pypdf
from urllib.parse import urlparse
from common import USER_AGENT, load_json, build_alias_index, match_actors, strip_html, safe_json

# --- config (application reads config, remember) ---
TAS_NOTION_TOKEN = os.environ.get("TAS_NOTION_TOKEN")
INBOX_DS_ID = "3c14ef9d-f9e9-808d-8f48-000b3fa5e197"
ACTOR_DS_ID =  "2cb4ef9d-f9e9-80f4-a0d5-000ba2963368"
ACTORS_FILE = os.environ.get("ACTORS_FILE", "actors.json")
actors = load_json(ACTORS_FILE, [])

NOTION_HEADERS = {
    "Authorization": f"Bearer {TAS_NOTION_TOKEN}",
    "Notion-Version": "2026-03-11",
    "Content-Type": "application/json",
}

def fetch_article(url):
    """Returns (kind, payload): ("html", str) | ("pdf", bytes) | (None, None)."""
    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=30)
        resp.raise_for_status()
        
        # Extract and sanitize the content type header
        content_type = resp.headers.get("Content-Type", "").lower()
        
        # Branch based on the content type
        if "application/pdf" in content_type:
            return "pdf", resp.content
        else:
            # Fall back to HTML string processing
            return "html", resp.text
            
    except requests.exceptions.RequestException as e:
        print(f"Fetch failed for {url}: {e}", file=sys.stderr)
        return None, None


def extract_content(kind, payload):
    """Returns (title, date, text) -- any of which may be None."""
    if kind == "html":
        metadata = trafilatura.extract_metadata(payload)
        text = trafilatura.extract(payload)
        title = metadata.title if metadata else None
        date = metadata.date if metadata else None
        return title, date, text
        
    elif kind == "pdf":
        try:
            # Load bytes into an in-memory stream for pypdf
            pdf_file = io.BytesIO(payload)
            reader = pypdf.PdfReader(pdf_file)
            
            # Extract text page by page
            text_pages = []
            for page in reader.pages:
                page_text = page.extract_text()
                if page_text:
                    text_pages.append(page_text)
            text = "\n".join(text_pages) if text_pages else None
            
            # Extract title metadata with a junk-filter fallback
            title = None
            if reader.metadata and reader.metadata.title:
                raw_title = reader.metadata.title.strip()
                # Skip known automated junk titles from word processors
                if raw_title and not raw_title.startswith("Microsoft Word"):
                    title = raw_title
            
            # Intentionally skip date per the specification rule
            date = None
            
            return title, date, text

        except Exception as e:
            print(f"PDF extraction failed: {e}", file=sys.stderr)
            return None, None, None
            
    return None, None, None

def derive_vendor(url): 
        domain = urlparse(url).netloc
        return domain.removeprefix('www.')

def notion_entry_exists(url):
    resp = requests.post(
        f"https://api.notion.com/v1/data_sources/{INBOX_DS_ID}/query",
        headers=NOTION_HEADERS,
        json={"filter": {"property": "URL", "url": {"equals": url}},
            "page_size": 1},
        timeout=30,
    )
    resp.raise_for_status()
    return len(safe_json(resp, "inbox query")["results"]) > 0

def resolve_actor_ids(names):
    resolved, unresolved = [], []
    for name in names:
        resp = requests.post(
            f"https://api.notion.com/v1/data_sources/{ACTOR_DS_ID}/query",
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

def decide(matches, unresolved, text):
    # Condition 1: No matches at all
    if not matches:
        return "Needs Review", "no actors matched"
    
    # Condition 2: Some names unresolved
    if unresolved:
        # Converts list of unresolved names into a comma-separated string
        unresolved_str = ", ".join(unresolved)
        return "Needs Review", f"unresolved names: {unresolved_str}"
    
    # Condition 3: Text is thin (e.g., empty, whitespace-only, or under a certain threshold)
    # Note: Adjust the length threshold (e.g., 20 characters) to fit your actual data requirements.
    if not text or len(text.strip()) < 200:
        return "Needs Review", "extraction thin"
    
    # Default condition: All checks passed
    return "Matched", ""
def process_url(url):
    kind, payload = fetch_article(url)
    
    # Handle fetch failures gracefully
    if not payload:
        return {
            "title": None,
            "date": None,
            "text_source": derive_vendor(url),
            "resolved": [],
            "aliases_hit": "",
            "status": "Needs Review",
            "reason": "fetch failed"
        }

    title, date, text = extract_content(kind, payload)
    
    alias_index = build_alias_index(actors)
    matches = match_actors(f"{title} {text}", alias_index)
    resolved, unresolved = resolve_actor_ids([name for name, _ in matches])
    
    status, reason = decide(matches, unresolved, text)
    
    # Build comma-separated string of matched variants for the Notion column
    aliases_hit = ", ".join([variant for _, variant in matches])

    return {
        "title": title,
        "date": date,
        "text_source": derive_vendor(url),
        "resolved": resolved,
        "aliases_hit": aliases_hit,
        "status": status,
        "reason": reason,
        "url": url,
    }

def get_ticked_entries():
    url = f"https://api.notion.com/v1/data_sources/{INBOX_DS_ID}/query"
    
    # Payload targeting rows where the checkbox is marked True
    payload = {
        "filter": {
            "property": "Reprocess",  
            "checkbox": {
                "equals": True
            }
        },
        "page_size": 100
    }
    
    all_results = []
    has_more = True
    start_cursor = None
    
    while has_more:
        if start_cursor:
            payload["start_cursor"] = start_cursor
            
        try:
            resp = requests.post(url, headers=NOTION_HEADERS, json=payload, timeout=30)
            resp.raise_for_status()
            data = safe_json(resp, "fetch ticked entries")
            
            # Append this batch of pages to our main list
            all_results.extend(data.get("results", []))
            
            # Check for pagination tokens
            has_more = data.get("has_more", False)
            start_cursor = data.get("next_cursor", None)
            
        except requests.exceptions.RequestException as e:
            print(f"Failed to query ticked entries from Notion: {e}", file=sys.stderr)
            break
            
    print(f"Found {len(all_results)} entries queued for reprocessing.")
    return all_results
def reprocess():
    ticked_entries = get_ticked_entries() 
    for entry in ticked_entries:
        page_id = entry["id"]
        url = entry["properties"]["URL"]["url"]
        print(f"Reprocessing: {url}")
        try:
            # Process via the exact same rules pipeline
            result = process_url(url)
            
            # Write update back to the exact same Notion page ID
            update_entry(page_id, result)
        except Exception as e:
            print(f"Failed to reprocess page {page_id}: {e}", file=sys.stderr)

def update_entry(page_id, result):
    properties = {
        "Title": {"title": [{"text": {"content": result["title"] or result["url"]}}]},
        "Threat Actors": {"relation": [{"id": pid} for _, pid in result["resolved"]]},
        "Matched Aliases": {"rich_text": [{"text": {"content": result["aliases_hit"]}}]},
        "Source": {"rich_text": [{"text": {"content": result["text_source"]}}]},
        "Status": {"select": {"name": result["status"]}},
        "Review Reason": {"rich_text": [{"text": {"content": result["reason"]}}]},
        "Reprocess": {"checkbox": False},
        "Published Date": {"date": {"start": result["date"]} if result["date"] else None},
    }
    resp = requests.patch(
        f"https://api.notion.com/v1/pages/{page_id}",
        headers=NOTION_HEADERS,
        json={"properties": properties},
        timeout=30,
    )
    resp.raise_for_status()
    print(f"Updated entry: {result['title'] or page_id} [{result['status']}]")

def main():
<<<<<<< HEAD
    if os.environ.get("REPROCESS"):
        reprocess()
        return
    url = os.environ["CAPTURE_URL"]    
    if notion_entry_exists(url):
        print("Entry exists")
        return
    result = process_url(url)
    create_entry(url=url, **result)
=======
    def main():
        url = os.environ["CAPTURE_URL"]
        if notion_entry_exists(url):
            print("Entry exists")
            return
        result = process_url(url)
        create_entry(url=url, **result)
>>>>>>> fdf6b74488c3f3556973f99955e5f86064f0368e


if __name__ == "__main__":
    main()

