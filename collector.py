"""
Threat actor mention collector.

Fetches RSS feeds (vendor blogs, news aggregators, Google Alerts), matches
article titles/summaries against a threat-actor alias list, and posts new
matches to WordPress as "Flagged Mention" entries via the REST API.

Requires the "CTI Flagged Mentions" plugin (cti-flagged-mentions.php) to be
active on the WordPress site.

Stateless by design: before creating a mention, the script asks WordPress
itself whether an entry with the same source_url already exists, so it's
safe to re-run on a schedule (cron, GitHub Actions, etc.) with no local
state file to manage or lose.

Environment variables required:
  WP_BASE_URL      e.g. https://yourcti.site  (no trailing slash needed)
  WP_USER          WordPress username
  WP_APP_PASSWORD  WordPress Application Password
                    (Users -> Profile -> Application Passwords in wp-admin)

Optional environment variables:
  FEEDS_FILE   path to feeds.json  (default: feeds.json)
  ACTORS_FILE  path to actors.json (default: actors.json)
"""

import json
import os
import re
import sys
from datetime import datetime, timezone

import feedparser
import requests

WP_BASE_URL = os.environ["WP_BASE_URL"].rstrip("/")
WP_USER = os.environ["WP_USER"]
WP_APP_PASSWORD = os.environ["WP_APP_PASSWORD"]

FEEDS_FILE = os.environ.get("FEEDS_FILE", "feeds.json")
ACTORS_FILE = os.environ.get("ACTORS_FILE", "actors.json")

WP_API = f"{WP_BASE_URL}/wp-json/wp/v2"
MENTION_ENDPOINT = f"{WP_API}/flagged_mention"
ACTOR_TAX_ENDPOINT = f"{WP_API}/mention_actor"
STATUS_TAX_ENDPOINT = f"{WP_API}/mention_status"

AUTH = (WP_USER, WP_APP_PASSWORD)
TIMEOUT = 30

# Some blogs/CDNs block requests that don't look like a real browser.
# Bot-identifying agent strings (e.g. "MyBot/1.0") are often flagged more
# aggressively by WAFs than a generic browser string, so we mimic Chrome.
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"


def load_json(path, default):
    if not os.path.exists(path):
        print(f"Warning: {path} not found, using empty default.", file=sys.stderr)
        return default
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def build_alias_index(actors):
    """
    actors.json format:
    [
      {"name": "APT29", "aliases": ["APT29", "Cozy Bear", "Midnight Blizzard", "NOBELIUM"]}
    ]
    Word-boundary, case-insensitive matching -- good enough for an MVP and
    avoids matching "APT1" inside an unrelated word.
    """
    index = []
    for actor in actors:
        canonical = actor["name"]
        for alias in actor.get("aliases", [canonical]):
            pattern = re.compile(r"\b" + re.escape(alias) + r"\b", re.IGNORECASE)
            index.append((pattern, canonical, alias))
    return index


def match_actors(text, alias_index):
    """Returns [(canonical_name, alias_that_matched), ...], one entry per actor."""
    found = {}
    for pattern, canonical, alias in alias_index:
        if canonical not in found and pattern.search(text):
            found[canonical] = alias
    return list(found.items())


def strip_html(text):
    return re.sub(r"<[^<]+?>", "", text or "")


def safe_json(resp, context=""):
    """resp.json(), but with useful diagnostics if the body isn't valid JSON.
    A 2xx status with a non-JSON body usually means a bot-challenge or
    interstitial page from a WAF/security layer rather than a real API
    response -- this surfaces what actually came back instead of just
    crashing on an opaque JSONDecodeError."""
    try:
        return resp.json()
    except ValueError:
        snippet = resp.text[:200].replace("\n", " ")
        label = f" from {context}" if context else ""
        print(f"Non-JSON response{label} (HTTP {resp.status_code}): {snippet}", file=sys.stderr)
        raise


def mention_exists(source_url):
    resp = requests.get(
        MENTION_ENDPOINT,
        params={"source_url": source_url, "status": "any", "per_page": 1},
        auth=AUTH,
        timeout=TIMEOUT,
    )
    resp.raise_for_status()
    return len(safe_json(resp, "mention_exists")) > 0


def get_or_create_term(endpoint, name, cache):
    if name in cache:
        return cache[name]
    resp = requests.get(endpoint, params={"search": name, "per_page": 100}, auth=AUTH, timeout=TIMEOUT)
    resp.raise_for_status()
    for term in safe_json(resp, "term search"):
        if term["name"].lower() == name.lower():
            cache[name] = term["id"]
            return term["id"]
    resp = requests.post(endpoint, json={"name": name}, auth=AUTH, timeout=TIMEOUT)
    resp.raise_for_status()
    term_id = safe_json(resp, "term create")["id"]
    cache[name] = term_id
    return term_id


def create_flagged_mention(entry, matches, actor_cache, status_cache):
    actor_ids = [get_or_create_term(ACTOR_TAX_ENDPOINT, name, actor_cache) for name, _ in matches]
    status_id = get_or_create_term(STATUS_TAX_ENDPOINT, "New", status_cache)
    alias_hit = matches[0][1]

    payload = {
        "title": (entry.get("title") or "Untitled")[:200],
        "status": "draft",  # keeps it out of any public queries
        "mention_actor": actor_ids,
        "mention_status": [status_id],
        "meta": {
            "source_name": entry.get("source_name", ""),
            "source_url": entry.get("link", ""),
            "matched_alias": alias_hit,
            "snippet": strip_html(entry.get("summary", ""))[:500],
            "found_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        },
    }
    resp = requests.post(MENTION_ENDPOINT, json=payload, auth=AUTH, timeout=TIMEOUT)
    resp.raise_for_status()
    return safe_json(resp, "create mention")


def main():
    feeds = load_json(FEEDS_FILE, [])
    actors = load_json(ACTORS_FILE, [])
    if not actors:
        print("No actors loaded -- nothing to match against. Check actors.json.", file=sys.stderr)
        return
    if not feeds:
        print("No feeds loaded -- nothing to check. Check feeds.json.", file=sys.stderr)
        return

    alias_index = build_alias_index(actors)
    actor_cache, status_cache = {}, {}
    created, checked = 0, 0

    for feed in feeds:
        parsed = feedparser.parse(feed["url"], agent=USER_AGENT)
        status = parsed.get("status")

        if status and status >= 400:
            print(f"Warning: '{feed.get('name', feed['url'])}' returned HTTP {status}", file=sys.stderr)
            continue

        if parsed.bozo and not parsed.entries:
            reason = parsed.get("bozo_exception", "unknown error")
            print(f"Warning: could not parse '{feed.get('name', feed['url'])}': {reason}", file=sys.stderr)
            continue

        for entry in parsed.entries:
            link = entry.get("link", "")
            if not link:
                continue
            checked += 1

            text_blob = f"{entry.get('title', '')} {entry.get('summary', '')}"
            matches = match_actors(text_blob, alias_index)
            if not matches:
                continue

            try:
                if mention_exists(link):
                    continue
                entry["source_name"] = feed.get("name") or parsed.feed.get("title", "")
                create_flagged_mention(entry, matches, actor_cache, status_cache)
                created += 1
                print(f"Flagged: {entry.get('title')} -> {[m[0] for m in matches]}")
            except requests.exceptions.RequestException as e:
                print(f"Failed on {link}: {e}", file=sys.stderr)

    print(f"Done. Checked {checked} articles across {len(feeds)} feed(s), flagged {created} new mention(s).")


if __name__ == "__main__":
    main()
