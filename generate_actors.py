"""Regenerate actors.json from the Notion Actor and Alias databases.

Build-time tool, run manually:

    python generate_actors.py

The regenerated actors.json is meant to be committed, so git history records
alias coverage changes over time -- this script does not run on a schedule.

Environment variables required:
  TAS_NOTION_TOKEN   Notion integration token (same one capture.py uses)

Optional environment variables:
  ACTORS_FILE     path to actors.json   (default: actors.json)
  VARIANTS_FILE   path to variants.json (default: variants.json)

Data model:
  Actor database   -- title property "Primary Name"
  Alias database   -- title property "Alias Name", select property "Status",
                       relation property "Threat Actor Primary Name" (single
                       linked actor page)

Design note: the whole actor/alias structure is built up in memory first.
Only if every Notion query and every merge step succeeds does the script
write actors.json (and it writes atomically, via a temp file + os.replace).
A partial failure -- a paginated query erroring out halfway, a malformed
page -- must not produce a half-written actors.json, since both capture.py
and collector.py trust that file completely and would silently degrade
against a truncated actor/alias list.
"""
import json
import os
import sys
import tempfile
from collections import defaultdict

import requests

from common import safe_json, get_secret

TAS_NOTION_TOKEN = get_secret("TAS_NOTION_TOKEN", "notion_token")
ACTOR_DS_ID = "2cb4ef9d-f9e9-80f4-a0d5-000ba2963368"
ALIAS_DS_ID = "2cc4ef9d-f9e9-808d-9f5e-000ba59abca4"

ACTORS_FILE = os.environ.get("ACTORS_FILE", "actors.json")
VARIANTS_FILE = os.environ.get("VARIANTS_FILE", "variants.json")

# Alias statuses that should NOT be treated as confirmed aliases.
EXCLUDED_STATUSES = set()

NOTION_HEADERS = {
    "Authorization": f"Bearer {TAS_NOTION_TOKEN}",
    "Notion-Version": "2026-03-11",
    "Content-Type": "application/json",
}

PAGE_SIZE = 100
TIMEOUT = 30


def query_data_source(ds_id, context):
    """Query a Notion data source, following has_more/next_cursor to
    exhaustion. Any HTTP or JSON error propagates -- callers must not catch
    it and carry on, since that's exactly the "half-write" this script is
    designed to avoid."""
    results = []
    cursor = None
    while True:
        body = {"page_size": PAGE_SIZE}
        if cursor:
            body["start_cursor"] = cursor
        resp = requests.post(
            f"https://api.notion.com/v1/data_sources/{ds_id}/query",
            headers=NOTION_HEADERS,
            json=body,
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        data = safe_json(resp, context)
        results.extend(data["results"])
        if data.get("has_more"):
            cursor = data.get("next_cursor")
        else:
            break
    return results


def get_title_text(page, prop_name):
    prop = page.get("properties", {}).get(prop_name, {})
    parts = prop.get("title", [])
    text = "".join(p.get("plain_text", "") for p in parts).strip()
    return text or None


def get_select_name(page, prop_name):
    prop = page.get("properties", {}).get(prop_name, {})
    select = prop.get("select")
    return select.get("name") if select else None


def get_relation_id(page, prop_name):
    prop = page.get("properties", {}).get(prop_name, {})
    relation = prop.get("relation", [])
    return relation[0]["id"] if relation else None


def build_actor_map(actor_pages):
    """{page_id: primary_name}, skipping (and warning about) actor pages
    with no readable title rather than aborting the whole run."""
    actor_map = {}
    for page in actor_pages:
        name = get_title_text(page, "Primary Name")
        if not name:
            print(f"Warning: actor page {page.get('id')} has no Primary Name, skipping", file=sys.stderr)
            continue
        actor_map[page["id"]] = name
    return actor_map


def build_alias_groups(alias_pages, actor_map):
    """Group surviving alias names by actor page ID. Returns (groups, stats)
    where stats explains how many aliases were dropped and why -- printed
    later so the skip counts are auditable, not silent."""
    groups = defaultdict(set)
    stats = {"excluded_status": 0, "no_name": 0, "no_relation": 0, "unknown_actor": 0}

    for page in alias_pages:
        alias_name = get_title_text(page, "Alias Name")
        if not alias_name:
            stats["no_name"] += 1
            print(f"Warning: alias page {page.get('id')} has no Alias Name, skipping", file=sys.stderr)
            continue

        status = get_select_name(page, "Status")
        if status in EXCLUDED_STATUSES:
            stats["excluded_status"] += 1
            continue

        actor_id = get_relation_id(page, "Threat Actor Primary Name")
        if not actor_id:
            stats["no_relation"] += 1
            print(f"Warning: alias '{alias_name}' has no linked actor, skipping", file=sys.stderr)
            continue

        if actor_id not in actor_map:
            stats["unknown_actor"] += 1
            print(f"Warning: alias '{alias_name}' links to unmapped actor page {actor_id}, skipping", file=sys.stderr)
            continue

        groups[actor_id].add(alias_name)

    return groups, stats


def build_actors_by_name(actor_map, alias_groups):
    """{canonical_name: {alias, ...}}, covering every actor page even if it
    has zero surviving aliases -- collector.py/capture.py match on the
    canonical name too, so a zero-alias actor is still a useful entry."""
    actors_by_name = {}
    for actor_id, name in actor_map.items():
        aliases = alias_groups.get(actor_id, set())
        aliases = {a for a in aliases if a.strip().lower() != name.strip().lower()}
        actors_by_name[name] = aliases
    return actors_by_name


def load_variants(path):
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def merge_variants(actors_by_name, variants):
    """Merge variants.json aliases into the matching actor (case-insensitive
    name match). A variant actor with no match in the Notion actor list is
    reported, not silently dropped -- variants.json only adds aliases to
    actors that already exist, it doesn't introduce new actors."""
    name_lookup = {name.strip().lower(): name for name in actors_by_name}

    for variant in variants:
        vname = variant.get("name")
        if not vname:
            continue
        match = name_lookup.get(vname.strip().lower())
        if match is None:
            print(f"Warning: variants.json actor '{vname}' has no matching actor in Notion, skipping its aliases", file=sys.stderr)
            continue
        for alias in variant.get("aliases", []):
            if alias.strip().lower() != match.strip().lower():
                actors_by_name[match].add(alias)


def load_existing_actors(path):
    """Like common.load_json, but silent on a missing file -- on a first
    run there's nothing to diff against yet, and that's not a warning."""
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json_atomic(path, data):
    """Write via a temp file + os.replace so a crash or interrupt mid-write
    can never leave a truncated/corrupt actors.json in place."""
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".actors_", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write("\n")
        os.replace(tmp_path, path)
    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


def print_summary(final_actors, old_actors, skip_stats):
    old_by_name = {a["name"]: set(a.get("aliases", [])) for a in old_actors}
    new_by_name = {a["name"]: set(a["aliases"]) for a in final_actors}

    added_actors = sorted(set(new_by_name) - set(old_by_name), key=str.lower)
    removed_actors = sorted(set(old_by_name) - set(new_by_name), key=str.lower)
    common_actors = set(new_by_name) & set(old_by_name)

    per_actor_changes = []
    for name in sorted(common_actors, key=str.lower):
        added = new_by_name[name] - old_by_name[name]
        removed = old_by_name[name] - new_by_name[name]
        if added or removed:
            per_actor_changes.append((name, added, removed))

    total_aliases_new = sum(len(a["aliases"]) for a in final_actors)
    total_aliases_old = sum(len(a.get("aliases", [])) for a in old_actors)

    print("=" * 60)
    print("generate_actors.py summary")
    print("=" * 60)
    if any(skip_stats.values()):
        print(
            f"Skipped: {skip_stats['excluded_status']} excluded-status, "
            f"{skip_stats['no_relation']} unlinked, "
            f"{skip_stats['unknown_actor']} unmapped-actor, "
            f"{skip_stats['no_name']} unnamed"
        )
    print(f"Actors:  {len(final_actors)} (was {len(old_actors)})")
    print(f"Aliases: {total_aliases_new} (was {total_aliases_old})")

    if added_actors:
        print(f"New actors ({len(added_actors)}): {', '.join(added_actors)}")
    if removed_actors:
        print(f"Removed actors ({len(removed_actors)}): {', '.join(removed_actors)}")
    for name, added, removed in per_actor_changes:
        if added:
            print(f"  {name}: +{len(added)} alias(es): {', '.join(sorted(added, key=str.lower))}")
        if removed:
            print(f"  {name}: -{len(removed)} alias(es): {', '.join(sorted(removed, key=str.lower))}")

    if not added_actors and not removed_actors and not per_actor_changes:
        print("No changes vs existing actors.json.")


def main():
    if not TAS_NOTION_TOKEN:
        print("Error: TAS_NOTION_TOKEN is not set.", file=sys.stderr)
        sys.exit(1)

    try:
        print("Querying actor database...")
        actor_pages = query_data_source(ACTOR_DS_ID, "actor query")
        actor_map = build_actor_map(actor_pages)
        print(f"  {len(actor_map)} actor(s) loaded.")

        print("Querying alias database...")
        alias_pages = query_data_source(ALIAS_DS_ID, "alias query")
        alias_groups, skip_stats = build_alias_groups(alias_pages, actor_map)
        print(f"  {len(alias_pages)} alias page(s) processed.")

        actors_by_name = build_actors_by_name(actor_map, alias_groups)

        variants = load_variants(VARIANTS_FILE)
        if variants:
            print(f"Merging {len(variants)} entry(ies) from {VARIANTS_FILE}...")
            merge_variants(actors_by_name, variants)

        final_actors = [
            {"name": name, "aliases": sorted(actors_by_name[name], key=str.lower)}
            for name in sorted(actors_by_name, key=str.lower)
        ]
    except requests.exceptions.RequestException as e:
        print(f"Error: Notion query failed, actors.json NOT written: {e}", file=sys.stderr)
        sys.exit(1)

    old_actors = load_existing_actors(ACTORS_FILE)
    write_json_atomic(ACTORS_FILE, final_actors)
    print_summary(final_actors, old_actors, skip_stats)
    print(f"Wrote {ACTORS_FILE}.")


if __name__ == "__main__":
    main()
