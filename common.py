"""
Threat actor mention collector.


Stateless by design: before creating a mention, the script asks WordPress
itself whether an entry with the same source_url already exists, so it's
safe to re-run on a schedule (cron, GitHub Actions, etc.) with no local
state file to manage or lose.

"""

import json
import os
import re
import sys



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
        aliases = [canonical] + actor.get("aliases", [])
        for alias in aliases:
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

def get_secret(name, config_key=None):
    if name in os.environ:
        return os.environ[name]

    appdata_dir = os.environ.get("APPDATA")
    if appdata_dir:
        config_path = os.path.join(os.environ["APPDATA"], "cti-capture", "config.json")
    else:
        config_path = r"C:\Users\HP\AppData\Roaming\cti-capture\config.json"
    if appdata_dir and config_key and os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config_data = json.load(f)
                if config_key in config_data:
                    return config_data[config_key]
        except (json.JSONDecodeError, IOError) as e:
            raise RuntimeError(f"Config file {config_path} exists but could not be read: {e}") from e
    error_msg = (
        f"Error: {name} not found in environment or in "
        f"{config_path} (key: {config_key})"
    )
    raise KeyError(error_msg)    
