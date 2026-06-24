import json
import sys
from datetime import date
from pathlib import Path

import requests

SENTRY_BASE = "https://sentry.io/api/0"
FREE_LIMIT = 100
FREE_DAILY_CALLS = 3

_USAGE_FILE = Path.home() / ".sentryguard" / "usage.json"


def _get_today_count() -> int:
    try:
        data = json.loads(_USAGE_FILE.read_text(encoding="utf-8"))
        if data.get("date") == str(date.today()):
            return data.get("count", 0)
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return 0


def _increment_today_count() -> int:
    count = _get_today_count() + 1
    _USAGE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _USAGE_FILE.write_text(
        json.dumps({"date": str(date.today()), "count": count}),
        encoding="utf-8",
    )
    return count


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def verify_connection(org: str, token: str) -> None:
    """Raise SystemExit with a clear message if credentials are invalid."""
    url = f"{SENTRY_BASE}/organizations/{org}/"
    try:
        r = requests.get(url, headers=_headers(token), timeout=10)
    except requests.ConnectionError:
        sys.exit("✗ Network error: could not reach sentry.io. Check your internet connection.")
    except requests.Timeout:
        sys.exit("✗ Request timed out. Try again.")

    if r.status_code == 401:
        sys.exit("✗ Authentication failed. Check your Sentry API token.")
    if r.status_code == 403:
        sys.exit("✗ Permission denied. Make sure your token has org:read scope.")
    if r.status_code == 404:
        sys.exit(f"✗ Organization '{org}' not found. Check the org slug.")
    if not r.ok:
        sys.exit(f"✗ Sentry API error {r.status_code}: {r.text[:200]}")


def fetch_events(org: str, token: str, project: str | None, limit: int, pro: bool) -> list:
    """Fetch error events from Sentry. Enforces free-tier limits."""
    effective_limit = limit if pro else min(limit, FREE_LIMIT)

    if not pro:
        count = _increment_today_count()
        if count > FREE_DAILY_CALLS:
            sys.exit(
                f"✗ Free tier allows {FREE_DAILY_CALLS} scans per day. "
                "Activate your Pro license with: sentryguard activate <key>"
            )

    params: dict = {"limit": min(effective_limit, 100)}
    if project:
        params["project"] = project

    url = f"{SENTRY_BASE}/organizations/{org}/issues/"
    events = []
    fetched = 0

    while url and fetched < effective_limit:
        try:
            r = requests.get(url, headers=_headers(token), params=params, timeout=15)
        except requests.RequestException as e:
            sys.exit(f"✗ Network error while fetching events: {e}")

        if not r.ok:
            sys.exit(f"✗ Sentry API error {r.status_code}: {r.text[:200]}")

        page = r.json()
        if not isinstance(page, list):
            break

        for issue in page:
            if fetched >= effective_limit:
                break
            # Enrich with latest event detail for richer text content
            events.append(_enrich(issue, org, token))
            fetched += 1

        # Follow pagination
        url = r.links.get("next", {}).get("url")
        params = {}  # params already encoded in next URL

    return events


def _enrich(issue: dict, org: str, token: str) -> dict:
    """Fetch the latest raw event for an issue to get breadcrumbs/extra context."""
    issue_id = issue.get("id")
    if not issue_id:
        return issue
    try:
        url = f"{SENTRY_BASE}/issues/{issue_id}/events/latest/"
        r = requests.get(url, headers=_headers(token), timeout=10)
        if r.ok:
            detail = r.json()
            # Merge top-level issue fields (title, id) into the detail dict
            detail.setdefault("title", issue.get("title"))
            detail.setdefault("id", issue_id)
            return detail
    except requests.RequestException:
        pass
    return issue
