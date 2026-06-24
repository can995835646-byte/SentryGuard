import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

GUMROAD_VERIFY_URL = "https://api.gumroad.com/v2/licenses/verify"
PRODUCT_ID = "dfnxw"
LICENSE_FILE = Path.home() / ".sentryguard" / "license.json"
VERIFY_INTERVAL_HOURS = 24


def _load_raw() -> dict | None:
    try:
        return json.loads(LICENSE_FILE.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def _save_raw(data: dict) -> None:
    LICENSE_FILE.parent.mkdir(parents=True, exist_ok=True)
    LICENSE_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def verify_with_gumroad(key: str) -> tuple[bool, str]:
    """Call Gumroad API. Returns (is_valid, message)."""
    try:
        r = requests.post(
            GUMROAD_VERIFY_URL,
            data={"product_id": PRODUCT_ID, "license_key": key.strip()},
            timeout=10,
        )
        data = r.json()
    except requests.ConnectionError:
        return False, "Network error: could not reach Gumroad."
    except requests.Timeout:
        return False, "Request timed out."
    except Exception as e:
        return False, str(e)

    if not data.get("success"):
        return False, data.get("message", "Invalid license key.")

    purchase = data.get("purchase", {})
    if purchase.get("subscription_cancelled_at") or purchase.get("subscription_ended_at"):
        return False, "Subscription has been cancelled or expired."

    return True, "OK"


def activate(key: str) -> None:
    """Verify key with Gumroad and save locally. Exits with message on failure."""
    valid, msg = verify_with_gumroad(key)
    if not valid:
        sys.exit(f"✗ Activation failed: {msg}")
    _save_raw({
        "key": key.strip(),
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "valid": True,
    })


def is_pro() -> bool:
    """Return True if a valid cached license exists. Re-verifies once per day.
    Fails open if Gumroad is unreachable (don't punish paid users for outages)."""
    data = _load_raw()
    if not data or not data.get("valid") or not data.get("key"):
        return False

    verified_at_str = data.get("verified_at", "")
    try:
        verified_at = datetime.fromisoformat(verified_at_str)
        age_hours = (datetime.now(timezone.utc) - verified_at).total_seconds() / 3600
    except ValueError:
        age_hours = float("inf")

    if age_hours >= VERIFY_INTERVAL_HOURS:
        valid, msg = verify_with_gumroad(data["key"])
        if not valid:
            if "Network error" in msg or "timed out" in msg:
                # Gumroad unreachable — keep last known state, retry next run
                return data.get("valid", False)
            _save_raw({**data, "valid": False})
            return False
        _save_raw({**data, "verified_at": datetime.now(timezone.utc).isoformat()})

    return True


def deactivate() -> None:
    """Remove the stored license key."""
    if LICENSE_FILE.exists():
        LICENSE_FILE.unlink()
