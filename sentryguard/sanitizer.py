import copy
import re
from typing import List, Tuple

_CODE_BLOCK = re.compile(r"```[^`]*```", re.DOTALL)
_INLINE_CMD_CHAIN = re.compile(
    r"[^\n`]*(?:&&|\|\|)\s*(?:rm|curl|wget|nc|python|pip|bash|sh)\b[^\n`]*",
    re.IGNORECASE,
)
_BASE64_PIPE = re.compile(
    r"[^\n]*base64\s+-d\s*\|\s*(?:ba)?sh[^\n]*",
    re.IGNORECASE,
)
_SUSPICIOUS_EXTRA_KEYS = frozenset(
    {"shell_exec", "__command__", "__exec__", "run_command", "execute_shell"}
)

REDACTION = "[SENTRYGUARD: REMOVED]"


def sanitize_text(text: str) -> Tuple[str, List[str]]:
    """Strip known injection patterns from a string. Returns (clean, removed_list)."""
    removed: List[str] = []

    def _strip(pattern: re.Pattern, label: str, t: str) -> str:
        def _rep(m: re.Match) -> str:
            removed.append(f"{label}: {m.group(0)[:80]}")
            return REDACTION

        return pattern.sub(_rep, t)

    text = _strip(_CODE_BLOCK, "code_block", text)
    text = _strip(_BASE64_PIPE, "base64_pipe", text)
    text = _strip(_INLINE_CMD_CHAIN, "cmd_chain", text)
    return text, removed


def sanitize_event(event: dict) -> Tuple[dict, List[str]]:
    """Return a deep-copy of *event* with injection payloads removed.

    Second element is a list of human-readable strings describing what was removed.
    """
    event = copy.deepcopy(event)
    all_removed: List[str] = []

    for field in ("message", "title"):
        if event.get(field):
            clean, removed = sanitize_text(str(event[field]))
            event[field] = clean
            all_removed.extend(removed)

    # Remove suspicious extra keys entirely
    extra = event.get("extra")
    if isinstance(extra, dict):
        for key in list(extra.keys()):
            if key.lower() in _SUSPICIOUS_EXTRA_KEYS:
                all_removed.append(f"extra_key '{key}': {str(extra[key])[:80]}")
                del extra[key]

    # Sanitize breadcrumb messages
    breadcrumbs = event.get("breadcrumbs") or {}
    for crumb in breadcrumbs.get("values") or []:
        if crumb.get("message"):
            clean, removed = sanitize_text(str(crumb["message"]))
            crumb["message"] = clean
            all_removed.extend(removed)

    # Sanitize exception values
    exception = event.get("exception") or {}
    for exc in exception.get("values") or []:
        if exc.get("value"):
            clean, removed = sanitize_text(str(exc["value"]))
            exc["value"] = clean
            all_removed.extend(removed)

    return event, all_removed
