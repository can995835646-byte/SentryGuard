import re
from .models import ThreatResult

# Known Agentjacking injection patterns
_MARKDOWN_CODE_INJECTION = re.compile(
    r"```\s*(bash|sh|shell|cmd|powershell|zsh).*?```",
    re.DOTALL | re.IGNORECASE,
)
_CHAINED_COMMANDS = re.compile(r"(&&|\|\||;)\s*(rm|curl|wget|nc|python|pip|bash|sh)\b", re.IGNORECASE)
_COMMAND_CONTEXT_KEYS = re.compile(r"['\"]?(shell_exec|__command__|__exec__|run_command|execute_shell)['\"]?\s*:", re.IGNORECASE)
_ENV_EXFIL = re.compile(r"\$\{?\s*(AWS_|SECRET|TOKEN|API_KEY|PASSWORD|PRIVATE_KEY)\w*", re.IGNORECASE)
_PROMPT_OVERRIDE = re.compile(
    r"(ignore (previous|all|above)|disregard (your|all)|new instruction|you are now|forget (your|all)|system prompt)",
    re.IGNORECASE,
)

# Pattern 6: Base64-encoded shell payload piped to interpreter
# Length floor only on standalone heredoc form; pipe-to-shell form is unambiguous without it.
_BASE64_SHELL_EVAL = re.compile(
    r"(?:echo\s+['\"]?[A-Za-z0-9+/=]+['\"]?\s*\|\s*base64\s+-d\s*\|\s*(?:ba)?sh"
    r"|eval\s*\(\s*(?:echo|printf)\s+['\"]?[A-Za-z0-9+/=]+['\"]?\s*\|\s*base64\s+-d\s*\)"
    r"|base64\s+-d\s*<<<\s*['\"]?[A-Za-z0-9+/=]{8,})",
    re.IGNORECASE,
)

# Pattern 7: LLM system-prompt format injection (attacker impersonates system role)
_SYSTEM_PROMPT_INJECTION = re.compile(
    r"(?:\[SYSTEM\]\s*:"
    r"|<<SYS>>"
    r"|<\|system\|>"
    r"|<\|im_start\|>\s*system\b"
    r"|\[INST\]\s*\[SYS\]"
    r"|\bSYSTEM\s+OVERRIDE\s*:"
    r"|\bADMIN\s+(?:OVERRIDE|MODE)\s*:"
    r"|\bDEVELOPER\s+MODE\s+ENABLED\b)",
    re.IGNORECASE,
)


def _extract_text(event: dict) -> str:
    """Pull all searchable text out of a Sentry event dict."""
    parts = []
    parts.append(event.get("message") or event.get("title") or "")

    # exception values
    exception = event.get("exception") or {}
    for exc in (exception.get("values") or []):
        parts.append(exc.get("value") or "")
        parts.append(exc.get("type") or "")

    # extra / context / tags
    for key in ("extra", "contexts", "tags"):
        val = event.get(key)
        if val:
            parts.append(str(val))

    # breadcrumbs
    breadcrumbs = event.get("breadcrumbs") or {}
    for crumb in (breadcrumbs.get("values") or []):
        parts.append(crumb.get("message") or "")
        parts.append(str(crumb.get("data") or ""))

    return "\n".join(parts)


def detect(event: dict) -> ThreatResult:
    """Run all detectors against a single Sentry event and return a ThreatResult."""
    text = _extract_text(event)
    patterns_found = []
    preview_snippet = ""

    # Pattern 1: Markdown shell code block injection
    m = _MARKDOWN_CODE_INJECTION.search(text)
    if m:
        patterns_found.append("markdown_code_injection")
        if not preview_snippet:
            preview_snippet = m.group(0)[:120]

    # Pattern 2: Chained shell commands (wget, curl, rm -rf …)
    m = _CHAINED_COMMANDS.search(text)
    if m:
        patterns_found.append("chained_shell_commands")
        if not preview_snippet:
            start = max(0, m.start() - 40)
            preview_snippet = text[start: m.end() + 40]

    # Pattern 3: Special context key injection
    m = _COMMAND_CONTEXT_KEYS.search(text)
    if m:
        patterns_found.append("command_context_key")
        if not preview_snippet:
            start = max(0, m.start() - 20)
            preview_snippet = text[start: m.end() + 60]

    # Pattern 4: Environment variable exfiltration attempt
    m = _ENV_EXFIL.search(text)
    if m:
        patterns_found.append("env_var_exfiltration")
        if not preview_snippet:
            start = max(0, m.start() - 20)
            preview_snippet = text[start: m.end() + 60]

    # Pattern 5: Direct prompt override attempt
    m = _PROMPT_OVERRIDE.search(text)
    if m:
        patterns_found.append("prompt_override")
        if not preview_snippet:
            start = max(0, m.start() - 20)
            preview_snippet = text[start: m.end() + 60]

    # Pattern 6: Base64-encoded shell payload
    m = _BASE64_SHELL_EVAL.search(text)
    if m:
        patterns_found.append("base64_shell_eval")
        if not preview_snippet:
            start = max(0, m.start() - 20)
            preview_snippet = text[start: m.end() + 40]

    # Pattern 7: LLM system-prompt format injection
    m = _SYSTEM_PROMPT_INJECTION.search(text)
    if m:
        patterns_found.append("system_prompt_injection")
        if not preview_snippet:
            start = max(0, m.start() - 20)
            preview_snippet = text[start: m.end() + 60]

    # Determine threat level
    high_patterns = {
        "markdown_code_injection",
        "command_context_key",
        "chained_shell_commands",
        "base64_shell_eval",
    }
    if any(p in high_patterns for p in patterns_found):
        threat_level = "high"
    elif patterns_found:
        threat_level = "medium"
    else:
        threat_level = "clean"

    return ThreatResult(
        event_id=str(event.get("id") or event.get("eventID") or ""),
        timestamp=str(event.get("dateCreated") or event.get("timestamp") or ""),
        title=str(event.get("title") or event.get("message") or "")[:120],
        threat_level=threat_level,
        detected_patterns=patterns_found,
        payload_preview=preview_snippet.strip(),
    )
