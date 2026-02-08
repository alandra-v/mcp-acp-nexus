"""Tool description sanitization for untrusted MCP servers.

This module provides sanitization functions to protect against:
- Prompt injection attacks in tool descriptions
- Misleading instructions targeting the LLM
- Malicious links or markup
- Unicode homoglyph attacks
- Overly long descriptions

Principle: Treat tool descriptions like untrusted HTML from the internet.

Usage:
    from mcp_acp.security.sanitizer import sanitize_description

    result = sanitize_description(untrusted_text)
    if result.modifications:
        # Log what was sanitized
        ...
    clean_text = result.text
"""

from __future__ import annotations

__all__ = [
    "MAX_DESCRIPTION_LENGTH",
    "SanitizationResult",
    "sanitize_description",
]

import re
import unicodedata
from dataclasses import dataclass, field

# Maximum description length (chars)
# Based on real MCP servers: most are 100-300 chars, max ~315
# 500 is generous while still preventing context waste
MAX_DESCRIPTION_LENGTH: int = 500

# Patterns that may indicate prompt injection attempts
# These are logged as warnings but NOT removed (too many false positives)
SUSPICIOUS_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "instruction_override",
        re.compile(
            r"(?i)\b(ignore|disregard|override|bypass|forget)\b.*\b(previous|above|prior|all|instructions?)\b"
        ),
    ),
    (
        "role_assumption",
        re.compile(r"(?i)\b(you are|act as|pretend|assume the role)\b"),
    ),
    (
        "system_prompt",
        re.compile(r"(?i)\b(system prompt|system message|hidden instruction)\b"),
    ),
]

# Pattern to match markdown links: [text](url)
MARKDOWN_LINK_PATTERN = re.compile(r"\[([^\]]+)\]\([^)]+\)")

# Pattern to match HTML tags: <tag> or </tag> or <tag attr="value">
HTML_TAG_PATTERN = re.compile(r"<[^>]+>")

# Pattern to match control characters (except newline, tab, carriage return)
CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


@dataclass(frozen=True, slots=True)
class SanitizationResult:
    """Result of sanitizing a description.

    Attributes:
        text: The sanitized text.
        modifications: List of modifications made (for logging).
        suspicious_patterns: List of suspicious patterns detected (for warnings).
        original_length: Original text length before sanitization.
    """

    text: str
    modifications: list[str] = field(default_factory=list)
    suspicious_patterns: list[str] = field(default_factory=list)
    original_length: int = 0


def sanitize_description(
    desc: str | None,
    max_length: int = MAX_DESCRIPTION_LENGTH,
) -> SanitizationResult:
    """Sanitize tool description from untrusted server.

    Applies the following sanitization steps:
    1. Normalize Unicode (NFKC - collapses homoglyphs)
    2. Remove control characters
    3. Normalize whitespace
    4. Strip markdown links (keep text, remove URL)
    5. Strip HTML tags
    6. Detect suspicious patterns (log warning, don't remove)
    7. Truncate to max length

    Args:
        desc: Raw description from MCP server.
        max_length: Maximum allowed length.

    Returns:
        SanitizationResult with sanitized text and modification details.
    """
    if not desc:
        return SanitizationResult(text="", original_length=0)

    original_length = len(desc)
    modifications: list[str] = []
    suspicious: list[str] = []
    text = desc

    # 1. Normalize Unicode (collapse homoglyphs like "а" -> "a")
    normalized = unicodedata.normalize("NFKC", text)
    if normalized != text:
        modifications.append("unicode_normalized")
        text = normalized

    # 2. Remove control characters (keep \n, \t, \r)
    cleaned = CONTROL_CHAR_PATTERN.sub("", text)
    if cleaned != text:
        modifications.append("control_chars_removed")
        text = cleaned

    # 3. Normalize whitespace (collapse multiple spaces/newlines)
    collapsed = " ".join(text.split())
    if collapsed != text:
        # Don't log this - too noisy, happens on almost every description
        text = collapsed

    # 4. Strip markdown links: [text](url) -> text
    if MARKDOWN_LINK_PATTERN.search(text):
        text = MARKDOWN_LINK_PATTERN.sub(r"\1", text)
        modifications.append("markdown_links_stripped")

    # 5. Strip HTML tags
    if HTML_TAG_PATTERN.search(text):
        text = HTML_TAG_PATTERN.sub("", text)
        modifications.append("html_tags_stripped")

    # 6. Detect suspicious patterns (warn only, don't remove)
    for pattern_name, pattern in SUSPICIOUS_PATTERNS:
        if pattern.search(text):
            suspicious.append(pattern_name)

    # 7. Truncate if too long
    if len(text) > max_length:
        text = text[: max_length - 3] + "..."
        modifications.append("truncated")

    return SanitizationResult(
        text=text,
        modifications=modifications,
        suspicious_patterns=suspicious,
        original_length=original_length,
    )
