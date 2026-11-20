"""Output helpers for STYX-RECON."""

from __future__ import annotations

import json
import re

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]")
MAX_DISPLAY_LENGTH = 512


def sanitize(value: object, limit: int = MAX_DISPLAY_LENGTH) -> str:
    """Make an untrusted value safe for rich terminal rendering.

    Control characters are removed and long values are truncated. Rich markup
    is neutralized separately by wrapping this text in ``rich.text.Text``.
    """
    text = _CONTROL_RE.sub("", str(value))
    if len(text) > limit:
        return text[: limit - 1] + "…"
    return text


def print_json(data: dict) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False))
