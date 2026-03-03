from __future__ import annotations

import re

_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_PROJECT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def validate_key_name(key: str) -> str:
    key = (key or "").strip()
    if not _KEY_RE.match(key):
        raise ValueError(
            "Invalid secret key name. Use a valid environment variable style name "
            "(letters/numbers/underscore, not starting with a number)."
        )
    return key


def validate_project_name(project: str) -> str:
    project = (project or "").strip()
    if not project:
        raise ValueError("Project name cannot be empty.")
    if not _PROJECT_RE.match(project):
        raise ValueError(
            "Invalid project name. Use 1-64 chars: letters/numbers and . _ - (must start with alnum)."
        )
    return project


def parse_csv(value: str | None) -> list[str]:
    if not value:
        return []
    items = []
    for part in value.split(","):
        part = part.strip()
        if part:
            items.append(part)
    return items
