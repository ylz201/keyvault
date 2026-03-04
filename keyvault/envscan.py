from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from keyvault.validation import validate_key_name

DEFAULT_ENV_FILENAMES = [
    ".env",
    ".env.local",
    ".env.development",
    ".env.development.local",
    ".env.production",
    ".env.production.local",
    ".env.test",
    ".env.test.local",
]

PUBLIC_KEY_PREFIXES = (
    "NEXT_PUBLIC_",
    "VITE_",
    "PUBLIC_",
    "REACT_APP_",
)

PLACEHOLDER_VALUES = {
    "",
    "changeme",
    "change_me",
    "your_key_here",
    "example",
    "test",
    "dummy",
    "todo",
}

_SKIP_RECURSIVE_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".idea",
    ".vscode",
}

MAX_ENV_FILE_SIZE_BYTES = 1024 * 1024


@dataclass(frozen=True)
class EnvSecretCandidate:
    key: str
    value: str
    source: Path
    confidence: int
    reason: str


def _decode_dotenv_value(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1]:
        if value[0] == '"':
            try:
                decoded = json.loads(value)
                if isinstance(decoded, str):
                    return decoded
            except json.JSONDecodeError:
                return value[1:-1]
        if value[0] == "'":
            return value[1:-1]
    if " #" in value:
        return value.split(" #", 1)[0].rstrip()
    return value


def discover_env_files(
    base_dir: Path,
    explicit_files: list[str] | None = None,
    recursive: bool = False,
) -> list[Path]:
    """
    Discover dotenv-style files in a predictable, security-conscious way.

    - If explicit_files is provided, only those files are used.
    - Otherwise, scan common .env filenames in base_dir.
    - Recursive mode scans descendants for `.env*`, skipping common large/hidden dirs.
    """
    base_dir = base_dir.expanduser().resolve()

    if explicit_files:
        result: list[Path] = []
        for item in explicit_files:
            p = Path(item).expanduser()
            if not p.is_absolute():
                p = (base_dir / p).resolve()
            if p.is_file():
                result.append(p)
        return result

    if not recursive:
        result = []
        for name in DEFAULT_ENV_FILENAMES:
            p = base_dir / name
            if p.is_file():
                result.append(p.resolve())
        return result

    found: list[Path] = []
    for root, dirs, files in os.walk(base_dir):
        dirs[:] = [d for d in dirs if d not in _SKIP_RECURSIVE_DIRS and not d.startswith(".")]
        for filename in files:
            if filename.startswith(".env"):
                p = (Path(root) / filename).resolve()
                if p.is_file():
                    found.append(p)
    found.sort()
    return found


def _secret_confidence(key: str, value: str) -> tuple[int, str]:
    upper = key.upper()
    value_stripped = value.strip()
    value_lower = value_stripped.lower()

    if upper.startswith(PUBLIC_KEY_PREFIXES):
        return 0, "public variable prefix"

    score = 0
    reasons: list[str] = []

    high_patterns: list[tuple[str, int, str]] = [
        ("API_KEY", 95, "contains API_KEY"),
        ("PRIVATE_KEY", 95, "contains PRIVATE_KEY"),
        ("CLIENT_SECRET", 95, "contains CLIENT_SECRET"),
        ("ACCESS_TOKEN", 90, "contains ACCESS_TOKEN"),
        ("REFRESH_TOKEN", 90, "contains REFRESH_TOKEN"),
        ("PASSWORD", 90, "contains PASSWORD"),
        ("PASSWD", 90, "contains PASSWD"),
        ("SECRET", 85, "contains SECRET"),
        ("TOKEN", 80, "contains TOKEN"),
        ("CREDENTIAL", 80, "contains CREDENTIAL"),
        ("AUTH", 75, "contains AUTH"),
    ]

    for needle, points, reason in high_patterns:
        if needle in upper:
            score = max(score, points)
            reasons.append(reason)

    if upper.endswith("_KEY"):
        score = max(score, 75)
        reasons.append("ends with _KEY")
    if upper.endswith("_TOKEN"):
        score = max(score, 80)
        reasons.append("ends with _TOKEN")

    value_prefix_patterns: list[tuple[str, int, str]] = [
        ("sk-", 90, "value starts with sk-"),
        ("ghp_", 90, "value starts with ghp_"),
        ("xoxb-", 90, "value starts with xoxb-"),
        ("xoxp-", 90, "value starts with xoxp-"),
        ("AKIA", 90, "value starts with AKIA"),
        ("AIza", 90, "value starts with AIza"),
        ("ya29.", 90, "value starts with ya29."),
        ("eyJ", 70, "value looks like JWT"),
    ]

    for prefix, points, reason in value_prefix_patterns:
        if value_stripped.startswith(prefix):
            score = max(score, points)
            reasons.append(reason)

    if len(value_stripped) >= 24:
        score = min(100, score + 5)
        reasons.append("value length >= 24")

    if value_lower in PLACEHOLDER_VALUES:
        score = min(score, 25)
        reasons.append("placeholder value")

    if not reasons:
        reasons.append("low signal")

    reason = ", ".join(dict.fromkeys(reasons))
    return score, reason


def scan_env_files(files: list[Path], include_all: bool = False) -> list[EnvSecretCandidate]:
    """
    Parse env files and return likely secret candidates.

    Later files override earlier files for duplicate keys.
    """
    selected: dict[str, EnvSecretCandidate] = {}

    for path in files:
        try:
            if path.stat().st_size > MAX_ENV_FILE_SIZE_BYTES:
                continue
        except OSError:
            continue

        for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            if line.startswith("export "):
                line = line[7:].strip()

            key, _, value = line.partition("=")
            key = key.strip()
            value = _decode_dotenv_value(value.strip())
            if not key:
                continue

            try:
                key = validate_key_name(key)
            except ValueError:
                continue

            confidence, reason = _secret_confidence(key, value)
            if include_all:
                if confidence < 40:
                    confidence = 40
                reason = f"{reason}; included by --all"
                selected[key] = EnvSecretCandidate(
                    key=key,
                    value=value,
                    source=path,
                    confidence=confidence,
                    reason=reason,
                )
                continue

            if confidence < 70:
                continue

            selected[key] = EnvSecretCandidate(
                key=key,
                value=value,
                source=path,
                confidence=confidence,
                reason=reason,
            )

    items = list(selected.values())
    items.sort(key=lambda item: (-item.confidence, item.key))
    return items
