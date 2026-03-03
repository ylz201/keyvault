from __future__ import annotations

import os
import tempfile
from pathlib import Path


def write_text_secure(path: Path | str, data: str, mode: int = 0o600) -> None:
    """
    Write text data to a file with restrictive permissions.

    - Writes via a temporary file then replaces atomically
    - Attempts to enforce `mode` on both temp and final file
    """
    path = Path(path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        try:
            os.fchmod(fd, mode)
        except OSError:
            pass

        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass

        os.replace(tmp_path, path)
        try:
            os.chmod(path, mode)
        except OSError:
            pass
    finally:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        except OSError:
            pass


def format_mode_bits(path: Path) -> str | None:
    try:
        st = path.stat()
    except OSError:
        return None
    return oct(st.st_mode & 0o777)
