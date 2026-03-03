from __future__ import annotations

import os
import stat
from pathlib import Path


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def test_export_output_is_owner_only(isolated_keyvault, tmp_path):
    store = isolated_keyvault["store"].SecretStore()
    store.set("OPENAI_API_KEY", "sk-test", project="proj")

    out = tmp_path / ".env"
    isolated_keyvault["cli"].export(project="proj", output=str(out))

    assert out.exists()
    assert _mode(out) == 0o600

