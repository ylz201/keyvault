"""
Encrypted SQLite storage engine for KeyVault.

All secret values are encrypted with Fernet before being written to disk.
The database is stored at ~/.keyvault/vault.db.
"""

import sqlite3
from datetime import datetime
from pathlib import Path

from keyvault.crypto import encrypt, decrypt, ensure_keyvault_dir, KEYVAULT_DIR
from keyvault.models import Secret


DB_FILE = KEYVAULT_DIR / "vault.db"

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS secrets (
    key         TEXT NOT NULL,
    value       TEXT NOT NULL,
    project     TEXT,
    description TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    UNIQUE(key, project)
);
"""


class SecretStore:
    """Encrypted secret storage backed by SQLite."""

    def __init__(self, db_path: Path | None = None):
        self.db_path = db_path or DB_FILE
        self._init_db()

    def _init_db(self):
        """Ensure the database and table exist."""
        ensure_keyvault_dir()
        conn = self._connect()
        conn.execute(_CREATE_TABLE)
        conn.commit()
        conn.close()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self.db_path))

    # ── CRUD ──────────────────────────────────────────────

    def set(self, key: str, value: str, project: str | None = None, description: str | None = None) -> Secret:
        """Set (create or update) a secret."""
        now = datetime.now().isoformat()
        encrypted_value = encrypt(value)

        conn = self._connect()
        cursor = conn.cursor()

        # Check if exists
        cursor.execute(
            "SELECT rowid FROM secrets WHERE key = ? AND project IS ?",
            (key, project)
        )
        existing = cursor.fetchone()

        if existing:
            cursor.execute(
                "UPDATE secrets SET value = ?, description = ?, updated_at = ? WHERE key = ? AND project IS ?",
                (encrypted_value, description, now, key, project)
            )
        else:
            cursor.execute(
                "INSERT INTO secrets (key, value, project, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (key, encrypted_value, project, description, now, now)
            )

        conn.commit()
        conn.close()

        return Secret(key=key, value=value, project=project, description=description, created_at=now, updated_at=now)

    def get(self, key: str, project: str | None = None) -> str | None:
        """Get a secret value by key. Returns None if not found."""
        conn = self._connect()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT value FROM secrets WHERE key = ? AND project IS ?",
            (key, project)
        )
        row = cursor.fetchone()
        conn.close()

        if row is None:
            return None
        return decrypt(row[0])

    def get_full(self, key: str, project: str | None = None) -> Secret | None:
        """Get a full Secret object by key."""
        conn = self._connect()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT key, value, project, description, created_at, updated_at FROM secrets WHERE key = ? AND project IS ?",
            (key, project)
        )
        row = cursor.fetchone()
        conn.close()

        if row is None:
            return None
        return Secret(
            key=row[0],
            value=decrypt(row[1]),
            project=row[2],
            description=row[3],
            created_at=row[4],
            updated_at=row[5],
        )

    def list(self, project: str | None = None, all_scopes: bool = False) -> list[Secret]:
        """List secrets. If all_scopes=True, list all regardless of project."""
        conn = self._connect()
        cursor = conn.cursor()

        if all_scopes:
            cursor.execute("SELECT key, value, project, description, created_at, updated_at FROM secrets ORDER BY project, key")
        else:
            cursor.execute(
                "SELECT key, value, project, description, created_at, updated_at FROM secrets WHERE project IS ? ORDER BY key",
                (project,)
            )

        rows = cursor.fetchall()
        conn.close()

        return [
            Secret(
                key=r[0], value=decrypt(r[1]), project=r[2],
                description=r[3], created_at=r[4], updated_at=r[5]
            )
            for r in rows
        ]

    def delete(self, key: str, project: str | None = None) -> bool:
        """Delete a secret. Returns True if a row was deleted."""
        conn = self._connect()
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM secrets WHERE key = ? AND project IS ?",
            (key, project)
        )
        deleted = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return deleted

    def get_all_as_env(self, project: str | None = None) -> dict[str, str]:
        """
        Get all secrets as a flat dict suitable for os.environ injection.
        Project-specific keys override global keys.
        """
        result: dict[str, str] = {}

        # Global secrets first
        for s in self.list(project=None):
            result[s.key] = s.value

        # Project overrides
        if project:
            for s in self.list(project=project):
                result[s.key] = s.value

        return result

    def import_dotenv(self, filepath: str, project: str | None = None) -> int:
        """Import secrets from a .env file. Returns count of imported keys."""
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {filepath}")

        count = 0
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue

            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()

            # Remove surrounding quotes
            if (value.startswith('"') and value.endswith('"')) or \
               (value.startswith("'") and value.endswith("'")):
                value = value[1:-1]

            self.set(key, value, project=project)
            count += 1

        return count

    def export_dotenv(self, project: str | None = None) -> str:
        """Export secrets as .env formatted string."""
        lines = []
        env = self.get_all_as_env(project=project)
        for key, value in sorted(env.items()):
            # Quote values that contain spaces or special chars
            if " " in value or "'" in value or '"' in value:
                value = f'"{value}"'
            lines.append(f"{key}={value}")
        return "\n".join(lines)
