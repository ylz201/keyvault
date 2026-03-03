"""
Encrypted SQLite storage engine for KeyVault.

Secret values are encrypted with Fernet before being written to disk.
Secret metadata (key names, project names, descriptions) is encrypted too.

Lookups use deterministic HMAC-SHA256 identifiers so plaintext metadata
does not appear in the database file.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
from datetime import datetime
from pathlib import Path

from keyvault.crypto import (
    decrypt,
    encrypt,
    ensure_keyvault_dir,
    get_keyvault_dir,
    master_key_material,
)
from keyvault.models import Secret, SecretMetadata
from keyvault.validation import validate_key_name, validate_project_name


def _default_db_file() -> Path:
    return get_keyvault_dir() / "vault.db"

_CREATE_TABLE = """
	CREATE TABLE IF NOT EXISTS secrets (
	    key_id      TEXT NOT NULL,
	    key_name    TEXT NOT NULL,
	    value       TEXT NOT NULL,
	    project_id  TEXT NOT NULL,
	    project_name TEXT,
	    description TEXT,
	    created_at  TEXT NOT NULL,
	    updated_at  TEXT NOT NULL,
	    UNIQUE(key_id, project_id)
	);
"""

_CREATE_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_secrets_project_id ON secrets(project_id);
"""

_SAFE_DOTENV_VALUE_RE = re.compile(r"^[A-Za-z0-9_@%+=:,./-]+$")


def _encode_dotenv_value(value: str) -> str:
    if value and _SAFE_DOTENV_VALUE_RE.match(value):
        return value
    return json.dumps(value, ensure_ascii=False)


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


class SecretStore:
    """Encrypted secret storage backed by SQLite."""

    def __init__(self, db_path: Path | None = None):
        self.db_path = db_path or _default_db_file()
        self._id_key = master_key_material()
        self._init_db()

    def _init_db(self):
        """Ensure the database and table exist."""
        ensure_keyvault_dir()
        migrated = False
        with self._connect() as conn:
            migrated = self._ensure_schema(conn)
            conn.execute(_CREATE_TABLE)
            conn.executescript(_CREATE_INDEXES)
            conn.commit()
        if migrated:
            # Reduce remnants of the legacy schema (best-effort).
            with self._connect() as conn:
                conn.execute("VACUUM")
        # P0 fix: restrict vault.db to owner-only
        if self.db_path.exists():
            try:
                os.chmod(self.db_path, 0o600)
            except OSError:
                pass

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        try:
            conn.execute("PRAGMA secure_delete=ON")
        except sqlite3.Error:
            pass
        return conn

    def _table_columns(self, conn: sqlite3.Connection) -> set[str]:
        return {row[1] for row in conn.execute("PRAGMA table_info(secrets)").fetchall()}

    def _table_exists(self, conn: sqlite3.Connection, name: str) -> bool:
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (name,),
        ).fetchone()
        return row is not None

    def _recover_interrupted_migration(self, conn: sqlite3.Connection) -> bool:
        """
        Recover from interrupted v1->v2 migrations.

        If migration stopped after renaming `secrets` -> `secrets_v1`, restore
        that table name so normal migration can run again.
        """
        has_secrets = self._table_exists(conn, "secrets")
        has_v1 = self._table_exists(conn, "secrets_v1")
        has_new = self._table_exists(conn, "secrets_new")

        if has_secrets:
            return False
        if has_v1 and has_new:
            conn.execute("DROP TABLE secrets_new")
            conn.execute("ALTER TABLE secrets_v1 RENAME TO secrets")
            return True
        if has_v1:
            conn.execute("ALTER TABLE secrets_v1 RENAME TO secrets")
            return True
        if has_new:
            conn.execute("ALTER TABLE secrets_new RENAME TO secrets")
            return True
        return False

    def _ensure_schema(self, conn: sqlite3.Connection) -> bool:
        """
        Ensure the current DB uses the v2 schema.

        Returns True if a migration was performed.
        """
        migrated = self._recover_interrupted_migration(conn)
        cols = self._table_columns(conn)
        if not cols:
            return migrated
        if {"key_id", "key_name", "project_id"}.issubset(cols):
            return migrated
        if {"key", "value"}.issubset(cols):
            self._migrate_v1_to_v2(conn)
            return True
        raise RuntimeError(f"Unsupported secrets table schema: {sorted(cols)}")

    def _migrate_v1_to_v2(self, conn: sqlite3.Connection) -> None:
        """
        Migrate legacy schema (plaintext key/project/description) to v2.

        - Encrypts metadata at rest (key/project/description)
        - Uses HMAC identifiers for lookups
        - Deduplicates legacy global rows caused by NULL UNIQUE behavior
        """
        started_tx = False
        if not conn.in_transaction:
            conn.execute("BEGIN IMMEDIATE")
            started_tx = True
        try:
            rows = conn.execute(
                "SELECT key, value, project, description, created_at, updated_at FROM secrets"
            ).fetchall()

            # Deduplicate by (key, project) keeping latest updated_at.
            best: dict[tuple[str, str], tuple[str, str, str | None, str | None, str, str]] = {}
            for key, value, project, description, created_at, updated_at in rows:
                key_plain = str(key)
                project_plain = "" if project in {None, ""} else str(project)
                dedupe_key = (key_plain, project_plain)
                existing = best.get(dedupe_key)
                if existing is None or str(updated_at) > existing[5]:
                    best[dedupe_key] = (
                        key_plain,
                        str(value),
                        project_plain,
                        None if description is None else str(description),
                        str(created_at),
                        str(updated_at),
                    )

            conn.execute("ALTER TABLE secrets RENAME TO secrets_v1")
            conn.execute(
                """
                CREATE TABLE secrets_new (
                    key_id       TEXT NOT NULL,
                    key_name     TEXT NOT NULL,
                    value        TEXT NOT NULL,
                    project_id   TEXT NOT NULL,
                    project_name TEXT,
                    description  TEXT,
                    created_at   TEXT NOT NULL,
                    updated_at   TEXT NOT NULL,
                    UNIQUE(key_id, project_id)
                );
                """
            )

            for key_plain, value_cipher, project_plain, desc_plain, created_at, updated_at in best.values():
                key_id = self._key_id(key_plain)
                project_id = self._project_id(project_plain)
                key_name_enc = encrypt(key_plain)
                project_name_enc = encrypt(project_plain) if project_plain else None
                desc_enc = encrypt(desc_plain) if desc_plain else None

                conn.execute(
                    """
                    INSERT INTO secrets_new
                        (key_id, key_name, value, project_id, project_name, description, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        key_id,
                        key_name_enc,
                        value_cipher,
                        project_id,
                        project_name_enc,
                        desc_enc,
                        created_at,
                        updated_at,
                    ),
                )

            conn.execute("DROP TABLE secrets_v1")
            conn.execute("ALTER TABLE secrets_new RENAME TO secrets")
            if started_tx:
                conn.commit()
        except Exception:
            if started_tx and conn.in_transaction:
                conn.rollback()
            raise

    def _hmac_hex(self, label: str, data: str) -> str:
        msg = f"{label}:{data}".encode("utf-8")
        return hmac.new(self._id_key, msg, hashlib.sha256).hexdigest()

    def _key_id(self, key: str) -> str:
        return self._hmac_hex("key", key)

    def _project_id(self, project: str) -> str:
        return self._hmac_hex("project", project)

    @staticmethod
    def _decrypt_optional(ciphertext: str | None) -> str | None:
        if not ciphertext:
            return None
        return decrypt(ciphertext)

    # ── CRUD ──────────────────────────────────────────────

    def set(self, key: str, value: str, project: str | None = None, description: str | None = None) -> Secret:
        """Set (create or update) a secret."""
        key = validate_key_name(key)
        if project == "":
            project = None
        elif project is not None:
            project = validate_project_name(project)

        now = datetime.now().isoformat()
        key_id = self._key_id(key)
        project_plain = project or ""
        project_id = self._project_id(project_plain)

        encrypted_value = encrypt(value)
        key_name_enc = encrypt(key)
        project_name_enc = encrypt(project_plain) if project_plain else None
        desc_enc = encrypt(description) if description else None

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO secrets
                    (key_id, key_name, value, project_id, project_name, description, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(key_id, project_id) DO UPDATE SET
                    key_name = excluded.key_name,
                    value = excluded.value,
                    project_name = excluded.project_name,
                    description = excluded.description,
                    updated_at = excluded.updated_at
                """,
                (
                    key_id,
                    key_name_enc,
                    encrypted_value,
                    project_id,
                    project_name_enc,
                    desc_enc,
                    now,
                    now,
                ),
            )
            conn.commit()

        return Secret(key=key, value=value, project=project, description=description, created_at=now, updated_at=now)

    def get(self, key: str, project: str | None = None) -> str | None:
        """Get a secret value by key. Returns None if not found."""
        key = validate_key_name(key)
        if project == "":
            project = None
        elif project is not None:
            project = validate_project_name(project)

        key_id = self._key_id(key)
        project_plain = project or ""
        project_id = self._project_id(project_plain)
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT value FROM secrets WHERE key_id = ? AND project_id = ?",
                (key_id, project_id)
            )
            row = cursor.fetchone()

        if row is None:
            return None
        return decrypt(row[0])

    def get_full(self, key: str, project: str | None = None) -> Secret | None:
        """Get a full Secret object by key."""
        key = validate_key_name(key)
        if project == "":
            project = None
        elif project is not None:
            project = validate_project_name(project)

        key_id = self._key_id(key)
        project_plain = project or ""
        project_id = self._project_id(project_plain)
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT key_name, value, project_name, description, created_at, updated_at FROM secrets WHERE key_id = ? AND project_id = ?",
                (key_id, project_id)
            )
            row = cursor.fetchone()

        if row is None:
            return None
        return Secret(
            key=decrypt(row[0]),
            value=decrypt(row[1]),
            project=self._decrypt_optional(row[2]),
            description=self._decrypt_optional(row[3]),
            created_at=row[4],
            updated_at=row[5],
        )

    def list_metadata(self, project: str | None = None, all_scopes: bool = False) -> list[SecretMetadata]:
        """List secret metadata without decrypting values."""
        if project == "":
            project = None
        elif project is not None:
            project = validate_project_name(project)

        with self._connect() as conn:
            cursor = conn.cursor()
            if all_scopes:
                cursor.execute(
                    "SELECT key_name, project_name, description, created_at, updated_at FROM secrets"
                )
            else:
                project_plain = project or ""
                project_id = self._project_id(project_plain)
                cursor.execute(
                    "SELECT key_name, project_name, description, created_at, updated_at FROM secrets WHERE project_id = ?",
                    (project_id,),
                )
            rows = cursor.fetchall()

        items = [
            SecretMetadata(
                key=decrypt(r[0]),
                project=self._decrypt_optional(r[1]),
                description=self._decrypt_optional(r[2]),
                created_at=r[3],
                updated_at=r[4],
            )
            for r in rows
        ]
        items.sort(key=lambda s: (s.project or "", s.key))
        return items

    def list(self, project: str | None = None, all_scopes: bool = False) -> list[Secret]:
        """List secrets. If all_scopes=True, list all regardless of project."""
        if project == "":
            project = None
        elif project is not None:
            project = validate_project_name(project)

        with self._connect() as conn:
            cursor = conn.cursor()

            if all_scopes:
                cursor.execute("SELECT key_name, value, project_name, description, created_at, updated_at FROM secrets")
            else:
                project_plain = project or ""
                project_id = self._project_id(project_plain)
                cursor.execute(
                    "SELECT key_name, value, project_name, description, created_at, updated_at FROM secrets WHERE project_id = ?",
                    (project_id,)
                )

            rows = cursor.fetchall()

        items = [
            Secret(
                key=decrypt(r[0]),
                value=decrypt(r[1]),
                project=self._decrypt_optional(r[2]),
                description=self._decrypt_optional(r[3]),
                created_at=r[4],
                updated_at=r[5],
            )
            for r in rows
        ]
        items.sort(key=lambda s: (s.project or "", s.key))
        return items

    def delete(self, key: str, project: str | None = None) -> bool:
        """Delete a secret. Returns True if a row was deleted."""
        key = validate_key_name(key)
        if project == "":
            project = None
        elif project is not None:
            project = validate_project_name(project)

        key_id = self._key_id(key)
        project_plain = project or ""
        project_id = self._project_id(project_plain)
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM secrets WHERE key_id = ? AND project_id = ?",
                (key_id, project_id)
            )
            deleted = cursor.rowcount > 0
            conn.commit()
        return deleted

    def get_all_as_env(self, project: str | None = None, include_global: bool = True) -> dict[str, str]:
        """
        Get all secrets as a flat dict suitable for os.environ injection.
        Project-specific keys override global keys.
        """
        if project == "":
            project = None
        elif project is not None:
            project = validate_project_name(project)

        result: dict[str, str] = {}

        # Global secrets first
        if include_global:
            for s in self.list(project=None):
                result[s.key] = s.value

        # Project overrides
        if project:
            for s in self.list(project=project):
                result[s.key] = s.value

        return result

    def import_dotenv(self, filepath: str, project: str | None = None) -> int:
        """Import secrets from a .env file. Returns count of imported keys."""
        if project == "":
            project = None
        elif project is not None:
            project = validate_project_name(project)

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

            # Handle `export KEY=VALUE` format
            if line.startswith("export "):
                line = line[7:]

            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            value = _decode_dotenv_value(value)

            if not key:
                continue

            key = validate_key_name(key)
            self.set(key, value, project=project)
            count += 1

        return count

    def export_dotenv(self, project: str | None = None) -> str:
        """Export secrets as .env formatted string."""
        lines = []
        env = self.get_all_as_env(project=project)
        for key, value in sorted(env.items()):
            lines.append(f"{key}={_encode_dotenv_value(value)}")
        return "\n".join(lines)
