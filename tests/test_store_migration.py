from __future__ import annotations

import sqlite3


def test_migrate_global_null_project_dedup(isolated_keyvault):
    crypto = isolated_keyvault["crypto"]
    store_mod = isolated_keyvault["store"]

    crypto.ensure_keyvault_dir()
    db_path = crypto.get_keyvault_dir() / "vault.db"

    # Legacy schema (project nullable; UNIQUE won't prevent NULL duplicates in SQLite)
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        """
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
    )

    c1 = crypto.encrypt("v1")
    c2 = crypto.encrypt("v2")
    c3 = crypto.encrypt("v3")

    conn.execute(
        "INSERT INTO secrets (key, value, project, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        ("OPENAI_API_KEY", c1, None, None, "2020-01-01T00:00:00", "2020-01-01T00:00:00"),
    )
    conn.execute(
        "INSERT INTO secrets (key, value, project, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        ("OPENAI_API_KEY", c2, None, None, "2020-01-02T00:00:00", "2020-01-02T00:00:00"),
    )
    conn.execute(
        "INSERT INTO secrets (key, value, project, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        ("OPENAI_API_KEY", c3, "", None, "2020-01-03T00:00:00", "2020-01-03T00:00:00"),
    )
    conn.commit()
    conn.close()

    store = store_mod.SecretStore(db_path=db_path)

    conn = sqlite3.connect(str(db_path))
    rows = conn.execute(
        "SELECT key_id, project_id, updated_at FROM secrets WHERE key_id = ? AND project_id = ?",
        (store._key_id("OPENAI_API_KEY"), store._project_id("")),
    ).fetchall()
    conn.close()

    assert len(rows) == 1
    assert rows[0][2] == "2020-01-03T00:00:00"
    assert store.get("OPENAI_API_KEY", project=None) == "v3"

    # Plaintext key name should not be present in the DB file after migration + VACUUM.
    assert b"OPENAI_API_KEY" not in db_path.read_bytes()


def test_recovers_from_interrupted_migration_with_temp_tables(isolated_keyvault):
    crypto = isolated_keyvault["crypto"]
    store_mod = isolated_keyvault["store"]

    crypto.ensure_keyvault_dir()
    db_path = crypto.get_keyvault_dir() / "vault.db"

    conn = sqlite3.connect(str(db_path))
    conn.execute(
        """
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
    )
    conn.execute(
        "INSERT INTO secrets (key, value, project, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        ("OPENAI_API_KEY", crypto.encrypt("v1"), None, None, "2020-01-01T00:00:00", "2020-01-01T00:00:00"),
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
    conn.commit()
    conn.close()

    store = store_mod.SecretStore(db_path=db_path)
    assert store.get("OPENAI_API_KEY", project=None) == "v1"

    conn = sqlite3.connect(str(db_path))
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    conn.close()
    assert "secrets" in tables
    assert "secrets_v1" not in tables
    assert "secrets_new" not in tables
