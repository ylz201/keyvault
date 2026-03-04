from __future__ import annotations


def test_scan_env_imports_high_confidence_keys_only(isolated_keyvault, tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join(
            [
                "OPENAI_API_KEY=sk-super-secret-1234567890",
                "DEBUG=true",
                "NEXT_PUBLIC_API_URL=https://example.com",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    cli = isolated_keyvault["cli"]
    store_mod = isolated_keyvault["store"]

    cli.scan_env(
        project="scanproj",
        file=[str(env_file)],
        recursive=False,
        root=str(tmp_path),
        include_all=False,
        apply=True,
        force=True,
    )

    store = store_mod.SecretStore()
    assert store.get("OPENAI_API_KEY", project="scanproj") == "sk-super-secret-1234567890"
    assert store.get("DEBUG", project="scanproj") is None


def test_scan_env_dry_run_does_not_import(isolated_keyvault, tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("OPENAI_API_KEY=sk-dry-run-123456\n", encoding="utf-8")

    cli = isolated_keyvault["cli"]
    store_mod = isolated_keyvault["store"]

    cli.scan_env(
        project="scanproj",
        file=[str(env_file)],
        recursive=False,
        root=str(tmp_path),
        include_all=False,
        apply=False,
        force=True,
    )

    store = store_mod.SecretStore()
    assert store.get("OPENAI_API_KEY", project="scanproj") is None
