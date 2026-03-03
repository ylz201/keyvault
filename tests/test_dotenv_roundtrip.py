from __future__ import annotations


def test_dotenv_roundtrip_with_special_characters(isolated_keyvault, tmp_path):
    store_mod = isolated_keyvault["store"]
    store = store_mod.SecretStore()

    store.set("SAFE_TOKEN", "abc-123", project="p1")
    store.set("COMPLEX_TOKEN", "a b\"c'\n#x\t\\", project="p1")

    dotenv_text = store.export_dotenv(project="p1")
    assert "SAFE_TOKEN=abc-123" in dotenv_text
    assert 'COMPLEX_TOKEN=' in dotenv_text

    dotenv_file = tmp_path / ".env.roundtrip"
    dotenv_file.write_text(dotenv_text + "\n", encoding="utf-8")

    imported = store.import_dotenv(str(dotenv_file), project="p2")
    assert imported == 2
    assert store.get("SAFE_TOKEN", project="p2") == "abc-123"
    assert store.get("COMPLEX_TOKEN", project="p2") == "a b\"c'\n#x\t\\"
