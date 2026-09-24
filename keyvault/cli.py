"""Trusted administrator CLI. Agents must use keyvault-gateway or the MCP bridge.

This CLI intentionally retains plaintext export/get for the vault owner. It is
not an authorization boundary and must not be installed with vault access in an
untrusted agent sandbox.
"""
from __future__ import annotations
from pathlib import Path
from typing import List, Optional
import subprocess
import sys
import typer
from rich.console import Console
from rich.table import Table
from keyvault.store import SecretStore
from keyvault.validation import validate_key_name, validate_project_name
from keyvault.fs import write_text_secure, format_mode_bits
from keyvault.envscan import discover_env_files, scan_env_files
from keyvault.process_env import injection_environment

app = typer.Typer(name="keyvault", help="KeyVault administrator tools (not agent tools)", add_completion=False, no_args_is_help=True)
console = Console()

def _get_store():
    return SecretStore()

def _scope(project):
    return validate_project_name(project) if project is not None else None

@app.command()
def set(key: str, value: Optional[str] = typer.Argument(None),
        project: Optional[str] = typer.Option(None, "--project", "-p"),
        description: Optional[str] = typer.Option(None, "--desc", "-d"),
        stdin: bool = typer.Option(False, "--stdin", "-s")):
    """Save a credential; prefer hidden input, never chat or a command argument."""
    key = validate_key_name(key); project = _scope(project)
    value = sys.stdin.read().rstrip("\r\n") if stdin else value
    if value is None:
        value = typer.prompt("Enter secret value", hide_input=True)
    if not value:
        raise typer.BadParameter("Empty values are not allowed")
    _get_store().set(key, value, project=project, description=description)
    console.print("Secret saved")

@app.command()
def get(key: str, project: Optional[str] = typer.Option(None, "--project", "-p"),
        unmask: bool = typer.Option(False, "--unmask", "-u")):
    """ADMIN: exact-scope retrieval. No automatic global fallback."""
    value = _get_store().get(validate_key_name(key), project=_scope(project))
    if value is None:
        raise typer.Exit(1)
    # No Rich markup interpretation of secret strings.
    print(value if unmask else "********")

@app.command(name="list")
def list_secrets(project: Optional[str] = typer.Option(None, "--project", "-p"),
                 all_scopes: bool = typer.Option(False, "--all", "-a")):
    """List metadata only."""
    table = Table("Key", "Scope", "Updated")
    for item in _get_store().list_metadata(project=_scope(project), all_scopes=all_scopes):
        table.add_row(item.key, item.scope_label(), item.updated_at)
    console.print(table)

@app.command()
def delete(key: str, project: Optional[str] = typer.Option(None, "--project", "-p"),
           force: bool = typer.Option(False, "--force", "-f")):
    """ADMIN: remove a stored credential; upstream revocation is separate."""
    key = validate_key_name(key); project = _scope(project)
    if not force and not typer.confirm("Delete this stored credential?"):
        raise typer.Abort()
    if not _get_store().delete(key, project=project):
        raise typer.Exit(1)
    console.print("Deleted locally; upstream revocation was not attempted")

@app.command(name="import")
def import_env(filepath: str, project: Optional[str] = typer.Option(None, "--project", "-p")):
    """ADMIN: import a trusted dotenv file."""
    count = _get_store().import_dotenv(filepath, project=_scope(project))
    console.print(f"Imported {count} keys")

@app.command(name="scan-env")
def scan_env(project: Optional[str] = typer.Option(None, "--project", "-p"),
             file: Optional[List[str]] = typer.Option(None, "--file"),
             recursive: bool = typer.Option(False, "--recursive", "-r"),
             root: str = typer.Option(".", "--root"),
             include_all: bool = typer.Option(False, "--all"),
             apply: bool = typer.Option(False, "--apply/--dry-run"),
             force: bool = typer.Option(False, "--force", "-y")):
    """ADMIN: preview candidates; --apply explicitly enables writes."""
    project = _scope(project)
    directory = Path(root).expanduser()
    if not directory.is_dir():
        raise typer.BadParameter("Invalid root directory")
    files = discover_env_files(directory, explicit_files=file, recursive=recursive)
    if not files:
        raise typer.BadParameter("No env files found")
    candidates = scan_env_files(files, include_all=include_all)
    table = Table("Key", "Value", "Confidence", "Source")
    for item in candidates:
        table.add_row(item.key, "********", str(item.confidence), str(item.source))
    console.print(table)
    if not apply:
        console.print("Dry run mode; no keys were imported.")
        return
    if not force and not typer.confirm(f"Import {len(candidates)} keys?"):
        raise typer.Abort()
    store = _get_store()
    for item in candidates:
        store.set(item.key, item.value, project=project, description=f"Imported by scan-env from {item.source.name}")
    console.print(f"Imported {len(candidates)} keys")

@app.command()
def export(project: Optional[str] = typer.Option(None, "--project", "-p"),
           output: Optional[str] = typer.Option(None, "--output", "-o")):
    """ADMIN: plaintext export. Never expose this command to the model."""
    content = _get_store().export_dotenv(project=_scope(project))
    if output:
        write_text_secure(Path(output).expanduser(), content + "\n", mode=0o600)
        console.print("Exported to owner-only file")
    else:
        print("Warning: plaintext administrator export", file=sys.stderr)
        print(content)

@app.command(context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def inject(ctx: typer.Context, project: Optional[str] = typer.Option(None, "--project", "-p"),
           include_global: bool = typer.Option(False, "--global/--no-global"),
           keys: Optional[List[str]] = typer.Option(None, "--key", "-k")):
    """ADMIN ONLY: selected keys into a trusted subprocess. This is NOT isolation."""
    if not ctx.args or not keys:
        raise typer.BadParameter("Supply explicit --key entries and a trusted command after --")
    try:
        env = injection_environment(_get_store(), [validate_key_name(k) for k in keys], _scope(project), include_global)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from None
    print("Administrator subprocess injection; not an agent sandbox", file=sys.stderr)
    raise typer.Exit(subprocess.run(ctx.args, env=env, check=False).returncode)

@app.command()
def info():
    """Show storage configuration, never key material."""
    from keyvault.crypto import get_keyvault_dir, get_master_key_backend, master_key_location
    directory = get_keyvault_dir()
    console.print({"directory": str(directory), "mode": format_mode_bits(directory),
                   "backend": get_master_key_backend(), "key_location": master_key_location()})

@app.command()
def harden(delete_file: bool = typer.Option(False, "--delete-file"),
           force: bool = typer.Option(False, "--force", "-f")):
    """Verify and migrate the master key to keyring before removing any file key."""
    from keyvault.crypto import harden_master_key_to_keyring
    if delete_file and not force and not typer.confirm("Remove the file key after verified migration?"):
        raise typer.Abort()
    harden_master_key_to_keyring(delete_file=delete_file)
    console.print("Master key migration verified")

if __name__ == "__main__":
    app()
