"""
KeyVault CLI — Manage API keys for LLM Agents.

Usage:
    keyvault set KEY VALUE          Set a secret
    keyvault get KEY                Get a secret value
    keyvault list                   List all secrets
    keyvault delete KEY             Delete a secret
    keyvault import FILE            Import from .env file
    keyvault export                 Export as .env format
    keyvault inject -- CMD          Execute a command with secrets injected
"""

import os
import subprocess
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from keyvault.fs import format_mode_bits, write_text_secure
from keyvault.store import SecretStore
from keyvault.validation import validate_key_name, validate_project_name

app = typer.Typer(
    name="keyvault",
    help="🔐 KeyVault — Lightweight secrets manager for LLM Agents.",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()


def _get_store() -> SecretStore:
    return SecretStore()


# ── SET ──────────────────────────────────────────────────

@app.command()
def set(
    key: str = typer.Argument(..., help="Secret key name (e.g. OPENAI_API_KEY)"),
    value: str = typer.Argument(None, help="Secret value (omit to enter interactively)"),
    project: Optional[str] = typer.Option(None, "--project", "-p", help="Project scope (default: global)"),
    description: Optional[str] = typer.Option(None, "--desc", "-d", help="Description / notes"),
    stdin: bool = typer.Option(False, "--stdin", "-s", help="Read value from stdin (for piping)"),
):
    """Set (create or update) a secret.
    
    For security, prefer interactive input to avoid leaking the value
    into shell history. Omit the VALUE argument or use --stdin.
    """
    try:
        key = validate_key_name(key)
        if project is not None:
            project = validate_project_name(project)
    except ValueError as e:
        raise typer.BadParameter(str(e))

    if stdin:
        import sys
        value = sys.stdin.read().strip()
    elif value is None:
        # Interactive hidden prompt (not saved in shell history)
        value = typer.prompt("Enter secret value", hide_input=True)

    if not value:
        console.print("❌ Empty value. Aborting.")
        raise typer.Exit(code=1)

    store = _get_store()
    secret = store.set(key, value, project=project, description=description)
    scope = f"[cyan]project:{project}[/]" if project else "[green]global[/]"
    console.print(f"✅ [bold]{key}[/] saved ({scope})")


# ── GET ──────────────────────────────────────────────────

@app.command()
def get(
    key: str = typer.Argument(..., help="Secret key name"),
    project: Optional[str] = typer.Option(None, "--project", "-p", help="Project scope"),
    unmask: bool = typer.Option(False, "--unmask", "-u", help="Show full value (default: masked)"),
):
    """Get a secret value."""
    try:
        key = validate_key_name(key)
        if project is not None:
            project = validate_project_name(project)
    except ValueError as e:
        raise typer.BadParameter(str(e))

    store = _get_store()
    secret = store.get_full(key, project=project)

    if secret is None:
        # Fallback: try global if project was specified
        if project:
            secret = store.get_full(key, project=None)
            if secret:
                console.print(f"[dim](not found in project:{project}, using global)[/]")

    if secret is None:
        console.print(f"❌ [bold red]{key}[/] not found.")
        raise typer.Exit(code=1)

    if unmask:
        console.print(secret.value)
    else:
        console.print(f"[bold]{key}[/] = {secret.masked_value()}  [dim]({secret.scope_label()})[/]")


# ── LIST ─────────────────────────────────────────────────

@app.command(name="list")
def list_secrets(
    project: Optional[str] = typer.Option(None, "--project", "-p", help="Filter by project"),
    all_scopes: bool = typer.Option(False, "--all", "-a", help="Show all scopes"),
):
    """List all stored secrets."""
    try:
        if project is not None:
            project = validate_project_name(project)
    except ValueError as e:
        raise typer.BadParameter(str(e))

    store = _get_store()
    secrets = store.list_metadata(project=project, all_scopes=all_scopes)

    if not secrets:
        console.print("[dim]No secrets found. Use [bold]keyvault set KEY VALUE[/] to add one.[/]")
        return

    table = Table(title="🔐 KeyVault Secrets", border_style="dim")
    table.add_column("Key", style="bold orange1", no_wrap=True)
    table.add_column("Value", style="dim")
    table.add_column("Scope", style="cyan")
    table.add_column("Description")
    table.add_column("Updated", style="dim")

    for s in secrets:
        table.add_row(
            s.key,
            "••••••••",
            s.scope_label(),
            s.description or "",
            s.updated_at[:19],
        )

    console.print(table)


# ── DELETE ───────────────────────────────────────────────

@app.command()
def delete(
    key: str = typer.Argument(..., help="Secret key name"),
    project: Optional[str] = typer.Option(None, "--project", "-p", help="Project scope"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
):
    """Delete a secret."""
    try:
        key = validate_key_name(key)
        if project is not None:
            project = validate_project_name(project)
    except ValueError as e:
        raise typer.BadParameter(str(e))

    if not force:
        confirm = typer.confirm(f"Delete '{key}' ({('project:' + project) if project else 'global'})?")
        if not confirm:
            raise typer.Abort()

    store = _get_store()
    deleted = store.delete(key, project=project)

    if deleted:
        console.print(f"🗑️  [bold]{key}[/] deleted.")
    else:
        console.print(f"❌ [bold red]{key}[/] not found.")
        raise typer.Exit(code=1)


# ── IMPORT ───────────────────────────────────────────────

@app.command(name="import")
def import_env(
    filepath: str = typer.Argument(..., help="Path to .env file"),
    project: Optional[str] = typer.Option(None, "--project", "-p", help="Import into project scope"),
):
    """Import secrets from a .env file."""
    try:
        if project is not None:
            project = validate_project_name(project)
    except ValueError as e:
        raise typer.BadParameter(str(e))

    store = _get_store()
    try:
        count = store.import_dotenv(filepath, project=project)
    except FileNotFoundError as e:
        console.print(f"❌ {e}")
        raise typer.Exit(code=1)
    except ValueError as e:
        console.print(f"❌ {e}")
        raise typer.Exit(code=1)

    scope = f"project:{project}" if project else "global"
    console.print(f"✅ Imported [bold]{count}[/] keys into [cyan]{scope}[/] scope.")


# ── EXPORT ───────────────────────────────────────────────

@app.command()
def export(
    project: Optional[str] = typer.Option(None, "--project", "-p", help="Include project-specific overrides"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Write to file instead of stdout"),
):
    """Export secrets as .env format."""
    try:
        if project is not None:
            project = validate_project_name(project)
    except ValueError as e:
        raise typer.BadParameter(str(e))

    store = _get_store()
    content = store.export_dotenv(project=project)

    if not content:
        console.print("[dim]No secrets to export.[/]")
        return

    if output:
        from pathlib import Path
        out_path = Path(output).expanduser()
        write_text_secure(out_path, content + "\n", mode=0o600)
        mode_bits = format_mode_bits(out_path) or "unknown"
        console.print(f"✅ Exported to [bold]{out_path}[/] (mode {mode_bits})")
    else:
        import sys

        if sys.stdout.isatty():
            console.print(
                "[yellow]Warning:[/] Exporting secrets to stdout. "
                "If you redirect to a file, ensure it is owner-only (e.g. chmod 600).",
                file=sys.stderr,
            )
        console.print(content)


# ── INJECT ───────────────────────────────────────────────

@app.command(
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True}
)
def inject(
    ctx: typer.Context,
    project: Optional[str] = typer.Option(None, "--project", "-p", help="Include project-specific overrides"),
    include_global: bool = typer.Option(True, "--global/--no-global", help="Include global secrets"),
    keys: Optional[List[str]] = typer.Option(None, "--key", "-k", help="Only inject specific key(s). Repeatable."),
):
    """Execute a command with all secrets injected as environment variables.
    
    Usage: keyvault inject -- python my_script.py
    """
    try:
        if project is not None:
            project = validate_project_name(project)
        if keys:
            keys = [validate_key_name(k) for k in keys]
    except ValueError as e:
        raise typer.BadParameter(str(e))

    if not ctx.args:
        console.print("❌ No command specified. Usage: keyvault inject -- python script.py")
        raise typer.Exit(code=1)

    store = _get_store()
    env_secrets = store.get_all_as_env(project=project, include_global=include_global)
    if keys:
        missing = [k for k in keys if k not in env_secrets]
        env_secrets = {k: env_secrets[k] for k in keys if k in env_secrets}
        if missing:
            import sys

            console.print(
                f"[yellow]Warning:[/] {len(missing)} requested key(s) not found: {', '.join(missing)}",
                file=sys.stderr,
            )

    # Merge with current environment
    env = {**os.environ, **env_secrets}

    cmd = ctx.args
    console.print(f"[dim]🔑 Injecting {len(env_secrets)} secret(s) into subprocess...[/]")
    console.print(f"[dim]▶ Running: {' '.join(cmd)}[/]")

    result = subprocess.run(cmd, env=env)
    raise typer.Exit(code=result.returncode)


# ── INFO ─────────────────────────────────────────────────

@app.command()
def info():
    """Show KeyVault configuration info."""
    from keyvault.crypto import (
        get_keyvault_dir,
        get_master_key_backend,
        get_master_key_file,
        master_key_exists,
        master_key_location,
    )
    from keyvault import __version__

    vault_dir = get_keyvault_dir()
    db_file = vault_dir / "vault.db"
    master_key_file = get_master_key_file()

    panel_content = Text()
    panel_content.append(f"Version:     {__version__}\n")
    panel_content.append(f"Vault Dir:   {vault_dir} (mode {format_mode_bits(vault_dir) or 'unknown'})\n")
    panel_content.append(f"Database:    {db_file} (mode {format_mode_bits(db_file) or 'missing'})\n")
    panel_content.append(f"Key Backend: {get_master_key_backend()}\n")
    panel_content.append(f"Master Key:  {master_key_location()}\n")
    if master_key_location() != "keyring":
        panel_content.append(f"Key File:    {master_key_file} (mode {format_mode_bits(master_key_file) or 'missing'})\n")
    panel_content.append(f"DB Exists:   {'✅' if db_file.exists() else '❌'}\n")
    panel_content.append(f"Key Exists:  {'✅' if master_key_exists() else '❌'}")

    console.print(Panel(panel_content, title="🔐 KeyVault Info", border_style="cyan"))


@app.command()
def harden(
    delete_file: bool = typer.Option(
        False,
        "--delete-file",
        help="Delete the on-disk master key file after migrating to keyring (recommended).",
    ),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation prompts"),
):
    """Harden master key storage by migrating it into the OS keyring."""
    from keyvault.crypto import get_master_key_file, harden_master_key_to_keyring

    master_key_file = get_master_key_file()
    if delete_file and master_key_file.exists() and not force:
        ok = typer.confirm(
            f"Delete master key file at '{master_key_file}' after migrating to keyring?"
        )
        if not ok:
            raise typer.Abort()

    try:
        present = harden_master_key_to_keyring(delete_file=delete_file)
    except Exception as e:
        console.print(f"❌ {e}")
        raise typer.Exit(code=1)

    if present:
        console.print("✅ Master key is now available via OS keyring.")
        if delete_file and not master_key_file.exists():
            console.print("[dim]On-disk master key file removed.[/]")
    else:
        console.print("❌ Failed to migrate master key to keyring.")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
