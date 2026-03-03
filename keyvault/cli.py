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
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from keyvault.store import SecretStore

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
    value: str = typer.Argument(..., help="Secret value"),
    project: Optional[str] = typer.Option(None, "--project", "-p", help="Project scope (default: global)"),
    description: Optional[str] = typer.Option(None, "--desc", "-d", help="Description / notes"),
):
    """Set (create or update) a secret."""
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
    store = _get_store()
    secrets = store.list(project=project, all_scopes=all_scopes)

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
            s.masked_value(),
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
    store = _get_store()
    try:
        count = store.import_dotenv(filepath, project=project)
    except FileNotFoundError as e:
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
    store = _get_store()
    content = store.export_dotenv(project=project)

    if not content:
        console.print("[dim]No secrets to export.[/]")
        return

    if output:
        from pathlib import Path
        Path(output).write_text(content + "\n")
        console.print(f"✅ Exported to [bold]{output}[/]")
    else:
        console.print(content)


# ── INJECT ───────────────────────────────────────────────

@app.command(
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True}
)
def inject(
    ctx: typer.Context,
    project: Optional[str] = typer.Option(None, "--project", "-p", help="Include project-specific overrides"),
):
    """Execute a command with all secrets injected as environment variables.
    
    Usage: keyvault inject -- python my_script.py
    """
    if not ctx.args:
        console.print("❌ No command specified. Usage: keyvault inject -- python script.py")
        raise typer.Exit(code=1)

    store = _get_store()
    env_secrets = store.get_all_as_env(project=project)

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
    from keyvault.crypto import KEYVAULT_DIR, MASTER_KEY_FILE
    from keyvault.store import DB_FILE
    from keyvault import __version__

    panel_content = Text()
    panel_content.append(f"Version:     {__version__}\n")
    panel_content.append(f"Vault Dir:   {KEYVAULT_DIR}\n")
    panel_content.append(f"Database:    {DB_FILE}\n")
    panel_content.append(f"Master Key:  {MASTER_KEY_FILE}\n")
    panel_content.append(f"DB Exists:   {'✅' if DB_FILE.exists() else '❌'}\n")
    panel_content.append(f"Key Exists:  {'✅' if MASTER_KEY_FILE.exists() else '❌'}")

    console.print(Panel(panel_content, title="🔐 KeyVault Info", border_style="cyan"))


if __name__ == "__main__":
    app()
