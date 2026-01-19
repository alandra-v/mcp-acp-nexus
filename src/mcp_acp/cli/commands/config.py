"""Config command group for mcp-acp CLI.

Provides configuration management subcommands.
"""

from __future__ import annotations

__all__ = ["config"]

import json
import shutil
import sys
from pathlib import Path

import click

from mcp_acp.config import AppConfig
from mcp_acp.utils.cli import edit_json_loop, get_editor, show_editor_hints
from mcp_acp.utils.config import (
    get_audit_log_path,
    get_backend_log_path,
    get_client_log_path,
    get_config_history_path,
    get_config_path,
    get_system_log_path,
)
from mcp_acp.utils.history_logging import log_config_updated

from ..styling import style_error, style_header, style_success


def _load_raw_config(config_path: Path) -> dict[str, object]:
    """Load raw JSON from config file without Pydantic defaults."""
    with open(config_path, encoding="utf-8") as f:
        result: dict[str, object] = json.load(f)
        return result


def _is_default(raw_config: dict[str, object], *keys: str) -> bool:
    """Check if a config path is missing from raw file (using default).

    Args:
        raw_config: Raw JSON dict from file.
        *keys: Path to the value (e.g., "hitl", "timeout_seconds").

    Returns:
        True if the key path is missing from raw config.
    """
    current: object = raw_config
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return True
        current = current[key]
    return False


def _default_marker() -> str:
    """Return styled (default) marker."""
    return click.style(" (default)", dim=True)


@click.group()
def config() -> None:
    """Configuration management commands.

    \b
    Editor selection for 'config edit' (in order):
      1. $EDITOR environment variable
      2. $VISUAL environment variable
      3. Falls back to 'notepad' (Windows) or 'vi' (macOS/Linux)

    \b
    Common editor commands:
      vim/vi:  Esc (normal mode), :wq (save+exit), :q! (exit no save)
      nano:    Ctrl+O Enter (save), Ctrl+X (exit)
      VS Code: Cmd/Ctrl+S (save), close tab to finish
    """
    pass


@config.command("show")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def config_show(as_json: bool) -> None:
    """Display current configuration.

    Loads configuration from the OS-appropriate location.
    Values marked (default) are not in the config file - using built-in defaults.
    """
    config_file_path = get_config_path()

    try:
        loaded_config = AppConfig.load_from_files(config_file_path)
        raw_config = _load_raw_config(config_file_path)

        if as_json:
            # Output as JSON (exclude sensitive auth fields)
            config_dict = loaded_config.model_dump(mode="json")
            # Add computed paths
            config_dict["_computed"] = {
                "config_file": str(config_file_path),
                "log_files": {
                    "audit": str(get_audit_log_path(loaded_config)),
                    "client_wire": str(get_client_log_path(loaded_config)),
                    "backend_wire": str(get_backend_log_path(loaded_config)),
                    "system": str(get_system_log_path(loaded_config)),
                    "config_history": str(get_config_history_path(loaded_config)),
                },
            }
            click.echo(json.dumps(config_dict, indent=2))
            return

        # Display formatted configuration
        click.echo("\nmcp-acp configuration:\n")

        click.echo(style_header("Logging"))
        click.echo(f"  log_dir: {loaded_config.logging.log_dir}")
        click.echo(f"  log_level: {loaded_config.logging.log_level}")
        click.echo(f"  include_payloads: {loaded_config.logging.include_payloads}")
        click.echo()
        click.echo("  Log files (computed from log_dir):")
        click.echo(f"    audit: {get_audit_log_path(loaded_config)}")
        click.echo(f"    client_wire: {get_client_log_path(loaded_config)}")
        click.echo(f"    backend_wire: {get_backend_log_path(loaded_config)}")
        click.echo(f"    system: {get_system_log_path(loaded_config)}")
        click.echo(f"    config_history: {get_config_history_path(loaded_config)}")
        click.echo()

        click.echo(style_header("Backend"))
        click.echo(f"  server_name: {loaded_config.backend.server_name}")
        if loaded_config.backend.transport:
            click.echo(f"  transport: {loaded_config.backend.transport}")
        else:
            click.echo("  transport: auto-detect (prefers HTTP when reachable)")

        if loaded_config.backend.stdio:
            click.echo("  stdio:")
            click.echo(f"    command: {loaded_config.backend.stdio.command}")
            click.echo(f"    args: {loaded_config.backend.stdio.args}")
        else:
            click.echo("  stdio: (not configured)")

        if loaded_config.backend.http:
            click.echo("  http:")
            click.echo(f"    url: {loaded_config.backend.http.url}")
            click.echo(f"    timeout: {loaded_config.backend.http.timeout}")
        else:
            click.echo("  http: (not configured)")
        click.echo()

        click.echo(style_header("Proxy"))
        click.echo(f"  name: {loaded_config.proxy.name}")
        click.echo()

        # Auth section
        click.echo(style_header("Authentication"))
        if loaded_config.auth is None:
            click.echo("  (not configured)")
        else:
            if loaded_config.auth.oidc:
                click.echo("  oidc:")
                click.echo(f"    issuer: {loaded_config.auth.oidc.issuer}")
                click.echo(f"    client_id: {loaded_config.auth.oidc.client_id}")
                click.echo(f"    audience: {loaded_config.auth.oidc.audience}")
            else:
                click.echo("  oidc: (not configured)")

            if loaded_config.auth.mtls:
                click.echo("  mtls:")
                click.echo(f"    client_cert: {loaded_config.auth.mtls.client_cert_path}")
                click.echo(f"    client_key: {loaded_config.auth.mtls.client_key_path}")
                click.echo(f"    ca_bundle: {loaded_config.auth.mtls.ca_bundle_path}")
            else:
                click.echo("  mtls: (not configured)")
        click.echo()

        # HITL section - mark values not in config file as defaults
        hitl_is_default = _is_default(raw_config, "hitl")
        hitl_header = style_header("Human-in-the-Loop (HITL)")
        if hitl_is_default:
            click.echo(hitl_header + _default_marker())
        else:
            click.echo(hitl_header)

        timeout_default = _is_default(raw_config, "hitl", "timeout_seconds")
        click.echo(
            f"  timeout_seconds: {loaded_config.hitl.timeout_seconds}"
            + (_default_marker() if timeout_default else "")
        )

        on_timeout_default = _is_default(raw_config, "hitl", "default_on_timeout")
        click.echo(
            f"  default_on_timeout: {loaded_config.hitl.default_on_timeout}"
            + (_default_marker() if on_timeout_default else "")
        )

        ttl_default = _is_default(raw_config, "hitl", "approval_ttl_seconds")
        click.echo(
            f"  approval_ttl_seconds: {loaded_config.hitl.approval_ttl_seconds}"
            + (_default_marker() if ttl_default else "")
        )
        click.echo("  cache_side_effects: (per-rule in policy)")
        click.echo()

        click.echo(f"Config file: {config_file_path}")

    except (FileNotFoundError, ValueError) as e:
        click.echo("\n" + style_error(f"Error: {e}"), err=True)
        sys.exit(1)


@config.command("path")
def config_path_cmd() -> None:
    """Show config file path.

    Displays the OS-appropriate config file location:
    - macOS: ~/Library/Application Support/mcp-acp/
    - Linux: ~/.config/mcp-acp/
    - Windows: C:\\Users\\<user>\\AppData\\Roaming\\mcp-acp/
    """
    path = get_config_path()
    click.echo(str(path))

    if not path.exists():
        click.echo("(file does not exist - run 'mcp-acp init' to create)", err=True)


@config.command("edit")
def config_edit() -> None:
    """Edit configuration in $EDITOR.

    Opens the config file in your default editor (vim, nano, etc.).
    After editing, validates the configuration with Pydantic.
    If validation fails, offers to re-edit until valid or aborted.

    Uses $EDITOR environment variable, falls back to $VISUAL,
    then 'notepad' on Windows or 'vi' on macOS/Linux.

    \b
    Common editor commands:
    vim/vi:  Esc (normal mode), :wq (save+exit), :q! (exit no save)
    nano:    Ctrl+O Enter (save), Ctrl+X (exit)
    VS Code: Cmd/Ctrl+S (save), close tab to finish
    """
    config_path = get_config_path()

    # Check config exists
    if not config_path.exists():
        click.echo(style_error(f"Error: Config file not found at {config_path}"), err=True)
        click.echo("Run 'mcp-acp init' to create configuration.", err=True)
        sys.exit(1)

    # Load and store original config for change detection
    try:
        original_config = AppConfig.load_from_files(config_path)
        original_dict = original_config.model_dump()
    except (FileNotFoundError, ValueError) as e:
        click.echo(style_error(f"Error loading config: {e}"), err=True)
        sys.exit(1)

    # Get current content as formatted JSON
    initial_content = json.dumps(original_dict, indent=2)

    # Show editor info and hints
    editor = get_editor()
    click.echo(f"Opening config in {editor}...")
    show_editor_hints(editor)

    click.pause("Press Enter to open editor...")

    # Edit loop - re-edit on validation failure
    edited_content, new_dict, new_config = edit_json_loop(
        initial_content,
        AppConfig.model_validate,
        "configuration",
    )

    # Backup original before saving
    backup_path = config_path.with_suffix(".json.bak")
    shutil.copy(config_path, backup_path)

    try:
        # Write user's edited content directly (preserves their formatting/key order)
        with open(config_path, "w", encoding="utf-8") as f:
            f.write(edited_content)
            if not edited_content.endswith("\n"):
                f.write("\n")

        # Success - remove backup
        backup_path.unlink()

    except OSError as e:
        click.echo("\n" + style_error(f"Error saving config: {e}"), err=True)
        click.echo(f"Original backed up at: {backup_path}", err=True)
        sys.exit(1)

    # Log config update
    new_version = log_config_updated(
        get_config_history_path(new_config),
        config_path,
        original_dict,
        new_dict,  # Use parsed dict to match what was saved
        source="cli_config_edit",
    )

    if new_version:
        click.echo("\n" + style_success(f"Configuration updated (version {new_version})."))
    else:
        click.echo("\n" + style_success("Configuration saved (no changes detected)."))
    click.echo(f"Saved to: {config_path}")


@config.command("validate")
@click.option(
    "--path",
    "-p",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Validate file at this path (does not change config location)",
)
def config_validate(path: Path | None) -> None:
    """Validate configuration file.

    Checks the config file for:
    - Valid JSON syntax
    - Schema validation (required fields, types)
    - Pydantic model validation

    Note: The --path flag validates a file at a different location (useful
    for testing changes or CI/CD). It does NOT change where the proxy loads
    config from - that is always the OS default location.

    Exit codes:
        0: Config is valid
        1: Config is invalid or not found
    """
    config_file_path = path or get_config_path()

    try:
        AppConfig.load_from_files(config_file_path)
        click.echo(style_success(f"Config valid: {config_file_path}"))
    except json.JSONDecodeError as e:
        click.echo(style_error(f"Invalid JSON: {e}"), err=True)
        sys.exit(1)
    except (FileNotFoundError, ValueError) as e:
        click.echo(style_error(str(e)), err=True)
        sys.exit(1)
