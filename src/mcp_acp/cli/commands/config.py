"""Config command group for mcp-acp CLI.

Provides configuration management subcommands for multi-proxy mode.
"""

from __future__ import annotations

__all__ = ["config"]

import json
import shutil
import sys
from pathlib import Path

import click

from mcp_acp.config import PerProxyConfig, load_proxy_config
from mcp_acp.manager.config import (
    ManagerConfig,
    get_manager_config_path,
    get_proxy_config_path,
    list_configured_proxies,
    load_manager_config,
)
from mcp_acp.utils.cli import edit_json_loop, get_editor, show_editor_hints

from ..styling import style_dim, style_error, style_header, style_success, style_warning


def _load_raw_config(config_path: Path) -> dict[str, object]:
    """Load raw JSON from config file without Pydantic defaults."""
    with open(config_path, encoding="utf-8") as f:
        result: dict[str, object] = json.load(f)
        return result


@click.group()
def config() -> None:
    """Configuration management commands.

    \b
    Config types:
      --manager: Manager configuration (manager.json) - OIDC settings
      --proxy NAME: Per-proxy configuration - backend, HITL, mTLS settings

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
@click.option("--manager", "-m", "show_manager", is_flag=True, help="Show manager configuration")
@click.option("--proxy", "-p", "proxy_name", help="Show proxy configuration")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def config_show(show_manager: bool, proxy_name: str | None, as_json: bool) -> None:
    """Display configuration.

    Specify --manager or --proxy to choose which config to show.
    """
    if not show_manager and not proxy_name:
        click.echo(style_error("Specify --manager or --proxy <name>"), err=True)
        click.echo(style_dim("Use 'mcp-acp config path' to see all config paths."), err=True)
        sys.exit(1)

    if show_manager and proxy_name:
        click.echo(style_error("Cannot specify both --manager and --proxy"), err=True)
        sys.exit(1)

    if show_manager:
        _show_manager_config(as_json)
    else:
        _show_proxy_config(proxy_name, as_json)


def _show_manager_config(as_json: bool) -> None:
    """Show manager configuration."""
    config_path = get_manager_config_path()

    if not config_path.exists():
        click.echo(style_error(f"Manager config not found: {config_path}"), err=True)
        click.echo(style_dim("Run 'mcp-acp init' to create configuration."), err=True)
        sys.exit(1)

    try:
        manager_config = load_manager_config()
    except Exception as e:
        click.echo(style_error(f"Error loading config: {e}"), err=True)
        sys.exit(1)

    if as_json:
        config_dict = manager_config.model_dump(mode="json")
        config_dict["_computed"] = {"config_file": str(config_path)}
        click.echo(json.dumps(config_dict, indent=2))
        return

    click.echo("\n" + style_header("Manager Configuration"))
    click.echo()
    click.echo(f"  ui_port: {manager_config.ui_port}")
    click.echo(f"  log_dir: {manager_config.log_dir}")
    click.echo(f"  log_level: {manager_config.log_level}")
    click.echo()

    click.echo(style_header("Authentication"))
    if manager_config.auth is None:
        click.echo("  (not configured)")
    else:
        click.echo("  oidc:")
        click.echo(f"    issuer: {manager_config.auth.oidc.issuer}")
        click.echo(f"    client_id: {manager_config.auth.oidc.client_id}")
        click.echo(f"    audience: {manager_config.auth.oidc.audience}")
    click.echo()

    click.echo(f"Config file: {config_path}")


def _show_proxy_config(proxy_name: str | None, as_json: bool) -> None:
    """Show proxy configuration."""
    if not proxy_name:
        click.echo(style_error("Proxy name required with --proxy"), err=True)
        sys.exit(1)

    config_path = get_proxy_config_path(proxy_name)

    if not config_path.exists():
        click.echo(style_error(f"Proxy '{proxy_name}' not found."), err=True)
        click.echo(style_dim("Run 'mcp-acp proxy list' to see available proxies."), err=True)
        sys.exit(1)

    try:
        proxy_config = load_proxy_config(proxy_name)
    except Exception as e:
        click.echo(style_error(f"Error loading config: {e}"), err=True)
        sys.exit(1)

    if as_json:
        config_dict = proxy_config.model_dump(mode="json")
        config_dict["_computed"] = {"config_file": str(config_path)}
        click.echo(json.dumps(config_dict, indent=2))
        return

    click.echo("\n" + style_header(f"Proxy: {proxy_name}"))
    click.echo(f"  ID: {proxy_config.proxy_id}")
    click.echo(f"  Created: {proxy_config.created_at}")
    click.echo()

    click.echo(style_header("Backend"))
    backend = proxy_config.backend
    click.echo(f"  Name: {backend.server_name}")
    click.echo(f"  Transport: {backend.transport}")

    if backend.stdio:
        click.echo(f"  Command: {backend.stdio.command}")
        if backend.stdio.args:
            click.echo(f"  Args: {' '.join(backend.stdio.args)}")

    if backend.http:
        click.echo(f"  URL: {backend.http.url}")
        click.echo(f"  Timeout: {backend.http.timeout}s")
    click.echo()

    click.echo(style_header("HITL"))
    click.echo(f"  Timeout: {proxy_config.hitl.timeout_seconds}s")
    click.echo(f"  Approval TTL: {proxy_config.hitl.approval_ttl_seconds}s")
    click.echo()

    click.echo(style_header("mTLS"))
    if proxy_config.mtls:
        click.echo(f"  Client cert: {proxy_config.mtls.client_cert_path}")
        click.echo(f"  Client key: {proxy_config.mtls.client_key_path}")
        click.echo(f"  CA bundle: {proxy_config.mtls.ca_bundle_path}")
    else:
        click.echo("  (not configured)")
    click.echo()

    click.echo(f"Config file: {config_path}")


@config.command("path")
@click.option("--manager", "-m", "show_manager", is_flag=True, help="Show manager config path")
@click.option("--proxy", "-p", "proxy_name", help="Show proxy config path")
def config_path_cmd(show_manager: bool, proxy_name: str | None) -> None:
    """Show config file paths.

    Without flags, shows all config paths.
    """
    if show_manager and proxy_name:
        click.echo(style_error("Cannot specify both --manager and --proxy"), err=True)
        sys.exit(1)

    if show_manager:
        path = get_manager_config_path()
        click.echo(str(path))
        if not path.exists():
            click.echo(style_dim("(file does not exist - run 'mcp-acp init' to create)"), err=True)
        return

    if proxy_name:
        path = get_proxy_config_path(proxy_name)
        click.echo(str(path))
        if not path.exists():
            click.echo(style_dim(f"(file does not exist - run 'mcp-acp proxy add {proxy_name}')"), err=True)
        return

    # No flags - show all paths
    click.echo(style_header("Configuration Paths"))
    click.echo()

    # Manager config
    manager_path = get_manager_config_path()
    exists = "✓" if manager_path.exists() else "✗"
    click.echo(f"  Manager: {manager_path}")
    click.echo(f"           {exists} {'exists' if manager_path.exists() else 'not found'}")
    click.echo()

    # Proxy configs
    proxies = list_configured_proxies()
    if proxies:
        click.echo("  Proxies:")
        for name in proxies:
            proxy_path = get_proxy_config_path(name)
            click.echo(f"    {name}: {proxy_path}")
    else:
        click.echo("  Proxies: (none configured)")
    click.echo()


@config.command("edit")
@click.option("--manager", "-m", "edit_manager", is_flag=True, help="Edit manager configuration")
@click.option("--proxy", "-p", "proxy_name", help="Edit proxy configuration")
def config_edit(edit_manager: bool, proxy_name: str | None) -> None:
    """Edit configuration in $EDITOR.

    Specify --manager or --proxy to choose which config to edit.
    After editing, validates the configuration with Pydantic.
    If validation fails, offers to re-edit until valid or aborted.
    """
    if not edit_manager and not proxy_name:
        click.echo(style_error("Specify --manager or --proxy <name>"), err=True)
        sys.exit(1)

    if edit_manager and proxy_name:
        click.echo(style_error("Cannot specify both --manager and --proxy"), err=True)
        sys.exit(1)

    if edit_manager:
        _edit_manager_config()
    else:
        _edit_proxy_config(proxy_name)


def _edit_manager_config() -> None:
    """Edit manager configuration."""
    config_path = get_manager_config_path()

    if not config_path.exists():
        click.echo(style_error(f"Manager config not found: {config_path}"), err=True)
        click.echo(style_dim("Run 'mcp-acp init' to create configuration."), err=True)
        sys.exit(1)

    try:
        original_config = load_manager_config()
        original_dict = original_config.model_dump()
    except Exception as e:
        click.echo(style_error(f"Error loading config: {e}"), err=True)
        sys.exit(1)

    initial_content = json.dumps(original_dict, indent=2)

    editor = get_editor()
    click.echo(f"Opening config in {editor}...")
    show_editor_hints(editor)
    click.pause("Press Enter to open editor...")

    edited_content, new_dict, new_config = edit_json_loop(
        initial_content,
        ManagerConfig.model_validate,
        "manager configuration",
    )

    # Backup and save
    backup_path = config_path.with_suffix(".json.bak")
    shutil.copy(config_path, backup_path)

    try:
        with open(config_path, "w", encoding="utf-8") as f:
            f.write(edited_content)
            if not edited_content.endswith("\n"):
                f.write("\n")
        backup_path.unlink()
    except OSError as e:
        click.echo("\n" + style_error(f"Error saving config: {e}"), err=True)
        click.echo(f"Original backed up at: {backup_path}", err=True)
        sys.exit(1)

    click.echo("\n" + style_success("Manager configuration saved."))
    click.echo(f"Saved to: {config_path}")


def _edit_proxy_config(proxy_name: str | None) -> None:
    """Edit proxy configuration."""
    if not proxy_name:
        click.echo(style_error("Proxy name required with --proxy"), err=True)
        sys.exit(1)

    config_path = get_proxy_config_path(proxy_name)

    if not config_path.exists():
        click.echo(style_error(f"Proxy '{proxy_name}' not found."), err=True)
        click.echo(style_dim("Run 'mcp-acp proxy list' to see available proxies."), err=True)
        sys.exit(1)

    try:
        original_config = load_proxy_config(proxy_name)
        original_dict = original_config.model_dump()
    except Exception as e:
        click.echo(style_error(f"Error loading config: {e}"), err=True)
        sys.exit(1)

    initial_content = json.dumps(original_dict, indent=2)

    editor = get_editor()
    click.echo(f"Opening config in {editor}...")
    show_editor_hints(editor)
    click.pause("Press Enter to open editor...")

    edited_content, new_dict, new_config = edit_json_loop(
        initial_content,
        PerProxyConfig.model_validate,
        "proxy configuration",
    )

    # Backup and save
    backup_path = config_path.with_suffix(".json.bak")
    shutil.copy(config_path, backup_path)

    try:
        with open(config_path, "w", encoding="utf-8") as f:
            f.write(edited_content)
            if not edited_content.endswith("\n"):
                f.write("\n")
        backup_path.unlink()
    except OSError as e:
        click.echo("\n" + style_error(f"Error saving config: {e}"), err=True)
        click.echo(f"Original backed up at: {backup_path}", err=True)
        sys.exit(1)

    click.echo("\n" + style_success(f"Proxy configuration saved."))
    click.echo(f"Saved to: {config_path}")


@config.command("validate")
@click.option("--manager", "-m", "validate_manager", is_flag=True, help="Validate manager only")
@click.option("--proxy", "-p", "proxy_name", help="Validate specific proxy only")
def config_validate(validate_manager: bool, proxy_name: str | None) -> None:
    """Validate configuration files.

    Without flags, validates manager and all proxy configs.
    Use --manager or --proxy to validate specific configs.

    Exit codes:
        0: All configs valid
        1: Config invalid or not found
    """
    if validate_manager and proxy_name:
        click.echo(style_error("Cannot specify both --manager and --proxy"), err=True)
        sys.exit(1)

    all_valid = True

    if validate_manager:
        # Validate manager only
        all_valid = _validate_manager()
    elif proxy_name:
        # Validate specific proxy only
        all_valid = _validate_proxy(proxy_name)
    else:
        # Validate ALL
        click.echo(style_header("Validating all configurations"))
        click.echo()

        # Validate manager
        manager_valid = _validate_manager()
        all_valid = all_valid and manager_valid

        # Validate all proxies
        proxies = list_configured_proxies()
        if proxies:
            click.echo()
            for name in proxies:
                proxy_valid = _validate_proxy(name)
                all_valid = all_valid and proxy_valid
        else:
            click.echo(style_dim("  No proxies configured."))

        click.echo()
        if all_valid:
            click.echo(style_success("All configurations valid."))
        else:
            click.echo(style_error("Some configurations invalid."))

    sys.exit(0 if all_valid else 1)


def _validate_manager() -> bool:
    """Validate manager configuration. Returns True if valid."""
    config_path = get_manager_config_path()

    if not config_path.exists():
        click.echo(style_warning(f"Manager config not found: {config_path}"))
        return False

    try:
        load_manager_config()
        click.echo(style_success(f"Manager config valid: {config_path}"))
        return True
    except json.JSONDecodeError as e:
        click.echo(style_error(f"Invalid JSON in manager config: {e}"))
        return False
    except Exception as e:
        click.echo(style_error(f"Invalid manager config: {e}"))
        return False


def _validate_proxy(proxy_name: str) -> bool:
    """Validate proxy configuration. Returns True if valid."""
    config_path = get_proxy_config_path(proxy_name)

    if not config_path.exists():
        click.echo(style_warning(f"Proxy '{proxy_name}' not found: {config_path}"))
        return False

    try:
        load_proxy_config(proxy_name)
        click.echo(style_success(f"Proxy '{proxy_name}' config valid: {config_path}"))
        return True
    except json.JSONDecodeError as e:
        click.echo(style_error(f"Invalid JSON in proxy '{proxy_name}' config: {e}"))
        return False
    except Exception as e:
        click.echo(style_error(f"Invalid proxy '{proxy_name}' config: {e}"))
        return False
