"""Policy command group for mcp-acp CLI.

Provides policy management subcommands for multi-proxy mode.
"""

from __future__ import annotations

__all__ = ["policy"]

import json
import shutil
import sys
from datetime import datetime
from pathlib import Path

import click

from mcp_acp.cli.api_client import ProxyAPIError, ProxyNotRunningError, api_request
from mcp_acp.constants import CLI_POLICY_RELOAD_TIMEOUT_SECONDS
from mcp_acp.manager.config import (
    get_proxy_policy_path,
    list_configured_proxies,
)
from mcp_acp.pdp.policy import PolicyConfig, PolicyRule
from mcp_acp.utils.cli import (
    edit_json_loop,
    get_editor,
    require_proxy_name,
    show_editor_hints,
)
from mcp_acp.utils.policy import load_policy, save_policy

from ..styling import style_dim, style_error, style_label, style_success, style_warning


@click.group()
def policy() -> None:
    """Policy management commands.

    \b
    Subcommands:
      show      Display current policy rules
      path      Show policy file path
      edit      Edit policy in $EDITOR
      add       Add a new policy rule
      validate  Validate policy files
      reload    Hot reload policy (requires running proxy)
    """
    pass


@policy.command("validate")
@click.option("--proxy", "-p", "proxy_name", help="Validate specific proxy policy")
def policy_validate(proxy_name: str | None) -> None:
    """Validate policy files.

    Without --proxy, validates ALL proxy policies.
    With --proxy, validates only the specified proxy's policy.

    Exit codes:
        0: Policy is valid
        1: Policy is invalid or not found
    """
    if proxy_name:
        # Validate specific proxy
        valid = _validate_proxy_policy(proxy_name)
        sys.exit(0 if valid else 1)

    # Validate ALL
    proxies = list_configured_proxies()
    if not proxies:
        click.echo(style_warning("No proxies configured."))
        click.echo(style_dim("Run 'mcp-acp proxy add' to create one."))
        sys.exit(0)

    click.echo(style_label("Validating all policies"))
    click.echo()

    all_valid = True
    for name in proxies:
        valid = _validate_proxy_policy(name)
        all_valid = all_valid and valid

    click.echo()
    if all_valid:
        click.echo(style_success("All policies valid."))
    else:
        click.echo(style_error("Some policies invalid."))

    sys.exit(0 if all_valid else 1)


def _validate_proxy_policy(proxy_name: str) -> bool:
    """Validate a proxy's policy. Returns True if valid."""
    policy_path = get_proxy_policy_path(proxy_name)

    if not policy_path.exists():
        click.echo(style_warning(f"  {proxy_name}: policy not found"))
        return False

    try:
        policy_config = load_policy(policy_path)
        rule_count = len(policy_config.rules)
        click.echo(style_success(f"  {proxy_name}: valid ({rule_count} rules)"))
        return True
    except json.JSONDecodeError as e:
        click.echo(style_error(f"  {proxy_name}: invalid JSON - {e}"))
        return False
    except Exception as e:
        click.echo(style_error(f"  {proxy_name}: invalid - {e}"))
        return False


@policy.command("path")
@click.option("--proxy", "-p", "proxy_name", help="Show specific proxy policy path")
def policy_path_cmd(proxy_name: str | None) -> None:
    """Show policy file paths.

    Without --proxy, shows all proxy policy paths.
    """
    if proxy_name:
        path = get_proxy_policy_path(proxy_name)
        click.echo(str(path))
        if not path.exists():
            click.echo(style_dim("(file does not exist)"), err=True)
        return

    # Show all
    proxies = list_configured_proxies()
    if not proxies:
        click.echo(style_dim("No proxies configured."))
        click.echo(style_dim("Run 'mcp-acp proxy add' to create one."))
        return

    click.echo(style_label("Policy Paths"))
    click.echo()

    for name in proxies:
        path = get_proxy_policy_path(name)
        exists = "✓" if path.exists() else "✗"
        click.echo(f"  {name}: {path}")
        click.echo(f"         {exists} {'exists' if path.exists() else 'not found'}")
    click.echo()


@policy.command("reload")
@click.option("--proxy", "-p", "proxy_name", required=True, help="Proxy name")
def policy_reload(proxy_name: str) -> None:
    """Reload policy in running proxy.

    Validates and applies the current policy.json without restarting the proxy.
    Requires the proxy to be running (start with 'mcp-acp start --proxy <name>').

    This command communicates with the proxy's management API via UDS.

    Example:
        mcp-acp policy reload --proxy filesystem

    Exit codes:
        0: Policy reloaded successfully
        1: Reload failed (validation error, file error, or proxy not running)
    """
    try:
        result = api_request(
            "POST",
            "/api/control/reload-policy",
            proxy_name=proxy_name,
            timeout=CLI_POLICY_RELOAD_TIMEOUT_SECONDS,
        )

        if not isinstance(result, dict):
            click.echo(style_error("Reload failed: Unexpected response"), err=True)
            sys.exit(1)

        if result.get("status") == "success":
            old_count = result.get("old_rules_count", "?")
            new_count = result.get("new_rules_count", "?")
            approvals_cleared = result.get("approvals_cleared", 0)
            version = result.get("policy_version")

            click.echo(style_success(f"Policy reloaded: {old_count} → {new_count} rules"))
            if approvals_cleared > 0:
                click.echo(
                    f"  {approvals_cleared} cached approval{'s' if approvals_cleared != 1 else ''} cleared"
                )
            if version:
                click.echo(f"  Version: {version}")
        else:
            error = result.get("error", "Unknown error")
            click.echo(style_error(f"Reload failed: {error}"), err=True)
            sys.exit(1)

    except ProxyNotRunningError:
        click.echo(style_warning(f"Proxy '{proxy_name}' is not running — skipping hot reload."))
        click.echo(style_dim("  Changes will be applied automatically on next startup."))
    except ProxyAPIError as e:
        click.echo(style_error(f"Error: {e.message}"), err=True)
        sys.exit(1)


@policy.command("show")
@click.option("--proxy", "-p", "proxy_name", required=True, help="Proxy name")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def policy_show(proxy_name: str, as_json: bool) -> None:
    """Display proxy policy."""
    proxy_name = require_proxy_name(proxy_name)
    policy_path = get_proxy_policy_path(proxy_name)

    try:
        policy_config = load_policy(policy_path)
    except FileNotFoundError:
        click.echo(style_error(f"Policy not found: {policy_path}"), err=True)
        sys.exit(1)
    except ValueError as e:
        click.echo(style_error(str(e)), err=True)
        sys.exit(1)

    # Get file modification time
    mtime = policy_path.stat().st_mtime
    modified = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")

    if as_json:
        # JSON output - read raw file to show only actual fields (not Pydantic defaults)
        with open(policy_path, encoding="utf-8") as f:
            raw_policy = json.load(f)
        raw_policy["_metadata"] = {
            "proxy": proxy_name,
            "file": str(policy_path),
            "modified": modified,
            "rules_count": len(policy_config.rules),
        }
        click.echo(json.dumps(raw_policy, indent=2))
    else:
        # Human-readable output
        click.echo("\n" + style_label(f"Policy: {proxy_name}") + f" {policy_path}")
        click.echo(f"Modified: {modified}")
        click.echo(f"Rules: {len(policy_config.rules)}")
        click.echo(f"Default action: {policy_config.default_action}")
        click.echo()

        if not policy_config.rules:
            click.echo("  (no rules defined)")
        else:
            for i, rule in enumerate(policy_config.rules, 1):
                effect_color = {"allow": "green", "deny": "red", "hitl": "yellow"}.get(rule.effect, "white")
                effect_str = click.style(rule.effect.upper(), fg=effect_color, bold=True)

                # Build condition summary
                conds = []
                if rule.conditions.tool_name:
                    conds.append(f"tool={rule.conditions.tool_name}")
                if rule.conditions.path_pattern:
                    conds.append(f"path={rule.conditions.path_pattern}")
                if rule.conditions.backend_id:
                    conds.append(f"backend={rule.conditions.backend_id}")
                cond_str = ", ".join(conds) if conds else "(no conditions)"

                rule_id = rule.id or f"rule-{i}"
                click.echo(f"  [{rule_id}] {effect_str}: {cond_str}")
                if rule.description:
                    click.echo(f"    {rule.description}")


@policy.command("edit")
@click.option("--proxy", "-p", "proxy_name", required=True, help="Proxy name")
def policy_edit(proxy_name: str) -> None:
    """Edit proxy policy in $EDITOR.

    Opens the policy file in your default editor.
    After editing, validates the policy with Pydantic.
    If validation fails, offers to re-edit until valid or aborted.

    Note: If the proxy is running, you'll need to reload the policy
    with 'mcp-acp policy reload --proxy <name>' or restart the proxy.
    """
    proxy_name = require_proxy_name(proxy_name)
    policy_path = get_proxy_policy_path(proxy_name)

    # Check policy exists
    if not policy_path.exists():
        click.echo(style_error(f"Policy not found: {policy_path}"), err=True)
        sys.exit(1)

    # Load original for validation
    try:
        original_config = load_policy(policy_path)
        original_dict = original_config.model_dump(mode="json")
    except (FileNotFoundError, ValueError) as e:
        click.echo(style_error(f"Error loading policy: {e}"), err=True)
        sys.exit(1)

    # Get current content as formatted JSON
    initial_content = json.dumps(original_dict, indent=2)

    # Show editor info and hints
    editor = get_editor()
    click.echo(f"Opening policy in {editor}...")
    show_editor_hints(editor)

    click.pause("Press Enter to open editor...")

    # Edit loop - re-edit on validation failure
    edited_content, _, _ = edit_json_loop(
        initial_content,
        PolicyConfig.model_validate,
        "policy",
    )

    # Backup and save
    backup_path = policy_path.with_suffix(".json.bak")
    shutil.copy(policy_path, backup_path)

    try:
        with open(policy_path, "w", encoding="utf-8") as f:
            f.write(edited_content)
            if not edited_content.endswith("\n"):
                f.write("\n")

        backup_path.unlink()

    except OSError as e:
        click.echo("\n" + style_error(f"Error saving policy: {e}"), err=True)
        click.echo(f"Original backed up at: {backup_path}", err=True)
        sys.exit(1)

    rule_count = len(json.loads(edited_content).get("rules", []))
    click.echo("\n" + style_success(f"Policy saved ({rule_count} rules)"))
    click.echo(f"  File: {policy_path}")
    click.echo()
    click.echo(click.style("Note:", fg="yellow", bold=True) + " If proxy is running, reload with:")
    click.echo(f"  mcp-acp policy reload --proxy {proxy_name}")


# All cacheable side effects - matches UI (RuleFormDialog.tsx)
ALL_CACHEABLE_SIDE_EFFECTS = [
    "fs_read",
    "fs_write",
    "db_read",
    "db_write",
    "network_egress",
    "network_ingress",
    "process_spawn",
    "sudo_elevate",
    "secrets_read",
    "env_read",
    "clipboard_read",
    "clipboard_write",
    "browser_open",
    "email_send",
    "cloud_api",
    "container_exec",
    "keychain_read",
    "screen_capture",
    "audio_capture",
    "camera_capture",
]

RULE_SCHEMA = """\
Policy Rule Schema
==================

A rule has these top-level fields:
  - id: string (optional) - Unique identifier for logging/debugging
  - description: string (optional) - Human-readable description
  - effect: "allow" | "deny" | "hitl" (REQUIRED)
  - conditions: object (REQUIRED) - At least one condition must be specified
  - cache_side_effects: string[] (optional, HITL only) - Enable approval caching

Conditions:
  - tool_name: string | string[]  - Tool name pattern (glob: *, ?)
  - path_pattern: string | string[]  - File path pattern (glob: *, **, ?)
  - source_path: string | string[]  - Source path for move/copy operations
  - dest_path: string | string[]  - Destination path for move/copy operations
  - operations: ["read" | "write" | "delete"]  - Operation types
  - extension: string | string[]  - File extension (e.g., ".key", ".env")
  - scheme: string | string[]  - URI scheme (e.g., "file", "db", "s3")
  - resource_type: "tool" | "resource" | "prompt" | "server"
  - mcp_method: string | string[]  - MCP method pattern (e.g., "resources/*")
  - subject_id: string | string[]  - User/subject ID

Matching Logic:
  - Between different conditions: AND (all must match)
  - Within array values: OR (any value matches)

  Example - OR within a field:
    "tool_name": ["read_*", "write_*"]   --> matches read_* OR write_*
    "extension": [".env", ".key"]        --> matches .env OR .key

  Example - AND between fields:
    "tool_name": "bash", "path_pattern": "/home/**"  --> must match BOTH

HITL Approval Caching (only when effect="hitl"):
  cache_side_effects allows caching user approvals for repeated tool calls.
  Set to list of side effects to enable, or omit/null to disable.

  Cacheable side effects:
    fs_read, fs_write, db_read, db_write, network_egress, network_ingress,
    process_spawn, sudo_elevate, secrets_read, env_read, clipboard_read,
    clipboard_write, browser_open, email_send, cloud_api, container_exec,
    keychain_read, screen_capture, audio_capture, camera_capture

  Security: code_exec tools are NEVER cached (command args not in cache key).

Note: side_effects condition is not yet exposed in CLI/UI.

Examples:
  {"effect": "allow", "conditions": {"tool_name": "read_*"}}
  {"effect": "deny", "conditions": {"extension": [".key", ".env", ".pem"]}}
  {"effect": "hitl", "conditions": {"tool_name": "bash", "path_pattern": "/home/**"}}
  {"effect": "hitl", "conditions": {"tool_name": "read_*"}, "cache_side_effects": ["fs_read"]}
"""

RULE_TEMPLATE = """\
{
  "id": null,
  "description": null,
  "effect": "hitl",
  "conditions": {
    "tool_name": "*"
  },
  "cache_side_effects": null
}
"""


@policy.command("add")
@click.option("--proxy", "-p", "proxy_name", required=True, help="Proxy name")
def policy_add(proxy_name: str) -> None:
    """Add a new rule via editor.

    Shows the rule schema, then opens your editor with a template.
    Edit the JSON, save and close to add the rule.

    Note: If the proxy is running, you'll need to reload the policy
    with 'mcp-acp policy reload --proxy <name>' or restart the proxy.
    """
    proxy_name = require_proxy_name(proxy_name)
    policy_path = get_proxy_policy_path(proxy_name)

    # Load existing policy
    try:
        policy_config = load_policy(policy_path)
    except FileNotFoundError:
        click.echo(style_error(f"Policy not found: {policy_path}"), err=True)
        sys.exit(1)
    except ValueError as e:
        click.echo(style_error(f"Error loading policy: {e}"), err=True)
        sys.exit(1)

    # Show schema
    click.echo()
    click.echo(RULE_SCHEMA)
    click.echo()

    # Show editor info
    editor = get_editor()
    click.echo(f"Opening editor ({editor})...")

    click.pause("Press Enter to open editor...")

    # Edit loop
    current_content = RULE_TEMPLATE
    while True:
        edited_content = click.edit(current_content, extension=".json")

        if edited_content is None:
            click.echo(style_dim("Edit cancelled."))
            sys.exit(0)

        if edited_content.strip() == current_content.strip():
            click.echo(style_dim("No changes made."))
            sys.exit(0)

        # Validate
        try:
            rule_dict = json.loads(edited_content)
            # Remove null values before validation
            rule_dict = {k: v for k, v in rule_dict.items() if v is not None}
            if "conditions" in rule_dict:
                rule_dict["conditions"] = {k: v for k, v in rule_dict["conditions"].items() if v is not None}
            rule = PolicyRule.model_validate(rule_dict)
            break
        except json.JSONDecodeError as e:
            click.echo("\n" + style_error(f"Error: Invalid JSON: {e}"), err=True)
        except ValueError as e:
            click.echo("\n" + style_error(f"Error: Invalid rule: {e}"), err=True)

        if not click.confirm("Re-edit rule?", default=True):
            click.echo(style_dim("Cancelled."))
            sys.exit(1)

        current_content = edited_content

    # Add rule to policy
    policy_config.rules.append(rule)

    # Save
    try:
        save_policy(policy_config, policy_path)
    except OSError as e:
        click.echo(style_error(f"Error saving policy: {e}"), err=True)
        sys.exit(1)

    click.echo("\n" + style_success(f"Rule added (now {len(policy_config.rules)} rules)"))
    click.echo(f"  File: {policy_path}")
    click.echo()
    click.echo(click.style("Note:", fg="yellow", bold=True) + " If proxy is running, reload with:")
    click.echo(f"  mcp-acp policy reload --proxy {proxy_name}")
