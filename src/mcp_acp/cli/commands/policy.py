"""Policy command group for mcp-acp-nexus CLI.

Provides policy management subcommands.
"""

from __future__ import annotations

__all__ = ["policy"]

import json
import os
import shutil
import sys
from pathlib import Path

import click

from mcp_acp.cli.api_client import APIError, ProxyNotRunningError, api_request

from ..styling import style_dim, style_error, style_label, style_success
from mcp_acp.constants import CLI_POLICY_RELOAD_TIMEOUT_SECONDS
from mcp_acp.utils.policy import get_policy_path, load_policy, save_policy


@click.group()
def policy() -> None:
    """Policy management commands."""
    pass


@policy.command("validate")
@click.option(
    "--path",
    "-p",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Validate file at this path (does not change policy location)",
)
def policy_validate(path: Path | None) -> None:
    """Validate policy file.

    Checks the policy file for:
    - Valid JSON syntax
    - Schema validation (conditions, effects, rule structure)
    - At least one condition per rule (security requirement)

    Note: The --path flag validates a file at a different location (useful
    for testing changes or CI/CD). It does NOT change where the proxy loads
    policy from - that is always the OS default location.

    Exit codes:
        0: Policy is valid
        1: Policy is invalid or not found
    """
    policy_path = path or get_policy_path()

    try:
        policy_config = load_policy(policy_path)
        rule_count = len(policy_config.rules)
        click.echo(style_success(f"Policy valid: {policy_path}"))
        click.echo(f"  {rule_count} rule{'s' if rule_count != 1 else ''} defined")
        click.echo(f"  Default action: {policy_config.default_action}")
    except (FileNotFoundError, ValueError) as e:
        click.echo(style_error(str(e)), err=True)
        sys.exit(1)


@policy.command("path")
def policy_path_cmd() -> None:
    """Show policy file path.

    Displays the OS-appropriate policy file location.
    """
    path = get_policy_path()
    click.echo(str(path))

    if not path.exists():
        click.echo("(file does not exist - run 'mcp-acp-nexus init' to create)", err=True)


@policy.command("reload")
def policy_reload() -> None:
    """Reload policy in running proxy.

    Validates and applies the current policy.json without restarting the proxy.
    Requires the proxy to be running (start with 'mcp-acp-nexus start' or via MCP client).

    This command communicates with the proxy's management API via UDS.

    Exit codes:
        0: Policy reloaded successfully
        1: Reload failed (validation error, file error, or proxy not running)
    """
    try:
        result = api_request("POST", "/api/control/reload-policy", timeout=CLI_POLICY_RELOAD_TIMEOUT_SECONDS)

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
        click.echo(style_error("Error: Proxy not running"), err=True)
        click.echo("  Start the proxy with: mcp-acp-nexus start", err=True)
        click.echo("  Or restart your MCP client (e.g., Claude Desktop)", err=True)
        sys.exit(1)
    except APIError as e:
        click.echo(style_error(f"Error: {e.message}"), err=True)
        sys.exit(1)


@policy.command("show")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def policy_show(as_json: bool) -> None:
    """Display current policy.

    Shows the policy file contents with rule count and metadata.
    """
    policy_path = get_policy_path()

    try:
        policy_config = load_policy(policy_path)
    except (FileNotFoundError, ValueError) as e:
        click.echo(style_error(str(e)), err=True)
        sys.exit(1)

    # Get file modification time
    mtime = policy_path.stat().st_mtime
    from datetime import datetime

    modified = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")

    if as_json:
        # JSON output - read raw file to show only actual fields (not Pydantic defaults)
        with open(policy_path, encoding="utf-8") as f:
            raw_policy = json.load(f)
        raw_policy["_metadata"] = {
            "file": str(policy_path),
            "modified": modified,
            "rules_count": len(policy_config.rules),
        }
        click.echo(json.dumps(raw_policy, indent=2))
    else:
        # Human-readable output
        click.echo("\n" + style_label("Policy") + f" {policy_path}")
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
def policy_edit() -> None:
    """Edit policy in $EDITOR.

    Opens the policy file in your default editor.
    After editing, validates the policy with Pydantic.
    If validation fails, offers to re-edit until valid or aborted.

    Note: If the proxy is running, you'll need to reload the policy
    with 'mcp-acp-nexus policy reload' or restart the proxy.
    """
    policy_path = get_policy_path()

    # Check policy exists
    if not policy_path.exists():
        click.echo(style_error(f"Error: Policy file not found at {policy_path}"), err=True)
        click.echo("Run 'mcp-acp-nexus init' to create policy.", err=True)
        sys.exit(1)

    # Load original for validation
    try:
        original_config = load_policy(policy_path)
        original_dict = original_config.model_dump(mode="json")
    except (FileNotFoundError, ValueError) as e:
        click.echo(style_error(f"Error loading policy: {e}"), err=True)
        sys.exit(1)

    # Get current content as formatted JSON
    current_content = json.dumps(original_dict, indent=2)

    # Determine editor
    if sys.platform == "win32":
        default_editor = "notepad"
    else:
        default_editor = "vi"
    editor = os.environ.get("EDITOR") or os.environ.get("VISUAL") or default_editor
    click.echo(f"Opening policy in {editor}...")

    # Show hints for common editors
    editor_name = os.path.basename(editor).split()[0]
    if editor_name in ("vim", "vi", "nvim"):
        click.echo("  Esc = normal mode | :wq = save+exit | :q! = exit no save")
    elif editor_name == "nano":
        click.echo("  Ctrl+O Enter = save | Ctrl+X = exit")

    click.pause("Press Enter to open editor...")

    # Edit loop
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
            from mcp_acp.pdp.policy import PolicyConfig

            new_dict = json.loads(edited_content)
            PolicyConfig.model_validate(new_dict)
            break
        except json.JSONDecodeError as e:
            click.echo("\n" + style_error(f"Error: Invalid JSON: {e}"), err=True)
        except ValueError as e:
            click.echo("\n" + style_error(f"Error: Invalid policy: {e}"), err=True)

        if not click.confirm("Re-edit policy?", default=True):
            click.echo(style_dim("Edit cancelled."))
            sys.exit(1)

        current_content = edited_content

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
    click.echo("  mcp-acp-nexus policy reload")


RULE_SCHEMA = """\
Policy Rule Schema
==================

A rule has these top-level fields:
  - id: string (optional) - Unique identifier for logging/debugging
  - description: string (optional) - Human-readable description
  - effect: "allow" | "deny" | "hitl" (REQUIRED)
  - conditions: object (REQUIRED) - At least one condition must be specified

Conditions (all use AND logic - all specified must match):
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

Note: side_effects condition is not yet exposed in CLI/UI. Tool side effects
are currently hardcoded; see roadmap.md section 1.1 for planned external
tool registry that will enable dynamic side effect selection.

When a field accepts string[], any value matches (OR logic within field).

Examples:
  {"effect": "allow", "conditions": {"tool_name": "read_*"}}
  {"effect": "deny", "conditions": {"extension": [".key", ".env", ".pem"]}}
  {"effect": "hitl", "conditions": {"tool_name": "bash", "path_pattern": "/home/**"}}
"""

RULE_TEMPLATE = """\
{
  "id": null,
  "description": null,
  "effect": "hitl",
  "conditions": {
    "tool_name": "*"
  }
}
"""


@policy.command("add")
def policy_add() -> None:
    """Add a new rule via editor.

    Shows the rule schema, then opens your editor with a template.
    Edit the JSON, save and close to add the rule.

    Note: If the proxy is running, you'll need to reload the policy
    with 'mcp-acp-nexus policy reload' or restart the proxy.
    """
    from mcp_acp.pdp.policy import PolicyRule

    policy_path = get_policy_path()

    # Load existing policy
    try:
        policy_config = load_policy(policy_path)
    except FileNotFoundError:
        click.echo(style_error(f"Error: Policy file not found at {policy_path}"), err=True)
        click.echo("Run 'mcp-acp-nexus init' to create policy.", err=True)
        sys.exit(1)
    except ValueError as e:
        click.echo(style_error(f"Error loading policy: {e}"), err=True)
        sys.exit(1)

    # Show schema
    click.echo()
    click.echo(RULE_SCHEMA)
    click.echo()

    # Determine editor
    if sys.platform == "win32":
        default_editor = "notepad"
    else:
        default_editor = "vi"
    editor = os.environ.get("EDITOR") or os.environ.get("VISUAL") or default_editor
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
    click.echo("  mcp-acp-nexus policy reload")
